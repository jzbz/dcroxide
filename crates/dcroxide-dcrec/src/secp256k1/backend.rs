// SPDX-License-Identifier: ISC
//! The seam between this crate's dcrd-ordered steps and the variable-time
//! arithmetic they borrow from `dcroxide-secp256k1-vartime` (ADR-0016).
//! This is the only module of the crate that names that crate, so another
//! backend, k256's code before it or a libsecp256k1 binding, slots in, as
//! code, by changing this module alone.  Only the verification and
//! recovery functions name this module, so no signing function reaches
//! it; `tests/vartime_boundary.rs` holds both rules.
//!
//! Every function here takes public values only, and none can panic: when
//! the vartime crate declines (its safegcd loop past its iteration cap, a
//! case its proof rules out) or hands back a value k256 refuses, the seam
//! computes the answer on k256 instead, as the code before it did, and
//! debug builds assert.  An assertion in release would be an outage under
//! `panic = "abort"`.  Tests can force that path, which production never
//! takes, so it is tested too.
//!
//! Until the multiplies move, the callers compute on k256's types, so the
//! seam returns them, converting inside where the conversion and its
//! fallback can sit together.

use dcroxide_secp256k1_vartime as vartime;
use k256::Scalar;
use k256::elliptic_curve::PrimeField;

/// w = x^-1 mod N for a nonzero x below N, given big-endian, in variable
/// time, as dcrd's `ModNScalar.InverseValNonConst`: the vartime crate's
/// port of libsecp256k1's safegcd, else k256's `invert_vartime`.  Both
/// callers, ECDSA verification's step 3 and compact recovery's step 7,
/// have established 1 <= x < N.  Should x be zero or not below N anyway,
/// the result is zero, which makes verification fail at step 6 and
/// recovery at step 10, and debug builds assert.
pub(crate) fn scalar_inverse(x: &[u8; 32]) -> Scalar {
    debug_assert!(*x != [0; 32], "scalar_inverse of zero");
    if !forced_fallback() {
        let w = vartime::Scalar::from_be_bytes(x)
            .and_then(|x| x.try_inverse_var())
            .and_then(|w| Option::<Scalar>::from(Scalar::from_repr(w.to_be_bytes().into())));
        debug_assert!(w.is_some(), "the vartime scalar inverse declined");
        if let Some(w) = w {
            return w;
        }
    }
    let w = Option::<Scalar>::from(Scalar::from_repr((*x).into()))
        .and_then(|x| Option::<Scalar>::from(x.invert_vartime()));
    debug_assert!(
        w.is_some(),
        "scalar_inverse of zero or of a value not below N"
    );
    w.unwrap_or(Scalar::ZERO)
}

#[cfg(test)]
std::thread_local! {
    /// Set by [`tests::force_fallback`]: the seam takes k256's path.
    static FORCE_FALLBACK: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// Whether a test has forced k256's path on this thread.
#[cfg(test)]
fn forced_fallback() -> bool {
    FORCE_FALLBACK.with(core::cell::Cell::get)
}

/// Production never forces the fallback.
#[cfg(not(test))]
#[inline(always)]
fn forced_fallback() -> bool {
    false
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        reason = "test arithmetic: k256 scalar operators, which are modular, \
                  and byte indices below 32"
    )]

    use super::*;

    use dcroxide_testutil::SplitMix64;
    use k256::FieldBytes;
    use k256::elliptic_curve::ops::Reduce;

    use crate::secp256k1::GROUP_ORDER_BYTES;

    /// Runs `f` with the seam forced onto k256's path on this thread.
    pub(super) fn force_fallback<T>(f: impl FnOnce() -> T) -> T {
        FORCE_FALLBACK.with(|c| c.set(true));
        let r = f();
        FORCE_FALLBACK.with(|c| c.set(false));
        r
    }

    /// k256's own variable-time inverse, the reference.
    fn reference(x: &[u8; 32]) -> [u8; 32] {
        let s = Option::<Scalar>::from(Scalar::from_repr((*x).into())).expect("below N");
        let w = Option::<Scalar>::from(s.invert_vartime()).expect("nonzero");
        w.to_repr().into()
    }

    /// The nonzero scalars below N the seam is checked on: 1, 2, N-1,
    /// N-2, every 2^k below N, and random ones, uniform and with long runs
    /// of zero or one bits.
    fn inputs() -> Vec<[u8; 32]> {
        let mut v = Vec::new();
        let mut one = [0u8; 32];
        one[31] = 1;
        v.push(one);
        let mut two = [0u8; 32];
        two[31] = 2;
        v.push(two);
        let mut nm1 = GROUP_ORDER_BYTES;
        nm1[31] -= 1;
        v.push(nm1);
        let mut nm2 = GROUP_ORDER_BYTES;
        nm2[31] -= 2;
        v.push(nm2);
        for k in 0..256 {
            let mut b = [0u8; 32];
            b[31 - k / 8] = 1 << (k % 8);
            if b < GROUP_ORDER_BYTES {
                v.push(b);
            }
        }
        let mut rng = SplitMix64(0xbac4_e2d0_0001);
        for i in 0..512 {
            let mut b = [0u8; 32];
            rng.fill(&mut b);
            match i % 4 {
                1 => b[..20].fill(0),
                2 => b[..16].fill(0xff),
                3 => b[8..].fill(0),
                _ => {}
            }
            let s = <Scalar as Reduce<FieldBytes>>::reduce(&b.into());
            if !bool::from(s.is_zero()) {
                v.push(s.to_repr().into());
            }
        }
        v
    }

    /// The seam's inverse equals k256's `invert_vartime` on every input,
    /// through the vartime crate and through the forced fallback alike,
    /// and x * w = 1.
    #[test]
    fn scalar_inverse_matches_k256_on_both_paths() {
        let inputs = inputs();
        assert!(inputs.len() > 700);
        for x in &inputs {
            let want = reference(x);
            let w = scalar_inverse(x);
            let wf = force_fallback(|| scalar_inverse(x));
            assert_eq!(
                <[u8; 32]>::from(w.to_repr()),
                want,
                "vartime path, x {x:02x?}"
            );
            assert_eq!(
                <[u8; 32]>::from(wf.to_repr()),
                want,
                "forced path, x {x:02x?}"
            );
            let s = Option::<Scalar>::from(Scalar::from_repr((*x).into())).expect("below N");
            assert!(bool::from((s * w - Scalar::ONE).is_zero()));
        }
    }

    /// The forced path really is k256's: the switch is per thread and
    /// clears itself, and the vartime crate alone gives the same bytes.
    #[test]
    fn the_switch_forces_and_clears() {
        let x = inputs()[10];
        assert!(!forced_fallback());
        assert!(force_fallback(forced_fallback));
        assert!(!forced_fallback());
        let vt = vartime::Scalar::from_be_bytes(&x)
            .and_then(|s| s.try_inverse_var())
            .expect("the vartime inverse")
            .to_be_bytes();
        assert_eq!(vt, reference(&x));
        assert_eq!(<[u8; 32]>::from(scalar_inverse(&x).to_repr()), vt);
    }

    /// Zero, which neither caller passes, asserts in builds with debug
    /// assertions and gives zero on both paths without them, so a caller
    /// bug fails verification rather than the node.
    #[test]
    #[cfg_attr(debug_assertions, should_panic(expected = "scalar_inverse of zero"))]
    fn zero_asserts_or_gives_zero() {
        assert!(bool::from(scalar_inverse(&[0; 32]).is_zero()));
        assert!(bool::from(
            force_fallback(|| scalar_inverse(&[0; 32])).is_zero()
        ));
    }
}
