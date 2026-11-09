// SPDX-License-Identifier: ISC
//! The seam between this crate's dcrd-ordered steps and the variable-time
//! arithmetic they borrow from `dcroxide-secp256k1-vartime` (ADR-0016).
//! This is the only module of the crate that names that crate, so another
//! backend, k256's code before it or a libsecp256k1 binding, slots in, as
//! code, by changing this module alone.  Only the verification, recovery
//! and key-parsing functions name this module, so no signing function
//! reaches it; `tests/vartime_boundary.rs` holds both rules.
//!
//! Every function here takes public values only, and none can panic: when
//! the vartime crate declines (its safegcd loop past an iteration cap, a
//! case its proof rules out) or hands back a value k256 refuses or the
//! seam's own check rejects, the seam computes the answer on k256 instead,
//! as the code before it did, and debug builds assert.  An assertion in
//! release would be an outage under `panic = "abort"`.  Tests can force
//! that path, which production never takes, so it is tested too.
//!
//! ECDSA verification's sum, u1*G + u2*Q, comes back as an opaque [`Sum`]
//! that answers dcrd's steps 6 to 10 (is it infinity, is its x this
//! value) without the caller knowing which backend computed it.  Until
//! recovery, Schnorr verification and the key type move, their callers
//! compute on k256's types, so the seam returns those, converting inside
//! where the conversion and its fallback can sit together.

use dcroxide_secp256k1_vartime as vartime;
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::ops::{MulByGeneratorVartime, Reduce};
use k256::elliptic_curve::point::{AffineCoordinates, BatchNormalize, DecompressPoint};
use k256::elliptic_curve::subtle::Choice;
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};

use super::PublicKey;

/// X = u1*G + u2*Q of ECDSA verification, from whichever backend computed
/// it.  The caller asks only what dcrd's steps 6 to 10 ask.
pub(crate) struct Sum(SumInner);

/// The two backends' forms of the sum.
enum SumInner {
    /// The vartime crate's Jacobian point.
    Vt(vartime::Point),
    /// k256's sum, normalized once; `None` is the identity.
    K256(Option<AffinePoint>),
}

impl Sum {
    /// Whether X is the point at infinity (dcrd's step 6).
    pub(crate) fn is_infinity(&self) -> bool {
        match &self.0 {
            SumInner::Vt(p) => p.is_infinity(),
            SumInner::K256(a) => a.is_none(),
        }
    }

    /// Whether X's affine x equals x, given big-endian and below P: dcrd's
    /// steps 8 and 10, false at infinity.  The vartime crate's point
    /// answers as dcrd does, X == x * Z^2, with no inversion.  k256 keeps
    /// its projective coordinates private, so its sum was normalized once
    /// and its affine x is compared instead.
    pub(crate) fn x_equals(&self, x_be: &[u8; 32]) -> bool {
        match &self.0 {
            SumInner::Vt(p) => p.x_equals_var(x_be),
            SumInner::K256(a) => a.is_some_and(|a| <[u8; 32]>::from(a.x()) == *x_be),
        }
    }
}

/// ECDSA verification's steps 2 to 5 for a signature (r, s) with both in
/// [1, N-1], as the caller's step 1 and the signature's construction
/// establish: e = H mod N, w = s^-1, u1 = e*w, u2 = r*w and X = u1*G +
/// u2*Q, dcrd's order, all on the vartime crate's port of libsecp256k1
/// (its safegcd inverse, its scalar products and its Straus loop over
/// static generator tables).
///
/// Should the vartime crate decline anywhere (r or s not below N, the
/// inverse's cap, the key's conversion, the wNAF builder's guard; none
/// happens for valid inputs), the sum is k256's combined multiply and one
/// `batch_normalize_vartime` instead, the code the last gate soak ran
/// (stage 2a's fallback), and debug builds assert.  Builds with debug
/// assertions also compute k256's sum every time and stop if the two
/// disagree on infinity or on x; that check only reads, so they compute
/// what release computes.
pub(crate) fn ecdsa_mul_g_add(hash: &[u8; 32], r: &[u8; 32], s: &[u8; 32], q: &PublicKey) -> Sum {
    if !forced_fallback() {
        let x = vartime_sum(hash, r, s, q).filter(|_| !forced_decline());
        debug_assert!(
            x.is_some(),
            "the vartime crate declined ECDSA verification's sum"
        );
        if let Some(x) = x {
            let sum = Sum(SumInner::Vt(x));
            #[cfg(debug_assertions)]
            cross_check(&sum, &k256_sum(hash, r, s, q));
            return sum;
        }
    }
    k256_sum(hash, r, s, q)
}

/// Steps 2 to 5 on the vartime crate; `None` wherever it declines.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "the vartime crate's Scalar operators are arithmetic mod N"
)]
fn vartime_sum(
    hash: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    q: &PublicKey,
) -> Option<vartime::Point> {
    let r = vartime::Scalar::from_be_bytes(r)?;
    let s = vartime::Scalar::from_be_bytes(s)?;
    let e = vartime::Scalar::reduce_be_bytes(hash);
    let w = s.try_inverse_var()?;
    let u1 = e * w;
    let u2 = r * w;
    #[cfg(test)]
    let u2 = if skewed_sum() {
        let mut one = [0u8; 32];
        one[31] = 1;
        u2 + vartime::Scalar::reduce_be_bytes(&one)
    } else {
        u2
    };
    mul_g_add(&u1, &u2, q)
}

/// u1*G + u2*Q on the vartime crate: the key enters through
/// `from_be_coordinates`, which checks the curve equation again (k256 has
/// checked it), and the multiply is `ecmult_var`.  The piece recovery and
/// Schnorr verification will share.
fn mul_g_add(u1: &vartime::Scalar, u2: &vartime::Scalar, q: &PublicKey) -> Option<vartime::Point> {
    let k = q.serialize_uncompressed();
    let (x, y) = k[1..].split_first_chunk::<32>()?;
    let q = vartime::Affine::from_be_coordinates(x, y.first_chunk::<32>()?)?;
    vartime::ecmult_var(&q, u2, u1)
}

/// Steps 2 to 5 on k256, the code the last gate soak ran as stage 2a's
/// fallback: its `invert_vartime`, its scalar products, its combined multiply
/// `mul_by_generator_and_mul_add_vartime` and one `batch_normalize_vartime`.
/// Should r or s not be below N, which the caller rules out, the sum is
/// the identity, so verification fails at step 6, and debug builds
/// assert.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "k256's Scalar operators are arithmetic mod N"
)]
fn k256_sum(hash: &[u8; 32], r: &[u8; 32], s: &[u8; 32], q: &PublicKey) -> Sum {
    let r = Option::<Scalar>::from(Scalar::from_repr((*r).into()));
    let w = Option::<Scalar>::from(Scalar::from_repr((*s).into()))
        .and_then(|s| Option::<Scalar>::from(s.invert_vartime()));
    let (Some(r), Some(w)) = (r, w) else {
        debug_assert!(false, "k256_sum: r or s not in [1, N-1]");
        return Sum(SumInner::K256(None));
    };
    let e = <Scalar as Reduce<FieldBytes>>::reduce(&(*hash).into());
    let x = ProjectivePoint::mul_by_generator_and_mul_add_vartime(
        &(e * w),
        &(r * w),
        &q.as_k256_point(),
    );
    if bool::from(x.is_identity()) {
        return Sum(SumInner::K256(None));
    }
    let [a] =
        <ProjectivePoint as BatchNormalize<[ProjectivePoint; 1]>>::batch_normalize_vartime(&[x]);
    Sum(SumInner::K256(Some(a)))
}

/// Builds with debug assertions: the vartime crate's sum agrees with
/// k256's on infinity and, when finite, on x.  Reads and asserts only.
#[cfg(debug_assertions)]
fn cross_check(vt: &Sum, k: &Sum) {
    assert_eq!(
        vt.is_infinity(),
        k.is_infinity(),
        "ECDSA verification's sum: infinity differs from k256's"
    );
    if let SumInner::K256(Some(a)) = &k.0 {
        assert!(
            vt.x_equals(&a.x().into()),
            "ECDSA verification's sum: x differs from k256's"
        );
    }
}

/// w = x^-1 mod N for a nonzero x below N, given big-endian, in variable
/// time, as dcrd's `ModNScalar.InverseValNonConst`: the vartime crate's
/// port of libsecp256k1's safegcd, else k256's `invert_vartime`.  The
/// caller, compact recovery's step 7, has established 1 <= x < N.  Should
/// x be zero or not below N anyway, the result is zero, which makes
/// recovery fail at step 10, and debug builds assert.
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

/// The curve point whose x, below P, is given big-endian and whose y has
/// the oddness `odd`, or `None` when x^3 + 7 has no square root, so that
/// no point has this x: dcrd's `DecompressY`, on the vartime crate's port
/// of libsecp256k1's square root, which normalizes the root before reading
/// its oddness and again after negating it, as dcrd does.  Both callers,
/// compressed key parsing and compact recovery's steps 4 and 5, have
/// established x < P.
///
/// The vartime crate's `None` is the answer, not a reason to fall back;
/// builds with debug assertions hold it to k256's.  Its point must have
/// the x and the oddness asked for, two byte compares, and reaches k256
/// through `from_coordinates`, which checks the curve equation again;
/// should either check refuse it, the seam decompresses on k256 instead,
/// the code before this, and debug builds assert.
pub(crate) fn decompress(x: &[u8; 32], odd: bool) -> Option<AffinePoint> {
    if !forced_fallback() {
        let Some(a) = vartime::Affine::decompress_var(x, odd ^ wrong_oddness()) else {
            debug_assert!(
                k256_decompress(x, odd).is_none(),
                "the vartime crate found no point for an x k256 decompresses"
            );
            return None;
        };
        let (ax, ay) = a.to_be_bytes();
        let p = if ax == *x && (ay[31] & 1 == 1) == odd {
            Option::<AffinePoint>::from(AffinePoint::from_coordinates(&ax.into(), &ay.into()))
        } else {
            None
        };
        debug_assert!(
            p.is_some(),
            "k256 refused the vartime crate's point, or its x or oddness differ"
        );
        if p.is_some() {
            return p;
        }
    }
    k256_decompress(x, odd)
}

/// k256's decompression, the code before the vartime crate's.
fn k256_decompress(x: &[u8; 32], odd: bool) -> Option<AffinePoint> {
    Option::<AffinePoint>::from(AffinePoint::decompress(
        &(*x).into(),
        Choice::from(u8::from(odd)),
    ))
}

#[cfg(test)]
std::thread_local! {
    /// Set by [`tests::force_fallback`]: the seam takes k256's path.
    static FORCE_FALLBACK: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    /// Set by [`tests::force_wrong_oddness`]: the seam asks the vartime
    /// crate for the other oddness, as a port bug might answer.
    static WRONG_ODDNESS: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    /// Set by [`tests::force_decline`]: the vartime crate's sum counts as
    /// declined.
    static FORCE_DECLINE: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    /// Set by [`tests::skew_sum`]: the vartime crate is given u2 + 1, as a
    /// port bug might compute, so the debug cross-check must stop it.
    static SKEW_SUM: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// Whether a test has the vartime crate's sum count as declined.
#[cfg(test)]
fn forced_decline() -> bool {
    FORCE_DECLINE.with(core::cell::Cell::get)
}

/// Whether a test has the vartime crate given a skewed u2.
#[cfg(test)]
fn skewed_sum() -> bool {
    SKEW_SUM.with(core::cell::Cell::get)
}

/// Production never declines a sum it has.
#[cfg(not(test))]
#[inline(always)]
fn forced_decline() -> bool {
    false
}

/// Whether a test has forced k256's path on this thread.
#[cfg(test)]
fn forced_fallback() -> bool {
    FORCE_FALLBACK.with(core::cell::Cell::get)
}

/// Whether a test has the seam ask for the wrong oddness on this thread.
#[cfg(test)]
fn wrong_oddness() -> bool {
    WRONG_ODDNESS.with(core::cell::Cell::get)
}

/// Production never forces the fallback.
#[cfg(not(test))]
#[inline(always)]
fn forced_fallback() -> bool {
    false
}

/// Production asks for the oddness it was given.
#[cfg(not(test))]
#[inline(always)]
fn wrong_oddness() -> bool {
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

    use crate::secp256k1::{FIELD_PRIME_BYTES, GROUP_ORDER_BYTES};

    /// Runs `f` with the seam forced onto k256's path on this thread.
    pub(super) fn force_fallback<T>(f: impl FnOnce() -> T) -> T {
        FORCE_FALLBACK.with(|c| c.set(true));
        let r = f();
        FORCE_FALLBACK.with(|c| c.set(false));
        r
    }

    /// Runs `f` with the seam asking the vartime crate for the other
    /// oddness on this thread.
    pub(super) fn force_wrong_oddness<T>(f: impl FnOnce() -> T) -> T {
        WRONG_ODDNESS.with(|c| c.set(true));
        let r = f();
        WRONG_ODDNESS.with(|c| c.set(false));
        r
    }

    /// Runs `f` with the vartime crate's ECDSA sum counted as declined on
    /// this thread.
    fn force_decline<T>(f: impl FnOnce() -> T) -> T {
        FORCE_DECLINE.with(|c| c.set(true));
        let r = f();
        FORCE_DECLINE.with(|c| c.set(false));
        r
    }

    /// Runs `f` with the vartime crate given u2 + 1 on this thread.
    #[cfg(debug_assertions)]
    fn skew_sum<T>(f: impl FnOnce() -> T) -> T {
        SKEW_SUM.with(|c| c.set(true));
        let r = f();
        SKEW_SUM.with(|c| c.set(false));
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

    /// The forced path really is k256's: the switches are per thread and
    /// clear themselves, and the vartime crate alone gives the same bytes.
    #[test]
    fn the_switch_forces_and_clears() {
        let x = inputs()[10];
        assert!(!forced_fallback());
        assert!(force_fallback(forced_fallback));
        assert!(!forced_fallback());
        assert!(force_decline(forced_decline));
        assert!(!forced_decline());
        assert!(!skewed_sum());
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

    /// k256's own decompression, the reference.
    fn reference_decompress(x: &[u8; 32], odd: bool) -> Option<AffinePoint> {
        Option::<AffinePoint>::from(AffinePoint::decompress(
            &(*x).into(),
            Choice::from(u8::from(odd)),
        ))
    }

    /// x values below P for decompression: 0, 1, 2, 7, P-1, P-2, P-3 (the
    /// largest x with a point), P-N and N (the recovery boundary), every
    /// 2^k, and random ones, uniform and with long runs of zero or one
    /// bits; about half have no point.
    fn decompress_inputs() -> Vec<[u8; 32]> {
        let small = |v: u8| {
            let mut b = [0u8; 32];
            b[31] = v;
            b
        };
        let below_p = |d: u8| {
            let mut b = FIELD_PRIME_BYTES;
            b[31] -= d;
            b
        };
        let mut v = vec![
            small(0),
            small(1),
            small(2),
            small(7),
            below_p(1),
            below_p(2),
            below_p(3),
            crate::secp256k1::PRIME_MINUS_ORDER_BYTES,
            GROUP_ORDER_BYTES,
        ];
        for k in 0..256 {
            let mut b = [0u8; 32];
            b[31 - k / 8] = 1 << (k % 8);
            v.push(b);
        }
        let mut rng = SplitMix64(0xbac4_e2d0_0002);
        while v.len() < 1024 {
            let mut b = [0u8; 32];
            rng.fill(&mut b);
            match v.len() % 4 {
                1 => b[..20].fill(0),
                2 => b[..16].fill(0xff),
                3 => b[8..].fill(0),
                _ => {}
            }
            if b < FIELD_PRIME_BYTES {
                v.push(b);
            }
        }
        v
    }

    /// The seam's decompression equals k256's `decompress`, point for
    /// point and None for None, through the vartime crate and through the
    /// forced fallback, for both oddnesses of every input.
    #[test]
    fn decompress_matches_k256_on_both_paths() {
        let (mut points, mut none) = (0u32, 0u32);
        for x in &decompress_inputs() {
            for odd in [false, true] {
                let want = reference_decompress(x, odd);
                let got = decompress(x, odd);
                let forced = force_fallback(|| decompress(x, odd));
                assert_eq!(got, want, "vartime path, x {x:02x?} odd {odd}");
                assert_eq!(forced, want, "forced path, x {x:02x?} odd {odd}");
                match got {
                    Some(p) => {
                        points += 1;
                        assert_eq!(<[u8; 32]>::from(p.x()), *x);
                        assert_eq!(bool::from(p.y_is_odd()), odd);
                    }
                    None => none += 1,
                }
            }
        }
        // x = 0 has no point (7 is not a square mod P), and P-3 is the
        // largest x below P that has one.
        assert!(decompress(&[0; 32], false).is_none());
        let mut pm3 = FIELD_PRIME_BYTES;
        pm3[31] -= 3;
        assert!(decompress(&pm3, true).is_some());
        assert!(points > 700 && none > 700, "{points} points, {none} none");
    }

    /// The seam's consistency check: a point of the other oddness from the
    /// vartime crate, as a port bug might give, is not passed on.  Builds
    /// with debug assertions stop on it; without them the seam gives
    /// k256's point, and a `None` stays `None`.
    #[test]
    #[cfg_attr(
        debug_assertions,
        should_panic(expected = "or its x or oddness differ")
    )]
    fn a_point_of_the_wrong_oddness_is_not_passed_on() {
        for x in decompress_inputs().iter().take(64) {
            for odd in [false, true] {
                let got = force_wrong_oddness(|| decompress(x, odd));
                assert_eq!(got, reference_decompress(x, odd), "x {x:02x?} odd {odd}");
            }
        }
        assert!(!wrong_oddness());
    }

    // ---------------------------------------------------------------------
    // ECDSA verification's sum.

    use k256::elliptic_curve::group::CurveAffine;

    use crate::secp256k1::ecdsa::{Signature, VerifyStep, sign};
    use crate::secp256k1::{PRIME_MINUS_ORDER_BYTES, PrivateKey};

    /// The step verification decides at, through the vartime crate and
    /// through the forced k256 arm; both must agree.
    fn step_both(sig: &Signature, hash: &[u8; 32], key: &PublicKey) -> VerifyStep {
        let vt = sig.verify_detailed(hash, key);
        let k = force_fallback(|| sig.verify_detailed(hash, key));
        assert_eq!(vt, k, "the two arms disagree");
        vt
    }

    /// A k256 scalar as big-endian bytes.
    fn be(x: &Scalar) -> [u8; 32] {
        x.to_repr().into()
    }

    /// A random nonzero k256 scalar.
    fn rand_scalar(rng: &mut SplitMix64) -> Scalar {
        loop {
            let mut b = [0u8; 32];
            rng.fill(&mut b);
            let s = <Scalar as Reduce<FieldBytes>>::reduce(&b.into());
            if !bool::from(s.is_zero()) {
                return s;
            }
        }
    }

    /// The signature, hash and key that make verification compute exactly
    /// (u1, u2) and reach X = u1*G + u2*Q with the given r: Q = (X -
    /// u1*G) / u2, s = r / u2, e = u1 * s (below N, so the hash's
    /// reduction keeps it).  `None` when Q would be infinity.
    fn sig_for(
        x: &ProjectivePoint,
        r: &Scalar,
        u1: &Scalar,
        u2: &Scalar,
    ) -> Option<(Signature, [u8; 32], PublicKey)> {
        let u2i = Option::<Scalar>::from(u2.invert_vartime())?;
        let q = ((*x - ProjectivePoint::GENERATOR * u1) * u2i).to_affine();
        if bool::from(q.is_identity()) {
            return None;
        }
        let s = *r * u2i;
        let e = *u1 * s;
        Some((
            Signature::new(be(r), be(&s))?,
            be(&e),
            PublicKey::from_affine(q),
        ))
    }

    /// The point with x and the given oddness, by k256.
    fn point_at(x: &[u8; 32], odd: bool) -> Option<ProjectivePoint> {
        reference_decompress(x, odd).map(ProjectivePoint::from)
    }

    /// The first x at or above `from` that has a point, as bytes and the
    /// point; `from` advances by one each try.
    fn first_point_from(mut from: [u8; 32]) -> ([u8; 32], ProjectivePoint) {
        loop {
            if let Some(p) = point_at(&from, from[31] & 1 == 1) {
                return (from, p);
            }
            let mut i = 31;
            loop {
                from[i] = from[i].wrapping_add(1);
                if from[i] != 0 || i == 0 {
                    break;
                }
                i -= 1;
            }
        }
    }

    /// Signatures signed by k256 (dcrec's `sign`), their high-S twins, a
    /// hash at or above N and a hash equal to N (e = 0), and tampered
    /// hashes, r, s and keys: the vartime crate's sum and k256's give the
    /// same step.
    #[test]
    fn ecdsa_sum_matches_k256_on_both_paths() {
        let mut rng = SplitMix64(0xbac4_e2d0_0003);
        let mut steps = [0u32; 6];
        for i in 0..96 {
            let mut d = [0u8; 32];
            rng.fill(&mut d);
            let Some(key) = PrivateKey::from_bytes(&d) else {
                continue;
            };
            let pk = key.public_key();
            let mut hash = [0u8; 32];
            rng.fill(&mut hash);
            match i % 8 {
                1 => hash = GROUP_ORDER_BYTES,
                2 => hash[..4].fill(0xff),
                _ => {}
            }
            let sig = sign(&key, &hash);
            let high = Signature::new(
                *sig.r_bytes(),
                crate::secp256k1::negate_mod_n(sig.s_bytes()),
            )
            .expect("below N");
            let other = PrivateKey::from_bytes(&[7; 32])
                .expect("a key")
                .public_key();
            let mut bad_hash = hash;
            bad_hash[31] ^= 1;
            let mut r1 = *sig.r_bytes();
            r1[31] ^= 1;
            let mut s1 = *sig.s_bytes();
            s1[31] ^= 1;
            assert!(step_both(&sig, &hash, &pk).accepts());
            assert!(step_both(&high, &hash, &pk).accepts());
            for (sg, h, k) in [
                (sig, bad_hash, pk),
                (sig, hash, other),
                (
                    Signature::new(r1, *sig.s_bytes()).expect("below N"),
                    hash,
                    pk,
                ),
                (
                    Signature::new(*sig.r_bytes(), s1).expect("below N"),
                    hash,
                    pk,
                ),
            ] {
                let st = step_both(&sg, &h, &k);
                assert!(!st.accepts());
                steps[st as usize] += 1;
            }
        }
        // A signer's r is almost never below P - N, so tampering rejects
        // at step 9.
        assert!(steps[VerifyStep::Step9Reject as usize] > 0);
    }

    /// Every step verification can decide at, constructed, through both
    /// arms: step 6 (Q = -(u1/u2)G, so X is infinity); step 8 with X.x
    /// random below N and with X.x in [P - N, N); step 9 (r at or above P - N,
    /// X.x not r); step 10 accepting (X.x in [N, N + 2^32), r = X.x - N);
    /// step 10 rejecting (r below P - N, X.x neither r nor r + N).
    #[test]
    fn each_verify_step_on_both_paths() {
        let mut rng = SplitMix64(0xbac4_e2d0_0004);
        let g = ProjectivePoint::GENERATOR;
        let sc = |b: &[u8; 32]| Option::<Scalar>::from(Scalar::from_repr((*b).into()));
        let mut seen = [0u32; 6];
        for _ in 0..16 {
            let (u1, u2) = (rand_scalar(&mut rng), rand_scalar(&mut rng));

            // Step 6: Q = -(u1/u2)G, any r.
            let u2i = u2.invert_vartime().expect("nonzero");
            let q = (g * -(u1 * u2i)).to_affine();
            let r = rand_scalar(&mut rng);
            let s = r * u2i;
            let sig = Signature::new(be(&r), be(&s)).expect("below N");
            let st = step_both(&sig, &be(&(u1 * s)), &PublicKey::from_affine(q));
            assert_eq!(st, VerifyStep::Step6Infinity);
            seen[st as usize] += 1;

            // Step 8, X.x below N (r = X.x).
            let x = g * rand_scalar(&mut rng);
            let xb: [u8; 32] = x.to_affine().x().into();
            if let Some(r) = sc(&xb)
                && let Some((sig, h, k)) = sig_for(&x, &r, &u1, &u2)
            {
                assert_eq!(step_both(&sig, &h, &k), VerifyStep::Step8Accept);
                seen[VerifyStep::Step8Accept as usize] += 1;
            }

            // Step 9: r at or above P - N, X.x random.
            // P - N's byte 30 is 0xba, so this adds up to 0x40 there
            // without a carry.
            let mut rb = PRIME_MINUS_ORDER_BYTES;
            rb[30] += (rng.next_u64() % 0x41) as u8;
            let r = sc(&rb).expect("below N");
            if let Some((sig, h, k)) = sig_for(&(g * rand_scalar(&mut rng)), &r, &u1, &u2) {
                assert_eq!(step_both(&sig, &h, &k), VerifyStep::Step9Reject);
                seen[VerifyStep::Step9Reject as usize] += 1;
            }

            // Step 10 rejecting: r below P - N, X.x random.
            let mut rb = [0u8; 32];
            rng.fill(&mut rb[20..]);
            let r = sc(&rb).expect("below N");
            if let Some((sig, h, k)) = sig_for(&(g * rand_scalar(&mut rng)), &r, &u1, &u2) {
                assert_eq!(step_both(&sig, &h, &k), VerifyStep::Step10Reject);
                seen[VerifyStep::Step10Reject as usize] += 1;
            }
        }

        // Step 8 with X.x in [P - N, N): the first such x with a point.
        let (xb, x) = first_point_from(PRIME_MINUS_ORDER_BYTES);
        let (u1, u2) = (rand_scalar(&mut rng), rand_scalar(&mut rng));
        let (sig, h, k) = sig_for(&x, &sc(&xb).expect("below N"), &u1, &u2).expect("Q");
        assert_eq!(step_both(&sig, &h, &k), VerifyStep::Step8Accept);
        let mut r1 = xb;
        r1[31] = r1[31].wrapping_add(1);
        let (sig, h, k) = sig_for(&x, &sc(&r1).expect("below N"), &u1, &u2).expect("Q");
        assert_eq!(step_both(&sig, &h, &k), VerifyStep::Step9Reject);

        // Step 10 accepting: X.x in [N, N + 2^32), r = X.x - N.
        for start in [1u8, 77, 200] {
            let mut from = GROUP_ORDER_BYTES;
            from[31] = from[31].wrapping_add(start);
            from[30] = from[30].wrapping_add(u8::from(from[31] < start));
            let (xb, x) = first_point_from(from);
            let mut rb = [0u8; 32];
            let (mut borrow, mut i) = (0i16, 31usize);
            loop {
                let d = i16::from(xb[i]) - i16::from(GROUP_ORDER_BYTES[i]) - borrow;
                rb[i] = d.rem_euclid(256) as u8;
                borrow = i16::from(d < 0);
                if i == 0 {
                    break;
                }
                i -= 1;
            }
            assert_eq!(rb[..28], [0u8; 28], "X.x - N is not tiny");
            let r = sc(&rb).expect("below N");
            let (sig, h, k) = sig_for(&x, &r, &u1, &u2).expect("Q");
            assert_eq!(step_both(&sig, &h, &k), VerifyStep::Step10Accept);
            seen[VerifyStep::Step10Accept as usize] += 1;
        }
        for st in [
            VerifyStep::Step6Infinity,
            VerifyStep::Step8Accept,
            VerifyStep::Step9Reject,
            VerifyStep::Step10Accept,
            VerifyStep::Step10Reject,
        ] {
            assert!(seen[st as usize] > 0, "{st:?} never reached");
        }
    }

    /// A sum the vartime crate declines is k256's instead: builds with
    /// debug assertions stop on the decline; without them the step is
    /// k256's.
    #[test]
    #[cfg_attr(
        debug_assertions,
        should_panic(expected = "the vartime crate declined ECDSA verification's sum")
    )]
    fn a_declined_sum_falls_back() {
        let key = PrivateKey::from_bytes(&[3; 32]).expect("a key");
        let hash = [9u8; 32];
        let sig = sign(&key, &hash);
        let pk = key.public_key();
        let declined = force_decline(|| sig.verify_detailed(&hash, &pk));
        assert_eq!(declined, force_fallback(|| sig.verify_detailed(&hash, &pk)));
        assert!(declined.accepts());
    }

    /// The debug cross-check stops a vartime sum that differs from k256's:
    /// here the vartime crate is given u2 + 1.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "ECDSA verification's sum: x differs from k256's")]
    fn the_cross_check_catches_a_skewed_sum() {
        let key = PrivateKey::from_bytes(&[5; 32]).expect("a key");
        let hash = [11u8; 32];
        let sig = sign(&key, &hash);
        let pk = key.public_key();
        let _ = skew_sum(|| sig.verify_detailed(&hash, &pk));
    }

    /// r or s at N, which no caller passes, reaches neither a panic in
    /// release nor a verdict: debug builds stop on the decline, and
    /// without debug assertions the sum is the identity on both arms.
    #[test]
    #[cfg_attr(debug_assertions, should_panic(expected = "declined"))]
    fn out_of_range_inputs_reject_without_panicking() {
        let pk = PrivateKey::from_bytes(&[3; 32])
            .expect("a key")
            .public_key();
        let mut one = [0u8; 32];
        one[31] = 1;
        for (r, s) in [(GROUP_ORDER_BYTES, one), (one, GROUP_ORDER_BYTES)] {
            assert!(ecdsa_mul_g_add(&[1; 32], &r, &s, &pk).is_infinity());
            assert!(force_fallback(|| ecdsa_mul_g_add(&[1; 32], &r, &s, &pk)).is_infinity());
        }
    }

    /// r exactly P - N, the bound of dcrd's step 9: rejected at step 9
    /// when X.x is not r, before r + N = P is formed, and accepted at
    /// step 8 when X.x is P - N (that x has a point).
    #[test]
    fn step_9_at_exactly_p_minus_n() {
        let mut rng = SplitMix64(0xbac4_e2d0_0005);
        let g = ProjectivePoint::GENERATOR;
        let r = Option::<Scalar>::from(Scalar::from_repr(PRIME_MINUS_ORDER_BYTES.into()))
            .expect("below N");
        for _ in 0..8 {
            let (u1, u2) = (rand_scalar(&mut rng), rand_scalar(&mut rng));
            let x = g * rand_scalar(&mut rng);
            if let Some((sig, h, k)) = sig_for(&x, &r, &u1, &u2) {
                assert_eq!(step_both(&sig, &h, &k), VerifyStep::Step9Reject);
            }
        }
        for odd in [false, true] {
            let x = point_at(&PRIME_MINUS_ORDER_BYTES, odd).expect("P - N is an x");
            let (u1, u2) = (rand_scalar(&mut rng), rand_scalar(&mut rng));
            let (sig, h, k) = sig_for(&x, &r, &u1, &u2).expect("Q");
            assert_eq!(step_both(&sig, &h, &k), VerifyStep::Step8Accept);
        }
    }

    /// The forced fallback really skips the vartime crate's sum on ECDSA
    /// verification: with u2 skewed for the vartime crate only, the forced
    /// path still accepts and the debug cross-check never runs.
    #[cfg(debug_assertions)]
    #[test]
    fn the_forced_fallback_skips_the_vartime_sum() {
        let key = PrivateKey::from_bytes(&[5; 32]).expect("a key");
        let hash = [11u8; 32];
        let sig = sign(&key, &hash);
        let pk = key.public_key();
        assert!(force_fallback(|| skew_sum(|| sig.verify_detailed(&hash, &pk))).accepts());
    }
}
