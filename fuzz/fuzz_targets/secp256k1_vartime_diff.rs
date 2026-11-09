// SPDX-License-Identifier: ISC
//! Differential fuzz target for dcroxide-secp256k1-vartime against k256
//! and fiat-crypto, in process, with no oracle.  The first input byte
//! chooses the level, by its low bit, and the rest is the level's input.
//!
//! Scalar level (even), two 32-byte big-endian values a and b:
//! `from_be_bytes` must accept exactly what k256's `from_repr` accepts
//! (values below N) and agree on the value; `reduce_be_bytes` must equal
//! k256's reduction; on the reduced values, a + b, a * b and -a must equal
//! k256's, a's bytes must parse back to a, and `try_inverse_var` must
//! return a value (its cap is never reached) equal to k256's
//! `invert_vartime` and constant-time `invert`, with the inverse of zero
//! zero.
//!
//! Field level (odd), through the `internals` feature: a magnitude byte m
//! (1 to 8) and two values of five 64-bit little-endian limbs each, each
//! limb cut to the bound magnitude m allows, so every value is one the
//! field's contracts admit.  `mul` and `sqr` must equal fiat-crypto's
//! Dettman multiplication and squaring limb for limb and k256's product by
//! value; `add_assign`, `negate_unchecked(m)`, `normalize_var` and
//! `normalizes_to_zero` must agree with k256 by value.  The first 32 bytes
//! of the limbs, big-endian, then go through the tracked `Fe`: the limit
//! parse against k256's, `get_b32`, `is_odd`, `sqrt` (existence as k256's,
//! the root squaring back to the value or to its negation) and `equal`; and
//! through key decompression, with the magnitude byte's low bit as the
//! parity: `Affine::decompress_var` must give k256's point or k256's
//! `None`, and the point must come back from `from_be_coordinates`.
//!
//! Any difference panics with the inputs.  Builds with debug assertions
//! also run the field's magnitude bookkeeping and `fe_verify`.

#![no_main]

use dcroxide_secp256k1_vartime::{Affine, Fe, FeRaw, Scalar};
use fiat_crypto::secp256k1_dettman_64::{
    fiat_secp256k1_dettman_mul, fiat_secp256k1_dettman_square,
};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::hazmat::FieldArithmetic;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::{AffineCoordinates, DecompressPoint};
use k256::elliptic_curve::subtle::Choice;
use k256::{AffinePoint, FieldBytes};
use libfuzzer_sys::fuzz_target;

/// k256's field element.
type KFe = <k256::Secp256k1 as FieldArithmetic>::FieldElement;

/// k256's scalar as big-endian bytes.
fn kb(s: &k256::Scalar) -> [u8; 32] {
    s.to_repr().into()
}

/// k256's field element as big-endian bytes.
fn kfb(f: &KFe) -> [u8; 32] {
    f.to_repr().into()
}

fn scalar_level(a: &[u8; 32], b: &[u8; 32]) {
    // Parsing: exactly the values below N, with the same value.
    for x in [a, b] {
        let ours = Scalar::from_be_bytes(x);
        let theirs = Option::<k256::Scalar>::from(k256::Scalar::from_repr((*x).into()));
        assert_eq!(
            ours.map(|s| s.to_be_bytes()),
            theirs.map(|s| kb(&s)),
            "from_be_bytes {x:02x?}"
        );
    }
    let (ra, rb) = (Scalar::reduce_be_bytes(a), Scalar::reduce_be_bytes(b));
    let ka = <k256::Scalar as Reduce<FieldBytes>>::reduce(&(*a).into());
    let kbb = <k256::Scalar as Reduce<FieldBytes>>::reduce(&(*b).into());
    assert_eq!(ra.to_be_bytes(), kb(&ka), "reduce_be_bytes {a:02x?}");
    assert_eq!(rb.to_be_bytes(), kb(&kbb), "reduce_be_bytes {b:02x?}");
    assert_eq!(
        Scalar::from_be_bytes(&ra.to_be_bytes()),
        Some(ra),
        "round trip {a:02x?}"
    );

    assert_eq!(
        (ra + rb).to_be_bytes(),
        kb(&(ka + kbb)),
        "add {a:02x?} {b:02x?}"
    );
    assert_eq!(
        (ra * rb).to_be_bytes(),
        kb(&(ka * kbb)),
        "mul {a:02x?} {b:02x?}"
    );
    assert_eq!((-ra).to_be_bytes(), kb(&(-ka)), "neg {a:02x?}");

    for (x, kx, raw) in [(ra, ka, a), (rb, kbb, b)] {
        let inv = x
            .try_inverse_var()
            .expect("the inverse stays within its cap");
        if x.is_zero() {
            assert!(inv.is_zero(), "inverse of zero {raw:02x?}");
            continue;
        }
        let kv = Option::<k256::Scalar>::from(kx.invert_vartime()).expect("nonzero");
        let kc = Option::<k256::Scalar>::from(kx.invert()).expect("nonzero");
        assert_eq!(
            inv.to_be_bytes(),
            kb(&kv),
            "inverse vs invert_vartime {raw:02x?}"
        );
        assert_eq!(inv.to_be_bytes(), kb(&kc), "inverse vs invert {raw:02x?}");
    }
}

/// Five limbs from 40 little-endian bytes, each cut to magnitude m's bound
/// (n\[0..3\] <= 2m(2^52-1), n\[4\] <= 2m(2^48-1)).
fn limbs_at(bytes: &[u8], m: u64) -> [u64; 5] {
    let mut n = [0u64; 5];
    for (i, l) in n.iter_mut().enumerate() {
        let v = u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().expect("8 bytes"));
        let bound = if i < 4 {
            0xF_FFFF_FFFF_FFFF * 2 * m
        } else {
            0xFFFF_FFFF_FFFF * 2 * m
        };
        *l = v % (bound + 1);
    }
    n
}

/// The value of five limbs mod p, on k256's field: sum n\[i\] * 2^(52i).
fn kval(n: &[u64; 5]) -> KFe {
    let base = KFe::from(1u64 << 52);
    let mut acc = KFe::from(0u64);
    for l in n.iter().rev() {
        acc = acc * base + KFe::from(*l);
    }
    acc.normalize()
}

/// The bytes of a raw value after `normalize_var`.
fn raw_bytes(r: &FeRaw) -> [u8; 32] {
    let mut t = *r;
    t.normalize_var();
    let (u, ok) = FeRaw::set_b32_limit(&t.get_b32());
    assert!(
        ok && u.n == t.n,
        "normalize_var left {:x?} unnormalized",
        t.n
    );
    t.get_b32()
}

fn field_level(m_byte: u8, a_bytes: &[u8], b_bytes: &[u8]) {
    let m = 1 + u64::from(m_byte % 8);
    let a = FeRaw {
        n: limbs_at(a_bytes, m),
    };
    let b = FeRaw {
        n: limbs_at(b_bytes, m),
    };
    let (ka, kbv) = (kval(&a.n), kval(&b.n));

    // The kernel, limb for limb against fiat and by value against k256.
    let mut f = [0u64; 5];
    fiat_secp256k1_dettman_mul(&mut f, &a.n, &b.n);
    let p = a.mul(&b);
    assert_eq!(p.n, f, "mul limbs {:x?} {:x?}", a.n, b.n);
    assert_eq!(
        raw_bytes(&p),
        kfb(&(ka * kbv)),
        "mul value {:x?} {:x?}",
        a.n,
        b.n
    );
    fiat_secp256k1_dettman_square(&mut f, &a.n);
    let s = a.sqr();
    assert_eq!(s.n, f, "sqr limbs {:x?}", a.n);
    assert_eq!(raw_bytes(&s), kfb(&ka.square()), "sqr value {:x?}", a.n);

    // Addition (magnitude 2m <= 16), negation at magnitude m, the zero test.
    let mut sum = a;
    sum.add_assign(&b);
    assert_eq!(
        raw_bytes(&sum),
        kfb(&(ka + kbv)),
        "add {:x?} {:x?}",
        a.n,
        b.n
    );
    let neg = a.negate_unchecked(u32::try_from(m).expect("m <= 8"));
    assert_eq!(raw_bytes(&neg), kfb(&(-ka)), "negate {:x?}", a.n);
    assert_eq!(
        a.normalizes_to_zero(),
        bool::from(ka.normalizes_to_zero()),
        "normalizes_to_zero {:x?}",
        a.n
    );

    // The tracked element and decompression, on 32 input bytes.
    let x: [u8; 32] = a_bytes[..32].try_into().expect("32 bytes");
    let ours = Fe::set_b32_limit(&x);
    let theirs = Option::<KFe>::from(KFe::from_repr(x.into()));
    assert_eq!(ours.is_some(), theirs.is_some(), "set_b32_limit {x:02x?}");
    if let (Some(fx), Some(kx)) = (ours, theirs) {
        assert_eq!(fx.get_b32(), x);
        assert_eq!(fx.is_odd(), x[31] & 1 == 1);
        let (r, ok) = fx.sqrt();
        let kr = Option::<KFe>::from(kx.sqrt());
        assert_eq!(ok, kr.is_some(), "sqrt existence {x:02x?}");
        let mut r2 = r.sqr();
        r2.normalize_var();
        let want = if ok { kx } else { -kx };
        assert_eq!(r2.get_b32(), kfb(&want.normalize()), "sqrt {x:02x?}");
        assert!(r2.equal(&fx) == ok, "equal {x:02x?}");
    }
    let odd = m_byte & 1 == 1;
    let point = Affine::decompress_var(&x, odd);
    let kp = Option::<AffinePoint>::from(AffinePoint::decompress(
        &x.into(),
        Choice::from(u8::from(odd)),
    ));
    assert_eq!(
        point.map(|p| p.to_be_bytes()),
        kp.map(|p| (p.x().into(), p.y().into())),
        "decompress_var {x:02x?} odd {odd}"
    );
    if let Some(p) = point {
        let (px, py) = p.to_be_bytes();
        assert_eq!(p.y_is_odd(), odd);
        assert!(Affine::from_be_coordinates(&px, &py) == Some(p));
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&level, rest)) = data.split_first() else {
        return;
    };
    if level & 1 == 0 {
        if rest.len() < 64 {
            return;
        }
        let a: [u8; 32] = rest[..32].try_into().expect("32 bytes");
        let b: [u8; 32] = rest[32..64].try_into().expect("32 bytes");
        scalar_level(&a, &b);
    } else {
        if rest.len() < 81 {
            return;
        }
        field_level(rest[0], &rest[1..41], &rest[41..81]);
    }
});
