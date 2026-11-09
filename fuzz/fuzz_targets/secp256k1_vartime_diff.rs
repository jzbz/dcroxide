// SPDX-License-Identifier: ISC
//! Differential fuzz target for dcroxide-secp256k1-vartime against k256
//! and fiat-crypto, in process, with no oracle.  The first input byte
//! chooses the level, by its value mod 3, and the rest is the level's
//! input.
//!
//! Scalar level (0), two 32-byte big-endian values a and b:
//! `from_be_bytes` must accept exactly what k256's `from_repr` accepts
//! (values below N) and agree on the value; `reduce_be_bytes` must equal
//! k256's reduction; on the reduced values, a + b, a * b and -a must equal
//! k256's, a's bytes must parse back to a, and `try_inverse_var` must
//! return a value (its cap is never reached) equal to k256's
//! `invert_vartime` and constant-time `invert`, with the inverse of zero
//! zero.
//!
//! Field level (1), through the `internals` feature: a magnitude byte m
//! (1 to 8) and two values of five 64-bit little-endian limbs each, each
//! limb cut to the bound magnitude m allows, so every value is one the
//! field's contracts admit.  `mul` and `sqr` must equal fiat-crypto's
//! Dettman multiplication and squaring limb for limb and k256's product by
//! value; `add_assign`, `negate_unchecked(m)`, `normalize_var` and
//! `normalizes_to_zero` must agree with k256 by value.  The first 32 bytes
//! of the limbs, big-endian, then go through the tracked `Fe`: the limit
//! parse against k256's, `get_b32`, `is_odd`, `sqrt` (existence as k256's,
//! the root squaring back to the value or to its negation), `equal` and
//! `inv_var` (a value, its cap never reached, multiplying back to one, or
//! zero for zero, and equal to k256's inversion); and through key
//! decompression, with the magnitude byte's low bit as the
//! parity: `Affine::decompress_var` must give k256's point or k256's
//! `None`, and the point must come back from `from_be_coordinates`.
//!
//! Multiply level (2), through the public API only: a mode byte, then 96
//! bytes.  Raw mode (even): the key Q is k*G for the first 32 bytes as k
//! (k256's multiply), or, when the mode's second bit is set, the point
//! decompressed from them; na and ng are the next 32 bytes each, reduced
//! mod N.  Structured mode (odd), where the Straus loop's four digit
//! strings collide: Q is one of +-G, +-2G, +-3G, +-lambda G, +-lambda^2 G,
//! +-2^128 G, +-lambda 2^128 G times a small k, and na = a + b*lambda and
//! ng = c + d*2^128 with small signed a to d, all read from the input.
//! `ecmult_var` must return a point; it is infinity exactly when k256's
//! `mul_by_generator_and_mul_add_vartime` gives the identity, and
//! `to_affine_var` must answer (never decline) with `None` exactly then;
//! when finite, its point must be k256's affine point, with y's parity,
//! and come back from `from_be_coordinates`, `x_equals_var` must accept
//! k256's x and refuse x + 1 (below p), and dcrd's x check for r = X.x mod
//! N (accept if X.x is r, reject if r >= P - N, accept if X.x is r + N)
//! must decide as it does on k256's x.  Structured mode reaches ng = 0,
//! where the G half of the loop is empty.
//!
//! Any difference panics with the inputs.  Builds with debug assertions
//! also run the field's magnitude bookkeeping and `fe_verify`.

#![no_main]

use dcroxide_secp256k1_vartime::{Affine, Fe, FeRaw, Scalar, ecmult_var};
use fiat_crypto::secp256k1_dettman_64::{
    fiat_secp256k1_dettman_mul, fiat_secp256k1_dettman_square,
};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::group::CurveAffine;
use k256::elliptic_curve::hazmat::FieldArithmetic;
use k256::elliptic_curve::ops::{MulByGeneratorVartime, Reduce};
use k256::elliptic_curve::point::{AffineCoordinates, DecompressPoint};
use k256::elliptic_curve::subtle::Choice;
use k256::{AffinePoint, FieldBytes, ProjectivePoint};
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
        let inv = fx.inv_var().expect("the inverse stays within its cap");
        let kinv = Option::<KFe>::from(kx.invert());
        match kinv {
            None => assert_eq!(inv.get_b32(), [0; 32], "inverse of zero"),
            Some(ki) => {
                assert_eq!(inv.get_b32(), kfb(&ki.normalize()), "inv_var {x:02x?}");
                let mut one = inv.mul(&fx);
                one.normalize_var();
                let mut want = [0u8; 32];
                want[31] = 1;
                assert_eq!(one.get_b32(), want, "x * inv_var(x) {x:02x?}");
            }
        }
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

/// N, big-endian.
const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// P - N, big-endian.
const P_MINUS_N: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x45, 0x51, 0x23, 0x19, 0x50, 0xb7, 0x5f, 0xc4, 0x40, 0x2d, 0xa1, 0x72, 0x2f, 0xc9, 0xba, 0xee,
];

/// lambda, big-endian.
const LAMBDA: [u8; 32] = [
    0x53, 0x63, 0xad, 0x4c, 0xc0, 0x5c, 0x30, 0xe0, 0xa5, 0x26, 0x1c, 0x02, 0x88, 0x12, 0x64, 0x5a,
    0x12, 0x2e, 0x22, 0xea, 0x20, 0x81, 0x66, 0x78, 0xdf, 0x02, 0x96, 0x7c, 0x1b, 0x23, 0xbd, 0x72,
];

/// a + b, big-endian, and whether it carried out.
fn add_be(a: &[u8; 32], b: &[u8; 32]) -> ([u8; 32], bool) {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let s = u16::from(a[i]) + u16::from(b[i]) + carry;
        out[i] = s as u8;
        carry = s >> 8;
    }
    (out, carry != 0)
}

/// A small signed value as k256's scalar.
fn ks_i(v: i64) -> k256::Scalar {
    let s = k256::Scalar::from(v.unsigned_abs());
    if v < 0 { -s } else { s }
}

/// dcrd's x check for r = x mod N on an x oracle: accept at step 8 if X.x
/// is r, reject at step 9 if r >= P - N, else accept at step 10 if X.x is
/// r + N.  Returns the step's number and the verdict.
fn x_check(r: &[u8; 32], x_is: impl Fn(&[u8; 32]) -> bool) -> (u8, bool) {
    if x_is(r) {
        return (8, true);
    }
    if *r >= P_MINUS_N {
        return (9, false);
    }
    (10, x_is(&add_be(r, &N).0))
}

fn ecmult_level(mode: u8, bytes: &[u8]) {
    let b32 = |i: usize| -> [u8; 32] { bytes[32 * i..32 * i + 32].try_into().expect("32 bytes") };
    let g = ProjectivePoint::GENERATOR;
    let (qk, na, ng) = if mode & 1 == 0 {
        let q = if mode & 2 == 0 {
            g * <k256::Scalar as Reduce<FieldBytes>>::reduce(&b32(0).into())
        } else {
            let Some(p) = Option::<AffinePoint>::from(AffinePoint::decompress(
                &b32(0).into(),
                Choice::from(mode >> 2 & 1),
            )) else {
                return;
            };
            ProjectivePoint::from(p)
        };
        let na = <k256::Scalar as Reduce<FieldBytes>>::reduce(&b32(1).into());
        let ng = <k256::Scalar as Reduce<FieldBytes>>::reduce(&b32(2).into());
        (q, na, ng)
    } else {
        let lam = Option::<k256::Scalar>::from(k256::Scalar::from_repr(LAMBDA.into()))
            .expect("lambda below N");
        let mut two128 = [0u8; 32];
        two128[15] = 1;
        let t = Option::<k256::Scalar>::from(k256::Scalar::from_repr(two128.into()))
            .expect("2^128 below N");
        let bases = [
            g,
            g.double(),
            g * k256::Scalar::from(3u64),
            g * lam,
            g * (lam * lam),
            g * t,
            g * (lam * t),
        ];
        let base = bases[usize::from(bytes[0] % 7)];
        let base = if bytes[0] & 0x80 == 0 { base } else { -base };
        let q = base * k256::Scalar::from(1 + u64::from(bytes[1] % 16));
        let small = |i: usize| i64::from(bytes[2 + i] as i8) / 16;
        let na = ks_i(small(0)) + ks_i(small(1)) * lam;
        let ng = ks_i(small(2)) + ks_i(small(3)) * t;
        (q, na, ng)
    };
    let qa = qk.to_affine();
    if bool::from(qa.is_identity()) {
        return;
    }
    let (qx, qy): ([u8; 32], [u8; 32]) = (qa.x().into(), qa.y().into());
    let a = Affine::from_be_coordinates(&qx, &qy).expect("k256's point is on the curve");
    let (sa, sg) = (
        Scalar::from_be_bytes(&kb(&na)).expect("below N"),
        Scalar::from_be_bytes(&kb(&ng)).expect("below N"),
    );
    let ours = ecmult_var(&a, &sa, &sg).expect("ecmult_var declined");
    let theirs = ProjectivePoint::mul_by_generator_and_mul_add_vartime(&ng, &na, &qk).to_affine();
    let inf = bool::from(theirs.is_identity());
    assert_eq!(
        ours.is_infinity(),
        inf,
        "infinity: Q {qx:02x?} na {:02x?} ng {:02x?}",
        kb(&na),
        kb(&ng)
    );
    let affine = ours.to_affine_var().expect("to_affine_var declined");
    assert_eq!(affine.is_none(), inf, "to_affine_var at infinity");
    let Some(af) = affine else {
        return;
    };
    let (x, y): ([u8; 32], [u8; 32]) = (theirs.x().into(), theirs.y().into());
    assert_eq!(af.to_be_bytes(), (x, y), "to_affine_var, Q {qx:02x?}");
    assert_eq!(af.y_is_odd(), y[31] & 1 == 1, "y_is_odd, Q {qx:02x?}");
    assert!(
        Affine::from_be_coordinates(&x, &y) == Some(af),
        "from_be_coordinates of to_affine_var's point"
    );
    assert!(
        ours.x_equals_var(&x),
        "x_equals_var refused k256's x {x:02x?}"
    );
    let one = {
        let mut b = [0u8; 32];
        b[31] = 1;
        b
    };
    let (x1, carry) = add_be(&x, &one);
    if !carry && Option::<KFe>::from(KFe::from_repr(x1.into())).is_some() {
        assert!(
            !ours.x_equals_var(&x1),
            "x_equals_var accepted x + 1, x {x:02x?}"
        );
    }
    let r: [u8; 32] = kb(&<k256::Scalar as Reduce<FieldBytes>>::reduce(&x.into()));
    assert_eq!(
        x_check(&r, |v| ours.x_equals_var(v)),
        x_check(&r, |v| *v == x),
        "dcrd's x check, x {x:02x?}"
    );
}

fuzz_target!(|data: &[u8]| {
    let Some((&level, rest)) = data.split_first() else {
        return;
    };
    match level % 3 {
        0 => {
            if rest.len() < 64 {
                return;
            }
            let a: [u8; 32] = rest[..32].try_into().expect("32 bytes");
            let b: [u8; 32] = rest[32..64].try_into().expect("32 bytes");
            scalar_level(&a, &b);
        }
        1 => {
            if rest.len() < 81 {
                return;
            }
            field_level(rest[0], &rest[1..41], &rest[41..81]);
        }
        _ => {
            if rest.len() < 97 {
                return;
            }
            ecmult_level(rest[0], &rest[1..97]);
        }
    }
});
