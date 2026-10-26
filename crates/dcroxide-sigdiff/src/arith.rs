// SPDX-License-Identifier: ISC
//! The curve constants and the 256-bit arithmetic the generators and models
//! do on byte strings.
//!
//! `k256`'s field element type is private, so coordinates are handled as
//! 32-byte values: x + N, x + P, P − y, −2x mod P and the like are plain
//! 256-bit additions and subtractions here, written out on `u64` limbs
//! with `overflowing_add`/`overflowing_sub`.  Every constant is this
//! crate's own (`tests/constants.rs` holds the secp256k1 ones against
//! dcroxide-dcrec's, and the tests below hold them against `k256`), so no
//! input depends on the code under test.  Big-endian is secp256k1's byte
//! order and little-endian Ed25519's.

use core::cmp::Ordering;

/// The secp256k1 field prime P = 2^256 − 2^32 − 977, big-endian.
pub const P: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];

/// The secp256k1 group order N, big-endian.
pub const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// P − N = `0x14551231950b75fc4402da1722fc9baee`, big-endian: an x
/// coordinate at or above N is `N + t` for `t` below this, and dcrd's
/// verify step 9 rejects an r at or above it.
pub const P_MINUS_N: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x45, 0x51, 0x23, 0x19, 0x50, 0xb7, 0x5f, 0xc4, 0x40, 0x2d, 0xa1, 0x72, 0x2f, 0xc9, 0xba, 0xee,
];

/// ⌊N/2⌋ = (N − 1)/2, big-endian: the largest low S.
pub const HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// 2^256 − P = `0x1000003d1`, big-endian: the values a coordinate can be
/// encoded above P with (x + P for x below this fits in 32 bytes).
pub const TWO_256_MINUS_P: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0xd1,
];

/// 2^256 − N = `0x14551231950b75fc4402da1732fc9bebf`, big-endian.
pub const TWO_256_MINUS_N: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x45, 0x51, 0x23, 0x19, 0x50, 0xb7, 0x5f, 0xc4, 0x40, 0x2d, 0xa1, 0x73, 0x2f, 0xc9, 0xbe, 0xbf,
];

/// The Ed25519 field prime p = 2^255 − 19, little-endian.
pub const ED25519_P: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// The Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493,
/// little-endian.
pub const ED25519_L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Four 64-bit limbs, least significant first.
type Limbs = [u64; 4];

fn limbs_be(v: &[u8; 32]) -> Limbs {
    let mut out = [0u64; 4];
    for (limb, chunk) in out.iter_mut().zip(v.as_chunks::<8>().0.iter().rev()) {
        *limb = u64::from_be_bytes(*chunk);
    }
    out
}

fn bytes_be(v: &Limbs) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (chunk, limb) in out.as_chunks_mut::<8>().0.iter_mut().rev().zip(v) {
        *chunk = limb.to_be_bytes();
    }
    out
}

fn limbs_le(v: &[u8; 32]) -> Limbs {
    let mut out = [0u64; 4];
    for (limb, chunk) in out.iter_mut().zip(v.as_chunks::<8>().0) {
        *limb = u64::from_le_bytes(*chunk);
    }
    out
}

fn bytes_le(v: &Limbs) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (chunk, limb) in out.as_chunks_mut::<8>().0.iter_mut().zip(v) {
        *chunk = limb.to_le_bytes();
    }
    out
}

/// a + b and the carry out of the top limb.
fn add_limbs(a: &Limbs, b: &Limbs) -> (Limbs, bool) {
    let mut out = [0u64; 4];
    let mut carry = false;
    for ((o, x), y) in out.iter_mut().zip(a).zip(b) {
        let (sum, c1) = x.overflowing_add(*y);
        let (sum, c2) = sum.overflowing_add(u64::from(carry));
        *o = sum;
        carry = c1 | c2;
    }
    (out, carry)
}

/// a − b and the borrow out of the top limb.
fn sub_limbs(a: &Limbs, b: &Limbs) -> (Limbs, bool) {
    let mut out = [0u64; 4];
    let mut borrow = false;
    for ((o, x), y) in out.iter_mut().zip(a).zip(b) {
        let (diff, b1) = x.overflowing_sub(*y);
        let (diff, b2) = diff.overflowing_sub(u64::from(borrow));
        *o = diff;
        borrow = b1 | b2;
    }
    (out, borrow)
}

/// a + b mod 2^256 for big-endian values, and whether it carried.
pub fn add_be(a: &[u8; 32], b: &[u8; 32]) -> ([u8; 32], bool) {
    let (sum, carry) = add_limbs(&limbs_be(a), &limbs_be(b));
    (bytes_be(&sum), carry)
}

/// a − b mod 2^256 for big-endian values, and whether it borrowed (a < b).
pub fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> ([u8; 32], bool) {
    let (diff, borrow) = sub_limbs(&limbs_be(a), &limbs_be(b));
    (bytes_be(&diff), borrow)
}

/// a + b mod 2^256 for little-endian values, and whether it carried.
pub fn add_le(a: &[u8; 32], b: &[u8; 32]) -> ([u8; 32], bool) {
    let (sum, carry) = add_limbs(&limbs_le(a), &limbs_le(b));
    (bytes_le(&sum), carry)
}

/// a − b mod 2^256 for little-endian values, and whether it borrowed.
pub fn sub_le(a: &[u8; 32], b: &[u8; 32]) -> ([u8; 32], bool) {
    let (diff, borrow) = sub_limbs(&limbs_le(a), &limbs_le(b));
    (bytes_le(&diff), borrow)
}

/// Compares two big-endian values (their byte order is their numeric
/// order, so this is the arrays' own comparison, named for symmetry with
/// [`cmp_le`]).
pub fn cmp_be(a: &[u8; 32], b: &[u8; 32]) -> Ordering {
    a.cmp(b)
}

/// Compares two little-endian values numerically.
pub fn cmp_le(a: &[u8; 32], b: &[u8; 32]) -> Ordering {
    a.iter().rev().cmp(b.iter().rev())
}

/// `v` as a 32-byte big-endian value.
pub fn be_from_u64(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

/// `v` as a 32-byte little-endian value.
pub fn le_from_u64(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&v.to_le_bytes());
    out
}

/// Whether a value is zero (either byte order).
pub fn is_zero(v: &[u8; 32]) -> bool {
    v.iter().all(|&b| b == 0)
}

/// (a + b) mod P for big-endian a and b below P.
pub fn add_mod_p(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    debug_assert!(*a < P && *b < P, "add_mod_p takes reduced values");
    let (sum, carry) = add_be(a, b);
    if carry || sum >= P {
        // The true sum is below 2P < 2^257, so one subtraction reduces it;
        // with a carry its top bit is the borrow this subtraction takes.
        sub_be(&sum, &P).0
    } else {
        sum
    }
}

/// 2a mod P for big-endian a below P.
pub fn double_mod_p(a: &[u8; 32]) -> [u8; 32] {
    add_mod_p(a, a)
}

/// −a mod P for big-endian a below P: P − a, and zero for zero.
pub fn neg_mod_p(a: &[u8; 32]) -> [u8; 32] {
    debug_assert!(*a < P, "neg_mod_p takes a reduced value");
    if is_zero(a) { *a } else { sub_be(&P, a).0 }
}

/// −a mod N for big-endian a below N: N − a, and zero for zero.
pub fn neg_mod_n(a: &[u8; 32]) -> [u8; 32] {
    debug_assert!(*a < N, "neg_mod_n takes a reduced value");
    if is_zero(a) { *a } else { sub_be(&N, a).0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcroxide_testutil::SplitMix64;
    use k256::elliptic_curve::PrimeField;
    use k256::elliptic_curve::point::AffineCoordinates;
    use k256::elliptic_curve::scalar::IsHigh;
    use k256::{AffinePoint, ProjectivePoint, Scalar};

    fn random_scalar(rng: &mut SplitMix64) -> Scalar {
        loop {
            let mut bytes = [0u8; 32];
            rng.fill(&mut bytes);
            if let Some(s) = Option::<Scalar>::from(Scalar::from_repr(bytes.into()))
                && !bool::from(s.is_zero())
            {
                return s;
            }
        }
    }

    fn xy(point: &ProjectivePoint) -> ([u8; 32], [u8; 32]) {
        let affine = point.to_affine();
        (affine.x().into(), affine.y().into())
    }

    /// N is k256's group order, ⌊N/2⌋ its boundary of high S, and the
    /// derived constants are what their names say.
    #[test]
    fn constants_agree_with_k256_and_each_other() {
        let n_minus_1: [u8; 32] = (-Scalar::ONE).to_repr().into();
        assert_eq!(add_be(&n_minus_1, &be_from_u64(1)), (N, false));
        assert!(bool::from(Scalar::from_repr(N.into()).is_none()));
        let half: Scalar = Option::from(Scalar::from_repr(HALF_N.into())).expect("below N");
        assert!(!bool::from(half.is_high()));
        assert!(bool::from((half + Scalar::ONE).is_high()));

        assert_eq!(sub_be(&P, &N), (P_MINUS_N, false));
        assert_eq!(add_be(&P, &TWO_256_MINUS_P), ([0; 32], true));
        assert_eq!(add_be(&N, &TWO_256_MINUS_N), ([0; 32], true));
        assert_eq!(add_be(&HALF_N, &HALF_N), (n_minus_1, false));
        assert_eq!(TWO_256_MINUS_P, be_from_u64(0x1_0000_03d1));

        // p = 2^255 − 19 and L = 2^252 + c, built from their definitions.
        let mut two_255 = [0u8; 32];
        two_255[31] = 0x80;
        assert_eq!(add_le(&ED25519_P, &le_from_u64(19)), (two_255, false));
        let mut two_252 = [0u8; 32];
        two_252[31] = 0x10;
        let (c, borrow) = sub_le(&ED25519_L, &two_252);
        assert!(!borrow);
        assert_eq!(
            c[..16],
            0x14de_f9de_a2f7_9cd6_5812_631a_5cf5_d3ed_u128.to_le_bytes()
        );
        assert!(c[16..].iter().all(|&b| b == 0));
    }

    /// Additions and subtractions against u128 arithmetic where both fit,
    /// carries and borrows at the top, and comparisons in both orders.
    #[test]
    fn add_sub_and_compare() {
        let mut rng = SplitMix64(0x5eed_a417);
        for _ in 0..1_000 {
            let (a, b) = (rng.next_u64(), rng.next_u64());
            let sum = u128::from(a).wrapping_add(u128::from(b));
            let mut want = [0u8; 32];
            want[16..].copy_from_slice(&sum.to_be_bytes());
            assert_eq!(add_be(&be_from_u64(a), &be_from_u64(b)), (want, false));
            let mut want_le = [0u8; 32];
            want_le[..16].copy_from_slice(&sum.to_le_bytes());
            assert_eq!(add_le(&le_from_u64(a), &le_from_u64(b)), (want_le, false));
            assert_eq!(
                cmp_be(&be_from_u64(a), &be_from_u64(b)),
                a.cmp(&b),
                "{a} {b}"
            );
            assert_eq!(cmp_le(&le_from_u64(a), &le_from_u64(b)), a.cmp(&b));

            let mut x = [0u8; 32];
            let mut y = [0u8; 32];
            rng.fill(&mut x);
            rng.fill(&mut y);
            let (s, carry) = add_be(&x, &y);
            let (back, borrow) = sub_be(&s, &y);
            assert_eq!(back, x);
            assert_eq!(borrow, carry, "a carry out is a borrow back");
            let (d, borrow) = sub_be(&x, &y);
            assert_eq!(borrow, x < y);
            assert_eq!(add_be(&d, &y).0, x);
            let (s, _) = add_le(&x, &y);
            assert_eq!(sub_le(&s, &y).0, x);
        }
        assert_eq!(sub_be(&[0; 32], &be_from_u64(1)), ([0xff; 32], true));
        assert_eq!(add_be(&[0xff; 32], &be_from_u64(1)), ([0; 32], true));
        assert_eq!(
            cmp_le(&le_from_u64(1 << 8), &le_from_u64(0xff)),
            Ordering::Greater
        );
        assert!(is_zero(&[0; 32]) && !is_zero(&be_from_u64(1)));
    }

    /// The mod-P helpers on real coordinates: −y is the negated point's y,
    /// and, with β the cube root of unity whose λ maps (x, y) to (βx, y),
    /// x + βx + β²x = 0, so −2x = βx + β²x − x.
    #[test]
    fn mod_p_helpers_on_points() {
        // λ, the scalar with λ³ = 1 acting as (x, y) -> (βx, y).
        let lambda: Scalar = Option::from(Scalar::from_repr(
            [
                0x53, 0x63, 0xad, 0x4c, 0xc0, 0x5c, 0x30, 0xe0, 0xa5, 0x26, 0x1c, 0x02, 0x88, 0x12,
                0x64, 0x5a, 0x12, 0x2e, 0x22, 0xea, 0x20, 0x81, 0x66, 0x78, 0xdf, 0x02, 0x96, 0x7c,
                0x1b, 0x23, 0xbd, 0x72,
            ]
            .into(),
        ))
        .expect("below N");
        assert_eq!(lambda * lambda * lambda, Scalar::ONE);
        assert_ne!(lambda, Scalar::ONE);

        let mut rng = SplitMix64(0x0bad_cafe);
        for _ in 0..32 {
            let q = ProjectivePoint::GENERATOR * random_scalar(&mut rng);
            let (x1, y1) = xy(&q);
            let (_, neg_y) = xy(&(-q));
            assert_eq!(neg_mod_p(&y1), neg_y);
            assert_eq!(add_mod_p(&y1, &neg_y), [0; 32]);

            let (x2, y2) = xy(&(q * lambda));
            let (x3, y3) = xy(&(q * lambda * lambda));
            assert_eq!((y2, y3), (y1, y1), "λ keeps y");
            assert_eq!(add_mod_p(&add_mod_p(&x1, &x2), &x3), [0; 32]);
            let minus_two_x = neg_mod_p(&double_mod_p(&x1));
            assert_eq!(
                minus_two_x,
                add_mod_p(&add_mod_p(&x2, &x3), &neg_mod_p(&x1))
            );

            // The coordinates are field elements k256 takes back.
            assert!(bool::from(
                AffinePoint::from_coordinates(&x1.into(), &neg_y.into()).is_some()
            ));
        }
        assert_eq!(neg_mod_p(&[0; 32]), [0; 32]);
        assert_eq!(neg_mod_n(&be_from_u64(1)), sub_be(&N, &be_from_u64(1)).0);
        assert_eq!(
            double_mod_p(&sub_be(&P, &be_from_u64(1)).0),
            sub_be(&P, &be_from_u64(2)).0
        );
    }
}
