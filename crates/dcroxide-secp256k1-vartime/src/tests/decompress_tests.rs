// SPDX-License-Identifier: ISC
//! Key decompression and the affine point API: dcrd's `TestDecompressY`
//! vectors; decompression against k256's on random, structured and
//! near-p x values with both parities, the output normalized limb for
//! limb; the boundary keys (the smallest and largest x with a point, and
//! every point with a tiny y); y normalized after the negation, also from
//! an x above magnitude 1; `from_be_coordinates`' acceptance and
//! rejections; equality on the normalized coordinates, whatever built the
//! point; and the curve check refusing the point at infinity.

use dcroxide_testutil::SplitMix64;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::{AffinePoint, ProjectivePoint};

use super::dcrd_vectors::DECOMPRESS_Y;
use super::*;
use crate::group::Ge;
use crate::{Affine, ecmult_var};

/// dcrd's hex, any length up to 64 digits, as 32 big-endian bytes.
fn dcrd_hex(h: &str) -> [u8; 32] {
    hex32(&format!("{h:0>64}"))
}

/// a + d (d small), wrapping past 2^256 as the caller allows.
pub(crate) fn add_small(a: &[u64; 4], d: u64) -> [u64; 4] {
    let mut r = *a;
    let (s, mut carry) = r[0].overflowing_add(d);
    r[0] = s;
    for x in r.iter_mut().skip(1) {
        if !carry {
            break;
        }
        let (s, c) = x.overflowing_add(1);
        *x = s;
        carry = c;
    }
    r
}

/// `fe_sqrt`'s root of x^3 + 7, normalized, and whether it exists.
fn x_root(x: &Fe) -> (Fe, bool) {
    let mut x3 = x.sqr().mul(x);
    x3.add_int(7);
    let (r, ok) = x3.sqrt();
    (norm(&r), ok)
}

/// a^e for e given as little-endian words, by square and multiply on the
/// crate's field; only to construct test inputs, which are then checked by
/// the reference.
fn fe_pow(a: &Fe, e: &[u64; 4]) -> Fe {
    let mut r = fe_w(&[1, 0, 0, 0]);
    for i in (0..256).rev() {
        r = r.sqr();
        if (e[i / 64] >> (i % 64)) & 1 == 1 {
            r = r.mul(a);
        }
    }
    r
}

/// Every point (x, y) with 0 < y < `lim`: y^2 - 7 must be a cube, one
/// cube root is (y^2 - 7)^((p+2)/9), since p = 7 mod 9, and as p = 1 mod 3
/// the other two are it times beta and beta^2, beta a cube root of unity.
/// Each x is checked by the reference (x^3 + 7 = y^2), independently of
/// the exponentiation that found it.
pub(crate) fn tiny_y_points(lim: u64) -> Vec<([u8; 32], u64)> {
    // beta, written out here and checked by the reference.
    const BETA: [u64; 4] = [
        0xc139_6c28_7195_01ee,
        0x9cf0_4975_12f5_8995,
        0x6e64_479e_ac34_34e9,
        0x7ae9_6a2b_657c_0710,
    ];
    let beta2 = mul_p(&BETA, &BETA);
    assert_eq!(mul_p(&beta2, &BETA), [1, 0, 0, 0]);
    assert_ne!(BETA, [1, 0, 0, 0]);
    // (p + 2) / 9, little-endian.
    let e = {
        let mut num = add_small(&P, 2);
        let mut rem = 0u128;
        for i in (0..4).rev() {
            let cur = (rem << 64) | u128::from(num[i]);
            num[i] = (cur / 9) as u64;
            rem = cur % 9;
        }
        assert_eq!(rem, 0);
        num
    };
    let mut out = Vec::new();
    for y in 1..lim {
        let c = sub_p(&mul_p(&[y, 0, 0, 0], &[y, 0, 0, 0]), &[7, 0, 0, 0]);
        let x = fe_val(&fe_pow(&fe_w(&c), &e));
        if mul_p(&mul_p(&x, &x), &x) == c {
            for x in [x, mul_p(&x, &BETA), mul_p(&x, &beta2)] {
                assert_eq!(mul_p(&mul_p(&x, &x), &x), c);
                out.push((words_to_be(&x), y));
            }
        }
    }
    out
}

/// Checks a decompressed point against k256's answer and the API's
/// promises: coordinates normalized limb for limb, x as given, y of the
/// parity asked for.
fn check_against_k256(x: &[u8; 32], odd: bool) -> Option<Affine> {
    let ours = Affine::decompress_var(x, odd);
    assert_eq!(
        ours.map(|a| a.to_be_bytes()),
        k_decompress(x, odd),
        "x = {x:02x?} odd {odd}"
    );
    if let Some(a) = ours {
        let g = a.as_ge();
        assert_eq!(g.x.raw().n, norm(&g.x).raw().n, "x not normalized");
        assert_eq!(g.y.raw().n, norm(&g.y).raw().n, "y not normalized");
        assert_eq!(a.to_be_bytes().0, *x);
        assert_eq!(a.y_is_odd(), odd);
        assert!(g.is_valid_var());
    }
    ours
}

#[test]
fn dcrd_decompress_vectors() {
    for (name, x, valid, odd_y, even_y) in DECOMPRESS_Y {
        let xb = dcrd_hex(x);
        for (want_odd, want) in [(true, odd_y), (false, even_y)] {
            let got = Affine::decompress_var(&xb, want_odd);
            assert_eq!(got.is_some(), valid, "{name}");
            if let Some(a) = got {
                assert_eq!(
                    a.to_be_bytes(),
                    (xb, dcrd_hex(want)),
                    "{name} odd {want_odd}"
                );
                assert_eq!(a.y_is_odd(), want_odd);
            }
        }
    }
}

/// Decompression against k256 on random x (about half non-residues, and
/// half of the rest needing the negation), structured x, x just below and
/// at or above p, both parities.
#[test]
fn decompress_vs_k256() {
    let n = (cases() / 20).max(1);
    let mut r = SplitMix64(0xdec0_0001);
    let (mut valid, mut invalid, mut negated, mut ge_p) = (0u64, 0u64, 0u64, 0u64);
    for i in 0..n {
        let w = match i % 8 {
            0 => words_structured(&mut r),
            1 => {
                let d = r.below(1 << 33);
                match r.below(4) {
                    0 => [u64::MAX; 4],
                    1 => add_small(&P, d),
                    _ => sub4(&P, &[d + 1, 0, 0, 0]),
                }
            }
            _ => words(&mut r),
        };
        if ge4(&w, &P) {
            ge_p += 1;
        }
        let xb = words_to_be(&w);
        let odd = r.below(2) == 1;
        match check_against_k256(&xb, odd) {
            Some(a) => {
                valid += 1;
                let (rt, _) = x_root(&a.as_ge().x);
                if rt.is_odd() != odd {
                    negated += 1;
                }
            }
            None => invalid += 1,
        }
    }
    eprintln!(
        "decompress_vs_k256: {n} x values: {valid} valid ({negated} needed the negation), \
         {invalid} invalid ({ge_p} with x >= p)"
    );
    assert!(negated > 0 && valid > negated && invalid > ge_p && ge_p > 0);
}

/// The boundary keys: x = 0 has no point, x = 1 is the smallest x with
/// one, p - 3 the largest below p; and all 183 points with 0 < y < 200
/// (three x for each of the 61 such y), both parities, so y and p - y.
#[test]
fn decompress_boundary_keys() {
    for odd in [false, true] {
        assert!(Affine::decompress_var(&[0; 32], odd).is_none());
        assert!(check_against_k256(&words_to_be(&[1, 0, 0, 0]), odd).is_some());
        for d in [1u64, 2] {
            assert!(check_against_k256(&words_to_be(&sub4(&P, &[d, 0, 0, 0])), odd).is_none());
        }
        assert!(check_against_k256(&words_to_be(&sub4(&P, &[3, 0, 0, 0])), odd).is_some());
    }
    let tiny = tiny_y_points(200);
    assert!(tiny.iter().any(|&(_, y)| y == 1), "y = 1 not found");
    for (xb, y) in &tiny {
        for odd in [false, true] {
            let a = check_against_k256(xb, odd).expect("a tiny-y x is on the curve");
            let want = if (y & 1 == 1) == odd {
                [*y, 0, 0, 0]
            } else {
                sub4(&P, &[*y, 0, 0, 0])
            };
            assert_eq!(a.to_be_bytes().1, words_to_be(&want));
        }
    }
    eprintln!("tiny-y points (y < 200): {}", tiny.len());
    assert_eq!(tiny.len(), 183);
}

/// `Ge::set_xo_var` normalizes y after the negation: with the parity
/// asked for always the opposite of `fe_sqrt`'s root, y comes out
/// normalized, claimed so in debug builds, and on the curve.
#[test]
fn set_xo_var_normalizes_after_negation() {
    let mut r = SplitMix64(0x786f_0001);
    let mut negated = 0u64;
    for _ in 0..(cases() / 40).max(1) {
        let x = fe_w(&words_below_p(&mut r));
        let (root, ok) = x_root(&x);
        if !ok {
            assert!(Ge::set_xo_var(&x, false).is_none());
            continue;
        }
        let want_odd = !root.is_odd();
        let g = Ge::set_xo_var(&x, want_odd).expect("x has a point");
        negated += 1;
        assert_eq!(
            g.y.raw().n,
            norm(&g.y).raw().n,
            "y not normalized after the negation"
        );
        #[cfg(debug_assertions)]
        assert!(g.y.is_normalized_claim());
        assert_eq!(g.y.is_odd(), want_odd);
        assert!(g.is_valid_var());
    }
    assert!(negated > 0);
}

/// `Ge::set_xo_var` on an x above magnitude 1 (2 to 4, the affine x
/// bound, with limbs near the bound): y normalized, the parity as asked,
/// the values k256's.
#[test]
fn set_xo_var_unnormalized_x() {
    let mut r = SplitMix64(0x7365_745f_786f_7661);
    let (mut valid, mut negated) = (0u64, 0u64);
    for k in 0..(cases() / 40).max(1) {
        let w = words_below_p(&mut r);
        let x = fe_w(&w);
        let mag = 2 + (k % 3) as u8;
        let xi = norm(&x.negate(1)).negate(mag - 1);
        let odd = r.below(2) == 1;
        let got = Ge::set_xo_var(&xi, odd);
        let want = k_decompress(&words_to_be(&w), odd);
        assert_eq!(got.is_some(), want.is_some());
        if let (Some(g), Some((wx, wy))) = (got, want) {
            valid += 1;
            assert_eq!(g.y.raw().n, norm(&g.y).raw().n, "y not normalized");
            assert_eq!(g.y.is_odd(), odd);
            assert_eq!(fe_bytes(&g.x), wx);
            assert_eq!(g.y.get_b32(), wy);
            assert!(g.is_valid_var());
            let (rt, _) = x_root(&xi);
            if rt.is_odd() != odd {
                negated += 1;
            }
        }
    }
    assert!(valid > 0 && negated > 0);
}

/// `Affine::from_be_coordinates` accepts every curve point, (x, y) and
/// (x, p - y), and refuses y + 1 (off the curve), x or y at or above p
/// (p itself, and x + p or y + p where they fit in 256 bits); the points
/// it accepts equal the decompressed ones.
#[test]
fn from_be_coordinates_accepts_points_and_refuses_the_rest() {
    let mut r = SplitMix64(0x7075_625f_6170_6921);
    let mut off_curve = 0u64;
    let mut q = ProjectivePoint::GENERATOR;
    for k in 0..(cases() / 200).max(16) {
        if k > 0 {
            let mut b = [0u8; 32];
            r.fill(&mut b);
            let s = <k256::Scalar as k256::elliptic_curve::ops::Reduce<k256::FieldBytes>>::reduce(
                &b.into(),
            );
            q = ProjectivePoint::GENERATOR * s;
        }
        let qa = AffinePoint::from(q);
        let qx: [u8; 32] = qa.x().into();
        let qy: [u8; 32] = qa.y().into();
        let a = Affine::from_be_coordinates(&qx, &qy).expect("a curve point");
        assert_eq!(a.to_be_bytes(), (qx, qy));
        assert_eq!(a.y_is_odd(), bool::from(qa.y_is_odd()));
        assert!(Affine::decompress_var(&qx, a.y_is_odd()) == Some(a));
        assert!(Affine::decompress_var(&qx, !a.y_is_odd()) != Some(a));

        let ny = words_to_be(&neg_p(&be_to_words(&qy)));
        let an = Affine::from_be_coordinates(&qx, &ny).expect("the negated point");
        assert_eq!(an.y_is_odd(), !a.y_is_odd());

        let y1 = add_small(&be_to_words(&qy), 1);
        if !ge4(&y1, &P) {
            assert!(Affine::from_be_coordinates(&qx, &words_to_be(&y1)).is_none());
            off_curve += 1;
        }
        for (cx, cy) in [(be_to_words(&qx), true), (be_to_words(&qy), false)] {
            let mut sum = [0u64; 4];
            let mut c = 0u128;
            for i in 0..4 {
                let t = u128::from(cx[i]) + u128::from(P[i]) + c;
                sum[i] = t as u64;
                c = t >> 64;
            }
            if c == 0 {
                let s = words_to_be(&sum);
                let got = if cy {
                    Affine::from_be_coordinates(&s, &qy)
                } else {
                    Affine::from_be_coordinates(&qx, &s)
                };
                assert!(got.is_none());
            }
        }
        assert!(Affine::from_be_coordinates(&words_to_be(&P), &qy).is_none());
        assert!(Affine::from_be_coordinates(&qx, &words_to_be(&P)).is_none());
    }
    assert!(off_curve > 0);
    assert!(Affine::from_be_coordinates(&[0; 32], &[0; 32]).is_none());
}

/// Equality of affine points is equality of their normalized
/// coordinates, whatever built them: a point from `from_be_coordinates`,
/// from `decompress_var` and from `to_affine_var` of the multiply's
/// Jacobian output (Z not 1) compares equal, though builds with debug
/// assertions give the three different bookkeeping; a point and its
/// negation (same x) and a point and lambda times it (beta*x, same y)
/// compare unequal; and over every pair, `==` agrees with the
/// serialized coordinates.  dcrec's public key equality is this.
#[test]
fn affine_equality_is_coordinate_equality() {
    let mut r = SplitMix64(0x6166_665f_6571_7521);
    let one = crate::Scalar::reduce_be_bytes(&words_to_be(&[1, 0, 0, 0]));
    let zero = crate::Scalar::reduce_be_bytes(&[0; 32]);
    let lambda = crate::scalar::LAMBDA;
    let mut points = Vec::new();
    for _ in 0..32 {
        let qx = words_to_be(&words_below_p(&mut r));
        let odd = r.next_u64() & 1 == 1;
        let Some(d) = Affine::decompress_var(&qx, odd) else {
            continue;
        };
        let (x, y) = d.to_be_bytes();
        let c = Affine::from_be_coordinates(&x, &y).expect("a curve point");
        let j = ecmult_var(&d, &one, &zero)
            .expect("the guard")
            .to_affine_var()
            .expect("the cap")
            .expect("not infinity");
        assert!(c == d && j == d && j == c);

        let n = Affine::from_be_coordinates(&x, &words_to_be(&neg_p(&be_to_words(&y))))
            .expect("the negation");
        assert!(n != d);
        assert_eq!(n.to_be_bytes().0, x);

        let b = ecmult_var(&d, &lambda, &zero)
            .expect("the guard")
            .to_affine_var()
            .expect("the cap")
            .expect("not infinity");
        assert!(b != d);
        assert_eq!(b.to_be_bytes().1, y);
        points.extend([d, c, j, n, b]);
    }
    assert!(points.len() >= 40, "{} points", points.len());
    for (i, a) in points.iter().enumerate() {
        for b in &points[i..] {
            assert_eq!(a == b, a.to_be_bytes() == b.to_be_bytes());
        }
    }
}

/// Points whose coordinates differ only in y's lowest limb are unequal:
/// (x, y) and (x, P - y) for y = (P - 1) / 2 - 2, whose y limbs differ in
/// limb 0 alone (by 5).
#[test]
fn affine_equality_sees_every_limb() {
    let x = dcrd_hex("8a369db2d6ecfaa666514299e447165e31fba21f0b2c3c1d5a0fc77c3e150672");
    let odd = Affine::decompress_var(&x, true).expect("a point");
    let even = Affine::decompress_var(&x, false).expect("a point");
    assert_eq!(
        odd.to_be_bytes().1,
        dcrd_hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe15")
    );
    assert_eq!(
        even.to_be_bytes().1,
        dcrd_hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe1a")
    );
    assert!(odd != even);
    assert!(odd == Affine::from_be_coordinates(&x, &odd.to_be_bytes().1).expect("on the curve"));
}

/// `Ge::is_valid_var` refuses the point at infinity, whatever its
/// coordinates hold: the curve point at x = 1 is valid, and the same
/// coordinates flagged as infinity are not.
#[test]
fn infinity_is_not_valid() {
    let p = Affine::decompress_var(&words_to_be(&[1, 0, 0, 0]), false).expect("x = 1 has a point");
    let g = Ge {
        infinity: true,
        ..*p.as_ge()
    };
    assert!(p.as_ge().is_valid_var());
    assert!(!g.is_valid_var());
}
