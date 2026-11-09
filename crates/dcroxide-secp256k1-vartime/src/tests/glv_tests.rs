// SPDX-License-Identifier: ISC AND MIT
//
// `endomorphism_split` follows libsecp256k1 src/tests.c's
// `test_scalar_split` and `run_endomorphism_tests` (Copyright (c) 2013,
// 2014, 2015 Pieter Wuille, Gregory Maxwell), as vendored by
// secp256k1-sys 0.14.1.  MIT; see NOTICE.
//
//! The GLV split and the wNAF builder: the split's constants against
//! k256's and the lattice they come from; the split's identity and bounds
//! on random, edge and near-bound scalars, by crypto-bigint as well as by
//! the split's own debug check; small combinations a + b*lambda that split
//! to exactly (a, b); libsecp256k1's split test; and the wNAF's digits
//! (each zero or odd and within the table, w - 1 zeros between nonzero
//! ones, summing to the scalar) with its guard, which must decline
//! exactly the values that do not fit 129 positions after the fold.

use dcroxide_testutil::SplitMix64;
use k256::elliptic_curve::point::AffineCoordinates;

use super::*;
use crate::field::BETA;
use crate::scalar::{
    G1, G2, K1_BOUND, K2_BOUND, LAMBDA, MINUS_B1, MINUS_B2, Scalar, split_lambda_verify,
};
use crate::wnaf::{Digit, WNAF_LEN, try_wnaf};

fn sc(w: &[u64; 4]) -> Scalar {
    Scalar::from_be_bytes(&words_to_be(w)).expect("below N")
}
fn scw(s: &Scalar) -> [u64; 4] {
    be_to_words(&s.to_be_bytes())
}
fn reduce_n(w: &[u64; 4]) -> [u64; 4] {
    if ge4(w, &NORD) { sub4(w, &NORD) } else { *w }
}
fn rand_sc(r: &mut SplitMix64) -> [u64; 4] {
    reduce_n(&if r.below(4) == 0 {
        words_structured(r)
    } else {
        words(r)
    })
}
fn be32(b: &[u8]) -> [u64; 4] {
    let mut a = [0u8; 32];
    a.copy_from_slice(b);
    be_to_words(&a)
}
fn ge8(a: &[u64; 8], b: &[u64; 8]) -> bool {
    for i in (0..8).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}
fn sub8(a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
    let mut r = [0u64; 8];
    let mut borrow = 0u64;
    for i in 0..8 {
        let (d, o1) = a[i].overflowing_sub(b[i]);
        let (d, o2) = d.overflowing_sub(borrow);
        r[i] = d;
        borrow = u64::from(o1 | o2);
    }
    r
}

/// The split's constants are k256's (glv.rs, copied below); lambda is a
/// primitive cube root of unity mod N; a_i + b_i*lambda = 0 for the
/// lattice basis of scalar_impl.h:105-108; g1 and g2 are the rounded
/// quotients they claim to be; and lambda*G = (beta*G.x, G.y) by k256.
#[test]
fn constants_match_k256_glv_and_the_lattice() {
    // k256 0.14 src/arithmetic/mul/glv.rs:10-36, copied.
    const K_MINUS_LAMBDA: [u8; 32] = [
        0xac, 0x9c, 0x52, 0xb3, 0x3f, 0xa3, 0xcf, 0x1f, 0x5a, 0xd9, 0xe3, 0xfd, 0x77, 0xed, 0x9b,
        0xa4, 0xa8, 0x80, 0xb9, 0xfc, 0x8e, 0xc7, 0x39, 0xc2, 0xe0, 0xcf, 0xc8, 0x10, 0xb5, 0x12,
        0x83, 0xcf,
    ];
    const K_MINUS_B1: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xe4, 0x43, 0x7e, 0xd6, 0x01, 0x0e, 0x88,
        0x28, 0x6f, 0x54, 0x7f, 0xa9, 0x0a, 0xbf, 0xe4, 0xc3,
    ];
    const K_MINUS_B2: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0x8a, 0x28, 0x0a, 0xc5, 0x07, 0x74, 0x34, 0x6d, 0xd7, 0x65, 0xcd, 0xa8, 0x3d, 0xb1,
        0x56, 0x2c,
    ];
    const K_G1: [u8; 32] = [
        0x30, 0x86, 0xd2, 0x21, 0xa7, 0xd4, 0x6b, 0xcd, 0xe8, 0x6c, 0x90, 0xe4, 0x92, 0x84, 0xeb,
        0x15, 0x3d, 0xaa, 0x8a, 0x14, 0x71, 0xe8, 0xca, 0x7f, 0xe8, 0x93, 0x20, 0x9a, 0x45, 0xdb,
        0xb0, 0x31,
    ];
    const K_G2: [u8; 32] = [
        0xe4, 0x43, 0x7e, 0xd6, 0x01, 0x0e, 0x88, 0x28, 0x6f, 0x54, 0x7f, 0xa9, 0x0a, 0xbf, 0xe4,
        0xc4, 0x22, 0x12, 0x08, 0xac, 0x9d, 0xf5, 0x06, 0xc6, 0x15, 0x71, 0xb4, 0xae, 0x8a, 0xc4,
        0x7f, 0x71,
    ];
    assert_eq!((-LAMBDA).to_be_bytes(), K_MINUS_LAMBDA);
    assert_eq!(MINUS_B1.to_be_bytes(), K_MINUS_B1);
    assert_eq!(MINUS_B2.to_be_bytes(), K_MINUS_B2);
    assert_eq!(G1.to_be_bytes(), K_G1);
    assert_eq!(G2.to_be_bytes(), K_G2);

    let n = cb_n();
    let l = cb(&scw(&LAMBDA));
    let l2 = l.mul_mod(&l, &n);
    assert_eq!(cbw(&l2.mul_mod(&l, &n)), [1, 0, 0, 0]);
    assert_eq!(
        cbw(&l2.add_mod(&l, &n).add_mod(&cb(&[1, 0, 0, 0]), &n)),
        [0; 4]
    );

    let a1 = [0xe86c_90e4_9284_eb15, 0x3086_d221_a7d4_6bcd, 0, 0];
    let b2 = a1;
    // a2 = 0x0114ca50f7a8e2f3f657c1108d9d44cfd8 (129 bits)
    let a2 = [0x57c1_108d_9d44_cfd8, 0x14ca_50f7_a8e2_f3f6, 0x01, 0];
    let minus_b1 = scw(&MINUS_B1);
    let b1 = cbw(&cb(&minus_b1).neg_mod(&n));
    assert_eq!(
        cbw(&cb(&a1).add_mod(&cb(&b1).mul_mod(&l, &n), &n)),
        [0; 4],
        "a1 + b1*lambda != 0"
    );
    assert_eq!(
        cbw(&cb(&a2).add_mod(&cb(&b2).mul_mod(&l, &n), &n)),
        [0; 4],
        "a2 + b2*lambda != 0"
    );
    assert_eq!(scw(&-MINUS_B2), b2);

    // split_lambda_verify's bounds from the same lattice: (a1 + a2 + 1)/2
    // and (-b1 + b2)/2 + 1 (scalar_impl.h:292-302).
    let add4 = |x: [u64; 4], y: [u64; 4]| {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let t = u128::from(x[i]) + u128::from(y[i]) + carry;
            out[i] = t as u64;
            carry = t >> 64;
        }
        assert_eq!(carry, 0);
        out
    };
    let half = |x: [u64; 4]| {
        [
            x[0] >> 1 | x[1] << 63,
            x[1] >> 1 | x[2] << 63,
            x[2] >> 1 | x[3] << 63,
            x[3] >> 1,
        ]
    };
    assert_eq!(half(add4(add4(a1, a2), [1, 0, 0, 0])), K1_BOUND);
    assert_eq!(add4(half(add4(minus_b1, b2)), [1, 0, 0, 0]), K2_BOUND);

    // |g*N - 2^384*b| <= N/2.
    let half_n = {
        let mut h = [0u64; 8];
        h[..4].copy_from_slice(&[
            NORD[0] >> 1 | NORD[1] << 63,
            NORD[1] >> 1 | NORD[2] << 63,
            NORD[2] >> 1 | NORD[3] << 63,
            NORD[3] >> 1,
        ]);
        h
    };
    for (g, b) in [(scw(&G1), b2), (scw(&G2), minus_b1)] {
        let gn = mulw(&g, &NORD);
        let target = [0, 0, 0, 0, 0, 0, b[0], b[1]];
        let diff = if ge8(&gn, &target) {
            sub8(&gn, &target)
        } else {
            sub8(&target, &gn)
        };
        assert!(
            !ge8(&diff, &half_n) || diff == half_n,
            "g is not round(2^384 * b / N)"
        );
    }

    let g = k256::ProjectivePoint::GENERATOR;
    let lg = (g * ksc(&scw(&LAMBDA))).to_affine();
    let ga = g.to_affine();
    let (gx, gy) = (be32(&ga.x()), be32(&ga.y()));
    assert_eq!(
        be32(&lg.x()),
        mul_p(&fe_val(&BETA), &gx),
        "lambda*G.x != beta*G.x"
    );
    assert_eq!(be32(&lg.y()), gy, "lambda*G.y != G.y");
}

/// beta is k256's, and a cube root of unity other than 1.
#[test]
fn beta_is_k256s_and_a_cube_root_of_unity() {
    // k256 0.14 src/arithmetic/projective.rs:32-37 (ENDOMORPHISM_BETA), copied.
    const K256_BETA: [u8; 32] = [
        0x7a, 0xe9, 0x6a, 0x2b, 0x65, 0x7c, 0x07, 0x10, 0x6e, 0x64, 0x47, 0x9e, 0xac, 0x34, 0x34,
        0xe9, 0x9c, 0xf0, 0x49, 0x75, 0x12, 0xf5, 0x89, 0x95, 0xc1, 0x39, 0x6c, 0x28, 0x71, 0x95,
        0x01, 0xee,
    ];
    assert_eq!(BETA.get_b32(), K256_BETA);
    let vb = fe_val(&BETA);
    assert_ne!(vb, [1, 0, 0, 0]);
    assert_eq!(mul_p(&mul_p(&vb, &vb), &vb), [1, 0, 0, 0]);
    assert_eq!(add_p(&add_p(&mul_p(&vb, &vb), &vb), &[1, 0, 0, 0]), [0; 4]);
}

/// sum(2^i * d_i) mod N by crypto-bigint, after checking the digits: zero
/// or odd, |d| <= 2^(w-1) - 1, at least w - 1 zeros between nonzero
/// digits, and `len` one past the last nonzero one.
fn check_wnaf<T: Digit>(d: &[T; WNAF_LEN], len: usize, w: u32) -> [u64; 4] {
    let n = cb_n();
    let mut acc = cb(&[0; 4]);
    let mut pow = cb(&[1, 0, 0, 0]);
    let mut last: Option<usize> = None;
    let lim = (1i32 << (w - 1)) - 1;
    for (i, x) in d.iter().enumerate() {
        let v = x.to_i32();
        if v != 0 {
            assert!(v & 1 == 1, "even digit {v}");
            assert!(v.abs() <= lim, "digit {v} outside the table for w={w}");
            if let Some(p) = last {
                assert!(
                    i - p >= w as usize,
                    "digits at {p} and {i} closer than w={w}"
                );
            }
            last = Some(i);
            let term = cb(&[u64::from(v.unsigned_abs()), 0, 0, 0]).mul_mod(&pow, &n);
            acc = if v > 0 {
                acc.add_mod(&term, &n)
            } else {
                acc.sub_mod(&term, &n)
            };
        }
        pow = pow.add_mod(&pow, &n);
    }
    assert_eq!(len, last.map_or(0, |p| p + 1), "returned length");
    cbw(&acc)
}

/// The wNAF of s at window w reconstructs s, and the `i8` and `i16`
/// builds agree where both fit; false if the guard declines.
fn wnaf_roundtrip(s: &Scalar, w: u32) -> bool {
    let mut d16 = [0i16; WNAF_LEN];
    let Some(len) = try_wnaf(&mut d16, s, w) else {
        return false;
    };
    assert_eq!(
        check_wnaf(&d16, len, w),
        scw(s),
        "wNAF(w={w}) does not reconstruct"
    );
    if w <= 8 {
        let mut d8 = [0i8; WNAF_LEN];
        let len8 = try_wnaf(&mut d8, s, w).expect("i8 and i16 agree on Some");
        assert_eq!(len8, len);
        assert!(d8.iter().zip(d16.iter()).all(|(a, b)| i16::from(*a) == *b));
    }
    true
}

/// The fold the builder applies: s, or N - s when bit 255 is set.
fn folded(w: &[u64; 4]) -> [u64; 4] {
    if w[3] >> 63 == 1 { sub4(&NORD, w) } else { *w }
}

/// The windows the reconstruction checks run at: the key's, the largest
/// `i8` one, the generator tables' and the largest `i16` one.
const WINDOWS: [u32; 4] = [5, 8, crate::g_tables::WINDOW_G, 16];

/// On random scalars: r1 + lambda*r2 = k by crypto-bigint, both halves
/// below 2^128 after the fold, the split's own bound check, and both
/// halves through the wNAF guard; every sixteenth case reconstructs at
/// every window.
#[test]
fn split_random_identity_bounds_and_wnaf() {
    let n = cb_n();
    let l = cb(&scw(&LAMBDA));
    let mut r = SplitMix64(0x6c70_0001);
    for k in 0..cases() / 4 {
        let wk = rand_sc(&mut r);
        let s = sc(&wk);
        let (r1, r2) = s.split_lambda();
        split_lambda_verify(&r1, &r2, &s);
        let (w1, w2) = (scw(&r1), scw(&r2));
        assert_eq!(
            cbw(&cb(&w1).add_mod(&cb(&w2).mul_mod(&l, &n), &n)),
            wk,
            "r1 + lambda*r2 != k"
        );
        let (f1, f2) = (folded(&w1), folded(&w2));
        assert!(
            f1[2] == 0 && f1[3] == 0 && f2[2] == 0 && f2[3] == 0,
            "a split half >= 2^128 after the fold"
        );
        let mut d = [0i8; WNAF_LEN];
        assert!(
            try_wnaf(&mut d, &r1, 5).is_some() && try_wnaf(&mut d, &r2, 5).is_some(),
            "the guard declined a split half"
        );
        if k % 16 == 0 {
            for w in WINDOWS {
                assert!(wnaf_roundtrip(&r1, w) && wnaf_roundtrip(&r2, w));
            }
        }
    }
}

/// The edges: 0, 1, 2, N - 1, N - 2, lambda and its negation and square,
/// (N-1)/2 and (N+1)/2, 2^127, 2^128 - 1, 2^128, 2^128 + 1, 2^255, 2^128
/// +- d and N - 2^128 - d for d up to 64, and libsecp256k1's scalars near
/// the split's bounds: the split's check, every window's reconstruction of
/// both halves, and `split_128`'s halves.
#[test]
fn split_edges_and_near_bounds() {
    let nm1 = sub4(&NORD, &[1, 0, 0, 0]);
    let h = [
        nm1[0] >> 1 | nm1[1] << 63,
        nm1[1] >> 1 | nm1[2] << 63,
        nm1[2] >> 1 | nm1[3] << 63,
        nm1[3] >> 1,
    ];
    let mut h1 = h;
    h1[0] += 1;
    let mut ks: Vec<[u64; 4]> = vec![
        [0; 4],
        [1, 0, 0, 0],
        [2, 0, 0, 0],
        nm1,
        sub4(&NORD, &[2, 0, 0, 0]),
        scw(&LAMBDA),
        scw(&-LAMBDA),
        scw(&(LAMBDA * LAMBDA)),
        h,
        h1,
        [0, 1 << 63, 0, 0],
        [u64::MAX, u64::MAX, 0, 0],
        [0, 0, 1, 0],
        [1, 0, 1, 0],
        [0, 0, 0, 1 << 63],
    ];
    for d in 1..=64u64 {
        ks.push(reduce_n(&[d.wrapping_neg(), u64::MAX, 0, 0]));
        ks.push(reduce_n(&[d, 0, 1, 0]));
        ks.push(sub4(&NORD, &[d, 0, 1, 0]));
    }
    for v in super::vectors::SCALARS_NEAR_SPLIT_BOUNDS {
        ks.push(be_to_words(&hex32(v)));
    }
    for wk in &ks {
        let s = sc(wk);
        let (r1, r2) = s.split_lambda();
        split_lambda_verify(&r1, &r2, &s);
        for w in WINDOWS {
            assert!(
                wnaf_roundtrip(&r1, w) && wnaf_roundtrip(&r2, w),
                "edge k={wk:x?}: the guard declined"
            );
        }
        let (lo, hi) = s.split_128();
        for w in WINDOWS {
            assert!(wnaf_roundtrip(&lo, w) && wnaf_roundtrip(&hi, w));
        }
    }
}

/// a + b*lambda for |a|, |b| <= 40 splits to exactly (a, b), so the
/// collision grid's digit strings are the ones it intends.
#[test]
fn small_combinations_split_exactly() {
    let s = |x: i64| {
        let v = Scalar::from_u32(x.unsigned_abs() as u32);
        if x < 0 { -v } else { v }
    };
    for a in -40i64..=40 {
        for b in -40i64..=40 {
            let (r1, r2) = (s(a) + s(b) * LAMBDA).split_lambda();
            assert!(r1 == s(a) && r2 == s(b), "split({a} + {b}*lambda)");
        }
    }
}

/// `test_scalar_split` (tests.c:5961-5985) as `run_endomorphism_tests`
/// (:5988-6007) calls it: 0, 1, -1, lambda, lambda + 1, random scalars
/// and the scalars near the bounds; r2*lambda + r1 = k, and each half, or
/// its negation when above N/2, has its top 16 bytes zero.
#[test]
fn endomorphism_split() {
    let half_n = [
        0xDFE9_2F46_681B_20A0,
        0x5D57_6E73_57A4_501D,
        u64::MAX,
        0x7FFF_FFFF_FFFF_FFFF,
    ];
    let check = |full: &Scalar| {
        let (s1, slam) = full.split_lambda();
        assert!(LAMBDA * slam + s1 == *full);
        for x in [s1, slam] {
            let w = scw(&x);
            let x = if ge4(&w, &half_n) && w != half_n {
                -x
            } else {
                x
            };
            assert_eq!(x.to_be_bytes()[..16], [0u8; 16]);
        }
    };
    let mut ks = vec![
        Scalar::ZERO,
        Scalar::ONE,
        -Scalar::ONE,
        LAMBDA,
        LAMBDA + Scalar::ONE,
    ];
    let mut r = SplitMix64(0x656e_646f);
    for _ in 0..cases() / 20 {
        ks.push(sc(&rand_sc(&mut r)));
    }
    for v in super::vectors::SCALARS_NEAR_SPLIT_BOUNDS {
        ks.push(Scalar::from_be_bytes(&hex32(v)).expect("below N"));
    }
    for k in &ks {
        check(k);
    }
}

/// The wNAF's properties at every window from 2 to 16 on its edges, and
/// its guard: `None` exactly when the folded value is at or above 2^128,
/// on constructed values (2^128, 2^128 + 1, N - 2^128, 2^192, N - 2^192)
/// and on random ones of every shape.
#[test]
fn wnaf_properties_and_guard() {
    let mut r = SplitMix64(0x6c70_0002);
    let two128 = [0, 0, 1, 0];
    let edge: Vec<[u64; 4]> = vec![
        [0; 4],
        [1, 0, 0, 0],
        [u64::MAX, u64::MAX, 0, 0],
        [0, 1 << 63, 0, 0],
        sub4(&NORD, &[u64::MAX, u64::MAX, 0, 0]),
        sub4(&NORD, &[1, 0, 0, 0]),
    ];
    for w in &edge {
        for win in 2..=16u32 {
            assert!(wnaf_roundtrip(&sc(w), win), "edge {w:x?} w={win}");
        }
    }
    for w in [
        two128,
        [1, 0, 1, 0],
        sub4(&NORD, &two128),
        [0, 0, 0, 1],
        sub4(&NORD, &[0, 0, 0, 1]),
    ] {
        let mut d = [0i16; WNAF_LEN];
        assert!(
            try_wnaf(&mut d, &sc(&w), 15).is_none(),
            "the guard let {w:x?} through"
        );
    }
    let (mut some, mut none) = (0u64, 0u64);
    for k in 0..cases() / 4 {
        let w = match k % 3 {
            0 => rand_sc(&mut r),
            1 => [r.next_u64(), r.next_u64(), 0, 0],
            _ => sub4(&NORD, &[r.next_u64(), r.next_u64(), 0, 0]),
        };
        let f = folded(&w);
        let expect = f[2] == 0 && f[3] == 0;
        let win = 2 + (k % 15) as u32;
        let mut d = [0i16; WNAF_LEN];
        let got = try_wnaf(&mut d, &sc(&w), win);
        assert_eq!(
            got.is_some(),
            expect,
            "the guard disagrees with the fold for {w:x?}"
        );
        if let Some(len) = got {
            some += 1;
            if k % 8 < 3 {
                assert_eq!(check_wnaf(&d, len, win), w);
            }
        } else {
            none += 1;
        }
    }
    assert!(some > 0 && none > 0);
}
