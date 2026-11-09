// SPDX-License-Identifier: ISC AND MIT
//
// `ecmult_constants_*` follow libsecp256k1 src/tests.c's
// `test_ecmult_accumulate`, `test_ecmult_constants_2bit`,
// `test_ecmult_constants_sha` and their expected hashes, and
// `point_times_order` and `ecmult_target_mode1` its
// `test_point_times_order`, `run_point_times_order` and
// `test_ecmult_target` (Copyright (c) 2013, 2014, 2015 Pieter Wuille,
// Gregory Maxwell), as vendored by secp256k1-sys 0.14.1.  MIT; see
// NOTICE.
//
//! The multiply: the collision grid, where the four digit strings meet
//! each other and the key's multiples, with every special case of every
//! addition site counted; random and edge scalars against k256's
//! combined multiply and its constant-time `lincomb`; final points at the
//! x-check's boundaries, with the check itself; wNAF strings that reach
//! position 128 and digits that index the tables' last entries;
//! libsecp256k1's known-answer hashes over many multiples of G; the
//! public point API; and a digest of fixed-seed results that every build
//! profile must reproduce.

use dcroxide_testutil::SplitMix64;
use k256::elliptic_curve::group::CurveAffine;
use k256::elliptic_curve::ops::{LinearCombination, MulByGeneratorVartime};
use k256::elliptic_curve::point::{AffineCoordinates, DecompressPoint};
use k256::elliptic_curve::subtle::Choice;
use k256::{AffinePoint, ProjectivePoint};
use sha2::{Digest, Sha256};

use super::branches::{self, BRANCH_NAMES, SITE_NAMES, Site};
use super::points::*;
use super::*;
use crate::group::{G, Ge, Gej};
use crate::scalar::{LAMBDA, Scalar};
use crate::wnaf::{Digit, WNAF_LEN, try_wnaf};

/// na*Q + ng*G by the crate, as affine bytes; the wNAF guard must never
/// decline.
fn ours(q: &Ge, na: &Scalar, ng: &Scalar) -> Option<Bytes2> {
    let r = crate::ecmult::ecmult_var(q, na, ng).expect("the wNAF guard declined");
    gej_bytes(&r)
}

/// na*Q + ng*G by k256's `mul_by_generator_and_mul_add_vartime`.
fn k_ref(q: &ProjectivePoint, na: &Scalar, ng: &Scalar) -> Option<Bytes2> {
    kp_bytes(&ProjectivePoint::mul_by_generator_and_mul_add_vartime(
        &to_k(ng),
        &to_k(na),
        q,
    ))
}

/// na*Q + ng*G by k256's constant-time `lincomb`.
fn k_lincomb(q: &ProjectivePoint, na: &Scalar, ng: &Scalar) -> Option<Bytes2> {
    kp_bytes(&ProjectivePoint::lincomb(&[
        (ProjectivePoint::GENERATOR, to_k(ng)),
        (*q, to_k(na)),
    ]))
}

/// Whether the tests run at the release and soak-asserts volume.
fn full() -> bool {
    cases() >= 1_000_000
}

/// The collision grid: Q in {+-G, +-2G, +-3G, +-lambda G, +-lambda^2 G,
/// +-2^128 G, +-lambda 2^128 G}, na = a + b*lambda and ng = c + d*2^128
/// for a, b, c, d in [-3, 3] (in [-2, 2] below the 10^6 volume).  The
/// split gives exactly (a, b), so the four digit strings are known and
/// small, and their partial sums collide with each other and with Q's
/// multiples; every result, infinity included, against k256.  Every
/// special case of every addition site must fire except an addend at
/// infinity, which no table entry is.
#[test]
fn collision_grid() {
    let t = pow2_128();
    let gk = ProjectivePoint::GENERATOR;
    let (lk, tk) = (to_k(&LAMBDA), to_k(&t));
    let bases: [(&str, ProjectivePoint); 7] = [
        ("G", gk),
        ("2G", gk.double()),
        ("3G", gk * k256::Scalar::from(3u64)),
        ("lG", gk * lk),
        ("l^2G", gk * (lk * lk)),
        ("2^128G", gk * tk),
        ("l2^128G", gk * (lk * tk)),
    ];
    let range: i64 = if full() { 3 } else { 2 };
    let (mut total, mut infinities) = (0u64, 0u64);
    branches::reset();
    for (name, b) in bases {
        for qk in [b, -b] {
            let q = ge_from_kp(&qk);
            for a in -range..=range {
                for bb in -range..=range {
                    let na = sc_i64(a) + sc_i64(bb) * LAMBDA;
                    let (s1, s2) = na.split_lambda();
                    assert!(s1 == sc_i64(a) && s2 == sc_i64(bb), "split of {a} + {bb}l");
                    for c in -range..=range {
                        for d in -range..=range {
                            let ng = sc_i64(c) + sc_i64(d) * t;
                            let want = k_ref(&qk, &na, &ng);
                            infinities += u64::from(want.is_none());
                            assert_eq!(
                                ours(&q, &na, &ng),
                                want,
                                "grid Q={name} (or its negation) a={a} b={bb} c={c} d={d}"
                            );
                            total += 1;
                        }
                    }
                }
            }
        }
    }
    let c = branches::get();
    println!("collision grid: {total} cases (range +-{range}), {infinities} at infinity");
    for (s, name) in SITE_NAMES.iter().enumerate() {
        println!("  {name:>8}: {:?}", c[s]);
    }
    for s in [Site::A, Site::LambdaA, Site::G, Site::G128] {
        for b in [0usize, 1, 3, 4] {
            assert!(
                c[s as usize][b] > 0,
                "site {} branch {} never fired",
                SITE_NAMES[s as usize],
                BRANCH_NAMES[b]
            );
        }
        assert_eq!(c[s as usize][2], 0, "an addend at infinity in the loop");
    }
    let dbl = c[Site::Double as usize];
    assert!(dbl[0] > 0 && dbl[1] > 0);
    assert!(infinities > 0);
}

/// Random keys from a k256 walk with na and ng uniform, structured, zero,
/// small, near N or near 2^128, against k256's combined multiply, and on
/// every eighth case also against its constant-time `lincomb`.  A tenth
/// of the volume.
#[test]
fn random_vs_k256() {
    let n = cases() / 10;
    let threads = 4u64;
    let inf: u64 = std::thread::scope(|s| {
        (0..threads)
            .map(|th| {
                s.spawn(move || {
                    let mut r = SplitMix64(0x00ec_0000 + th);
                    let mut walk = Walk::new(&mut r);
                    let mut inf = 0u64;
                    for i in 0..n / threads {
                        let qk = ProjectivePoint::from(walk.next(&mut r));
                        let q = ge_from_kp(&qk);
                        let pick = |r: &mut SplitMix64| -> Scalar {
                            match r.below(16) {
                                0 => Scalar::ZERO,
                                1 => sc_i64(r.below(1 << 20) as i64 - (1 << 19)),
                                2 => sc_i64(-(r.below(1 << 16) as i64) - 1),
                                3 => pow2_128() + sc_i64(r.below(1 << 16) as i64 - (1 << 15)),
                                _ => rand_scalar(r),
                            }
                        };
                        let (na, ng) = (pick(&mut r), pick(&mut r));
                        let want = k_ref(&qk, &na, &ng);
                        inf += u64::from(want.is_none());
                        assert_eq!(ours(&q, &na, &ng), want, "random case {i} thread {th}");
                        if i % 8 == 0 {
                            assert_eq!(k_lincomb(&qk, &na, &ng), want);
                        }
                    }
                    inf
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().expect("thread"))
            .sum()
    });
    println!("random_vs_k256: {n} cases, {inf} at infinity");
}

/// The edge scalars: 0, 1, 2, -1, -2, lambda, -lambda, lambda^2, 2^128 and
/// its neighbours and negation, 2^255 and its negation, 2^127, (N-1)/2 and
/// (N+1)/2, and libsecp256k1's 20 scalars near the split's bounds; every
/// pair, for six keys (two below the 10^6 volume), against k256's
/// combined multiply, and against its `lincomb` (on every eighth pair
/// below the 10^6 volume).
#[test]
fn edge_scalars_vs_k256() {
    let half = |w: [u64; 4]| Scalar::from_be_bytes(&words_to_be(&w)).expect("below N");
    let two255 = Scalar::reduce_be_bytes(&words_to_be(&[0, 0, 0, 1 << 63]));
    let mut edges: Vec<Scalar> = vec![
        Scalar::ZERO,
        Scalar::ONE,
        sc_i64(2),
        sc_i64(-1),
        sc_i64(-2),
        LAMBDA,
        -LAMBDA,
        LAMBDA * LAMBDA,
        pow2_128(),
        pow2_128() + Scalar::ONE,
        pow2_128() + sc_i64(-1),
        -pow2_128(),
        two255,
        -two255,
        Scalar::reduce_be_bytes(&words_to_be(&[0, 1 << 63, 0, 0])),
        half([
            0xDFE9_2F46_681B_20A0,
            0x5D57_6E73_57A4_501D,
            u64::MAX,
            0x7FFF_FFFF_FFFF_FFFF,
        ]),
        half([
            0xDFE9_2F46_681B_20A1,
            0x5D57_6E73_57A4_501D,
            u64::MAX,
            0x7FFF_FFFF_FFFF_FFFF,
        ]),
    ];
    for v in super::vectors::SCALARS_NEAR_SPLIT_BOUNDS {
        edges.push(Scalar::from_be_bytes(&hex32(v)).expect("below N"));
    }
    assert_eq!(edges.len(), 37);
    let mut r = SplitMix64(0xed6e);
    let mut walk = Walk::new(&mut r);
    let mut qs = vec![
        ProjectivePoint::GENERATOR,
        ProjectivePoint::from(walk.next(&mut r)),
    ];
    if full() {
        qs.push(-ProjectivePoint::GENERATOR);
        for _ in 0..3 {
            qs.push(ProjectivePoint::from(walk.next(&mut r)));
        }
    }
    let mut k = 0u64;
    for qk in &qs {
        let q = ge_from_kp(qk);
        for na in &edges {
            for ng in &edges {
                let want = k_ref(qk, na, ng);
                assert_eq!(ours(&q, na, ng), want, "edge na={na:?} ng={ng:?}");
                if full() || k.is_multiple_of(8) {
                    assert_eq!(k_lincomb(qk, na, ng), want);
                }
                k += 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Final points at the x check's boundaries.

/// A class of boundary target points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    /// X.x in [N, N + 2^32): r = X.x - N is tiny and step 10 accepts.
    XAboveN,
    /// X.x in [P - N, N): step 8 accepts an r at or above P - N.
    XInPMinusNToN,
    /// A tiny x.
    TinyX,
    /// A tiny y, or a tiny p - y (below 200).
    TinyY,
}

/// The point with x and the given oddness, by k256's decompression.
fn k_decomp(x: &[u64; 4], odd: bool) -> Option<AffinePoint> {
    Option::from(AffinePoint::decompress(
        &words_to_be(x).into(),
        Choice::from(u8::from(odd)),
    ))
}

/// The boundary target points, each with its class.
fn boundary_points() -> Vec<(Class, AffinePoint)> {
    let mut r = SplitMix64(0xb0_0d);
    let mut out = Vec::new();
    let pmn = sub4(&P, &NORD);
    let mut ks: Vec<u64> = (1..=600).collect();
    ks.extend((0..600).map(|_| r.below(1 << 32)));
    ks.push((1 << 32) - 1);
    for k in ks {
        if let Some(p) = k_decomp(
            &super::decompress_tests::add_small(&NORD, k),
            r.below(2) == 1,
        ) {
            out.push((Class::XAboveN, p));
        }
    }
    let mut xs: Vec<[u64; 4]> = (0..400)
        .map(|k| super::decompress_tests::add_small(&pmn, k))
        .collect();
    xs.extend((1..=400).map(|k| sub4(&NORD, &[k, 0, 0, 0])));
    for _ in 0..400 {
        let mut w = NORD;
        w[0] = r.next_u64();
        w[1] = r.next_u64() & 0x7FFF_FFFF_FFFF_FFFF;
        if ge4(&w, &pmn) && !ge4(&w, &NORD) {
            xs.push(w);
        }
    }
    for x in xs {
        if let Some(p) = k_decomp(&x, r.below(2) == 1) {
            out.push((Class::XInPMinusNToN, p));
        }
    }
    for x in 1..=600u64 {
        if let Some(p) = k_decomp(&[x, 0, 0, 0], r.below(2) == 1) {
            out.push((Class::TinyX, p));
        }
    }
    for (x, y) in super::decompress_tests::tiny_y_points(200) {
        let xw = be_to_words(&x);
        for odd in [false, true] {
            let p = k_decomp(&xw, odd).expect("a tiny-y x is on the curve");
            let yw = be_to_words(&p.y().into());
            assert!(yw == [y, 0, 0, 0] || yw == sub4(&P, &[y, 0, 0, 0]));
            out.push((Class::TinyY, p));
        }
    }
    out
}

/// (Q, u1, u2) with u1*G + u2*Q = target for random u1 and nonzero u2:
/// Q = (target - u1*G) / u2, on k256.  `None` when Q would be infinity.
fn solve_q(target: &ProjectivePoint, r: &mut SplitMix64) -> Option<(AffinePoint, Scalar, Scalar)> {
    let u1 = rand_scalar(r);
    let u2 = loop {
        let s = rand_scalar(r);
        if !s.is_zero() {
            break s;
        }
    };
    let u2i = to_k(&u2).invert_vartime().expect("nonzero");
    let qa = ((*target - ProjectivePoint::GENERATOR * to_k(&u1)) * u2i).to_affine();
    if bool::from(qa.is_identity()) {
        return None;
    }
    Some((qa, u1, u2))
}

/// Every boundary point reached as a multiply's result, from one random
/// (u1, u2) each (four at the 10^6 volume), compared exactly; and the x
/// check on it: true for X.x, false for X.x - N when X.x >= N and for
/// X.x + 1.
#[test]
fn boundary_final_points() {
    let pts = boundary_points();
    let mut r = SplitMix64(0xb0_0e);
    let tries = if full() { 4 } else { 1 };
    let mut by_class = [0u64; 4];
    for (class, p) in &pts {
        let pp = ProjectivePoint::from(*p);
        let want = kp_bytes(&pp);
        for _ in 0..tries {
            let Some((qa, u1, u2)) = solve_q(&pp, &mut r) else {
                continue;
            };
            let q = ge_from_k(&qa);
            let x = crate::ecmult::ecmult_var(&q, &u2, &u1).expect("guard");
            assert_eq!(gej_bytes(&x), want, "boundary {class:?}");
            let pt = crate::Point::from_gej(x);
            let xb: [u8; 32] = p.x().into();
            assert!(pt.x_equals_var(&xb));
            let xw = be_to_words(&xb);
            if ge4(&xw, &NORD) {
                assert!(!pt.x_equals_var(&words_to_be(&sub4(&xw, &NORD))));
            }
            assert!(!pt.x_equals_var(&words_to_be(&add_p(&xw, &[1, 0, 0, 0]))));
            by_class[*class as usize] += 1;
        }
    }
    println!(
        "boundary_final_points: {} targets; cases by class {by_class:?}",
        pts.len()
    );
    assert!(by_class.iter().all(|&c| c > 0));
}

// ---------------------------------------------------------------------------
// Long strings and the tables' last entries.

/// The wNAF's length and whether a digit indexes the last table entry.
fn wnaf_stats<T: Digit>(s: &Scalar, w: u32) -> (usize, bool) {
    let mut d = [T::ZERO; WNAF_LEN];
    let bits = try_wnaf(&mut d, s, w).expect("guard");
    let top = (1i32 << (w - 1)) - 1;
    (bits, d.iter().any(|x| x.to_i32().abs() == top))
}

/// Per digit string, how often the wNAF reaches position 128 (129
/// positions used) and how often a digit indexes the last table entry,
/// with constructed generator scalars that force both on each of its
/// strings and libsecp256k1's scalars near the split's bounds for the
/// key's; each must happen.  Every result against k256.
#[test]
fn long_strings_and_last_entries() {
    let n = (cases() / 20).max(1_000);
    let mut r = SplitMix64(0x6269_7473_3132_39aa);
    let mut walk = Walk::new(&mut r);
    let w = crate::g_tables::WINDOW_G;
    let two128 = pow2_128();
    let mut constructed: Vec<Scalar> = Vec::new();
    let top = (1u64 << (w - 1)) - 1;
    let neg_top = (1u64 << (w - 1)) + 1; // first digit -(2^(w-1) - 1)
    for lo in [top, neg_top, 0] {
        for hi in [top, neg_top, 0] {
            constructed.push(sc_i64(lo as i64) + sc_i64(hi as i64) * two128);
        }
    }
    let be = |w: [u64; 4]| Scalar::from_be_bytes(&words_to_be(&w)).expect("below N");
    constructed.push(be([u64::MAX, u64::MAX, u64::MAX - 1, u64::MAX >> 1]));
    constructed.push(be([u64::MAX, u64::MAX, 0, 0]));
    constructed.push(be([0, 0, u64::MAX - 1, u64::MAX - 1]));

    // Key scalars whose lambda half reaches position 128, which random
    // scalars rarely give (its bound is about 2^127.1): searched for on a
    // fixed seed.
    let mut s = SplitMix64(0x6c61_6d31_3239);
    let mut long_lam: Vec<Scalar> = Vec::new();
    for _ in 0..1_000_000 {
        let k = Scalar::reduce_be_bytes(&words_to_be(&words(&mut s)));
        if wnaf_stats::<i8>(&k.split_lambda().1, crate::ecmult::WINDOW_A).0 == 129 {
            long_lam.push(k);
            if long_lam.len() == 4 {
                break;
            }
        }
    }
    assert!(
        !long_lam.is_empty(),
        "no lambda half of 129 positions found"
    );
    let near = super::vectors::SCALARS_NEAR_SPLIT_BOUNDS
        .iter()
        .map(|v| Scalar::from_be_bytes(&hex32(v)).expect("below N"));
    let key_scalars: Vec<Scalar> = long_lam.into_iter().chain(near).collect();

    // [string][0: 129 positions, 1: last entry]
    let mut cnt_a = [[0u64; 2]; 2];
    let mut cnt_g = [[0u64; 2]; 2];
    let total = n as usize + constructed.len().max(key_scalars.len());
    for k in 0..total {
        let qk = ProjectivePoint::from(walk.next(&mut r));
        let q = ge_from_kp(&qk);
        let na = if k < n as usize {
            rand_scalar(&mut r)
        } else {
            key_scalars[(k - n as usize) % key_scalars.len()]
        };
        let ng = if k < n as usize {
            rand_scalar(&mut r)
        } else {
            constructed[(k - n as usize) % constructed.len()]
        };
        if !na.is_zero() {
            let (a1, al) = na.split_lambda();
            for (si, s) in [a1, al].iter().enumerate() {
                let (b, l) = wnaf_stats::<i8>(s, crate::ecmult::WINDOW_A);
                cnt_a[si][0] += u64::from(b == 129);
                cnt_a[si][1] += u64::from(l);
            }
        }
        let (g1, g128) = ng.split_128();
        for (si, s) in [g1, g128].iter().enumerate() {
            let (b, l) = wnaf_stats::<i16>(s, w);
            cnt_g[si][0] += u64::from(b == 129);
            cnt_g[si][1] += u64::from(l);
        }
        assert_eq!(ours(&q, &na, &ng), k_ref(&qk, &na, &ng), "case {k}");
    }
    println!("long strings and last entries: A {cnt_a:?}, G {cnt_g:?}");
    assert!(cnt_a.iter().chain(&cnt_g).all(|c| c[0] > 0 && c[1] > 0));
}

// ---------------------------------------------------------------------------
// libsecp256k1's known answers.

/// `test_ecmult_accumulate` (tests.c:5724-5753) for the ways this crate
/// multiplies: x*G as ecmult(G, x, 0) and as ecmult(G, 0, x), the latter
/// the C's ecmult(infinity, 0, x), since A cannot be infinity at the API.
/// Both must agree; the point is hashed as its 65-byte uncompressed
/// serialization, or one zero byte for infinity.
fn accumulate(acc: &mut Sha256, x: &Scalar) {
    let a = crate::ecmult::ecmult_var(&G, x, &Scalar::ZERO).expect("guard");
    let b = crate::ecmult::ecmult_var(&G, &Scalar::ZERO, x).expect("guard");
    let pa = gej_bytes(&a);
    assert_eq!(pa, gej_bytes(&b), "x*G two ways, x = {x:?}");
    match pa {
        None => acc.update([0u8]),
        Some((px, py)) => {
            acc.update([4u8]);
            acc.update(px);
            acc.update(py);
        }
    }
}

/// The scalars of `test_ecmult_constants_2bit` (tests.c:5755-5797): i and
/// -i for i in 0..=36, then j*2^i for i in 0..256 and odd j below 256.
fn scalars_2bit() -> Vec<Scalar> {
    let mut v = Vec::new();
    for i in 0..=36u32 {
        let x = Scalar::from_u32(i);
        v.push(x);
        v.push(-x);
    }
    for i in 0..256 {
        for j in (1..256u32).step_by(2) {
            let mut x = Scalar::from_u32(j);
            for _ in 0..i {
                x = x + x;
            }
            v.push(x);
        }
    }
    v
}

/// The scalars of `test_ecmult_constants_sha` (tests.c:5799-5841): 0, 1,
/// -1, then SHA256(LE32(prefix) || LE16(i)) mod N for i below `iter`.
fn scalars_sha(prefix: u32, iter: u16) -> Vec<Scalar> {
    let mut v = vec![Scalar::ZERO, Scalar::ONE, -Scalar::ONE];
    for i in 0..iter {
        let mut inp = prefix.to_le_bytes().to_vec();
        inp.extend_from_slice(&i.to_le_bytes());
        let h: [u8; 32] = Sha256::digest(&inp).into();
        v.push(Scalar::reduce_be_bytes(&h));
    }
    v
}

/// libsecp256k1's expected hashes over x*G for the scalars of
/// `test_ecmult_constants_2bit` and both `test_ecmult_constants_sha` runs
/// (`run_ecmult_constants`, tests.c:5843-5875), "computed using an
/// independent implementation".  At the 10^6 volume all three run in full;
/// below it the first 64 scalars of each are checked against k256 instead.
#[test]
fn ecmult_constants() {
    const EXPECTED_2BIT: [u8; 32] = [
        0xe4, 0x71, 0x1b, 0x4d, 0x14, 0x1e, 0x68, 0x48, 0xb7, 0xaf, 0x47, 0x2b, 0x4c, 0xd2, 0x04,
        0x14, 0x3a, 0x75, 0x87, 0x60, 0x1a, 0xf9, 0x63, 0x60, 0xd0, 0xcb, 0x1f, 0xaa, 0x85, 0x9a,
        0xb7, 0xb4,
    ];
    const EXPECTED_6BIT20: [u8; 32] = [
        0x68, 0xb6, 0xed, 0x6f, 0x28, 0xca, 0xc9, 0x7f, 0x8e, 0x8b, 0xd6, 0xc0, 0x61, 0x79, 0x34,
        0x6e, 0x5a, 0x8f, 0x2b, 0xbc, 0x3e, 0x1f, 0xc5, 0x2e, 0x2a, 0xd0, 0x45, 0x67, 0x7f, 0x95,
        0x95, 0x8e,
    ];
    const EXPECTED_8BIT8: [u8; 32] = [
        0x8b, 0x65, 0x8e, 0xea, 0x86, 0xae, 0x3c, 0x95, 0x90, 0xb6, 0x77, 0xa4, 0x8c, 0x76, 0xd9,
        0xec, 0xf5, 0xab, 0x8a, 0x2f, 0xfd, 0xdb, 0x19, 0x12, 0x1a, 0xee, 0xe6, 0xb7, 0x6e, 0x05,
        0x3f, 0xc6,
    ];
    let runs = [
        ("2bit", scalars_2bit(), EXPECTED_2BIT),
        ("sha 1024", scalars_sha(4_808_378, 1024), EXPECTED_6BIT20),
        ("sha 2048", scalars_sha(1_607_366_309, 2048), EXPECTED_8BIT8),
    ];
    for (name, xs, want) in runs {
        if full() {
            let mut acc = Sha256::new();
            for x in &xs {
                accumulate(&mut acc, x);
            }
            let got: [u8; 32] = acc.finalize().into();
            assert_eq!(got, want, "test_ecmult_constants_{name}");
        } else {
            for x in xs.iter().take(64) {
                assert_eq!(
                    ours(&G, x, &Scalar::ZERO),
                    kp_bytes(&(ProjectivePoint::GENERATOR * to_k(x))),
                    "{name}: x = {x:?}"
                );
                assert_eq!(ours(&G, &Scalar::ZERO, x), ours(&G, x, &Scalar::ZERO));
            }
        }
    }
}

/// `test_point_times_order` (tests.c:4600-4633) on the points of
/// `run_point_times_order` (:4715-4734): x = 2 squared 500 times, the
/// point with each x that has one (odd y): x*P + x*G plus (N-x)*P +
/// (N-x)*G is infinity, and the zero and one edges; then the known value
/// of x after the squarings.  Below the 10^6 volume, every fifth point.
#[test]
fn point_times_order() {
    let mut r = SplitMix64(0x7074_6f00);
    let mut x = fe_w(&[2, 0, 0, 0]);
    let step = if full() { 1 } else { 5 };
    let mut seen = 0u64;
    for i in 0..500 {
        if let Some(p) = Ge::set_xo_var(&norm(&x), true) {
            assert!(p.is_valid_var());
            if i % step == 0 {
                let s = rand_scalar(&mut r);
                let ns = -s;
                let r1 = crate::ecmult::ecmult_var(&p, &s, &s).expect("guard");
                let r2 = crate::ecmult::ecmult_var(&p, &ns, &ns).expect("guard");
                let sum = r1.add_var(&r2, None);
                assert!(sum.is_infinity());
                let z = crate::ecmult::ecmult_var(&p, &Scalar::ZERO, &Scalar::ZERO).expect("guard");
                assert!(z.is_infinity());
                let one =
                    crate::ecmult::ecmult_var(&p, &Scalar::ONE, &Scalar::ZERO).expect("guard");
                assert_eq!(gej_bytes(&one), ge_bytes(&p));
                let g1 = crate::ecmult::ecmult_var(&p, &Scalar::ZERO, &Scalar::ONE).expect("guard");
                assert_eq!(gej_bytes(&g1), ge_bytes(&G));
                seen += 1;
            }
        }
        x = x.sqr();
    }
    assert!(seen > 0);
    let xr = Fe::from_be_u32([
        0x7603_CB59,
        0xB0EF_6C63,
        0xFE60_8479,
        0x2A0C_378C,
        0xDB32_33A8,
        0x0F8A_9A09,
        0xA877_DEAD,
        0x31B3_8C45,
    ]);
    assert!(norm(&x).equal(&xr));
}

/// `test_ecmult_target` mode 1 (tests.c:4665-4701) for each of
/// libsecp256k1's scalars near the split's bounds: random n1, n2 = -(n1 +
/// target), and n1*P + n2*P + target*P is infinity for a random P.  Twice
/// per scalar, 64 times at the 10^6 volume.
#[test]
fn ecmult_target_mode1() {
    let mut r = SplitMix64(0x7461_7267);
    let mut walk = Walk::new(&mut r);
    let reps = if full() { 64 } else { 2 };
    for v in super::vectors::SCALARS_NEAR_SPLIT_BOUNDS {
        let target = Scalar::from_be_bytes(&hex32(v)).expect("below N");
        for _ in 0..reps {
            let n1 = rand_scalar(&mut r);
            let n2 = -(n1 + target);
            let p = ge_from_k(&walk.next(&mut r));
            let m = |k: &Scalar| crate::ecmult::ecmult_var(&p, k, &Scalar::ZERO).expect("guard");
            let sum = m(&target).add_var(&m(&n1), None).add_var(&m(&n2), None);
            assert!(sum.is_infinity(), "target {v}");
        }
    }
}

// ---------------------------------------------------------------------------
// The public point API and the digest.

/// `Affine::from_be_coordinates` with the key's y, its negation, a wrong y
/// and coordinates at or above p; `y_is_odd`; and `ecmult_var` and
/// `Point` against k256, an infinite sum every sixteenth case (na*G +
/// (-na)*G).
#[test]
fn public_point_api() {
    use crate::{Affine, ecmult_var};
    let n = (cases() / 40).max(500);
    let mut r = SplitMix64(0x7075_625f_6170_6921);
    let mut walk = Walk::new(&mut r);
    let g = Affine::from_be_coordinates(&fe_bytes(&G.x), &fe_bytes(&G.y)).expect("G");
    let (mut inf, mut fin) = (0u64, 0u64);
    for k in 0..n {
        let q = ge_from_k(&walk.next(&mut r));
        let (qx, qy) = (fe_bytes(&q.x), fe_bytes(&q.y));
        let a = Affine::from_be_coordinates(&qx, &qy).expect("a valid key");
        assert_eq!(a.y_is_odd(), qy[31] & 1 == 1);
        assert!(Affine::from_be_coordinates(&qx, &fe_bytes(&q.y.negate(1))).is_some());
        let mut y1 = be_to_words(&qy);
        y1[0] ^= 1;
        if !ge4(&y1, &P) {
            assert!(Affine::from_be_coordinates(&qx, &words_to_be(&y1)).is_none());
        }
        assert!(Affine::from_be_coordinates(&words_to_be(&P), &qy).is_none());
        assert!(Affine::from_be_coordinates(&qx, &words_to_be(&P)).is_none());

        let (aa, na, ng) = if k % 16 == 0 {
            let na = rand_scalar(&mut r);
            (g, na, -na)
        } else {
            (a, rand_scalar(&mut r), rand_scalar(&mut r))
        };
        let pt = ecmult_var(&aa, &na, &ng).expect("guard");
        let want = k_ref(&ge_to_kp(aa.as_ge()), &na, &ng);
        assert_eq!(gej_bytes(pt.as_gej()), want);
        assert_eq!(pt.is_infinity(), want.is_none());
        match want {
            None => {
                assert!(!pt.x_equals_var(&[0; 32]));
                inf += 1;
            }
            Some((wx, _)) => {
                assert!(pt.x_equals_var(&wx));
                fin += 1;
            }
        }
    }
    assert!(inf > 0 && fin > 0);
}

/// x values at or above p for `x_equals_var`: p, p + k and 2^256 - 1.
fn x_ge_p_inputs() -> Vec<[u8; 32]> {
    let mut v = vec![words_to_be(&P), [0xff; 32]];
    for k in 1..64u64 {
        v.push(words_to_be(&super::decompress_tests::add_small(&P, k)));
    }
    v
}

/// Without debug assertions, `x_equals_var` is false for every x at or
/// above p, also on points whose X.x is x - p, which a reducing parse
/// would accept, and at infinity.
#[cfg(not(debug_assertions))]
#[test]
fn x_equals_var_is_false_for_x_at_or_above_p() {
    let mut r = SplitMix64(0x7867_6570_5f72_656c);
    let mut checked = 0u64;
    for xb in x_ge_p_inputs() {
        let red = words_to_be(&sub4(&be_to_words(&xb), &P));
        for odd in [false, true] {
            if let Some(a) = crate::Affine::decompress_var(&red, odd) {
                let z = rand_fe_nz(&mut r);
                let g = Gej::set_ge(a.as_ge());
                let gz = Gej {
                    x: g.x.mul(&z.sqr()),
                    y: g.y.mul(&z.sqr().mul(&z)),
                    z,
                    infinity: false,
                };
                let pt = crate::Point::from_gej(gz);
                assert!(pt.x_equals_var(&red));
                assert!(!pt.x_equals_var(&xb), "x >= p accepted");
                checked += 1;
            }
        }
        assert!(!crate::Point::from_gej(Gej::INFINITY).x_equals_var(&xb));
    }
    assert!(checked > 0);
}

/// With debug assertions, x at or above p stops on `x_equals_var`'s
/// assertion: no caller passes one.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "x_equals_var: x >= p")]
fn x_equals_var_asserts_on_x_at_or_above_p() {
    let pt = crate::Point::from_gej(Gej::set_ge(&G));
    let _ = pt.x_equals_var(&x_ge_p_inputs()[0]);
}

/// The multiply's results, the same in every build profile: FNV-1a over
/// the affine bytes of 512 fixed-seed `ecmult_var` results (a byte for
/// infinity) and the x check's answers on X.x and X.x + 1.  Builds with
/// debug assertions only read and assert, so the value is pinned.
#[test]
fn ecmult_digest_is_pinned() {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |b: &[u8]| {
        for &x in b {
            h ^= u64::from(x);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    };
    let mut r = SplitMix64(0x00d1_6e57);
    let mut walk = Walk::new(&mut r);
    for i in 0..512 {
        let q = ge_from_k(&walk.next(&mut r));
        let na = rand_scalar(&mut r);
        let ng = if i % 64 == 0 {
            -na
        } else {
            rand_scalar(&mut r)
        };
        let q = if i % 64 == 0 { G } else { q };
        let x = crate::ecmult::ecmult_var(&q, &na, &ng).expect("guard");
        let pt = crate::Point::from_gej(x);
        match gej_bytes(&x) {
            Some((px, py)) => {
                eat(&px);
                eat(&py);
                let x1 = words_to_be(&add_p(&be_to_words(&px), &[1, 0, 0, 0]));
                eat(&[
                    u8::from(pt.x_equals_var(&px)),
                    u8::from(pt.x_equals_var(&x1)),
                ]);
            }
            None => eat(&[0xff]),
        }
    }
    println!("ecmult digest {h:#018x}");
    assert_eq!(h, ECMULT_DIGEST, "the ecmult digest changed");
}

/// The digest's value, recorded from the first run.
const ECMULT_DIGEST: u64 = 0x77d7_af8c_ac8c_a190;
