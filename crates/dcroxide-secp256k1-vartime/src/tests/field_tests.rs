// SPDX-License-Identifier: ISC AND MIT
//
// `libsecp_sqrt`, `libsecp_be32_overflow`, `libsecp_equal_magnitude_bounds`,
// `libsecp_convert_bytes`, `libsecp_inverse_identity` and the inverse edge
// cases follow libsecp256k1 src/tests.c (Copyright (c) 2013, 2014, 2015
// Pieter Wuille, Gregory Maxwell), as vendored by secp256k1-sys 0.14.1.
// MIT; see NOTICE.
//
//! Field tests: every operation the field has today against the
//! schoolbook reference, crypto-bigint and k256, at every magnitude its
//! contract allows; `mul` and `sqr` limb for limb against fiat-crypto,
//! with the corner products; the boundary lattice through the
//! normalizations, both zero tests, negation, halving, equality and the
//! bytes; the byte limits and the storage form; the square root; the
//! inverse against both references, with libsecp256k1's identity and
//! fixed cases; libsecp256k1's own field tests where they cover these
//! operations; that `fe_verify` and the preconditions refuse limbs beyond
//! their claim; and a digest of fixed-seed results that every build
//! profile must reproduce.  Debug builds run every operation's magnitude
//! bookkeeping and `fe_verify` throughout.

use dcroxide_testutil::SplitMix64;
use fiat_crypto::secp256k1_dettman_64::{
    fiat_secp256k1_dettman_mul, fiat_secp256k1_dettman_square,
};

use super::*;
use crate::field::{Fe, FeRaw, FeStorage};
use crate::modinv64::modinv64_var_counted;

const M52: u64 = 0xF_FFFF_FFFF_FFFF;
const M48: u64 = 0xFFFF_FFFF_FFFF;

/// The largest limbs magnitude m allows.
fn max_limbs(m: u8) -> [u64; 5] {
    let k = 2 * u64::from(m);
    [M52 * k, M52 * k, M52 * k, M52 * k, M48 * k]
}

/// Random limbs at magnitude m (1..=32); `extreme` puts each limb at or
/// just under its maximum.
fn rand_fe(r: &mut SplitMix64, m: u8, extreme: bool) -> Fe {
    let mx = max_limbs(m);
    let mut n = [0u64; 5];
    for i in 0..5 {
        n[i] = if extreme {
            if r.next_u64() & 1 == 0 {
                mx[i]
            } else {
                mx[i] - r.below(256)
            }
        } else {
            r.below(mx[i] + 1)
        };
    }
    Fe::from_limbs(n, m, false)
}

/// Canonical 5x52 limbs of a value below 2^256, computed here, not by the
/// code under test.
fn words_to_limbs(w: &[u64; 4]) -> [u64; 5] {
    let bit = |i: usize| (w[i / 64] >> (i % 64)) & 1;
    let mut n = [0u64; 5];
    for i in 0..256 {
        n[i / 52] |= bit(i) << (i % 52);
    }
    n
}

/// a + b, magnitudes adding.
fn fe_add(a: &Fe, b: &Fe) -> Fe {
    let mut t = *a;
    t.add_assign(b);
    t
}

/// A small integer (<= 0x7FFF), normalized, magnitude 1 (0 for zero), as
/// `fe_set_int` gives it.
fn fe_int(a: u16) -> Fe {
    Fe::from_limbs([u64::from(a), 0, 0, 0, 0], u8::from(a != 0), true)
}

/// The same value at magnitude m (2..=32), with limbs near the bound: a
/// negation of the negation.
fn inflate(f: &Fe, m: u8) -> Fe {
    assert!((2..=32).contains(&m));
    norm(&norm(f).negate(1)).negate(m - 1)
}

/// Cases for the heavier reference comparisons: a tenth of `cases()`.
fn tenth() -> u64 {
    (cases() / 10).max(1)
}

#[test]
fn mul_limb_exact_vs_fiat_and_value_vs_references() {
    let mut r = SplitMix64(0x0f1e_1d00_0001);
    let p = cb_p();
    let mut total = 0u64;
    for m in [1u8, 2, 4, 6, 8] {
        for k in 0..tenth() {
            let a = rand_fe(&mut r, m, k % 4 == 0);
            let b = rand_fe(&mut r, m, k % 4 == 1);
            let ours = a.mul(&b);
            let mut f = [0u64; 5];
            fiat_secp256k1_dettman_mul(&mut f, &a.raw().n, &b.raw().n);
            assert_eq!(
                ours.raw().n,
                f,
                "mul limbs differ from fiat at m={m}: a={:x?} b={:x?}",
                a.raw().n,
                b.raw().n
            );
            let (va, vb) = (fe_val(&a), fe_val(&b));
            let want = mul_p(&va, &vb);
            assert_eq!(fe_val(&ours), want, "mul value m={m}");
            if k % 4 == 0 {
                assert_eq!(cbw(&cb(&va).mul_mod(&cb(&vb), &p)), want);
                assert_eq!(kfe_w(&(kfe(&va) * kfe(&vb))), want);
            }
            total += 1;
        }
    }
    eprintln!("mul: {total} cases limb-exact vs fiat and value-equal vs the references");
}

#[test]
fn sqr_vs_fiat_and_references() {
    let mut r = SplitMix64(0x0f1e_1d00_0002);
    let p = cb_p();
    for m in [1u8, 2, 4, 6, 8] {
        for k in 0..tenth() {
            let a = rand_fe(&mut r, m, k % 4 == 0);
            let ours = a.sqr();
            let mut f = [0u64; 5];
            fiat_secp256k1_dettman_square(&mut f, &a.raw().n);
            assert_eq!(ours.raw().n, f, "sqr limbs differ from fiat at m={m}");
            let va = fe_val(&a);
            let want = mul_p(&va, &va);
            assert_eq!(fe_val(&ours), want, "sqr value m={m}");
            assert_eq!(fe_val(&a.mul(&a)), want);
            if k % 4 == 0 {
                assert_eq!(cbw(&cb(&va).square_mod(&p)), want);
                assert_eq!(kfe_w(&kfe(&va).square()), want);
            }
        }
    }
}

/// add (magnitudes summing to <= 32), negate(m) for every m <= 31 on
/// inputs up to magnitude m, and add_int, against the reference, and
/// every fourth case against k256 as well.
#[test]
fn small_ops_vs_reference() {
    let mut r = SplitMix64(0x0f1e_1d00_0003);
    for k in 0..tenth() {
        let ma = 1 + r.below(31) as u8;
        let mb = 1 + r.below(u64::from(32 - ma)) as u8;
        let a = rand_fe(&mut r, ma, k % 8 == 0);
        let b = rand_fe(&mut r, mb, k % 8 == 1);
        let s = fe_add(&a, &b);
        assert_eq!(fe_val(&s), add_p(&fe_val(&a), &fe_val(&b)));
        if k % 4 == 0 {
            let (ka, kb) = (kfe(&fe_val(&a)), kfe(&fe_val(&b)));
            assert_eq!(fe_val(&s), kfe_w(&(ka + kb).normalize()), "add vs k256");
        }
        #[cfg(debug_assertions)]
        assert_eq!(s.magnitude(), ma + mb);

        let m = r.below(32) as u8;
        let mi = if m == 0 {
            0
        } else {
            r.below(u64::from(m) + 1) as u8
        };
        let a = if mi == 0 {
            fe_int(0)
        } else {
            rand_fe(&mut r, mi, k % 8 == 2)
        };
        let ng = a.negate(m);
        assert_eq!(
            fe_val(&ng),
            neg_p(&fe_val(&a)),
            "negate({m}) of magnitude {mi}"
        );
        if k % 4 == 0 {
            let ka = kfe(&fe_val(&a));
            assert_eq!(fe_val(&ng), kfe_w(&(-ka).normalize()), "negate vs k256");
        }
        #[cfg(debug_assertions)]
        assert_eq!(ng.magnitude(), m + 1);

        let mt = 1 + r.below(31) as u8;
        let mut t = rand_fe(&mut r, mt, false);
        let before = fe_val(&t);
        let c = r.below(0x8000) as u16;
        t.add_int(c);
        assert_eq!(fe_val(&t), add_p(&before, &[u64::from(c), 0, 0, 0]));
        if k % 4 == 0 {
            let kt = kfe(&before) + KFe::from(u64::from(c));
            assert_eq!(fe_val(&t), kfe_w(&kt.normalize()), "add_int vs k256");
        }

        // half: a/2, magnitude floor(m/2) + 1.
        let mh = 1 + r.below(31) as u8;
        let a = rand_fe(&mut r, mh, k % 8 == 3);
        let mut h = a;
        h.half();
        assert_eq!(
            add_p(&fe_val(&h), &fe_val(&h)),
            fe_val(&a),
            "half at magnitude {mh}"
        );
        #[cfg(debug_assertions)]
        assert_eq!(h.magnitude(), (mh >> 1) + 1);

        // mul_int: a*c with c*m <= 32.
        let mm = 1 + r.below(16) as u8;
        let c = 1 + r.below(u64::from(32 / mm)) as u8;
        let a = rand_fe(&mut r, mm, k % 8 == 4);
        let mut t = a;
        t.mul_int(c);
        assert_eq!(fe_val(&t), mul_p(&fe_val(&a), &[u64::from(c), 0, 0, 0]));
        #[cfg(debug_assertions)]
        assert_eq!(t.magnitude(), mm * c);

        // normalize_weak and both zero tests.
        let mw = 1 + r.below(32) as u8;
        let a = rand_fe(&mut r, mw, k % 8 == 5);
        let mut w = a;
        w.normalize_weak();
        assert_eq!(fe_val(&w), fe_val(&a));
        assert!(w.raw().n[4] >> 49 == 0);
        #[cfg(debug_assertions)]
        assert_eq!(w.magnitude(), 1);
        assert_eq!(a.normalizes_to_zero_var(), a.normalizes_to_zero());
    }
}

/// Every 5-limb combination from a structured set per limb, at magnitudes
/// 1 to 32, through `normalize_var`, `normalizes_to_zero`, `negate`,
/// `equal` and `get_b32`: where the carries live.
#[test]
fn boundary_lattice() {
    let p_l = words_to_limbs(&P);
    let pm1 = words_to_limbs(&sub4(&P, &[1, 0, 0, 0]));
    let pp1 = [p_l[0] + 1, p_l[1], p_l[2], p_l[3], p_l[4]];
    let mut total = 0u64;
    for m in [1u8, 2, 3, 4, 8, 16, 31, 32] {
        let mx = max_limbs(m);
        let choices: Vec<Vec<u64>> = (0..5)
            .map(|i| {
                let mut v: Vec<u64> = [0, 1, M52 - 1, M52, p_l[i], pm1[i], pp1[i], mx[i]]
                    .into_iter()
                    .filter(|&x| x <= mx[i])
                    .collect();
                v.sort_unstable();
                v.dedup();
                v
            })
            .collect();
        let mut idx = [0usize; 5];
        loop {
            let n = [
                choices[0][idx[0]],
                choices[1][idx[1]],
                choices[2][idx[2]],
                choices[3][idx[3]],
                choices[4][idx[4]],
            ];
            let a = Fe::from_limbs(n, m, false);
            let v = fe_val(&a);
            let canon = words_to_limbs(&v);

            let t = norm(&a);
            assert_eq!(t.raw().n, canon, "normalize_var {n:x?} m={m}");
            let z = v == [0; 4];
            assert_eq!(a.normalizes_to_zero(), z, "normalizes_to_zero {n:x?} m={m}");
            assert_eq!(
                a.normalizes_to_zero_var(),
                z,
                "normalizes_to_zero_var {n:x?} m={m}"
            );
            let mut ct = a;
            ct.normalize();
            assert_eq!(ct.raw().n, canon, "normalize {n:x?} m={m}");
            let mut w = a;
            w.normalize_weak();
            assert_eq!(fe_val(&w), v, "normalize_weak {n:x?} m={m}");
            if m <= 31 {
                let mut h = a;
                h.half();
                assert_eq!(add_p(&fe_val(&h), &fe_val(&h)), v, "half {n:x?} m={m}");
            }
            if m <= 31 {
                assert_eq!(fe_val(&a.negate(m)), neg_p(&v), "negate {n:x?} m={m}");
            }
            if m <= 30 {
                assert!(t.equal(&a), "equal(normalize(a), a) {n:x?} m={m}");
                let mut other = t;
                other.add_int(1);
                assert!(!norm(&other).equal(&a), "equal(a + 1, a) {n:x?} m={m}");
            }
            assert_eq!(t.get_b32(), words_to_be(&v));
            total += 1;

            let mut i = 0;
            loop {
                idx[i] += 1;
                if idx[i] < choices[i].len() {
                    break;
                }
                idx[i] = 0;
                i += 1;
                if i == 5 {
                    break;
                }
            }
            if i == 5 {
                break;
            }
        }
    }
    eprintln!("boundary lattice: {total} elements");
    assert_eq!(total, 38_000);
}

/// `mul` and `sqr` over the corner set {0, max_m, max_m - 1, p's limb}
/// per limb at m = 1, 2, 4, 8: every square, and the full 4^5 x 4^5 grid
/// of products when the volume is 10^6 or more (CI's release and
/// soak-asserts runs), a seeded sample otherwise; limb for limb against
/// fiat and by value against the reference.
#[test]
fn product_corners() {
    let p_l = words_to_limbs(&P);
    let mut r = SplitMix64(0x0f1e_1d00_0004);
    let full = cases() >= 1_000_000;
    let mut total = 0u64;
    for m in [1u8, 2, 4, 8] {
        let mx = max_limbs(m);
        let corner = |i: usize, c: usize| [0, mx[i], mx[i] - 1, p_l[i]][c];
        let ops: Vec<Fe> = (0..1024usize)
            .map(|code| {
                let mut n = [0u64; 5];
                for (i, x) in n.iter_mut().enumerate() {
                    *x = corner(i, (code >> (2 * i)) & 3);
                }
                Fe::from_limbs(n, m, false)
            })
            .collect();
        let vals: Vec<[u64; 4]> = ops.iter().map(fe_val).collect();
        for (i, a) in ops.iter().enumerate() {
            let s = a.sqr();
            assert_eq!(fe_val(&s), mul_p(&vals[i], &vals[i]));
            let mut f = [0u64; 5];
            fiat_secp256k1_dettman_square(&mut f, &a.raw().n);
            assert_eq!(s.raw().n, f, "sqr corner limbs");
        }
        let pairs: Vec<(usize, usize)> = if full {
            (0..1024)
                .flat_map(|i| (0..1024).map(move |j| (i, j)))
                .collect()
        } else {
            (0..tenth())
                .map(|_| (r.below(1024) as usize, r.below(1024) as usize))
                .collect()
        };
        for (i, j) in pairs {
            let prod = ops[i].mul(&ops[j]);
            let mut f = [0u64; 5];
            fiat_secp256k1_dettman_mul(&mut f, &ops[i].raw().n, &ops[j].raw().n);
            assert_eq!(prod.raw().n, f, "mul corner limbs");
            assert_eq!(fe_val(&prod), mul_p(&vals[i], &vals[j]));
            total += 1;
        }
    }
    eprintln!("product corners: {total} products and 4,096 squares (full grid: {full})");
}

/// `set_b32_limit` refuses exactly the values at or above p (p itself,
/// p + 1 and 2^256 - 1 among them), and parses the rest to their value;
/// `get_b32` gives the bytes back; `is_odd` is the low bit; and an
/// unnormalized value's bytes after `normalize_var` are its value's.
#[test]
fn bytes_and_limits() {
    let ff = [u64::MAX; 4];
    let pm1 = sub4(&P, &[1, 0, 0, 0]);
    let pp1 = [P[0] + 1, P[1], P[2], P[3]];
    for (w, ok) in [
        (P, false),
        (pp1, false),
        (ff, false),
        (pm1, true),
        ([0; 4], true),
        ([1, 0, 0, 0], true),
    ] {
        let b = words_to_be(&w);
        let lim = Fe::set_b32_limit(&b);
        assert_eq!(lim.is_some(), ok, "set_b32_limit {w:x?}");
        if let Some(x) = lim {
            assert_eq!(x.get_b32(), b);
            assert_eq!(x.raw().n, words_to_limbs(&w));
        }
    }
    let mut r = SplitMix64(0x0f1e_1d00_0005);
    for _ in 0..tenth() {
        let w = if r.below(2) == 0 {
            words(&mut r)
        } else {
            words_structured(&mut r)
        };
        let b = words_to_be(&w);
        let lim = Fe::set_b32_limit(&b);
        assert_eq!(lim.is_some(), !ge4(&w, &P));
        if let Some(x) = lim {
            assert_eq!(fe_val(&x), w);
            assert_eq!(x.get_b32(), b);
            assert_eq!(x.is_odd(), w[0] & 1 == 1);
            // The same value at a higher magnitude normalizes back.
            let m = 2 + r.below(31) as u8;
            let y = inflate(&x, m);
            assert_eq!(norm(&y).get_b32(), b);
            // The storage form holds the value's words, and comes back.
            let st = x.to_storage();
            assert_eq!(st.n, w);
            let back = Fe::from_storage(&st);
            assert_eq!(back.raw().n, x.raw().n);
            #[cfg(debug_assertions)]
            assert!(back.is_normalized_claim());
        }
    }
    // p - 1 in storage form.
    let pm1 = sub4(&P, &[1, 0, 0, 0]);
    let st = FeStorage { n: pm1 };
    assert_eq!(fe_val(&Fe::from_storage(&st)), pm1);
    assert_eq!(Fe::from_storage(&st).to_storage(), st);
}

/// `sqrt` against k256's and the reference: random values at magnitudes
/// up to 8 (about half non-squares) and known squares; a square's root
/// squares back to it, a non-square's root squares to its negation; edge
/// values.
#[test]
fn sqrt_vs_references() {
    let mut r = SplitMix64(0x0f1e_1d00_0007);
    let mut squares = 0u64;
    let n = (cases() / 40).max(1);
    let check = |a: &Fe, squares: &mut u64| {
        let va = fe_val(a);
        let (s, ok) = a.sqrt();
        let vs = fe_val(&s);
        let k: Option<KFe> = kfe(&va).sqrt().into();
        assert_eq!(
            ok,
            k.is_some(),
            "sqrt existence differs from k256 for {va:x?}"
        );
        if let Some(k) = k {
            *squares += 1;
            assert_eq!(mul_p(&vs, &vs), va);
            let kv = kfe_w(&k);
            assert!(kv == vs || kv == neg_p(&vs));
        } else {
            assert_eq!(mul_p(&vs, &vs), neg_p(&va), "non-square: r^2 != -a");
        }
        #[cfg(debug_assertions)]
        assert_eq!(s.magnitude(), 1);
    };
    for k in 0..n {
        let m = 2 + r.below(7) as u8;
        let a = fe_w(&words_below_p(&mut r));
        let a = if k % 2 == 0 { a } else { inflate(&a, m) };
        check(&a, &mut squares);
        let b = fe_w(&words_below_p(&mut r));
        check(&b.sqr(), &mut squares);
    }
    for w in [
        [0u64; 4],
        [1, 0, 0, 0],
        [4, 0, 0, 0],
        [7, 0, 0, 0],
        sub4(&P, &[1, 0, 0, 0]),
        sub4(&P, &[7, 0, 0, 0]),
    ] {
        check(&fe_w(&w), &mut squares);
    }
    // 7 = 0^3 + 7 is not a square (no point has x = 0), nor is -1 (p = 3
    // mod 4).
    assert!(!fe_int(7).sqrt().1);
    assert!(!fe_int(1).negate(1).sqrt().1);
    eprintln!("sqrt: {n} random, {n} known squares and 6 edges; {squares} squares seen");
    assert!(squares > n);
}

/// libsecp256k1's `test_sqrt` (tests.c:3503-3515): the root of a square
/// is plus or minus the known one, and a non-square has none.
fn libsecp_test_sqrt(a: &Fe, k: Option<&Fe>) {
    let (r1, v) = a.sqrt();
    assert_eq!(v, k.is_some());
    if let Some(k) = k {
        // Check that the returned root is +/- the given known answer
        let mut r2 = r1.negate(1);
        let mut r1 = r1;
        r1.add_assign(k);
        r2.add_assign(k);
        assert!(norm(&r1).normalizes_to_zero() || norm(&r2).normalizes_to_zero());
    }
}

/// libsecp256k1's `run_sqrt` (tests.c:3517-3547): sqrt(0) = 0; the small
/// squares 1..=100 and their negations; random squares, their negations
/// and their products with a non-square.
#[test]
fn libsecp_sqrt() {
    let x = fe_int(0);
    libsecp_test_sqrt(&x.sqr(), Some(&x));
    for i in 1..=100u16 {
        let x = fe_int(i);
        let s = x.sqr();
        libsecp_test_sqrt(&s, Some(&x));
        libsecp_test_sqrt(&s.negate(1), None);
    }
    let mut r = SplitMix64(0x0f1e_1d00_0008);
    // A random nonzero value (the structured words include zero now and
    // then, whose square's negation is a square).
    let mut nonzero = || loop {
        let w = words_below_p(&mut r);
        if w != [0; 4] {
            break fe_w(&w);
        }
    };
    for _ in 0..10 {
        // random_fe_non_square (tests.c:3123-3129)
        let ns = nonzero();
        let ns = if ns.sqrt().1 { ns.negate(1) } else { ns };
        for _ in 0..(cases() / 2_000).max(4) {
            let x = nonzero();
            let s = x.sqr();
            libsecp_test_sqrt(&s, Some(&x));
            libsecp_test_sqrt(&s.negate(1), None);
            libsecp_test_sqrt(&s.mul(&ns), None);
        }
    }
}

/// libsecp256k1's `run_field_be32_overflow` (tests.c:3180-3245), on what
/// the field has today: p, p + 1 and 2^256 - 1 are refused by the limit
/// parse, and as raw limbs (`set_b32_mod`) normalize to 0, 1 and
/// 2^256 - p.
#[test]
fn libsecp_be32_overflow() {
    let zero_overflow = hex32("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    let one_overflow = hex32("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30");
    let ff_overflow = [0xFF; 32];
    let ff = hex32("00000000000000000000000000000000000000000000000000000001000003d0");
    let one = words_to_be(&[1, 0, 0, 0]);
    for (b, want) in [
        (zero_overflow, [0; 32]),
        (one_overflow, one),
        (ff_overflow, ff),
    ] {
        assert!(Fe::set_b32_limit(&b).is_none());
        let raw = Fe::from_limbs(FeRaw::set_b32_mod(&b).n, 1, false);
        assert_eq!(raw.normalizes_to_zero(), want == [0; 32]);
        assert_eq!(norm(&raw).get_b32(), want);
    }
}

/// libsecp256k1's `run_fe_equal_magnitude_boundaries` (tests.c:3138-3148):
/// a value equals itself with the first operand at magnitude 0 or 1 and
/// the second at any magnitude up to 30, `fe_equal`'s bounds.
#[test]
fn libsecp_equal_magnitude_bounds() {
    let mut r = SplitMix64(0x0f1e_1d00_0009);
    for _ in 0..tenth() {
        let a = fe_w(&words_below_p(&mut r));
        let m = r.below(31) as u8;
        let mut b = if m < 2 { a } else { inflate(&a, m) };
        assert!(a.equal(&b));
        if m < 30 {
            b.add_int(1);
            assert!(!a.equal(&b));
        }
    }
    // The extremes: magnitude 30 at the limb bound.
    let a = fe_w(&[5, 0, 0, 0]);
    assert!(a.equal(&inflate(&a, 30)));
}

/// libsecp256k1's `run_field_convert` (tests.c:3150-3178), bytes only (the
/// storage form arrives with its caller).
#[test]
fn libsecp_convert_bytes() {
    let b32 = hex32("0001020304050607111213141516171822232425262728293334353637383940");
    let fe = Fe::set_b32_limit(&b32).expect("below p");
    assert_eq!(fe.get_b32(), b32);
    assert_eq!(
        fe_val(&fe),
        [
            0x3334_3536_3738_3940,
            0x2223_2425_2627_2829,
            0x1112_1314_1516_1718,
            0x0001_0203_0405_0607
        ]
    );
}

/// `fe_verify` reads the limbs, not only the claim: a value whose limbs
/// exceed its claimed magnitude is refused at its first use in builds
/// with debug assertions.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "exceed magnitude")]
fn fe_verify_refuses_limbs_beyond_their_magnitude() {
    let mut n = max_limbs(2);
    n[3] += 1;
    let _ = Fe::from_limbs(n, 2, false);
}

/// `fe_verify` refuses a normalized claim for a value at or above p.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "normalized value >= p")]
fn fe_verify_refuses_a_normalized_claim_at_p() {
    let _ = Fe::from_limbs(words_to_limbs(&P), 1, true);
}

/// modinv64's outer iterations for a's inverse.
fn fe_inv_iters(a: &Fe) -> u32 {
    let t = norm(a);
    modinv64_var_counted(&t.raw().to_signed62(), &crate::field::MODINFO_FE)
        .expect("within the cap")
        .1
}

/// libsecp256k1's `test_inverse_field` (tests.c:3594-3618): x * (1/x) =
/// 1, and 1/(1/x - 1) + 1 = -1/(x - 1); 1/0 = 0.
fn libsecp_inverse_identity(x: &Fe) -> Fe {
    let minus_one = Fe::from_be_u32([
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFE,
        0xFFFF_FC2E,
    ]);
    let l = x.inv_var().expect("cap");
    if x.normalizes_to_zero_var() {
        assert!(l.normalizes_to_zero());
        return l;
    }
    let mut t = x.mul(&l);
    t.add_assign(&minus_one);
    assert!(t.normalizes_to_zero(), "x*(1/x) != 1");
    let mut r = *x;
    r.add_assign(&minus_one);
    if r.normalizes_to_zero_var() {
        return l;
    }
    let r = r.inv_var().expect("cap");
    let mut l2 = l;
    l2.add_assign(&minus_one);
    let mut l2 = l2.inv_var().expect("cap");
    l2.add_int(1);
    l2.add_assign(&r);
    assert!(l2.normalizes_to_zero_var(), "1/(1/x-1)+1 != -1/(x-1)");
    l
}

/// A field element from 32 bytes mod p (`fe_set_b32_mod`), magnitude 1.
fn fe_mod(b: &[u8; 32]) -> Fe {
    Fe::from_limbs(FeRaw::set_b32_mod(b).n, 1, false)
}

/// The inverse, compiled for the tests and the table generator: against
/// the reference, crypto-bigint and k256 on canonical values and on
/// values at every magnitude; libsecp256k1's identity on 0, p (a zero not
/// in canonical form), 1, p - 1, every 2^k and 2^k - 1, values with long
/// runs of trailing zeros, 0..999 and their negations (tests.c:3834-3849),
/// and its 46 fixed pairs both ways; never more than the 12 outer
/// iterations the safegcd bound allows.
#[test]
fn inverse_vs_references_and_edges() {
    let p = cb_p();
    let mut r = SplitMix64(0x0f1e_1d00_0006);
    let mut max_iters = 0u32;
    for k in 0..tenth() {
        let a = if k % 2 == 0 {
            fe_w(&words_below_p(&mut r))
        } else {
            let m = 1 + r.below(32) as u8;
            rand_fe(&mut r, m, k % 8 == 1)
        };
        let va = fe_val(&a);
        let inv = a.inv_var().expect("within the cap");
        #[cfg(debug_assertions)]
        assert!(inv.is_normalized_claim());
        let vi = fe_val(&inv);
        assert_eq!(inv.raw().n, words_to_limbs(&vi), "inverse not normalized");
        if va == [0; 4] {
            assert_eq!(vi, [0; 4]);
            continue;
        }
        assert_eq!(mul_p(&va, &vi), [1, 0, 0, 0], "a * inv(a) != 1");
        if k % 4 == 0 {
            assert_eq!(
                cbw(&Option::<U256>::from(cb(&va).invert_mod(&p)).expect("invertible")),
                vi
            );
            assert_eq!(
                kfe_w(&Option::<KFe>::from(kfe(&va).invert()).expect("invertible")),
                vi
            );
        }
        if k % 16 == 0 {
            max_iters = max_iters.max(fe_inv_iters(&a));
        }
    }
    let mut edges: Vec<Fe> = vec![
        Fe::ZERO,
        Fe::from_limbs(words_to_limbs(&P), 1, false),
        Fe::ONE,
        fe_w(&sub4(&P, &[1, 0, 0, 0])),
    ];
    for b in 0..256 {
        let mut w = [0u64; 4];
        w[b / 64] = 1u64 << (b % 64);
        edges.push(fe_mod(&words_to_be(&w)));
        edges.push(fe_mod(&words_to_be(&sub4(&w, &[1, 0, 0, 0]))));
        let mut t = words(&mut r);
        for i in 0..b {
            t[i / 64] &= !(1u64 << (i % 64));
        }
        edges.push(fe_mod(&words_to_be(&t)));
    }
    for i in 0..1000u16 {
        let x = fe_int(i);
        edges.push(x);
        edges.push(x.negate(1));
    }
    for e in &edges {
        libsecp_inverse_identity(e);
        max_iters = max_iters.max(fe_inv_iters(e));
    }
    for [x, y] in super::vectors::FE_CASES {
        let (x, y) = (fe_mod(&hex32(x)), fe_mod(&hex32(y)));
        assert!(
            libsecp_inverse_identity(&x).equal(&y),
            "fe_cases: inv(x) != y"
        );
        assert!(
            libsecp_inverse_identity(&y).equal(&x),
            "fe_cases: inv(y) != x"
        );
        max_iters = max_iters.max(fe_inv_iters(&x)).max(fe_inv_iters(&y));
    }
    assert!(
        max_iters <= 12,
        "more than 12 outer iterations: {max_iters}"
    );
}

/// `mul` refuses an operand above magnitude 8 in builds with debug
/// assertions (its precondition, field_impl.h:340-341).
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "magnitude 9 > 8")]
fn mul_refuses_magnitude_above_8() {
    let a = inflate(&fe_int(3), 9);
    let _ = a.mul(&a);
}

/// Each debug precondition of the field refuses a magnitude one above its
/// bound, operand by operand (field_impl.h's VERIFY checks of `fe_mul`,
/// `fe_sqr`, `fe_sqrt`, `fe_equal`, `fe_half` and `fe_mul_int`), `mul`
/// and `sqr` claim magnitude 1 for what they return, and `half` and
/// `mul_int` drop the normalized claim.
#[cfg(debug_assertions)]
mod preconditions {
    use super::*;

    fn m9() -> Fe {
        inflate(&fe_int(3), 9)
    }

    #[test]
    #[should_panic(expected = "magnitude 9 > 8")]
    fn mul_left_at_9() {
        let _ = m9().mul(&fe_int(3));
    }

    #[test]
    #[should_panic(expected = "magnitude 9 > 8")]
    fn mul_right_at_9() {
        let _ = fe_int(3).mul(&m9());
    }

    #[test]
    #[should_panic(expected = "magnitude 9 > 8")]
    fn sqr_at_9() {
        let _ = m9().sqr();
    }

    #[test]
    #[should_panic(expected = "magnitude 9 > 8")]
    fn sqrt_at_9() {
        let _ = m9().sqrt();
    }

    #[test]
    #[should_panic(expected = "magnitude 2 > 1")]
    fn equal_left_at_2() {
        let _ = inflate(&fe_int(3), 2).equal(&fe_int(3));
    }

    #[test]
    #[should_panic(expected = "magnitude 31 > 30")]
    fn equal_right_at_31() {
        let _ = fe_int(3).equal(&inflate(&fe_int(3), 31));
    }

    #[test]
    #[should_panic(expected = "magnitude 32 > 31")]
    fn half_at_32() {
        let mut a = inflate(&fe_int(3), 32);
        a.half();
    }

    #[test]
    #[should_panic(expected = "fe_mul_int: 9 times magnitude 4")]
    fn mul_int_past_32() {
        let mut a = inflate(&fe_int(3), 4);
        a.mul_int(9);
    }

    #[test]
    #[should_panic(expected = "fe_mul_int: 11 times magnitude 3")]
    fn mul_int_at_33() {
        let mut a = inflate(&fe_int(3), 3);
        a.mul_int(11);
    }

    #[test]
    fn half_and_mul_int_drop_the_normalized_claim() {
        let mut a = fe_int(3);
        assert!(a.is_normalized_claim());
        a.half();
        assert!(!a.is_normalized_claim());
        assert_eq!(a.magnitude(), 1);
        let mut b = fe_int(3);
        b.mul_int(2);
        assert!(!b.is_normalized_claim());
        assert_eq!(b.magnitude(), 2);
    }

    #[test]
    fn mul_and_sqr_claim_magnitude_1() {
        let a = inflate(&fe_int(3), 8);
        assert_eq!(a.mul(&a).magnitude(), 1);
        assert_eq!(a.sqr().magnitude(), 1);
    }
}

/// The digest of a fixed computation over every field operation and over
/// decompression, on fixed seeds, equal to one committed constant in every
/// build profile: the dev profile, release, release with assertions and
/// with overflow checks off must compute the same limbs, which assertions
/// that only read cannot change.
#[test]
fn field_digest_is_pinned() {
    // FNV-1a, 64-bit, over the little-endian bytes of each limb.
    fn absorb(h: &mut u64, x: u64) {
        for b in x.to_le_bytes() {
            *h ^= u64::from(b);
            *h = h.wrapping_mul(0x0000_0100_0000_01B3);
        }
    }
    let mut h = 0xCBF2_9CE4_8422_2325u64;
    let mut r = SplitMix64(0x00d1_6e57);
    for k in 0..2048u32 {
        let m = [1u8, 2, 4, 8][(k % 4) as usize];
        let a = rand_fe(&mut r, m, k % 3 == 0);
        let b = rand_fe(&mut r, m, k % 5 == 0);
        let p = a.mul(&b);
        let s = a.sqr();
        let sum = norm(&fe_add(&a, &b));
        let neg = a.negate(m);
        let (q, ok) = a.sqrt();
        for x in p
            .raw()
            .n
            .iter()
            .chain(s.raw().n.iter())
            .chain(sum.raw().n.iter())
            .chain(neg.raw().n.iter())
            .chain(q.raw().n.iter())
        {
            absorb(&mut h, *x);
        }
        absorb(&mut h, u64::from(ok));
        absorb(&mut h, u64::from(a.normalizes_to_zero()));
        let mut x = [0u8; 32];
        r.fill(&mut x);
        if let Some(pt) = crate::Affine::decompress_var(&x, k % 2 == 1) {
            let (px, py) = pt.to_be_bytes();
            for w in be_to_words(&px).into_iter().chain(be_to_words(&py)) {
                absorb(&mut h, w);
            }
        } else {
            absorb(&mut h, 2);
        }
    }
    assert_eq!(h, 0xb7b1_3ce9_dc73_8171, "field digest {h:#018x}");
}
