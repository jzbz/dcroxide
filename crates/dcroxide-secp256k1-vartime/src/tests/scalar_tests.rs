// SPDX-License-Identifier: ISC AND MIT
//
// `libsecp_inverse_identity`, `check_overflow_edges`, `challenge_vectors`
// and the inverse edge cases follow libsecp256k1 src/tests.c (Copyright
// (c) 2013, 2014, 2015 Pieter Wuille, Gregory Maxwell), as vendored by
// secp256k1-sys 0.14.1.  MIT; see NOTICE.
//
//! Scalar and scalar-inverse tests: the operations against crypto-bigint
//! and k256 on random, structured and lattice inputs; `reduce_512` alone;
//! the byte limits; the inverse against both references with libsecp256k1's
//! identity, its fixed cases, rare inputs and the iteration bound; the
//! iteration caps and the refusal of a result not below N; libsecp256k1's
//! static multiplication vectors; and a digest of fixed-seed results that
//! every build profile must reproduce.

use dcroxide_testutil::SplitMix64;

use super::*;
use crate::modinv64::{
    MAX_OUTER, PROVEN_OUTER, Signed62, divsteps_62_var_for_tests, modinv64_var_capped,
};
use crate::scalar::{MODINFO_SCALAR, Scalar, mul_512, reduce_512};

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
fn from_hex(h: &str) -> Scalar {
    Scalar::from_be_bytes(&hex32(h)).expect("below N")
}

#[test]
fn ops_vs_references() {
    let n = cb_n();
    let mut r = SplitMix64(0x5ca1_0001);
    for k in 0..cases() {
        let (wa, wb) = (rand_sc(&mut r), rand_sc(&mut r));
        let (a, b) = (sc(&wa), sc(&wb));
        let (ca, cbb) = (cb(&wa), cb(&wb));
        assert_eq!(scw(&(a * b)), cbw(&ca.mul_mod(&cbb, &n)), "mul");
        assert_eq!(scw(&(a + b)), cbw(&ca.add_mod(&cbb, &n)), "add");
        assert_eq!(scw(&(-a)), cbw(&ca.neg_mod(&n)), "negate");
        if k % 4 == 0 {
            let (ka, kb) = (ksc(&wa), ksc(&wb));
            assert_eq!(scw(&(a * b)), ksc_w(&(ka * kb)));
            assert_eq!(scw(&(a + b)), ksc_w(&(ka + kb)));
            assert_eq!(scw(&(-a)), ksc_w(&(-ka)));
        }
    }
}

/// Limbs from {0, 1, 2^64-1, N's limb, (N-1)'s limb}: 625 values (those at
/// or above N reduced by `set_b32`), pairs through mul and add (all of
/// them without debug assertions, a seventh with), each through negate,
/// against crypto-bigint and k256.
#[test]
fn limb_lattice() {
    let n = cb_n();
    let nm1 = sub4(&NORD, &[1, 0, 0, 0]);
    let mut vals = Vec::new();
    for code in 0..625u32 {
        let mut w = [0u64; 4];
        let mut c = code;
        for (i, x) in w.iter_mut().enumerate() {
            *x = [0, 1, u64::MAX, NORD[i], nm1[i]][(c % 5) as usize];
            c /= 5;
        }
        let (s, over) = Scalar::set_b32(&words_to_be(&w));
        assert_eq!(over, ge4(&w, &NORD));
        assert_eq!(scw(&s), reduce_n(&w));
        assert_eq!(Scalar::from_be_bytes(&words_to_be(&w)).is_some(), !over);
        assert!(Scalar::reduce_be_bytes(&words_to_be(&w)) == s);
        vals.push((s, cb(&reduce_n(&w)), ksc(&reduce_n(&w))));
    }
    let step = if cfg!(debug_assertions) { 7 } else { 1 };
    let mut total = 0u64;
    for (i, (a, ca, ka)) in vals.iter().enumerate() {
        for (b, cbb, kb) in vals.iter().skip(i % step).step_by(step) {
            let (prod, sum) = (scw(&(*a * *b)), scw(&(*a + *b)));
            assert_eq!(prod, cbw(&ca.mul_mod(cbb, &n)));
            assert_eq!(sum, cbw(&ca.add_mod(cbb, &n)));
            assert_eq!(prod, ksc_w(&(*ka * *kb)));
            assert_eq!(sum, ksc_w(&(*ka + *kb)));
            total += 1;
        }
        assert_eq!(scw(&(-*a)), cbw(&ca.neg_mod(&n)));
        assert_eq!(scw(&(-*a)), ksc_w(&(-*ka)));
    }
    eprintln!("scalar lattice: {total} pairs");
}

/// `reduce_512` on structured and random 512-bit inputs against
/// crypto-bigint's `U512` remainder, and `mul_512` against the schoolbook
/// product.
#[test]
fn reduce_512_vs_bigint() {
    let n = cb_n();
    let mut total = 0u64;
    for code in 0..65536u32 {
        let mut l = [0u64; 8];
        let mut c = code;
        for (i, x) in l.iter_mut().enumerate() {
            *x = [0, 1, u64::MAX, NORD[i % 4]][(c % 4) as usize];
            c /= 4;
        }
        assert_eq!(reduce_512(&l), cbw(&cb512(&l).rem(&n)), "reduce_512 {l:x?}");
        total += 1;
    }
    let mut r = SplitMix64(0x5ca1_0002);
    for _ in 0..cases() {
        let mut l = [0u64; 8];
        for x in &mut l {
            *x = r.next_u64();
        }
        assert_eq!(reduce_512(&l), cbw(&cb512(&l).rem(&n)));
        let (a, b) = (rand_sc(&mut r), rand_sc(&mut r));
        assert_eq!(mul_512(&a, &b), mulw(&a, &b));
        total += 1;
    }
    eprintln!("reduce_512: {total} inputs");
}

#[test]
fn bytes_and_negate_edges() {
    let nm1 = sub4(&NORD, &[1, 0, 0, 0]);
    let np1 = [NORD[0] + 1, NORD[1], NORD[2], NORD[3]];
    let ff = [u64::MAX; 4];
    assert!(Scalar::from_be_bytes(&words_to_be(&nm1)).is_some());
    assert_eq!(scw(&Scalar::reduce_be_bytes(&words_to_be(&nm1))), nm1);
    for w in [NORD, np1, ff] {
        assert!(Scalar::from_be_bytes(&words_to_be(&w)).is_none());
        assert_eq!(
            scw(&Scalar::reduce_be_bytes(&words_to_be(&w))),
            sub4(&w, &NORD)
        );
    }
    assert_eq!(Scalar::ZERO.to_be_bytes(), [0; 32]);
    assert!(Scalar::ZERO.is_zero() && !Scalar::ONE.is_zero());
    // (-1)+1 is zero, and so is its negation (tests.c, run_scalar_tests).
    assert!((-Scalar::ZERO).is_zero());
    assert_eq!(-Scalar::ZERO, Scalar::ZERO);
    assert_eq!(scw(&(-Scalar::ONE)), nm1);
    assert_eq!(scw(&(-sc(&nm1))), [1, 0, 0, 0]);
    assert!((sc(&nm1) + Scalar::ONE).is_zero());
    assert!((-(sc(&nm1) + Scalar::ONE)).is_zero());
    let (s, over) = sc(&nm1).add_with_overflow_for_tests(&Scalar::ONE);
    assert!(s.is_zero() && over);
    let (s, over) = sc(&nm1).add_with_overflow_for_tests(&sc(&nm1));
    assert!(over && scw(&s) == sub4(&nm1, &[1, 0, 0, 0]));
    let (s, over) = Scalar::ONE.add_with_overflow_for_tests(&Scalar::ONE);
    assert!(!over && scw(&s) == [2, 0, 0, 0]);
    assert!(!sc(&nm1).is_zero());
    assert!(sc(&nm1) != Scalar::ZERO);
}

/// `test_scalar_check_overflow` (tests.c:2434-2479): 0 and N-1 do not
/// overflow, N, N+1 and 2^256-1 do, and random bytes (half of them with
/// the top 16 bytes 0xff, to reach N's neighbourhood) overflow exactly when
/// they are at or above N's bytes.
#[test]
fn check_overflow_edges() {
    let n_be = words_to_be(&NORD);
    let mut r = SplitMix64(0x5ca1_0007);
    let mut overflows = 0u64;
    for i in 0..20_000u32 {
        let mut b = [0u8; 32];
        r.fill(&mut b);
        if i % 2 == 0 {
            b[..16].fill(0xff);
        }
        let expect = b >= n_be;
        let (_, over) = Scalar::set_b32(&b);
        assert_eq!(over, expect, "{b:02x?}");
        assert_eq!(Scalar::from_be_bytes(&b).is_none(), expect);
        overflows += u64::from(over);
    }
    assert!(overflows > 1000, "too few overflowing inputs: {overflows}");
}

/// libsecp256k1's `test_inverse_scalar` (tests.c:3572-3592): x * (1/x) is
/// 1, and 1/(1/x - 1) + 1 is -1/(x - 1).  Returns 1/x.
fn libsecp_inverse_identity(x: &Scalar) -> Scalar {
    let minus_one = -Scalar::ONE;
    let l = x.try_inverse_var().expect("within the cap");
    if x.is_zero() {
        assert!(l.is_zero());
        return l;
    }
    assert!(*x * l == Scalar::ONE, "x*(1/x) != 1");
    let r = *x + minus_one;
    if r.is_zero() {
        return l;
    }
    let r = r.try_inverse_var().expect("within the cap");
    let l2 = (minus_one + l).try_inverse_var().expect("within the cap") + Scalar::ONE;
    assert!((r + l2).is_zero(), "1/(1/x-1)+1 != -1/(x-1)");
    l
}

/// The inverse against crypto-bigint, k256's `invert_vartime` and its
/// constant-time `invert` on random and structured input; libsecp256k1's
/// identity on the edges (0, 1, -1, every 2^k, random values with k low
/// zero bits, which take the batched divsteps, and 0..999 with their
/// negations, whose small size shrinks the loop's length early) and on
/// `scalar_cases` both ways (tests.c:3826-3833); and no input needing
/// more than the 12 outer iterations the proof allows.
#[test]
fn inverse_vs_references_and_edges() {
    let n = cb_n();
    let mut r = SplitMix64(0x5ca1_0005);
    let mut max_iters = 0u32;
    for k in 0..cases() {
        let w = rand_sc(&mut r);
        let s = sc(&w);
        let (inv, it) = s.inverse_var_counted().expect("within the cap");
        assert!(s.try_inverse_var() == Some(inv));
        max_iters = max_iters.max(it);
        let wi = scw(&inv);
        if w == [0; 4] {
            assert_eq!(wi, [0; 4]);
            continue;
        }
        assert!(s * inv == Scalar::ONE);
        if k % 2 == 0 {
            let want: U256 = Option::from(cb(&w).invert_mod(&n)).expect("invertible");
            assert_eq!(cbw(&want), wi);
        }
        if k % 4 == 0 {
            let kv: k256::Scalar = Option::from(ksc(&w).invert_vartime()).expect("invertible");
            let kc: k256::Scalar = Option::from(ksc(&w).invert()).expect("invertible");
            assert_eq!(ksc_w(&kv), wi);
            assert_eq!(ksc_w(&kc), wi);
        }
    }
    let mut edges = vec![Scalar::ZERO, Scalar::ONE, -Scalar::ONE];
    for b in 0..256 {
        let mut w = [0u64; 4];
        w[b / 64] = 1u64 << (b % 64);
        edges.push(Scalar::reduce_be_bytes(&words_to_be(&w)));
        let mut t = words(&mut r);
        for i in 0..b {
            t[i / 64] &= !(1u64 << (i % 64));
        }
        edges.push(Scalar::reduce_be_bytes(&words_to_be(&t)));
    }
    for i in 0..1000u32 {
        let x = Scalar::from_u32(i);
        edges.push(x);
        edges.push(-x);
    }
    for e in &edges {
        let inv = libsecp_inverse_identity(e);
        let w = scw(e);
        let kv: Option<k256::Scalar> = ksc(&w).invert_vartime().into();
        assert_eq!(kv.map_or([0; 4], |k| ksc_w(&k)), scw(&inv));
        max_iters = max_iters.max(e.inverse_var_counted().expect("within the cap").1);
    }
    for [x, y] in super::vectors::SCALAR_CASES {
        let (x, y) = (from_hex(x), from_hex(y));
        assert!(
            libsecp_inverse_identity(&x) == y,
            "scalar_cases: inv(x) != y"
        );
        assert!(
            libsecp_inverse_identity(&y) == x,
            "scalar_cases: inv(y) != x"
        );
        max_iters = max_iters
            .max(x.inverse_var_counted().expect("within the cap").1)
            .max(y.inverse_var_counted().expect("within the cap").1);
    }
    eprintln!(
        "scalar inverse: {} random + {} edge + {} scalar_cases pairs; max outer iterations {max_iters}",
        cases(),
        edges.len(),
        super::vectors::SCALAR_CASES.len()
    );
    assert!(max_iters <= PROVEN_OUTER);
}

/// Inputs that take rare paths of the safegcd driver, found by running
/// 2 x 10^7 random inputs through deliberately broken copies of it, so
/// that every profile reaches what only CI's 10^6-case release run
/// otherwise might: the length shrink while the top limb of f or g is -1
/// and the limb below has bit 61 clear (the first sixteen; about 1 input
/// in 40,000), and `update_de_62`'s starting md and me when e is negative
/// and the result leaves the range a correct start keeps it in (the last
/// seven; about 1 in 3 x 10^6).  Each inverse is checked against
/// crypto-bigint.
#[test]
fn inverse_rare_driver_paths() {
    let n = cb_n();
    for h in [
        "b9e251868acae4833ccf0aa5918768f8a29550b67fbce6e5091cbff77a074c02",
        "fb9072c69cb534701a2b716782415aa1cc4f0e055aec555a5320c87b7e6755c5",
        "fdc961457f13d0892ed5fa706931e18204ab03905f0b14ab52ed0d80feb37127",
        "97f190491dce7c5eb45565a2fb0bf2f51f72fc82cca8747f3bedd0f0afb77d2e",
        "215195e3fcb40abfc313a4729ba8f8ed24cb75f939cf9edbb269f5bdd5de9305",
        "10f8525b621819cbe05998a71e51991a53115b551c1f17d1b1937d7ea3cea9cb",
        "f6164f327de4fd285bf58653d1d43bd871ced55233215dd9add9978b64cc7f06",
        "69f486c3b817be07c1c3b30ab4876cff0674225eb35e9a0a6ef15f1c1a50f51b",
        "552b41ef8c98662143dc39bb11ec4f253bdfc6d3a19bfc5845fcbb42f9c42aab",
        "531b6d69b066715ea575d91a6cc6d7380e0e1946b7c5e022927f3370009f7f38",
        "096dea08ed69027193dbe712e2fc8452e4908eb54ea705d3c534d7f0a69b1a35",
        "ec23394c9476ee53ab2ac21bc51bdc913e6456ec98b919f176077c0a7af81225",
        "d178d47b0cc608a760c4e791abe97e09e8136960d283a3cccf3b0e8b60852145",
        "82dabe697c1cd09db747e5aa7f65b1c3f880e7452c25c6b4f9716177ed4314a5",
        "a2f1dfd660f2a6cac16638931e80176e4c86476062a3926a401a2f71ea99eb1b",
        "4f02604ef51fd73a8bb1a35f3e9c311228f49155e6403e57c0dd4278c5489d00",
        "80391ef7a6713898b37e44b7c56452e06981adbde4aa434bb1a93a9512beb416",
        "889b93f958a889c0e3b4447ba0e6d4b1bbf1fdb3c5bb7db8697776ece0ddd25e",
        "a0cf1dbb786aff95f8d75489d420c2625ea5a861f7fd421c29f415e5a06e490f",
        "41b6e3f22233ba9f813c57b913d9b1b97d4e9e018cb7fce3406ff43a56bcfe7c",
        "6cfa0465e3b6134ebf593b80f2a34aa481b538a5d272f1185046535e8aa61bf7",
        "8af0ce1b6f39e05094f6342606e2563210989cd74e6283d740cb0cc8c38e9807",
        "247746ce841c07980000000000000000ffffffffffffffffffffffffffffffff",
    ] {
        let x = from_hex(h);
        let want: U256 = Option::from(cb(&scw(&x)).invert_mod(&n)).expect("invertible");
        let (inv, it) = x.inverse_var_counted().expect("within the cap");
        assert_eq!(scw(&inv), cbw(&want), "{h}");
        assert!(it <= PROVEN_OUTER, "{h}: {it} outer iterations");
    }
}

/// The iteration cap: no input needs more than 12 outer iterations, so
/// the `None` path is reached with a smaller cap through the same driver.
/// Every input that needs k iterations returns `None` under a cap of
/// k - 1 and `Some`, the right inverse, under k; zero takes exactly one,
/// and the cap is twice the proven 12.
#[test]
fn modinv_cap_returns_none_past_the_cap() {
    assert_eq!((PROVEN_OUTER, MAX_OUTER), (12, 24));
    let mut r = SplitMix64(0x5ca1_0006);
    let mut seen = [0u32; 13];
    for i in 0..1000 {
        let w = match i {
            0 => [0; 4],
            1 => [1, 0, 0, 0],
            _ => rand_sc(&mut r),
        };
        let s = sc(&w);
        let x = s.to_signed62_for_tests();
        let (inv, k) = modinv64_var_capped(&x, &MODINFO_SCALAR, MAX_OUTER).expect("within the cap");
        assert!((1..=PROVEN_OUTER).contains(&k));
        if i == 0 {
            assert_eq!((inv, k), (Signed62 { v: [0; 5] }, 1), "zero");
        }
        seen[k as usize] += 1;
        assert!(
            modinv64_var_capped(&x, &MODINFO_SCALAR, k - 1).is_none(),
            "cap {} did not stop a {k}-iteration input",
            k - 1
        );
        let (again, k2) = modinv64_var_capped(&x, &MODINFO_SCALAR, k).expect("enough iterations");
        assert_eq!((again, k2), (inv, k));
        assert!(modinv64_var_capped(&x, &MODINFO_SCALAR, 0).is_none());
    }
    eprintln!("outer iterations by count: {seen:?}");
}

/// The inner loop's pass cap: an even f, which the driver never passes
/// and only a port bug could make, leaves g odd after every update, so
/// no divstep happens and the C would spin.  Release builds decline
/// instead; builds with debug assertions stop at the ported invariant
/// first.  A real batch is unaffected.
#[test]
#[cfg_attr(debug_assertions, should_panic(expected = "f & 1 == 1"))]
fn divsteps_decline_an_even_f() {
    assert!(divsteps_62_var_for_tests(-1, 0x3FD2_5E8C_D036_4141, 5).is_some());
    assert_eq!(divsteps_62_var_for_tests(5, 2, 1), None);
}

/// `from_signed62` refuses what modinv64 must never return, N itself, N + 1
/// and 2^256 - 1 in its limb form, and takes N - 1 and 0, so a wrong
/// safegcd result becomes `None` and the caller's fallback, not a scalar
/// outside the range.
#[test]
fn from_signed62_refuses_values_not_below_n() {
    fn limbs(w: &[u64; 4]) -> Signed62 {
        const M62: u64 = u64::MAX >> 2;
        Signed62 {
            v: [
                w[0] & M62,
                ((w[0] >> 62) | (w[1] << 2)) & M62,
                ((w[1] >> 60) | (w[2] << 4)) & M62,
                ((w[2] >> 58) | (w[3] << 6)) & M62,
                w[3] >> 56,
            ]
            .map(|x| x as i64),
        }
    }
    let nm1 = sub4(&NORD, &[1, 0, 0, 0]);
    let np1 = [NORD[0] + 1, NORD[1], NORD[2], NORD[3]];
    for w in [NORD, np1, [u64::MAX; 4]] {
        assert!(
            Scalar::from_signed62_for_tests(&limbs(&w)).is_none(),
            "{w:x?}"
        );
    }
    for w in [nm1, [0; 4], [1, 0, 0, 0]] {
        let s = Scalar::from_signed62_for_tests(&limbs(&w)).expect("below N");
        assert_eq!(scw(&s), w);
        assert_eq!(s.to_signed62_for_tests(), limbs(&w));
    }
}

/// libsecp256k1's static scalar vectors (tests.c:2549-3118, in
/// `run_scalar_tests`): x*y and x*x against Sage's responses, and, for a
/// nonzero y, 1/y against k256's constant-time inverse, (x*y)*(1/y) = x
/// and (1/y)*y = 1.  libsecp256k1 compares its two inverses there; the
/// constant-time one here is k256's.
#[test]
fn challenge_vectors() {
    use super::vectors::{CHAL, RES};
    for (i, ([cx, cy], [r1, r2])) in CHAL.iter().zip(RES.iter()).enumerate() {
        let (x, y, r1, r2) = (from_hex(cx), from_hex(cy), from_hex(r1), from_hex(r2));
        let z = x * y;
        assert!(z == r1, "vector {i}: x*y");
        if !y.is_zero() {
            let zz = y.try_inverse_var().expect("within the cap");
            let kc: k256::Scalar = Option::from(ksc(&scw(&y)).invert()).expect("invertible");
            assert_eq!(scw(&zz), ksc_w(&kc), "vector {i}: 1/y against k256");
            assert!(z * zz == x, "vector {i}: (x*y)/y");
            assert!(zz * y == Scalar::ONE, "vector {i}: (1/y)*y");
        }
        assert!(x * x == r2, "vector {i}: x*x");
    }
}

/// The digest of a fixed computation over every operation this module
/// has, on fixed seeds, equal to one committed constant in every build
/// profile: the dev profile, release, release with assertions and with
/// overflow checks off must compute the same values, which assertions
/// that only read cannot change.
#[test]
fn scalar_digest_is_pinned() {
    // FNV-1a, 64-bit, over the big-endian bytes of each result.
    fn absorb(h: &mut u64, s: &Scalar) {
        for b in s.to_be_bytes() {
            *h ^= u64::from(b);
            *h = h.wrapping_mul(0x0000_0100_0000_01B3);
        }
    }
    let mut h = 0xCBF2_9CE4_8422_2325u64;
    let mut r = SplitMix64(0x5ca1_d16e);
    for i in 0..4096u32 {
        let mut ba = [0u8; 32];
        let mut bb = [0u8; 32];
        r.fill(&mut ba);
        r.fill(&mut bb);
        if i % 8 == 0 {
            ba[..16].fill(0xff);
        }
        let a = Scalar::reduce_be_bytes(&ba);
        let b = Scalar::reduce_be_bytes(&bb);
        absorb(&mut h, &a);
        absorb(&mut h, &(a * b));
        absorb(&mut h, &(a + b));
        absorb(&mut h, &(-a));
        absorb(&mut h, &a.try_inverse_var().expect("within the cap"));
        h ^= u64::from(Scalar::from_be_bytes(&ba).is_some());
    }
    assert_eq!(h, 0x9ed1_f629_6216_674f, "scalar digest {h:#018x}");
}
