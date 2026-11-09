// SPDX-License-Identifier: ISC
//! ECDSA verification's branches, built on k256 and judged by dcrd
//! (ADR-0016): every case is a signature constructed so that verification
//! computes chosen scalars u1 and u2, or reaches a chosen final point X,
//! and dcrd's verdict through `tools/oracle`'s `ecdsa_verify_raw` is the
//! reference, never k256's or this crate's.  Each case also checks the
//! step `verify_detailed` reports against dcrd's algorithm run on X's
//! affine x.
//!
//! - The collision grid: Q in {+-G, +-2G, +-3G, +-lambda G, +-lambda^2 G,
//!   +-2^128 G, +-lambda 2^128 G}, u2 = a + b*lambda (nonzero), u1 = c +
//!   d*2^128, a to d in [-3, 3], where the Straus loop's four digit
//!   strings collide; r = X.x mod N, or a fixed-seed r when X is infinity,
//!   s = r/u2 and e = u1*s as the hash, so verification recomputes exactly
//!   (u1, u2).
//! - Final points at the x check's boundaries: X.x in [N, N + 2^32) and
//!   X.x = P - 3 (step 10 accepts r = X.x - N), X.x in [P - N, N) (step 8
//!   accepts an r at or above P - N), tiny x, tiny y, and X at infinity
//!   (Q = -(u1/u2)G); each with r + 1 and r - 1 as well, which steps 9
//!   and 10 reject (r - 1 = P - N - 1 at X.x = P - N reaches step 10).
//! - r exactly P - N, step 9's bound, with a random X: step 9 rejects
//!   before r + N = P is formed.
//! - u2 = 1 (s = r).
//!
//! Below the 10^6 volume (`DCROXIDE_VARTIME_CASES`, as CI's soak-asserts
//! run sets it) or in builds with debug assertions, the grid runs [-1, 1]
//! and the boundary classes a fixed subset.  The committed file
//! `tests/data/vartime_ecdsa_branches.txt` holds the first case of each
//! (grid key or boundary class, step) of the small selection with dcrd's
//! answer: one test checks it everywhere, without Go, and one rebuilds it
//! with dcrd and compares it byte for byte.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "k256 scalar and field operators, which are modular, and byte \
              offsets within 32-byte arrays"
)]

use std::collections::BTreeSet;
use std::fmt::Write as _;

use dcroxide_dcrec::secp256k1::ecdsa::{Signature, VerifyStep};
use dcroxide_dcrec::secp256k1::{FIELD_PRIME_BYTES, GROUP_ORDER_BYTES, PublicKey};
use dcroxide_testutil::{Oracle, SplitMix64, hex, oracle_or_skip, unhex};
use k256::elliptic_curve::group::CurveAffine;
use k256::elliptic_curve::hazmat::FieldArithmetic;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::{AffineCoordinates, DecompressPoint};
use k256::elliptic_curve::subtle::Choice;
use k256::elliptic_curve::{Field, PrimeField};
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};

/// k256's field element.
type Fe = <k256::Secp256k1 as FieldArithmetic>::FieldElement;

/// The committed vectors.
const COMMITTED: &str = include_str!("data/vartime_ecdsa_branches.txt");

/// P - N, big-endian.
const P_MINUS_N: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x45, 0x51, 0x23, 0x19, 0x50, 0xb7, 0x5f, 0xc4, 0x40, 0x2d, 0xa1, 0x72, 0x2f, 0xc9, 0xba, 0xee,
];

/// lambda, the endomorphism's scalar, big-endian.
const LAMBDA: [u8; 32] = [
    0x53, 0x63, 0xad, 0x4c, 0xc0, 0x5c, 0x30, 0xe0, 0xa5, 0x26, 0x1c, 0x02, 0x88, 0x12, 0x64, 0x5a,
    0x12, 0x2e, 0x22, 0xea, 0x20, 0x81, 0x66, 0x78, 0xdf, 0x02, 0x96, 0x7c, 0x1b, 0x23, 0xbd, 0x72,
];

/// One constructed case.
struct Case {
    /// The class: `grid`, a boundary class, or `u2-one`.
    class: &'static str,
    /// What within the class (the grid's key, accept or r+1), and the step
    /// dcrd's algorithm decides at, as `<what>/<step>`.
    variant: String,
    /// The `ecdsa_verify_raw` request: key_len || key || hash || r || s.
    request: Vec<u8>,
    /// The step dcrd's algorithm decides at, on X's affine x.
    step: VerifyStep,
}

/// A step's short name in the file.
fn step_name(s: VerifyStep) -> &'static str {
    match s {
        VerifyStep::Step1Zero => "step1",
        VerifyStep::Step6Infinity => "step6",
        VerifyStep::Step8Accept => "step8",
        VerifyStep::Step9Reject => "step9",
        VerifyStep::Step10Accept => "step10-accept",
        VerifyStep::Step10Reject => "step10-reject",
    }
}

/// a + b, big-endian, with no carry out (the callers' sums stay below P).
fn add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let s = u16::from(a[i]) + u16::from(b[i]) + carry;
        out[i] = s as u8;
        carry = s >> 8;
    }
    assert_eq!(carry, 0);
    out
}

/// a - b, big-endian, for a >= b.
fn sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = i16::from(a[i]) - i16::from(b[i]) - borrow;
        out[i] = d.rem_euclid(256) as u8;
        borrow = i16::from(d < 0);
    }
    assert_eq!(borrow, 0);
    out
}

/// A small value, big-endian.
fn small(v: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&v.to_be_bytes());
    b
}

/// dcrd's verification decided on X's affine x: step 6 at infinity, step
/// 8 if X.x = r, step 9 if r >= P - N, step 10 on whether X.x = r + N.
fn dcrd_step(x: Option<[u8; 32]>, r: &[u8; 32]) -> VerifyStep {
    match x {
        None => VerifyStep::Step6Infinity,
        Some(x) if x == *r => VerifyStep::Step8Accept,
        Some(_) if *r >= P_MINUS_N => VerifyStep::Step9Reject,
        Some(x) if x == add(r, &GROUP_ORDER_BYTES) => VerifyStep::Step10Accept,
        Some(_) => VerifyStep::Step10Reject,
    }
}

/// A scalar from big-endian bytes below N.
fn scalar(b: &[u8; 32]) -> Scalar {
    Option::from(Scalar::from_repr((*b).into())).expect("below N")
}

/// A small signed integer as a scalar.
fn sc_i64(v: i64) -> Scalar {
    let s = Scalar::from(v.unsigned_abs());
    if v < 0 { -s } else { s }
}

/// A random nonzero scalar.
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

/// The case whose verification computes (u1, u2) against key Q and meets
/// X = u1*G + u2*Q, with r as given: s = r/u2 and e = u1*s.
fn case(
    class: &'static str,
    what: &str,
    q: &AffinePoint,
    x: &ProjectivePoint,
    r: &[u8; 32],
    u1: &Scalar,
    u2: &Scalar,
) -> Case {
    let s = scalar(r) * u2.invert_vartime().expect("u2 nonzero");
    let e = *u1 * s;
    let mut request = vec![33u8, 2 | q.y_is_odd().unwrap_u8()];
    request.extend_from_slice(&q.x());
    request.extend_from_slice(&e.to_repr());
    request.extend_from_slice(r);
    request.extend_from_slice(&s.to_repr());
    let xa = x.to_affine();
    let xx = (!bool::from(xa.is_identity())).then(|| <[u8; 32]>::from(xa.x()));
    let step = dcrd_step(xx, r);
    Case {
        class,
        variant: format!("{what}/{}", step_name(step)),
        request,
        step,
    }
}

/// The grid at range `range`.
fn grid(range: i64) -> Vec<Case> {
    let g = ProjectivePoint::GENERATOR;
    let lam = scalar(&LAMBDA);
    let mut two128 = [0u8; 32];
    two128[15] = 1;
    let t = scalar(&two128);
    let bases: [(&str, ProjectivePoint); 7] = [
        ("G", g),
        ("2G", g.double()),
        ("3G", g * Scalar::from(3u64)),
        ("lG", g * lam),
        ("l^2G", g * (lam * lam)),
        ("2^128G", g * t),
        ("l2^128G", g * (lam * t)),
    ];
    let mut rng = SplitMix64(0x6772_6964_7363_6731);
    let mut out = Vec::new();
    for (name, b) in bases {
        for (sign, q) in [("+", b), ("-", -b)] {
            let qa = q.to_affine();
            for a in -range..=range {
                for bb in -range..=range {
                    let u2 = sc_i64(a) + sc_i64(bb) * lam;
                    if bool::from(u2.is_zero()) {
                        continue;
                    }
                    for c in -range..=range {
                        for d in -range..=range {
                            let u1 = sc_i64(c) + sc_i64(d) * t;
                            let x = g * u1 + q * u2;
                            let xa = x.to_affine();
                            let r = if bool::from(xa.is_identity()) {
                                rand_scalar(&mut rng)
                            } else {
                                <Scalar as Reduce<FieldBytes>>::reduce(&xa.x())
                            };
                            let what = format!("{sign}{name}");
                            out.push(case("grid", &what, &qa, &x, &r.to_repr().into(), &u1, &u2));
                        }
                    }
                }
            }
        }
    }
    out
}

/// The point with x and the given oddness, by k256's decompression.
fn point_at(x: &[u8; 32], odd: bool) -> Option<AffinePoint> {
    Option::from(AffinePoint::decompress(
        &(*x).into(),
        Choice::from(u8::from(odd)),
    ))
}

/// The x of every point whose y is below 200, on k256's field: y^2 - 7
/// must be a cube, one cube root is (y^2 - 7)^((P+2)/9) since P = 7 mod 9,
/// and the others are it times beta and beta^2.
fn tiny_y_xs() -> Vec<[u8; 32]> {
    // (P + 2) / 9, little-endian words.
    const CUBE_ROOT_EXP: [u64; 4] = [
        0x1c71_c71c_5555_54e9,
        0x71c7_1c71_c71c_71c7,
        0xc71c_71c7_1c71_c71c,
        0x1c71_c71c_71c7_1c71,
    ];
    const BETA: [u8; 32] = [
        0x7a, 0xe9, 0x6a, 0x2b, 0x65, 0x7c, 0x07, 0x10, 0x6e, 0x64, 0x47, 0x9e, 0xac, 0x34, 0x34,
        0xe9, 0x9c, 0xf0, 0x49, 0x75, 0x12, 0xf5, 0x89, 0x95, 0xc1, 0x39, 0x6c, 0x28, 0x71, 0x95,
        0x01, 0xee,
    ];
    let beta: Fe = Option::from(Fe::from_repr(BETA.into())).expect("beta below P");
    let seven = Fe::from(7u64);
    let mut xs = Vec::new();
    for y in 1..200u64 {
        let c = (Fe::from(y).square() - seven).normalize();
        let x = c.pow_vartime(CUBE_ROOT_EXP);
        if bool::from((x.square() * x - c).normalize().is_zero()) {
            for x in [x, x * beta, x * beta.square()] {
                xs.push(x.normalize().to_repr().into());
            }
        }
    }
    assert_eq!(xs.len(), 183, "points with y < 200");
    xs
}

/// The boundary classes' final points, as (class, X); `subset` keeps the
/// first eight of each class.
fn boundary_targets(subset: bool) -> Vec<(&'static str, AffinePoint)> {
    let mut rng = SplitMix64(0x626f_756e_6461_7279);
    let mut out: Vec<(&'static str, AffinePoint)> = Vec::new();
    let push = |class: &'static str, x: &[u8; 32], odd: bool, out: &mut Vec<_>| {
        if let Some(p) = point_at(x, odd) {
            out.push((class, p));
        }
    };
    let mut ks: Vec<u64> = (1..=600).collect();
    ks.extend((0..600).map(|_| rng.below(1 << 32)));
    ks.push((1 << 32) - 1);
    for k in ks {
        push(
            "x-above-n",
            &add(&GROUP_ORDER_BYTES, &small(k)),
            rng.below(2) == 1,
            &mut out,
        );
    }
    let mut pm3 = FIELD_PRIME_BYTES;
    pm3[31] -= 3;
    push("x-p-minus-3", &pm3, false, &mut out);
    push("x-p-minus-3", &pm3, true, &mut out);
    for k in 0..400 {
        push(
            "x-in-p-minus-n-to-n",
            &add(&P_MINUS_N, &small(k)),
            rng.below(2) == 1,
            &mut out,
        );
        push(
            "x-in-p-minus-n-to-n",
            &sub(&GROUP_ORDER_BYTES, &small(k + 1)),
            rng.below(2) == 1,
            &mut out,
        );
    }
    for x in 1..=600 {
        push("tiny-x", &small(x), rng.below(2) == 1, &mut out);
    }
    for x in tiny_y_xs() {
        push("tiny-y", &x, false, &mut out);
        push("tiny-y", &x, true, &mut out);
    }
    if subset {
        let mut kept: Vec<(&'static str, AffinePoint)> = Vec::new();
        for (c, p) in out {
            if kept.iter().filter(|(k, _)| *k == c).count() < 8 {
                kept.push((c, p));
            }
        }
        kept
    } else {
        out
    }
}

/// The boundary cases: for each target X, Q solved for a random (u1, u2),
/// r chosen for the accepting step (X.x, or X.x - N when X.x >= N), and
/// r + 1 and r - 1 too; r exactly P - N with a random X; and X at
/// infinity, Q = -(u1/u2)G, with a random r.
fn boundary(subset: bool) -> Vec<Case> {
    let mut rng = SplitMix64(0x626f_756e_6461_7232);
    let g = ProjectivePoint::GENERATOR;
    let mut out = Vec::new();
    for (class, xa) in boundary_targets(subset) {
        let x = ProjectivePoint::from(xa);
        let (u1, u2) = (rand_scalar(&mut rng), rand_scalar(&mut rng));
        let q = ((x - g * u1) * u2.invert_vartime().expect("nonzero")).to_affine();
        if bool::from(q.is_identity()) {
            continue;
        }
        let xx: [u8; 32] = xa.x().into();
        let r = if xx >= GROUP_ORDER_BYTES {
            sub(&xx, &GROUP_ORDER_BYTES)
        } else {
            xx
        };
        out.push(case(class, "accept", &q, &x, &r, &u1, &u2));
        let r1 = add(&r, &small(1));
        if r1 < GROUP_ORDER_BYTES {
            out.push(case(class, "r+1", &q, &x, &r1, &u1, &u2));
        }
        if r > small(1) {
            out.push(case(class, "r-1", &q, &x, &sub(&r, &small(1)), &u1, &u2));
        }
    }
    let n_extra = if subset { 4 } else { 64 };
    for _ in 0..n_extra {
        let (u1, u2) = (rand_scalar(&mut rng), rand_scalar(&mut rng));
        let x = g * rand_scalar(&mut rng);
        let q = ((x - g * u1) * u2.invert_vartime().expect("nonzero")).to_affine();
        if bool::from(q.is_identity()) {
            continue;
        }
        out.push(case(
            "r-at-p-minus-n",
            "random-x",
            &q,
            &x,
            &P_MINUS_N,
            &u1,
            &u2,
        ));
    }
    for _ in 0..n_extra {
        let (u1, u2) = (rand_scalar(&mut rng), rand_scalar(&mut rng));
        let q = (g * -(u1 * u2.invert_vartime().expect("nonzero"))).to_affine();
        let r: [u8; 32] = rand_scalar(&mut rng).to_repr().into();
        out.push(case(
            "infinity",
            "q=-(u1/u2)G",
            &q,
            &ProjectivePoint::IDENTITY,
            &r,
            &u1,
            &u2,
        ));
    }
    out
}

/// Signatures with s = r, so u2 = 1 and X = u1*G + Q.
fn u2_one(n: usize) -> Vec<Case> {
    let mut rng = SplitMix64(0x7532_5f6f_6e65);
    let g = ProjectivePoint::GENERATOR;
    (0..n)
        .map(|_| {
            let q = g * rand_scalar(&mut rng);
            let u1 = rand_scalar(&mut rng);
            let x = g * u1 + q;
            let r = <Scalar as Reduce<FieldBytes>>::reduce(&x.to_affine().x());
            case(
                "u2-one",
                "s=r",
                &q.to_affine(),
                &x,
                &r.to_repr().into(),
                &u1,
                &Scalar::ONE,
            )
        })
        .collect()
}

/// Whether the full sets run: release without debug assertions, or the
/// 10^6 volume as CI's soak-asserts run sets it.
fn full() -> bool {
    !cfg!(debug_assertions)
        || std::env::var("DCROXIDE_VARTIME_CASES")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .is_some_and(|n| n >= 1_000_000)
}

/// This crate's step for a case's request.
fn our_step(request: &[u8]) -> VerifyStep {
    assert_eq!(request.len(), 1 + 33 + 96);
    let key = PublicKey::parse(&request[1..34]).expect("a valid key");
    let hash: [u8; 32] = request[34..66].try_into().expect("32 bytes");
    let r: [u8; 32] = request[66..98].try_into().expect("32 bytes");
    let s: [u8; 32] = request[98..130].try_into().expect("32 bytes");
    Signature::new(r, s)
        .expect("r and s below N")
        .verify_detailed(&hash, &key)
}

/// dcrd's verdict for a request.
fn dcrd_verdict(oracle: &mut Oracle, request: &[u8]) -> bool {
    match oracle.call_ok("ecdsa_verify_raw", request).as_str() {
        "true" => true,
        "false" => false,
        other => panic!("ecdsa_verify_raw answered {other}"),
    }
}

/// Every case: this crate's step equals dcrd's algorithm's on X, and its
/// verdict equals dcrd's.
fn check_all(oracle: &mut Oracle, cases: &[Case]) -> BTreeSet<&'static str> {
    let mut steps = BTreeSet::new();
    for (i, c) in cases.iter().enumerate() {
        let ours = our_step(&c.request);
        assert_eq!(ours, c.step, "{} {} case {i}: step", c.class, c.variant);
        assert_eq!(
            dcrd_verdict(oracle, &c.request),
            ours.accepts(),
            "{} {} case {i}: verdict, request {}",
            c.class,
            c.variant,
            hex(&c.request)
        );
        steps.insert(step_name(ours));
    }
    steps
}

/// The collision grid's signatures against dcrd.
#[test]
fn collision_grid_signatures_match_dcrd() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let cases = grid(if full() { 3 } else { 1 });
    let steps = check_all(&mut oracle, &cases);
    println!("{} grid signatures; steps {steps:?}", cases.len());
    assert!(steps.contains("step6") && steps.contains("step8"));
}

/// The boundary signatures against dcrd.
#[test]
fn boundary_signatures_match_dcrd() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let cases = boundary(!full());
    let steps = check_all(&mut oracle, &cases);
    println!("{} boundary signatures; steps {steps:?}", cases.len());
    for s in ["step6", "step8", "step9", "step10-accept", "step10-reject"] {
        assert!(steps.contains(s), "no boundary case reached {s}");
    }
    let exact: Vec<&Case> = cases
        .iter()
        .filter(|c| c.class == "r-at-p-minus-n")
        .collect();
    assert!(!exact.is_empty() && exact.iter().all(|c| c.step == VerifyStep::Step9Reject));
}

/// Signatures with u2 = 1 against dcrd.
#[test]
fn u2_one_signatures_match_dcrd() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let cases = u2_one(if full() { 256 } else { 16 });
    check_all(&mut oracle, &cases);
}

/// The committed selection: the first case of each (grid key, step) of the
/// grid at [-1, 1], and of each (class, step) of the boundary subset, plus
/// the first u2 = 1 case, in that order.
fn selection() -> Vec<(usize, Case)> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for set in [grid(1), boundary(true), u2_one(1)] {
        for (i, c) in set.into_iter().enumerate() {
            let what = c.variant.split('/').next().unwrap_or("").to_owned();
            let key = if c.class == "grid" {
                format!("grid {what} {}", step_name(c.step))
            } else {
                format!("{} {}", c.class, step_name(c.step))
            };
            if seen.insert(key) {
                out.push((i, c));
            }
        }
    }
    out
}

/// The file's text for the selection with dcrd's answers.
fn file_text(oracle: &mut Oracle) -> String {
    let mut s = String::new();
    for line in [
        "# ECDSA verification's branches on dcroxide-secp256k1-vartime, judged by dcrd:",
        "# per grid key or boundary class, the first case of each step dcrd's",
        "# algorithm decides at, as tests/vartime_ecdsa_branches.rs constructs them",
        "# on k256 from its fixed seeds (the collision grid at [-1, 1], the boundary",
        "# subset of eight targets per class, u2 = 1), each answer given by dcrd's",
        "# dcrec/secp256k1/v4 at the parity pin 3360ae4d through tools/oracle.",
        "# committed_branch_vectors_regenerate rebuilds the file and fails on any",
        "# difference; committed_branch_vectors_hold checks it without Go.",
        "#",
        "# <class>|<what>/<step>|<case index>|ecdsa_verify_raw|<request data hex>|<answer>",
    ] {
        let _ = writeln!(s, "{line}");
    }
    for (i, c) in selection() {
        let answer = dcrd_verdict(oracle, &c.request);
        let _ = writeln!(
            s,
            "{}|{}|{i}|ecdsa_verify_raw|{}|{answer}",
            c.class,
            c.variant,
            hex(&c.request)
        );
    }
    s
}

/// Each committed line: this crate's verdict is the recorded dcrd answer,
/// and its step the step the line names.  Needs no Go.
#[test]
fn committed_branch_vectors_hold() {
    let mut n = 0;
    let mut steps = BTreeSet::new();
    for line in COMMITTED
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let f: Vec<&str> = line.split('|').collect();
        let [_, variant, _, "ecdsa_verify_raw", request, answer] = f[..] else {
            panic!("{line}: not six fields");
        };
        let ours = our_step(&unhex(request));
        let want_step = variant.rsplit('/').next().unwrap_or("");
        assert_eq!(step_name(ours), want_step, "{line}: step");
        assert_eq!(ours.accepts().to_string(), answer, "{line}: dcrd's answer");
        steps.insert(want_step.to_owned());
        n += 1;
    }
    assert!(n >= 30, "{n} lines");
    for s in ["step6", "step8", "step9", "step10-accept", "step10-reject"] {
        assert!(steps.contains(s), "no committed line reaches {s}");
    }
}

/// The committed file is the selection with dcrd's answers, byte for byte.
/// With `DCROXIDE_REGEN_ECDSA_BRANCHES=<path>` set, a differing text is
/// written there, never into the source tree, and the test still fails.
#[test]
fn committed_branch_vectors_regenerate() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let text = file_text(&mut oracle);
    if text != COMMITTED {
        if let Ok(path) = std::env::var("DCROXIDE_REGEN_ECDSA_BRANCHES") {
            std::fs::write(&path, &text).expect("write the regenerated vectors");
            println!("wrote {path}");
        }
        panic!("tests/data/vartime_ecdsa_branches.txt differs from its construction");
    }
}
