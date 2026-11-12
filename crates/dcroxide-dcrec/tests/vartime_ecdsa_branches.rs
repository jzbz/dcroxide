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
//! (grid key or boundary class, step) of the small selection, and the grid
//! cases whose Straus loop doubles through an addition at each of its four
//! call sites, with dcrd's answer: one test checks it everywhere, without
//! Go, and one rebuilds it with dcrd and compares it byte for byte.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "k256 scalar and field operators, which are modular, and byte \
              offsets within 32-byte arrays"
)]

mod common;

use std::collections::BTreeSet;
use std::fmt::Write as _;

use common::{
    P_MINUS_N, add, data_lines, full, grid_bases, point_at, rand_scalar, require_regenerated,
    sc_i64, scalar, small, sub, tiny_y_xs,
};
use dcroxide_dcrec::secp256k1::ecdsa::{Signature, VerifyStep};
use dcroxide_dcrec::secp256k1::{FIELD_PRIME_BYTES, GROUP_ORDER_BYTES, PublicKey};
use dcroxide_testutil::{Oracle, SplitMix64, hex, oracle_or_skip, unhex};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::group::CurveAffine;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};

/// The committed vectors.
const COMMITTED: &str = include_str!("data/vartime_ecdsa_branches.txt");

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
    let lam = scalar(&common::LAMBDA);
    let t = common::pow2_128();
    let bases = grid_bases();
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
/// grid at [-1, 1], with the grid's doubling cases
/// ([`common::DOUBLING_CELLS`], labelled `<key>/<cell>/<step>`) in their
/// place, then the first case of each (class, step) of the boundary
/// subset, and the first u2 = 1 case.
fn selection() -> Vec<(usize, Case)> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for set in [grid(1), boundary(true), u2_one(1)] {
        for (i, mut c) in set.into_iter().enumerate() {
            let what = c.variant.split('/').next().unwrap_or("").to_owned();
            let key = if c.class == "grid" {
                format!("grid {what} {}", step_name(c.step))
            } else {
                format!("{} {}", c.class, step_name(c.step))
            };
            let cell = (c.class == "grid")
                .then(|| common::doubling_cell(i))
                .flatten();
            if let Some(cell) = cell {
                c.variant = format!("{what}/{cell}/{}", step_name(c.step));
            }
            if seen.insert(key) || cell.is_some() {
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
        "# subset of eight targets per class, u2 = 1), plus the grid cases whose",
        "# Straus loop doubles through an addition at each call site (labelled",
        "# dbl-<site>), each answer given by dcrd's",
        "# dcrec/secp256k1/v4 at the parity pin 46e9df48 through tools/oracle.",
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
    for (line, f) in data_lines(COMMITTED) {
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
    common::assert_doubling_cells_named(data_lines(COMMITTED).map(|(_, f)| f[1]));
}

/// The committed file is the selection with dcrd's answers, byte for byte.
/// With `DCROXIDE_REGEN_ECDSA_BRANCHES=<path>` set, a differing text is
/// written there, never into the source tree, and the test still fails.
#[test]
fn committed_branch_vectors_regenerate() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    require_regenerated(
        &file_text(&mut oracle),
        COMMITTED,
        "DCROXIDE_REGEN_ECDSA_BRANCHES",
        "tests/data/vartime_ecdsa_branches.txt",
    );
}
