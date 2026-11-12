// SPDX-License-Identifier: ISC
//! Public keys at the edges of the curve check, built on k256 and judged
//! by dcrd (ADR-0016): since the key type moved onto
//! dcroxide-secp256k1-vartime, every key is parsed, checked against the
//! curve and serialized there, so each case here is a key in one encoding
//! and dcrd's `ParsePubKey` through `tools/oracle`'s `pubkey_parse` is the
//! reference for the verdict, the error kind, the error text and both
//! serializations, never k256's or this crate's.  Each case is also
//! checked against dcrd's order of checks run on k256 (x's range, y's
//! range, the hybrid parity, then the curve), the second reference, which
//! needs no Go, and every accepted encoding of one point must give one
//! key that parses back from dcrd's serializations.
//!
//! The classes, each point in the uncompressed form, both hybrid forms
//! (one of them of the wrong parity) and both compressed forms:
//!
//! - `tiny-y`: the 183 points whose y is below 200, with y and with P - y;
//! - `small-x`: the first four x from 1 up that have a point;
//! - `top-x`: P - 3 and P - 4, the two largest x with a point, N and the
//!   next x above N with a point;
//! - `off-curve`: (x, y + 1) below P and (x, P - 1 - y) for the tiny-y points,
//!   (x, 0), (0, y) and (P - 1, y) for a few points, in the three 65-byte
//!   forms, and the x values 0, P - 2, P - 1 and N - 1, which have no
//!   point, compressed;
//! - `range`: x and y at P and P + 1, alone and together, in every form;
//! - `random`: 64 seeded keys.
//!
//! The committed file `tests/data/vartime_pubkey_branches.txt` holds the
//! first case of each (class, encoding, outcome) with dcrd's answer: one
//! test checks it everywhere, without Go, and one rebuilds it with dcrd
//! and compares it byte for byte.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "byte offsets within 65-byte keys"
)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use common::{add, data_lines, point_at, rand_scalar, require_regenerated, small, sub, tiny_y_xs};
use dcroxide_dcrec::secp256k1::{FIELD_PRIME_BYTES, GROUP_ORDER_BYTES, PublicKey};
use dcroxide_testutil::{Oracle, SplitMix64, hex, oracle_or_skip, unhex};
use k256::AffinePoint;
use k256::ProjectivePoint;
use k256::elliptic_curve::point::AffineCoordinates;

/// The committed vectors.
const COMMITTED: &str = include_str!("data/vartime_pubkey_branches.txt");

/// The oracle's command.
const PARSE: &str = "pubkey_parse";

/// One constructed key.
struct Case {
    /// The class.
    class: &'static str,
    /// The encoding's prefix byte and the outcome dcrd's order of checks
    /// gives on k256, as `<prefix hex>/<ok or dcrd's error kind>`.
    variant: String,
    /// The serialized key.
    key: Vec<u8>,
}

impl Case {
    /// The outcome the variant names.
    fn outcome(&self) -> &str {
        self.variant.rsplit('/').next().unwrap_or("")
    }
}

/// dcrd's `ParsePubKey` checks in its order, the curve on k256: the point,
/// or dcrd's error kind.
fn reference(key: &[u8]) -> Result<AffinePoint, &'static str> {
    match key.len() {
        65 => {
            let format = key[0];
            if ![4, 6, 7].contains(&format) {
                return Err("ErrPubKeyInvalidFormat");
            }
            let x: [u8; 32] = key[1..33].try_into().expect("32 bytes");
            let y: [u8; 32] = key[33..].try_into().expect("32 bytes");
            if x >= FIELD_PRIME_BYTES {
                return Err("ErrPubKeyXTooBig");
            }
            if y >= FIELD_PRIME_BYTES {
                return Err("ErrPubKeyYTooBig");
            }
            if format != 4 && (format == 7) != (y[31] & 1 == 1) {
                return Err("ErrPubKeyMismatchedOddness");
            }
            Option::from(AffinePoint::from_coordinates(&x.into(), &y.into()))
                .ok_or("ErrPubKeyNotOnCurve")
        }
        33 => {
            let format = key[0];
            if format != 2 && format != 3 {
                return Err("ErrPubKeyInvalidFormat");
            }
            let x: [u8; 32] = key[1..].try_into().expect("32 bytes");
            if x >= FIELD_PRIME_BYTES {
                return Err("ErrPubKeyXTooBig");
            }
            point_at(&x, format == 3).ok_or("ErrPubKeyNotOnCurve")
        }
        _ => Err("ErrPubKeyInvalidLen"),
    }
}

/// The case for a key, its outcome by [`reference`].
fn case(class: &'static str, key: Vec<u8>) -> Case {
    let outcome = reference(&key).map_or_else(str::to_owned, |_| "ok".to_owned());
    Case {
        class,
        variant: format!("{:02x}/{outcome}", key[0]),
        key,
    }
}

/// (x, y) in the three 65-byte forms: uncompressed, even hybrid, odd
/// hybrid.
fn long_forms(class: &'static str, x: &[u8; 32], y: &[u8; 32]) -> Vec<Case> {
    [4u8, 6, 7]
        .into_iter()
        .map(|prefix| {
            let mut key = vec![prefix];
            key.extend_from_slice(x);
            key.extend_from_slice(y);
            case(class, key)
        })
        .collect()
}

/// x in both compressed forms.
fn short_forms(class: &'static str, x: &[u8; 32]) -> Vec<Case> {
    [2u8, 3]
        .into_iter()
        .map(|prefix| {
            let mut key = vec![prefix];
            key.extend_from_slice(x);
            case(class, key)
        })
        .collect()
}

/// Both points at x in every form.
fn point_forms(class: &'static str, x: &[u8; 32]) -> Vec<Case> {
    let mut out = Vec::new();
    for odd in [false, true] {
        let p = point_at(x, odd).expect("a point");
        out.extend(long_forms(class, x, &p.y().into()));
    }
    out.extend(short_forms(class, x));
    out
}

/// P - d, big-endian.
fn below_p(d: u64) -> [u8; 32] {
    sub(&FIELD_PRIME_BYTES, &small(d))
}

/// The first `n` x values from `from` up that have a point.
fn xs_with_points(mut from: [u8; 32], n: usize) -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    while out.len() < n {
        if point_at(&from, false).is_some() {
            out.push(from);
        }
        from = add(&from, &small(1));
    }
    out
}

/// The `tiny-y` class.
fn tiny_y() -> Vec<Case> {
    tiny_y_xs()
        .iter()
        .flat_map(|x| point_forms("tiny-y", x))
        .collect()
}

/// The `small-x` and `top-x` classes.
fn small_and_top_x() -> Vec<Case> {
    let mut out = Vec::new();
    for x in xs_with_points(small(1), 4) {
        out.extend(point_forms("small-x", &x));
    }
    assert_eq!(xs_with_points(below_p(4), 2), [below_p(4), below_p(3)]);
    let n_next = xs_with_points(add(&GROUP_ORDER_BYTES, &small(1)), 1)[0];
    for x in [below_p(3), below_p(4), GROUP_ORDER_BYTES, n_next] {
        out.extend(point_forms("top-x", &x));
    }
    out
}

/// The `off-curve` and `range` classes.
fn off_curve_and_range() -> Vec<Case> {
    let mut out = Vec::new();
    let one = small(1);
    let p_minus_1 = below_p(1);
    for x in tiny_y_xs() {
        for odd in [false, true] {
            let y: [u8; 32] = point_at(&x, odd).expect("a point").y().into();
            // y + 1 is P for y = P - 1, a range case, not this class's.
            if y != p_minus_1 {
                out.extend(long_forms("off-curve", &x, &add(&y, &one)));
            }
            out.extend(long_forms("off-curve", &x, &sub(&p_minus_1, &y)));
        }
    }
    for x in xs_with_points(small(1), 2)
        .into_iter()
        .chain([below_p(3), GROUP_ORDER_BYTES])
    {
        let y: [u8; 32] = point_at(&x, true).expect("a point").y().into();
        out.extend(long_forms("off-curve", &x, &[0; 32]));
        out.extend(long_forms("off-curve", &[0; 32], &y));
        out.extend(long_forms("off-curve", &p_minus_1, &y));
    }
    for x in [
        small(0),
        below_p(2),
        below_p(1),
        sub(&GROUP_ORDER_BYTES, &one),
    ] {
        out.extend(short_forms("off-curve", &x));
    }

    let x = xs_with_points(small(1), 1)[0];
    let y: [u8; 32] = point_at(&x, false).expect("a point").y().into();
    let p = FIELD_PRIME_BYTES;
    let p1 = add(&p, &one);
    for (xx, yy) in [(p, y), (p1, y), (x, p), (x, p1), (p, p), (p1, p1)] {
        out.extend(long_forms("range", &xx, &yy));
    }
    for xx in [p, p1] {
        out.extend(short_forms("range", &xx));
    }
    out
}

/// The `random` class.
fn random() -> Vec<Case> {
    let mut rng = SplitMix64(0x7075_626b_6579_7321);
    (0..64)
        .flat_map(|_| {
            let p = (ProjectivePoint::GENERATOR * rand_scalar(&mut rng)).to_affine();
            point_forms("random", &p.x().into())
        })
        .collect()
}

/// This crate's answer, as [`dcrd_answer`] gives dcrd's: `ok`, the
/// uncompressed and the compressed serialization, or `err`, the kind and
/// the error text.
fn our_answer(key: &[u8]) -> String {
    match PublicKey::parse(key) {
        Ok(pk) => format!(
            "ok {} {}",
            hex(&pk.serialize_uncompressed()),
            hex(&pk.serialize_compressed())
        ),
        Err(e) => format!("err {} {e}", e.kind_name()),
    }
}

/// dcrd's answer through the oracle.
fn dcrd_answer(oracle: &mut Oracle, key: &[u8]) -> String {
    let resp = oracle.call(PARSE, key);
    match resp.get("error").and_then(|e| e.as_str()) {
        None => format!(
            "ok {} {}",
            resp["result"].as_str().expect("result"),
            resp["compressed"].as_str().expect("compressed")
        ),
        Some(text) => format!("err {} {text}", resp["kind"].as_str().expect("kind")),
    }
}

/// A case's answer by this crate, checked against the second reference:
/// the outcome the variant names, k256's point as both serializations on
/// acceptance, and the key parsed back from both.
fn ours_checked(c: &Case, what: &str) -> String {
    let ours = our_answer(&c.key);
    let want = reference(&c.key);
    match PublicKey::parse(&c.key) {
        Ok(pk) => {
            let k = want.unwrap_or_else(|e| panic!("{what}: k256's order stops at {e}"));
            assert_eq!(c.outcome(), "ok", "{what}: the outcome");
            let u = pk.serialize_uncompressed();
            let cmp = pk.serialize_compressed();
            assert_eq!(u[0], 4, "{what}");
            assert_eq!(u[1..33], <[u8; 32]>::from(k.x()), "{what}: x");
            assert_eq!(u[33..], <[u8; 32]>::from(k.y()), "{what}: y");
            assert_eq!(cmp[0], 2 | (u[64] & 1), "{what}: the parity");
            assert_eq!(cmp[1..], u[1..33], "{what}: the compressed x");
            assert_eq!(PublicKey::parse(&u), Ok(pk), "{what}: uncompressed again");
            assert_eq!(PublicKey::parse(&cmp), Ok(pk), "{what}: compressed again");
            if c.key[0] == 4 {
                assert_eq!(u[..], c.key[..], "{what}: the key back");
            }
        }
        Err(e) => {
            assert_eq!(want.err(), Some(e.kind_name()), "{what}: k256's order");
            assert_eq!(c.outcome(), e.kind_name(), "{what}: the outcome");
        }
    }
    ours
}

/// Every case: this crate's answer matches the second reference, every
/// accepted encoding of one point gives one key, and, with Go, the answer
/// equals dcrd's.  Returns the variants seen.
fn check_all(cases: &[Case]) -> BTreeSet<String> {
    let mut oracle = oracle_or_skip();
    let mut keys: BTreeMap<[u8; 64], PublicKey> = BTreeMap::new();
    let mut variants = BTreeSet::new();
    for (i, c) in cases.iter().enumerate() {
        let what = format!("{} {} case {i}, key {}", c.class, c.variant, hex(&c.key));
        let ours = ours_checked(c, &what);
        if let Ok(pk) = PublicKey::parse(&c.key) {
            let u: [u8; 64] = pk.serialize_uncompressed()[1..]
                .try_into()
                .expect("64 bytes");
            assert_eq!(
                *keys.entry(u).or_insert(pk),
                pk,
                "{what}: one key per point"
            );
        }
        if let Some(oracle) = oracle.as_mut() {
            assert_eq!(dcrd_answer(oracle, &c.key), ours, "{what}: dcrd's answer");
        }
        variants.insert(c.variant.clone());
    }
    variants
}

/// Asserts that `variants` holds every one named.
fn reached(variants: &BTreeSet<String>, want: &[&str]) {
    for v in want {
        assert!(variants.contains(*v), "never reached {v}: {variants:?}");
    }
}

/// The accepting and parity outcomes every class of curve points reaches.
const POINT_OUTCOMES: [&str; 7] = [
    "04/ok",
    "06/ok",
    "06/ErrPubKeyMismatchedOddness",
    "07/ok",
    "07/ErrPubKeyMismatchedOddness",
    "02/ok",
    "03/ok",
];

/// Keys with a tiny y, and with P - y, in every form.
#[test]
fn tiny_y_keys_match_dcrd() {
    let cases = tiny_y();
    assert_eq!(cases.len(), 183 * 8);
    let variants = check_all(&cases);
    reached(&variants, &POINT_OUTCOMES);
    assert_eq!(variants.len(), POINT_OUTCOMES.len(), "{variants:?}");
}

/// Keys at the smallest and the largest x with a point, and at N.
#[test]
fn small_and_top_x_keys_match_dcrd() {
    let cases = small_and_top_x();
    for class in ["small-x", "top-x"] {
        let variants: BTreeSet<String> = cases
            .iter()
            .filter(|c| c.class == class)
            .map(|c| c.variant.clone())
            .collect();
        assert_eq!(
            variants.len(),
            POINT_OUTCOMES.len(),
            "{class}: {variants:?}"
        );
    }
    reached(&check_all(&cases), &POINT_OUTCOMES);
}

/// Keys off the curve and coordinates out of range, in every form.
#[test]
fn off_curve_and_range_keys_match_dcrd() {
    let cases = off_curve_and_range();
    let variants = check_all(&cases);
    reached(
        &variants,
        &[
            "04/ErrPubKeyNotOnCurve",
            "06/ErrPubKeyNotOnCurve",
            "06/ErrPubKeyMismatchedOddness",
            "07/ErrPubKeyNotOnCurve",
            "07/ErrPubKeyMismatchedOddness",
            "02/ErrPubKeyNotOnCurve",
            "03/ErrPubKeyNotOnCurve",
            "04/ErrPubKeyXTooBig",
            "04/ErrPubKeyYTooBig",
            "06/ErrPubKeyXTooBig",
            "06/ErrPubKeyYTooBig",
            "07/ErrPubKeyXTooBig",
            "07/ErrPubKeyYTooBig",
            "02/ErrPubKeyXTooBig",
            "03/ErrPubKeyXTooBig",
        ],
    );
    assert!(!variants.iter().any(|v| v.ends_with("/ok")), "{variants:?}");
}

/// Seeded keys in every form.
#[test]
fn random_keys_match_dcrd() {
    let variants = check_all(&random());
    reached(&variants, &POINT_OUTCOMES);
}

/// The committed selection, in this order: the first case of each
/// (class, variant) of the tiny-y, small-x, top-x, off-curve, range and
/// random classes.
fn selection() -> Vec<(usize, Case)> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for set in [tiny_y(), small_and_top_x(), off_curve_and_range(), random()] {
        for (i, c) in set.into_iter().enumerate() {
            if seen.insert(format!("{} {}", c.class, c.variant)) {
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
        "# Public keys at the edges of dcroxide-secp256k1-vartime's curve check,",
        "# judged by dcrd: per class, the first key of each encoding and outcome,",
        "# as tests/vartime_pubkey_branches.rs constructs them on k256 (points",
        "# with a tiny y, the smallest and largest x with a point and x = N,",
        "# keys off the curve, coordinates out of range, seeded keys), each answer",
        "# given by dcrd's dcrec/secp256k1/v4 ParsePubKey at the parity pin",
        "# 46e9df48 through tools/oracle: ok with the uncompressed and compressed",
        "# serializations, or err with the kind and dcrd's error text.",
        "# committed_pubkey_vectors_regenerate rebuilds the file and fails on any",
        "# difference; committed_pubkey_vectors_hold checks it without Go.",
        "#",
        "# <class>|<prefix>/<outcome>|<case index>|pubkey_parse|<key hex>|<answer>",
    ] {
        let _ = writeln!(s, "{line}");
    }
    for (i, c) in selection() {
        let answer = dcrd_answer(oracle, &c.key);
        let _ = writeln!(
            s,
            "{}|{}|{i}|{PARSE}|{}|{answer}",
            c.class,
            c.variant,
            hex(&c.key)
        );
    }
    s
}

/// Each committed line: this crate's answer is the recorded dcrd answer,
/// and it matches the outcome the line names.  Needs no Go.
#[test]
fn committed_pubkey_vectors_hold() {
    let mut n = 0;
    let mut outcomes = BTreeSet::new();
    for (line, f) in data_lines(COMMITTED) {
        let [_, variant, _, command, key, answer] = f[..] else {
            panic!("{line}: not six fields");
        };
        assert_eq!(command, PARSE, "{line}");
        let c = Case {
            class: "committed",
            variant: variant.to_owned(),
            key: unhex(key),
        };
        assert_eq!(ours_checked(&c, line), answer, "{line}: dcrd's answer");
        outcomes.insert(c.outcome().to_owned());
        n += 1;
    }
    assert!(n >= 40, "{n} lines");
    assert_eq!(
        outcomes,
        BTreeSet::from(
            [
                "ok",
                "ErrPubKeyMismatchedOddness",
                "ErrPubKeyNotOnCurve",
                "ErrPubKeyXTooBig",
                "ErrPubKeyYTooBig",
            ]
            .map(str::to_owned)
        )
    );
}

/// The committed file is the selection with dcrd's answers, byte for byte.
/// With `DCROXIDE_REGEN_PUBKEY_BRANCHES=<path>` set, a differing text is
/// written there, never into the source tree, and the test still fails.
#[test]
fn committed_pubkey_vectors_regenerate() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    require_regenerated(
        &file_text(&mut oracle),
        COMMITTED,
        "DCROXIDE_REGEN_PUBKEY_BRANCHES",
        "tests/data/vartime_pubkey_branches.txt",
    );
}
