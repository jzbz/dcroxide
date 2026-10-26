// SPDX-License-Identifier: ISC
//! Public key parsing classes (K-*).
//!
//! Every case is two requests on the same bytes: `pubkey_parse`, dcrd's
//! `secp256k1.ParsePubKey`, and `schnorr_pubkey_parse`, dcrd's
//! `schnorr.ParsePubKey`.  dcrd's order is length; format; x ≥ P; y ≥ P;
//! hybrid oddness; on the curve (`pubkey.go`).  The Schnorr parser wants
//! 33 bytes and a 02/03 format first, with errors of its own and no kind,
//! then hands the key to the first; so the Schnorr request's intent follows
//! from the length and format ([`schnorr_intent`]).

use std::borrow::Cow;

use k256::AffinePoint;

use crate::arith::{self, P, TWO_256_MINUS_P};
use crate::class::{Case, ClassSpec, Consistency, Family, Intent, Mix, Size, Tags, Tier};
use crate::cmd::{self, Cmd};
use crate::entropy::Entropy;
use crate::r#gen::kwrap_points::{KWRAP_POINTS, WrapPoint};
use crate::r#gen::{
    ALL_ACCEPTED, DECOMPRESS_TRIES, Draw, FLOOR_A, NONE_ACCEPTED, PR_CASES, SCALAR_TRIES, base_mul,
    be, compressed, decompress, digit, from_xy, parsed, stratum, uncompressed, with_format,
    with_parity, x_of, y_is_odd, y_of,
};

/// Both key parsers.
const PARSERS: &[Cmd] = &[Cmd::PubkeyParse, Cmd::SchnorrPubkeyParse];

/// The five key formats, with the parity of y each names (`None`: any).
const FORMATS: [(u8, Option<bool>); 5] = [
    (0x02, Some(false)),
    (0x03, Some(true)),
    (0x04, None),
    (0x06, Some(false)),
    (0x07, Some(true)),
];

/// The three 65-byte formats.
const LONG_FORMATS: [(u8, Option<bool>); 3] = [FORMATS[2], FORMATS[3], FORMATS[4]];

/// A format byte's label.
fn format_label(format: u8) -> &'static str {
    match format {
        0x02 => "02",
        0x03 => "03",
        0x04 => "04",
        0x06 => "06",
        0x07 => "07",
        _ => "other",
    }
}

/// x, and y for a 65-byte format, under `format`.
fn encode(format: u8, x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
    if format == 0x02 || format == 0x03 {
        [&[format][..], x].concat()
    } else {
        with_format(format, x, y).to_vec()
    }
}

/// The Schnorr parser's intent for `key`, given `pubkey_parse`'s: a
/// rejection without a kind ([`Intent::RejectPlain`]) unless the key is 33
/// bytes with a 02/03 format, and otherwise `pubkey_parse`'s intent, with
/// the compressed value for an accepted key.
pub fn schnorr_intent(key: &[u8], intent: &Intent) -> Intent {
    let compressed_form = key.len() == 33 && matches!(key.first(), Some(0x02 | 0x03));
    if !compressed_form {
        return Intent::RejectPlain;
    }
    match intent {
        Intent::AcceptValue(value) => Intent::AcceptValue(value.get(65..).unwrap_or(&[]).to_vec()),
        other => other.clone(),
    }
}

/// A case of `key` through both parsers, `intent` being `pubkey_parse`'s.
fn key_case(variant: impl Into<Cow<'static, str>>, key: Vec<u8>, intent: Intent) -> Case {
    let schnorr = schnorr_intent(&key, &intent);
    Case {
        variant: variant.into(),
        requests: vec![cmd::pubkey_parse(&key), cmd::schnorr_pubkey_parse(&key)],
        intents: vec![intent, schnorr],
        consistency: Consistency::None,
        tags: Tags::NONE,
    }
}

/// A random point whose y has the parity a format names.
fn point_for(d: &mut Draw, parity: Option<bool>) -> AffinePoint {
    let q = base_mul(&d.key());
    match parity {
        Some(odd) => with_parity(&q, odd),
        None => q,
    }
}

/// y moved by 2 up or down (drawn), staying below P; the parity is kept.
fn shift_two(d: &mut Draw, y: &[u8; 32]) -> [u8; 32] {
    let two = be(2);
    let up = arith::add_be(y, &two);
    let down = arith::sub_be(y, &two);
    let up_ok = !up.1 && up.0 < P;
    if (d.coin() && up_ok) || down.1 {
        up.0
    } else {
        down.0
    }
}

fn k_valid(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let (format, parity) = FORMATS[stratum(i, 5)];
    let q = point_for(&mut d, parity);
    let key = encode(format, &x_of(&q), &y_of(&q));
    d.finish(key_case(
        format_label(format),
        key,
        Intent::AcceptValue(parsed(&q)),
    ))
}

fn k_hybrid_mismatch(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let off_curve = stratum(i, 2) == 1;
    let (key, label) = d.retry(
        SCALAR_TRIES,
        || (vec![0x06; 65], "on-curve"),
        |d| {
            let q = base_mul(&d.key());
            let wrong = 0x06 | u8::from(!y_is_odd(&q));
            let x = x_of(&q);
            if off_curve {
                // y ± 2 keeps the parity, so the oddness check still fails
                // first; the point must be off the curve.
                let y = shift_two(d, &y_of(&q));
                from_xy(&x, &y)
                    .is_none()
                    .then(|| (with_format(wrong, &x, &y).to_vec(), "off-curve"))
            } else {
                Some((with_format(wrong, &x, &y_of(&q)).to_vec(), "on-curve"))
            }
        },
    );
    d.finish(key_case(
        label,
        key,
        Intent::RejectKind("ErrPubKeyMismatchedOddness"),
    ))
}

/// The labels of the coordinate values at or above P.
const AT_OR_ABOVE_P: [&str; 4] = ["P", "P+1", "max", "random"];

/// Value `k`: P, P + 1, 2^256 − 1, or uniform in [P, 2^256).
fn at_or_above_p(d: &mut Draw, k: usize) -> [u8; 32] {
    match k {
        0 => P,
        1 => arith::add_be(&P, &be(1)).0,
        2 => [0xff; 32],
        _ => arith::add_be(&P, &d.uniform_below(&TWO_256_MINUS_P)).0,
    }
}

fn k_x_too_big(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let k = stratum(i, 4);
    let (format, _) = FORMATS[digit(i, 4, 5)];
    // In half the strata a 65-byte key's y is at or above P too: x is
    // checked first, so its kind is still x's.
    let y_too_big = digit(i, 20, 2) == 1 && format != 0x02 && format != 0x03;
    let x = at_or_above_p(&mut d, k);
    let y = if y_too_big {
        at_or_above_p(&mut d, 3)
    } else {
        d.bytes32()
    };
    d.finish(key_case(
        format!(
            "{}/{}{}",
            AT_OR_ABOVE_P[k],
            format_label(format),
            if y_too_big { "/y-too-big" } else { "" }
        ),
        encode(format, &x, &y),
        Intent::RejectKind("ErrPubKeyXTooBig"),
    ))
}

fn k_y_too_big(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let k = stratum(i, 4);
    let (format, _) = LONG_FORMATS[digit(i, 4, 3)];
    let x = x_of(&base_mul(&d.key()));
    let y = at_or_above_p(&mut d, k);
    d.finish(key_case(
        format!("{}/{}", AT_OR_ABOVE_P[k], format_label(format)),
        encode(format, &x, &y),
        Intent::RejectKind("ErrPubKeyYTooBig"),
    ))
}

fn k_wrap(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let case = if stratum(i, 2) == 0 {
        // x₀ below 2^256 − P that decompresses, encoded as x₀ + P: a parser
        // that reduces mod P would take it for the point (x₀, y).
        let (format, parity) = FORMATS[digit(i, 2, 5)];
        let (x0, q) = d.retry(
            DECOMPRESS_TRIES,
            || (be(1), base_mul(&k256::Scalar::ONE)),
            |d| {
                let x0 = d.uniform_below(&TWO_256_MINUS_P);
                let odd = parity.unwrap_or_else(|| d.coin());
                decompress(&x0, odd).map(|q| (x0, q))
            },
        );
        let x = arith::add_be(&x0, &P).0;
        key_case(
            format!("x+P/{}", format_label(format)),
            encode(format, &x, &y_of(&q)),
            Intent::RejectKind("ErrPubKeyXTooBig"),
        )
    } else {
        // A constant point with a small y, encoded as (x, y + P), the
        // hybrid byte matching y: drawn uniformly among the table's points
        // whose y has the format's parity, so no draw is retried.
        let (format, parity) = LONG_FORMATS[digit(i, 2, 3)];
        let wanted = |point: &&WrapPoint| parity.is_none_or(|odd| (point.y & 1 == 1) == odd);
        let count = KWRAP_POINTS.iter().filter(wanted).count();
        let at = d.below(u64::try_from(count).expect("192 points at most"));
        let point = KWRAP_POINTS
            .iter()
            .filter(wanted)
            .nth(usize::try_from(at).expect("an index below the count"))
            .copied()
            .expect("an index below the count");
        let y = arith::add_be(&point.y_bytes(), &P).0;
        key_case(
            format!("y+P/{}", format_label(format)),
            encode(format, &point.x_bytes(), &y),
            Intent::RejectKind("ErrPubKeyYTooBig"),
        )
    };
    d.finish(case)
}

fn k_near_p(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let (format, parity) = FORMATS[stratum(i, 5)];
    let q = d.retry(
        DECOMPRESS_TRIES,
        || base_mul(&k256::Scalar::ONE),
        |d| {
            // x = P − 1 − u for u below 2^32.
            let u = be(d.below(1 << 32).saturating_add(1));
            let x = arith::sub_be(&P, &u).0;
            let odd = parity.unwrap_or_else(|| d.coin());
            decompress(&x, odd)
        },
    );
    d.finish(key_case(
        format_label(format),
        encode(format, &x_of(&q), &y_of(&q)),
        Intent::AcceptValue(parsed(&q)),
    ))
}

fn k_off_curve(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let case = if stratum(i, 2) == 0 {
        // A valid point with y moved by 2; the hybrid byte matches the new
        // y, whose parity is the old one's.
        let (format, parity) = LONG_FORMATS[digit(i, 2, 3)];
        let (x, y) = d.retry(
            SCALAR_TRIES,
            || (be(1), be(1)),
            |d| {
                let q = point_for(d, parity);
                let x = x_of(&q);
                let y = shift_two(d, &y_of(&q));
                from_xy(&x, &y).is_none().then_some((x, y))
            },
        );
        key_case(
            format!("uncompressed/{}", format_label(format)),
            encode(format, &x, &y),
            Intent::RejectKind("ErrPubKeyNotOnCurve"),
        )
    } else {
        // An x below P for which x³ + 7 has no square root.
        let format = [0x02, 0x03][digit(i, 2, 2)];
        let x = d.retry(
            DECOMPRESS_TRIES,
            || be(0),
            |d| {
                let x = d.bytes32();
                (x < P && decompress(&x, false).is_none()).then_some(x)
            },
        );
        key_case(
            format!("compressed/{}", format_label(format)),
            encode(format, &x, &[0; 32]),
            Intent::RejectKind("ErrPubKeyNotOnCurve"),
        )
    };
    d.finish(case)
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
)]
fn k_neg_y(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let (format, parity) = LONG_FORMATS[stratum(i, 3)];
    // (x, P − y) is −Q; Q is picked so that −Q's y has the format's parity.
    let q = point_for(&mut d, parity.map(|odd| !odd));
    let neg_y = arith::neg_mod_p(&y_of(&q));
    d.finish(key_case(
        format_label(format),
        encode(format, &x_of(&q), &neg_y),
        Intent::AcceptValue(parsed(&-q)),
    ))
}

/// K-mutate's edits.
const KEY_MUTATIONS: [&str; 3] = ["format", "xor", "truncate"];

fn k_mutate(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let edit = stratum(i, 3);
    let q = base_mul(&d.key());
    // The mutations of crates/dcroxide-dcrec/tests/oracle_differential.rs:
    // a compressed or uncompressed key, then a random format byte, one byte
    // xored with a random byte, or a cut anywhere.
    let mut key = if d.coin() {
        compressed(&q).to_vec()
    } else {
        uncompressed(&q).to_vec()
    };
    match edit {
        0 => key[0] = d.byte(),
        1 => {
            let at = d.len_in(0, key.len().saturating_sub(1));
            let x = d.byte();
            key[at] ^= x;
        }
        _ => {
            let cut = d.len_in(0, key.len());
            key.truncate(cut);
        }
    }
    d.finish(key_case(KEY_MUTATIONS[edit], key, Intent::Any))
}

/// x = i / 2 in 0..=1024 under format 02 + i % 2.  Each case's intent is
/// computed: the point when x decompresses, ErrPubKeyNotOnCurve when not.
fn k_small_x(e: &mut dyn Entropy, i: u64) -> Case {
    let d = Draw::new(e);
    let odd = stratum(i, 2) == 1;
    let x = be(u64::try_from(digit(i, 2, 1025)).unwrap_or(0));
    let format = 0x02 | u8::from(odd);
    let intent = match decompress(&x, odd) {
        Some(q) => Intent::AcceptValue(parsed(&q)),
        None => Intent::RejectKind("ErrPubKeyNotOnCurve"),
    };
    d.finish(key_case(
        format_label(format),
        encode(format, &x, &[0; 32]),
        intent,
    ))
}

/// Format byte i % 256 at length 33 (i < 256) or 65, on a random valid
/// point with an even y, so that of the two hybrid bytes exactly 06
/// parses.  Each case's intent is computed: 02, 03, 04 and 06 parse, 07 is
/// ErrPubKeyMismatchedOddness, every other byte ErrPubKeyInvalidFormat.
fn k_format(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let format = u8::try_from(stratum(i, 256)).unwrap_or(0);
    let long = digit(i, 256, 2) == 1;
    let q = point_for(&mut d, Some(false));
    let (x, y) = (x_of(&q), y_of(&q));
    let (key, label, intent) = if long {
        let key = with_format(format, &x, &y).to_vec();
        match format {
            0x04 => (key, "65/valid", Intent::AcceptValue(parsed(&q))),
            0x06 | 0x07 if (format == 0x07) == y_is_odd(&q) => {
                (key, "65/valid", Intent::AcceptValue(parsed(&q)))
            }
            0x06 | 0x07 => (
                key,
                "65/mismatched-oddness",
                Intent::RejectKind("ErrPubKeyMismatchedOddness"),
            ),
            _ => (
                key,
                "65/invalid-format",
                Intent::RejectKind("ErrPubKeyInvalidFormat"),
            ),
        }
    } else {
        let key = [&[format][..], &x].concat();
        match format {
            0x02 | 0x03 => {
                let point = with_parity(&q, format == 0x03);
                (key, "33/valid", Intent::AcceptValue(parsed(&point)))
            }
            _ => (
                key,
                "33/invalid-format",
                Intent::RejectKind("ErrPubKeyInvalidFormat"),
            ),
        }
    };
    d.finish(key_case(label, key, intent))
}

/// Length i in 0..=70: a valid compressed key at 33, a valid uncompressed
/// key at 65, random bytes (ErrPubKeyInvalidLen) at every other length.
fn k_length(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let len = usize::try_from(i).unwrap_or(0);
    let q = base_mul(&d.key());
    let case = match len {
        33 => key_case(
            "33",
            compressed(&q).to_vec(),
            Intent::AcceptValue(parsed(&q)),
        ),
        65 => key_case(
            "65",
            uncompressed(&q).to_vec(),
            Intent::AcceptValue(parsed(&q)),
        ),
        _ => key_case(
            "other",
            d.bytes(len),
            Intent::RejectKind("ErrPubKeyInvalidLen"),
        ),
    };
    d.finish(case)
}

/// K-valid.
pub const K_VALID: ClassSpec = ClassSpec {
    name: "K-valid",
    family: Family::Pubkey,
    commands: PARSERS,
    size: Size::Stratified {
        strata: 5,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: k_valid,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "a random point under the formats 02, 03, 04, 06 and 07 (i % 5), y of the parity the \
          format names",
};

/// K-hybridMismatch.
pub const K_HYBRID_MISMATCH: ClassSpec = ClassSpec {
    name: "K-hybridMismatch",
    family: Family::Pubkey,
    commands: PARSERS,
    size: Size::Stratified {
        strata: 2,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: k_hybrid_mismatch,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "a hybrid key with the byte of the other parity, on the curve or off it with y moved \
          by 2 (i % 2): the oddness is checked before the curve",
};

/// K-XTooBig.
pub const K_X_TOO_BIG: ClassSpec = ClassSpec {
    name: "K-XTooBig",
    family: Family::Pubkey,
    commands: PARSERS,
    size: Size::Stratified {
        strata: 40,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: k_x_too_big,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "x at P, P+1, 2^256-1 or random above P (i % 4) under each of the five formats \
          ((i / 4) % 5); the 65-byte forms take a random y, or ((i / 20) % 2) a y above P too, \
          which must not be checked before x",
};

/// K-YTooBig.
pub const K_Y_TOO_BIG: ClassSpec = ClassSpec {
    name: "K-YTooBig",
    family: Family::Pubkey,
    commands: PARSERS,
    size: Size::Stratified {
        strata: 12,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: k_y_too_big,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "a valid x with y at P, P+1, 2^256-1 or random above P (i % 4) under 04, 06 and 07 \
          ((i / 4) % 3)",
};

/// K-wrap.
pub const K_WRAP: ClassSpec = ClassSpec {
    name: "K-wrap",
    family: Family::Pubkey,
    commands: PARSERS,
    size: Size::Stratified {
        strata: 2,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: k_wrap,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "valid points with a coordinate encoded plus P (i % 2): x + P for an x below 2^256 - P \
          that decompresses, under the five formats, or y + P for one of 192 constant points \
          with a small y, under 04, 06 and 07",
};

/// K-nearP.
pub const K_NEAR_P: ClassSpec = ClassSpec {
    name: "K-nearP",
    family: Family::Pubkey,
    commands: PARSERS,
    size: Size::Stratified {
        strata: 5,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: k_near_p,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "valid points with x within 2^32 below P, under the five formats (i % 5)",
};

/// K-offCurve.
pub const K_OFF_CURVE: ClassSpec = ClassSpec {
    name: "K-offCurve",
    family: Family::Pubkey,
    commands: PARSERS,
    size: Size::Stratified {
        strata: 2,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: k_off_curve,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "points off the curve (i % 2): a valid point's y moved by 2 under 04, 06 and 07, or an \
          x with no y under 02 and 03",
};

/// K-negY.
pub const K_NEG_Y: ClassSpec = ClassSpec {
    name: "K-negY",
    family: Family::Pubkey,
    commands: PARSERS,
    size: Size::Stratified {
        strata: 3,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: k_neg_y,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "(x, P - y) for a valid (x, y), the point -Q, under 04, 06 and 07 (i % 3)",
};

/// K-mutate.
pub const K_MUTATE: ClassSpec = ClassSpec {
    name: "K-mutate",
    family: Family::Pubkey,
    commands: PARSERS,
    size: Size::Stratified {
        strata: 3,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: k_mutate,
    mix: &[],
    pr_cases: PR_CASES,
    doc: "a valid key with a random format byte, a byte xored, or a cut (i % 3)",
};

/// K-smallX.
pub const K_SMALL_X: ClassSpec = ClassSpec {
    name: "K-smallX",
    family: Family::Pubkey,
    commands: PARSERS,
    size: Size::Finite { size: 2_050 },
    tier: Tier::Finite,
    generator: k_small_x,
    mix: &[Mix::AcceptCount(976)],
    pr_cases: 64,
    doc: "every x in 0..=1024 (i / 2) under 02 and 03 (i % 2): 488 of the x decompress",
};

/// K-format.
pub const K_FORMAT: ClassSpec = ClassSpec {
    name: "K-format",
    family: Family::Pubkey,
    commands: PARSERS,
    size: Size::Finite { size: 512 },
    tier: Tier::Finite,
    generator: k_format,
    mix: &[Mix::AcceptCount(4)],
    pr_cases: 64,
    doc: "every format byte (i % 256) at length 33 and 65 (i / 256) on a valid point with an \
          even y: 02, 03, 04 and 06 parse, 07 has mismatched oddness",
};

/// K-length.
pub const K_LENGTH: ClassSpec = ClassSpec {
    name: "K-length",
    family: Family::Pubkey,
    commands: PARSERS,
    size: Size::Finite { size: 71 },
    tier: Tier::Finite,
    generator: k_length,
    mix: &[Mix::AcceptCount(2)],
    pr_cases: 71,
    doc: "every length 0..=70 (i): a valid key at 33 and 65, random bytes elsewhere",
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::class::generate;
    use std::collections::BTreeSet;

    /// Every K class.
    const CLASSES: [&ClassSpec; 12] = [
        &K_VALID,
        &K_HYBRID_MISMATCH,
        &K_X_TOO_BIG,
        &K_Y_TOO_BIG,
        &K_WRAP,
        &K_NEAR_P,
        &K_OFF_CURVE,
        &K_NEG_Y,
        &K_MUTATE,
        &K_SMALL_X,
        &K_FORMAT,
        &K_LENGTH,
    ];

    /// dcrd's `ParsePubKey` as a test model, on `k256`: its checks in its
    /// order (`pubkey.go`), answering the kind it returns or what
    /// `pubkey_parse` answers for the key.
    fn parse(key: &[u8]) -> Result<Vec<u8>, &'static str> {
        let (&format, rest) = key.split_first().ok_or("ErrPubKeyInvalidLen")?;
        match key.len() {
            65 => {
                if !matches!(format, 0x04 | 0x06 | 0x07) {
                    return Err("ErrPubKeyInvalidFormat");
                }
                let x: [u8; 32] = rest[..32].try_into().expect("x");
                let y: [u8; 32] = rest[32..].try_into().expect("y");
                if x >= P {
                    return Err("ErrPubKeyXTooBig");
                }
                if y >= P {
                    return Err("ErrPubKeyYTooBig");
                }
                if format != 0x04 && (y[31] & 1 == 1) != (format == 0x07) {
                    return Err("ErrPubKeyMismatchedOddness");
                }
                from_xy(&x, &y)
                    .map(|q| parsed(&q))
                    .ok_or("ErrPubKeyNotOnCurve")
            }
            33 => {
                if !matches!(format, 0x02 | 0x03) {
                    return Err("ErrPubKeyInvalidFormat");
                }
                let x: [u8; 32] = rest.try_into().expect("x");
                if x >= P {
                    return Err("ErrPubKeyXTooBig");
                }
                decompress(&x, format == 0x03)
                    .map(|q| parsed(&q))
                    .ok_or("ErrPubKeyNotOnCurve")
            }
            _ => Err("ErrPubKeyInvalidLen"),
        }
    }

    fn cases(class: &ClassSpec, n: u64) -> impl Iterator<Item = (u64, Case)> + '_ {
        (0..n).map(move |i| (i, generate(class, 0x006b_5eed, i)))
    }

    /// Every intent holds in the parse model, for both requests: 64 cases
    /// of each sampled class, every element of each finite one.
    #[test]
    fn every_intent_holds_in_the_model() {
        for class in CLASSES {
            let n = class.size.finite().unwrap_or(64);
            for (i, case) in cases(class, n) {
                assert!(!case.variant.starts_with("fallback"), "{} {i}", class.name);
                let key = &case.requests[0].data;
                assert_eq!(&case.requests[1].data, key);
                let got = parse(key);
                let ctx = format!("{} case {i} ({})", class.name, case.variant);
                match &case.intents[0] {
                    Intent::AcceptValue(want) => assert_eq!(got.as_ref(), Ok(want), "{ctx}"),
                    Intent::RejectKind(kind) => assert_eq!(got, Err(*kind), "{ctx}"),
                    Intent::Any => {}
                    other => panic!("{ctx}: {other:?}"),
                }
                assert_eq!(
                    case.intents[1],
                    schnorr_intent(key, &case.intents[0]),
                    "{ctx}"
                );
            }
        }
    }

    /// The finite classes' exact counts: 976 of K-smallX's keys parse, 4 of
    /// K-format's (1 with mismatched oddness, 507 of invalid format), 2 of
    /// K-length's.
    #[test]
    fn finite_classes_have_their_counts() {
        let count = |class: &ClassSpec, want: &Intent| {
            cases(class, class.size.finite().expect("finite"))
                .filter(|(_, c)| match (want, &c.intents[0]) {
                    (Intent::Accept, Intent::AcceptValue(_)) => true,
                    (Intent::RejectKind(a), Intent::RejectKind(b)) => a == b,
                    _ => false,
                })
                .count()
        };
        assert_eq!(count(&K_SMALL_X, &Intent::Accept), 976);
        assert_eq!(count(&K_FORMAT, &Intent::Accept), 4);
        assert_eq!(
            count(&K_FORMAT, &Intent::RejectKind("ErrPubKeyMismatchedOddness")),
            1
        );
        assert_eq!(
            count(&K_FORMAT, &Intent::RejectKind("ErrPubKeyInvalidFormat")),
            507
        );
        assert_eq!(count(&K_LENGTH, &Intent::Accept), 2);
        for (class, want) in [(&K_SMALL_X, 976), (&K_FORMAT, 4), (&K_LENGTH, 2)] {
            assert_eq!(class.mix, &[Mix::AcceptCount(want)], "{}", class.name);
        }
    }

    /// The x + P and y + P encodings reduce to valid points, so a parser
    /// that reduces mod P instead of rejecting would accept every K-wrap
    /// case.
    #[test]
    fn wrapped_keys_reduce_to_valid_points() {
        for (i, case) in cases(&K_WRAP, 64) {
            let key = &case.requests[0].data;
            let x: [u8; 32] = key[1..33].try_into().expect("x");
            let (x_reduced, borrow) = arith::sub_be(&x, &P);
            if case.variant.starts_with("x+P/") {
                assert!(!borrow, "case {i}: x at or above P");
                let format = key[0];
                let point = if key.len() == 33 {
                    decompress(&x_reduced, format == 0x03)
                } else {
                    let y: [u8; 32] = key[33..].try_into().expect("y");
                    from_xy(&x_reduced, &y)
                        .filter(|q| format == 0x04 || y_is_odd(q) == (format == 0x07))
                };
                assert!(point.is_some(), "case {i}: x - P is a valid key");
            } else {
                assert!(borrow, "case {i}: x below P");
                let y: [u8; 32] = key[33..].try_into().expect("y");
                let (y_reduced, borrow) = arith::sub_be(&y, &P);
                assert!(!borrow, "case {i}: y at or above P");
                let q = from_xy(&x, &y_reduced).expect("on the curve");
                assert!(
                    key[0] == 0x04 || y_is_odd(&q) == (key[0] == 0x07),
                    "case {i}"
                );
            }
        }
    }

    /// The Schnorr parser's intent: a rejection without a kind for every
    /// key that is not 33 bytes with a 02/03 format, `pubkey_parse`'s
    /// otherwise, an accepted key's value cut to its compressed form.
    #[test]
    fn schnorr_intents_follow_the_length_and_format() {
        let q = base_mul(&k256::Scalar::ONE);
        let accept = Intent::AcceptValue(parsed(&q));
        assert_eq!(
            schnorr_intent(&compressed(&q), &accept),
            Intent::AcceptValue(compressed(&q).to_vec())
        );
        let curve = Intent::RejectKind("ErrPubKeyNotOnCurve");
        assert_eq!(schnorr_intent(&compressed(&q), &curve), curve);
        assert_eq!(
            schnorr_intent(&uncompressed(&q), &accept),
            Intent::RejectPlain
        );
        let mut other = compressed(&q);
        other[0] = 0x04;
        assert_eq!(
            schnorr_intent(&other, &Intent::RejectKind("ErrPubKeyInvalidFormat")),
            Intent::RejectPlain
        );
        assert_eq!(
            schnorr_intent(&[0x02; 32], &Intent::RejectKind("ErrPubKeyInvalidLen")),
            Intent::RejectPlain
        );
    }

    /// Within its per-PR count K-XTooBig sends every 65-byte format under
    /// every x value with a y at or above P too, so a parser that checks y
    /// before x answers the wrong kind there.
    #[test]
    fn x_and_y_both_too_big_are_reached() {
        let both: BTreeSet<String> = cases(&K_X_TOO_BIG, K_X_TOO_BIG.pr_cases)
            .filter(|(_, c)| {
                let key = &c.requests[0].data;
                key.len() == 65 && key[1..33] >= P[..] && key[33..] >= P[..]
            })
            .map(|(_, c)| c.variant.into_owned())
            .collect();
        assert_eq!(both.len(), 12, "{both:?}");
        assert!(both.iter().all(|v| v.ends_with("/y-too-big")), "{both:?}");
    }

    #[test]
    fn per_pr_counts_cover_every_variant() {
        for class in CLASSES {
            if class.size.finite().is_some() {
                continue;
            }
            let seen = |n: u64| -> BTreeSet<String> {
                cases(class, n)
                    .map(|(_, c)| c.variant.into_owned())
                    .collect()
            };
            assert_eq!(
                seen(class.pr_cases),
                seen(class.pr_cases.saturating_mul(2)),
                "{}",
                class.name
            );
        }
    }
}
