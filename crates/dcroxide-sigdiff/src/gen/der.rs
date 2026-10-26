// SPDX-License-Identifier: ISC
//! DER signature parsing classes (DER-*).
//!
//! dcrd's `ParseDERSignature` (`ecdsa/signature.go`) checks, in order: the
//! length (8..=72), the sequence byte, the total length, that S's type and
//! length bytes are inside the signature, S's length, R's integer marker,
//! R's length, sign and padding, the same for S, then R's range and zero,
//! then S's.  DER-kind builds, for each of its 19 kinds, an input that
//! passes every earlier check and fails exactly that one.

use std::borrow::Cow;

use crate::arith::{self, N, TWO_256_MINUS_N};
use crate::class::{Case, ClassSpec, Family, Intent, Size, Tier};
use crate::cmd::{self, Cmd};
use crate::entropy::Entropy;
use crate::r#gen::{
    ALL_ACCEPTED, Draw, FLOOR_A, NONE_ACCEPTED, PR_CASES, der_int, der_minimal, der_sequence,
    digit, scalar_bytes, single, stratum,
};

/// The parse command.
const PARSE: &[Cmd] = &[Cmd::EcdsaParseDer];

/// A random r or s in `[1, N-1]`.
fn component(d: &mut Draw) -> [u8; 32] {
    scalar_bytes(&d.key())
}

fn der_valid(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let high = stratum(i, 2) == 1;
    let r = component(&mut d);
    let mut s = component(&mut d);
    if (s > arith::HALF_N) != high {
        s = arith::neg_mod_n(&s);
    }
    let value = [r, s].concat();
    d.finish(single(
        if high { "high-s" } else { "low-s" },
        cmd::ecdsa_parse_der(&der_minimal(&r, &s)),
        Intent::AcceptValue(value),
    ))
}

/// DER-mutate's edits.
const MUTATIONS: [&str; 3] = ["truncate", "flip", "append"];

fn der_mutate(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let edit = stratum(i, 3);
    let r = component(&mut d);
    let s = component(&mut d);
    let mut der = der_minimal(&r, &s);
    // The edits of crates/dcroxide-dcrec/tests/oracle_differential.rs: a
    // cut anywhere (the whole kept included), one byte xored with a random
    // byte, or one random byte appended.
    match edit {
        0 => {
            let cut = d.len_in(0, der.len());
            der.truncate(cut);
        }
        1 => {
            let at = d.len_in(0, der.len().saturating_sub(1));
            let x = d.byte();
            der[at] ^= x;
        }
        _ => {
            let x = d.byte();
            der.push(x);
        }
    }
    d.finish(single(
        MUTATIONS[edit],
        cmd::ecdsa_parse_der(&der),
        Intent::Any,
    ))
}

/// A byte that is usually `want` and one time in `odds` random.
fn mostly(d: &mut Draw, odds: u64, want: u8) -> u8 {
    if d.below(odds) == 0 { d.byte() } else { want }
}

/// An integer body of `len` bytes biased toward 0x00 and 0xff, to reach
/// the padding and sign checks.
fn biased(d: &mut Draw, len: usize) -> Vec<u8> {
    (0..len)
        .map(|_| match d.below(4) {
            0 => 0x00,
            1 => 0xff,
            _ => d.byte(),
        })
        .collect()
}

fn der_structured(e: &mut dyn Entropy, _: u64) -> Case {
    let mut d = Draw::new(e);
    // The structured generator of crates/dcroxide-dcrec/tests/
    // oracle_differential.rs: plausible markers with random lengths and
    // integer bodies, each marker and length occasionally wrong.
    let r_len = d.len_in(0, 35);
    let s_len = d.len_in(0, 35);
    let total = r_len.saturating_add(s_len).saturating_add(4);
    let total_byte = u8::try_from(total).unwrap_or(u8::MAX);
    let mut der = vec![
        mostly(&mut d, 20, 0x30),
        mostly(&mut d, 10, total_byte),
        mostly(&mut d, 20, 0x02),
        mostly(&mut d, 10, u8::try_from(r_len).unwrap_or(u8::MAX)),
    ];
    der.extend(biased(&mut d, r_len));
    der.push(mostly(&mut d, 20, 0x02));
    der.push(mostly(&mut d, 10, u8::try_from(s_len).unwrap_or(u8::MAX)));
    der.extend(biased(&mut d, s_len));
    d.finish(single(
        "structured",
        cmd::ecdsa_parse_der(&der),
        Intent::Any,
    ))
}

/// DER-kind's kinds, in the order dcrd checks them.
pub const DER_KINDS: [&str; 19] = [
    "ErrSigTooShort",
    "ErrSigTooLong",
    "ErrSigInvalidSeqID",
    "ErrSigInvalidDataLen",
    "ErrSigMissingSTypeID",
    "ErrSigMissingSLen",
    "ErrSigInvalidSLen",
    "ErrSigInvalidRIntID",
    "ErrSigZeroRLen",
    "ErrSigNegativeR",
    "ErrSigTooMuchRPadding",
    "ErrSigInvalidSIntID",
    "ErrSigZeroSLen",
    "ErrSigNegativeS",
    "ErrSigTooMuchSPadding",
    "ErrSigRTooBig",
    "ErrSigRIsZero",
    "ErrSigSTooBig",
    "ErrSigSIsZero",
];

/// An integer body that is negative: 1..=33 bytes, the first with its top
/// bit set.
fn negative(d: &mut Draw) -> Vec<u8> {
    let len = d.len_in(1, 33);
    let mut v = d.bytes(len);
    v[0] |= 0x80;
    v
}

/// An integer body with too much padding: a zero byte, then a byte below
/// 0x80, then random bytes, 2..=33 in all.
fn padded(d: &mut Draw) -> Vec<u8> {
    let len = d.len_in(2, 33);
    let mut v = d.bytes(len);
    v[0] = 0x00;
    v[1] &= 0x7f;
    v
}

/// The labels of the values [`too_big`] encodes.
const TOO_BIG: [&str; 4] = ["N", "max", "random", "33-bytes"];

/// A well-formed integer body of a value at or above N, value `k`: the
/// minimal encoding of N itself, of 2^256 − 1 or of a value uniform in
/// [N, 2^256), or 33 significant bytes.
fn too_big(d: &mut Draw, k: usize) -> Vec<u8> {
    match k {
        0 => der_int(&N),
        1 => der_int(&[0xff; 32]),
        2 => der_int(&arith::add_be(&N, &d.uniform_below(&TWO_256_MINUS_N)).0),
        _ => {
            let mut v = d.bytes(33);
            v[0] = (v[0] & 0x7f).max(1);
            v
        }
    }
}

/// The input of DER-kind for kind `kind`, built to pass every check dcrd
/// makes before that kind's; `big` picks the value of the two too-big
/// kinds ([`TOO_BIG`]).
fn kind_input(d: &mut Draw, kind: usize, big: usize) -> Vec<u8> {
    let r = der_int(&component(d));
    let s = der_int(&component(d));
    let base = der_sequence(&r, &s);
    // Offsets in the base: 0 sequence, 1 length, 2 R marker, 3 R length,
    // 4 R, then S's marker and length.
    let s_marker = r.len().saturating_add(4);
    match kind {
        0 => {
            let len = d.len_in(0, 7);
            d.bytes(len)
        }
        1 => {
            let len = d.len_in(73, 100);
            d.bytes(len)
        }
        2 => {
            let mut v = base;
            v[0] ^= d.nonzero_byte();
            v
        }
        3 => {
            let mut v = base;
            v[1] ^= d.nonzero_byte();
            v
        }
        4 => {
            // 30 L 02 rl R, with R running to the end: S's marker would
            // sit past it.
            let total = d.len_in(8, 72);
            let rl = total.saturating_sub(4);
            let mut v = vec![0x30, byte(total.saturating_sub(2)), 0x02, byte(rl)];
            v.extend(d.bytes(rl));
            v
        }
        5 => {
            // 30 L 02 rl R 02, S's marker the last byte.
            let total = d.len_in(8, 72);
            let rl = total.saturating_sub(5);
            let mut v = vec![0x30, byte(total.saturating_sub(2)), 0x02, byte(rl)];
            v.extend(d.bytes(rl));
            v.push(0x02);
            v
        }
        6 => {
            let mut v = base;
            let at = s_marker.saturating_add(1);
            v[at] ^= d.nonzero_byte();
            v
        }
        7 => {
            let mut v = base;
            v[2] ^= d.nonzero_byte();
            v
        }
        8 => {
            // A zero-length R; S two or more bytes so the whole is at
            // least 8.
            let len = d.len_in(2, 33);
            der_sequence(&[], &d.bytes(len))
        }
        9 => der_sequence(&negative(d), &s),
        10 => der_sequence(&padded(d), &s),
        11 => {
            let mut v = base;
            v[s_marker] ^= d.nonzero_byte();
            v
        }
        12 => der_sequence(&r, &[]),
        13 => der_sequence(&r, &negative(d)),
        14 => der_sequence(&r, &padded(d)),
        15 => der_sequence(&too_big(d, big), &s),
        16 => der_sequence(&[0x00], &s),
        17 => der_sequence(&r, &too_big(d, big)),
        _ => der_sequence(&r, &[0x00]),
    }
}

fn byte(n: usize) -> u8 {
    u8::try_from(n).expect("a DER length below 256")
}

fn der_kind(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let kind = stratum(i, 19);
    let big = digit(i, 19, 4);
    let der = kind_input(&mut d, kind, big);
    let name = DER_KINDS[kind];
    let short = name.strip_prefix("ErrSig").unwrap_or(name);
    let variant = match name {
        "ErrSigRTooBig" | "ErrSigSTooBig" => Cow::Owned(format!("{short}/{}", TOO_BIG[big])),
        _ => Cow::Borrowed(short),
    };
    d.finish(single(
        variant,
        cmd::ecdsa_parse_der(&der),
        Intent::RejectKind(name),
    ))
}

/// DER-valid.
pub const DER_VALID: ClassSpec = ClassSpec {
    name: "DER-valid",
    family: Family::Der,
    commands: PARSE,
    size: Size::Stratified {
        strata: 2,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: der_valid,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "minimal DER of random r and s in [1, N-1], s in its low or high half (i % 2); the \
          parsed r and s must be the encoded ones",
};

/// DER-mutate.
pub const DER_MUTATE: ClassSpec = ClassSpec {
    name: "DER-mutate",
    family: Family::Der,
    commands: PARSE,
    size: Size::Stratified {
        strata: 3,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: der_mutate,
    mix: &[],
    pr_cases: PR_CASES,
    doc: "a valid encoding truncated, with a byte xored, or with a byte appended (i % 3)",
};

/// DER-structured.
pub const DER_STRUCTURED: ClassSpec = ClassSpec {
    name: "DER-structured",
    family: Family::Der,
    commands: PARSE,
    size: Size::Sampled { floor: FLOOR_A },
    tier: Tier::A,
    generator: der_structured,
    mix: &[],
    pr_cases: PR_CASES,
    doc: "plausible DER markers and lengths, each occasionally wrong, around integer bodies \
          biased toward 0x00 and 0xff",
};

/// DER-kind.
pub const DER_KIND: ClassSpec = ClassSpec {
    name: "DER-kind",
    family: Family::Der,
    commands: PARSE,
    size: Size::Stratified {
        strata: 19,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: der_kind,
    mix: NONE_ACCEPTED,
    pr_cases: 76,
    doc: "for each of dcrd's 19 DER parse kinds (i % 19), an input that passes every earlier \
          check and fails that one; the two too-big kinds encode N, 2^256-1, a random value \
          above N or 33 significant bytes ((i / 19) % 4)",
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::class::generate;
    use std::collections::BTreeSet;

    /// dcrd's `ParseDERSignature` as a test model: its checks in its order
    /// (`ecdsa/signature.go`), answering the kind it returns or the parsed
    /// r ‖ s.  It shows, without the oracle, that each DER-kind recipe
    /// reaches its kind.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "offsets of a signature of at most 72 bytes, each bounded by the checks before it"
    )]
    fn parse(sig: &[u8]) -> Result<Vec<u8>, &'static str> {
        let len = sig.len();
        if len < 8 {
            return Err("ErrSigTooShort");
        }
        if len > 72 {
            return Err("ErrSigTooLong");
        }
        if sig[0] != 0x30 {
            return Err("ErrSigInvalidSeqID");
        }
        if usize::from(sig[1]) != len - 2 {
            return Err("ErrSigInvalidDataLen");
        }
        let r_len = usize::from(sig[3]);
        let s_type = 4 + r_len;
        if s_type >= len {
            return Err("ErrSigMissingSTypeID");
        }
        if s_type + 1 >= len {
            return Err("ErrSigMissingSLen");
        }
        let s_off = s_type + 2;
        let s_len = usize::from(sig[s_type + 1]);
        if s_off + s_len != len {
            return Err("ErrSigInvalidSLen");
        }
        if sig[2] != 0x02 {
            return Err("ErrSigInvalidRIntID");
        }
        if r_len == 0 {
            return Err("ErrSigZeroRLen");
        }
        if sig[4] & 0x80 != 0 {
            return Err("ErrSigNegativeR");
        }
        if r_len > 1 && sig[4] == 0 && sig[5] & 0x80 == 0 {
            return Err("ErrSigTooMuchRPadding");
        }
        if sig[s_type] != 0x02 {
            return Err("ErrSigInvalidSIntID");
        }
        if s_len == 0 {
            return Err("ErrSigZeroSLen");
        }
        if sig[s_off] & 0x80 != 0 {
            return Err("ErrSigNegativeS");
        }
        if s_len > 1 && sig[s_off] == 0 && sig[s_off + 1] & 0x80 == 0 {
            return Err("ErrSigTooMuchSPadding");
        }
        let scalar = |body: &[u8], too_big, zero| -> Result<[u8; 32], &'static str> {
            let first = body.iter().position(|&b| b != 0).unwrap_or(body.len());
            let digits = &body[first..];
            if digits.len() > 32 {
                return Err(too_big);
            }
            let mut v = [0u8; 32];
            v[32 - digits.len()..].copy_from_slice(digits);
            if v >= N {
                return Err(too_big);
            }
            if v == [0; 32] {
                return Err(zero);
            }
            Ok(v)
        };
        let r = scalar(&sig[4..s_type], "ErrSigRTooBig", "ErrSigRIsZero")?;
        let s = scalar(&sig[s_off..], "ErrSigSTooBig", "ErrSigSIsZero")?;
        Ok([r, s].concat())
    }

    fn cases(class: &ClassSpec, n: u64) -> impl Iterator<Item = (u64, crate::class::Case)> + '_ {
        (0..n).map(move |i| (i, generate(class, 0xde5_eed, i)))
    }

    #[test]
    fn every_kind_recipe_reaches_its_kind() {
        let mut reached = BTreeSet::new();
        for (i, case) in cases(&DER_KIND, 19 * 16) {
            let Intent::RejectKind(want) = case.intents[0] else {
                panic!("case {i}: {:?}", case.intents[0]);
            };
            assert_eq!(parse(&case.requests[0].data), Err(want), "case {i}");
            reached.insert(want);
        }
        assert_eq!(reached.len(), 19);
        // The two too-big kinds reach the boundary itself, R or S exactly N,
        // within the per-PR count.
        let at_n = der_int(&N);
        let mut boundary = BTreeSet::new();
        for (i, case) in cases(&DER_KIND, DER_KIND.pr_cases) {
            let der = &case.requests[0].data;
            match case.variant.as_ref() {
                "RTooBig/N" => assert_eq!(der.get(4..37), Some(at_n.as_slice()), "case {i}"),
                "STooBig/N" => assert!(der.ends_with(&at_n), "case {i}"),
                _ => continue,
            }
            boundary.insert(case.variant.into_owned());
        }
        assert_eq!(boundary.len(), 2, "{boundary:?}");
        // Every length stays within 8..=72 but the two length kinds'.
        for (i, case) in cases(&DER_KIND, 19 * 16) {
            let len = case.requests[0].data.len();
            match case.intents[0] {
                Intent::RejectKind("ErrSigTooShort") => assert!(len < 8, "case {i}"),
                Intent::RejectKind("ErrSigTooLong") => {
                    assert!((73..=100).contains(&len), "case {i}")
                }
                _ => assert!((8..=72).contains(&len), "case {i}: {len} bytes"),
            }
        }
    }

    #[test]
    fn valid_encodings_parse_to_their_values() {
        for (i, case) in cases(&DER_VALID, 32) {
            let Intent::AcceptValue(want) = &case.intents[0] else {
                panic!("case {i}");
            };
            assert_eq!(parse(&case.requests[0].data).as_ref(), Ok(want), "case {i}");
            let s: [u8; 32] = want[32..].try_into().expect("s");
            assert_eq!(s > arith::HALF_N, case.variant == "high-s", "case {i}");
        }
        // The edits and the structured generator reach a spread of kinds.
        let mut kinds = BTreeSet::new();
        for class in [&DER_MUTATE, &DER_STRUCTURED] {
            for (_, case) in cases(class, 2_000) {
                kinds.insert(parse(&case.requests[0].data).err().unwrap_or("ok"));
            }
        }
        assert!(kinds.len() >= 12, "{kinds:?}");
    }

    #[test]
    fn per_pr_counts_cover_every_variant() {
        for class in [&DER_VALID, &DER_MUTATE, &DER_STRUCTURED, &DER_KIND] {
            let seen = |n: u64| -> BTreeSet<String> {
                cases(class, n)
                    .map(|(_, c)| c.variant.into_owned())
                    .collect()
            };
            assert_eq!(
                seen(class.pr_cases),
                seen(class.pr_cases * 2),
                "{}",
                class.name
            );
        }
        assert_eq!(DER_KIND.pr_cases, 4 * 19, "four per kind");
    }
}
