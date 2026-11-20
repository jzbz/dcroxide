// SPDX-License-Identifier: ISC
//! `dcroxide-bench base58`: a micro benchmark of dcroxide-base58's four
//! functions against decred/base58's, the package dcrd and dcrwallet link,
//! through the oracle.
//!
//! **The strings.** Three shapes, drawn from `--seed` with SplitMix64:
//! a mainnet pay-to-pubkey-hash address (`Ds`, version `07 3f` and a
//! 20-byte hash, 35 characters), an extended public key as dcrd's
//! hdkeychain writes it (`dpub`, the 4-byte version `02 fd a9 26`, depth,
//! parent fingerprint, child number, chain code and a compressed public
//! key, then the double BLAKE-256 checksum: 111 characters), and a
//! 1,000-character string, a check-encoded 726-byte payload drawn again
//! until it encodes to exactly 1,000 characters.  An extended key is not
//! a base58check string in decred/base58's sense, whose version is two
//! bytes, but its checksum is the same function of the same bytes, so
//! `check_decode` accepts it, taking the first two version bytes as the
//! version and the rest as the payload; hdkeychain's own parse does the
//! same work.  Every string is valid: the error paths are the batch
//! differential's (`crates/dcroxide-base58/tests/oracle_differential.rs`),
//! not this program's.
//!
//! **What is timed.** For each shape, `decode` and `check_decode` of each
//! string, `encode` of each string's decoding and `check_encode` of each
//! string's payload and version, the inputs made untimed on both sides.
//! The outputs are serialized untimed, as `tools/oracle/base58bench.go`
//! serializes Go's, and both sides fold the serialization into a 64-bit
//! FNV-1a digest; the run stops unless the two agree, so every timed pass
//! is also a differential over every string.  The order of passes, the
//! warm-up and the alternation of the side going first are `dcrec`'s
//! (the `dcrec` module).

use std::fmt::Write as _;
use std::hint::black_box;
use std::io::Write as _;
use std::time::Instant;

use dcroxide_base58::{CheckError, check_decode, check_encode, decode, encode};
use dcroxide_testutil::{Oracle, SplitMix64};

use crate::dcrec::{
    Pass, allowed_cpus, fnv1a64, load_average, oracle_path, per_op, rust_first, since,
};
use crate::{Args, median};

/// The seed `--seed` defaults to, so that runs without it time the same
/// strings.
const DEFAULT_SEED: u64 = 0x6261_7365_3538_6265;

/// One string shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Shape {
    /// A mainnet pay-to-pubkey-hash address, 35 characters.
    Address,
    /// An extended public key, 111 characters.
    Xpub,
    /// A 1,000-character check-encoded string.
    Long,
}

impl Shape {
    /// Every shape, in the order a round runs them.
    pub(crate) const ALL: [Shape; 3] = [Shape::Address, Shape::Xpub, Shape::Long];

    /// The name the output uses.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Shape::Address => "address",
            Shape::Xpub => "xpub",
            Shape::Long => "long",
        }
    }

    /// The length in characters of every string of the shape.
    pub(crate) fn chars(self) -> usize {
        match self {
            Shape::Address => 35,
            Shape::Xpub => 111,
            Shape::Long => 1000,
        }
    }

    /// The number of strings a pass takes when `--cases` is `cases`: the
    /// long strings cost about thirty times an address to decode, so they
    /// get a sixteenth as many.
    pub(crate) fn count(self, cases: usize) -> usize {
        match self {
            Shape::Address | Shape::Xpub => cases,
            Shape::Long => (cases / 16).max(1),
        }
    }

    /// One string of the shape.
    pub(crate) fn draw(self, rng: &mut SplitMix64) -> String {
        match self {
            Shape::Address => {
                let mut hash = [0u8; 20];
                rng.fill(&mut hash);
                check_encode(&hash, [0x07, 0x3f])
            }
            Shape::Xpub => {
                // The last two version bytes, depth, parent fingerprint,
                // child number, chain code, then a compressed public key.
                let mut payload = [0u8; 76];
                rng.fill(&mut payload);
                payload[0] = 0xa9;
                payload[1] = 0x26;
                payload[43] = 0x02 | (payload[43] & 1);
                check_encode(&payload, [0x02, 0xfd])
            }
            Shape::Long => loop {
                let mut payload = [0u8; 728];
                rng.fill(&mut payload);
                let s = check_encode(&payload[2..], [payload[0], payload[1]]);
                if s.len() == 1000 {
                    return s;
                }
            },
        }
    }
}

/// `count` strings of `shape` drawn from `seed`.
pub(crate) fn draw_strings(shape: Shape, seed: u64, count: usize) -> Vec<String> {
    let mut rng = SplitMix64(SplitMix64::derive(seed, shape.name(), 0));
    (0..count).map(|_| shape.draw(&mut rng)).collect()
}

/// The strings as the oracle's `base58_bench` takes them: each its length
/// as four big-endian bytes, then its bytes.
pub(crate) fn encode_strings(strings: &[String]) -> Vec<u8> {
    let total = strings
        .iter()
        .fold(0usize, |n, s| n.saturating_add(s.len()).saturating_add(4));
    let mut out = Vec::with_capacity(total);
    for s in strings {
        push_len_prefixed(&mut out, s.as_bytes());
    }
    out
}

/// Append `b`'s length as four big-endian bytes, then `b`.
fn push_len_prefixed(out: &mut Vec<u8>, b: &[u8]) {
    let len = u32::try_from(b.len()).expect("a benchmark output is far below 4 GiB");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(b);
}

/// A `check_decode` result serialized as `base58bench.go` serializes Go's:
/// 0, the version and the length-prefixed payload for a decoded string, 1
/// for a checksum error and 2 for an invalid format.
pub(crate) fn push_check_decoded(out: &mut Vec<u8>, r: &Result<(Vec<u8>, [u8; 2]), CheckError>) {
    match r {
        Ok((payload, version)) => {
            out.push(0);
            out.extend_from_slice(version);
            push_len_prefixed(out, payload);
        }
        Err(CheckError::Checksum) => out.push(1),
        Err(CheckError::InvalidFormat) => out.push(2),
    }
}

/// One operation.
pub(crate) struct Op {
    /// The name `--ops`, the output and the oracle use.
    pub(crate) name: &'static str,
    /// The timed pass.
    pub(crate) run: fn(&[String]) -> Pass,
}

/// `decode` of every string.
fn run_decode(strings: &[String]) -> Pass {
    let mut outs = Vec::with_capacity(strings.len());
    let start = Instant::now();
    for s in strings {
        outs.push(decode(black_box(s)));
    }
    let ns = since(start);
    let mut out = Vec::new();
    for o in &outs {
        push_len_prefixed(&mut out, o);
    }
    Pass { ns, out }
}

/// `check_decode` of every string.
fn run_check_decode(strings: &[String]) -> Pass {
    let mut outs = Vec::with_capacity(strings.len());
    let start = Instant::now();
    for s in strings {
        outs.push(check_decode(black_box(s)));
    }
    let ns = since(start);
    let mut out = Vec::new();
    for o in &outs {
        push_check_decoded(&mut out, o);
    }
    Pass { ns, out }
}

/// `encode` of every string's decoding, decoded untimed.
fn run_encode(strings: &[String]) -> Pass {
    let inputs: Vec<Vec<u8>> = strings.iter().map(|s| decode(s)).collect();
    let mut outs = Vec::with_capacity(inputs.len());
    let start = Instant::now();
    for input in &inputs {
        outs.push(encode(black_box(input)));
    }
    let ns = since(start);
    let mut out = Vec::new();
    for o in &outs {
        push_len_prefixed(&mut out, o.as_bytes());
    }
    Pass { ns, out }
}

/// `check_encode` of every string's payload and version, decoded untimed.
fn run_check_encode(strings: &[String]) -> Pass {
    let inputs: Vec<(Vec<u8>, [u8; 2])> = strings
        .iter()
        .map(|s| check_decode(s).expect("every benchmark string is check-encoded"))
        .collect();
    let mut outs = Vec::with_capacity(inputs.len());
    let start = Instant::now();
    for (payload, version) in &inputs {
        outs.push(check_encode(black_box(payload), *black_box(version)));
    }
    let ns = since(start);
    let mut out = Vec::new();
    for o in &outs {
        push_len_prefixed(&mut out, o.as_bytes());
    }
    Pass { ns, out }
}

/// Every operation, in the order a round runs them for each shape.
pub(crate) const OPS: &[Op] = &[
    Op {
        name: "decode",
        run: run_decode,
    },
    Op {
        name: "check_decode",
        run: run_check_decode,
    },
    Op {
        name: "encode",
        run: run_encode,
    },
    Op {
        name: "check_encode",
        run: run_check_encode,
    },
];

/// Go's pass of `op` over the encoded strings, through the oracle: the
/// nanoseconds and the digest it reports.
pub(crate) fn go_pass(
    oracle: &mut Oracle,
    op: &str,
    encoded: &[u8],
    count: usize,
) -> Result<(u64, u64), String> {
    let name = u8::try_from(op.len()).map_err(|_| format!("op name {op} is too long"))?;
    let mut data = Vec::with_capacity(encoded.len().saturating_add(op.len()).saturating_add(1));
    data.push(name);
    data.extend_from_slice(op.as_bytes());
    data.extend_from_slice(encoded);
    let resp = oracle.call("base58_bench", &data);
    if let Some(err) = resp.get("error").and_then(|e| e.as_str()) {
        return Err(format!("oracle base58_bench {op}: {err}"));
    }
    let ns = resp["detail"]["ns"]
        .as_u64()
        .ok_or_else(|| format!("oracle base58_bench {op}: no ns in {resp}"))?;
    let cases = resp["detail"]["cases"]
        .as_u64()
        .ok_or_else(|| format!("oracle base58_bench {op}: no case count in {resp}"))?;
    if usize::try_from(cases).ok() != Some(count) {
        return Err(format!(
            "oracle base58_bench {op}: {cases} cases, {count} sent"
        ));
    }
    let digest = resp["detail"]["digest"]
        .as_str()
        .and_then(|d| u64::from_str_radix(d, 16).ok())
        .ok_or_else(|| format!("oracle base58_bench {op}: no digest in {resp}"))?;
    Ok((ns, digest))
}

/// One row of the benchmark: a shape, an operation, and the index of the
/// shape's strings.
struct Row {
    shape: Shape,
    op: &'static Op,
    data: usize,
}

/// Run the benchmark.
#[allow(
    clippy::too_many_lines,
    reason = "one linear procedure: set up, warm up, the rounds, the summary"
)]
pub(crate) fn cmd_base58(args: &Args) -> Result<(), String> {
    let cases: usize = match args.get("cases") {
        Some(v) => v.parse().map_err(|e| format!("bad --cases: {e}"))?,
        None => 16384,
    };
    if cases == 0 {
        return Err("--cases must be at least 1".to_string());
    }
    let rounds: usize = match args.get("rounds") {
        Some(v) => v.parse().map_err(|e| format!("bad --rounds: {e}"))?,
        None => 5,
    };
    let seed = match args.get("seed") {
        Some(v) => dcroxide_testutil::parse_seed(v).ok_or_else(|| format!("bad --seed {v}"))?,
        None => DEFAULT_SEED,
    };
    let start_go = match args.get("start").unwrap_or("rust") {
        "rust" => false,
        "go" => true,
        other => return Err(format!("--start must be rust or go (got {other})")),
    };
    let ops: Vec<&'static Op> = match args.get("ops") {
        None => OPS.iter().collect(),
        Some(list) => list
            .split(',')
            .map(|name| {
                OPS.iter()
                    .find(|op| op.name == name)
                    .ok_or_else(|| format!("unknown op {name}"))
            })
            .collect::<Result<_, _>>()?,
    };
    let shapes: Vec<Shape> = match args.get("shapes") {
        None => Shape::ALL.to_vec(),
        Some(list) => list
            .split(',')
            .map(|name| {
                Shape::ALL
                    .into_iter()
                    .find(|s| s.name() == name)
                    .ok_or_else(|| format!("unknown shape {name}"))
            })
            .collect::<Result<_, _>>()?,
    };
    let mut out_file = match args.get("out") {
        Some(path) => {
            Some(std::fs::File::create(path).map_err(|e| format!("unable to create {path}: {e}"))?)
        }
        None => None,
    };
    let mut oracle = oracle_path(args).map(|p| Oracle::spawn_at(&p));

    println!(
        "base58 bench: {cases} cases ({} long), seed {seed:#018x}, {rounds} rounds, start {}, \
         cpus {}, load {}",
        Shape::Long.count(cases),
        if start_go { "go" } else { "rust" },
        allowed_cpus(),
        load_average()
    );
    if let Some(oracle) = oracle.as_mut() {
        let info = oracle.call("build_info", &[]);
        println!(
            "go: {} (decred/base58 and crypto/blake256 as tools/oracle/go.mod requires them)",
            info["go_version"].as_str().unwrap_or("unknown"),
        );
    } else {
        println!("go: no oracle (--oracle or DCROXIDE_ORACLE_BIN), Rust side only");
    }

    // Per shape: its strings, and the same encoded for the oracle.
    let mut data: Vec<(Vec<String>, Vec<u8>)> = Vec::with_capacity(shapes.len());
    let mut rows = Vec::with_capacity(shapes.len().saturating_mul(ops.len()));
    for &shape in &shapes {
        let strings = draw_strings(shape, seed, shape.count(cases));
        if let Some(bad) = strings.iter().find(|s| s.len() != shape.chars()) {
            return Err(format!(
                "{} string {bad} is {} characters, not {}",
                shape.name(),
                bad.len(),
                shape.chars()
            ));
        }
        let encoded = encode_strings(&strings);
        for &op in &ops {
            rows.push(Row {
                shape,
                op,
                data: data.len(),
            });
        }
        data.push((strings, encoded));
    }

    // Per row: Rust's and Go's nanoseconds per operation, one a round.
    let mut timings: Vec<(Vec<f64>, Vec<f64>)> = vec![(Vec::new(), Vec::new()); rows.len()];
    // Round 0 is the warm-up, kept out of the summary.
    for round in 0..=rounds {
        for (i, row) in rows.iter().enumerate() {
            let (strings, encoded) = &data[row.data];
            let count = strings.len();
            let mut rust = None;
            let mut go = None;
            let order = if rust_first(round, i, start_go) {
                [true, false]
            } else {
                [false, true]
            };
            for is_rust in order {
                if is_rust {
                    let pass = (row.op.run)(strings);
                    rust = Some((pass.ns, fnv1a64(&pass.out)));
                } else if let Some(oracle) = oracle.as_mut() {
                    go = Some(go_pass(oracle, row.op.name, encoded, count)?);
                }
            }
            let (rust_ns, rust_digest) = rust.expect("the Rust side always runs");
            if let Some((_, go_digest)) = go
                && go_digest != rust_digest
            {
                return Err(format!(
                    "{} {}: dcroxide-base58's digest {rust_digest:016x} is not decred/base58's \
                     {go_digest:016x} (round {round})",
                    row.shape.name(),
                    row.op.name,
                ));
            }
            let mut line = format!(
                "{{\"round\":{round},\"warmup\":{},\"shape\":\"{}\",\"op\":\"{}\",\
                 \"cases\":{count},\"rust_first\":{},\"rust_ns\":{rust_ns},\
                 \"digest\":\"{rust_digest:016x}\"",
                round == 0,
                row.shape.name(),
                row.op.name,
                order[0]
            );
            if let Some((go_ns, _)) = go {
                let _ = write!(line, ",\"go_ns\":{go_ns}");
            }
            line.push('}');
            if let Some(f) = out_file.as_mut() {
                writeln!(f, "{line}").map_err(|e| format!("write --out: {e}"))?;
            }
            if round > 0 {
                timings[i].0.push(per_op(rust_ns, count));
                if let Some((go_ns, _)) = go {
                    timings[i].1.push(per_op(go_ns, count));
                }
            }
        }
        if round > 0 {
            eprintln!("base58 bench: round {round} of {rounds} done");
        }
    }

    println!(
        "{:<22} {:>12} {:>12} {:>12} {:>12} {:>9}",
        "op (ns/op)", "rust median", "rust least", "go median", "go least", "rust/go"
    );
    for (row, (rust, go)) in rows.iter().zip(timings.iter_mut()) {
        let rust_least = rust.iter().copied().fold(f64::INFINITY, f64::min);
        let rust_median = median(rust);
        let (go_median, go_least, ratio) = if go.is_empty() {
            ("-".to_string(), "-".to_string(), "-".to_string())
        } else {
            let least = go.iter().copied().fold(f64::INFINITY, f64::min);
            let med = median(go);
            (
                format!("{med:.1}"),
                format!("{least:.1}"),
                format!("{:.3}", rust_median / med),
            )
        };
        println!(
            "{:<22} {rust_median:>12.1} {rust_least:>12.1} {go_median:>12} {go_least:>12} {ratio:>9}",
            format!("{}/{}", row.op.name, row.shape.name())
        );
    }
    if oracle.is_some() {
        println!(
            "every pass of every row gave the same digest on both sides ({rounds} rounds and the \
             warm-up)"
        );
    }
    println!("load after: {}", load_average());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcroxide_testutil::oracle_or_skip;

    /// The strings are a function of the seed and the shape, have the
    /// shape's length and check-decode, and the extended keys read as
    /// `dpub`.
    #[test]
    fn strings_are_deterministic_and_well_formed() {
        for shape in Shape::ALL {
            let a = draw_strings(shape, 7, 40);
            assert_eq!(a, draw_strings(shape, 7, 40));
            assert_ne!(a, draw_strings(shape, 8, 40));
            for s in &a {
                assert_eq!(s.len(), shape.chars(), "{s}");
                let (payload, _) = check_decode(s).expect("check-encoded");
                if shape == Shape::Xpub {
                    assert!(s.starts_with("dpub"), "{s}");
                    assert_eq!(payload.len(), 76);
                }
                if shape == Shape::Address {
                    assert!(s.starts_with("Ds"), "{s}");
                }
            }
        }
        let encoded = encode_strings(&["ab".to_string(), String::new()]);
        assert_eq!(encoded, [0, 0, 0, 2, b'a', b'b', 0, 0, 0, 0]);
        assert_eq!(Shape::Long.count(100), 6);
        assert_eq!(Shape::Long.count(3), 1);
    }

    /// Every operation's outputs equal decred/base58's over the same
    /// strings, through the oracle's `base58_bench`: the check every
    /// benchmark pass makes.
    #[test]
    fn every_operation_matches_go() {
        let Some(mut oracle) = oracle_or_skip() else {
            return;
        };
        let mut rng = SplitMix64::from_entropy("base58 bench strings");
        let seed = rng.next_u64();
        for shape in Shape::ALL {
            let strings = draw_strings(shape, seed, 24);
            let encoded = encode_strings(&strings);
            for op in OPS {
                let pass = (op.run)(&strings);
                let (_, go_digest) =
                    go_pass(&mut oracle, op.name, &encoded, strings.len()).expect("oracle answers");
                assert_eq!(
                    fnv1a64(&pass.out),
                    go_digest,
                    "{} {} against decred/base58's",
                    shape.name(),
                    op.name
                );
            }
        }
        // The oracle refuses what it should, and the client reports it.
        let err = go_pass(&mut oracle, "nope", &[], 0).expect_err("unknown op");
        assert!(err.contains("unknown op"), "{err}");
    }
}
