// SPDX-License-Identifier: ISC
//! `dcroxide-bench dcrec`: a micro benchmark of dcroxide-dcrec's
//! operations on secrets, each against dcrd's own through the oracle.
//!
//! The operations are the ones `crates/dcroxide-dcrec/src/ct_check.rs`
//! times for constant time: the generator's multiplication by a secret
//! scalar, through k256's basepoint table and through its `lincomb`, the
//! public key, the private key's range check, ECDSA and EC-Schnorr-DCRv0
//! signing, the RFC 6979 nonce, HD derivation's private child sum, and
//! Ed25519's public key and signing.  Each has a Go counterpart in
//! `tools/oracle/bench.go` (`secp_bench`), which times dcrd's call on the
//! same cases in the oracle's own process.
//!
//! **What is timed.** Each side prepares its inputs untimed (keys parsed,
//! scalars decoded), times one pass of the operation over every case,
//! storing each result, and serializes the results untimed into one byte
//! string.  Both sides fold that string into a 64-bit FNV-1a digest, and
//! the run stops unless the two digests agree: every timed pass is also a
//! differential of the two implementations over every case.
//!
//! **The order.** A run makes one warm-up pass of every operation on each
//! side, which builds k256's table and dcrd's, then `--rounds` rounds.  In
//! each round each operation runs once on each side, the side going
//! first alternating from operation to operation and from round to round,
//! and `--start go` turning the whole pattern round, so that a process
//! run with each start value puts every pair in both orders equally
//! often.  The oracle is a child process and inherits this one's CPU
//! affinity, so `taskset` on this process pins both sides to the same
//! processors; while one side runs the other waits on a pipe.
//!
//! **What it cannot do.**  This crate takes dcroxide-dcrec with its
//! default `precomputed-tables` feature, as the node does, and Cargo
//! unifies that feature into every k256 in the workspace build, so
//! dcrec's no-table build cannot be linked here.  The `lincomb` row
//! times the multiplication that build makes, k256's `GENERATOR * k`,
//! directly; what the other rows would cost without the table is that
//! row's difference added to them, an inference, not a measurement.

use std::fmt::Write as _;
use std::hint::black_box;
use std::io::Write as _;
use std::path::PathBuf;
use std::time::Instant;

use dcroxide_dcrec::edwards;
use dcroxide_dcrec::secp256k1::{
    PrivateKey, add_private_tweak, check_scalar, ecdsa, nonce::nonce_rfc6979, schnorr,
};
use dcroxide_testutil::{Oracle, SplitMix64};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::group::GroupEncoding;
use k256::{FieldBytes, ProjectivePoint, Scalar};

use crate::{Args, median};

/// The size of one case as the oracle takes it: key, hash, tweak, parent
/// and seed, 32 bytes each (`tools/oracle/bench.go`'s `benchCaseLen`).
pub(crate) const CASE_LEN: usize = 5 * 32;

/// The seed `--seed` defaults to, so that runs without it time the same
/// cases.
const DEFAULT_SEED: u64 = 0x6463_7265_6362_656e;

/// One case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Case {
    /// A private key in [1, N-1].
    pub(crate) key: [u8; 32],
    /// The hash signed; Ed25519's message too.
    pub(crate) hash: [u8; 32],
    /// An HD derivation's Il, in [1, N-1].
    pub(crate) tweak: [u8; 32],
    /// An HD parent private key, any 32 bytes (dcrd reduces it modulo N).
    pub(crate) parent: [u8; 32],
    /// An Ed25519 seed.
    pub(crate) seed: [u8; 32],
}

/// `count` cases drawn from `seed` with SplitMix64: each key and tweak
/// drawn again until it lies in [1, N-1].
pub(crate) fn draw_cases(seed: u64, count: usize) -> Vec<Case> {
    let mut rng = SplitMix64(seed);
    let scalar = |rng: &mut SplitMix64| {
        let mut b = [0u8; 32];
        loop {
            rng.fill(&mut b);
            if check_scalar(&b).is_ok() {
                return b;
            }
        }
    };
    let any = |rng: &mut SplitMix64| {
        let mut b = [0u8; 32];
        rng.fill(&mut b);
        b
    };
    (0..count)
        .map(|_| Case {
            key: scalar(&mut rng),
            hash: any(&mut rng),
            tweak: scalar(&mut rng),
            parent: any(&mut rng),
            seed: any(&mut rng),
        })
        .collect()
}

/// The cases as the oracle's `secp_bench` takes them.
pub(crate) fn encode_cases(cases: &[Case]) -> Vec<u8> {
    let mut out = Vec::with_capacity(cases.len().saturating_mul(CASE_LEN));
    for c in cases {
        for field in [&c.key, &c.hash, &c.tweak, &c.parent, &c.seed] {
            out.extend_from_slice(field);
        }
    }
    out
}

/// The 64-bit FNV-1a hash, the digest both sides fold their outputs into.
pub(crate) fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// One timed pass: the elapsed nanoseconds and the outputs, serialized
/// and concatenated in case order.
pub(crate) struct Pass {
    /// Nanoseconds the pass took, over every case.
    pub(crate) ns: u64,
    /// The outputs.
    pub(crate) out: Vec<u8>,
}

/// The nanoseconds since `start`, saturating.
fn since(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// One operation.
pub(crate) struct Op {
    /// The name `--ops` and the output use.
    pub(crate) name: &'static str,
    /// The oracle's name for dcrd's counterpart.
    pub(crate) go: &'static str,
    /// The timed pass.
    pub(crate) run: fn(&[Case]) -> Pass,
}

/// The cases' private keys, parsed untimed.
fn keys(cases: &[Case]) -> Vec<PrivateKey> {
    cases
        .iter()
        .map(|c| PrivateKey::from_bytes(&c.key).expect("every case's key is in [1, N-1]"))
        .collect()
}

/// The cases' keys as k256 scalars, decoded untimed.
fn scalars(cases: &[Case]) -> Vec<Scalar> {
    cases
        .iter()
        .map(|c| {
            Option::from(Scalar::from_repr(FieldBytes::from(c.key)))
                .expect("every case's key is below N")
        })
        .collect()
}

/// Projective points brought to affine coordinates and compressed, untimed.
fn compressed(points: &[ProjectivePoint]) -> Vec<u8> {
    points
        .iter()
        .flat_map(|p| p.to_affine().to_bytes())
        .collect()
}

/// k*G through k256's `mul_by_generator`, which with the
/// `precomputed-tables` feature this build has is the basepoint table's
/// walk: dcrec's `mul_secret_by_generator` in its default build.
fn generator_table(cases: &[Case]) -> Pass {
    let ks = scalars(cases);
    let mut points = Vec::with_capacity(ks.len());
    let start = Instant::now();
    for k in &ks {
        points.push(ProjectivePoint::mul_by_generator(black_box(k)));
    }
    let ns = since(start);
    Pass {
        ns,
        out: compressed(&points),
    }
}

/// k*G through k256's `GENERATOR * k`, its constant-time `lincomb`: dcrec's
/// `mul_secret_by_generator` built without default features.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "a point multiplication, not integer arithmetic"
)]
fn generator_lincomb(cases: &[Case]) -> Pass {
    let ks = scalars(cases);
    let mut points = Vec::with_capacity(ks.len());
    let start = Instant::now();
    for k in &ks {
        points.push(ProjectivePoint::GENERATOR * *black_box(k));
    }
    let ns = since(start);
    Pass {
        ns,
        out: compressed(&points),
    }
}

/// `PrivateKey::public_key`: dG, its affine coordinates and the curve check.
fn public_key(cases: &[Case]) -> Pass {
    let keys = keys(cases);
    let mut pubs = Vec::with_capacity(keys.len());
    let start = Instant::now();
    for key in &keys {
        pubs.push(black_box(key).public_key());
    }
    let ns = since(start);
    Pass {
        ns,
        out: pubs.iter().flat_map(|p| p.serialize_compressed()).collect(),
    }
}

/// `PrivateKey::from_bytes`: the range check and the key.
fn key_from_bytes(cases: &[Case]) -> Pass {
    let mut keys = Vec::with_capacity(cases.len());
    let start = Instant::now();
    for c in cases {
        keys.push(PrivateKey::from_bytes(black_box(&c.key)));
    }
    let ns = since(start);
    let mut out = Vec::with_capacity(cases.len().saturating_mul(32));
    for key in &keys {
        out.extend_from_slice(&*key.as_ref().expect("in range").serialize());
    }
    Pass { ns, out }
}

/// `ecdsa::sign`: the RFC 6979 nonce, kG and the low-S signature.
fn ecdsa_sign(cases: &[Case]) -> Pass {
    let keys = keys(cases);
    let mut sigs = Vec::with_capacity(keys.len());
    let start = Instant::now();
    for (key, c) in keys.iter().zip(cases) {
        sigs.push(ecdsa::sign(black_box(key), black_box(&c.hash)));
    }
    let ns = since(start);
    Pass {
        ns,
        out: sigs.iter().flat_map(ecdsa::Signature::serialize).collect(),
    }
}

/// `schnorr::sign`: EC-Schnorr-DCRv0 with its RFC 6979 nonce.
fn schnorr_sign(cases: &[Case]) -> Pass {
    let keys = keys(cases);
    let mut sigs = Vec::with_capacity(keys.len());
    let start = Instant::now();
    for (key, c) in keys.iter().zip(cases) {
        sigs.push(schnorr::sign(black_box(key), black_box(&c.hash)));
    }
    let ns = since(start);
    Pass {
        ns,
        out: sigs
            .iter()
            .flat_map(|s| s.as_ref().expect("a key in range signs").serialize())
            .collect(),
    }
}

/// `nonce_rfc6979` with no extra data or version, the first candidate, as
/// `ecdsa::sign` asks for it.
fn rfc6979_nonce(cases: &[Case]) -> Pass {
    let mut nonces = Vec::with_capacity(cases.len());
    let start = Instant::now();
    for c in cases {
        nonces.push(nonce_rfc6979(
            black_box(&c.key),
            black_box(&c.hash),
            None,
            None,
            0,
        ));
    }
    let ns = since(start);
    Pass {
        ns,
        out: nonces.concat(),
    }
}

/// `add_private_tweak`: HD derivation's private child sum, the tweak's
/// range check and the parent's reduction modulo N included.
fn hd_private_child(cases: &[Case]) -> Pass {
    let mut sums = Vec::with_capacity(cases.len());
    let start = Instant::now();
    for c in cases {
        sums.push(add_private_tweak(black_box(&c.tweak), black_box(&c.parent)));
    }
    let ns = since(start);
    let mut out = Vec::with_capacity(cases.len().saturating_mul(32));
    for sum in &sums {
        out.extend_from_slice(&*sum.as_ref().expect("every tweak is in range").serialize());
    }
    Pass { ns, out }
}

/// `edwards::SecretKey::from_seed` and `public_key`.
fn ed25519_public_key(cases: &[Case]) -> Pass {
    let mut pubs = Vec::with_capacity(cases.len());
    let start = Instant::now();
    for c in cases {
        pubs.push(edwards::SecretKey::from_seed(*black_box(&c.seed)).public_key());
    }
    let ns = since(start);
    Pass {
        ns,
        out: pubs
            .iter()
            .flat_map(edwards::PublicKey::serialize)
            .collect(),
    }
}

/// `edwards::sign` over the case's hash as the message.  It derives the
/// public key from the seed again for every signature, where dcrd's key
/// carries the one `PrivKeyFromSecret` computed.
fn ed25519_sign(cases: &[Case]) -> Pass {
    let secrets: Vec<_> = cases
        .iter()
        .map(|c| edwards::SecretKey::from_seed(c.seed))
        .collect();
    let mut sigs = Vec::with_capacity(cases.len());
    let start = Instant::now();
    for (secret, c) in secrets.iter().zip(cases) {
        sigs.push(edwards::sign(black_box(secret), black_box(&c.hash)));
    }
    let ns = since(start);
    Pass {
        ns,
        out: sigs
            .iter()
            .flat_map(edwards::Signature::serialize)
            .collect(),
    }
}

/// `edwards::sign_with_pub_key_bytes` with the public key computed
/// untimed, as dcrd's key carries it.
fn ed25519_sign_known_key(cases: &[Case]) -> Pass {
    let secrets: Vec<_> = cases
        .iter()
        .map(|c| {
            let secret = edwards::SecretKey::from_seed(c.seed);
            let public = secret.public_key().serialize();
            (secret, public)
        })
        .collect();
    let mut sigs = Vec::with_capacity(cases.len());
    let start = Instant::now();
    for ((secret, public), c) in secrets.iter().zip(cases) {
        sigs.push(edwards::sign_with_pub_key_bytes(
            black_box(secret),
            black_box(public),
            black_box(&c.hash),
        ));
    }
    let ns = since(start);
    Pass {
        ns,
        out: sigs
            .iter()
            .flat_map(edwards::Signature::serialize)
            .collect(),
    }
}

/// Every operation, in the order a round runs them.
pub(crate) const OPS: &[Op] = &[
    Op {
        name: "generator_table",
        go: "generator",
        run: generator_table,
    },
    Op {
        name: "generator_lincomb",
        go: "generator",
        run: generator_lincomb,
    },
    Op {
        name: "public_key",
        go: "public_key",
        run: public_key,
    },
    Op {
        name: "key_from_bytes",
        go: "key_from_bytes",
        run: key_from_bytes,
    },
    Op {
        name: "ecdsa_sign",
        go: "ecdsa_sign",
        run: ecdsa_sign,
    },
    Op {
        name: "schnorr_sign",
        go: "schnorr_sign",
        run: schnorr_sign,
    },
    Op {
        name: "rfc6979_nonce",
        go: "rfc6979_nonce",
        run: rfc6979_nonce,
    },
    Op {
        name: "hd_private_child",
        go: "hd_private_child",
        run: hd_private_child,
    },
    Op {
        name: "ed25519_public_key",
        go: "ed25519_public_key",
        run: ed25519_public_key,
    },
    Op {
        name: "ed25519_sign",
        go: "ed25519_sign",
        run: ed25519_sign,
    },
    Op {
        name: "ed25519_sign_known_key",
        go: "ed25519_sign",
        run: ed25519_sign_known_key,
    },
];

/// dcrd's pass of `op` over the encoded cases, through the oracle: the
/// nanoseconds and the digest it reports.
pub(crate) fn go_pass(oracle: &mut Oracle, op: &str, encoded: &[u8]) -> Result<(u64, u64), String> {
    let name = u8::try_from(op.len()).map_err(|_| format!("op name {op} is too long"))?;
    let mut data = Vec::with_capacity(encoded.len().saturating_add(op.len()).saturating_add(1));
    data.push(name);
    data.extend_from_slice(op.as_bytes());
    data.extend_from_slice(encoded);
    let resp = oracle.call("secp_bench", &data);
    if let Some(err) = resp.get("error").and_then(|e| e.as_str()) {
        return Err(format!("oracle secp_bench {op}: {err}"));
    }
    let ns = resp["detail"]["ns"]
        .as_u64()
        .ok_or_else(|| format!("oracle secp_bench {op}: no ns in {resp}"))?;
    let digest = resp["detail"]["digest"]
        .as_str()
        .and_then(|d| u64::from_str_radix(d, 16).ok())
        .ok_or_else(|| format!("oracle secp_bench {op}: no digest in {resp}"))?;
    Ok((ns, digest))
}

/// Which side a round's pair runs first: Rust when true.  Alternates from
/// operation to operation and from round to round, and `start_go` turns
/// the pattern round.
pub(crate) fn rust_first(round: usize, op: usize, start_go: bool) -> bool {
    round.wrapping_add(op).is_multiple_of(2) != start_go
}

/// The processors this process may run on, from /proc/self/status, or
/// "unknown".
fn allowed_cpus() -> String {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
                .map(|v| v.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// The first three fields of /proc/loadavg, or "unknown".
fn load_average() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .map(|s| s.split_whitespace().take(3).collect::<Vec<_>>().join(" "))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Nanoseconds per operation of a pass over `cases` cases.
#[allow(
    clippy::cast_precision_loss,
    reason = "nanosecond totals and case counts far below 2^52"
)]
fn per_op(ns: u64, cases: usize) -> f64 {
    ns as f64 / cases.max(1) as f64
}

/// The oracle binary: `--oracle`, else `DCROXIDE_ORACLE_BIN`; `none`
/// leaves dcrd out.
fn oracle_path(args: &Args) -> Option<PathBuf> {
    let named = args
        .get("oracle")
        .map(str::to_string)
        .or_else(|| std::env::var(dcroxide_testutil::ORACLE_BIN_VAR).ok())?;
    (named != "none").then(|| PathBuf::from(named))
}

/// Run the benchmark.
#[allow(
    clippy::too_many_lines,
    reason = "one linear procedure: set up, warm up, the rounds, the summary"
)]
pub(crate) fn cmd_dcrec(args: &Args) -> Result<(), String> {
    let count: usize = match args.get("cases") {
        Some(v) => v.parse().map_err(|e| format!("bad --cases: {e}"))?,
        None => 8192,
    };
    if count == 0 {
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
    let ops: Vec<&Op> = match args.get("ops") {
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
    let mut out_file = match args.get("out") {
        Some(path) => {
            Some(std::fs::File::create(path).map_err(|e| format!("unable to create {path}: {e}"))?)
        }
        None => None,
    };
    let mut oracle = oracle_path(args).map(|p| Oracle::spawn_at(&p));

    println!(
        "dcrec bench: {count} cases, seed {seed:#018x}, {rounds} rounds, start {}, cpus {}, load {}",
        if start_go { "go" } else { "rust" },
        allowed_cpus(),
        load_average()
    );
    if let Some(oracle) = oracle.as_mut() {
        let info = oracle.call("build_info", &[]);
        println!(
            "dcrd: {} {}",
            info["go_version"].as_str().unwrap_or("unknown"),
            info["modules"]
        );
    } else {
        println!("dcrd: no oracle (--oracle or DCROXIDE_ORACLE_BIN), Rust side only");
    }

    let cases = draw_cases(seed, count);
    let encoded = encode_cases(&cases);

    // Per op: Rust's and Go's nanoseconds per operation, one a round.
    let mut timings: Vec<(Vec<f64>, Vec<f64>)> = vec![(Vec::new(), Vec::new()); ops.len()];
    // Round 0 is the warm-up, kept out of the summary.
    for round in 0..=rounds {
        for (i, op) in ops.iter().enumerate() {
            let mut rust = None;
            let mut go = None;
            let order = if rust_first(round, i, start_go) {
                [true, false]
            } else {
                [false, true]
            };
            for is_rust in order {
                if is_rust {
                    let pass = (op.run)(&cases);
                    rust = Some((pass.ns, fnv1a64(&pass.out)));
                } else if let Some(oracle) = oracle.as_mut() {
                    go = Some(go_pass(oracle, op.go, &encoded)?);
                }
            }
            let (rust_ns, rust_digest) = rust.expect("the Rust side always runs");
            if let Some((_, go_digest)) = go
                && go_digest != rust_digest
            {
                return Err(format!(
                    "{}: dcrec's digest {rust_digest:016x} is not dcrd's {go_digest:016x} \
                     (round {round})",
                    op.name
                ));
            }
            let mut line = format!(
                "{{\"round\":{round},\"warmup\":{},\"op\":\"{}\",\"go_op\":\"{}\",\
                 \"cases\":{count},\"rust_first\":{},\"rust_ns\":{rust_ns},\
                 \"digest\":\"{rust_digest:016x}\"",
                round == 0,
                op.name,
                op.go,
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
            eprintln!("dcrec bench: round {round} of {rounds} done");
        }
    }

    println!(
        "{:<24} {:>12} {:>12} {:>12} {:>12} {:>9}",
        "op (ns/op)", "rust median", "rust least", "go median", "go least", "rust/go"
    );
    for (op, (rust, go)) in ops.iter().zip(timings.iter_mut()) {
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
            "{:<24} {rust_median:>12.1} {rust_least:>12.1} {go_median:>12} {go_least:>12} {ratio:>9}",
            op.name
        );
    }
    if oracle.is_some() {
        println!(
            "every pass of every op gave the same digest on both sides ({} rounds and the warm-up)",
            rounds
        );
    }
    println!("load after: {}", load_average());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcroxide_testutil::oracle_or_skip;

    /// The cases are a function of the seed, and every key and tweak is in
    /// [1, N-1], which the operations' `expect`s rely on.
    #[test]
    fn cases_are_deterministic_and_in_range() {
        let a = draw_cases(7, 200);
        assert_eq!(a, draw_cases(7, 200));
        assert_ne!(a, draw_cases(8, 200));
        for c in &a {
            assert!(check_scalar(&c.key).is_ok());
            assert!(check_scalar(&c.tweak).is_ok());
        }
        let encoded = encode_cases(&a);
        assert_eq!(encoded.len(), 200 * CASE_LEN);
        assert_eq!(&encoded[CASE_LEN..CASE_LEN + 32], &a[1].key);
        assert_eq!(&encoded[CASE_LEN - 32..CASE_LEN], &a[0].seed);
    }

    /// The published FNV-1a 64 values, as `tools/oracle`'s test checks
    /// its own.
    #[test]
    fn fnv1a64_matches_the_published_values() {
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a64(b"foobar"), 0x8594_4171_f739_67e8);
    }

    /// Each pair runs in both orders equally often over two rounds, and the
    /// two start values give opposite orders.
    #[test]
    fn the_first_side_alternates() {
        for op in 0..OPS.len() {
            assert_ne!(rust_first(0, op, false), rust_first(1, op, false));
            assert_ne!(rust_first(3, op, false), rust_first(3, op, true));
        }
        assert_ne!(rust_first(0, 0, false), rust_first(0, 1, false));
    }

    /// Operations that compute the same thing give the same outputs: the
    /// table against `lincomb`, and Ed25519 signing either way.
    #[test]
    fn paired_operations_agree() {
        let cases = draw_cases(11, 64);
        assert_eq!(generator_table(&cases).out, generator_lincomb(&cases).out);
        assert_eq!(generator_table(&cases).out, public_key(&cases).out);
        assert_eq!(ed25519_sign(&cases).out, ed25519_sign_known_key(&cases).out);
        for op in OPS {
            assert!(!(op.run)(&cases).out.is_empty(), "{}", op.name);
        }
    }

    /// Every operation's outputs equal dcrd's over the same cases, through
    /// the oracle's `secp_bench`: the check every benchmark pass makes.
    #[test]
    fn every_operation_matches_dcrd() {
        let Some(mut oracle) = oracle_or_skip() else {
            return;
        };
        let mut rng = SplitMix64::from_entropy("dcrec bench cases");
        let cases = draw_cases(rng.next_u64(), 48);
        let encoded = encode_cases(&cases);
        for op in OPS {
            let pass = (op.run)(&cases);
            let (_, go_digest) = go_pass(&mut oracle, op.go, &encoded).expect("oracle answers");
            assert_eq!(
                fnv1a64(&pass.out),
                go_digest,
                "{} against dcrd's {}",
                op.name,
                op.go
            );
        }
        // The oracle refuses what it should, and the client reports it.
        let err = go_pass(&mut oracle, "nope", &encoded).expect_err("unknown op");
        assert!(err.contains("unknown op"), "{err}");
    }
}
