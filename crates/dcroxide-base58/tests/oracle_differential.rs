// SPDX-License-Identifier: ISC
//! Differential tests: the crate's base58 vs. decred/base58 live through the
//! oracle, over random payloads (biased toward leading zeros) and mutated
//! check-encoded strings, one string a request; and in batches over more
//! than a million valid and invalid strings, through the oracle's
//! `base58_bench`, which answers for thousands of strings at a time with
//! a digest of Go's outputs.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

mod inputs;

use dcroxide_base58::{CheckError, check_decode, check_encode, decode, encode};
use dcroxide_testutil::{Oracle, SplitMix64, hex, oracle_or_skip};

/// Like `call_ok` but treats an omitted result as the empty string (the
/// oracle's JSON omits empty fields, and empty results are meaningful for
/// base58: invalid or empty inputs decode/encode to nothing).
fn call_str(oracle: &mut Oracle, cmd: &str, data: &[u8]) -> String {
    let resp = oracle.call(cmd, data);
    if let Some(err) = resp.get("error").and_then(|e| e.as_str()) {
        panic!("oracle error for cmd {cmd}: {err}");
    }
    resp["result"].as_str().unwrap_or("").to_string()
}

#[test]
fn base58_differential() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("base58-differential");

    const ROUNDS: usize = 2000;
    for round in 0..ROUNDS {
        // Random payload with a bias toward leading zeros.
        let mut payload = rng.bytes(64);
        let lead_zeros = rng.below(4) as usize;
        for b in payload.iter_mut().take(lead_zeros) {
            *b = 0;
        }

        // Encode differential.
        let ours = encode(&payload);
        let theirs = call_str(&mut oracle, "base58_encode", &payload);
        assert_eq!(
            ours,
            theirs,
            "encode divergence at round {round}: {}",
            hex(&payload)
        );

        // Decode differential over the (valid) encoding and a mutated
        // variant that may contain invalid characters.
        let decoded_theirs = call_str(&mut oracle, "base58_decode", ours.as_bytes());
        assert_eq!(
            hex(&decode(&ours)),
            decoded_theirs,
            "decode divergence at round {round}: {ours}"
        );

        let mut mutated = ours.into_bytes();
        if !mutated.is_empty() {
            let idx = rng.below(mutated.len() as u64) as usize;
            mutated[idx] = match rng.below(4) {
                0 => b'0', // invalid character
                1 => b'O', // invalid character
                2 => b'l', // invalid character
                _ => b'1',
            };
        }
        let mutated = String::from_utf8(mutated).expect("ascii");
        let decoded_theirs = call_str(&mut oracle, "base58_decode", mutated.as_bytes());
        assert_eq!(
            hex(&decode(&mutated)),
            decoded_theirs,
            "mutated decode divergence at round {round}: {mutated}"
        );

        // Check-encode differential.
        let version = [rng.next_u64() as u8, rng.next_u64() as u8];
        let check_payload = rng.bytes(48);
        let ours = check_encode(&check_payload, version);
        let mut req = Vec::with_capacity(2 + check_payload.len());
        req.extend_from_slice(&version);
        req.extend_from_slice(&check_payload);
        let theirs = call_str(&mut oracle, "base58_check_encode", &req);
        assert_eq!(ours, theirs, "check_encode divergence at round {round}");

        // Check-decode round trip plus corruption.
        let (payload_back, version_back) = check_decode(&ours).expect("round trip");
        assert_eq!(payload_back, check_payload);
        assert_eq!(version_back, version);

        let mut corrupted = ours.into_bytes();
        let idx = rng.below(corrupted.len() as u64) as usize;
        let orig = corrupted[idx];
        corrupted[idx] = if orig == b'2' { b'3' } else { b'2' };
        let corrupted = String::from_utf8(corrupted).expect("ascii");
        let ours_kind = match check_decode(&corrupted) {
            Ok(_) => "ok".to_string(),
            Err(CheckError::Checksum) => "checksum".to_string(),
            Err(CheckError::InvalidFormat) => "invalid format".to_string(),
        };
        let resp = oracle.call("base58_check_decode", corrupted.as_bytes());
        let theirs_kind = if resp["result"].is_string() {
            "ok".to_string()
        } else {
            resp["kind"].as_str().expect("kind present").to_string()
        };
        assert_eq!(
            ours_kind, theirs_kind,
            "check_decode divergence at round {round}: {corrupted}"
        );
    }
}

/// The strings a batch request carries.
const BATCH: usize = 8192;

/// The strings the batch differential compares, at least.
const BATCH_TOTAL: usize = 1_000_000;

/// Append `b`'s length as four big-endian bytes, then `b`: the framing of
/// `base58_bench`'s cases and of its outputs (`tools/oracle/base58bench.go`).
fn push_len_prefixed(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&u32::try_from(b.len()).expect("short").to_be_bytes());
    out.extend_from_slice(b);
}

/// The 64-bit FNV-1a hash, the digest `base58_bench` answers with.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// The crate's outputs for `op` over `strings`, serialized the way
/// `base58_bench` serializes Go's.
fn ours_serialized(op: &str, strings: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for s in strings {
        match op {
            "decode" => push_len_prefixed(&mut out, &decode(s)),
            "check_decode" => match check_decode(s) {
                Ok((payload, version)) => {
                    out.push(0);
                    out.extend_from_slice(&version);
                    push_len_prefixed(&mut out, &payload);
                }
                Err(CheckError::Checksum) => out.push(1),
                Err(CheckError::InvalidFormat) => out.push(2),
            },
            "encode" => push_len_prefixed(&mut out, encode(&decode(s)).as_bytes()),
            "check_encode" => {
                let (payload, version) = check_decode(s).expect("only check-encoded strings");
                push_len_prefixed(&mut out, check_encode(&payload, version).as_bytes());
            }
            _ => unreachable!("op {op}"),
        }
    }
    out
}

/// Go's digest for `op` over `strings`.
fn go_digest(oracle: &mut Oracle, op: &str, strings: &[String]) -> u64 {
    let mut data = vec![op.len() as u8];
    data.extend_from_slice(op.as_bytes());
    for s in strings {
        push_len_prefixed(&mut data, s.as_bytes());
    }
    let resp = oracle.call("base58_bench", &data);
    if let Some(err) = resp.get("error").and_then(|e| e.as_str()) {
        panic!("oracle base58_bench {op}: {err}");
    }
    assert_eq!(
        resp["detail"]["cases"].as_u64(),
        Some(strings.len() as u64),
        "{op}: case count"
    );
    resp["detail"]["digest"]
        .as_str()
        .and_then(|d| u64::from_str_radix(d, 16).ok())
        .unwrap_or_else(|| panic!("oracle base58_bench {op}: no digest in {resp}"))
}

/// The first string of a batch whose output differs from Go's, found one
/// string a request with the per-string commands.
fn first_divergence(oracle: &mut Oracle, op: &str, strings: &[String]) -> String {
    for s in strings {
        let one = std::slice::from_ref(s);
        if fnv1a64(&ours_serialized(op, one)) != go_digest(oracle, op, one) {
            let decoded = call_str(oracle, "base58_decode", s.as_bytes());
            return format!("{s:?}: ours {}, Go's decode {decoded}", hex(&decode(s)));
        }
    }
    "no single string differs; the batch framing does".to_string()
}

/// The worker threads of the batch differential, each with its own
/// oracle process.
const BATCH_WORKERS: usize = 4;

/// Compare every batch of `strings` with Go for `ops`, on
/// [`BATCH_WORKERS`] threads.
fn compare_batches(strings: &[String], ops: &[&str]) {
    let batches: Vec<&[String]> = strings.chunks(BATCH).collect();
    std::thread::scope(|scope| {
        for worker in 0..BATCH_WORKERS {
            let batches = &batches;
            scope.spawn(move || {
                let mut oracle = oracle_or_skip().expect("the oracle answered on this thread");
                for batch in batches.iter().skip(worker).step_by(BATCH_WORKERS) {
                    for &op in ops {
                        if fnv1a64(&ours_serialized(op, batch)) != go_digest(&mut oracle, op, batch)
                        {
                            panic!(
                                "{op} diverges from Go: {}",
                                first_divergence(&mut oracle, op, batch)
                            );
                        }
                    }
                }
            });
        }
    });
}

/// `decode`, `check_decode` and `encode` of each decoding against Go's
/// over at least a million strings (`tests/inputs/mod.rs`: every length
/// from 0 to 120, strings of only '1', the largest value of every length
/// to 300, one invalid character at every position of every length to
/// 120, random bytes, check-encoded and corrupted strings, lengths around
/// the decoder's stack array and random digits up to 1,200 characters;
/// then [`inputs::largest`], the largest value of every length from 301 to
/// 1,200 and around every multiple of 512 to 4,608; then random strings
/// to make up the count), and `check_encode` over those that check-decode.
#[test]
fn batch_differential() {
    if oracle_or_skip().is_none() {
        return;
    }
    let mut rng = SplitMix64::from_entropy("base58 batch differential");
    let mut strings = inputs::structured(&mut rng, 64);
    strings.extend(inputs::largest());
    let structured = strings.len();
    while strings.len() < BATCH_TOTAL {
        strings.push(inputs::random(&mut rng));
    }

    compare_batches(&strings, &["decode", "check_decode", "encode"]);

    let mut checked = Vec::new();
    let mut counts = [0usize; 3];
    for s in &strings {
        match check_decode(s) {
            Ok(_) => {
                counts[0] += 1;
                checked.push(s.clone());
            }
            Err(CheckError::Checksum) => counts[1] += 1,
            Err(CheckError::InvalidFormat) => counts[2] += 1,
        }
    }
    compare_batches(&checked, &["check_encode"]);

    println!(
        "{} strings ({structured} structured): {} check-decode, {} checksum errors, {} invalid \
         format",
        strings.len(),
        counts[0],
        counts[1],
        counts[2],
    );
    // Each outcome must be well represented, or the comparison above
    // proves less than it says.
    assert!(counts.iter().all(|&n| n > 10_000), "{counts:?}");
}
