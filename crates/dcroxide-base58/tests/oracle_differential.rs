// SPDX-License-Identifier: ISC
//! Differential tests: our base58 vs. decred/base58 live through the
//! oracle, over random payloads (biased toward leading zeros) and mutated
//! check-encoded strings.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

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
