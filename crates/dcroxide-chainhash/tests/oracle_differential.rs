// SPDX-License-Identifier: ISC
//! Differential tests: our `Hash` string parsing/formatting vs. dcrd's
//! `chaincfg/chainhash`, live — including the short-string zero-padding
//! quirk and error classification.

use dcroxide_chainhash::{Hash, HashError};
use dcroxide_testutil::{SplitMix64, hex, oracle_or_skip};

/// Assert that our parse verdict matches the oracle's for one input string.
fn check_parse(oracle: &mut dcroxide_testutil::Oracle, input: &str) {
    let ours = input.parse::<Hash>();
    let resp = oracle.call("newhashfromstr", input.as_bytes());
    match (&ours, resp.get("error").and_then(|e| e.as_str())) {
        (Ok(hash), None) => {
            let want = resp["result"].as_str().expect("result present");
            assert_eq!(hex(hash.as_bytes()), want, "hash bytes for input {input:?}");
        }
        (Err(err), Some(oracle_err)) => {
            // Error *classification* must agree (exact message text is not
            // chased; dcrd's texts come from Go's errors).
            let want_marker = match err {
                HashError::StrSize => "max hash string length",
                HashError::InvalidHexByte(_) => "invalid byte",
            };
            assert!(
                oracle_err.contains(want_marker),
                "error kind mismatch for {input:?}: ours {err:?}, oracle {oracle_err:?}"
            );
        }
        (ours, oracle_err) => {
            panic!("verdict mismatch for {input:?}: ours {ours:?}, oracle error {oracle_err:?}")
        }
    }
}

#[test]
fn hash_from_str_matches_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };

    // Deterministic edge cases: the dcrd test vectors plus boundary shapes.
    for input in [
        "",
        "1",
        "12",
        "123",
        "0",
        "00",
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        "19d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        "3264bc2ac36a60840790ba1d475d01367e7c723da941069e9dc",
        "01234567890123456789012345678901234567890123456789012345678912345",
        "abcdefg",
        "banana",
        "ABCDEF",
        "g",
        "0g",
        "g0",
    ] {
        check_parse(&mut oracle, input);
    }

    // Random strings over a hex-heavy alphabet with occasional invalid
    // bytes, random lengths straddling the 64-char limit.
    const CHARSET: &[u8] = b"0123456789abcdefABCDEF0123456789abcdefgz!";
    let mut rng = SplitMix64::from_entropy("chainhash parse differential");
    for _ in 0..3_000 {
        let len = rng.below(70) as usize;
        let s: String = (0..len)
            .map(|_| CHARSET[rng.below(CHARSET.len() as u64) as usize] as char)
            .collect();
        check_parse(&mut oracle, &s);
    }
}

#[test]
fn hash_display_matches_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };

    let mut rng = SplitMix64::from_entropy("chainhash display differential");
    for _ in 0..500 {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        let hash = Hash(bytes);
        assert_eq!(
            hash.to_string(),
            oracle.call_ok("hash_string", &bytes),
            "display of {}",
            hex(&bytes)
        );
    }
}
