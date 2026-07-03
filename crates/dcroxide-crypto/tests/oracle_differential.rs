// SPDX-License-Identifier: ISC
//! Differential test: our BLAKE-256 vs. dcrd's `crypto/blake256`, live.
//!
//! This is the Phase 0 "demo differential test" from the project brief: it
//! drives `tools/oracle` (a Go shim linking the exact dcrd module versions
//! pinned by release-v2.1.5) and byte-compares digests. See
//! `dcroxide-testutil` for the harness and skip/require policy.

use dcroxide_crypto::blake256;
use dcroxide_testutil::{SplitMix64, hex, oracle_or_skip};

#[test]
fn blake256_matches_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };

    // The fixed KAT lengths first: every padding path, deterministically.
    for n in [
        0usize, 1, 32, 54, 55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, 129, 200,
    ] {
        let data: Vec<u8> = (0..n).map(|i| i as u8).collect();
        assert_eq!(
            hex(&blake256::sum256(&data)),
            oracle.call_ok("blake256", &data),
            "pattern input, len {n}"
        );
    }

    // Then random inputs; the seed is printed so failures reproduce exactly.
    let mut rng = SplitMix64::from_entropy("blake256 differential");
    const CASES: usize = 5_000;
    for i in 0..CASES {
        let data = rng.bytes(4096);
        assert_eq!(
            hex(&blake256::sum256(&data)),
            oracle.call_ok("blake256", &data),
            "random input {i}, len {}",
            data.len()
        );
    }
}
