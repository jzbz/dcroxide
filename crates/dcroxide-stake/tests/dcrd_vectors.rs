// SPDX-License-Identifier: ISC
//! Oracle-free replay of dcrd's staketx_test.go transaction vectors.
//!
//! `data/staketx_vectors.txt` was generated mechanically inside dcrd's
//! blockchain/stake package at release-v2.1.5: every `*wire.MsgTx` vector
//! from staketx_test.go serialized to hex, followed by dcrd's own verdicts
//! (DetermineTxType, the six Check* functions, commitment extraction, and
//! vote extraction) in the same line format as the live oracle
//! `stake_analyze` dump. This test replays each transaction through our
//! implementation and compares the full dump, so the curated dcrd edge
//! cases stay covered without a Go toolchain.
//!
//! Also ports the fixed reward-calculation tables and the 100k-iteration
//! Hash256PRNG state vector from dcrd's tests.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use core::str::FromStr;

use dcroxide_chainhash::{Hash, hash_h};
use dcroxide_stake as stake;
use dcroxide_testutil::{hex, unhex};
use dcroxide_wire::MsgTx;

/// Rebuild the dump for one transaction; must mirror the generator in the
/// dcrd-side dump test (and the oracle `stake_analyze` handler) line for
/// line.
fn analyze(tx: &MsgTx) -> String {
    let mut w = String::new();
    w.push_str(&format!("type={}\n", stake::determine_tx_type(tx) as u8));
    let ok_or = |r: Result<(), stake::RuleError>| -> String {
        match r {
            Ok(()) => "ok".to_string(),
            Err(e) => e.kind.kind_name().to_string(),
        }
    };
    w.push_str(&format!("checksstx={}\n", ok_or(stake::check_sstx(tx))));
    let ssgen_result = stake::check_ssgen_votes(tx);
    w.push_str(&format!(
        "checkssgen={}\n",
        match &ssgen_result {
            Ok(_) => "ok".to_string(),
            Err(e) => e.kind.kind_name().to_string(),
        }
    ));
    w.push_str(&format!("checkssrtx={}\n", ok_or(stake::check_ssrtx(tx))));
    w.push_str(&format!("checktadd={}\n", ok_or(stake::check_tadd(tx))));
    w.push_str(&format!(
        "checktspend={}\n",
        match stake::check_tspend(tx) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.kind.kind_name().to_string(),
        }
    ));
    w.push_str(&format!(
        "checktreasurybase={}\n",
        ok_or(stake::check_treasury_base(tx))
    ));
    if stake::is_sstx(tx) {
        let info = stake::tx_sstx_stake_output_info(tx);
        for i in 0..info.is_p2sh.len() {
            w.push_str(&format!(
                "commit={} {} {} {} {} {} {} {}\n",
                info.is_p2sh[i],
                hex(&info.addresses[i]),
                info.amounts[i],
                info.change_amounts[i],
                info.spend_rules[i][0],
                info.spend_rules[i][1],
                info.spend_limits[i][0],
                info.spend_limits[i][1],
            ));
        }
    }
    if stake::is_ssgen(tx) {
        let (block_hash, height) = stake::ssgen_block_voted_on(tx);
        w.push_str(&format!("votedon={block_hash} {height}\n"));
        w.push_str(&format!("votebits={}\n", stake::ssgen_vote_bits(tx)));
        w.push_str(&format!("voteversion={}\n", stake::ssgen_version(tx)));
        for v in ssgen_result.expect("is_ssgen implies ok") {
            w.push_str(&format!("tv={} {}\n", v.hash, v.vote));
        }
    }
    w
}

#[test]
fn staketx_vectors() {
    let data = include_str!("data/staketx_vectors.txt");
    let mut lines = data.lines().peekable();
    let mut seen = 0usize;
    while let Some(header) = lines.next() {
        let mut parts = header.split(' ');
        assert_eq!(parts.next(), Some("tx"), "malformed vector header");
        let name = parts.next().expect("vector name");
        let tx_hex = parts.next().expect("vector tx hex");
        let (tx, _) = MsgTx::from_bytes(&unhex(tx_hex)).expect("vector tx deserializes");

        let mut expected = String::new();
        for line in lines.by_ref() {
            if line == "end" {
                break;
            }
            expected.push_str(line);
            expected.push('\n');
        }

        assert_eq!(analyze(&tx), expected, "vector {name} diverged");
        seen += 1;
    }
    assert_eq!(seen, 31, "expected all staketx_test.go vectors");
}

/// dcrd TestBasicPRNG: 100,000 draws from a PRNG seeded with
/// BLAKE-256(0x01) must land on a known state hash.
#[test]
fn prng_100k_state_vector() {
    let seed = hash_h(&[0x01]);
    let mut prng = stake::Hash256Prng::new(&seed.0);
    for _ in 0..100_000 {
        prng.hash256_rand();
    }
    let expected =
        Hash::from_str("24f1cd72aefbfc85a9d3e21e2eb732615688d3634bf94499af5a81e0eb45c4e4")
            .expect("valid hash string");
    assert_eq!(prng.state_hash(), expected);
}

/// dcrd TestCalculateRewards fixed tables.
#[test]
fn calculate_rewards_vectors() {
    // Evenly divisible over all outputs.
    let got = stake::calculate_rewards(
        &[2_500_000_000, 2_500_000_000, 5_000_000_000, 10_000_000_000],
        20_000_000_000,
        100_000_000,
    );
    assert_eq!(
        got,
        vec![2_512_500_000, 2_512_500_000, 5_025_000_000, 10_050_000_000]
    );

    // Remainder of 2 (truncated per contributor).
    let got = stake::calculate_rewards(
        &[100_000_000, 100_000_000, 100_000_000],
        300_000_000,
        300_002,
    );
    assert_eq!(got, vec![100_100_000, 100_100_000, 100_100_000]);
}

/// dcrd TestCalculateRevocationRewards fixed tables, including the
/// PRNG-driven remainder distribution when auto revocations are active.
#[test]
fn calculate_revocation_rewards_vectors() {
    let prev_header = unhex(concat!(
        "07000000dc02335daa073d293e1b150648f0444a60b9c97604abd01e0000000000",
        "0000003c449b2321c4bd0d1fa76ed59f80ebaf46f16cfb2d17ba46948f09f21861",
        "095566482410a463ed49473c27278cd7a2a3712a3b19ff1f6225717d3eb71cc2b5",
        "590100012c7312a3c30500050095a100000cf42418f1820a870300000020a10700",
        "091600005b32a55f5bcce31078832100007469943958002e000000000000000000",
        "000000000000000000000007000000",
    ));

    // Evenly divisible, auto revocations disabled (header unused).
    let contribs = [2_500_000_000, 2_500_000_000, 5_000_000_000, 10_000_000_000];
    let got = stake::calculate_revocation_rewards(&contribs, 20_000_000_000, &[], false);
    assert_eq!(got, contribs.to_vec());

    // Remainder of 4, auto revocations disabled: remainder is discarded.
    let contribs = [100_000_000i64; 8];
    let got = stake::calculate_revocation_rewards(&contribs, 799_999_996, &[], false);
    assert_eq!(got, vec![99_999_999i64; 8]);

    // Evenly divisible, auto revocations enabled.
    let contribs = [2_500_000_000, 2_500_000_000, 5_000_000_000, 10_000_000_000];
    let got = stake::calculate_revocation_rewards(&contribs, 20_000_000_000, &prev_header, true);
    assert_eq!(got, contribs.to_vec());

    // Remainder of 4, auto revocations enabled: the four extra atoms land
    // on PRNG-chosen outputs (seeded from the previous header).
    let contribs = [100_000_000i64; 8];
    let got = stake::calculate_revocation_rewards(&contribs, 799_999_996, &prev_header, true);
    assert_eq!(
        got,
        vec![
            99_999_999,
            100_000_000,
            99_999_999,
            99_999_999,
            99_999_999,
            99_999_999,
            100_000_001,
            100_000_000,
        ]
    );
}
