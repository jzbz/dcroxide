// SPDX-License-Identifier: ISC
//! Replay of dcrd's context-free transaction and proof validation
//! verdicts generated inside dcrd's internal/blockchain package
//! (`data/validate_vectors.txt`): `CheckTransaction` over structured
//! and mutated transactions across agenda-flag combinations,
//! `checkProofOfStake` over blocks with ticket-shaped stake
//! transactions, and `checkProofOfWorkSanity` over random headers.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::RuleError;
use dcroxide_blockchain::validate::{
    AgendaFlags, check_proof_of_stake, check_proof_of_work_sanity, check_transaction,
};
use dcroxide_chaincfg::mainnet_params;
use dcroxide_standalone::{BigInt, Sign};
use dcroxide_testutil::unhex;
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx};

fn kind_of(result: Result<(), RuleError>) -> String {
    match result {
        Ok(()) => "ok".to_string(),
        Err(e) => e.kind.kind_name().to_string(),
    }
}

#[test]
fn validate_vectors() {
    let params = mainnet_params();
    let pow_limit = BigInt::from_bytes_be(Sign::Plus, &params.pow_limit.to_be_bytes());
    let data = include_str!("data/validate_vectors.txt");

    let mut counts = [0usize; 3];
    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "checktx" => {
                let flags = AgendaFlags(f[1].parse().expect("flags"));
                let (tx, _) = MsgTx::from_bytes(&unhex(f[2])).expect("tx");
                let want = f[3];
                assert_eq!(
                    kind_of(check_transaction(&tx, &params, flags)),
                    want,
                    "{line}"
                );
                counts[0] += 1;
            }
            "pos" => {
                let pos_limit: i64 = f[1].parse().expect("limit");
                let (block, _) = MsgBlock::from_bytes(&unhex(f[2])).expect("block");
                let want = f[3];
                assert_eq!(
                    kind_of(check_proof_of_stake(&block, pos_limit)),
                    want,
                    "{line}"
                );
                counts[1] += 1;
            }
            "pow" => {
                let skip: bool = f[1].parse().expect("skip");
                let (header, _) = BlockHeader::from_bytes(&unhex(f[2])).expect("header");
                let want = f[3];
                assert_eq!(
                    kind_of(check_proof_of_work_sanity(&header, &pow_limit, skip)),
                    want,
                    "{line}"
                );
                counts[2] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [400, 60, 60], "row counts");
}
