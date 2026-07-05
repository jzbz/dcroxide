// SPDX-License-Identifier: ISC
//! Replay of dcrd's context-free block sanity verdicts generated
//! inside dcrd's internal/blockchain package
//! (`data/blocksanity_vectors.txt`): `checkBlockHeaderSanity` over
//! random headers biased around the stake validation height boundary
//! and `checkBlockSanity` over assembled blocks with regular and
//! ticket-shaped stake transactions.  The dump uses a fixed
//! `MedianTimeSource` whose adjusted time is replayed here directly.

use dcroxide_blockchain::RuleError;
use dcroxide_blockchain::validate::{check_block_header_sanity, check_block_sanity};
use dcroxide_chaincfg::mainnet_params;
use dcroxide_testutil::unhex;
use dcroxide_wire::{BlockHeader, MsgBlock};

/// The fixed adjusted time the dump's time source returned.
const ADJUSTED_TIME: i64 = 1454954400;

fn kind_of(result: Result<(), RuleError>) -> String {
    match result {
        Ok(()) => "ok".to_string(),
        Err(e) => e.kind.kind_name().to_string(),
    }
}

#[test]
fn blocksanity_vectors() {
    let params = mainnet_params();
    let data = include_str!("data/blocksanity_vectors.txt");

    let mut counts = [0usize; 2];
    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "hdr" => {
                let skip: bool = f[1].parse().expect("skip");
                let (header, _) = BlockHeader::from_bytes(&unhex(f[2])).expect("header");
                let want = f[3];
                assert_eq!(
                    kind_of(check_block_header_sanity(
                        &header,
                        ADJUSTED_TIME,
                        skip,
                        &params
                    )),
                    want,
                    "{line}"
                );
                counts[0] += 1;
            }
            "block" => {
                // The dump always passes BFNoPoWCheck for full blocks.
                let (block, _) = MsgBlock::from_bytes(&unhex(f[1])).expect("block");
                let want = f[2];
                assert_eq!(
                    kind_of(check_block_sanity(&block, ADJUSTED_TIME, true, &params)),
                    want,
                    "{line}"
                );
                counts[1] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [250, 150], "row counts");
}
