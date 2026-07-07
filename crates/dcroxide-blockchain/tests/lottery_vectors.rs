// SPDX-License-Identifier: ISC
//! Replay of dcrd's LotteryDataForBlock battery
//! (`data/lottery_vectors.txt`): a real regnet chain built past the
//! stake validation height from dcrd's own fullblocktests generator,
//! with dcrd's real LotteryDataForBlock exercised directly.  The block
//! bytes are recorded so the chain engine here rebuilds the same chain
//! and queries the same lottery state, comparing the winning tickets,
//! the pool size, and the PRNG final state for blocks above and below
//! the stake enabled height and the unknown-block error.  The block
//! content varies per generation, so the blocks are frozen alongside
//! the expectations.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::regnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_testutil::{hex, unhex};
use dcroxide_wire::MsgBlock;

fn parse_hash(s: &str) -> Hash {
    let bytes = unhex(s);
    let mut h = [0u8; 32];
    for (i, b) in bytes.iter().rev().enumerate() {
        h[i] = *b;
    }
    Hash(h)
}

#[test]
fn lottery_data_matches_dcrd() {
    let params = regnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    let data = include_str!("data/lottery_vectors.txt");

    let now: i64 = data
        .lines()
        .find_map(|l| l.strip_prefix("now|"))
        .expect("now row")
        .parse()
        .unwrap();

    for line in data.lines() {
        if let Some(rest) = line.strip_prefix("blk|") {
            let hex_block = rest.split('|').nth(1).unwrap();
            let (block, _) = MsgBlock::from_bytes(&unhex(hex_block)).expect("block");
            let (_, errs) = chain.process_block(&block, now, &params);
            assert!(errs.is_empty(), "block rejected: {errs:?}");
        }
    }

    for line in data.lines() {
        let f: Vec<&str> = line.split('|').collect();
        if f[0] != "ldb" {
            continue;
        }
        // ldb|name|hash|ok|winnerscsv|poolsize|finalstatehex  OR  ldb|name|hash|err|msg
        let name = f[1];
        let hash = parse_hash(f[2]);
        let out = chain.lottery_data_for_block(&hash, &params);
        if f[3] == "err" {
            let err = out.unwrap_err();
            assert!(
                err.kind.to_string() == "ErrUnknownBlock",
                "row {name}: expected unknown-block error, got {:?}",
                err.kind
            );
        } else {
            let (winners, pool_size, final_state) =
                out.unwrap_or_else(|e| panic!("row {name}: {e:?}"));
            let want_winners: Vec<Hash> = if f[4].is_empty() {
                Vec::new()
            } else {
                f[4].split(',').map(parse_hash).collect()
            };
            assert_eq!(winners, want_winners, "row {name} winners");
            assert_eq!(pool_size.to_string(), f[5], "row {name} pool size");
            assert_eq!(hex(&final_state), f[6], "row {name} final state");
        }
    }
}
