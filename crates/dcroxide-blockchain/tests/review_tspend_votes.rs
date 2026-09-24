// SPDX-License-Identifier: ISC
//! The treasury spend vote tally over a node without block data
//! returns an error instead of aborting (review finding PW05#2).
//!
//! `gettreasuryspendvotes` resolves its block argument through any
//! indexed header, so a header whose body was never stored -- the best
//! header during initial sync, a side-chain header nobody downloaded --
//! reaches `tspend_count_votes`.  dcrd's `tSpendCountVotes` returns
//! `fetchBlockByNode`'s error there (`treasury.go:1026-1030`) and the
//! handler answers with an internal RPC error; the port `expect`ed the
//! body and, under `panic = "abort"`, took the whole node down.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::regnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_testutil::unhex;
use dcroxide_wire::{MsgBlock, MsgTx};

#[test]
fn tallying_votes_over_a_header_only_node_is_an_error() {
    let params = regnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    let mut now = 0;
    let mut header_only = None;
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("now"),
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                if f[1] == "bbm3" {
                    // Accept only the header of this one.
                    chain
                        .process_block_header(&block.header, now, &params)
                        .expect("header");
                    header_only = Some(block.header.block_hash());
                    break;
                }
                let (_, errs) = chain.process_block(&block, now, &params);
                assert!(errs.is_empty(), "{}: {errs:?}", f[1]);
            }
            _ => {}
        }
    }
    let hash = header_only.expect("bbm3 in the battery");
    let node = chain.index.lookup_node(&hash).expect("indexed header");
    assert!(
        !chain.store.node(node).status.have_data(),
        "the node must be header-only"
    );

    // A treasury spend whose voting window covers the block after it.
    let next_height = chain.store.node(node).height + 1;
    let tvi = params.treasury_vote_interval;
    let mul = params.treasury_vote_interval_multiplier;
    let expiry = (next_height as u32..)
        .find(|&e| dcroxide_standalone::inside_tspend_window(next_height, e, tvi, mul))
        .expect("an expiry whose window covers the height");
    let tspend = MsgTx {
        expiry,
        ..MsgTx::default()
    };

    let err = chain
        .tspend_count_votes(node, &tspend, &params)
        .expect_err("a header-only node has no votes to count");
    assert_eq!(err, format!("block {hash} does not exist"));
}
