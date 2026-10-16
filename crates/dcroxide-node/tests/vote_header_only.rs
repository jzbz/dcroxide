// SPDX-License-Identifier: ISC
//! A vote on a block the node knows only by its header, through the
//! daemon's own pool over a real chain.
//!
//! dcrd master checks that the block a vote votes on is known at the
//! height the vote claims (`6816d9de`, `checkVoteBlock`), from the block
//! index, where a block known only by its header has a node too
//! (`internal/blockchain/chain.go:1666-1673`).  After the scripts it asks
//! for the block's winning tickets (`023c42ff`, `checkVoteTicket`), from
//! `LotteryDataForBlock`, whose stake node needs the block's ticket data
//! (`stakenode.go:63-84`).  So between a block's header and its data, a
//! vote on it clears the first check and fails the lookup with a plain
//! error: the vote is not accepted, not relayed, and not a rule violation.
//! The port reproduces that: `NodePoolChain` answers headers from the
//! index and winners from `Chain::lottery_data_for_block`.
//!
//! Here a vote from dcrd's full block battery is offered three times:
//! before the chain has its block's header, refused as a vote on an
//! unknown block; with the header alone, refused with a plain error; and
//! with the block, accepted.

use std::sync::{Arc, Mutex};

use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};
use dcroxide_mempool::PoolError;
use dcroxide_stake::{TxType, determine_tx_type, ssgen_block_voted_on};
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;

/// The battery's generation time and its main chain, one block per
/// height from 1.
fn main_chain(params: &dcroxide_chaincfg::Params) -> (i64, Vec<MsgBlock>) {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcroxide-blockchain/tests/data/fullblock_vectors.txt"
    );
    let data = std::fs::read_to_string(path).expect("fullblock vectors");
    let mut now = 0;
    let mut tip = params.genesis_hash;
    let mut blocks = Vec::new();
    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("generation time"),
            // accept <name> <mainchain> <orphan> <blockhex>
            "accept" if f[2] == "true" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                if block.header.prev_block == tip {
                    tip = block.header.block_hash();
                    blocks.push(block);
                }
            }
            _ => {}
        }
    }
    (now, blocks)
}

#[test]
fn a_vote_on_a_block_known_only_by_its_header_fails_with_a_plain_error() {
    let params = dcroxide_chaincfg::regnet_params();
    let (now, blocks) = main_chain(&params);

    // The votes in the block two above stake validation height, on its
    // parent: with the chain stopped one block short of that parent, the
    // tip is at stake validation height, so the votes clear the pool's
    // stake validation height gate.
    let svh = params.stake_validation_height;
    let voting = blocks
        .iter()
        .position(|b| i64::from(b.header.height) == svh + 2)
        .expect("the battery passes stake validation height");
    let voted = &blocks[voting - 1];
    let vote = blocks[voting]
        .stransactions
        .iter()
        .find(|tx| determine_tx_type(tx) == TxType::SSGen)
        .expect("a vote")
        .clone();
    assert_eq!(ssgen_block_voted_on(&vote).0, voted.header.block_hash());

    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    for block in &blocks[..voting - 1] {
        let (_, errs) = chain
            .lock()
            .expect("chain")
            .process_block(block, now, &params);
        assert!(errs.is_empty(), "battery block must accept: {errs:?}");
    }
    // The battery's signature scripts are not push-only, so the pool
    // accepts non-standard transactions, as `--acceptnonstd` does.
    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &params,
        true,
        100,
        10000,
        false,
        true,
    );
    let offer = || {
        tx_pool
            .lock()
            .expect("tx pool")
            .process_transaction(&vote, false, true, 0)
    };

    // No header: a vote on an unknown block.
    let err = offer().expect_err("the voted block is unknown");
    assert_eq!(err.kind_name(), "ErrVoteBlockUnknown", "{err:?}");

    // The header alone: the block check passes and the winners lookup
    // fails, a plain error.
    chain
        .lock()
        .expect("chain")
        .process_block_header(&voted.header, now, &params)
        .expect("the header is accepted");
    let err = offer().expect_err("the voted block has no data");
    assert!(matches!(err, PoolError::Other(_)), "{err:?}");

    // The block: the same vote is accepted.
    let (_, errs) = chain
        .lock()
        .expect("chain")
        .process_block(voted, now, &params);
    assert!(errs.is_empty(), "the voted block must accept: {errs:?}");
    let accepted = offer().expect("the vote is accepted once its block is");
    assert_eq!(accepted, vec![vote.tx_hash()]);
}
