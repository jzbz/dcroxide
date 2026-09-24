// SPDX-License-Identifier: ISC
//! The treasury spend vote tally runs without the chain (review
//! finding B3-p#3).
//!
//! dcrd's exported `TSpendCountVotes` and `CheckTSpendHasVotes` take no
//! `chainLock` (`treasury.go:1090-1102`, `:1155-1161`); the tally reads
//! each block of the voting window, up to TVI x multiplier of them,
//! through `fetchBlockByNode` under a database `View` only.  The
//! daemon's RPC and mining seams ran the whole walk under the chain
//! mutex, so a block waiting to connect waited for every read.  The
//! seams now capture the window with `Chain::tspend_vote_window` under
//! the mutex and tally after releasing it.  This replays dcrd's
//! treasury corpus into a database-backed chain pruned to two blocks,
//! captures every recorded tally's window, drops the chain, and checks
//! the tallies and verdicts dcrd recorded still come out of the
//! windows alone, with the bodies read back from the database.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::HashMap;

use dcroxide_blockchain::blockindex::BlockStatus;
use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::{Params, simnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_testutil::unhex;
use dcroxide_wire::{MsgBlock, MsgTx};

fn parse_hash(s: &str) -> Hash {
    let bytes = unhex(s);
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Hash(h)
}

const CORPUS: &str = include_str!("data/treasury_vectors.txt");

/// Feed every corpus block to a database-backed chain the way
/// `review_treasury_window.rs` does, storing each body and pruning the
/// recent window to two blocks after each one.
fn replay_blocks_pruned(chain: &mut Chain, params: &Params) {
    for line in CORPUS.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        if f[0] != "blk" {
            continue;
        }
        let (block, _) = MsgBlock::from_bytes(&unhex(f[1])).expect("block");
        let prev = chain
            .index
            .lookup_node(&block.header.prev_block)
            .expect("previous node");
        let id = chain.store.new_node(&block.header, Some(prev));
        {
            let node = chain.store.node_mut(id);
            node.status = BlockStatus(BlockStatus::DATA_STORED.0 | BlockStatus::VALIDATED.0);
            node.is_fully_linked = true;
        }
        chain.index.add_node(&chain.store, id);
        chain
            .db
            .as_ref()
            .expect("db-backed")
            .update(|tx| tx.store_block(&block).map(|_| ()))
            .expect("store block");
        chain.blocks.insert(
            block.header.block_hash().0,
            std::sync::Arc::new(block.clone()),
        );
        chain
            .fetch_stake_node(id, params)
            .unwrap_or_else(|e| panic!("stake node: {e:?}"));
        chain
            .put_treasury_records(id, &block, params)
            .unwrap_or_else(|e| panic!("treasury records: {e:?}"));
        chain.best_chain.set_tip(&chain.store, Some(id));
        chain.prune_chain_memory(2);
    }
}

#[test]
fn the_vote_tally_needs_nothing_from_the_chain() {
    let params = simnet_params();
    let dir = tempfile::tempdir().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let mut chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("open chain");
    replay_blocks_pruned(&mut chain, &params);
    assert!(
        chain.blocks.len() <= 3,
        "the window's bodies must come from the database"
    );

    // Capture every recorded tally's window, and the verdict the chain
    // itself gives, while the chain is alive.
    let mut tspends: HashMap<String, MsgTx> = HashMap::new();
    let mut captured = Vec::new();
    for line in CORPUS.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "tspend" => {
                let (tx, _) = MsgTx::from_bytes(&unhex(f[2])).expect("tspend");
                tspends.insert(f[1].to_string(), tx);
            }
            "tcv" | "thv" => {
                let node = chain.index.lookup_node(&parse_hash(f[1])).expect("node");
                let tspend = &tspends[f[2]];
                let window = chain.tspend_vote_window(node, tspend, &params);
                let locked_tally = chain.tspend_count_votes(node, tspend, &params);
                let locked_verdict = chain.check_tspend_has_votes(node, tspend, &params);
                captured.push((line, window, locked_tally, locked_verdict));
            }
            _ => {}
        }
    }
    assert_eq!(captured.len(), 10, "every recorded tally was captured");

    // Nothing of the chain survives; the database stays open through
    // the windows' own handles.
    drop(chain);

    for (line, window, locked_tally, locked_verdict) in captured {
        let f: Vec<&str> = line.split(' ').collect();
        let window = match window {
            Ok(window) => window,
            Err(e) => {
                // The window checks run at capture, before any block
                // is read, in dcrd's order.
                assert!(e.contains("outside of the valid window"), "{line}: {e}");
                match f[0] {
                    "tcv" => assert_eq!("err", f[3], "{line}: unexpected error {e}"),
                    _ => assert_eq!("true", f[3], "{line}: the check must fail"),
                }
                assert_eq!(locked_tally, Err(e.clone()), "{line}");
                assert_eq!(locked_verdict, Err(e), "{line}");
                continue;
            }
        };
        match f[0] {
            "tcv" => {
                let (_, _, yes, no) = window
                    .count_votes()
                    .unwrap_or_else(|e| panic!("{line}: unexpected error {e}"));
                assert_eq!(yes.to_string(), f[3], "{line}: yes");
                assert_eq!(no.to_string(), f[4], "{line}: no");
                assert_eq!(locked_tally, window.count_votes(), "{line}");
            }
            _ => {
                let verdict = window.check_has_votes(&params);
                assert_eq!(verdict.is_err().to_string(), f[3], "{line}");
                assert_eq!(locked_verdict, verdict, "{line}");
            }
        }
    }
}
