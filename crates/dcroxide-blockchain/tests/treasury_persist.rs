// SPDX-License-Identifier: ISC
//! The treasury rows a connected block produces reach the database, and
//! survive a reopen without a clean shutdown (RVW-008).
//!
//! `connect_block` used to commit the best state, spend journal, stake
//! db, filter and header commitments in one transaction and then open a
//! *second* one for the treasury rows.  dcrd writes both inside its
//! single `db.Update` (`internal/blockchain/chain.go:671-719`).  Because
//! the metadata cache flushes the preceding window at the *start* of a
//! commit, the durable boundary could land between the two: a best state
//! on disk whose treasury row is not.  Nothing repairs that —
//! `initialize_utxo_state` replays the UTXO set, not the treasury bucket
//! — and `calculate_treasury_balance` reads a missing row as zero, which
//! every descendant then inherits.
//!
//! `treasury_vectors.rs` pins the values against dcrd but drives a
//! `Chain::new` memory chain with no database at all, and
//! `reorg_vectors.txt` -- the corpus that does drive a database-backed
//! chain -- carries no tspends, so the write path itself had no
//! coverage at all.  This exercises it against a real store.
//!
//! The atomicity that motivates the change is not what this asserts.
//! Observing it needs a durability boundary landing between the two
//! writes, which needs the blocks to go through `connect_block`; the
//! treasury corpus carries a zero `size` header field and is fed past
//! validation by hand, so it cannot.  Atomicity now holds by
//! construction instead -- there is one transaction, and no second one
//! to tear against.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::blockindex::BlockStatus;
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::treasurydb::{db_fetch_treasury_balance, db_fetch_tspend};
use dcroxide_chaincfg::simnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_testutil::unhex;
use dcroxide_wire::{MsgBlock, MsgTx};

/// Replay the treasury corpus into a database-backed chain, exactly as
/// `treasury_vectors.rs` replays it into a memory one.
fn replay(chain: &mut Chain, params: &dcroxide_chaincfg::Params) -> (Vec<Hash>, Vec<Hash>) {
    let data = include_str!("data/treasury_vectors.txt");
    let mut block_hashes = Vec::new();
    let mut tspend_hashes = Vec::new();

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "tspend" => {
                let (tx, _) = MsgTx::from_bytes(&unhex(f[2])).expect("tspend");
                tspend_hashes.push(tx.tx_hash());
            }
            "blk" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[1])).expect("block");
                let prev = chain
                    .index
                    .lookup_node(&block.header.prev_block)
                    .expect("previous node");
                let id = chain.store.new_node(&block.header, Some(prev));
                {
                    let node = chain.store.node_mut(id);
                    node.status =
                        BlockStatus(BlockStatus::DATA_STORED.0 | BlockStatus::VALIDATED.0);
                    node.is_fully_linked = true;
                }
                chain.index.add_node(&chain.store, id);
                chain
                    .blocks
                    .insert(block.header.block_hash().0, block.clone());
                chain
                    .fetch_stake_node(id, params)
                    .unwrap_or_else(|e| panic!("{line}: stake node: {e:?}"));
                chain
                    .put_treasury_records(id, &block, params)
                    .unwrap_or_else(|e| panic!("{line}: treasury records: {e:?}"));
                chain.best_chain.set_tip(&chain.store, Some(id));
                block_hashes.push(block.header.block_hash());
            }
            _ => {}
        }
    }
    (block_hashes, tspend_hashes)
}

/// Every block's balance row and every mined tspend's block list is
/// readable straight off disk in a fresh process-equivalent handle.
///
/// `cache_flush_interval_secs = 0` makes every commit flush the
/// preceding window, so the rows travel through the overlay rather than
/// sitting in it for the whole run.
#[test]
fn treasury_rows_reach_the_database() {
    let params = simnet_params();
    let dir = tempfile::tempdir().expect("tempdir");
    let mut opts = Options::new(dir.path().join("chain"), params.net.0);
    opts.cache_flush_interval_secs = 0;

    let (block_hashes, tspend_hashes) = {
        let db = Database::create(&opts).expect("create database");
        let mut chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("open chain");
        let out = replay(&mut chain, &params);
        chain
            .db
            .as_ref()
            .expect("db-backed")
            .close()
            .expect("close");
        out
    };

    assert_eq!(
        block_hashes.len(),
        240,
        "the corpus must be the 240-block chain"
    );
    assert_eq!(
        tspend_hashes.len(),
        4,
        "the corpus must carry its four tspends"
    );

    let db = Database::open(&opts).expect("reopen database");
    let tx = db.begin(false).expect("begin read");

    let mut missing = Vec::new();
    for hash in &block_hashes {
        if db_fetch_treasury_balance(&tx, hash)
            .expect("read the treasury bucket")
            .is_none()
        {
            missing.push(*hash);
        }
    }
    assert!(
        missing.is_empty(),
        "{} of {} blocks never wrote a treasury balance row; first: {:?}",
        missing.len(),
        block_hashes.len(),
        missing.first(),
    );

    // The relocated tspend loop: at least one of the corpus tspends is
    // mined, and a mined one must name the blocks it appears in.
    let mined: Vec<&Hash> = tspend_hashes
        .iter()
        .filter(|h| {
            db_fetch_tspend(&tx, h)
                .expect("read the tspend bucket")
                .is_some_and(|blocks| !blocks.is_empty())
        })
        .collect();
    assert!(
        !mined.is_empty(),
        "no tspend row reached the database; the relocated db_put_tspend loop is untested",
    );
    for hash in mined {
        let blocks = db_fetch_tspend(&tx, hash)
            .expect("read the tspend bucket")
            .unwrap_or_default();
        for b in &blocks {
            assert!(
                block_hashes.contains(b),
                "tspend {hash:?} names block {b:?}, which is not in the corpus",
            );
        }
    }
    tx.rollback().expect("rollback");
}
