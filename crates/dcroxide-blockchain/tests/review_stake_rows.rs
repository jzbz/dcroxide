// SPDX-License-Identifier: ISC
//! A ticket database row that cannot be read fails the stake-node fetch
//! instead of aborting the node (review finding S1-p#2).
//!
//! Regenerating a stake node that has left memory walks back from the
//! tip, undoing each block with the undo data and new tickets stored for
//! the height below it.  dcrd reads those rows with
//! `DbFetchBlockUndoData` and `DbFetchNewTickets` and returns their
//! error through `fetchStakeNode` (`tickets.go:762-779`), so a missing
//! or corrupt row rejects the operation while the node keeps running.
//! The port turned every failure into `None` and then called `expect`,
//! which under the release profile's `panic = "abort"` killed the
//! process.

use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::{Params, regnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_stake::ticketdb::{STAKE_BLOCK_UNDO_DATA_BUCKET_NAME, TICKETS_IN_BLOCK_BUCKET_NAME};
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;
use tempfile::TempDir;

/// A database-backed chain over the battery up to `bbm10`, with every
/// stake node more than two blocks below the tip pruned, and the node
/// five blocks below the tip, whose stake node now has to be rebuilt
/// from the ticket rows.
fn pruned_chain(
    dir: &TempDir,
    params: &Params,
) -> (Chain, dcroxide_blockchain::blockindex::NodeId) {
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let mut chain = Chain::open(db, params, Hash::ZERO, false, 0).expect("open chain");
    let mut now = 0;
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("now"),
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                let (_, errs) = chain.process_block(&block, now, params);
                assert!(errs.is_empty(), "{}: {errs:?}", f[1]);
                if f[1] == "bbm10" {
                    break;
                }
            }
            _ => {}
        }
    }
    let tip = chain.best_chain.tip().expect("tip");
    let target = chain
        .store
        .relative_ancestor(tip, 5)
        .expect("an ancestor below the keep window");
    chain.prune_chain_memory(2);
    assert!(
        chain.store.node(target).stake_node.is_none(),
        "the target's stake node was pruned"
    );
    (chain, target)
}

/// Replace (or with `None`, delete) a height's row in a ticket bucket.
fn set_row(chain: &Chain, bucket: &[u8], height: i64, row: Option<&[u8]>) {
    let key = (height as u32).to_le_bytes();
    chain
        .db
        .as_ref()
        .expect("db")
        .update(|tx| {
            let meta = tx.metadata();
            let b = meta.bucket(bucket).expect("ticket bucket");
            match row {
                Some(row) => b.put(&key, row),
                None => b.delete(&key),
            }
        })
        .expect("rewrite the row");
}

#[test]
fn a_missing_undo_row_fails_the_stake_node_fetch() {
    let params = regnet_params();
    let dir = TempDir::new().expect("tempdir");
    let (mut chain, target) = pruned_chain(&dir, &params);
    let height = chain.store.node(target).height;
    set_row(&chain, STAKE_BLOCK_UNDO_DATA_BUCKET_NAME, height, None);

    let err = chain
        .fetch_stake_node(target, &params)
        .expect_err("a missing undo row must fail the fetch");
    assert!(
        err.description.contains("missing key") && err.description.contains("block undo data"),
        "the ticket database's missing key error: {err:?}"
    );

    // The node is still running and still answers for the tip.
    let tip = chain.best_chain.tip().expect("tip");
    assert!(chain.fetch_stake_node(tip, &params).is_ok());
}

#[test]
fn a_corrupt_new_tickets_row_fails_the_stake_node_fetch() {
    let params = regnet_params();
    let dir = TempDir::new().expect("tempdir");
    let (mut chain, target) = pruned_chain(&dir, &params);
    let height = chain.store.node(target).height;
    // Ticket hashes are 32 bytes apiece, so a 33-byte row is corrupt.
    set_row(
        &chain,
        TICKETS_IN_BLOCK_BUCKET_NAME,
        height,
        Some(&[7u8; 33]),
    );

    let err = chain
        .fetch_stake_node(target, &params)
        .expect_err("a corrupt new tickets row must fail the fetch");
    assert_eq!(
        err.description, "corrupt data found when deserializing ticket hashes",
        "the ticket database's decode error is carried"
    );
}
