// SPDX-License-Identifier: ISC
//! The treasury state mirror is a recent window over the database, not
//! the whole bucket (review finding B1-p#7).
//!
//! dcrd keeps no treasury rows in memory: `calculateTreasuryBalance`
//! and the expenditure walks read `dbFetchTreasuryBalance` on every
//! lookup (`treasury.go:379-387`).  The port loaded the whole bucket at
//! startup and never evicted a row, about 548k rows on mainnet today.
//! This replays dcrd's treasury corpus into a database-backed chain,
//! pruning the mirrors down to two blocks after every block, and checks
//! every balance, expenditure limit and treasury spend verdict dcrd
//! recorded still comes out the same through the database fallback.
//! It also pins the two ways a row read through that fallback can go
//! wrong: a damaged row must fail the expenditure check as in dcrd, not
//! end the walk, and a chain without a database must keep its rows.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::HashMap;

use dcroxide_blockchain::RuleErrorKind;
use dcroxide_blockchain::blockindex::BlockStatus;
use dcroxide_blockchain::chaindb::TREASURY_BUCKET_NAME;
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::treasurydb::{db_fetch_treasury_balance, serialize_treasury_state};
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

fn raw_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const CORPUS: &str = include_str!("data/treasury_vectors.txt");

/// Feed every corpus block to the chain the way `treasury_vectors.rs`
/// feeds them, plus, for a database-backed chain, the stored body the
/// pruned mirrors fall back to, and prune to two blocks after each
/// one.  Every recorded verdict follows the last block in the
/// corpus, so replaying the blocks first changes no verdict.  Returns
/// the most rows the treasury mirror held at once.
fn replay_blocks_pruned(chain: &mut Chain, params: &Params) -> usize {
    let mut most_rows = 0;
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
        if let Some(db) = chain.db.as_ref() {
            db.update(|tx| tx.store_block(&block).map(|_| ()))
                .expect("store block");
        }
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
        most_rows = most_rows.max(chain.treasury_state.len());
    }
    most_rows
}

#[test]
fn treasury_verdicts_hold_with_the_mirror_pruned_to_two_blocks() {
    let params = simnet_params();
    let dir = tempfile::tempdir().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let mut chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("open chain");
    let most_rows = replay_blocks_pruned(&mut chain, &params);

    let mut tspends: HashMap<String, MsgTx> = HashMap::new();
    let mut checked = 0;
    for line in CORPUS.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let node_of =
            |chain: &Chain, s: &str| chain.index.lookup_node(&parse_hash(s)).expect("node");
        match f[0] {
            "tspend" => {
                let (tx, _) = MsgTx::from_bytes(&unhex(f[2])).expect("tspend");
                tspends.insert(f[1].to_string(), tx);
            }
            "tbal" => {
                let node = node_of(&chain, f[1]);
                assert_eq!(
                    chain.calculate_treasury_balance(node, &params).to_string(),
                    f[2],
                    "{line}"
                );
                checked += 1;
            }
            "mte" => {
                let node = node_of(&chain, f[1]);
                let amount = chain
                    .max_treasury_expenditure(node, &params)
                    .expect("max expenditure");
                assert_eq!(amount.to_string(), f[2], "{line}");
                checked += 1;
            }
            "tsc" => {
                let node = node_of(&chain, f[1]);
                let (block, _) = MsgBlock::from_bytes(&unhex(f[2])).expect("block");
                let kind = match chain.tspend_checks(node, &block, &params) {
                    Ok(()) => "ok".to_string(),
                    Err(e) => e.kind.kind_name().to_string(),
                };
                assert_eq!(kind, f[3], "{line}");
                checked += 1;
            }
            "tcv" => {
                let node = node_of(&chain, f[1]);
                match chain.tspend_count_votes(node, &tspends[f[2]], &params) {
                    Ok((_, _, yes, no)) => {
                        assert_eq!(yes.to_string(), f[3], "{line}: yes");
                        assert_eq!(no.to_string(), f[4], "{line}: no");
                    }
                    Err(e) => assert_eq!("err", f[3], "{line}: unexpected error {e}"),
                }
                checked += 1;
            }
            "thv" => {
                let node = node_of(&chain, f[1]);
                let failed = chain
                    .check_tspend_has_votes(node, &tspends[f[2]], &params)
                    .is_err();
                assert_eq!(failed.to_string(), f[3], "{line}");
                checked += 1;
            }
            "trow" => {
                // The row itself, read where it now lives.
                let hash = parse_hash(f[1]);
                let db = chain.db.as_ref().expect("db-backed");
                let tx = db.begin(false).expect("begin read");
                let ts = db_fetch_treasury_balance(&tx, &hash)
                    .expect("read")
                    .expect("treasury state row");
                tx.rollback().expect("rollback");
                let raw = serialize_treasury_state(&ts).expect("serialize");
                assert_eq!(raw_hex(&raw), f[2], "{line}");
                checked += 1;
            }
            _ => {}
        }
    }
    assert_eq!(checked, 26, "every recorded verdict was checked");
    assert!(
        most_rows <= 3,
        "the treasury mirror held {most_rows} rows with a two-block window"
    );
}

/// dcrd's `sumPastTreasuryChanges` ends its walk only on
/// `errDbTreasury`, the missing key (`treasury.go:595-606`); a row that
/// does not decode is returned as the error, and `tspendChecks` turns
/// it into `ErrInvalidExpenditure` (`validate.go:4138-4145`).  Only
/// `calculateTreasuryBalance` reads every fetch error as a zero balance
/// (`treasury.go:379-391`).  With the mirror a recent window, the
/// damaged row is read from the database, and reading it as the end of
/// the records would shorten the expenditure history instead.
#[test]
fn a_corrupt_treasury_row_below_the_window_fails_the_expenditure_check() {
    let params = simnet_params();
    let dir = tempfile::tempdir().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let mut chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("open chain");
    replay_blocks_pruned(&mut chain, &params);

    // The first recorded treasury spend check dcrd accepted.
    let line = CORPUS
        .lines()
        .find(|l| l.starts_with("tsc ") && l.ends_with(" ok"))
        .expect("an accepted tspend check");
    let f: Vec<&str> = line.split(' ').collect();
    let node = chain
        .index
        .lookup_node(&parse_hash(f[1]))
        .expect("pre-TVI node");
    let (block, _) = MsgBlock::from_bytes(&unhex(f[2])).expect("block");
    assert!(
        chain.tspend_checks(node, &block, &params).is_ok(),
        "the undamaged chain accepts the block"
    );

    // Damage the row five blocks back: inside the expenditure policy
    // window, outside the mirror, and neither of the two rows the
    // balance reads (the node's own and its coinbase-maturity
    // ancestor's).
    let victim = chain.store.relative_ancestor(node, 5).expect("ancestor");
    let victim_hash = chain.store.node(victim).hash;
    assert!(
        !chain.treasury_state.contains_key(&victim_hash.0),
        "the damaged row must be read from the database"
    );
    let damage = |chain: &Chain, hash: Hash| {
        chain
            .db
            .as_ref()
            .expect("db-backed")
            .update(|tx| {
                tx.metadata()
                    .bucket(TREASURY_BUCKET_NAME)
                    .expect("treasury bucket")
                    .put(&hash.0, &[])
            })
            .expect("damage the row");
    };
    damage(&chain, victim_hash);

    let err = chain
        .max_treasury_expenditure(node, &params)
        .expect_err("a corrupt row in the window is an error, not the end of the records");
    assert_eq!(
        err.description,
        "unexpected end of data while reading treasury balance"
    );
    let err = chain
        .tspend_checks(node, &block, &params)
        .expect_err("dcrd rejects the block");
    assert_eq!(err.kind, RuleErrorKind::InvalidExpenditure, "{err:?}");
    assert_eq!(
        err.description,
        "block contains a TSpend that has an invalid expenditure: unexpected end of data \
         while reading treasury balance"
    );

    // The balance alone reads a damaged row as zero, as dcrd's does.
    assert_ne!(chain.calculate_treasury_balance(node, &params), 0);
    // The node's own row may still be in the mirror; drop that copy so
    // the damaged database row is the one read.
    let own = chain.store.node(node).hash;
    chain.treasury_state.remove(&own.0);
    damage(&chain, own);
    assert_eq!(chain.calculate_treasury_balance(node, &params), 0);
}

/// The public `prune_chain_memory` clears the stake fields on any chain,
/// as dcrd's `pruneStakeNodes` does, but evicts the recent-window
/// mirrors only when a database backs them.  Without one the treasury
/// mirror is the only copy, and a row evicted from it reads as a zero
/// balance and a shortened expenditure history rather than failing.
#[test]
fn pruning_a_chain_without_a_database_keeps_its_treasury_rows() {
    let params = simnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    replay_blocks_pruned(&mut chain, &params);

    let mut checked = 0;
    for line in CORPUS.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let node_of =
            |chain: &Chain, s: &str| chain.index.lookup_node(&parse_hash(s)).expect("node");
        match f[0] {
            "tbal" => {
                let node = node_of(&chain, f[1]);
                assert_eq!(
                    chain.calculate_treasury_balance(node, &params).to_string(),
                    f[2],
                    "{line}"
                );
                checked += 1;
            }
            "mte" => {
                let node = node_of(&chain, f[1]);
                let amount = chain
                    .max_treasury_expenditure(node, &params)
                    .expect("max expenditure");
                assert_eq!(amount.to_string(), f[2], "{line}");
                checked += 1;
            }
            _ => {}
        }
    }
    assert_eq!(
        checked, 7,
        "every balance and expenditure verdict was checked"
    );

    // The stake fields below the keep window are still pruned; the
    // body, the only copy, stays.
    let tip = chain.best_chain.tip().expect("tip");
    let deep = chain.store.relative_ancestor(tip, 5).expect("ancestor");
    assert!(chain.store.node(deep).stake_node.is_none());
    assert!(!chain.store.node(deep).ticket_info_populated);
    assert!(chain.blocks.contains_key(&chain.store.node(deep).hash.0));
}
