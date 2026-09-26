// SPDX-License-Identifier: ISC
//! A ticket database failure carries dcrd's text, not a Rust debug dump
//! of the port's error types (review finding RG03#2).
//!
//! dcrd returns the error of its `stake` database entry points
//! unchanged: `LoadBestNode` out of `initChainState`
//! (`chainio.go:1721-1725`) and `WriteConnectedBestNode` out of
//! `connectBlock`'s update (`chain.go:687-690`).  A ticket database
//! `DBError` and a stake `RuleError` render as their bare description.
//! The port formatted the `StakeDbError` with `{:?}`, so a chain that
//! would not open reported `stake node: Rule(RuleError { kind: ... })`
//! and a drifted live bucket reported
//! `stake db: Ticket(TicketDbError { kind: MissingKey, ... })`.
//!
//! A failed block connect reaches its caller through
//! `persist_rule_error`, which rendered the database error with `{:?}`
//! as well, under a `chain database failure: ` prefix; it now renders
//! every database error but an `ErrCorruption` as its own text, so the
//! connect's error is dcrd's text alone.

use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::regnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_stake::stakedb::{db_fetch_best_state, db_put_best_state};
use dcroxide_stake::ticketdb::LIVE_TICKETS_BUCKET_NAME;
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;
use tempfile::TempDir;

/// A chain whose stake best state names a block other than the tip
/// fails to open with dcrd's `ErrDatabaseCorrupt` text alone.
#[test]
fn a_stake_node_that_will_not_load_reports_dcrds_text() {
    let params = regnet_params();
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("open chain");
    let db = chain.db.as_ref().expect("db-backed");
    db.update(|tx| {
        let mut state = db_fetch_best_state(tx).expect("stake best state");
        state.hash = Hash([7; 32]);
        db_put_best_state(tx, &state).expect("rewrite the stake best state");
        Ok(())
    })
    .expect("update");
    db.close().expect("close");
    drop(chain);

    let db = Database::open(&opts).expect("reopen database");
    let err = match Chain::open(db, &params, Hash::ZERO, false, 0) {
        Ok(_) => panic!("a stake best state off the tip must fail the open"),
        Err(err) => err,
    };
    assert_eq!(format!("{err}"), "best state corruption");
}

/// A winner whose live ticket row has gone missing fails the connect of
/// the next block with dcrd's `ErrMissingKey` text alone, not the
/// port's ticket or database error types.
#[test]
fn a_drifted_live_bucket_fails_the_connect_with_dcrds_text() {
    let params = regnet_params();
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let mut chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("open chain");

    let mut now = 0;
    let mut dropped = None;
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("now"),
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                // The first block that votes: drop the live row of a
                // ticket one of its votes spends.
                if let Some(vote) = block
                    .stransactions
                    .iter()
                    .find(|tx| dcroxide_stake::is_ssgen(tx))
                {
                    let ticket = vote.tx_in[1].previous_out_point.hash;
                    chain
                        .db
                        .as_ref()
                        .expect("db-backed")
                        .update(|tx| {
                            let meta = tx.metadata();
                            let live = meta.bucket(LIVE_TICKETS_BUCKET_NAME).expect("live bucket");
                            assert!(live.get(&ticket.0).is_some(), "the winner is live");
                            live.delete(&ticket.0)
                        })
                        .expect("drop the live row");
                    let (_, errs) = chain.process_block(&block, now, &params);
                    dropped = Some((ticket, errs));
                    break;
                }
                let (_, errs) = chain.process_block(&block, now, &params);
                assert!(errs.is_empty(), "{}: {errs:?}", f[1]);
            }
            _ => {}
        }
    }

    let (ticket, errs) = dropped.expect("the battery has a block that votes");
    let want = format!("missing key {ticket} to delete");
    let err = errs
        .iter()
        .find(|e| e.description.contains(&want))
        .unwrap_or_else(|| panic!("the connect fails with {want:?}: {errs:?}"));
    assert_eq!(
        err.description, want,
        "the ticket database error is carried as its own text"
    );
    assert!(
        !err.kind.is_rule_violation(),
        "a local fault, not the block's"
    );
}
