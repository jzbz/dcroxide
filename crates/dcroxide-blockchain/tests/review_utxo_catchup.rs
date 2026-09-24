// SPDX-License-Identifier: ISC
//! The startup UTXO catch-up replay stops on a shutdown request (review
//! finding XC7#7), and replays to the same set now that each block is
//! loaded once (B1-p#12).
//!
//! dcrd's `UtxoCache.Initialize` checks `b.interrupt` before every block
//! it detaches or replays and returns `errInterruptRequested`
//! (`utxocache.go:884-889`, `:974-979`), so SIGINT or SIGTERM during a
//! post-crash catch-up stops the node within a block.  The port's replay
//! took no interrupt at all: a stop request waited for the whole replay.
//!
//! The replay also reuses the block it just attached as the next one's
//! parent (dcrd's `prevBlockAttached`) instead of loading every block
//! twice; the reopen below checks that it still converges on the
//! reference set.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use dcroxide_blockchain::RuleErrorKind;
use dcroxide_blockchain::chaindb::{ChainDbError, db_fetch_utxo_set_state};
use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::{Params, regnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;
use tempfile::TempDir;

/// Replay the full block battery with the clock shifted forward by
/// `clock_offset`.  Two days makes every block look old, so the chain
/// never latches to current and only the periodic interval flushes the
/// UTXO cache: the initial-sync cadence whose unflushed tail an unclean
/// shutdown loses.
fn replay_battery(chain: &mut Chain, params: &Params, clock_offset: i64) {
    let mut now: i64 = 0;
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => {
                now = f[1]
                    .parse::<i64>()
                    .expect("now")
                    .saturating_add(clock_offset)
            }
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                let (_, errs) = chain.process_block(&block, now, params);
                let is_orphan = errs.len() == 1 && errs[0].kind == RuleErrorKind::MissingParent;
                assert!(errs.is_empty() || is_orphan, "accept {}: {errs:?}", f[1]);
            }
            _ => {}
        }
    }
}

fn recorded_flush_hash(db: &Database) -> Hash {
    let mut recorded = None;
    db.view(|tx| {
        recorded = db_fetch_utxo_set_state(tx).expect("state");
        Ok(())
    })
    .expect("read state");
    recorded.expect("a recorded utxo set state").last_flush_hash
}

#[test]
fn a_shutdown_request_stops_the_startup_utxo_catch_up() {
    let params = regnet_params();

    // The reference set: a clean run whose stats force a full flush.
    let ref_dir = TempDir::new().expect("tempdir");
    let ref_opts = Options::new(ref_dir.path().join("chain"), params.net.0);
    let mut reference = Chain::open(
        Database::create(&ref_opts).expect("create database"),
        &params,
        Hash::ZERO,
        true,
        0,
    )
    .expect("open chain");
    replay_battery(&mut reference, &params, 0);
    let expected = reference.fetch_utxo_stats().expect("reference stats");

    // The crash run: the per-block metadata reaches the store, but the
    // recorded utxo set state stays behind the tip.
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let mut chain = Chain::open(
        Database::create(&opts).expect("create database"),
        &params,
        Hash::ZERO,
        true,
        0,
    )
    .expect("open chain");
    replay_battery(&mut chain, &params, 48 * 60 * 60);
    let tip_hash = chain
        .best_chain
        .tip()
        .map(|t| chain.store.node(t).hash)
        .expect("tip");
    let db = chain.db.clone().expect("db");
    let behind = recorded_flush_hash(&db);
    assert_ne!(behind, tip_hash, "the crash run must leave a gap to replay");
    db.flush().expect("db flush");
    drop(chain);
    db.close().expect("close");
    drop(db);

    // A shutdown already requested when the replay starts stops it
    // before the first block, with dcrd's error, and leaves the
    // recorded state where it was.
    let interrupt = Arc::new(AtomicBool::new(true));
    let db = Database::open(&opts).expect("reopen database");
    let res = Chain::open_with_interrupt(
        db.clone(),
        &params,
        Hash::ZERO,
        false,
        0,
        Some(Arc::clone(&interrupt)),
    );
    match res {
        Err(ChainDbError::Interrupted) => {}
        Err(e) => panic!("expected the interrupt error, got {e:?}"),
        Ok(_) => panic!("the catch-up replay ignored the shutdown request"),
    }
    assert_eq!(
        ChainDbError::Interrupted.to_string(),
        "interrupt requested",
        "dcrd's errInterruptRequested text"
    );
    assert_eq!(
        recorded_flush_hash(&db),
        behind,
        "an interrupted catch-up must not move the recorded state"
    );
    db.close().expect("close");
    drop(db);

    // With no shutdown requested the same open replays the whole gap,
    // loading each block once, and converges on the reference set.
    interrupt.store(false, Ordering::SeqCst);
    let mut chain = Chain::open_with_interrupt(
        Database::open(&opts).expect("reopen database"),
        &params,
        Hash::ZERO,
        false,
        0,
        Some(interrupt),
    )
    .expect("the uninterrupted catch-up completes");
    assert_eq!(
        chain.best_chain.tip().map(|t| chain.store.node(t).hash),
        Some(tip_hash)
    );
    let stats = chain.fetch_utxo_stats().expect("caught-up stats");
    assert_eq!(stats, expected, "the replay converges on the reference set");
}
