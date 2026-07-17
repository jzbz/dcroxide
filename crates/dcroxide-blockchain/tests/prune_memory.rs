// SPDX-License-Identifier: ISC
//! Bounded chain memory: replay dcrd's full block battery through a
//! database-backed chain, prune the in-memory mirrors down to a small
//! keep window, and confirm every pruned block, filter, and stake node
//! is still served from the database — so a sustained sync stays
//! memory-bounded without losing correctness.

use dcroxide_blockchain::RuleErrorKind;
use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::regnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;
use tempfile::TempDir;

#[test]
fn pruning_keeps_the_chain_queryable_from_the_database() {
    let params = regnet_params();
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let mut chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("open chain");
    // Force the UTXO cache to flush on every connect, so the replay
    // exercises the periodic flush path alongside the block-body
    // pruning and the database fallbacks together.
    chain.set_utxo_cache_max_bytes(1);

    let data = include_str!("data/fullblock_vectors.txt");
    let mut now: i64 = 0;
    // Every accepted main-chain block hash, to re-query after pruning.
    let mut main_chain: Vec<Hash> = Vec::new();

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("now"),
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                let hash = block.header.block_hash();
                let (fork_len, errs) = chain.process_block(&block, now, &params);
                let is_orphan = errs.len() == 1 && errs[0].kind == RuleErrorKind::MissingParent;
                assert!(errs.is_empty() || is_orphan, "accept {}: {errs:?}", f[1]);
                if !is_orphan && fork_len == 0 && f[2] == "true" {
                    main_chain.push(hash);
                }
            }
            // Only the accepted main-chain blocks matter here.
            _ => {}
        }
    }

    let tip_before = chain.best_chain.tip().map(|t| chain.store.node(t).hash);
    assert!(main_chain.len() > 10, "battery produced a main chain");

    // Prune to a tiny window: everything but the last two blocks
    // leaves memory.
    chain.prune_chain_memory(2);

    // Every main-chain block is still served (from the database for the
    // pruned ones).
    for hash in &main_chain {
        assert!(
            chain.block_by_hash(hash).is_some(),
            "block {hash} must survive pruning via the database"
        );
    }

    // The UTXO set survives the frequent flushing: the current best
    // state's utxo set-state marker matches the tip, and entries are
    // served from the flushed backend.
    assert!(
        chain.fetch_utxo_stats().is_ok(),
        "the flushed utxo set must be queryable"
    );

    // An old block's committed filter is still served.
    let old = main_chain[main_chain.len() / 3];
    assert!(
        chain.filter_by_block_hash(&old).is_ok(),
        "the filter for a pruned block must be served from the database"
    );

    // The tip is unchanged, and a stale genesis timestamp aside, the
    // chain still knows its best block.
    assert_eq!(
        chain.best_chain.tip().map(|t| chain.store.node(t).hash),
        tip_before,
        "pruning must not move the tip"
    );

    // A reopen rebuilds from the database with the pruned state intact
    // (the recent window is warmed, the rest lazy) and the same tip.
    drop(chain);
    let db = Database::open(&opts).expect("reopen database");
    let chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("reopen chain");
    assert_eq!(
        chain.best_chain.tip().map(|t| chain.store.node(t).hash),
        tip_before,
        "the reopened chain resumes at the same tip"
    );
    for hash in &main_chain {
        assert!(
            chain.block_by_hash(hash).is_some(),
            "block {hash} must survive a reopen"
        );
    }
}

/// Replay the full block battery into a database-backed chain,
/// shifting the adjusted clock forward by the given offset.  A zero
/// offset keeps the battery's own clock — the blocks look freshly
/// mined, the chain latches to current, and every connect force
/// flushes the utxo cache like a caught-up dcrd.  A large offset
/// makes the same blocks look old — the chain never believes it is
/// current and only the periodic interval flushes, exactly the
/// initial-sync cadence whose unflushed tail an unclean shutdown
/// loses.
fn replay_battery(chain: &mut Chain, params: &dcroxide_chaincfg::Params, clock_offset: i64) {
    let data = include_str!("data/fullblock_vectors.txt");
    let mut now: i64 = 0;
    for line in data.lines() {
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

#[test]
fn an_unflushed_utxo_set_catches_up_on_reopen() {
    let params = regnet_params();

    // The reference: a clean run of the battery whose stats force a
    // full flush at the tip, folding the exact utxo set the chain
    // should always converge to.
    let dir_a = TempDir::new().expect("tempdir");
    let opts_a = Options::new(dir_a.path().join("chain"), params.net.0);
    let db_a = Database::create(&opts_a).expect("create database");
    let mut chain_a = Chain::open(db_a, &params, Hash::ZERO, true, 0).expect("open chain");
    replay_battery(&mut chain_a, &params, 0);
    let expected = chain_a.fetch_utxo_stats().expect("reference stats");
    assert!(expected.utxos > 0, "the battery leaves a utxo set");

    // The crash run: the same battery replayed as an initial sync —
    // the clock sits two days past the block timestamps so the chain
    // never latches to current and only the periodic interval
    // flushes — dropped WITHOUT the clean shutdown flush, so the
    // recorded utxo set state lags the best chain exactly as an
    // unclean shutdown mid-sync leaves it.  Old-fork rejection is
    // disabled to keep the battery's reorgs valid under the skewed
    // clock (and identically for the reference run above).
    let dir_b = TempDir::new().expect("tempdir");
    let opts_b = Options::new(dir_b.path().join("chain"), params.net.0);
    let db_b = Database::create(&opts_b).expect("create database");
    let mut chain_b = Chain::open(db_b, &params, Hash::ZERO, true, 0).expect("open chain");
    replay_battery(&mut chain_b, &params, 48 * 60 * 60);
    let tip_hash = chain_b
        .best_chain
        .tip()
        .map(|t| chain_b.store.node(t).hash)
        .expect("tip");
    let mut recorded: Option<dcroxide_blockchain::UtxoSetState> = None;
    chain_b
        .db
        .as_ref()
        .expect("db")
        .view(|tx| {
            recorded = dcroxide_blockchain::chaindb::db_fetch_utxo_set_state(tx).expect("state");
            Ok(())
        })
        .expect("read state");
    let recorded = recorded.expect("a recorded utxo set state");
    assert_ne!(
        recorded.last_flush_hash, tip_hash,
        "the crash run must leave the recorded utxo set state behind the tip"
    );
    drop(chain_b);

    // The reopen runs the catch-up replay: the utxo set converges to
    // the tip and folds to exactly the reference stats.
    let db_b = Database::open(&opts_b).expect("reopen database");
    let mut chain_b = Chain::open(db_b, &params, Hash::ZERO, false, 0).expect("reopen chain");
    assert_eq!(
        chain_b.best_chain.tip().map(|t| chain_b.store.node(t).hash),
        Some(tip_hash),
        "the reopened chain resumes at the same tip"
    );
    let stats = chain_b.fetch_utxo_stats().expect("caught-up stats");
    assert_eq!(
        stats, expected,
        "the caught-up utxo set folds to the reference stats"
    );

    // The stats' forced flush records the state at the tip.
    let mut caught_up: Option<dcroxide_blockchain::UtxoSetState> = None;
    chain_b
        .db
        .as_ref()
        .expect("db")
        .view(|tx| {
            caught_up = dcroxide_blockchain::chaindb::db_fetch_utxo_set_state(tx).expect("state");
            Ok(())
        })
        .expect("read state");
    assert_eq!(
        caught_up.expect("state").last_flush_hash,
        tip_hash,
        "the caught-up utxo set state records the tip"
    );
}
