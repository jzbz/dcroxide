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
    // The metadata write cache must reach disk first (the daemon's
    // clean shutdown flushes it).
    chain.db.as_ref().expect("db").flush().expect("db flush");
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
fn a_prestored_block_still_connects() {
    // A crash can land between storing a block's bytes and flushing
    // its index status row, leaving the database holding the block
    // while the chain does not know the data is available.  The
    // redelivered block must be accepted and connected — dcrd's
    // `dbMaybeStoreBlock` skips the store when the block is already
    // present — rather than rejected on the database's block-exists
    // error, which would stall the chain on that height forever.
    // Pre-storing every block's bytes replays the entire battery
    // through that crash window.
    let params = regnet_params();
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let mut chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("open chain");

    let data = include_str!("data/fullblock_vectors.txt");
    let mut now: i64 = 0;
    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("now"),
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                chain
                    .db
                    .as_ref()
                    .expect("db")
                    .update(|tx| {
                        if tx.has_block(&block.header.block_hash())? {
                            return Ok(());
                        }
                        tx.store_block(&block)
                    })
                    .expect("pre-store the block bytes");
                let (_, errs) = chain.process_block(&block, now, &params);
                let is_orphan = errs.len() == 1 && errs[0].kind == RuleErrorKind::MissingParent;
                assert!(errs.is_empty() || is_orphan, "accept {}: {errs:?}", f[1]);
            }
            _ => {}
        }
    }

    let tip = chain.best_chain.tip().expect("tip");
    assert!(
        chain.store.node(tip).height > 10,
        "the pre-stored battery still built the chain"
    );
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
    // Persist the per-block metadata (the write cache) while leaving
    // the recorded utxo set state behind the tip: the flush below is
    // the database's, not the chain's, so the catch-up replay is
    // still exercised on reopen.
    chain_b.db.as_ref().expect("db").flush().expect("db flush");
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

/// A utxo set state marker whose height disagrees with the block index
/// must stop the node, not be replayed over.
///
/// `reconcileDB` compares the block-file write cursor against the block
/// files and nothing else, so a metadata store that lost recent commits
/// reopens looking exactly like an ordinary unclean shutdown. The
/// 2026-08-17 engine work found a journal truncation that left rows the
/// state marker did not account for, and nothing on the startup path
/// noticed. A marker and an index that disagree about the same hash's
/// height is that damage made visible: two durability domains rolled back
/// by different amounts.
///
/// Narrower than what `crash.rs` asserts, which counts the rows a marker
/// names — a live utxo set records no expected row count, so there is
/// nothing here to count against. This costs one field comparison on a
/// node the catch-up already loads.
#[test]
#[should_panic(expected = "the metadata store and the block index disagree")]
fn a_utxo_state_height_disagreeing_with_the_index_stops_the_node() {
    let params = regnet_params();
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let mut chain = Chain::open(db, &params, Hash::ZERO, true, 0).expect("open chain");
    replay_battery(&mut chain, &params, 48 * 60 * 60);

    // Take the recorded state and put its own hash back at a height the
    // index does not agree with, which is what a partial rollback across
    // two durability domains produces.
    let mut recorded: Option<dcroxide_blockchain::UtxoSetState> = None;
    chain
        .db
        .as_ref()
        .expect("db")
        .view(|tx| {
            recorded = dcroxide_blockchain::chaindb::db_fetch_utxo_set_state(tx).expect("state");
            Ok(())
        })
        .expect("read state");
    let mut torn = recorded.expect("a recorded utxo set state");
    torn.last_flush_height = torn.last_flush_height.saturating_add(1);
    chain
        .db
        .as_ref()
        .expect("db")
        .update(|tx| {
            dcroxide_blockchain::chaindb::db_put_utxo_set_state(tx, &torn).expect("put state");
            Ok(())
        })
        .expect("write torn state");
    chain.db.as_ref().expect("db").flush().expect("db flush");
    drop(chain);

    // The reopen must refuse rather than replay over the disagreement.
    let db = Database::open(&opts).expect("reopen database");
    let _ = Chain::open(db, &params, Hash::ZERO, true, 0);
}

/// Blocks that never reach the best chain must not stay resident.
///
/// `prune_chain_memory` walks `parent` from the best-chain tip, so it
/// only ever visits that tip's ancestors.  Everything else -- side-chain
/// blocks, blocks a reorg disconnected, and blocks that cleared the
/// positional checks and were then rejected by a contextual or connect
/// check -- is never visited, and before the sweep stayed resident for
/// the life of the process.  dcrd has nothing to prune here because it
/// never accumulates them: bodies live in a `recentBlockCacheSize = 12`
/// LRU (`chain.go:43-48`) and everything else is served from the block
/// database.
///
/// The second half of the test is what proves the sweep is safe rather
/// than merely effective: every dropped block must still answer, out of
/// the database.
#[test]
fn pruning_bounds_the_bodies_that_never_reach_the_best_chain() {
    let params = regnet_params();
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let mut chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("open chain");

    let data = include_str!("data/fullblock_vectors.txt");
    let mut now: i64 = 0;
    // The battery marks blocks that do not end up on the best chain.
    let mut off_chain: Vec<Hash> = Vec::new();

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("now"),
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                let hash = block.header.block_hash();
                let (_, errs) = chain.process_block(&block, now, &params);
                let is_orphan = errs.len() == 1 && errs[0].kind == RuleErrorKind::MissingParent;
                assert!(errs.is_empty() || is_orphan, "accept {}: {errs:?}", f[1]);
                if !is_orphan && f[2] == "false" {
                    off_chain.push(hash);
                }
            }
            // Blocks rejected after the positional checks are the
            // largest resident population, and the one dcrd's own
            // comment goes out of its way to keep on disk.
            "reject" => {
                if let Ok((block, _)) = MsgBlock::from_bytes(&unhex(f[3])) {
                    let _ = chain.process_block(&block, now, &params);
                }
            }
            _ => {}
        }
    }

    assert!(
        off_chain.len() > 10,
        "the battery must fork off the best chain: {} off-chain",
        off_chain.len()
    );

    chain.prune_chain_memory(2);

    // The keep window is two blocks; a handful of side-chain blocks may
    // sit inside it legitimately.  What must not happen is the whole
    // off-chain population staying resident.
    assert!(
        chain.blocks.len() <= 8,
        "bodies off the best chain stay resident: {} left",
        chain.blocks.len()
    );

    // And every one of them still answers, from the database.
    for hash in &off_chain {
        assert!(
            chain.block_by_hash(hash).is_some(),
            "off-chain block {hash} must still be served from the database"
        );
    }
}

/// A block rejected by validation does not keep its body in memory.
///
/// `maybe_accept_block_data` stores every block that clears the
/// positional checks, which happens before the contextual and connect
/// checks, so a block failing one of those is already in the in-memory
/// mirror.  The stale sweep only reaches heights below
/// `tip - MIN_MEMORY_STAKE_NODES`, so without an explicit drop a peer
/// feeding proof-of-work-valid blocks that fail a later check at a
/// stationary tip keeps every one of them resident for the duration.
/// dcrd stores bodies to disk only and mirrors `recentBlockCacheSize`
/// of them, twelve, whatever the fork history looks like.
///
/// The assertion is over blocks the index marked `VALIDATE_FAILED`,
/// which is exactly the population the drop targets.  Blocks retained
/// for other reasons are out of scope here and stay: a re-submitted
/// block that draws `ErrDuplicateBlock` is a previously *accepted*
/// block whose body is legitimately resident, and a stored side-chain
/// block that never got connected because an ancestor failed is the
/// separate population `prune_chain_memory`'s comment names.
///
/// dcrd's own battery supplies the sample -- several hundred rejects
/// spanning every kind its generator produces, far broader than a
/// hand-built block.
#[test]
fn blocks_that_fail_validation_do_not_keep_their_bodies() {
    let params = regnet_params();
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let mut chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("open chain");

    let data = include_str!("data/fullblock_vectors.txt");
    let mut now: i64 = 0;
    let mut submitted: Vec<Hash> = Vec::new();

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("now"),
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                let _ = chain.process_block(&block, now, &params);
            }
            "reject" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[3])).expect("block");
                let hash = block.header.block_hash();
                let (_, errs) = chain.process_block(&block, now, &params);
                assert!(
                    !errs.is_empty(),
                    "reject {} should have been rejected",
                    f[1]
                );
                submitted.push(hash);
            }
            _ => {}
        }
    }

    let failed: Vec<&Hash> = submitted
        .iter()
        .filter(|h| match chain.index.lookup_node(h) {
            Some(node) => chain
                .index
                .node_status(&chain.store, node)
                .known_validate_failed(),
            None => false,
        })
        .collect();
    assert!(
        failed.len() > 50,
        "battery should mark a broad sample validation-failed, got {}",
        failed.len()
    );

    let retained: Vec<&&Hash> = failed
        .iter()
        .filter(|h| chain.blocks.contains_key(&h.0))
        .collect();
    assert!(
        retained.is_empty(),
        "{} of {} validation-failed block bodies stayed in memory (first: {})",
        retained.len(),
        failed.len(),
        retained.first().map(|h| h.to_string()).unwrap_or_default()
    );
}
