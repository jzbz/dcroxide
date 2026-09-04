// SPDX-License-Identifier: ISC
//! The warn-only block index flush records its failure (RV-002).
//!
//! dcrd's `flushBlockIndexWarnOnly` deliberately does not fail an
//! `invalidateblock` because the write did not land — the work is
//! already done by the time it runs — but it does say so:
//!
//! ```text
//! log.Warnf("Unable to flush block index changes to db: %v", err)
//! ```
//!
//! (`internal/blockchain/chain.go:1516-1520`). The port kept the
//! control flow and dropped the line, so an operator invalidating a
//! block against a failing store was told the call succeeded, restarted
//! into missing index rows, and had nothing naming the flush.
//!
//! Two tests, bracketing the behaviour from both sides: the failure
//! warns, and an empty modified set stays silent. The second is not
//! decoration. dcrd's `blockIndex.Flush` returns before it opens a
//! transaction when nothing is modified (`blockindex.go:1409-1414`);
//! this port's flush did not, and `Database::update` fails at
//! `check_open` even with zero rows, so without that short-circuit the
//! new line would fire where dcrd cannot — including on
//! `force_head_reorganization`'s success path, which is the one warn-only
//! flush the daemon actually reaches today.
//!
//! Neither test may be written against `Chain::new`: `flush_block_index`
//! returns `Ok(())` immediately when `db.is_none()`, so such a version
//! would pass whether or not the fix is present.

// Test-harness arithmetic over bounded heights.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::{Arc, Mutex};

use dcroxide_blockchain::notifications::LogLevel;
use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::{Params, simnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_wire::BlockHeader;

/// A header extending `prev`, mined until it clears the target.
fn header(prev: &BlockHeader, params: &Params) -> BlockHeader {
    let mut h = header_at(prev, params);
    while h.block_hash().0[31] >= 0x80 {
        h.nonce = h.nonce.wrapping_add(1);
    }
    h
}

fn header_at(prev: &BlockHeader, params: &Params) -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_block: prev.block_hash(),
        merkle_root: Hash::ZERO,
        stake_root: Hash::ZERO,
        vote_bits: 1,
        final_state: [0u8; 6],
        voters: 0,
        fresh_stake: 0,
        revocations: 0,
        pool_size: prev.pool_size,
        bits: params.pow_limit_bits,
        sbits: params.minimum_stake_diff,
        height: prev.height + 1,
        size: 0,
        timestamp: prev.timestamp + params.target_time_per_block_secs as u32,
        nonce: 0,
        extra_data: [0u8; 32],
        stake_version: 0,
    }
}

type Captured = Arc<Mutex<Vec<(LogLevel, String)>>>;

/// A chain with one accepted-but-never-connected header off genesis, its
/// modified set drained, a capturing log sink installed, and its store
/// closed underneath it.
///
/// The header is header-only and off the best chain, so `invalidate_block`
/// takes the early-return branch (dcrd `process.go:700-704`) and nothing
/// else in the call could have performed a write.
fn dead_store_chain(params: &Params) -> (tempfile::TempDir, Chain, Hash, Captured) {
    let dir = tempfile::tempdir().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let mut chain = Chain::open(db, params, Hash::ZERO, false, 0).expect("open chain");

    let h = header(&params.genesis_block.header, params);
    chain
        .process_block_header(&h, 2_000_000_000, params)
        .expect("header accepted");
    let side_hash = h.block_hash();

    // Drain the set, so anything counted below belongs to the call under
    // test rather than to this setup.
    chain.flush(params).expect("drain the modified set");

    let lines: Captured = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    chain.set_log_callback(Box::new(move |level, msg| {
        sink.lock().expect("sink").push((level, msg.to_string()));
    }));

    // Kill the store. Every later `update` fails at `check_open`, before
    // the closure runs.
    chain
        .db
        .as_ref()
        .expect("db-backed")
        .close()
        .expect("close");

    (dir, chain, side_hash, lines)
}

/// A failed warn-only flush emits dcrd's warning, and still succeeds.
#[test]
fn warn_only_flush_failure_emits_dcrds_warning() {
    let params = simnet_params();
    let (_dir, mut chain, side_hash, lines) = dead_store_chain(&params);

    // Derive the `%v` tail from the same failure rather than hardcoding
    // this storage layer's wording: the flush's error is
    // `ChainDbError::Db(_)`, whose `Display` delegates to this value.
    let probe = chain
        .db
        .as_ref()
        .expect("db-backed")
        .update(|_tx| Ok(()))
        .expect_err("the store is closed");
    let expected = format!("Unable to flush block index changes to db: {probe}");

    let errs = chain.invalidate_block(&side_hash, 2_000_000_000, &params);
    assert!(
        errs.is_empty(),
        "warn-only must not become propagate: {errs:?}"
    );

    let captured = lines.lock().expect("sink").clone();
    assert_eq!(
        captured.len(),
        1,
        "the flush failure must be recorded exactly once, saw {captured:?}"
    );
    // The prefix and the level are pinned against dcrd exactly; the text
    // after the colon is this storage layer's own description, since
    // dcroxide's store is not ffldb.
    assert_eq!(captured[0], (LogLevel::Warn, expected));
}

/// An empty modified set writes nothing and says nothing, as dcrd's
/// `blockIndex.Flush` does.
#[test]
fn an_empty_modified_set_is_silent_like_dcrds_flush() {
    let params = simnet_params();
    let (_dir, mut chain, side_hash, lines) = dead_store_chain(&params);

    assert_eq!(
        chain.index.modified_len(),
        0,
        "the setup flush drained the set"
    );

    // The header was never marked invalid, so the ancestor walk skips
    // `unset_status_flags`, `add_best_chain_candidate` does not mark
    // anything, the node has no data so the unlinked-child branch is
    // skipped, and there are no descendants. The warn-only flush
    // therefore runs over an empty set, and the reorg returns
    // immediately because the tip is already the target.
    let errs = chain.reconsider_block(&side_hash, 2_000_000_000, &params);
    assert!(errs.is_empty(), "reconsider must succeed: {errs:?}");

    let captured = lines.lock().expect("sink").clone();
    assert!(
        captured.is_empty(),
        "an empty modified set must not reach the database, so there is \
         nothing to warn about: {captured:?}"
    );
}
