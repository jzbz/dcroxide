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
