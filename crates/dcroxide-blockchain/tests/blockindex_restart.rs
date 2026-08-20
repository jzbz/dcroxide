// SPDX-License-Identifier: ISC
//! Loading the block index from storage does not mark its rows for
//! rewriting (RVW-009).
//!
//! dcrd has two entry points: `addNode` (`blockindex.go:665-722`), which
//! never touches `bi.modified`, and the exported `AddNode`
//! (`:757-762`), which adds the mark.  `addNodeFromDB` (`:733-751`) uses
//! the un-marking one, and `loadBlockIndex` (`chainio.go:1502`) goes
//! through it for every stored row.
//!
//! The port had only the marking form, so every row loaded at startup
//! was queued as dirty and the first `flush_block_index` after a restart
//! rewrote the whole index byte for byte — around 1.1M rows on mainnet.
//! That flush runs from inside `connect_block`, so it also forces a
//! metadata flush out of its own cadence.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::{Arc, Mutex};

use dcroxide_blockchain::blockindex::BlockStatus;
use dcroxide_blockchain::chaindb::{db_fetch_deployment_ver, db_put_deployment_ver};
use dcroxide_blockchain::chainio::decode_block_index_entry;
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::thresholdstate::current_deployment_version;
use dcroxide_chaincfg::{Params, simnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;

/// The reorg corpus's blocks, in file order.
fn corpus_blocks() -> Vec<MsgBlock> {
    include_str!("data/reorg_vectors.txt")
        .lines()
        .filter_map(|l| l.strip_prefix("blk "))
        .map(|hex| {
            MsgBlock::from_bytes(&unhex(hex.split(' ').next().expect("hex")))
                .expect("blk")
                .0
        })
        .collect()
}

/// Fill a chain with the corpus and leave it flushed and closed,
/// returning the hashes of the blocks that were added.
fn seed(opts: &Options, params: &Params) -> Vec<Hash> {
    let db = Database::create(opts).expect("create database");
    let mut chain = Chain::open(db, params, Hash::ZERO, false, 0).expect("open chain");
    let mut added = Vec::new();
    for block in &corpus_blocks() {
        let Some(parent) = chain.index.lookup_node(&block.header.prev_block) else {
            continue;
        };
        added.push(block.header.block_hash());
        let node = chain.store.new_node(&block.header, Some(parent));
        {
            let n = chain.store.node_mut(node);
            n.status = BlockStatus(BlockStatus::DATA_STORED.0 | BlockStatus::VALIDATED.0);
            n.is_fully_linked = true;
        }
        chain
            .blocks
            .insert(block.header.block_hash().0, block.clone());
        chain.index.add_node(&chain.store, node);
        // The reopen's warm-up fetches the block for every node that
        // claims stored data, so the bytes have to be there.
        chain
            .db
            .as_ref()
            .expect("db-backed")
            .update(|tx| {
                tx.store_block(block)
                    .map(|_| ())
                    .map_err(|e| panic!("store block: {e:?}"))
            })
            .expect("store block");
    }
    chain.flush(params).expect("flush the index");
    let n = chain.index.take_modified().len();
    assert_eq!(n, 0, "the seeding flush must leave nothing dirty");
    chain
        .db
        .as_ref()
        .expect("db-backed")
        .close()
        .expect("close");
    added
}

/// Nothing that came off disk is queued for rewriting.
///
/// The invariant is `modified` ⊇ *changed*, not equality: genesis is
/// marked when `Chain::open` creates it, before any row is loaded.  So
/// the assertion is on the loaded rows, and the second half is what
/// stops a "fix" that simply guts the marking from passing.
#[test]
fn nodes_loaded_from_the_database_are_not_marked_modified() {
    let params = simnet_params();
    let dir = tempfile::tempdir().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let seeded = seed(&opts, &params);
    assert!(seeded.len() > 1, "the corpus must carry more than genesis");

    let db = Database::open(&opts).expect("reopen database");
    let mut chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("reopen chain");

    // Exactly genesis, and nothing else.  `Chain::open` creates and
    // marks genesis before the load loop runs, so the invariant is
    // `modified` superset-of *changed*, not equality -- an asymmetry
    // that is real rather than an artefact of the test.  Pre-fix this
    // set is every loaded node.
    let genesis = chain
        .index
        .lookup_node(&params.genesis_hash)
        .expect("genesis is in the index");
    let dirty = chain.index.take_modified();
    assert_eq!(
        dirty,
        vec![genesis],
        "{} nodes were queued for rewriting; only genesis should be",
        dirty.len(),
    );

    // Marking still works for the paths that do change something, so a
    // "fix" that simply gutted the marking would not pass.
    let last = chain
        .index
        .lookup_node(seeded.last().expect("a seeded block"))
        .expect("the seeded block is in the index");
    chain
        .index
        .set_status_flags(&mut chain.store, last, BlockStatus::VALIDATED);
    let dirty = chain.index.take_modified();
    assert_eq!(
        dirty,
        vec![last],
        "a status change must still mark its node"
    );
}

/// The behavioural half, observed at the engine boundary: the first
/// flush after a restart writes no block-index rows.
///
/// Block-index writes are identified two ways — a 36-byte key and a
/// value that decodes as an index entry — because a key of that length
/// in another bucket would otherwise be counted.
#[test]
fn the_first_flush_after_a_restart_rewrites_no_block_index_rows() {
    let params = simnet_params();
    let dir = tempfile::tempdir().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let seeded = seed(&opts, &params);

    let index_writes: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
    let counter = Arc::clone(&index_writes);
    let mut reopen_opts = Options::new(dir.path().join("chain"), params.net.0);
    reopen_opts.write_log = Some(Arc::new(move |key: &[u8], value: Option<&[u8]>| {
        let Some(value) = value else { return };
        // The engine sees the bucket prefix ahead of chainio's
        // 4-byte height + 32-byte hash key, hence 40 rather than 36.
        // The value has to decode as an index entry *and* account for
        // every byte, so a same-shaped key in another bucket, or a
        // block record that merely starts with a header, is not counted.
        if key.len() == 40
            && decode_block_index_entry(value).is_ok_and(|(_, used)| used == value.len())
        {
            *counter.lock().expect("counter") += 1;
        }
    }));

    let db = Database::open(&reopen_opts).expect("reopen database");
    let mut chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("reopen chain");
    chain.flush(&params).expect("first flush");
    chain
        .db
        .as_ref()
        .expect("db-backed")
        .close()
        .expect("close");

    // Genesis alone: `Chain::open` marks it before the load loop runs.
    // Pre-fix every loaded row is rewritten instead.
    let written = *index_writes.lock().expect("counter");
    assert_eq!(
        written,
        1,
        "the first flush after a restart wrote {written} index rows, not just genesis, \
         out of {} loaded",
        seeded.len(),
    );
}

/// The one thing the un-marking split must not break: a row the load
/// loop *changes* still reaches disk.
///
/// The new-rules pass clears `VALIDATE_FAILED`/`INVALID_ANCESTOR` from
/// blocks that failed under rules predating a newly detected agenda.
/// Startup flushes those rows and then advances the stored deployment
/// version, so the pass does not run again -- which means an unmarked
/// row would keep its failure forever, and the block would be rejected
/// on every subsequent start.
///
/// Arming it takes two adjustments.  The stored deployment version is
/// pushed back to 0 so the binary's version leads it.  And simnet's next
/// deployment starts at time 0, which the pass reads as "no new rules"
/// (`new_rules_start_time != 0`), so that start time is moved to 1 --
/// below every corpus timestamp, so the median-time gate opens.
#[test]
fn the_new_rules_unmark_persists_the_node_it_changed() {
    let mut params = simnet_params();
    {
        let next = params
            .deployments
            .iter()
            .map(|(v, _)| *v)
            .filter(|v| *v > 0)
            .min()
            .expect("simnet has deployments");
        let (_, deployments) = params
            .deployments
            .iter_mut()
            .find(|(v, _)| *v == next)
            .expect("the next deployment version");
        deployments.first_mut().expect("a deployment").start_time = 1;
    }
    let params = params;

    let dir = tempfile::tempdir().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let seeded = seed(&opts, &params);

    // Fail one block, and push the stored deployment version back so the
    // load loop's new-rules pass arms on the next open.
    let failed_hash = *seeded.last().expect("a seeded block");
    {
        let db = Database::open(&opts).expect("reopen database");
        let mut chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("reopen chain");
        let target = chain
            .index
            .lookup_node(&failed_hash)
            .expect("the seeded block is in the index");
        assert_ne!(
            Some(target),
            chain.index.lookup_node(&params.genesis_hash),
            "the failed block must not be genesis, or the assertions collapse",
        );
        chain
            .index
            .set_status_flags(&mut chain.store, target, BlockStatus::VALIDATE_FAILED);
        chain.flush(&params).expect("flush the failure");
        let db = chain.db.as_ref().expect("db-backed");
        db.update(|tx| {
            db_put_deployment_ver(tx, 0).map_err(|e| panic!("put deployment ver: {e:?}"))
        })
        .expect("rewind the deployment version");
        db.close().expect("close");
    }

    // The open that runs the pass: it clears the flag, flushes the row,
    // and advances the stored version.
    {
        let db = Database::open(&opts).expect("reopen database");
        let chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("reopen chain");
        let node = chain
            .index
            .lookup_node(&failed_hash)
            .expect("the failed block is in the index");
        assert!(
            !chain.store.node(node).status.known_validate_failed(),
            "the new-rules pass did not clear VALIDATE_FAILED; the test arms nothing",
        );
        chain
            .db
            .as_ref()
            .expect("db-backed")
            .close()
            .expect("close");
    }

    // The open that proves it: the version has advanced, so the pass
    // cannot run again, and the flag must be clear because it was
    // written rather than merely cleared in memory.
    let db = Database::open(&opts).expect("reopen database");
    let chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("reopen chain");

    let stored = {
        let tx = chain
            .db
            .as_ref()
            .expect("db-backed")
            .begin(false)
            .expect("begin read");
        let v = db_fetch_deployment_ver(&tx);
        tx.rollback().expect("rollback");
        v
    };
    assert_eq!(
        stored,
        current_deployment_version(&params),
        "the stored deployment version must have advanced, or the pass re-runs forever",
    );

    let node = chain
        .index
        .lookup_node(&failed_hash)
        .expect("the failed block is in the index");
    assert!(
        !chain.store.node(node).status.known_validate_failed(),
        "the cleared status never reached disk: the pass will not run again, so the block \
         stays failed for the life of this data directory",
    );
}
