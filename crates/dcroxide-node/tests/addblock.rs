// SPDX-License-Identifier: ISC
//! End-to-end checks for the addblock importer core: a bootstrap
//! stream built from dcrd's own full-block battery imports into a
//! fresh regnet chain through the chain engine with bulk-import mode;
//! the pre-created transaction index stays at its pre-import tip
//! (dcrd's importer never notifies the index subscriber) and the next
//! start's catch-up indexes the imported blocks; a re-import counts
//! the blocks as already known, and a gap in the stream surfaces
//! dcrd's does-not-link error.

use std::sync::{Arc, Mutex};

use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};
use dcroxide_indexers::Indexer;
use dcroxide_node::addblock::run_import;
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;

/// The leading consecutive main-chain prefix of accepted blocks from
/// dcrd's `fullblocktests.Generate` battery, as raw block bytes.
fn accepted_prefix_raw(limit: usize) -> Vec<Vec<u8>> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcroxide-blockchain/tests/data/fullblock_vectors.txt"
    );
    let data = std::fs::read_to_string(path).expect("fullblock vectors");
    let mut tip = dcroxide_chaincfg::regnet_params().genesis_hash;
    let mut blocks = Vec::new();
    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        if f[0] != "accept" {
            continue;
        }
        let raw = unhex(f[4]);
        let (block, _) = MsgBlock::from_bytes(&raw).expect("block");
        if f[2] != "true" || block.header.prev_block != tip {
            continue;
        }
        tip = block.header.block_hash();
        blocks.push(raw);
        if blocks.len() == limit {
            break;
        }
    }
    assert_eq!(blocks.len(), limit, "battery must provide the prefix");
    blocks
}

/// A bootstrap-format stream over the raw blocks.
fn bootstrap_stream(net: u32, blocks: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for raw in blocks {
        dcroxide_database::bootstrap::write_block(&mut out, net, raw).expect("write record");
    }
    out
}

/// A fresh regnet chain in a temporary database.
fn fresh_chain() -> (tempfile::TempDir, Arc<Mutex<Chain>>, Database) {
    let params = dcroxide_chaincfg::regnet_params();
    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(
            db.clone(),
            &params,
            dcroxide_chainhash::Hash([0u8; 32]),
            false,
            0,
        )
        .expect("open chain"),
    ));
    (dir, chain, db)
}

/// Create the transaction index and catch it up (dcrd's
/// `newBlockImporter` index block, and equally the next daemon
/// start's), returning its tip.
fn txindex_tip(db: Database, chain: &Arc<Mutex<Chain>>) -> (i64, dcroxide_chainhash::Hash) {
    let params = dcroxide_chaincfg::regnet_params();
    let interrupt: dcroxide_indexers::Interrupt =
        Arc::new(core::sync::atomic::AtomicBool::new(false));
    let indexes = dcroxide_node::indexes::start_indexes(
        interrupt,
        Arc::new(db),
        Arc::clone(chain),
        params,
        true,
        false,
    )
    .expect("start indexes");
    indexes
        .tx_index
        .as_ref()
        .expect("txindex enabled")
        .lock()
        .expect("txindex")
        .tip()
        .expect("index tip")
}

/// A battery prefix imports through the chain engine; the pre-created
/// index stays at its pre-import tip while the import runs (dcrd's
/// importer performs no index maintenance) and the next start's
/// catch-up indexes the imported blocks; a second pass counts every
/// block as already known; and the every-block progress quirk logs
/// each one.
#[test]
fn imports_the_battery_prefix_with_deferred_indexing() {
    let params = dcroxide_chaincfg::regnet_params();
    let (_dir, chain, db) = fresh_chain();
    chain.lock().expect("chain").bulk_import_mode = true;

    // The pre-import index catch-up over the genesis chain (dcrd's
    // `newBlockImporter` creating the index before the import).
    let genesis_tip = txindex_tip(db.clone(), &chain);
    assert_eq!(genesis_tip.0, 0, "the index starts at the genesis tip");

    let blocks = accepted_prefix_raw(4);
    let stream = bootstrap_stream(params.net.0, &blocks);

    // Import with the zero-interval progress quirk: every processed
    // block logs one announcement.
    let mut logs: Vec<String> = Vec::new();
    let mut log = |msg: String| logs.push(msg);
    let (stats, err) = run_import(&chain, &params, &mut stream.as_slice(), 0, &mut log);
    assert_eq!(err, None, "the import must succeed");
    assert_eq!(stats.blocks_processed, 4);
    assert_eq!(stats.blocks_imported, 4);
    assert_eq!(logs.len(), 4, "a zero interval logs every block: {logs:?}");
    assert!(
        logs[0].starts_with("Processed 1 block in the last "),
        "progress line shape: {}",
        logs[0]
    );

    // The chain advanced to the last imported block.
    let (tip_hash, tip_height) = {
        let chain = chain.lock().expect("chain");
        let best = chain.best_snapshot();
        (best.hash, best.height)
    };
    assert_eq!(tip_height, 4, "the chain must advance to the prefix tip");
    let (last_block, _) = MsgBlock::from_bytes(blocks.last().expect("blocks")).expect("block");
    assert_eq!(tip_hash, last_block.header.block_hash());

    // The imported blocks were NOT indexed during the run; the next
    // start's catch-up brings the index to the imported tip (dcrd's
    // deferred indexing).
    let caught_up = txindex_tip(db, &chain);
    assert_eq!(
        caught_up,
        (tip_height, tip_hash),
        "the next start's catch-up must index the imported blocks"
    );

    // A second pass over the same stream skips every block as already
    // known.
    let mut noop_log = |_msg: String| {};
    let (stats, err) = run_import(&chain, &params, &mut stream.as_slice(), 10, &mut noop_log);
    assert_eq!(err, None, "the re-import must succeed");
    assert_eq!(stats.blocks_processed, 4);
    assert_eq!(stats.blocks_imported, 0, "every block is already known");
}

/// A stream that skips a block does not link to the available chain
/// (dcrd prints the missing parent hash), and a wrong-network record
/// fails with the read wrap.
#[test]
fn a_gap_and_a_network_mismatch_are_refused() {
    let params = dcroxide_chaincfg::regnet_params();
    let blocks = accepted_prefix_raw(3);

    // Blocks one and three, without two: the prev-link check fails.
    let (_dir, chain, _db) = fresh_chain();
    chain.lock().expect("chain").bulk_import_mode = true;
    let gapped = bootstrap_stream(params.net.0, &[blocks[0].clone(), blocks[2].clone()]);
    let mut log = |_msg: String| {};
    let (stats, err) = run_import(&chain, &params, &mut gapped.as_slice(), 10, &mut log);
    let (skipped_block, _) = MsgBlock::from_bytes(&blocks[2]).expect("block");
    assert_eq!(
        err,
        Some(format!(
            "import file contains block {} which does not link to the available block chain",
            skipped_block.header.prev_block
        ))
    );
    assert_eq!(stats.blocks_processed, 2, "the second record was counted");
    assert_eq!(stats.blocks_imported, 1);

    // A record for another network fails inside the read wrap.
    let (_dir2, chain2, _db2) = fresh_chain();
    let mismatched = bootstrap_stream(dcroxide_chaincfg::simnet_params().net.0, &blocks[..1]);
    let (_, err) = run_import(&chain2, &params, &mut mismatched.as_slice(), 10, &mut log);
    let err = err.expect("must fail");
    assert!(
        err.starts_with("error reading from input file: network mismatch -- got "),
        "unexpected error: {err}"
    );
}
