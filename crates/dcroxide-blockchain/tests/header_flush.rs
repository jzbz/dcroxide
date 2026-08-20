// SPDX-License-Identifier: ISC
//! Accepted headers reach the database before a block connects
//! (RVW-020).
//!
//! dcrd flushes the modified block index entries at the end of
//! `ProcessBlockHeader` (`process.go:267-271`), because a new header
//! always adds one. The port did not, and `flush_block_index` had only
//! three callers: the load path, `connect_block`, and
//! `disconnect_block`.
//!
//! Sync is strictly headers-first, so nothing drained the set until the
//! first block connected. On mainnet that meant the whole ~1.05M-entry
//! header chain accumulated, and the first connect materialized every
//! row at once -- a header apiece, roughly 250 MB -- and handed it to
//! one write transaction. None of it was durable in the meantime, so a
//! host that could not afford the allocation re-downloaded every header
//! and failed at the same place again.
//!
//! Not flushed per header, which dcrd can afford and this cannot: the
//! database writes at `Durability::Immediate`, so per-header would be an
//! fsync per header. One `headers` message worth is the threshold.

// Test-harness arithmetic over bounded heights.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::{Arc, Mutex};

use dcroxide_blockchain::chainio::decode_block_index_entry;
use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::{Params, simnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_wire::BlockHeader;

/// A header extending `prev`, mined until it clears the target.
///
/// Simnet's limit leaves the top bit clear, so about half of all nonces
/// qualify and the search is a couple of tries.
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

/// A write-log sink counting block index rows handed to the engine.
///
/// Observed at the engine boundary rather than by reopening the store:
/// a committed row still sits in the metadata overlay until the cache
/// flushes, so a reopen cannot tell "never written" from "written but
/// not yet durable", and this test is about the former.
///
/// Index rows are identified by key length and by a value that decodes
/// as an entry and accounts for every byte, so a same-shaped key in
/// another bucket is not counted.
fn counting_options(dir: &std::path::Path, net: u32) -> (Options, Arc<Mutex<usize>>) {
    let count = Arc::new(Mutex::new(0usize));
    let sink = Arc::clone(&count);
    let mut opts = Options::new(dir.join("chain"), net);
    opts.write_log = Some(Arc::new(move |key: &[u8], value: Option<&[u8]>| {
        let Some(value) = value else { return };
        if key.len() == 40
            && decode_block_index_entry(value).is_ok_and(|(_, used)| used == value.len())
        {
            *sink.lock().expect("counter") += 1;
        }
    }));
    (opts, count)
}

/// Headers accepted without any block connecting are still durable.
///
/// The chain is dropped rather than closed, so only what the header path
/// itself wrote survives. Pre-fix that is genesis alone, however many
/// headers were accepted.
#[test]
fn accepted_headers_are_flushed_without_waiting_for_a_block() {
    // Two full thresholds' worth, so the bound is crossed twice. The
    // threshold is lowered because the real one, 2000, is past simnet's
    // stake validation height and a headers-only fixture cannot reach it.
    const THRESHOLD: usize = 8;
    const HEADERS: u32 = 20;

    let params = simnet_params();
    let dir = tempfile::tempdir().expect("tempdir");
    let (opts, written) = counting_options(dir.path(), params.net.0);

    let accepted = {
        let db = Database::create(&opts).expect("create database");
        let chain = Arc::new(Mutex::new(
            Chain::open(db, &params, Hash::ZERO, false, 0).expect("open chain"),
        ));
        let mut guard = chain.lock().expect("chain");
        guard.set_header_flush_threshold(THRESHOLD);
        let mut prev = params.genesis_block.header;
        let mut n = 0u32;
        for _ in 0..HEADERS {
            let h = header(&prev, &params);
            guard
                .process_block_header(&h, 2_000_000_000, &params)
                .unwrap_or_else(|e| panic!("header {} rejected: {e:?}", h.height));
            prev = h;
            n += 1;
        }
        // No block ever connects.  The cache flush is what pushes
        // whatever was committed out to the engine, where the sink sees
        // it; pre-fix nothing was ever committed, so it pushes nothing.
        guard
            .db
            .as_ref()
            .expect("db-backed")
            .flush()
            .expect("flush");
        n
    };
    assert_eq!(accepted, HEADERS, "the fixture must accept every header");

    let rows = *written.lock().expect("counter");
    assert!(
        rows >= THRESHOLD,
        "only {rows} block index rows were written after {HEADERS} accepted headers: \
         nothing flushes until a block connects, so a mainnet header sync accumulates \
         the whole chain in memory and loses all of it on restart",
    );
}

/// The administrative paths flush too (dcrd's
/// `flushBlockIndexWarnOnly` at `process.go:703`, `:717`, `:767`).
///
/// Marking a side-chain block failed is the cheapest of them to reach:
/// it takes the early-return branch, so nothing else in the call could
/// have done the write.
#[test]
fn invalidating_a_side_chain_block_flushes_the_mark() {
    let params = simnet_params();
    let dir = tempfile::tempdir().expect("tempdir");
    let (opts, written) = counting_options(dir.path(), params.net.0);

    let (side_hash, before) = {
        let db = Database::create(&opts).expect("create database");
        let mut chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("open chain");
        // One header off genesis: accepted, never connected, so it is
        // not part of the best chain.
        let h = header(&params.genesis_block.header, &params);
        chain
            .process_block_header(&h, 2_000_000_000, &params)
            .expect("header accepted");
        let hash = h.block_hash();
        chain.flush(&params).expect("flush the header");
        let node = chain.index.lookup_node(&hash).expect("node");
        let before = chain
            .index
            .node_status(&chain.store, node)
            .known_validate_failed();
        chain
            .db
            .as_ref()
            .expect("db-backed")
            .close()
            .expect("close");
        (hash, before)
    };
    assert!(!before, "the block must start out not failed");

    let db = Database::open(&opts).expect("reopen database");
    let mut chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("reopen chain");
    // Drain anything the open itself left pending, so the count below is
    // the invalidation's alone.
    chain
        .db
        .as_ref()
        .expect("db-backed")
        .flush()
        .expect("flush");
    *written.lock().expect("counter") = 0;

    let errs = chain.invalidate_block(&side_hash, 2_000_000_000, &params);
    assert!(errs.is_empty(), "invalidating a side-chain block: {errs:?}");
    chain
        .db
        .as_ref()
        .expect("db-backed")
        .flush()
        .expect("flush");

    let rows = *written.lock().expect("counter");
    assert!(
        rows > 0,
        "invalidate_block wrote no block index rows, so the mark never reaches the \
         database and the block is a best-chain candidate again on the next start",
    );
}
