// SPDX-License-Identifier: ISC
//! How often the thread that processes a block hashes a block header.
//!
//! dcrd wraps a block in a `dcrutil.Block`, which hashes the header as
//! it is made and hands that hash out from then on
//! (`dcrutil/block.go:92-94`, `:288-293`).  The duplicate and
//! known-invalid checks, the record of a proven merkle commitment, the
//! recent blocks and the stored block, the key of the contextual merkle
//! check and the filter lookup all read that one hash (`process.go:452`,
//! `validate.go:2031`, `:2111`, `ffldb/db.go:1169`, `chain.go:989`).
//! `dcroxide_wire::MsgBlock` caches nothing, and each of those steps
//! hashes the header of the block it is handed, as does the contextual
//! proof of work check while the version 1 proof of work applies, but
//! for the store when the block arrives with its record for the block
//! files (below).
//!
//! These tests count the calls of `BlockHeader::block_hash` on the
//! processing thread for blocks that extend the tip of a chain over a
//! database, with the header already in the index, as during the
//! initial chain sync, and that arrive without such a record.  What a
//! call hashes depends on how the block is validated:
//!
//! - A block that is fully validated has its header hashed where the
//!   call starts, as its data is accepted, in the store, by the
//!   contextual proof of work check and for the key of the contextual
//!   merkle check, and once more for the record of a merkle commitment
//!   that the agenda's state proves before the data is accepted.  The
//!   reorganization's check that the block it was handed as the parent
//!   is the parent hashes the parent's header.
//! - A block added without full validation, as in a bulk import and as
//!   the ancestors of the assumed valid block are, has its header hashed
//!   twice more: for the filter lookup and by the view that connects
//!   it, for the best hash it records.
//!
//! The counts are the same for each way these tests hand a block over:
//! lent to `Chain::process_block`, shared with
//! `Chain::process_shared_block`, or in a `HashedBlock` without a
//! record to `Chain::process_hashed_block`.  The hash a `HashedBlock`
//! carries is not one the chain reads.  A `HashedBlock` that also
//! carries the block's record for the block files
//! (`HashedBlock::record`), as one made by a connection's `peer-reader`
//! thread does, is stored through `Transaction::store_block_record`,
//! which compares the hash it is handed with the one the record took of
//! its header as it was laid out and hashes no header itself.  Such a
//! block costs one header hash fewer than the counts here, the store's,
//! and these tests do not make one.
//!
//! The counter sees calls of `BlockHeader::block_hash` only.  A header
//! hashed from serialized bytes is not counted:
//! `Transaction::store_block_raw` does that to check the hash it is
//! given, which no step of these calls goes through.

// Test-harness arithmetic over small counts.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::Arc;

use dcroxide_blockchain::HashedBlock;
use dcroxide_blockchain::agendas::VOTE_ID_HEADER_COMMITMENTS;
use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::{Params, regnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_testutil::unhex;
use dcroxide_wire::{MsgBlock, header_hashes_on_this_thread};
use tempfile::TempDir;

/// How a block reaches the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arrival {
    /// `Chain::process_hashed_block`.
    Hashed,
    /// `Chain::process_shared_block`.
    Shared,
    /// `Chain::process_block`.
    Borrowed,
}

/// How the chain validates the blocks it is handed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Validation {
    /// Every check, as for a block past the assumed valid block.
    Full,
    /// `Chain::bulk_import_mode`: the block is marked valid as its data
    /// is accepted and connected without the expensive checks, which is
    /// also how an ancestor of the assumed valid block is added (dcrd
    /// `BFFastAdd`, `process.go:517-524`).  A chain as short as this one
    /// has no such ancestor, so the mode stands in for it.
    FastAdd,
}

/// The header hashes of one processing call on the processing thread,
/// by how the block is validated, whether the header commitments agenda
/// is decided for it, and how it arrived.
const HEADER_HASHES_PER_BLOCK: [(Validation, bool, Arrival, u64); 12] = [
    (Validation::Full, true, Arrival::Hashed, 7),
    (Validation::Full, true, Arrival::Shared, 7),
    (Validation::Full, true, Arrival::Borrowed, 7),
    (Validation::Full, false, Arrival::Hashed, 6),
    (Validation::Full, false, Arrival::Shared, 6),
    (Validation::Full, false, Arrival::Borrowed, 6),
    (Validation::FastAdd, true, Arrival::Hashed, 9),
    (Validation::FastAdd, true, Arrival::Shared, 9),
    (Validation::FastAdd, true, Arrival::Borrowed, 9),
    (Validation::FastAdd, false, Arrival::Hashed, 8),
    (Validation::FastAdd, false, Arrival::Shared, 8),
    (Validation::FastAdd, false, Arrival::Borrowed, 8),
];

/// The header hashes of one `Chain::maybe_accept_block_data` call.
const HEADER_HASHES_OF_DATA_ACCEPTANCE: u64 = 2;

/// Regnet, with the header commitments agenda forced to "no" when
/// `decided` is set (dcrd's `forceDeploymentResult`), which is the state
/// the main and test networks are in for every block: the merkle
/// commitment is then proven before the data is accepted and recorded
/// under the block's hash.
fn regnet(decided: bool) -> Params {
    let mut params = regnet_params();
    if decided {
        let mut found = false;
        for (_, deployments) in &mut params.deployments {
            for deployment in deployments.iter_mut() {
                if deployment.vote.id == VOTE_ID_HEADER_COMMITMENTS {
                    deployment.forced_choice_id = "no";
                    found = true;
                }
            }
        }
        assert!(found, "regnet has a header commitments deployment");
    }
    params
}

/// The battery's blocks that extend the tip one after another, with the
/// current time the battery is replayed at.
fn tip_extensions(limit: usize) -> (i64, Vec<MsgBlock>) {
    let (mut now, mut tip, mut blocks) = (0, regnet_params().genesis_hash, Vec::new());
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("now"),
            "accept" if f[2] == "true" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                if block.header.prev_block != tip {
                    break;
                }
                tip = block.header.block_hash();
                blocks.push(block);
                if blocks.len() == limit {
                    break;
                }
            }
            _ => {}
        }
    }
    assert_eq!(blocks.len(), limit, "the battery extends the tip enough");
    (now, blocks)
}

/// A new chain over a database of its own.
fn open(dir: &TempDir, name: &str, params: &Params) -> Chain {
    let opts = Options::new(dir.path().join(name), params.net.0);
    let db = Database::create(&opts).expect("create database");
    Chain::open(db, params, Hash::ZERO, false, 0).expect("open chain")
}

/// Process the blocks one after another on a new chain and return, for
/// each, how many headers the call hashed on this thread.  With
/// `headers_first` every header is in the index before the first block
/// arrives.
fn header_hashes_per_block(
    validation: Validation,
    arrival: Arrival,
    decided: bool,
    headers_first: bool,
    now: i64,
    blocks: &[MsgBlock],
) -> Vec<u64> {
    let params = regnet(decided);
    let dir = TempDir::new().expect("tempdir");
    let mut chain = open(&dir, "chain", &params);
    chain.bulk_import_mode = validation == Validation::FastAdd;
    if headers_first {
        for block in blocks {
            chain
                .process_block_header(&block.header, now, &params)
                .expect("header");
        }
    }

    let mut counts = Vec::new();
    for (i, block) in blocks.iter().enumerate() {
        let what = format!("block {i} ({validation:?}, {arrival:?})");
        let shared = Arc::new(block.clone());
        // Hashed where the block was read, before the count starts.
        let hashed = HashedBlock::new(Arc::clone(&shared));
        let before = header_hashes_on_this_thread();
        let (fork_len, errs) = match arrival {
            Arrival::Hashed => chain.process_hashed_block(&hashed, now, &params),
            Arrival::Shared => chain.process_shared_block(&shared, now, &params),
            Arrival::Borrowed => chain.process_block(block, now, &params),
        };
        counts.push(header_hashes_on_this_thread() - before);
        assert!(errs.is_empty(), "{what}: {errs:?}");
        assert_eq!(fork_len, 0, "{what}");
        let tip = chain.best_chain.tip().expect("tip");
        assert_eq!(
            chain.store.node(tip).hash,
            *hashed.hash(),
            "{what}: the block did not become the tip"
        );
    }
    counts
}

/// With its header already in the index, each block is connected with
/// the header hashes the table gives for it, the same for every block
/// and however it arrives: one more where the merkle commitment is
/// proven and recorded before the data is accepted, and two more for a
/// block added without full validation.
#[test]
fn a_connected_block_costs_the_processing_thread_the_header_hashes_of_the_table() {
    let (now, blocks) = tip_extensions(40);
    let measured: Vec<(Validation, bool, Arrival, Vec<u64>)> = HEADER_HASHES_PER_BLOCK
        .iter()
        .map(|&(validation, decided, arrival, _)| {
            let counts = header_hashes_per_block(validation, arrival, decided, true, now, &blocks);
            (validation, decided, arrival, counts)
        })
        .collect();
    let expected: Vec<(Validation, bool, Arrival, Vec<u64>)> = HEADER_HASHES_PER_BLOCK
        .iter()
        .map(|&(validation, decided, arrival, count)| {
            (validation, decided, arrival, vec![count; blocks.len()])
        })
        .collect();
    assert_eq!(measured, expected);
}

/// A block whose header is not in the index yet has it accepted first,
/// which hashes the header for itself.  What that adds is the same
/// however the block arrives.
#[test]
fn accepting_the_header_adds_the_same_hashes_however_the_block_arrives() {
    let (now, blocks) = tip_extensions(20);
    for validation in [Validation::Full, Validation::FastAdd] {
        for decided in [true, false] {
            let added = |arrival| -> Vec<u64> {
                let known =
                    header_hashes_per_block(validation, arrival, decided, true, now, &blocks);
                let unknown =
                    header_hashes_per_block(validation, arrival, decided, false, now, &blocks);
                unknown.iter().zip(&known).map(|(u, k)| u - k).collect()
            };
            let what = format!("{validation:?}, decided: {decided}");
            let for_hashed = added(Arrival::Hashed);
            assert!(
                for_hashed.iter().all(|&n| n >= 1),
                "{what}: accepting a header hashes it: {for_hashed:?}"
            );
            assert_eq!(added(Arrival::Shared), for_hashed, "{what}");
            assert_eq!(added(Arrival::Borrowed), for_hashed, "{what}");
        }
    }
}

/// `Chain::maybe_accept_block_data` hashes the header of the block it
/// is lent and files the block under that hash: in the mirror of recent
/// blocks and, over a database, in the store, which hashes the header
/// again, as the bytes the block serializes to.
#[test]
fn accepted_data_is_filed_under_the_hash_of_its_header() {
    let (now, blocks) = tip_extensions(3);
    let params = regnet(true);
    let dir = TempDir::new().expect("tempdir");
    let mut chain = open(&dir, "chain", &params);
    for block in &blocks {
        chain
            .process_block_header(&block.header, now, &params)
            .expect("header");
    }

    for (i, block) in blocks.iter().enumerate() {
        let hash = block.header.block_hash();
        let node = chain.index.lookup_node(&hash).expect("the header's node");
        assert!(!chain.blocks.contains_key(&hash.0), "block {i}");

        let before = header_hashes_on_this_thread();
        let linked = chain
            .maybe_accept_block_data(node, block, false, &params)
            .expect("the data is accepted");
        assert_eq!(
            header_hashes_on_this_thread() - before,
            HEADER_HASHES_OF_DATA_ACCEPTANCE,
            "block {i}"
        );

        // Each block's parent has its data by now, so the block is the
        // one node its data links.
        assert_eq!(linked, vec![node], "block {i}");
        assert_eq!(
            chain.blocks.get(&hash.0).map(|kept| (**kept).clone()),
            Some(block.clone()),
            "block {i}: the mirror"
        );
        let db = chain.db.as_ref().expect("the chain has a database");
        db.view(|tx| {
            assert!(tx.has_block(&hash, block.header.height)?, "block {i}");
            assert_eq!(
                tx.fetch_block(&hash, block.header.height)?,
                block.serialize(),
                "block {i}: the stored bytes"
            );
            Ok(())
        })
        .expect("view");

        // A second call finds the data already there and does nothing.
        let before = header_hashes_on_this_thread();
        let again = chain
            .maybe_accept_block_data(node, block, false, &params)
            .expect("the data is there");
        assert_eq!(again, Vec::new(), "block {i}");
        assert_eq!(header_hashes_on_this_thread(), before, "block {i}");
    }
}
