// SPDX-License-Identifier: ISC
//! dcrd's full block battery (`data/fullblock_vectors.txt`) through the
//! three ways a block reaches the chain, on chains that store their
//! blocks in a database.
//!
//! `Chain::process_block` is lent the block, `Chain::process_shared_block`
//! shares its allocation and `Chain::process_hashed_block` is handed it
//! with its hashes.  The batteries beside this one compare them on
//! chains that keep everything in memory.  A chain over a database does
//! more with a block: it writes the block unless the database already
//! has it, drops the body of a block it has marked as failed from its
//! mirror of recent blocks, and reads a block it no longer holds back
//! from the database, a new allocation that it hashes again.  None of
//! that depends on how the block arrived: every row gives the same fork
//! length and the same errors with the same texts, and leaves the same
//! tip and the same blocks in the mirror, on all three chains.  A block
//! that arrived shared is held by the chain in its mirror or not at all.

// Test-harness arithmetic over small counts.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::Arc;

use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::{HashedBlock, RuleError, RuleErrorKind};
use dcroxide_chaincfg::regnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;
use tempfile::TempDir;

/// What a processing call reported, in a form that compares.
fn outcome(result: &(i64, Vec<RuleError>)) -> (i64, Vec<(RuleErrorKind, String)>) {
    (
        result.0,
        result
            .1
            .iter()
            .map(|err| (err.kind, err.description.clone()))
            .collect(),
    )
}

/// The hash of the chain's best block.
fn tip_hash(chain: &Chain) -> Hash {
    chain.store.node(chain.best_chain.tip().expect("tip")).hash
}

/// The hashes of the blocks the chain's mirror of recent blocks holds.
fn mirrored(chain: &Chain) -> Vec<[u8; 32]> {
    chain.blocks.keys().copied().collect()
}

/// A new chain over a database of its own.
fn open(dir: &TempDir, name: &str) -> Chain {
    let params = regnet_params();
    let opts = Options::new(dir.path().join(name), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let mut chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("open chain");
    // Flush the UTXO cache on every connect, so that the replay goes
    // through the flush and the database fallbacks as well.
    chain.set_utxo_cache_max_bytes(1);
    chain
}

/// Every row of the battery gives the same result on a chain over a
/// database whether the block is lent, shared or arrives hashed.
#[test]
fn the_battery_gives_the_same_outcomes_through_every_entry_on_stored_chains() {
    let params = regnet_params();
    let dir = TempDir::new().expect("tempdir");
    let mut borrowed = open(&dir, "borrowed");
    let mut shared = open(&dir, "shared");
    let mut hashed = open(&dir, "hashed");

    let mut now: i64 = 0;
    let (mut rows, mut dropped, mut kept) = (0usize, 0usize, 0usize);
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let hex = match f[0] {
            "now" => {
                now = f[1].parse().expect("now");
                continue;
            }
            "accept" => f[4],
            "reject" => f[3],
            "orphanorreject" => f[2],
            _ => continue,
        };
        let name = f[1];
        let (block, _) = MsgBlock::from_bytes(&unhex(hex)).expect("block");
        let hash = block.header.block_hash().0;
        let lent = Arc::new(block.clone());
        let with_hashes = HashedBlock::new(Arc::new(block.clone()));
        let known_before = shared.blocks.contains_key(&hash);

        let b = borrowed.process_block(&block, now, &params);
        let s = shared.process_shared_block(&lent, now, &params);
        let h = hashed.process_hashed_block(&with_hashes, now, &params);
        assert_eq!(outcome(&s), outcome(&b), "{name}: shared");
        assert_eq!(outcome(&h), outcome(&b), "{name}: hashed");
        assert_eq!(tip_hash(&shared), tip_hash(&borrowed), "{name}: shared");
        assert_eq!(tip_hash(&hashed), tip_hash(&borrowed), "{name}: hashed");
        assert_eq!(mirrored(&shared), mirrored(&borrowed), "{name}: shared");
        assert_eq!(mirrored(&hashed), mirrored(&borrowed), "{name}: hashed");

        // The chain holds a block that arrived shared in its mirror, as
        // the caller's allocation, or nowhere: a block it refused, or
        // marked as failed and dropped, leaves the caller's reference
        // the only one.
        if !known_before {
            let in_mirror = shared.blocks.contains_key(&hash);
            let expected = if in_mirror { 2 } else { 1 };
            assert_eq!(Arc::strong_count(&lent), expected, "{name}: shared");
            assert_eq!(
                Arc::strong_count(with_hashes.block()),
                expected,
                "{name}: hashed"
            );
            if in_mirror {
                assert!(Arc::ptr_eq(&shared.blocks[&hash], &lent), "{name}: shared");
                assert!(
                    Arc::ptr_eq(&hashed.blocks[&hash], with_hashes.block()),
                    "{name}: hashed"
                );
                kept += 1;
            } else {
                dropped += 1;
            }
        }
        rows += 1;
    }

    assert!(rows > 500, "{rows} rows");
    assert!(
        kept > 100 && dropped > 100,
        "{kept} kept, {dropped} dropped"
    );
    // The chain handed hashed blocks hashed none of them as they
    // arrived, and all three hashed the same number of blocks again as
    // they connected them outside the call each arrived in.
    assert_eq!(hashed.arrivals_hashed, 0);
    assert_eq!(shared.arrivals_hashed, borrowed.arrivals_hashed);
    assert_eq!(shared.tx_hash_recomputes, borrowed.tx_hash_recomputes);
    assert_eq!(hashed.tx_hash_recomputes, borrowed.tx_hash_recomputes);
    assert!(
        borrowed.tx_hash_recomputes > 0,
        "no block was connected outside the call it arrived in"
    );
}
