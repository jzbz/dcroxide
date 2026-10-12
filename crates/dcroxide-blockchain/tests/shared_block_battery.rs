// SPDX-License-Identifier: ISC
//! dcrd's full block battery (`data/fullblock_vectors.txt`) through
//! `Chain::process_shared_block`, beside `Chain::process_block` on a twin
//! chain.
//!
//! A block that arrives shared by reference count is processed exactly as
//! a borrowed one: the same fork length, the same errors with the same
//! texts, and the same tip after every row.  What differs is only what
//! the chain keeps: the caller's own allocation where the block was
//! shared, and a copy of the block where it was borrowed (dcrd's
//! `ProcessBlock` caches the `*dcrutil.Block` it is handed,
//! `process.go:571`).

// Test-harness arithmetic over small counts.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::Arc;

use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::{RuleError, RuleErrorKind};
use dcroxide_chaincfg::regnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;

/// The battery's blocks in order, each with its row name and the
/// current time the row is replayed at.
fn battery_blocks() -> Vec<(String, i64, MsgBlock)> {
    let mut now = 0;
    let mut blocks = Vec::new();
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
        let (block, _) = MsgBlock::from_bytes(&unhex(hex)).expect("block");
        blocks.push((f[1].to_string(), now, block));
    }
    blocks
}

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

/// Every row of the battery gives the same result whether the block is
/// lent or shared, and the chain that was handed a shared block keeps
/// that very allocation where the other keeps a copy.
#[test]
fn the_battery_gives_the_same_outcomes_through_shared_blocks() {
    let params = regnet_params();
    let mut borrowed_chain = Chain::new(&params, Hash::ZERO, false);
    let mut shared_chain = Chain::new(&params, Hash::ZERO, false);

    // Every shared block is kept here as well, so no `Arc` the chain is
    // handed is ever the only one.
    let mut kept: Vec<Arc<MsgBlock>> = Vec::new();
    let (mut accepted, mut refused, mut mirrored) = (0usize, 0usize, 0usize);
    for (name, now, block) in battery_blocks() {
        let shared = Arc::new(block.clone());
        // The transaction lists of the shared block, by address: a copy
        // of the block would hold other ones.
        let regular_at = shared.transactions.as_ptr();
        let stake_at = shared.stransactions.as_ptr();

        let was_known = shared_chain
            .blocks
            .contains_key(&block.header.block_hash().0);
        let borrowed_result = borrowed_chain.process_block(&block, now, &params);
        let shared_result = shared_chain.process_shared_block(&shared, now, &params);
        assert_eq!(outcome(&shared_result), outcome(&borrowed_result), "{name}");
        assert_eq!(
            tip_hash(&shared_chain),
            tip_hash(&borrowed_chain),
            "{name}: the tips differ"
        );

        // The shared block is untouched, and still the caller's to use.
        assert_eq!(*shared, block, "{name}");

        if shared_result.1.is_empty() {
            accepted += 1;
        } else {
            refused += 1;
        }

        // A block whose data this call accepted is in both mirrors: as
        // the caller's allocation in one, as a copy in the other.
        let hash = block.header.block_hash().0;
        if !was_known && let Some(in_mirror) = shared_chain.blocks.get(&hash) {
            assert!(
                Arc::ptr_eq(in_mirror, &shared),
                "{name}: the mirror holds a copy of the shared block"
            );
            assert_eq!(in_mirror.transactions.as_ptr(), regular_at, "{name}");
            assert_eq!(in_mirror.stransactions.as_ptr(), stake_at, "{name}");
            // The caller's `Arc` and the mirror's, at least.
            assert!(Arc::strong_count(&shared) >= 2, "{name}");

            let copy = borrowed_chain
                .blocks
                .get(&hash)
                .unwrap_or_else(|| panic!("{name}: the twin chain did not keep the block"));
            assert!(!std::ptr::eq(Arc::as_ptr(copy), &raw const block), "{name}");
            assert_eq!(**copy, block, "{name}: the copy differs from the block");
            mirrored += 1;
        }
        kept.push(shared);
    }

    assert!(
        accepted >= 200 && refused >= 300,
        "{accepted} accepted, {refused} refused"
    );
    assert!(mirrored >= 200, "{mirrored} blocks kept by the mirror");

    // The mirrors hold the same blocks under the same hashes.
    assert_eq!(
        shared_chain.blocks.keys().collect::<Vec<_>>(),
        borrowed_chain.blocks.keys().collect::<Vec<_>>()
    );
    for (hash, block) in &shared_chain.blocks {
        assert_eq!(**block, *borrowed_chain.blocks[hash]);
    }
    drop(kept);
}

/// A block the chain refuses before it accepts the data is neither kept
/// nor copied: the caller's `Arc` stays the only one.
#[test]
fn a_refused_shared_block_is_not_kept() {
    let params = regnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);

    // The genesis block is already there: a duplicate.
    let genesis = Arc::new(params.genesis_block.clone());
    let (_, errs) = chain.process_shared_block(&genesis, 0, &params);
    assert_eq!(errs.len(), 1, "{errs:?}");
    assert_eq!(errs[0].kind, RuleErrorKind::DuplicateBlock);
    assert_eq!(Arc::strong_count(&genesis), 1);
    assert!(!Arc::ptr_eq(
        &chain.blocks[&genesis.header.block_hash().0],
        &genesis
    ));
}
