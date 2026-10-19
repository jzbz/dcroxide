// SPDX-License-Identifier: ISC
//! dcrd's full block battery (`data/fullblock_vectors.txt`) through
//! `Chain::process_hashed_block`, beside `Chain::process_block` on a
//! twin chain.
//!
//! A block may be hashed before it reaches the chain, into a
//! `HashedBlock`, and have its signature operations counted there too,
//! so that the thread connecting blocks does not hash it and counts it
//! only where that count is over the limit.  That changes nothing the
//! chain decides: every row of the battery, accepted, rejected or
//! orphaned, gives the same fork length and the same errors with the
//! same texts, and leaves the same tip, as the block processed without
//! hashes, the rows refused for too many signature operations among
//! them.  The chain that is handed hashed blocks hashes none of them
//! itself, keeps the allocation each arrived in, and connects with the
//! hashes it was handed.
//!
//! A hashed block may also carry the verdict of its data sanity checks,
//! reached where it was hashed (`HashedBlock::check_data_sanity`).  That
//! changes nothing either: the battery gives the same outcomes through
//! blocks checked with the values of the chain's parameters, which the
//! chain returns where it makes those checks, and through blocks checked
//! with another network's, which the chain does not read.

// Test-harness arithmetic over small counts.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::Arc;

use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::validate::DataSanityParams;
use dcroxide_blockchain::{HashedBlock, RuleError, RuleErrorKind};
use dcroxide_chaincfg::{mainnet_params, regnet_params};
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

/// Every row of the battery gives the same result whether the block
/// arrives hashed or is hashed by the chain, and the chain that was
/// handed hashed blocks hashed none of them itself.
#[test]
fn the_battery_gives_the_same_outcomes_through_hashed_blocks() {
    let params = regnet_params();
    let mut plain_chain = Chain::new(&params, Hash::ZERO, false);
    let mut hashed_chain = Chain::new(&params, Hash::ZERO, false);

    let (mut accepted, mut refused, mut mirrored) = (0usize, 0usize, 0usize);
    let mut kinds = std::collections::BTreeSet::new();
    for (name, now, block) in battery_blocks() {
        let hashed = HashedBlock::new(Arc::new(block.clone()));
        assert_eq!(*hashed.hash(), block.header.block_hash(), "{name}");

        let was_known = hashed_chain.blocks.contains_key(&hashed.hash().0);
        let plain_result = plain_chain.process_block(&block, now, &params);
        let hashed_result = hashed_chain.process_hashed_block(&hashed, now, &params);
        assert_eq!(outcome(&hashed_result), outcome(&plain_result), "{name}");
        assert_eq!(
            tip_hash(&hashed_chain),
            tip_hash(&plain_chain),
            "{name}: the tips differ"
        );

        match hashed_result.1.first() {
            None => accepted += 1,
            Some(err) => {
                refused += 1;
                kinds.insert(err.kind.kind_name());
            }
        }

        // A block whose data this call accepted is kept as the
        // allocation the hashed block owns.
        if !was_known && let Some(in_mirror) = hashed_chain.blocks.get(&hashed.hash().0) {
            assert!(
                Arc::ptr_eq(in_mirror, hashed.block()),
                "{name}: the mirror holds a copy of the hashed block"
            );
            mirrored += 1;
        }
    }

    assert!(
        accepted >= 200 && refused >= 300,
        "{accepted} accepted, {refused} refused"
    );
    assert!(mirrored >= 200, "{mirrored} blocks kept by the mirror");
    // The rejections are of many kinds, the merkle and duplicate checks
    // that read the hashes among them, and the rows refused for too many
    // signature operations are among those compared.  That the chain
    // counts a hashed block again where its count is over the limit is
    // shown in the crate's own tests
    // (`process::tests::the_battery_counts_a_hashed_block_only_over_the_limit`),
    // not here: a block over the limit that the contextual check let
    // through would be refused as it is connected, with the same kind
    // and text, by the count that includes pay-to-script-hash inputs.
    assert!(kinds.len() >= 40, "{} kinds: {kinds:?}", kinds.len());
    for kind in [
        "ErrBadMerkleRoot",
        "ErrDuplicateTx",
        "ErrDuplicateBlock",
        "ErrTooManySigOps",
    ] {
        assert!(kinds.contains(kind), "{kind} is not among {kinds:?}");
    }

    // The chain handed hashed blocks never hashed an arriving block; the
    // other hashed every block that got past its header checks.
    assert_eq!(hashed_chain.arrivals_hashed, 0);
    assert!(
        plain_chain.arrivals_hashed >= 300,
        "{} arrivals hashed",
        plain_chain.arrivals_hashed
    );
    // What a reorganization or a later link hashes again is the same
    // for both: those blocks are not the one being processed.
    assert_eq!(
        hashed_chain.tx_hash_recomputes,
        plain_chain.tx_hash_recomputes
    );

    // The mirrors hold the same blocks under the same hashes.
    assert_eq!(
        hashed_chain.blocks.keys().collect::<Vec<_>>(),
        plain_chain.blocks.keys().collect::<Vec<_>>()
    );
    for (hash, block) in &hashed_chain.blocks {
        assert_eq!(**block, *plain_chain.blocks[hash]);
    }
}

/// Every row of the battery gives the same result, and leaves the same
/// tip, whether the block arrives plain or hashed and checked for its
/// data's sanity, with the values of the chain's parameters or with
/// mainnet's, and the rows refused by those checks are among them.
#[test]
fn the_battery_gives_the_same_outcomes_through_checked_hashed_blocks() {
    let params = regnet_params();
    let own = DataSanityParams::of(&params);
    let other = DataSanityParams::of(&mainnet_params());
    assert_ne!(own, other);
    let mut plain_chain = Chain::new(&params, Hash::ZERO, false);
    let mut own_chain = Chain::new(&params, Hash::ZERO, false);
    let mut other_chain = Chain::new(&params, Hash::ZERO, false);

    let mut kinds = std::collections::BTreeSet::new();
    for (name, now, block) in battery_blocks() {
        let shared = Arc::new(block);
        let plain_result = plain_chain.process_shared_block(&shared, now, &params);
        for (values, chain) in [(own, &mut own_chain), (other, &mut other_chain)] {
            let mut hashed = HashedBlock::new(Arc::clone(&shared));
            assert_eq!(hashed.data_sanity_params(), None, "{name}");
            hashed.check_data_sanity(values);
            assert_eq!(hashed.data_sanity_params(), Some(values), "{name}");
            let result = chain.process_hashed_block(&hashed, now, &params);
            assert_eq!(outcome(&result), outcome(&plain_result), "{name}");
            assert_eq!(tip_hash(chain), tip_hash(&plain_chain), "{name}");
        }
        if let Some(err) = plain_result.1.first() {
            kinds.insert(err.kind.kind_name());
        }
    }
    // The chain handed verdicts reached with its own values checked no
    // arriving block itself; the one handed mainnet's checked every
    // block the plain chain checked.
    assert_eq!(own_chain.arrivals_checked, 0);
    assert!(plain_chain.arrivals_checked >= 300);
    assert_eq!(other_chain.arrivals_checked, plain_chain.arrivals_checked);
    for kind in [
        "ErrBadTxOutValue",
        "ErrDuplicateTx",
        "ErrDuplicateTxInputs",
        "ErrFreshStakeMismatch",
        "ErrNoTransactions",
        "ErrNoTxInputs",
        "ErrNoTxOutputs",
        "ErrNotEnoughStake",
        "ErrStakeBelowMinimum",
        "ErrWrongBlockSize",
    ] {
        assert!(kinds.contains(kind), "{kind} is not among {kinds:?}");
    }
}
