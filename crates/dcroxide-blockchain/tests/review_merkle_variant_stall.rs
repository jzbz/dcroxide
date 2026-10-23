// SPDX-License-Identifier: ISC
//! A block committing to the merkle variant not in force is rejected
//! without being marked, and does not stall a valid sibling.
//!
//! On regnet before a tally has found the header commitments
//! activation, the positional state of that agenda is undetermined, so
//! dcrd's `checkBlockDataPreconditions` accepts data matching either
//! merkle variant without proving the commitment
//! (`validate.go:2037-2048`).  A copy of a genuine block whose header's
//! merkle root is the combined (DCP0005) root therefore passes the
//! preconditions, is stored and linked, and becomes a best chain
//! candidate.  The contextual merkle check then rejects it with
//! `ErrBadMerkleRoot` (`validate.go:2063-2078`, `:2134-2142`), which
//! `maybeAcceptBlocks` and `reorganizeChainInternal` do not mark
//! (`process.go:367-374`, `chain.go:1209-1215`): data that matches a
//! header only under the variant not in force does not show the header
//! invalid.
//!
//! dcrd then keeps the block as a candidate.  While it, or a branch on
//! it, is the best candidate, `reorganizeChain` is handed it again after
//! the failed attempt and stops (`chain.go:1338-1341`), so the genuine
//! block, which ties on work and lost on received order, is rejected
//! with the copy's error, and the tip stays at the fork point until a
//! branch with strictly more work arrives.  The port takes the block,
//! and every candidate descending from it, out of the candidates when a
//! reorganization fails at it, still without marking any of them, and
//! falls back to the next best candidate in the same call; it also drops
//! the block's body from memory.  docs/PARITY.md records the divergence.
//!
//! dcrd's results in the first test were observed in dcrd at `6f6cf21b`,
//! whose code on that path is unchanged at `382ff4dd`; those the other
//! tests give for dcrd are read from that code.
//!
//! Every test runs on regnet as shipped with a database, on the
//! battery's accepted blocks up to `bm2` (height 4); `bm3` through `bm6`
//! are the genuine blocks that follow it, and `bm1` the one before `bm2`.

// Test-harness arithmetic over bounded values.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::blockindex::BlockStatus;
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::{RuleError, RuleErrorKind};
use dcroxide_chaincfg::{Params, regnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_standalone::{BigInt, Sign, check_proof_of_work};
use dcroxide_testutil::unhex;
use dcroxide_wire::{BlockHeader, MsgBlock};

/// The battery's accepted blocks before `bm3`, and `bm1` through `bm6`.
struct Battery {
    before_bm3: Vec<(MsgBlock, i64)>,
    bm1: MsgBlock,
    bm2: MsgBlock,
    bm3: MsgBlock,
    bm4: MsgBlock,
    bm5: MsgBlock,
    bm6: MsgBlock,
    now: i64,
}

fn battery() -> Battery {
    let mut now = 0;
    let mut before_bm3 = Vec::new();
    let mut named = std::collections::BTreeMap::new();
    let mut bm3_now = None;
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("now"),
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                if f[1] == "bm3" {
                    bm3_now = Some(now);
                }
                if bm3_now.is_none() {
                    before_bm3.push((block.clone(), now));
                }
                named.insert(f[1].to_string(), block);
            }
            _ => {}
        }
    }
    let mut take = |name: &str| {
        named
            .remove(name)
            .unwrap_or_else(|| panic!("{name} is in the battery"))
    };
    Battery {
        before_bm3,
        bm1: take("bm1"),
        bm2: take("bm2"),
        bm3: take("bm3"),
        bm4: take("bm4"),
        bm5: take("bm5"),
        bm6: take("bm6"),
        now: bm3_now.expect("bm3 is in the battery"),
    }
}

/// A database-backed chain at `bm2`.
fn chain_at_bm2(battery: &Battery, opts: &Options, params: &Params) -> Chain {
    let db = Database::create(opts).expect("create database");
    let mut chain = Chain::open(db, params, Hash::ZERO, false, 0).expect("open chain");
    for (block, now) in &battery.before_bm3 {
        let (_, errs) = chain.process_block(block, *now, params);
        assert!(errs.is_empty(), "{errs:?}");
    }
    assert_eq!(tip(&chain), battery.bm2.header.block_hash());
    chain
}

/// Grind the header's nonce from the given one until both of its proof
/// of work hashes meet its target, whichever the chain then checks.
fn grind_from(header: &mut BlockHeader, params: &Params, nonce: u32) {
    let pow_limit = BigInt::from_bytes_be(Sign::Plus, &params.pow_limit.to_be_bytes());
    let solved = |header: &BlockHeader| {
        [header.pow_hash_v1(), header.pow_hash_v2()]
            .iter()
            .all(|hash| check_proof_of_work(hash, header.bits, &pow_limit).is_ok())
    };
    header.nonce = nonce;
    while !solved(header) {
        header.nonce += 1;
    }
}

/// [`grind_from`] from zero.
fn grind(header: &mut BlockHeader, params: &Params) {
    grind_from(header, params, 0);
}

/// The block solved again from the nonce after its own: the same data
/// and parent under another hash.
fn another_solution(block: &MsgBlock, params: &Params) -> MsgBlock {
    let mut other = block.clone();
    grind_from(&mut other.header, params, block.header.nonce + 1);
    assert_ne!(other.header.block_hash(), block.header.block_hash());
    other
}

/// The block with its header committing to the combined root of its
/// two transaction trees, the variant not in force, and solved again.
fn wrong_variant_copy(block: &MsgBlock, params: &Params) -> MsgBlock {
    let mut copy = block.clone();
    copy.header.merkle_root = dcroxide_standalone::calc_combined_tx_tree_merkle_root(
        &copy.transactions,
        &copy.stransactions,
    );
    assert_ne!(copy.header.merkle_root, block.header.merkle_root);
    grind(&mut copy.header, params);
    copy
}

/// The block's data on another parent at the same height, solved again.
fn on_parent(block: &MsgBlock, parent: &MsgBlock, params: &Params) -> MsgBlock {
    let mut child = block.clone();
    child.header.prev_block = parent.header.block_hash();
    grind(&mut child.header, params);
    child
}

fn tip(chain: &Chain) -> Hash {
    chain
        .store
        .node(chain.best_chain.tip().expect("best chain tip"))
        .hash
}

fn status(chain: &Chain, block: &MsgBlock) -> BlockStatus {
    let node = chain
        .index
        .lookup_node(&block.header.block_hash())
        .expect("indexed");
    chain.store.node(node).status
}

fn is_candidate(chain: &Chain, block: &MsgBlock) -> bool {
    let node = chain
        .index
        .lookup_node(&block.header.block_hash())
        .expect("indexed");
    chain.index.is_best_chain_candidate(node)
}

/// The errors are the given number of `ErrBadMerkleRoot`s, each for the
/// copy's header.
fn assert_copy_errors(errs: &[RuleError], copy: &MsgBlock, count: usize) {
    assert_eq!(errs.len(), count, "{errs:?}");
    for err in errs {
        assert_eq!(err.kind, RuleErrorKind::BadMerkleRoot, "{err:?}");
        assert!(
            err.description
                .contains(&copy.header.merkle_root.to_string()),
            "{err:?}"
        );
    }
}

/// The case dcrd stalls on: the copy of `bm3`, then `bm3`, then `bm4`.
/// dcrd at `6f6cf21b` returns the copy's `ErrBadMerkleRoot` twice, leaves the copy stored, unmarked and the best candidate,
/// returns the same error for `bm3` with the tip still at `bm2`, and
/// moves only for `bm4`.  The copy's own processing gives dcrd's result
/// here too; `bm3` then connects.
#[test]
fn a_copy_committing_to_the_variant_not_in_force_does_not_stall_its_sibling() {
    let params = regnet_params();
    let battery = battery();
    let dir = tempfile::tempdir().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let mut chain = chain_at_bm2(&battery, &opts, &params);
    let now = battery.now;
    let copy = wrong_variant_copy(&battery.bm3, &params);
    let copy_hash = copy.header.block_hash();

    // Rejected by the contextual check as it is accepted, then by the
    // reorganization to it.
    let (_, errs) = chain.process_block(&copy, now, &params);
    assert_copy_errors(&errs, &copy, 2);
    assert_eq!(status(&chain, &copy), BlockStatus::DATA_STORED, "unmarked");
    assert!(!is_candidate(&chain, &copy));
    assert!(!chain.blocks.contains_key(&copy_hash.0), "body resident");
    assert!(chain.block_by_hash(&copy_hash).is_some(), "body stored");
    assert_eq!(tip(&chain), battery.bm2.header.block_hash());

    // The copy again is a duplicate, and its header is still valid.
    let (_, again) = chain.process_block(&copy, now, &params);
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].kind, RuleErrorKind::DuplicateBlock);
    assert_eq!(
        chain.process_block_header(&copy.header, now, &params),
        Ok(())
    );

    let (_, errs) = chain.process_block(&battery.bm3, now, &params);
    assert!(errs.is_empty(), "{errs:?}");
    assert_eq!(tip(&chain), battery.bm3.header.block_hash());

    let (_, errs) = chain.process_block(&battery.bm4, now, &params);
    assert!(errs.is_empty(), "{errs:?}");
    assert_eq!(tip(&chain), battery.bm4.header.block_hash());
    assert_eq!(status(&chain, &copy), BlockStatus::DATA_STORED);
    assert!(!chain.blocks.contains_key(&copy_hash.0));
}

/// A branch on the copy does not bring the stall back.  Its first block
/// passes its own checks, and the reorganization to it fails at the copy
/// with the copy's error, as in dcrd, which then stalls on it: there
/// `bm3` and even `bm4`, which ties with it on work, get the copy's
/// error.  A longer branch on the copy, sent once `bm3` is the tip,
/// makes the reorganization detach `bm3` before it fails at the copy;
/// dcrd stops there with the tip at `bm2`, the port reorganizes back to
/// `bm3`.
#[test]
fn a_branch_on_the_copy_does_not_stall_the_chain() {
    let params = regnet_params();
    let battery = battery();
    let dir = tempfile::tempdir().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let mut chain = chain_at_bm2(&battery, &opts, &params);
    let now = battery.now;
    let copy = wrong_variant_copy(&battery.bm3, &params);
    let child = on_parent(&battery.bm4, &copy, &params);
    let grandchild = on_parent(&battery.bm5, &child, &params);

    let (_, errs) = chain.process_block(&copy, now, &params);
    assert_copy_errors(&errs, &copy, 2);
    let (_, errs) = chain.process_block(&child, now, &params);
    assert_copy_errors(&errs, &copy, 1);
    for block in [&copy, &child] {
        assert_eq!(status(&chain, block), BlockStatus::DATA_STORED);
        assert!(!is_candidate(&chain, block));
    }
    assert_eq!(tip(&chain), battery.bm2.header.block_hash());

    let (_, errs) = chain.process_block(&battery.bm3, now, &params);
    assert!(errs.is_empty(), "{errs:?}");
    assert_eq!(tip(&chain), battery.bm3.header.block_hash());

    let (_, errs) = chain.process_block(&grandchild, now, &params);
    assert_copy_errors(&errs, &copy, 1);
    assert_eq!(status(&chain, &grandchild), BlockStatus::DATA_STORED);
    assert!(!is_candidate(&chain, &grandchild));
    assert_eq!(tip(&chain), battery.bm3.header.block_hash());

    let (_, errs) = chain.process_block(&battery.bm4, now, &params);
    assert!(errs.is_empty(), "{errs:?}");
    assert_eq!(tip(&chain), battery.bm4.header.block_hash());
}

/// A restart keeps only the tip as a candidate, in dcrd as here, so the
/// copy is no candidate after it; a block on the copy that arrives then
/// is handled as before the restart.  The load mirrors the stored body
/// of every block on a chain tip's branch near the tip, which it cannot
/// tell from a valid side branch's, so the copy's body is resident
/// again until the reorganization to the block on it fails at the copy
/// and drops it.
#[test]
fn a_branch_on_the_copy_after_a_restart_does_not_stall_the_chain() {
    let params = regnet_params();
    let battery = battery();
    let dir = tempfile::tempdir().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let mut chain = chain_at_bm2(&battery, &opts, &params);
    let now = battery.now;
    let copy = wrong_variant_copy(&battery.bm3, &params);
    let copy_hash = copy.header.block_hash();
    let child = on_parent(&battery.bm4, &copy, &params);

    let (_, errs) = chain.process_block(&copy, now, &params);
    assert_copy_errors(&errs, &copy, 2);
    chain.flush(&params).expect("flush");
    drop(chain);
    let db = Database::open(&opts).expect("reopen database");
    let mut chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("reopen chain");
    assert_eq!(tip(&chain), battery.bm2.header.block_hash());
    assert_eq!(status(&chain, &copy), BlockStatus::DATA_STORED);
    assert!(!is_candidate(&chain, &copy));
    assert!(chain.blocks.contains_key(&copy_hash.0), "body reloaded");

    let (_, errs) = chain.process_block(&child, now, &params);
    assert_copy_errors(&errs, &copy, 1);
    assert!(!is_candidate(&chain, &child));
    assert!(!chain.blocks.contains_key(&copy_hash.0), "body resident");
    let (_, errs) = chain.process_block(&battery.bm3, now, &params);
    assert!(errs.is_empty(), "{errs:?}");
    assert_eq!(tip(&chain), battery.bm3.header.block_hash());
}

/// `invalidateblock` marks the copy, and `reconsiderblock` unmarks it and
/// makes it a candidate again (`process.go:840-842`).  The
/// reorganization that ends the call fails at it with dcrd's error and
/// leaves it unmarked; dcrd then stalls on it again, the port falls back.
#[test]
fn reconsidering_the_copy_does_not_stall_the_chain() {
    let params = regnet_params();
    let battery = battery();
    let dir = tempfile::tempdir().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let mut chain = chain_at_bm2(&battery, &opts, &params);
    let now = battery.now;
    let copy = wrong_variant_copy(&battery.bm3, &params);
    let copy_hash = copy.header.block_hash();

    let (_, errs) = chain.process_block(&copy, now, &params);
    assert_copy_errors(&errs, &copy, 2);
    let errs = chain.invalidate_block(&copy_hash, now, &params);
    assert!(errs.is_empty(), "{errs:?}");
    assert_eq!(
        status(&chain, &copy),
        BlockStatus(BlockStatus::DATA_STORED.0 | BlockStatus::VALIDATE_FAILED.0)
    );

    let errs = chain.reconsider_block(&copy_hash, now, &params);
    assert_copy_errors(&errs, &copy, 1);
    assert_eq!(status(&chain, &copy), BlockStatus::DATA_STORED);
    assert!(!is_candidate(&chain, &copy));
    assert_eq!(tip(&chain), battery.bm2.header.block_hash());

    let (_, errs) = chain.process_block(&battery.bm3, now, &params);
    assert!(errs.is_empty(), "{errs:?}");
    assert_eq!(tip(&chain), battery.bm3.header.block_hash());
}

/// Neither place dcrd exempts a contextual `ErrBadMerkleRoot` from
/// marking (`process.go:367-374`, `chain.go:1209-1215`) marks the block,
/// or its descendants.  A copy of the tip, `bm2`, ties with it on work
/// and loses on received order, so its processing reaches only the
/// check made as it is accepted: one error.  A block on the copy has
/// more work, passes its own checks, and makes the reorganization detach
/// `bm2` and fail at the copy: one error, from that attempt alone.  This
/// holds with or without the port's removal of the copy from the
/// candidates.
#[test]
fn a_contextual_bad_merkle_root_marks_no_block() {
    let params = regnet_params();
    let battery = battery();
    let dir = tempfile::tempdir().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let mut chain = chain_at_bm2(&battery, &opts, &params);
    let now = battery.now;
    let copy = wrong_variant_copy(&battery.bm2, &params);
    let child = on_parent(&battery.bm3, &copy, &params);

    let (_, errs) = chain.process_block(&copy, now, &params);
    assert_copy_errors(&errs, &copy, 1);
    assert_eq!(status(&chain, &copy), BlockStatus::DATA_STORED);
    assert_eq!(chain.index.best_invalid(), None);
    assert_eq!(tip(&chain), battery.bm2.header.block_hash());

    let (_, errs) = chain.process_block(&child, now, &params);
    assert_copy_errors(&errs, &copy, 1);
    assert_eq!(status(&chain, &copy), BlockStatus::DATA_STORED);
    assert_eq!(status(&chain, &child), BlockStatus::DATA_STORED);
    assert_eq!(chain.index.best_invalid(), None);
    assert_eq!(
        chain.index.best_header().map(|n| chain.store.node(n).hash),
        Some(child.header.block_hash()),
        "the best header is still the child's"
    );
}

/// A side branch from `bm1` on the chain at `bm5`: `a4`, `a5` and `a6`
/// carry `bm2`, `bm3` and `bm4`'s data, and `s6` is another solution of
/// `a6`.  On each block at height 6 is a copy carrying `bm5`'s data:
/// `c7` on `a6`, with `d8`, carrying `bm6`'s data, on it, and `t7` on
/// `s6`.
struct SideBranch {
    a6: MsgBlock,
    s6: MsgBlock,
    c7: MsgBlock,
}

/// The chain at `bm5` with the side branch processed and `bm3`
/// invalidated.  The side blocks have less work than `bm5` and become
/// no candidates; `t7` ties with `bm5` and loses on received order, and
/// stays one, as `c7` does; `d8` makes the reorganization attach `a4`
/// through `a6` and fail at `c7`, which drops `c7` and `d8` and falls
/// back to `bm5`.  Invalidating `bm3` puts `d8` and `t7` back as
/// candidates with `bm2` (`process.go:744-766`); the reorganization to
/// `d8` attaches `a5`, which removes `bm2` as having less work, fails at
/// `c7` and drops it with `d8`, and the fallback to `t7` attaches `s6`
/// and fails at `t7`, which leaves no other candidate, with the tip at
/// `s6`.  In dcrd the tip stays at `a6` from `d8` on, with `c7`, `d8`
/// and `t7` candidates, and invalidating `bm3`, a block no longer on its
/// best chain, only marks it.
fn chain_after_the_fallbacks(
    battery: &Battery,
    opts: &Options,
    params: &Params,
) -> (Chain, SideBranch) {
    let mut chain = chain_at_bm2(battery, opts, params);
    let now = battery.now;
    for block in [&battery.bm3, &battery.bm4, &battery.bm5] {
        let (_, errs) = chain.process_block(block, now, params);
        assert!(errs.is_empty(), "{errs:?}");
    }
    let a4 = on_parent(&battery.bm2, &battery.bm1, params);
    let a5 = on_parent(&battery.bm3, &a4, params);
    let a6 = on_parent(&battery.bm4, &a5, params);
    let s6 = another_solution(&a6, params);
    let c7 = wrong_variant_copy(&on_parent(&battery.bm5, &a6, params), params);
    let t7 = wrong_variant_copy(&on_parent(&battery.bm5, &s6, params), params);
    let d8 = on_parent(&battery.bm6, &c7, params);
    for block in [&a4, &a5, &a6, &s6] {
        let (_, errs) = chain.process_block(block, now, params);
        assert!(errs.is_empty(), "{errs:?}");
    }
    for block in [&t7, &c7, &d8] {
        let (_, errs) = chain.process_block(block, now, params);
        assert_copy_errors(&errs, &c7, 1);
    }
    assert_eq!(tip(&chain), battery.bm5.header.block_hash());

    let errs = chain.invalidate_block(&battery.bm3.header.block_hash(), now, params);
    assert_copy_errors(&errs, &c7, 2);
    assert_eq!(tip(&chain), s6.header.block_hash());
    for block in [&c7, &d8, &t7] {
        assert_eq!(status(&chain, block), BlockStatus::DATA_STORED);
        assert!(!is_candidate(&chain, block));
    }
    (chain, SideBranch { a6, s6, c7 })
}

/// dcrd's candidates always hold at least the current tip, which
/// `RemoveLessWorkCandidates` asserts (`blockindex.go:1279-1284`).  The
/// fallbacks above took every candidate, and the tip, `s6`, never was
/// one; a forced reorganization to its sibling `a6` then connected a
/// block with no candidate left and panicked on that assertion.  The tip
/// is made a candidate again instead, and the reorganization succeeds.
/// dcrd, whose tip is `a6`, refuses it as made on the wrong chain.
#[test]
fn the_tip_stays_a_candidate_when_the_fallbacks_drop_every_other() {
    let params = regnet_params();
    let battery = battery();
    let dir = tempfile::tempdir().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let (mut chain, side) = chain_after_the_fallbacks(&battery, &opts, &params);
    assert!(is_candidate(&chain, &side.s6));

    let errs = chain.force_head_reorganization(
        side.s6.header.block_hash(),
        side.a6.header.block_hash(),
        battery.now,
        &params,
    );
    assert!(errs.is_empty(), "{errs:?}");
    assert_eq!(tip(&chain), side.a6.header.block_hash());
    assert_eq!(status(&chain, &side.c7), BlockStatus::DATA_STORED);
}

/// With no candidate left, a sibling of the tip with equal work, received
/// after it, became the only candidate and replaced it, where a tie goes
/// to the block received first (`blockindex.go:469-473`).  With the tip a
/// candidate again it keeps the tie.
#[test]
fn a_later_sibling_of_equal_work_does_not_replace_the_tip_after_the_fallbacks() {
    let params = regnet_params();
    let battery = battery();
    let dir = tempfile::tempdir().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let (mut chain, side) = chain_after_the_fallbacks(&battery, &opts, &params);
    let sibling = another_solution(&side.s6, &params);

    let (_, errs) = chain.process_block(&sibling, battery.now, &params);
    assert!(errs.is_empty(), "{errs:?}");
    assert_eq!(tip(&chain), side.s6.header.block_hash());
}
