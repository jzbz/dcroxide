// SPDX-License-Identifier: ISC
//! Blocks whose transactions are not the ones their header commits to,
//! or are too many or none, through the three ways a block reaches the
//! chain: `Chain::process_block`, `Chain::process_shared_block` and
//! `Chain::process_hashed_block`.
//!
//! A block that arrives in a `HashedBlock` brings the roots of its two
//! transaction merkle trees, built where it was hashed, and the chain
//! compares those with the header where it builds the trees itself for
//! any other block (dcrd `checkMerkleRoots`, `validate.go:1897-1952`).
//! That moves no decision: for each shape below the three entries give
//! the same fork length and the same error with the same text, and leave
//! the header's index entry, the best header, the tip and the mirror of
//! recent blocks the same.  The shapes are run under each state the
//! header commitments agenda can be in when the check asks: decided
//! inactive, decided active, and not decidable from the block's
//! position, where both commitments are tried.
//!
//! The blocks are built on the header of the battery's first block
//! (`data/fullblock_vectors.txt`), so that the header is accepted in
//! context and the data is what gets refused.  Their transactions are
//! copies of that block's coinbase told apart by lock time: enough for
//! the merkle check and the context-free sanity checks, which are the
//! checks that read the hashes before anything is stored.
//!
//! The last test takes the battery's first block itself, a valid block,
//! under a header that commits to its transactions the way the agenda
//! does not read the commitment.  With the agenda undecided that is the
//! one shape the merkle check lets through for now, so the block's data
//! is accepted and the contextual check, which hashes the transactions
//! for itself whatever the block arrived with, is what refuses it.

// Test-harness arithmetic over small counts.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::Arc;

use dcroxide_blockchain::agendas::VOTE_ID_HEADER_COMMITMENTS;
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::validate::check_proof_of_work_sanity;
use dcroxide_blockchain::{HashedBlock, RuleError, RuleErrorKind};
use dcroxide_chaincfg::{Params, regnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_standalone::{
    BigInt, Sign, calc_combined_tx_tree_merkle_root, calc_tx_tree_merkle_root,
};
use dcroxide_testutil::unhex;
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx};

/// What the header commitments agenda query answers for the block
/// under test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Agenda {
    /// Decided inactive: the header's merkle root commits to the regular
    /// tree and its stake root to the stake tree.
    Inactive,
    /// Decided active: the header's merkle root commits to both trees.
    Active,
    /// Not decidable from the block's position: either commitment is
    /// allowed for now.
    Undecided,
}

/// Regnet, with the header commitments agenda forced as the case asks
/// (dcrd's `forceDeploymentResult`).
fn regnet(agenda: Agenda) -> Params {
    let mut params = regnet_params();
    let choice = match agenda {
        Agenda::Inactive => "no",
        Agenda::Active => "yes",
        Agenda::Undecided => return params,
    };
    let mut found = false;
    for (_, deployments) in &mut params.deployments {
        for deployment in deployments.iter_mut() {
            if deployment.vote.id == VOTE_ID_HEADER_COMMITMENTS {
                deployment.forced_choice_id = choice;
                found = true;
            }
        }
    }
    assert!(found, "regnet has a header commitments deployment");
    params
}

/// The battery's first block, which extends the genesis block, and the
/// current time its row is replayed at.
fn first_battery_block() -> (i64, MsgBlock) {
    let mut now = 0;
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("now"),
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                assert_eq!(block.header.prev_block, regnet_params().genesis_hash);
                return (now, block);
            }
            _ => {}
        }
    }
    panic!("the battery accepts a block");
}

/// Grind the header's nonce from zero until its proof of work passes
/// the sanity checks.
fn grind(header: &mut BlockHeader, params: &Params) {
    let pow_limit = BigInt::from_bytes_be(Sign::Plus, &params.pow_limit.to_be_bytes());
    header.nonce = 0;
    while check_proof_of_work_sanity(header, &pow_limit, false).is_err() {
        header.nonce += 1;
    }
}

/// Make the header commit to the block's transactions the way the
/// agenda case reads the commitment, and to its size, then grind it.
/// With the agenda undecided the header commits as before DCP0005,
/// which is the commitment tried first.
fn commit(block: &mut MsgBlock, agenda: Agenda, params: &Params) {
    match agenda {
        Agenda::Inactive | Agenda::Undecided => {
            block.header.merkle_root = calc_tx_tree_merkle_root(&block.transactions);
            block.header.stake_root = calc_tx_tree_merkle_root(&block.stransactions);
        }
        Agenda::Active => {
            block.header.merkle_root =
                calc_combined_tx_tree_merkle_root(&block.transactions, &block.stransactions);
        }
    }
    block.header.size = block.serialize_size() as u32;
    grind(&mut block.header, params);
}

/// A block on the battery's first header with three regular and three
/// stake transactions, committed to by its header.
fn base_block(agenda: Agenda, params: &Params) -> (i64, MsgBlock) {
    let (now, first) = first_battery_block();
    let coinbase = first.transactions[0].clone();
    let numbered = |n: u32| MsgTx {
        lock_time: n,
        ..coinbase.clone()
    };
    let mut block = MsgBlock {
        header: first.header,
        transactions: vec![coinbase.clone(), numbered(1), numbered(2)],
        stransactions: vec![numbered(3), numbered(4), numbered(5)],
    };
    assert_eq!(
        block.header.fresh_stake, 0,
        "the first block buys no ticket"
    );
    commit(&mut block, agenda, params);
    (now, block)
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

/// What the chain holds about the block and its header after a call.
#[derive(Debug, PartialEq, Eq)]
struct Kept {
    /// The status bits of the header's index entry, if it has one.
    status: Option<u8>,
    /// Whether the chain has the block's data.
    have_block: bool,
    /// The best header.
    best_header: (Hash, i64),
    /// The best block.
    tip: Hash,
    /// The hashes of the blocks in the mirror of recent blocks.
    mirrored: Vec<[u8; 32]>,
}

fn kept(chain: &Chain, hash: &Hash) -> Kept {
    Kept {
        status: chain
            .index
            .lookup_node(hash)
            .map(|node| chain.store.node(node).status.0),
        have_block: chain.have_block(hash),
        best_header: chain.best_header(),
        tip: chain.store.node(chain.best_chain.tip().expect("tip")).hash,
        mirrored: chain.blocks.keys().copied().collect(),
    }
}

/// The text of a failed comparison of the header's merkle root field.
fn merkle_root_text(header: &BlockHeader, calculated: Hash) -> String {
    format!(
        "block merkle root is invalid - block header indicates {}, but calculated value is \
         {calculated}",
        header.merkle_root
    )
}

/// The text of a failed comparison of the header's stake root field.
fn stake_root_text(header: &BlockHeader, calculated: Hash) -> String {
    format!(
        "block stake merkle root is invalid - block header indicates {}, but calculated value \
         is {calculated}",
        header.stake_root
    )
}

/// The error the merkle check gives for a block whose trees are not the
/// ones its header commits to, by dcrd's rules (`validate.go:1909-1952`
/// and, with the agenda undecided, `:2039-2046`, which returns the
/// DCP0005 comparison's error when both fail), worked out on the
/// standalone functions that hash the transactions themselves.
fn merkle_failure(block: &MsgBlock, agenda: Agenda) -> (RuleErrorKind, String) {
    let header = &block.header;
    let regular = calc_tx_tree_merkle_root(&block.transactions);
    let stake = calc_tx_tree_merkle_root(&block.stransactions);
    let combined = calc_combined_tx_tree_merkle_root(&block.transactions, &block.stransactions);
    let text = match agenda {
        Agenda::Inactive if header.merkle_root != regular => merkle_root_text(header, regular),
        Agenda::Inactive => {
            assert_ne!(header.stake_root, stake, "the block fails the merkle check");
            stake_root_text(header, stake)
        }
        Agenda::Active | Agenda::Undecided => {
            assert_ne!(
                header.merkle_root, combined,
                "the block fails the merkle check"
            );
            merkle_root_text(header, combined)
        }
    };
    (RuleErrorKind::BadMerkleRoot, text)
}

/// One bad block made from the base block, and the one error every
/// entry must refuse it with.
struct Shape {
    name: &'static str,
    block: MsgBlock,
    error: (RuleErrorKind, String),
}

/// The bad shapes of the base block under one agenda case.
fn shapes(base: &MsgBlock, agenda: Agenda, params: &Params) -> Vec<Shape> {
    let mut shapes = Vec::new();

    // Trees that do not have the roots the header names.
    let mut wrong_trees = |name: &'static str, alter: &dyn Fn(&mut MsgBlock)| {
        let mut block = base.clone();
        alter(&mut block);
        let error = merkle_failure(&block, agenda);
        shapes.push(Shape { name, block, error });
    };
    wrong_trees("another regular transaction", &|b| {
        b.transactions[2].lock_time = 12;
    });
    wrong_trees("another stake transaction", &|b| {
        b.stransactions[2].lock_time = 15;
    });
    wrong_trees("another transaction in each tree", &|b| {
        b.transactions[2].lock_time = 12;
        b.stransactions[2].lock_time = 15;
    });
    wrong_trees("no transactions", &|b| {
        b.transactions.clear();
        b.stransactions.clear();
    });
    wrong_trees("no regular transactions", &|b| b.transactions.clear());

    // A tree of three leaves has the root of the same tree with its
    // last leaf repeated.  In a block whose header names the size with
    // the repeat, the trees are still the ones the header commits to,
    // so the merkle check passes and the sanity checks refuse the
    // repeat.
    for regular in [true, false] {
        let mut block = base.clone();
        let tree = if regular {
            &mut block.transactions
        } else {
            &mut block.stransactions
        };
        let last = tree[2].clone();
        tree.push(last.clone());
        assert_eq!(
            calc_tx_tree_merkle_root(&block.transactions),
            calc_tx_tree_merkle_root(&base.transactions)
        );
        assert_eq!(
            calc_tx_tree_merkle_root(&block.stransactions),
            calc_tx_tree_merkle_root(&base.stransactions)
        );
        block.header.size = block.serialize_size() as u32;
        grind(&mut block.header, params);
        shapes.push(Shape {
            name: if regular {
                "a repeated regular transaction"
            } else {
                "a repeated stake transaction"
            },
            block,
            error: (
                RuleErrorKind::DuplicateTx,
                format!("block contains duplicate transaction {}", last.tx_hash()),
            ),
        });
    }

    // No transactions, in a block whose header commits to exactly that.
    let mut empty = base.clone();
    empty.transactions.clear();
    empty.stransactions.clear();
    commit(&mut empty, agenda, params);
    shapes.push(Shape {
        name: "no transactions, as the header commits to",
        block: empty,
        error: (
            RuleErrorKind::NoTransactions,
            "block does not contain any transactions".to_string(),
        ),
    });

    shapes
}

/// Each bad shape is refused with the same error through every entry,
/// under each agenda case, and leaves the same behind in the index and
/// in the mirror.
#[test]
fn bad_shapes_are_refused_alike_however_the_block_arrives() {
    let mut refused = 0usize;
    for agenda in [Agenda::Inactive, Agenda::Active, Agenda::Undecided] {
        let params = regnet(agenda);
        let (now, base) = base_block(agenda, &params);
        for shape in shapes(&base, agenda, &params) {
            let what = format!("{agenda:?}, {}", shape.name);
            let hash = shape.block.header.block_hash();
            let shared = Arc::new(shape.block.clone());
            let hashed = HashedBlock::new(Arc::new(shape.block.clone()));
            assert_eq!(*hashed.hash(), hash, "{what}");

            let mut borrowing = Chain::new(&params, Hash::ZERO, false);
            let mut sharing = Chain::new(&params, Hash::ZERO, false);
            let mut hashing = Chain::new(&params, Hash::ZERO, false);
            let b = borrowing.process_block(&shape.block, now, &params);
            let s = sharing.process_shared_block(&shared, now, &params);
            let h = hashing.process_hashed_block(&hashed, now, &params);

            // The one error the shape was made for, from every entry.
            assert_eq!(outcome(&b), (0, vec![shape.error.clone()]), "{what}");
            assert_eq!(outcome(&s), outcome(&b), "{what}: shared");
            assert_eq!(outcome(&h), outcome(&b), "{what}: hashed");
            // The header was accepted before the data was refused, and
            // what the refusal left of it is the same.
            let left = kept(&borrowing, &hash);
            assert!(left.status.is_some(), "{what}: the header is not indexed");
            assert!(!left.have_block, "{what}");
            assert_eq!(kept(&sharing, &hash), left, "{what}: shared");
            assert_eq!(kept(&hashing, &hash), left, "{what}: hashed");
            // Only the chain that was handed hashes hashed nothing.
            assert_eq!(
                (
                    borrowing.arrivals_hashed,
                    sharing.arrivals_hashed,
                    hashing.arrivals_hashed
                ),
                (1, 1, 0),
                "{what}"
            );

            refused += 1;
        }
    }
    assert_eq!(refused, 3 * 8, "three agenda cases of eight shapes");
}

/// The base block itself passes the merkle check and the sanity checks
/// under each agenda case, so every refusal above is the shape's: what
/// refuses it is a later check, and the same one through every entry.
#[test]
fn the_base_block_passes_the_checks_the_shapes_fail() {
    for agenda in [Agenda::Inactive, Agenda::Active, Agenda::Undecided] {
        let params = regnet(agenda);
        let (now, base) = base_block(agenda, &params);
        let hash = base.header.block_hash();
        let shared = Arc::new(base.clone());
        let hashed = HashedBlock::new(Arc::new(base.clone()));

        let mut borrowing = Chain::new(&params, Hash::ZERO, false);
        let mut sharing = Chain::new(&params, Hash::ZERO, false);
        let mut hashing = Chain::new(&params, Hash::ZERO, false);
        let b = borrowing.process_block(&base, now, &params);
        let s = sharing.process_shared_block(&shared, now, &params);
        let h = hashing.process_hashed_block(&hashed, now, &params);

        let (_, errs) = &b;
        assert_eq!(errs.len(), 1, "{agenda:?}: {errs:?}");
        for passed in [
            RuleErrorKind::BadMerkleRoot,
            RuleErrorKind::WrongBlockSize,
            RuleErrorKind::DuplicateTx,
            RuleErrorKind::NoTransactions,
        ] {
            assert_ne!(errs[0].kind, passed, "{agenda:?}: {errs:?}");
        }
        assert_eq!(outcome(&s), outcome(&b), "{agenda:?}: shared");
        assert_eq!(outcome(&h), outcome(&b), "{agenda:?}: hashed");
        let left = kept(&borrowing, &hash);
        assert_eq!(kept(&sharing, &hash), left, "{agenda:?}: shared");
        assert_eq!(kept(&hashing, &hash), left, "{agenda:?}: hashed");
    }
}

/// A valid block under a header that commits to its transactions the
/// way the agenda does not read the commitment is refused alike through
/// every entry: the battery's first block with the combined root of
/// DCP0005 in its header before the agenda is active, and with the two
/// roots in its two fields once it is.
///
/// With the agenda decided the merkle check refuses the block before
/// anything is stored.  With the agenda undecided either commitment
/// passes that check for now, so the data is accepted, and the
/// contextual check refuses the block with the rule in force at its
/// height.  It does so twice in the one call, as the block is accepted
/// and as the reorganization that follows comes to it, because a
/// contextual merkle failure does not mark the block (dcrd
/// `process.go:367-371`, `chain.go:1209-1215`).  The contextual check
/// builds its trees from the block, so the roots a block arrived with
/// play no part in it.
#[test]
fn a_block_committed_the_way_the_agenda_does_not_read_is_refused_alike() {
    let (now, valid) = first_battery_block();
    let regular = calc_tx_tree_merkle_root(&valid.transactions);
    let stake = calc_tx_tree_merkle_root(&valid.stransactions);
    let combined = calc_combined_tx_tree_merkle_root(&valid.transactions, &valid.stransactions);
    // The battery commits the way the agenda reads before DCP0005.
    assert_eq!(
        (valid.header.merkle_root, valid.header.stake_root),
        (regular, stake)
    );
    assert_ne!(regular, combined);

    for agenda in [Agenda::Inactive, Agenda::Active, Agenda::Undecided] {
        let params = regnet(agenda);
        let mut block = valid.clone();
        if agenda != Agenda::Active {
            block.header.merkle_root = combined;
            grind(&mut block.header, &params);
        }
        // The header's merkle root and the root the check in force
        // calculates.  Regnet has not activated the agenda at this
        // height, so the contextual check reads the original commitment.
        let refusal = match agenda {
            Agenda::Inactive | Agenda::Undecided => (
                RuleErrorKind::BadMerkleRoot,
                merkle_root_text(&block.header, regular),
            ),
            Agenda::Active => (
                RuleErrorKind::BadMerkleRoot,
                merkle_root_text(&block.header, combined),
            ),
        };
        let (errors, stored) = match agenda {
            Agenda::Inactive | Agenda::Active => (vec![refusal], false),
            Agenda::Undecided => (vec![refusal.clone(), refusal], true),
        };

        let hash = block.header.block_hash();
        let shared = Arc::new(block.clone());
        let hashed = HashedBlock::new(Arc::new(block.clone()));
        let mut borrowing = Chain::new(&params, Hash::ZERO, false);
        let mut sharing = Chain::new(&params, Hash::ZERO, false);
        let mut hashing = Chain::new(&params, Hash::ZERO, false);
        let b = borrowing.process_block(&block, now, &params);
        let s = sharing.process_shared_block(&shared, now, &params);
        let h = hashing.process_hashed_block(&hashed, now, &params);

        assert_eq!(outcome(&b), (0, errors), "{agenda:?}");
        assert_eq!(outcome(&s), outcome(&b), "{agenda:?}: shared");
        assert_eq!(outcome(&h), outcome(&b), "{agenda:?}: hashed");
        let left = kept(&borrowing, &hash);
        assert_eq!(left.have_block, stored, "{agenda:?}");
        assert_eq!(left.tip, params.genesis_hash, "{agenda:?}");
        assert_eq!(kept(&sharing, &hash), left, "{agenda:?}: shared");
        assert_eq!(kept(&hashing, &hash), left, "{agenda:?}: hashed");

        // The same block under the header the agenda does read is
        // accepted by a chain that has seen neither.
        let mut good = valid.clone();
        if agenda == Agenda::Active {
            good.header.merkle_root = combined;
            grind(&mut good.header, &params);
        }
        let mut fresh = Chain::new(&params, Hash::ZERO, false);
        let accepted =
            fresh.process_hashed_block(&HashedBlock::new(Arc::new(good.clone())), now, &params);
        if agenda == Agenda::Active {
            // Past the merkle check, which is all this control is for:
            // the block's other commitments are not those of a block
            // made after the agenda.
            assert!(
                accepted
                    .1
                    .iter()
                    .all(|err| err.kind != RuleErrorKind::BadMerkleRoot),
                "{agenda:?}: {:?}",
                accepted.1
            );
        } else {
            assert_eq!(outcome(&accepted), (0, Vec::new()), "{agenda:?}");
            assert!(fresh.have_block(&good.header.block_hash()), "{agenda:?}");
        }
    }
}
