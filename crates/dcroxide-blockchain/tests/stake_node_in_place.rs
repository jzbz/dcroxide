// SPDX-License-Identifier: ISC
//! A connect that drops its parent's stake node makes the block's of the
//! parent's in place (`Node::connect_in_place`): the parent's ticket
//! treaps become the block's, changed where no one else holds them.
//!
//! Nothing anyone holds of the parent may change for it.  From `bsv0` on,
//! the battery is replayed below a header far ahead, so that every
//! connect drops its parent's node, as during an initial sync, and makes
//! the block's of it in place unless the parent's is held elsewhere or
//! the block's was made already.  The replay keeps what the chain hands
//! out across each block: the best snapshot and its missed tickets, a
//! copy of the tip's stake node as the RPC server takes one and walks it
//! on a thread of its own, and one block in four the tip's node itself,
//! which the connect must then leave alone, making the block's from it as
//! before.  Each must read after the block as it read before it, and the
//! replay must end where a replay without the far header ends.  The
//! replay does not tell which way a connect went; the power cuts below
//! and `the_stake_node_made_in_place_is_the_one_fetch_stake_node_makes`
//! in `process.rs` do.
//!
//! A connect that fails after its stake node was made in place must give
//! the parent, which is still the tip, its node back: every later fetch
//! of a stake node starts from the tip's.  The power under the metadata
//! store is cut at every write and sync of a block's processing in turn,
//! for two blocks whose stake nodes between them spend, miss, revoke and
//! buy tickets, and after each cut the tip must hold a stake node that
//! answers as the tip's did.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc;

use dcroxide_blockchain::RuleErrorKind;
use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::{Params, regnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options, SharedBackend};
use dcroxide_stake::ticketnode::Node as StakeNode;
use dcroxide_testutil::powerloss::PowerLossBackend;
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;
use tempfile::TempDir;

/// The battery's clock and its accepted blocks in file order.
fn battery() -> (i64, Vec<(String, MsgBlock)>) {
    let mut now = 0;
    let mut blocks = Vec::new();
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("now"),
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                blocks.push((f[1].to_string(), block));
            }
            _ => {}
        }
    }
    (now, blocks)
}

fn process(chain: &mut Chain, label: &str, block: &MsgBlock, now: i64, params: &Params) {
    let (_, errs) = chain.process_block(block, now, params);
    let is_orphan = errs.len() == 1 && errs[0].kind == RuleErrorKind::MissingParent;
    assert!(errs.is_empty() || is_orphan, "{label}: {errs:?}");
}

/// Every answer a stake node gives.
type Answers = (
    (u32, Vec<Hash>, [u8; 6], usize),
    (Vec<Hash>, Vec<Hash>, Vec<Hash>, Vec<Hash>),
);

fn answers(node: &StakeNode) -> Answers {
    (
        (
            node.height(),
            node.winners().to_vec(),
            node.final_state(),
            node.pool_size(),
        ),
        (
            node.live_tickets(),
            node.missed_tickets(),
            node.revoked_tickets(),
            node.expiring_next_block(),
        ),
    )
}

/// The tip's stake node answers.
fn tip_answers(chain: &Chain) -> Answers {
    let tip = chain.best_chain.tip().expect("tip");
    answers(
        chain
            .store
            .node(tip)
            .stake_node
            .as_deref()
            .expect("the tip's stake node is loaded"),
    )
}

/// The chain state a replay ends with.
#[derive(Debug, PartialEq)]
struct Outcome {
    tip: Hash,
    snapshot: String,
    stake: Answers,
}

fn outcome(chain: &mut Chain, params: &Params) -> Outcome {
    let tip = chain.best_chain.tip().expect("tip");
    let stake_node = chain.fetch_stake_node(tip, params).expect("tip stake node");
    Outcome {
        tip: chain.store.node(tip).hash,
        snapshot: format!("{:?}", chain.state_snapshot),
        stake: answers(&stake_node),
    }
}

/// Stand in a header 10,000 blocks ahead of the tip whose work nothing
/// in the battery can overtake (a target of one is 2^255 work), so every
/// connect from here on is more than 288 below the best header and
/// drops its parent's stake node, as during an initial sync (the
/// stand-in of `review_parent_prune.rs`).
fn lead_with_a_far_header(chain: &mut Chain) {
    let tip = chain.best_chain.tip().expect("tip");
    let mut header = chain.store.header(tip);
    header.prev_block = chain.store.node(tip).hash;
    header.height += 10_000;
    header.bits = 0x0300_0001;
    header.nonce = header.nonce.wrapping_add(1);
    let ahead = chain.store.new_node(&header, Some(tip));
    chain.index.add_node(&chain.store, ahead);
    assert_eq!(
        chain.index.best_header(),
        Some(ahead),
        "the far header leads"
    );
}

/// A fresh chain over a fresh store in the directory.
fn fresh_chain(dir: &Path, params: &Params) -> Chain {
    let opts = Options::new(dir.join("chain"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    Chain::open(db, params, Hash::ZERO, false, 0).expect("open chain")
}

/// Every holder of what the chain handed out about its tip keeps reading
/// what it read across a connect that drops the tip's stake node, made
/// of it in place or, while the tip's node is held, from it as before,
/// on this thread and on another; and the replay ends as the control
/// does.
#[test]
fn a_connect_made_in_place_changes_nothing_a_holder_reads() {
    let params = regnet_params();
    let (now, blocks) = battery();
    let split = blocks
        .iter()
        .position(|(label, _)| label == "bsv0")
        .expect("bsv0 in the battery");

    // Control: the battery as is, every stake node kept.
    let dir = TempDir::new().expect("tempdir");
    let mut control = fresh_chain(dir.path(), &params);
    for (label, block) in &blocks {
        process(&mut control, label, block, now, &params);
    }
    let want = outcome(&mut control, &params);

    let dir = TempDir::new().expect("tempdir");
    let mut chain = fresh_chain(dir.path(), &params);
    for (label, block) in &blocks[..split] {
        process(&mut chain, label, block, now, &params);
    }
    lead_with_a_far_header(&mut chain);

    // The RPC server's walk: a copy of the tip's node, walked on a
    // thread of its own while the chain goes on connecting, the copy
    // sharing the treaps the next connect is given.
    let (copies, walked) = mpsc::channel::<(StakeNode, Answers)>();
    let reader = std::thread::spawn(move || {
        let mut walks = 0usize;
        for (copy, read) in walked {
            for _ in 0..3 {
                assert_eq!(
                    answers(&copy),
                    read,
                    "a copy walked on its own thread changed"
                );
                walks += 1;
            }
        }
        walks
    });

    let (mut held_nodes, mut copies_sent) = (0usize, 0usize);
    for (number, (label, block)) in blocks[split..].iter().enumerate() {
        let tip = chain.best_chain.tip().expect("tip");
        let snapshot = chain.best_snapshot().clone();
        let snapshot_missed = snapshot.missed_tickets.to_vec();
        let copy: StakeNode = chain
            .store
            .node(tip)
            .stake_node
            .as_deref()
            .expect("the tip's stake node is loaded")
            .clone();
        let copy_read = answers(&copy);
        copies
            .send((copy.clone(), copy_read.clone()))
            .expect("the reader is there");
        copies_sent += 1;
        // One block in four, the tip's node itself is held across the
        // block, so the connect must leave it and copy what it changes.
        let held = (number % 4 == 0).then(|| {
            held_nodes += 1;
            let held = chain
                .fetch_stake_node(tip, &params)
                .expect("the tip's stake node");
            let read = answers(&held);
            (held, read)
        });

        process(&mut chain, label, block, now, &params);

        assert_eq!(
            snapshot.missed_tickets.to_vec(),
            snapshot_missed,
            "{label}: the snapshot's missed tickets changed"
        );
        assert_eq!(answers(&copy), copy_read, "{label}: the copy changed");
        if let Some((held, read)) = held {
            assert_eq!(answers(&held), read, "{label}: the held node changed");
        }
    }
    drop(copies);
    let walks = reader.join().expect("the reader's walks all read alike");
    assert_eq!(walks, 3 * copies_sent);
    assert!(
        held_nodes >= 10 && copies_sent >= 40,
        "{held_nodes} held, {copies_sent} copied"
    );

    // The parent's node went with every connect.
    let tip = chain.best_chain.tip().expect("tip");
    let below = chain.store.node(tip).parent.expect("parent");
    assert!(chain.store.node(below).stake_node.is_none());
    assert_eq!(outcome(&mut chain, &params), want);
}

/// Copy every file of a directory into another.
fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("mkdir");
    for entry in std::fs::read_dir(from).expect("read dir") {
        let entry = entry.expect("dir entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy");
        }
    }
}

/// The moves a block's stake node made of its parent's: winners spent,
/// tickets missed (a winner that did not vote, or a ticket that
/// expired), missed tickets revoked, and tickets bought.
#[derive(Debug, Default)]
struct Moves {
    spent: usize,
    missed: usize,
    revoked: usize,
    bought: usize,
}

fn moves(node: &StakeNode) -> Moves {
    let undo = node.undo_data();
    Moves {
        spent: undo.iter().filter(|u| u.spent).count(),
        missed: undo.iter().filter(|u| u.missed && !u.revoked).count(),
        revoked: undo.iter().filter(|u| u.revoked).count(),
        bought: node.new_tickets().len(),
    }
}

/// Cut the power under the metadata store at every write and sync of
/// the processing of the battery's block `label` in turn, below a
/// header far ahead, over a store holding the battery up to it; check
/// the tip after each cut, and return what the block's stake node moved.
fn cut_every_write(params: &Params, now: i64, blocks: &[(String, MsgBlock)], label: &str) -> Moves {
    let at = blocks
        .iter()
        .position(|(l, _)| l == label)
        .expect("the block is in the battery");
    let block = &blocks[at].1;

    // The store with the battery up to the block, whose parent is then
    // the tip, closed cleanly.
    let base = TempDir::new().expect("tempdir");
    let parent_answers = {
        let mut chain = fresh_chain(base.path(), params);
        for (label, block) in &blocks[..at] {
            process(&mut chain, label, block, now, params);
        }
        let tip = chain.best_chain.tip().expect("tip");
        assert_eq!(
            chain.store.node(tip).hash,
            block.header.prev_block,
            "{label} extends the tip"
        );
        let parent_answers = tip_answers(&chain);
        chain.db.as_ref().expect("db").close().expect("close");
        parent_answers
    };
    assert!(parent_answers.1.0.len() > 20, "{label}: the parent's pool");

    // The block connected over a copy with nothing cut.
    let (child_answers, moved) = {
        let dir = TempDir::new().expect("tempdir");
        copy_dir(&base.path().join("chain"), &dir.path().join("chain"));
        let opts = Options::new(dir.path().join("chain"), params.net.0);
        let mut chain = Chain::open(
            Database::open(&opts).expect("open"),
            params,
            Hash::ZERO,
            false,
            0,
        )
        .expect("open chain");
        lead_with_a_far_header(&mut chain);
        process(&mut chain, label, block, now, params);
        let tip = chain.best_chain.tip().expect("tip");
        assert_eq!(chain.store.node(tip).hash, block.header.block_hash());
        let moved = moves(
            chain
                .store
                .node(tip)
                .stake_node
                .as_deref()
                .expect("the tip's stake node is loaded"),
        );
        (tip_answers(&chain), moved)
    };

    // Every cut, from the first write of the block's processing on, until
    // the processing makes no write the cut can fall on.
    let (mut before_stake, mut after_stake, mut connected) = (0, 0, 0);
    for cut in 0.. {
        assert!(
            cut < 5_000,
            "{label}: the processing never ran out of writes"
        );
        let dir = TempDir::new().expect("tempdir");
        let db_dir = dir.path().join("chain");
        copy_dir(&base.path().join("chain"), &db_dir);
        let backend = PowerLossBackend::create(&db_dir.join("metadata.redb"), true);
        let mut opts = Options::new(&db_dir, params.net.0);
        opts.backend = Some(Arc::clone(&backend) as SharedBackend);
        // Every commit makes the ones before it durable, so a cut fails
        // the commit it falls in.
        opts.cache_max_size = 0;
        let mut chain = Chain::open(
            Database::open(&opts).expect("open"),
            params,
            Hash::ZERO,
            false,
            0,
        )
        .expect("open chain");
        lead_with_a_far_header(&mut chain);
        let parent = chain.best_chain.tip().expect("tip");
        let parent_node = Arc::downgrade(
            chain
                .store
                .node(parent)
                .stake_node
                .as_ref()
                .expect("the tip's stake node is loaded"),
        );

        backend.power_fails_after(cut);
        let (_, errs) = chain.process_block(block, now, params);
        if !backend.power_failed() {
            assert!(errs.is_empty(), "{label}: {errs:?}");
            assert_eq!(tip_answers(&chain), child_answers, "{label}");
            break;
        }

        let tip = chain.best_chain.tip().expect("tip");
        if tip != parent {
            // The cut fell after the block connected.
            connected += 1;
            assert_eq!(chain.store.node(tip).hash, block.header.block_hash());
            assert_eq!(tip_answers(&chain), child_answers, "{label}, cut {cut}");
            continue;
        }
        assert!(
            !errs.is_empty(),
            "{label}, cut {cut}: the block failed without an error"
        );
        assert_eq!(tip_answers(&chain), parent_answers, "{label}, cut {cut}");
        let child = chain.index.lookup_node(&block.header.block_hash());
        if child.is_some_and(|child| chain.store.node(child).stake_node.is_some()) {
            // The block's stake node was made, so the failure came after
            // it: the parent's node became the block's, and the tip's is
            // the one rebuilt.
            after_stake += 1;
            assert!(
                parent_node.upgrade().is_none(),
                "{label}, cut {cut}: the block's stake node was not made of the parent's"
            );
        } else {
            before_stake += 1;
        }
    }
    assert!(
        after_stake >= 1 && before_stake >= 1,
        "{label}: {before_stake} cuts before the stake node, {after_stake} after it, \
         {connected} after the connect"
    );
    moved
}

/// A connect that fails, at any write or sync of a block's processing,
/// leaves the tip with a stake node that answers as the tip's did; and
/// at the cuts that fall after the block's stake node was made of the
/// parent's, that is a node rebuilt from the block's, the parent's own
/// having become the block's.
///
/// The cuts are made in two blocks well past stake validation whose
/// stake nodes between them make every kind of move a rebuild undoes:
/// `brt1` spends four of its parent's winners, misses the fifth and buys
/// tickets, and `brt8` spends five, revokes a missed ticket and buys
/// tickets.  No ticket expires anywhere in the battery, which is shorter
/// than the 384 blocks a ticket lives on regnet; the stake crate's
/// `every_connect_makes_the_node_the_connect_by_versions_makes` undoes
/// expiries.
#[test]
fn a_connect_that_fails_after_its_stake_node_gives_the_parent_its_node_back() {
    let params = regnet_params();
    let (now, blocks) = battery();
    let mut all = Moves::default();
    for label in ["brt1", "brt8"] {
        let moved = cut_every_write(&params, now, &blocks, label);
        assert!(moved.spent >= 4 && moved.bought >= 1, "{label}: {moved:?}");
        all.spent += moved.spent;
        all.missed += moved.missed;
        all.revoked += moved.revoked;
        all.bought += moved.bought;
    }
    assert!(
        all.spent > 0 && all.missed > 0 && all.revoked > 0 && all.bought > 0,
        "{all:?}"
    );
}
