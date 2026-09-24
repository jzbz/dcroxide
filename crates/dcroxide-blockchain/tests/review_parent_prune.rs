// SPDX-License-Identifier: ISC
//! Connecting a block far behind the best header prunes its parent's
//! stake node on the spot, as dcrd's `connectBlock` does (review
//! finding B2-c#3).
//!
//! dcrd drops the parent's stake node and ticket info as soon as the
//! connected block is more than `minMemoryStakeNodes` below the best
//! header (`chain.go:795-808`), which during initial sync is every
//! block.  The port left that out, so everything connected between two
//! timed prunes -- 300 s of sync on mainnet -- stayed resident with its
//! stake node, body, journal, filter and ticket rows.
//!
//! The battery is far shorter than 288 blocks past any header, so the
//! test stands in a header far ahead of the chain -- the shape of
//! headers-first sync -- by inserting one into the index directly.  It
//! then replays the whole battery, reorganizations included, and checks
//! the result matches a replay without it: every pruned stake node,
//! ticket list and mirror entry must come back from the database.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::RuleErrorKind;
use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::{Params, regnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
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

/// The chain state a replay ends with.
#[derive(Debug, PartialEq)]
struct Outcome {
    tip: Hash,
    snapshot: String,
    missed: Vec<Hash>,
    revoked: Vec<Hash>,
    live: Vec<Hash>,
}

fn outcome(chain: &mut Chain, params: &Params) -> Outcome {
    let tip = chain.best_chain.tip().expect("tip");
    let stake_node = chain.fetch_stake_node(tip, params).expect("tip stake node");
    Outcome {
        tip: chain.store.node(tip).hash,
        snapshot: format!("{:?}", chain.state_snapshot),
        missed: stake_node.missed_tickets(),
        revoked: stake_node.revoked_tickets(),
        live: stake_node.live_tickets(),
    }
}

#[test]
fn connecting_far_behind_the_best_header_prunes_the_parent() {
    let params = regnet_params();
    let (now, blocks) = battery();
    let split = blocks
        .iter()
        .position(|(label, _)| label == "bsv0")
        .expect("bsv0 in the battery");

    // Control: the battery as is.  The clock never moves, so the timed
    // prune never fires and every stake node stays loaded.
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let mut control = Chain::open(db, &params, Hash::ZERO, false, 0).expect("open chain");
    for (label, block) in &blocks {
        process(&mut control, label, block, now, &params);
    }
    let want = outcome(&mut control, &params);

    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let mut chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("open chain");
    for (label, block) in &blocks[..split] {
        process(&mut chain, label, block, now, &params);
    }

    // A header 10,000 blocks ahead whose work nothing in the battery
    // can overtake (a target of one is 2^255 work), so it stays the best
    // header for the rest of the replay.
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

    for (label, block) in &blocks[split..] {
        process(&mut chain, label, block, now, &params);
    }
    assert_eq!(
        chain.index.best_header(),
        Some(ahead),
        "the far header still leads"
    );

    // The pruning happened: the block below the tip has no stake node,
    // no ticket info and no body in memory, while the control -- whose
    // best header is its tip -- kept them.
    let tip = chain.best_chain.tip().expect("tip");
    let below = chain.store.node(tip).parent.expect("parent");
    let n = chain.store.node(below);
    assert!(n.stake_node.is_none(), "the parent's stake node survived");
    assert!(!n.ticket_info_populated && n.new_tickets.is_none());
    assert!(
        !chain.blocks.contains_key(&n.hash.0),
        "the parent's body stayed in memory"
    );
    let control_tip = control.best_chain.tip().expect("tip");
    let control_below = control.store.node(control_tip).parent.expect("parent");
    assert!(control.store.node(control_below).stake_node.is_some());

    // And nothing it dropped changed a verdict or the ticket state.
    assert_eq!(outcome(&mut chain, &params), want);
}
