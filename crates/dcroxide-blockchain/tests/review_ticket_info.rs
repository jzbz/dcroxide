// SPDX-License-Identifier: ISC
//! Prunable ticket info is re-read from the block whenever it is not
//! in memory (review finding B1-c#1).
//!
//! dcrd decides whether a node's voted and revoked tickets are loaded
//! by whether the slices are nil (`maybeFetchTicketInfo`,
//! `stakenode.go:71-81`).  `loadBlockIndex` never fills them and
//! `pruneStakeNodes` sets them back to nil, so dcrd always re-reads the
//! block before `stake.Node.ConnectNode` needs them.  The port keeps a
//! flag instead, and the load path set it for every node with data
//! while leaving the lists empty.  A block stored before its parent
//! arrived, then connected after a restart, therefore got a stake node
//! built with no votes and no revocations: its voters were recorded as
//! missed, permanently, in the ticket database.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

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

fn open(opts: &Options, params: &Params, create: bool) -> Chain {
    let db = if create {
        Database::create(opts).expect("create database")
    } else {
        Database::open(opts).expect("open database")
    };
    Chain::open(db, params, Hash::ZERO, false, 0).expect("open chain")
}

fn process(chain: &mut Chain, block: &MsgBlock, now: i64, params: &Params) {
    let (_, errs) = chain.process_block(block, now, params);
    assert!(
        errs.is_empty(),
        "block {}: {errs:?}",
        block.header.block_hash()
    );
}

/// What the ticket database ends up holding for a connected block.
#[derive(Debug, PartialEq)]
struct StakeView {
    missed: Vec<Hash>,
    revoked: Vec<Hash>,
    live: Vec<Hash>,
    undo: String,
    snapshot_missed: Vec<Hash>,
}

fn stake_view(chain: &mut Chain, hash: &Hash, params: &Params) -> StakeView {
    let node = chain.index.lookup_node(hash).expect("node");
    let stake_node = chain.fetch_stake_node(node, params).expect("stake node");
    StakeView {
        missed: stake_node.missed_tickets(),
        revoked: stake_node.revoked_tickets(),
        live: stake_node.live_tickets(),
        undo: format!("{:?}", stake_node.undo_data()),
        snapshot_missed: chain.state_snapshot.missed_tickets.clone(),
    }
}

/// A block stored ahead of its parent, carried across a restart, and
/// connected when the parent finally arrives must produce the same
/// stake node -- and the same persisted missed-ticket set -- as when
/// no restart happened.
#[test]
fn a_child_stored_before_a_restart_connects_with_its_votes() {
    let params = regnet_params();
    let (now, blocks) = battery();
    // Past stake validation height, so both blocks carry votes.
    let p = blocks
        .iter()
        .position(|(label, _)| label == "bbm5")
        .expect("bbm5 in the battery");
    assert_eq!(blocks[p + 1].0, "bbm6", "the child follows its parent");
    let parent = &blocks[p].1;
    let child = &blocks[p + 1].1;
    let child_hash = child.header.block_hash();

    // Control: the same blocks, in order, no restart.
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let mut control = open(&opts, &params, true);
    for (_, block) in &blocks[..=p + 1] {
        process(&mut control, block, now, &params);
    }
    let want = stake_view(&mut control, &child_hash, &params);
    let control_child = control.index.lookup_node(&child_hash).expect("child");
    assert!(
        !control.store.node(control_child).tickets_voted.is_empty(),
        "the child must carry votes for the comparison to mean anything"
    );

    // The routine IBD shape: both headers first, the child's body
    // before the parent's, and a clean shutdown in between.
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let mut chain = open(&opts, &params, true);
    for (_, block) in &blocks[..p] {
        process(&mut chain, block, now, &params);
    }
    chain
        .process_block_header(&parent.header, now, &params)
        .expect("parent header");
    chain
        .process_block_header(&child.header, now, &params)
        .expect("child header");
    process(&mut chain, child, now, &params);
    let stored = chain.index.lookup_node(&child_hash).expect("child node");
    assert!(
        chain.store.node(stored).status.have_data(),
        "the child's body is stored"
    );
    assert_ne!(
        chain.best_chain.tip(),
        Some(stored),
        "the child cannot connect before its parent"
    );
    chain.flush(&params).expect("clean shutdown flush");
    chain.db.as_ref().expect("db").close().expect("close");
    drop(chain);

    let mut chain = open(&opts, &params, false);
    process(&mut chain, parent, now, &params);
    let tip = chain.best_chain.tip().expect("tip");
    assert_eq!(
        chain.store.node(tip).hash,
        child_hash,
        "delivering the parent connects the stored child"
    );
    let got = stake_view(&mut chain, &child_hash, &params);
    assert_eq!(
        got, want,
        "the child's stake node was built without its votes and revocations"
    );

    // And the ticket database the next start loads from agrees.
    chain.flush(&params).expect("flush");
    chain.db.as_ref().expect("db").close().expect("close");
    drop(chain);
    let chain = open(&opts, &params, false);
    assert_eq!(
        chain.state_snapshot.missed_tickets, want.snapshot_missed,
        "the persisted missed-ticket set diverged"
    );
}

/// The periodic prune empties the ticket lists, so it must clear the
/// flag that says they are loaded: dcrd's `pruneStakeNodes` sets the
/// slices back to nil, which is exactly what makes the next
/// `maybeFetchTicketInfo` re-read them.
#[test]
fn pruning_forgets_that_the_ticket_info_was_loaded() {
    let params = regnet_params();
    let (now, blocks) = battery();
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let mut chain = open(&opts, &params, true);
    let end = blocks
        .iter()
        .position(|(label, _)| label == "bbm10")
        .expect("bbm10 in the battery");
    for (_, block) in &blocks[..=end] {
        process(&mut chain, block, now, &params);
    }

    let tip = chain.best_chain.tip().expect("tip");
    let pruned = chain
        .store
        .relative_ancestor(tip, 5)
        .expect("an ancestor below the keep window");
    assert!(
        chain.store.node(pruned).ticket_info_populated,
        "a freshly accepted block has its ticket info loaded"
    );
    let want_voted = chain.store.node(pruned).tickets_voted.clone();
    assert!(!want_voted.is_empty(), "the pruned block carries votes");

    chain.prune_chain_memory(2);
    let n = chain.store.node(pruned);
    assert!(n.tickets_voted.is_empty(), "the prune empties the lists");
    assert!(
        !n.ticket_info_populated,
        "the lists were emptied but still read as loaded"
    );

    // The next stake-node build re-reads them, from the database now
    // that the body has left the recent window.
    chain
        .maybe_fetch_ticket_info(pruned, &params)
        .expect("re-read the pruned block");
    assert_eq!(chain.store.node(pruned).tickets_voted, want_voted);
}
