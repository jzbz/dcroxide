// SPDX-License-Identifier: ISC
//! The block index view's height lookups resume from the node served
//! last.
//!
//! dcrd's difficulty windows, ticket purchase sums and vote tallies step
//! `oldNode.parent` / `countNode.parent`.  `NodeBranchView` served every
//! step of those walks with a skip-list descent from the branch tip,
//! about 27 hops a step over the 2,880-node pre-DCP0011 retarget window,
//! and built a whole vote node (two allocations) for every step of the
//! 8,064-block tally (review finding B7-p#2).  It now resumes from the
//! last node it served when that is at or above the requested height,
//! which for a descending walk is one parent hop, and lends the tally
//! each node's own votes.
//!
//! These tests pin that every lookup still answers exactly what a
//! descent from the tip answers, over descending walks, jumps back up,
//! views on other branches taking turns with the cursor, out-of-range
//! heights and random probes, so the difficulty, stake and threshold
//! results cannot drift.

// Test-harness arithmetic over bounded heights.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::blockindex::{NodeId, NodeStore};
use dcroxide_blockchain::chainview_nodes::NodeBranchView;
use dcroxide_blockchain::difficulty::{ChainView, DiffNode};
use dcroxide_blockchain::stakever::VersionChainView;
use dcroxide_blockchain::thresholdstate::VoteChainView;
use dcroxide_testutil::SplitMix64;
use dcroxide_wire::BlockHeader;

/// Extend `parent` with nodes up to `to`, every one telling its branch
/// apart through `salt` in its timestamp, nonce and votes.
fn build_chain(
    store: &mut NodeStore,
    parent: Option<NodeId>,
    from: u32,
    to: u32,
    salt: u32,
) -> Vec<NodeId> {
    let mut ids = Vec::new();
    let mut parent = parent;
    for height in from..=to {
        let mut header = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header").0;
        header.height = height;
        header.bits = 0x1b01_ffff - (height % 5);
        header.sbits = i64::from(height * 3 + salt);
        header.pool_size = height + salt;
        header.fresh_stake = (height % 20) as u8;
        header.timestamp = 1_000_000 + height * 300 + salt;
        header.nonce = salt;
        let id = store.new_node(&header, parent);
        let votes = (0..(height + salt) % 6)
            .map(|i| (4 + (height + i + salt) % 3, (height ^ salt) as u16))
            .collect();
        store.populate_ticket_info(id, Vec::new(), Vec::new(), votes);
        ids.push(id);
        parent = Some(id);
    }
    ids
}

/// What a lookup must answer: the node a descent from the tip finds.
fn want(store: &NodeStore, tip: NodeId, height: i64) -> Option<NodeId> {
    if height < 0 || height > store.node(tip).height {
        return None;
    }
    store.ancestor(tip, height)
}

fn diff_node(store: &NodeStore, id: NodeId) -> DiffNode {
    let n = store.node(id);
    DiffNode {
        height: n.height,
        timestamp: n.timestamp,
        bits: n.bits,
        sbits: n.sbits,
        pool_size: n.pool_size,
        fresh_stake: n.fresh_stake,
    }
}

/// Every lookup the views serve at `height` against a descent from the
/// view's tip.
fn check(view: &NodeBranchView<'_>, height: i64, what: &str) {
    let store = view.store;
    let want = want(store, view.tip, height);
    assert_eq!(
        ChainView::node(view, height),
        want.map(|id| diff_node(store, id)),
        "{what}: difficulty node at {height}"
    );
    assert_eq!(
        view.cache_hash(height),
        want.map(|id| store.node(id).hash.0),
        "{what}: cache hash at {height}"
    );
    let vote = view.vote_node(height);
    assert_eq!(
        vote.as_ref().map(|n| (n.node.height, n.votes.clone())),
        want.map(|id| (store.node(id).height, store.node(id).votes.clone())),
        "{what}: vote node at {height}"
    );
    let mut lent = None;
    let found = view.visit_votes(height, &mut |votes| lent = Some(votes.to_vec()));
    assert_eq!(found, want.is_some(), "{what}: votes found at {height}");
    assert_eq!(
        lent,
        want.map(|id| store.node(id).votes.clone()),
        "{what}: votes lent at {height}"
    );
}

#[test]
fn resumed_lookups_answer_what_a_descent_from_the_tip_does() {
    let mut store = NodeStore::new();
    let main = build_chain(&mut store, None, 0, 3000, 0);
    let side = build_chain(&mut store, Some(main[1500]), 1501, 2900, 1);
    let twig = build_chain(&mut store, Some(side[600]), 2102, 2400, 2);
    let tips = [
        main[3000], side[1399], twig[298], main[2000], side[100], main[0],
    ];
    let views: Vec<NodeBranchView<'_>> = tips
        .iter()
        .map(|&tip| NodeBranchView { store: &store, tip })
        .collect();

    for view in &views {
        let tip = store.node(view.tip).height;
        // A full descending walk, then a jump back up to the tip and a
        // second descent past the fork points, then out of range.
        for height in (0..=tip).rev() {
            check(view, height, "descending");
        }
        for height in (0..=tip).rev().step_by(7) {
            check(view, height, "second descent");
        }
        for height in [-1, tip + 1, tip, 0, tip / 2, tip / 2 - 1, tip / 2 + 1] {
            check(view, height, "jumps");
        }
    }

    // Views on different branches taking turns: each lookup may find the
    // other branch's node in the cursor.
    for step in 0..2_900i64 {
        for view in &views {
            let tip = store.node(view.tip).height;
            check(view, tip - step, "interleaved");
        }
    }

    // Random probes, each on a random view.
    let mut rng = SplitMix64::from_entropy("branch cursor probes");
    for _ in 0..20_000 {
        let view = &views[rng.below(views.len() as u64) as usize];
        let tip = store.node(view.tip).height;
        let height = rng.below(tip as u64 + 3) as i64 - 1;
        check(view, height, "random");
    }
}
