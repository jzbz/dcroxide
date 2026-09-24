// SPDX-License-Identifier: ISC
//! The block index view's descending version walk.
//!
//! dcrd's `isMajorityVersion` and `CalcPastMedianTime` follow
//! `iterNode.parent`.  `NodeBranchView` used to serve each step with a
//! fresh skip-list descent from the branch tip plus a clone of the
//! node's votes, about twenty node visits and two allocations per step
//! of a 1000-block walk that runs for every header.  It now resolves
//! the start once and follows parent links.  These tests pin that the
//! walk visits exactly what the height-by-height default visits, on the
//! main branch and on a side branch, so the majority and median results
//! cannot drift.

// Test-harness arithmetic over bounded heights.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::blockindex::{NodeId, NodeStore};
use dcroxide_blockchain::chainview_nodes::NodeBranchView;
use dcroxide_blockchain::stakever::{
    VersionChainView, VersionNode, calc_past_median_time, is_majority_version,
};
use dcroxide_chaincfg::mainnet_params;
use dcroxide_wire::BlockHeader;

/// The same branch served only through `node`, so every walk takes
/// the trait's height-by-height default.
struct ByHeight<'a>(&'a NodeBranchView<'a>);

impl VersionChainView for ByHeight<'_> {
    fn node(&self, height: i64) -> Option<VersionNode> {
        VersionChainView::node(self.0, height)
    }
}

/// Extend `parent` with nodes up to `to`, mixing block versions,
/// timestamps and (from height 30) vote versions.
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
        header.version = 5 + ((height * 7 + salt) % 4) as i32;
        header.stake_version = (height + salt) % 3;
        // Out of order, so the median is not simply the middle block.
        header.timestamp = 1_000_000 + height * 300 + (height * 37 + salt) % 900;
        header.nonce = salt;
        let id = store.new_node(&header, parent);
        if height >= 30 {
            let votes = (0..(height + salt) % 6)
                .map(|i| (4 + (height + i) % 3, 1u16))
                .collect();
            store.populate_ticket_info(id, Vec::new(), Vec::new(), votes);
        }
        ids.push(id);
        parent = Some(id);
    }
    ids
}

fn walk(view: &impl VersionChainView, height: i64, limit: usize) -> Vec<VersionNode> {
    let mut visited = Vec::new();
    view.walk_back(height, &mut |node| {
        visited.push(node.clone());
        visited.len() < limit
    });
    visited
}

#[test]
fn parent_walk_matches_height_walk() {
    let mut params = mainnet_params();
    // Short enough to reach genesis from the tips below as well as to
    // stop early.
    params.block_upgrade_num_to_check = 300;

    let mut store = NodeStore::new();
    let main = build_chain(&mut store, None, 0, 1200, 0);
    let side = build_chain(&mut store, Some(main[700]), 701, 1100, 1);
    let views = [
        NodeBranchView {
            store: &store,
            tip: main[1200],
        },
        NodeBranchView {
            store: &store,
            tip: side[399],
        },
    ];

    for view in &views {
        let by_height = ByHeight(view);
        let tip = view.store.node(view.tip).height;
        for start in [0i64, 1, 5, 10, 11, 250, 699, 700, 701, 1000, tip] {
            for limit in [1usize, 11, 300, usize::MAX] {
                assert_eq!(
                    walk(view, start, limit),
                    walk(&by_height, start, limit),
                    "start {start} limit {limit}"
                );
            }
            assert_eq!(
                calc_past_median_time(view, start),
                calc_past_median_time(&by_height, start),
                "median at {start}"
            );
            for min_ver in 5..=9 {
                for num_required in [0u64, 1, 75, 150, 299, 300, 301] {
                    assert_eq!(
                        is_majority_version(view, min_ver, Some(start), num_required, &params),
                        is_majority_version(
                            &by_height,
                            min_ver,
                            Some(start),
                            num_required,
                            &params
                        ),
                        "start {start} min_ver {min_ver} required {num_required}"
                    );
                }
            }
        }

        // Out-of-range starts visit nothing.
        assert!(walk(view, -1, usize::MAX).is_empty());
        assert!(walk(view, tip + 1, usize::MAX).is_empty());
        assert!(!is_majority_version(view, 5, None, 1, &params));
        assert!(is_majority_version(view, 5, None, 0, &params));
    }

    // A full walk from the side tip visits every height down to genesis
    // along the side branch, carrying its vote versions.
    let side_walk = walk(&views[1], 1100, usize::MAX);
    assert_eq!(side_walk.len(), 1101);
    assert!(
        side_walk
            .iter()
            .zip((0..=1100).rev())
            .all(|(node, height)| node.height == height)
    );
    assert!(side_walk.iter().any(|node| !node.vote_versions.is_empty()));
}
