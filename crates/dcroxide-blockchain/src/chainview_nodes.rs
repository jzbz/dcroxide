// SPDX-License-Identifier: ISC
//! The efficient chain view over block index nodes from dcrd's
//! `chainview.go`: a flat height-indexed view of a specific branch of
//! the block tree with O(1) lookups, fork finding, and block locator
//! construction.
//!
//! This is named `chainview_nodes` because the crate already exposes
//! `ChainView` as the height-indexed difficulty view trait; this type
//! is the concrete engine structure over [`NodeStore`] nodes.

use alloc::vec::Vec;

use dcroxide_chainhash::Hash;

use crate::blockindex::{NodeId, NodeStore};

/// The approximate number of nodes produced per week on average, used
/// to size the view (dcrd `approxNodesPerWeek`).
const APPROX_NODES_PER_WEEK: usize = 12 * 24 * 7;

/// A block locator: hashes from a block backward to the genesis block,
/// dense for the first 10 then doubling in distance (dcrd
/// `BlockLocator`).
pub type BlockLocator = Vec<Hash>;

/// The masks and shifts for the fast log2 floor calculation (dcrd
/// `log2FloorMasks`).
const LOG2_FLOOR_MASKS: [u32; 5] = [0xffff0000, 0xff00, 0xf0, 0xc, 0x2];

/// The floor of the base-2 logarithm of the passed value (dcrd
/// `fastLog2Floor`); 0 for an input of 0.
pub fn fast_log2_floor(mut n: u32) -> u8 {
    let mut rv: u8 = 0;
    let mut exponent: u8 = 16;
    for mask in LOG2_FLOOR_MASKS {
        if n & mask != 0 {
            rv += exponent;
            n >>= exponent;
        }
        exponent >>= 1;
    }
    rv
}

/// A chain of block nodes from a particular tip back to the genesis
/// block, indexable by height (dcrd `chainView`).
#[derive(Default)]
pub struct NodeChainView {
    nodes: Vec<Option<NodeId>>,
}

impl NodeChainView {
    /// A new chain view for the given tip, which may be `None` for an
    /// empty view (dcrd `newChainView`).
    pub fn new(store: &NodeStore, tip: Option<NodeId>) -> NodeChainView {
        let mut view = NodeChainView::default();
        view.set_tip(store, tip);
        view
    }

    /// The genesis (first) node of the view, if any (dcrd `Genesis`).
    pub fn genesis(&self) -> Option<NodeId> {
        self.nodes.first().copied().flatten()
    }

    /// The current tip, if any (dcrd `Tip`).
    pub fn tip(&self) -> Option<NodeId> {
        self.nodes.last().copied().flatten()
    }

    /// Set the view to the given tip, efficiently reusing the common
    /// ancestry with the previous tip (dcrd `SetTip`).
    pub fn set_tip(&mut self, store: &NodeStore, tip: Option<NodeId>) {
        let Some(tip) = tip else {
            self.nodes.clear();
            return;
        };

        // Resize to exactly the number of nodes the new tip implies,
        // clearing any newly exposed slots so the ancestry walk below
        // fills them.
        let needed = (store.node(tip).height + 1) as usize;
        if self.nodes.capacity() < needed {
            self.nodes
                .reserve(needed + APPROX_NODES_PER_WEEK - self.nodes.len());
        }
        self.nodes.resize(needed, None);

        // Walk backwards filling entries until reaching ancestry
        // already present in the view.
        let mut node = Some(tip);
        while let Some(cur) = node {
            let height = store.node(cur).height as usize;
            if self.nodes[height] == Some(cur) {
                break;
            }
            self.nodes[height] = Some(cur);
            node = store.node(cur).parent;
        }
    }

    /// The height of the tip; -1 when empty (dcrd `Height`).
    pub fn height(&self) -> i64 {
        self.nodes.len() as i64 - 1
    }

    /// The node at the given height, if it exists in the view (dcrd
    /// `NodeByHeight`).
    pub fn node_by_height(&self, height: i64) -> Option<NodeId> {
        if height < 0 || height >= self.nodes.len() as i64 {
            return None;
        }
        self.nodes[height as usize]
    }

    /// Whether the two views are the same: same length and same tip
    /// (dcrd `Equals`).
    pub fn equals(&self, other: &NodeChainView) -> bool {
        self.nodes.len() == other.nodes.len() && self.tip() == other.tip()
    }

    /// Whether the view contains the passed node (dcrd `Contains`).
    pub fn contains(&self, store: &NodeStore, node: NodeId) -> bool {
        self.node_by_height(store.node(node).height) == Some(node)
    }

    /// The successor of the given node in the view, if the node is in
    /// the view and a successor exists (dcrd `Next`).
    pub fn next(&self, store: &NodeStore, node: NodeId) -> Option<NodeId> {
        if !self.contains(store, node) {
            return None;
        }
        self.node_by_height(store.node(node).height + 1)
    }

    /// The final common block between the view and the branch the
    /// given node sits on (dcrd `FindFork`); the node itself when it
    /// is in the view.
    pub fn find_fork(&self, store: &NodeStore, node: NodeId) -> Option<NodeId> {
        // Walk down to the view height first since no node above it
        // can be in the view.
        let chain_height = self.height();
        let mut node = if store.node(node).height > chain_height {
            store.ancestor(node, chain_height)
        } else {
            Some(node)
        };

        while let Some(cur) = node {
            if self.contains(store, cur) {
                break;
            }
            node = store.node(cur).parent;
        }
        node
    }

    /// A block locator for the passed node, or for the current tip
    /// when `None` (dcrd `BlockLocator`): the node itself, then dense
    /// hashes for 10 blocks, then doubling distances back to genesis.
    pub fn block_locator(&self, store: &NodeStore, node: Option<NodeId>) -> BlockLocator {
        let Some(mut node) = node.or_else(|| self.tip()) else {
            return BlockLocator::new();
        };

        let node_height = store.node(node).height;
        let max_entries = if node_height <= 12 {
            node_height as usize + 1
        } else {
            // The hash itself + previous 10 entries + genesis, then
            // floor(log2(height-10)) entries for the skip portion.
            12 + fast_log2_floor((node_height - 10) as u32) as usize
        };
        let mut locator = BlockLocator::with_capacity(max_entries);

        let mut step: i64 = 1;
        loop {
            locator.push(store.node(node).hash);

            // Nothing more to add once the genesis block is included.
            let height = store.node(node).height;
            if height == 0 {
                break;
            }

            // The height of the previous node to include, ensuring the
            // final node is the genesis block.
            let prev_height = (height - step).max(0);

            // O(1) lookup when the node is in the view; otherwise walk
            // backwards through the other chain to the right ancestor.
            let next = if self.contains(store, node) {
                self.nodes[prev_height as usize]
            } else {
                store.ancestor(node, prev_height)
            };
            let Some(next) = next else {
                break;
            };
            node = next;

            // Once 11 entries are included, start doubling the
            // distance between included hashes.
            if locator.len() > 10 {
                step *= 2;
            }
        }

        locator
    }
}
