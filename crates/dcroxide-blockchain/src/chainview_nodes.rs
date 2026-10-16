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

use crate::blockindex::{ActiveAnchor, NodeId, NodeStore};

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
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "rv sums distinct exponents from 16, 8, 4, 2, 1, so rv <= 31"
        )]
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
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "node heights come from the u32 header height, so height + 1 <= 2^32"
        )]
        let needed = (store.node(tip).height + 1) as usize;
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "needed <= 2^32, and self.nodes.len() <= capacity < needed, so the reservation neither overflows nor underflows"
        )]
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
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "a Vec's len is at most isize::MAX, so len as i64 - 1 >= -1"
    )]
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
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "node heights come from the u32 header height, so height + 1 <= 2^32"
    )]
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
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "node_height is in 0..=12 in the first arm and in 13..=u32::MAX (a u32 header height) in the second, and fast_log2_floor returns at most 31"
        )]
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
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "height is a u32 header height and step <= 2^33 (see the doubling below), so height - step >= -2^33"
            )]
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
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "every entry is lower than the last, and once step exceeds the u32 height the next entry is genesis, which ends the walk, so step <= 2^33"
            )]
            if locator.len() > 10 {
                step *= 2;
            }
        }

        locator
    }
}

/// A height-indexed view over the branch of the block tree ending at
/// a given tip node, bridging the arena-based block index to the
/// `ChainView`/`VoteChainView` abstractions the validation functions
/// walk.  dcrd's equivalents walk `blockNode` parent pointers
/// directly; here the deterministic skip list serves each height
/// lookup, resuming from the node the view served last (the store's
/// branch cursor) when that node is at or above the height, so a
/// descending walk -- the difficulty windows, the ticket purchase sums,
/// the vote tally -- takes one parent hop per step as dcrd's does.  The
/// descending version walks follow the parent links directly once their
/// start is resolved.
pub struct NodeBranchView<'a> {
    /// The node store holding the branch.
    pub store: &'a crate::blockindex::NodeStore,
    /// The branch tip.
    pub tip: crate::blockindex::NodeId,
}

impl NodeBranchView<'_> {
    /// The node at the given height along this branch.
    fn node_id(&self, height: i64) -> Option<NodeId> {
        if height < 0 || height > self.store.node(self.tip).height {
            return None;
        }
        // Resume from the node this branch served last when it is at or
        // above the height; any ancestor of the tip leads to the same
        // node, and the step below the last one is its parent.
        let from = match self.store.branch_cursor.get() {
            Some((tip, last)) if tip == self.tip && self.store.node(last).height >= height => last,
            _ => self.tip,
        };
        let id = self.store.ancestor(from, height)?;
        self.store.branch_cursor.set(Some((self.tip, id)));
        Some(id)
    }

    /// The height of the given node when it is an ancestor of (or is)
    /// the node at the given height along this branch (dcrd
    /// `IsAncestorOf`).
    fn ancestor_height(&self, id: NodeId, height: i64) -> Option<i64> {
        self.node_id(height)?;
        let id_height = self.store.node(id).height;
        (id_height <= height && self.node_id(id_height) == Some(id)).then_some(id_height)
    }
}

#[cfg(test)]
std::thread_local! {
    /// How many times this thread walked the skip list to tell whether
    /// a branch descends from an agenda's activation anchor (the check
    /// a remembered answer gets under debug assertions is not counted).
    /// It exists in this crate's unit-test builds only, where the tests
    /// read it to tell which anchor queries were answered from the node
    /// remembered beside the anchor.
    pub(crate) static ANCHOR_WALKS: core::cell::Cell<u64> =
        const { core::cell::Cell::new(0) };
}

/// Fill the version data of the given block node into `out`, reusing
/// its vote version buffer.
fn fill_version_node(n: &crate::blockindex::BlockNode, out: &mut crate::stakever::VersionNode) {
    out.height = n.height;
    out.timestamp = n.timestamp;
    out.block_version = n.block_version;
    out.stake_version = n.stake_version;
    out.vote_versions.clear();
    out.vote_versions.extend(n.votes.iter().map(|v| v.0));
}

impl crate::difficulty::ChainView for NodeBranchView<'_> {
    fn node(&self, height: i64) -> Option<crate::difficulty::DiffNode> {
        let n = self.store.node(self.node_id(height)?);
        Some(crate::difficulty::DiffNode {
            height: n.height,
            timestamp: n.timestamp,
            bits: n.bits,
            sbits: n.sbits,
            pool_size: n.pool_size,
            fresh_stake: n.fresh_stake,
        })
    }

    fn blake3_anchor_cached(&self, height: i64) -> Option<i64> {
        self.ancestor_height(self.store.blake3_work_diff_anchor.get()?, height)
    }

    fn cache_blake3_anchor(&self, height: i64) {
        if let Some(id) = self.node_id(height) {
            self.store.blake3_work_diff_anchor.set(Some(id));
        }
    }

    fn blake3_candidate_anchor_cached(&self, height: i64) -> Option<i64> {
        self.ancestor_height(self.store.blake3_work_diff_candidate_anchor.get()?, height)
    }

    fn cache_blake3_candidate_anchor(&self, height: i64) {
        if let Some(id) = self.node_id(height) {
            self.store.blake3_work_diff_candidate_anchor.set(Some(id));
        }
    }
}

impl crate::stakever::VersionChainView for NodeBranchView<'_> {
    fn node(&self, height: i64) -> Option<crate::stakever::VersionNode> {
        let mut node = crate::stakever::VersionNode::default();
        fill_version_node(self.store.node(self.node_id(height)?), &mut node);
        Some(node)
    }

    // Resolve the start once through the skip list and then follow
    // parent links, one hop per step exactly like dcrd's walks, with
    // one reused node rather than a fresh lookup and allocation per
    // step.
    fn walk_back(&self, height: i64, visit: &mut dyn FnMut(&crate::stakever::VersionNode) -> bool) {
        let mut node = crate::stakever::VersionNode::default();
        let mut id = self.node_id(height);
        while let Some(cur) = id {
            let n = self.store.node(cur);
            fill_version_node(n, &mut node);
            if !visit(&node) {
                break;
            }
            id = n.parent;
        }
    }

    fn cache_hash(&self, height: i64) -> Option<[u8; 32]> {
        Some(self.store.node(self.node_id(height)?).hash.0)
    }

    fn voter_version_interval_cached(&self, hash: [u8; 32]) -> Option<Option<u32>> {
        self.store
            .voter_version_interval_cache
            .borrow()
            .get(&hash)
            .copied()
    }

    fn cache_voter_version_interval(&self, hash: [u8; 32], version: Option<u32>) {
        self.store
            .voter_version_interval_cache
            .borrow_mut()
            .insert(hash, version);
    }

    fn stake_majority_cached(&self, min_ver: u32, hash: [u8; 32]) -> Option<bool> {
        self.store
            .stake_majority_cache
            .borrow()
            .get(&(min_ver, hash))
            .copied()
    }

    fn cache_stake_majority(&self, min_ver: u32, hash: [u8; 32], majority: bool) {
        self.store
            .stake_majority_cache
            .borrow_mut()
            .insert((min_ver, hash), majority);
    }

    fn prior_stake_version_cached(&self, hash: [u8; 32]) -> Option<Option<u32>> {
        self.store
            .prior_stake_version_cache
            .borrow()
            .get(&hash)
            .copied()
    }

    fn cache_prior_stake_version(&self, hash: [u8; 32], version: Option<u32>) {
        self.store
            .prior_stake_version_cache
            .borrow_mut()
            .insert(hash, version);
    }

    fn stake_version_cached(&self, hash: [u8; 32]) -> Option<u32> {
        self.store.stake_version_cache.borrow().get(&hash).copied()
    }

    fn cache_stake_version(&self, hash: [u8; 32], version: u32) {
        self.store
            .stake_version_cache
            .borrow_mut()
            .insert(hash, version);
    }
}

impl crate::thresholdstate::VoteChainView for NodeBranchView<'_> {
    fn vote_node(&self, height: i64) -> Option<crate::thresholdstate::VoteNode> {
        let n = self.store.node(self.node_id(height)?);
        Some(crate::thresholdstate::VoteNode {
            node: crate::stakever::VersionNode {
                height: n.height,
                timestamp: n.timestamp,
                block_version: n.block_version,
                stake_version: n.stake_version,
                vote_versions: n.votes.iter().map(|v| v.0).collect(),
            },
            votes: n.votes.clone(),
        })
    }

    // Lend the node's own votes rather than build a node per step.
    fn visit_votes(
        &self,
        height: i64,
        visit: &mut dyn FnMut(&crate::thresholdstate::BlockVotes),
    ) -> bool {
        let Some(id) = self.node_id(height) else {
            return false;
        };
        visit(&self.store.node(id).votes);
        true
    }

    fn threshold_state_cached(
        &self,
        deployment_version: u32,
        vote_id: &str,
        hash: [u8; 32],
    ) -> Option<crate::thresholdstate::ThresholdStateTuple> {
        self.store
            .threshold_state_cache
            .borrow()
            .get(vote_id)?
            .get(&(deployment_version, hash))
            .copied()
    }

    fn cache_threshold_state(
        &self,
        deployment_version: u32,
        vote_id: &str,
        hash: [u8; 32],
        state: crate::thresholdstate::ThresholdStateTuple,
    ) {
        self.store
            .threshold_state_cache
            .borrow_mut()
            .entry(alloc::string::String::from(vote_id))
            .or_default()
            .insert((deployment_version, hash), state);
    }

    // The anchor heights can sit far below the tip, so these resolve
    // ancestors through the skip list directly and leave the branch
    // cursor where the descending walks put it.
    fn ancestor_hash(&self, height: i64) -> Option<[u8; 32]> {
        if height < 0 || height > self.store.node(self.tip).height {
            return None;
        }
        let id = self.store.ancestor(self.tip, height)?;
        Some(self.store.node(id).hash.0)
    }

    fn active_anchor_cached(&self, agenda_id: &str, prev_height: i64) -> Option<&'static str> {
        let anchors = self.store.agenda_active_anchors.borrow();
        let entry = anchors.get(agenda_id)?;
        let anchor_height = self.store.node(entry.anchor).height;
        let tip = self.store.node(self.tip);
        if anchor_height > prev_height || prev_height > tip.height {
            return None;
        }

        // The anchor is an ancestor of the tip exactly when the node at the
        // anchor's height on the tip's branch is the anchor, which dcrd
        // finds by walking there on every query (`IsAncestorOf`,
        // `blockindex.go:372-374`, called at `thresholdstate.go:454` and
        // `agendas.go:652`).  The branch of a node is its parent's branch
        // and the node, one block higher (the positional header checks
        // refuse any other height, and the skip list is built on it), and
        // the remembered node is at or above the anchor's height on a branch
        // that holds the anchor there.  So a tip that is the remembered
        // node, or a child of it, has the anchor at that height too, and the
        // walk would only find it again.  Every other tip is walked for as
        // before: one on another branch, one below the remembered node, or
        // one more than a block past it.  Only a tip the anchor was just
        // shown to be an ancestor of is remembered in its place.
        let descendant = entry.descendant.get();
        if self.tip == descendant || tip.parent == Some(descendant) {
            debug_assert_eq!(
                self.store.ancestor(self.tip, anchor_height),
                Some(entry.anchor),
                "the node remembered for an activation anchor does not descend from it"
            );
        } else {
            #[cfg(test)]
            ANCHOR_WALKS.set(ANCHOR_WALKS.get().wrapping_add(1));
            if self.store.ancestor(self.tip, anchor_height) != Some(entry.anchor) {
                return None;
            }
        }
        entry.descendant.set(self.tip);
        Some(entry.choice_id)
    }

    fn has_active_anchor(&self, agenda_id: &str) -> bool {
        self.store
            .agenda_active_anchors
            .borrow()
            .contains_key(agenda_id)
    }

    fn cache_active_anchor(&self, agenda_id: &str, height: i64, choice_id: &'static str) {
        if height < 0 || height > self.store.node(self.tip).height {
            return;
        }
        if let Some(id) = self.store.ancestor(self.tip, height) {
            // The walk above is the proof that this view's tip descends
            // from the new anchor.
            self.store.agenda_active_anchors.borrow_mut().insert(
                alloc::string::String::from(agenda_id),
                ActiveAnchor {
                    anchor: id,
                    choice_id,
                    descendant: core::cell::Cell::new(self.tip),
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    // Test-harness arithmetic over bounded heights and counts.
    #![allow(clippy::arithmetic_side_effects)]

    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;

    use dcroxide_testutil::SplitMix64;
    use dcroxide_wire::BlockHeader;

    use super::{ANCHOR_WALKS, NodeBranchView};
    use crate::blockindex::{NodeId, NodeStore};
    use crate::thresholdstate::VoteChainView;

    /// A new node on top of the given one, or a first node, distinct by
    /// its tag.
    fn new_node(store: &mut NodeStore, parent: Option<NodeId>, tag: u32) -> NodeId {
        let mut header = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header").0;
        if let Some(parent) = parent {
            let prev = store.node(parent);
            header.prev_block = prev.hash;
            header.height = prev.height as u32 + 1;
        }
        header.nonce = tag;
        store.new_node(&header, parent)
    }

    /// `count` chained nodes on top of the given one, in height order.
    fn chained(store: &mut NodeStore, parent: NodeId, count: u32, tag: u32) -> Vec<NodeId> {
        let mut ids = Vec::new();
        let mut parent = parent;
        for _ in 0..count {
            parent = new_node(store, Some(parent), tag);
            ids.push(parent);
        }
        ids
    }

    /// The anchor query as dcrd answers it (`thresholdstate.go:441-460`):
    /// the anchor's choice when the node at the anchor's height on the
    /// tip's branch is the anchor, found by following parent links one
    /// at a time, with the view's bounds on the queried height.
    fn walked(
        store: &NodeStore,
        anchor: Option<(NodeId, &'static str)>,
        tip: NodeId,
        prev_height: i64,
    ) -> Option<&'static str> {
        let (anchor, choice_id) = anchor?;
        let anchor_height = store.node(anchor).height;
        if anchor_height > prev_height || prev_height > store.node(tip).height {
            return None;
        }
        let mut node = Some(tip);
        while let Some(cur) = node {
            if store.node(cur).height == anchor_height {
                break;
            }
            node = store.node(cur).parent;
        }
        (node == Some(anchor)).then_some(choice_id)
    }

    /// The view's answer to the anchor query, and whether it walked the
    /// skip list for it.
    fn asked(
        store: &NodeStore,
        tip: NodeId,
        agenda_id: &str,
        prev_height: i64,
    ) -> (Option<&'static str>, bool) {
        let before = ANCHOR_WALKS.get();
        let got = NodeBranchView { store, tip }.active_anchor_cached(agenda_id, prev_height);
        (got, ANCHOR_WALKS.get() != before)
    }

    /// Every remembered node descends from the anchor it is remembered
    /// for, by parent links alone.
    fn assert_remembered_nodes_descend(store: &NodeStore, what: &str) {
        for (agenda_id, entry) in store.agenda_active_anchors.borrow().iter() {
            let descendant = entry.descendant.get();
            assert_eq!(
                walked(
                    store,
                    Some((entry.anchor, entry.choice_id)),
                    descendant,
                    store.node(descendant).height
                ),
                Some(entry.choice_id),
                "{what}: the node remembered for {agenda_id} does not descend from its anchor"
            );
        }
    }

    /// The queries around the block at which an agenda activates.
    ///
    /// ```text
    /// genesis -> 1 -> ... -> 9 -> 10  -> 11  -> 12 -> 13
    ///                        |      \-> 11t -> 12t
    ///                        \-> 10s -> 11s
    /// ```
    ///
    /// The anchor is block 10, the parent of the activation block: 11 and
    /// 11t both activate the agenda, and 10s and 11s are on a branch
    /// that never does.
    #[test]
    fn the_anchor_query_is_exact_at_the_activation_boundary() {
        let mut store = NodeStore::new();
        let genesis = new_node(&mut store, None, 0);
        let main = chained(&mut store, genesis, 13, 0);
        let at = |height: usize| main[height - 1];
        let t = chained(&mut store, at(10), 2, 1);
        let s = chained(&mut store, at(9), 2, 2);
        let anchor = Some((at(10), "yes"));

        // Nothing is cached yet.
        assert_eq!(asked(&store, at(13), "agenda", 13), (None, false));

        // The tally caches the anchor from the anchor's own view.
        NodeBranchView {
            store: &store,
            tip: at(10),
        }
        .cache_active_anchor("agenda", 10, "yes");
        assert!(
            NodeBranchView {
                store: &store,
                tip: genesis
            }
            .has_active_anchor("agenda")
        );

        // (tip, queried height, walked for).  The cases run in order.
        let cases: [(&str, NodeId, i64, bool); 16] = [
            ("the block below the anchor", at(9), 9, false),
            ("the anchor itself", at(10), 10, false),
            ("the anchor, asked below itself", at(10), 9, false),
            ("the anchor, asked above itself", at(10), 11, false),
            ("the activation block", at(11), 11, false),
            (
                "the activation block, asked at the anchor",
                at(11),
                10,
                false,
            ),
            (
                "the activation block, asked below the anchor",
                at(11),
                9,
                false,
            ),
            (
                "the activation block, asked above itself",
                at(11),
                12,
                false,
            ),
            ("another block that activates", t[0], 11, true),
            ("its child", t[1], 12, false),
            ("the anchor's sibling", s[0], 10, true),
            ("the anchor's sibling again", s[0], 10, true),
            ("the sibling's child", s[1], 11, true),
            ("the sibling's child, asked at the anchor", s[1], 10, true),
            (
                "back two blocks past the activation block",
                at(13),
                13,
                true,
            ),
            ("and its parent", at(12), 12, true),
        ];
        for (name, tip, prev_height, want_walk) in cases {
            let want = walked(&store, anchor, tip, prev_height);
            assert_eq!(
                asked(&store, tip, "agenda", prev_height),
                (want, want_walk),
                "{name}"
            );
            assert_remembered_nodes_descend(&store, name);
        }

        // The answers themselves, spelled out for the boundary.
        assert_eq!(walked(&store, anchor, at(9), 9), None);
        assert_eq!(walked(&store, anchor, at(10), 10), Some("yes"));
        assert_eq!(walked(&store, anchor, at(11), 11), Some("yes"));
        assert_eq!(walked(&store, anchor, t[0], 11), Some("yes"));
        assert_eq!(walked(&store, anchor, s[0], 10), None);
        assert_eq!(walked(&store, anchor, s[1], 11), None);
    }

    /// The best chain leaves the anchor's branch and returns to it, and
    /// moves to a branch that forks above the anchor and back.
    ///
    /// ```text
    /// genesis -> ... -> 8 -> 9  -> 10  -> 11 -> 12 -> 13  -> 14  -> 15  -> ... -> 18
    ///                   |                        \-> 13b -> 14b -> 15b
    ///                   \-> 9s -> 10s -> ... -> 15s
    /// ```
    #[test]
    fn the_anchor_query_is_exact_across_reorganizations() {
        let mut store = NodeStore::new();
        let genesis = new_node(&mut store, None, 0);
        let main = chained(&mut store, genesis, 18, 0);
        let at = |height: usize| main[height - 1];
        let b = chained(&mut store, at(12), 3, 1);
        let s = chained(&mut store, at(8), 7, 2);
        let anchor = Some((at(10), "yes"));
        NodeBranchView {
            store: &store,
            tip: at(10),
        }
        .cache_active_anchor("agenda", 10, "yes");

        // Each step asks about the block after the tip, as connecting
        // that block does.
        let step = |name: &str, tip: NodeId, want: Option<&'static str>, want_walk: bool| {
            let prev_height = store.node(tip).height;
            assert_eq!(walked(&store, anchor, tip, prev_height), want, "{name}");
            assert_eq!(
                asked(&store, tip, "agenda", prev_height),
                (want, want_walk),
                "{name}"
            );
            assert_remembered_nodes_descend(&store, name);
        };

        // Up the anchor's branch a block at a time: never a walk.
        for height in 10..=14 {
            step(
                "connecting on the anchor's branch",
                at(height),
                Some("yes"),
                false,
            );
        }

        // A reorganization to the branch that forked below the anchor:
        // its first block is below the anchor's height, and every block
        // from there on is walked for and is not a descendant.
        step("the side branch below the anchor", s[0], None, false);
        for tip in &s[1..] {
            step("the side branch from the anchor's height", *tip, None, true);
        }

        // Back to the anchor's branch at the block it left, and on: the
        // node remembered before the reorganization still stands.
        step("back on the anchor's branch", at(14), Some("yes"), false);
        step("and its child", at(15), Some("yes"), false);

        // A reorganization to the branch that forked above the anchor:
        // one walk to find that it descends too, then none.
        step("the branch above the anchor", b[0], Some("yes"), true);
        step("and its child", b[1], Some("yes"), false);
        step("and its grandchild", b[2], Some("yes"), false);

        // And back: one walk, then none.
        step(
            "back from the branch above the anchor",
            at(15),
            Some("yes"),
            true,
        );
        step("and its child", at(16), Some("yes"), false);

        // Asking about the same tip again, or its parent and the tip in
        // turn as a block's connection and the next header do.
        step("the same tip", at(16), Some("yes"), false);
        step("its parent", at(15), Some("yes"), true);
        step("the tip again", at(16), Some("yes"), false);

        // A tip two blocks past the remembered node is walked for.
        step("two blocks on", at(18), Some("yes"), true);
        step("the block between", at(17), Some("yes"), true);
    }

    /// Replacing an agenda's anchor forgets the node remembered for the
    /// old one, and each agenda keeps its own.
    #[test]
    fn a_new_anchor_does_not_inherit_the_old_ones_descendant() {
        let mut store = NodeStore::new();
        let genesis = new_node(&mut store, None, 0);
        let main = chained(&mut store, genesis, 12, 0);
        let side = chained(&mut store, main[4], 7, 1);
        let view = |tip| NodeBranchView { store: &store, tip };

        // Two agendas anchored on the main branch at height 8, each with
        // the main tip remembered.
        view(main[7]).cache_active_anchor("first", 8, "yes");
        view(main[7]).cache_active_anchor("second", 8, "yes");
        for agenda_id in ["first", "second"] {
            assert_eq!(asked(&store, main[11], agenda_id, 12), (Some("yes"), true));
            assert_eq!(asked(&store, main[11], agenda_id, 12), (Some("yes"), false));
        }

        // The first agenda's anchor moves to the side branch, cached
        // from the side tip.
        view(side[6]).cache_active_anchor("first", 8, "no");
        assert_remembered_nodes_descend(&store, "after the replacement");
        assert_eq!(asked(&store, main[11], "first", 12), (None, true));
        assert_eq!(asked(&store, main[10], "first", 11), (None, true));
        assert_eq!(asked(&store, side[6], "first", 12), (Some("no"), false));
        assert_eq!(asked(&store, side[5], "first", 11), (Some("no"), true));

        // The second agenda is untouched.
        assert_eq!(asked(&store, main[11], "second", 12), (Some("yes"), false));
        assert_eq!(asked(&store, side[6], "second", 12), (None, true));
        assert_remembered_nodes_descend(&store, "at the end");
    }

    /// Random trees of headers that keep growing, anchors that are set
    /// and replaced from random branches, and queries in random order:
    /// every answer is the one following parent links gives, and the
    /// remembered nodes always descend from their anchors.
    #[test]
    fn anchor_queries_match_the_plain_walk_over_random_trees() {
        const AGENDAS: [&str; 3] = ["one", "two", "three"];
        const CHOICES: [&str; 2] = ["yes", "no"];
        let mut rng = SplitMix64::from_entropy("activation anchor differential");

        let (mut asked_count, mut walk_count, mut active_count) = (0u64, 0u64, 0u64);
        for tree in 0..20 {
            let mut store = NodeStore::new();
            let mut nodes = alloc::vec![new_node(&mut store, None, 0)];
            let mut anchors: BTreeMap<&str, (NodeId, &'static str)> = BTreeMap::new();

            // A node from the tree, most often one of the newest.
            let pick = |rng: &mut SplitMix64, nodes: &[NodeId]| {
                let len = nodes.len() as u64;
                let back = match rng.below(20) {
                    0..=8 => 0,
                    9..=12 => 1,
                    13..=16 => rng.below(8),
                    _ => rng.below(len),
                };
                nodes[(len - 1 - back.min(len - 1)) as usize]
            };

            for op in 0..3000u32 {
                let what = alloc::format!("tree {tree}, step {op}");
                match rng.below(20) {
                    // Grow the tree: mostly the newest branch, sometimes
                    // a fork near it or anywhere.
                    0..=6 => {
                        let parent = pick(&mut rng, &nodes);
                        nodes.push(new_node(&mut store, Some(parent), op + 1));
                    }
                    // Set or replace an anchor from some branch, at a
                    // height that may be out of its range.
                    7 => {
                        let agenda_id = AGENDAS[rng.below(3) as usize];
                        let choice_id = CHOICES[rng.below(2) as usize];
                        let tip = pick(&mut rng, &nodes);
                        let tip_height = store.node(tip).height;
                        let height = rng.below(tip_height as u64 + 3) as i64 - 1;
                        NodeBranchView { store: &store, tip }
                            .cache_active_anchor(agenda_id, height, choice_id);
                        if (0..=tip_height).contains(&height) {
                            let mut anchor = tip;
                            while store.node(anchor).height != height {
                                anchor = store.node(anchor).parent.expect("above the height");
                            }
                            anchors.insert(agenda_id, (anchor, choice_id));
                        }
                    }
                    // Ask, mostly about the block after the tip and
                    // otherwise about a height at the tip's edges or the
                    // anchor's.
                    _ => {
                        let agenda_id = AGENDAS[rng.below(3) as usize];
                        let anchor = anchors.get(agenda_id).copied();
                        let tip = pick(&mut rng, &nodes);
                        let tip_height = store.node(tip).height;
                        let prev_height = match (rng.below(10), anchor) {
                            (0..=5, _) => tip_height,
                            (6..=7, Some((anchor, _))) => {
                                store.node(anchor).height + rng.below(3) as i64 - 1
                            }
                            _ => rng.below(tip_height as u64 + 4) as i64 - 2,
                        };
                        let want = walked(&store, anchor, tip, prev_height);
                        let (got, walk) = asked(&store, tip, agenda_id, prev_height);
                        assert_eq!(got, want, "{what}: {agenda_id} at {prev_height}");
                        asked_count += 1;
                        walk_count += u64::from(walk);
                        active_count += u64::from(got.is_some());
                    }
                }
                assert_remembered_nodes_descend(&store, &what);
                for agenda_id in AGENDAS {
                    assert_eq!(
                        NodeBranchView {
                            store: &store,
                            tip: nodes[0]
                        }
                        .has_active_anchor(agenda_id),
                        anchors.contains_key(agenda_id),
                        "{what}: {agenda_id}"
                    );
                }
            }
        }

        // The sequences reach both kinds of answer, by both routes.
        assert!(active_count > 1000, "{active_count} active answers");
        assert!(
            asked_count - active_count > 1000,
            "too few inactive answers"
        );
        assert!(walk_count > 1000, "{walk_count} walks");
        assert!(
            walk_count < asked_count - 1000,
            "{walk_count} walks for {asked_count} queries"
        );
    }

    /// An answer taken from the remembered node is walked for all the
    /// same under debug assertions, and the two are compared.  The
    /// answer rests on a node being one block above its parent, which
    /// the positional header checks hold every header to before it gets
    /// a node.  This store, which only a test can build, hangs a node
    /// that claims the anchor's own height on the remembered node: the
    /// walk from it ends at the node itself, not at the anchor, and the
    /// check says so.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(
        expected = "the node remembered for an activation anchor does not descend from it"
    )]
    fn an_answer_from_the_remembered_node_is_checked_against_the_walk() {
        let mut store = NodeStore::new();
        let genesis = new_node(&mut store, None, 0);
        let main = chained(&mut store, genesis, 2, 0);
        NodeBranchView {
            store: &store,
            tip: main[1],
        }
        .cache_active_anchor("agenda", 1, "yes");
        assert_eq!(asked(&store, main[1], "agenda", 1), (Some("yes"), false));

        let mut header = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header").0;
        header.prev_block = store.node(main[1]).hash;
        header.height = 1;
        let misplaced = store.new_node(&header, Some(main[1]));
        assert_eq!(store.node(misplaced).parent, Some(main[1]));
        let _ = NodeBranchView {
            store: &store,
            tip: misplaced,
        }
        .active_anchor_cached("agenda", 1);
    }
}
