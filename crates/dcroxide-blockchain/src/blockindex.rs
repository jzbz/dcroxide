// SPDX-License-Identifier: ISC
//! The in-memory block index from dcrd's `blockindex.go`: block nodes
//! with deterministic skip-list ancestor traversal and accumulated
//! work sums, validation status flags, chain tip tracking, best chain
//! candidate selection, and invalidation propagation.
//!
//! Go's parent-pointer node graph is represented as an arena
//! ([`NodeStore`]) with index-based links, which both the block index
//! and the chain view borrow.  dcrd's short-key/collision map pair is
//! a pure memory optimization over a hash-keyed map and is not
//! reproduced; neither are the mutex wrappers (single-threaded here
//! until the chain engine settles concurrency), the database flush
//! machinery (`modified`/`Flush`, which arrive with engine
//! persistence), or the wall-clock cached-tip prune timer (the prune
//! itself is exposed directly).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use dcroxide_chainhash::Hash;
use dcroxide_uint256::Uint256;
use dcroxide_wire::BlockHeader;

use crate::stakever::MEDIAN_TIME_BLOCKS;

/// Possible status bit flags for a block (dcrd `blockStatus`).  These
/// values are serialized and must be stable.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockStatus(pub u8);

impl BlockStatus {
    /// No validation state flags set (dcrd `statusNone`).
    pub const NONE: BlockStatus = BlockStatus(0);
    /// The block's payload is stored on disk (dcrd
    /// `statusDataStored`).
    pub const DATA_STORED: BlockStatus = BlockStatus(1 << 0);
    /// The block and all of its ancestors have been fully validated
    /// (dcrd `statusValidated`).
    pub const VALIDATED: BlockStatus = BlockStatus(1 << 1);
    /// The block has failed validation (dcrd `statusValidateFailed`).
    pub const VALIDATE_FAILED: BlockStatus = BlockStatus(1 << 2);
    /// One of the block's ancestors has failed validation (dcrd
    /// `statusInvalidAncestor`).
    pub const INVALID_ANCESTOR: BlockStatus = BlockStatus(1 << 3);

    /// Whether the full block data is stored (dcrd `HaveData`).
    pub fn have_data(self) -> bool {
        self.0 & BlockStatus::DATA_STORED.0 != 0
    }

    /// Whether the block has been fully validated (dcrd
    /// `HasValidated`).
    pub fn has_validated(self) -> bool {
        self.0 & BlockStatus::VALIDATED.0 != 0
    }

    /// Whether the block itself or one of its ancestors is known to be
    /// invalid (dcrd `KnownInvalid`).
    pub fn known_invalid(self) -> bool {
        self.0 & (BlockStatus::VALIDATE_FAILED.0 | BlockStatus::INVALID_ANCESTOR.0) != 0
    }

    /// Whether one of the block's ancestors is known to be invalid
    /// (dcrd `KnownInvalidAncestor`).
    pub fn known_invalid_ancestor(self) -> bool {
        self.0 & BlockStatus::INVALID_ANCESTOR.0 != 0
    }

    /// Whether the block itself is known to have failed validation
    /// (dcrd `KnownValidateFailed`).
    pub fn known_validate_failed(self) -> bool {
        self.0 & BlockStatus::VALIDATE_FAILED.0 != 0
    }
}

/// The number of blocks before the best block hint to prune cached
/// chain tips (dcrd `cachedTipsPruneDepth`).
pub const CACHED_TIPS_PRUNE_DEPTH: i64 = 12;

/// A handle to a block node within a [`NodeStore`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, core::hash::Hash)]
pub struct NodeId(usize);

/// A block within the block tree (dcrd `blockNode`), holding the
/// header fields needed for chain selection and header
/// reconstruction.
#[derive(Clone, Debug)]
pub struct BlockNode {
    /// The parent node, if any.
    pub parent: Option<NodeId>,
    /// The skip-list ancestor used to speed up deep traversal.
    pub skip_to_ancestor: Option<NodeId>,
    /// The hash of the block this node represents.
    pub hash: Hash,
    /// The total amount of work in the chain up to and including this
    /// node.
    pub work_sum: Uint256,

    /// Block height.
    pub height: i64,
    /// Header vote bits.
    pub vote_bits: u16,
    /// Header lottery final state.
    pub final_state: [u8; 6],
    /// Header block version.
    pub block_version: i32,
    /// Header vote count.
    pub voters: u16,
    /// Header fresh stake (ticket) count.
    pub fresh_stake: u8,
    /// Header revocation count.
    pub revocations: u8,
    /// Header ticket pool size commitment.
    pub pool_size: u32,
    /// Header difficulty bits.
    pub bits: u32,
    /// Header stake difficulty.
    pub sbits: i64,
    /// Header timestamp as unix seconds.
    pub timestamp: i64,
    /// Header merkle root.
    pub merkle_root: Hash,
    /// Header stake tree merkle root.
    pub stake_root: Hash,
    /// Header block size commitment.
    pub block_size: u32,
    /// Header nonce.
    pub nonce: u32,
    /// Header extra data.
    pub extra_data: [u8; 32],
    /// Header stake version.
    pub stake_version: u32,

    /// The validation status bitfield.
    pub status: BlockStatus,
    /// Whether this block builds on a branch with the data for all of
    /// its ancestors available and is therefore eligible for
    /// validation.
    pub is_fully_linked: bool,

    /// Prunable ticket info: the tickets voted by this block.
    pub tickets_voted: Vec<Hash>,
    /// Prunable ticket info: the tickets revoked by this block.
    pub tickets_revoked: Vec<Hash>,
    /// The (vote version, bits) pairs carried by this block's votes.
    pub votes: Vec<(u32, u16)>,

    /// The order block data was received, to prevent gaining chain
    /// selection priority by submitting headers first.
    pub received_order_id: u32,

    /// The immutable ticket pool state as of this block, when loaded
    /// (dcrd `stakeNode`; pruned nodes drop it and it is regenerated
    /// on demand).
    pub stake_node: Option<dcroxide_stake::ticketnode::Node>,
    /// The tickets maturing in this block, when loaded (dcrd
    /// `newTickets`; `None` means never looked up while an empty list
    /// means no tickets mature here).
    pub new_tickets: Option<Vec<Hash>>,
    /// Whether the prunable vote and revocation info has been
    /// populated.  dcrd tracks this through the nil-ness of the
    /// ticket info slices; a flag is equivalent since they are always
    /// populated together and repopulation is idempotent.
    pub ticket_info_populated: bool,
}

/// Clear the lowest set bit in the passed value (dcrd
/// `clearLowestOneBit`).
fn clear_lowest_one_bit(n: i64) -> i64 {
    n & (n - 1)
}

/// The height of the ancestor to use when constructing the
/// deterministic skip list (dcrd `calcSkipListHeight`).
pub fn calc_skip_list_height(height: i64) -> i64 {
    if height < 0 {
        return 0;
    }
    clear_lowest_one_bit(clear_lowest_one_bit(height))
}

/// The proof of work as a 256-bit integer for the given difficulty
/// bits (dcrd `primitives.CalcWork` semantics via the standalone
/// big-integer implementation, which is zero for invalid or negative
/// targets).
fn calc_work_uint256(bits: u32) -> Uint256 {
    let work = dcroxide_standalone::calc_work(bits);
    let (_, bytes) = work.to_bytes_be();
    let mut be = [0u8; 32];
    let n = bytes.len().min(32);
    be[32 - n..].copy_from_slice(&bytes[bytes.len() - n..]);
    Uint256::from_be_bytes(&be)
}

/// Compare two hashes as little-endian uint256s (dcrd
/// `compareHashesAsUint256LE`): 1 when a > b, -1 when a < b, 0 when
/// equal.
pub fn compare_hashes_as_uint256_le(a: &Hash, b: &Hash) -> i32 {
    for index in (0..32).rev() {
        if a.0[index] != b.0[index] {
            return if a.0[index] > b.0[index] { 1 } else { -1 };
        }
    }
    0
}

/// The threshold-state cache rows: the deployment version, its vote
/// id, and the interval-boundary block hash mapping to the computed
/// state.
type ThresholdStateCacheMap = alloc::collections::BTreeMap<
    (u32, alloc::string::String, [u8; 32]),
    crate::thresholdstate::ThresholdStateTuple,
>;

/// The arena owning every block node, providing the node-level
/// operations dcrd implements as `blockNode` methods.
///
/// The store also owns the hash-keyed memoization caches dcrd keeps
/// on its `BlockChain` (the per-deployment `thresholdStateCache` and
/// the four stake-version caches from blockchain.go).  They live here
/// so the branch views can consult them without widening any
/// signatures; entries are keyed by block hash, so they are correct
/// across every branch and never need invalidating.  Interior
/// mutability lets the read-only views record results.
#[derive(Default)]
pub struct NodeStore {
    nodes: Vec<BlockNode>,
    /// dcrd's per-deployment `thresholdStateCache`, keyed by the
    /// deployment version, its vote id, and the interval-boundary
    /// block hash.
    pub(crate) threshold_state_cache: core::cell::RefCell<ThresholdStateCacheMap>,
    /// dcrd's `calcVoterVersionIntervalCache`, keyed by the
    /// interval-final block hash.
    pub(crate) voter_version_interval_cache:
        core::cell::RefCell<alloc::collections::BTreeMap<[u8; 32], Option<u32>>>,
    /// dcrd's `isStakeMajorityVersionCache`, keyed by the minimum
    /// version and the block hash.
    pub(crate) stake_majority_cache:
        core::cell::RefCell<alloc::collections::BTreeMap<(u32, [u8; 32]), bool>>,
    /// dcrd's `calcPriorStakeVersionCache`, keyed by the block hash.
    pub(crate) prior_stake_version_cache:
        core::cell::RefCell<alloc::collections::BTreeMap<[u8; 32], Option<u32>>>,
    /// dcrd's `calcStakeVersionCache`, keyed by the block hash.
    pub(crate) stake_version_cache:
        core::cell::RefCell<alloc::collections::BTreeMap<[u8; 32], u32>>,
}

impl NodeStore {
    /// A new empty node store.
    pub fn new() -> NodeStore {
        NodeStore::default()
    }

    /// The node for the given id.
    pub fn node(&self, id: NodeId) -> &BlockNode {
        &self.nodes[id.0]
    }

    /// Mutable access to the node for the given id.
    pub fn node_mut(&mut self, id: NodeId) -> &mut BlockNode {
        &mut self.nodes[id.0]
    }

    /// Create a block node for the given header and parent (dcrd
    /// `newBlockNode`/`initBlockNode`).  The work sum accumulates from
    /// the parent when one is provided.
    pub fn new_node(&mut self, header: &BlockHeader, parent: Option<NodeId>) -> NodeId {
        let mut node = BlockNode {
            parent: None,
            skip_to_ancestor: None,
            hash: header.block_hash(),
            work_sum: calc_work_uint256(header.bits),
            height: i64::from(header.height),
            block_version: header.version,
            vote_bits: header.vote_bits,
            final_state: header.final_state,
            voters: header.voters,
            fresh_stake: header.fresh_stake,
            pool_size: header.pool_size,
            bits: header.bits,
            sbits: header.sbits,
            timestamp: i64::from(header.timestamp),
            merkle_root: header.merkle_root,
            stake_root: header.stake_root,
            revocations: header.revocations,
            block_size: header.size,
            nonce: header.nonce,
            extra_data: header.extra_data,
            stake_version: header.stake_version,
            status: BlockStatus::NONE,
            is_fully_linked: false,
            tickets_voted: Vec::new(),
            tickets_revoked: Vec::new(),
            votes: Vec::new(),
            received_order_id: 0,
            stake_node: None,
            new_tickets: None,
            ticket_info_populated: false,
        };
        if let Some(parent_id) = parent {
            node.parent = Some(parent_id);
            node.skip_to_ancestor = self.ancestor(parent_id, calc_skip_list_height(node.height));
            let parent_work = self.node(parent_id).work_sum;
            node.work_sum.add(&parent_work);
        }
        let id = NodeId(self.nodes.len());
        self.nodes.push(node);
        id
    }

    /// Reconstruct the block header for the node (dcrd `Header`).
    pub fn header(&self, id: NodeId) -> BlockHeader {
        let node = self.node(id);
        let prev_block = match node.parent {
            Some(p) => self.node(p).hash,
            None => Hash([0u8; 32]),
        };
        BlockHeader {
            version: node.block_version,
            prev_block,
            merkle_root: node.merkle_root,
            stake_root: node.stake_root,
            vote_bits: node.vote_bits,
            final_state: node.final_state,
            voters: node.voters,
            fresh_stake: node.fresh_stake,
            revocations: node.revocations,
            pool_size: node.pool_size,
            bits: node.bits,
            sbits: node.sbits,
            height: node.height as u32,
            size: node.block_size,
            timestamp: node.timestamp as u32,
            nonce: node.nonce,
            extra_data: node.extra_data,
            stake_version: node.stake_version,
        }
    }

    /// The initialization vector for the ticket lottery PRNG (dcrd
    /// `lotteryIV`).
    pub fn lottery_iv(&self, id: NodeId) -> Hash {
        let header = self.header(id);
        dcroxide_stake::calc_hash256_prng_iv(&header.serialize())
    }

    /// Set the prunable ticket information (dcrd
    /// `populateTicketInfo`).
    pub fn populate_ticket_info(
        &mut self,
        id: NodeId,
        voted: Vec<Hash>,
        revoked: Vec<Hash>,
        votes: Vec<(u32, u16)>,
    ) {
        let node = self.node_mut(id);
        node.tickets_voted = voted;
        node.tickets_revoked = revoked;
        node.votes = votes;
        node.ticket_info_populated = true;
    }

    /// The ancestor node at the provided height, following the chain
    /// backwards via the skip list (dcrd `Ancestor`).  `None` when the
    /// height is negative or after this node.
    pub fn ancestor(&self, id: NodeId, height: i64) -> Option<NodeId> {
        if height < 0 || height > self.node(id).height {
            return None;
        }

        let mut n = Some(id);
        while let Some(cur) = n {
            let node = self.node(cur);
            if node.height == height {
                break;
            }
            // Skip to the linked ancestor when it won't overshoot the
            // target height.
            if node.skip_to_ancestor.is_some() && calc_skip_list_height(node.height) >= height {
                n = node.skip_to_ancestor;
                continue;
            }
            n = node.parent;
        }
        n
    }

    /// The ancestor a relative distance of blocks before this node
    /// (dcrd `RelativeAncestor`).
    pub fn relative_ancestor(&self, id: NodeId, distance: i64) -> Option<NodeId> {
        let height = self.node(id).height - distance;
        self.ancestor(id, height)
    }

    /// Whether this node is an ancestor of the target node; nodes are
    /// considered ancestors of themselves (dcrd `IsAncestorOf`).
    pub fn is_ancestor_of(&self, id: NodeId, target: NodeId) -> bool {
        self.ancestor(target, self.node(id).height) == Some(id)
    }

    /// The median time of the previous few blocks prior to and
    /// including this node, preserving dcrd's simple-middle-element
    /// behavior for even counts near genesis (dcrd
    /// `CalcPastMedianTime`).
    pub fn calc_past_median_time(&self, id: NodeId) -> i64 {
        let mut timestamps = Vec::with_capacity(MEDIAN_TIME_BLOCKS);
        let mut iter = Some(id);
        for _ in 0..MEDIAN_TIME_BLOCKS {
            let Some(cur) = iter else {
                break;
            };
            let node = self.node(cur);
            timestamps.push(node.timestamp);
            iter = node.parent;
        }
        timestamps.sort_unstable();
        timestamps[timestamps.len() / 2]
    }

    /// Whether node `a` is a better candidate than `b` for best chain
    /// selection (dcrd `betterCandidate`): more cumulative work, then
    /// data availability, then earlier received data, then the smaller
    /// hash as a little-endian uint256.
    pub fn better_candidate(&self, a: NodeId, b: NodeId) -> bool {
        let (na, nb) = (self.node(a), self.node(b));
        let work_cmp = na.work_sum.cmp(&nb.work_sum);
        if work_cmp != core::cmp::Ordering::Equal {
            return work_cmp == core::cmp::Ordering::Greater;
        }
        let a_has_data = na.status.have_data();
        if a_has_data != nb.status.have_data() {
            return a_has_data;
        }
        if na.received_order_id != nb.received_order_id {
            return na.received_order_id < nb.received_order_id;
        }
        compare_hashes_as_uint256_le(&na.hash, &nb.hash) < 0
    }
}

/// An entry tracking the chain tips at a single height (dcrd
/// `chainTipEntry`).
#[derive(Default)]
struct ChainTipEntry {
    tip: Option<NodeId>,
    other_tips: Vec<NodeId>,
}

/// The in-memory index of the block tree (dcrd `blockIndex`).  The
/// node arena is passed to each operation rather than owned so that
/// views and the index share the same store, mirroring dcrd's
/// freestanding node pointers.
pub struct BlockIndex {
    by_hash: BTreeMap<[u8; 32], NodeId>,
    chain_tips: BTreeMap<i64, ChainTipEntry>,
    total_tips: u64,

    best_header: Option<NodeId>,
    best_invalid: Option<NodeId>,
    /// Nodes with unflushed changes (dcrd `modified`).
    modified: alloc::collections::BTreeSet<NodeId>,
    best_chain_candidates: BTreeSet<NodeId>,
    unlinked_children_of: BTreeMap<NodeId, Vec<NodeId>>,
    next_received_order_id: u32,

    cached_tips: BTreeMap<[u8; 32], NodeId>,
    cached_tips_start: i64,
}

impl Default for BlockIndex {
    fn default() -> Self {
        BlockIndex::new()
    }
}

impl BlockIndex {
    /// A new empty block index (dcrd `newBlockIndex`); the next
    /// received order id starts at one since entries loaded from disk
    /// are zero.
    pub fn new() -> BlockIndex {
        BlockIndex {
            by_hash: BTreeMap::new(),
            chain_tips: BTreeMap::new(),
            total_tips: 0,
            best_header: None,
            best_invalid: None,
            modified: alloc::collections::BTreeSet::new(),
            best_chain_candidates: BTreeSet::new(),
            unlinked_children_of: BTreeMap::new(),
            next_received_order_id: 1,
            cached_tips: BTreeMap::new(),
            cached_tips_start: 0,
        }
    }

    /// Whether the index contains the hash and its block data is
    /// available (dcrd `HaveBlock`).
    pub fn have_block(&self, store: &NodeStore, hash: &Hash) -> bool {
        self.lookup_node(hash)
            .is_some_and(|id| store.node(id).status.have_data())
    }

    /// Add the provided node to the index (dcrd `addNode`/`AddNode`).
    /// Duplicate entries are not checked.
    pub fn add_node(&mut self, store: &NodeStore, node: NodeId) {
        self.modified.insert(node);
        let (hash, height, parent, invalid) = {
            let n = store.node(node);
            (n.hash, n.height, n.parent, n.status.known_invalid())
        };
        self.by_hash.insert(hash.0, node);

        // All new nodes are a new chain tip; when extending a chain
        // the parent is no longer a tip.
        self.add_chain_tip(node, height, hash);
        if let Some(parent_id) = parent {
            let (ph, phash) = {
                let p = store.node(parent_id);
                (p.height, p.hash)
            };
            self.remove_chain_tip(parent_id, ph, phash);
        }

        // Track the header with the most known work that is not known
        // to be invalid.
        if !invalid {
            let better = match self.best_header {
                Some(best) => store.better_candidate(node, best),
                None => true,
            };
            if better {
                self.best_header = Some(node);
            }
        }
    }

    /// Add a node that came from storage, updating the unlinked block
    /// dependencies and best invalid block as needed (dcrd
    /// `addNodeFromDB`).
    pub fn add_node_from_db(&mut self, store: &NodeStore, node: NodeId) {
        self.add_node(store, node);

        let n = store.node(node);
        let (fully_linked, have_data, parent, invalid) = (
            n.is_fully_linked,
            n.status.have_data(),
            n.parent,
            n.status.known_invalid(),
        );
        if !fully_linked
            && have_data
            && let Some(parent_id) = parent
            && !store.node(parent_id).status.known_invalid()
        {
            self.unlinked_children_of
                .entry(parent_id)
                .or_default()
                .push(node);
        }
        if invalid {
            self.maybe_update_best_invalid(store, node);
        }
    }

    fn add_chain_tip(&mut self, tip: NodeId, height: i64, hash: Hash) {
        self.total_tips += 1;
        self.cached_tips.insert(hash.0, tip);

        let entry = self.chain_tips.entry(height).or_default();
        if entry.tip.is_none() && entry.other_tips.is_empty() {
            entry.tip = Some(tip);
            return;
        }
        entry.other_tips.push(tip);
    }

    fn remove_chain_tip(&mut self, tip: NodeId, height: i64, hash: Hash) {
        self.cached_tips.remove(&hash.0);

        let Some(entry) = self.chain_tips.get_mut(&height) else {
            return;
        };
        if entry.tip == Some(tip) {
            self.total_tips -= 1;
            entry.tip = None;
            if entry.other_tips.is_empty() {
                self.chain_tips.remove(&height);
                return;
            }
            entry.tip = Some(entry.other_tips.remove(0));
            return;
        }
        if let Some(i) = entry.other_tips.iter().position(|&n| n == tip) {
            self.total_tips -= 1;
            entry.other_tips.remove(i);
        }
    }

    /// Call the provided function with each chain tip known to the
    /// index (dcrd `forEachChainTip`); returning an error stops the
    /// iteration.
    pub fn for_each_chain_tip<E>(
        &self,
        mut f: impl FnMut(NodeId) -> Result<(), E>,
    ) -> Result<(), E> {
        for entry in self.chain_tips.values() {
            if let Some(tip) = entry.tip {
                f(tip)?;
            }
            for &tip in &entry.other_tips {
                f(tip)?;
            }
        }
        Ok(())
    }

    /// Call the provided function with each chain tip with a height
    /// greater than the filter node, using the recent tip cache when
    /// possible (dcrd `forEachChainTipAfterHeight`).
    pub fn for_each_chain_tip_after_height<E>(
        &self,
        store: &NodeStore,
        filter: NodeId,
        mut f: impl FnMut(NodeId) -> Result<(), E>,
    ) -> Result<(), E> {
        let filter_height = store.node(filter).height;
        if filter_height >= self.cached_tips_start - 1 {
            for &tip in self.cached_tips.values() {
                if store.node(tip).height <= filter_height {
                    continue;
                }
                f(tip)?;
            }
            return Ok(());
        }

        for (&tip_height, entry) in &self.chain_tips {
            if tip_height <= filter_height {
                continue;
            }
            if let Some(tip) = entry.tip {
                f(tip)?;
            }
            for &tip in &entry.other_tips {
                f(tip)?;
            }
        }
        Ok(())
    }

    /// The node identified by the provided hash, if any (dcrd
    /// `lookupNode`/`LookupNode`).
    pub fn lookup_node(&self, hash: &Hash) -> Option<NodeId> {
        self.by_hash.get(&hash.0).copied()
    }

    /// The status associated with the provided node (dcrd
    /// `NodeStatus`).
    pub fn node_status(&self, store: &NodeStore, node: NodeId) -> BlockStatus {
        store.node(node).status
    }

    /// Set the provided status flags (dcrd `SetStatusFlags`).
    pub fn set_status_flags(&mut self, store: &mut NodeStore, node: NodeId, flags: BlockStatus) {
        self.modified.insert(node);
        store.node_mut(node).status.0 |= flags.0;
    }

    /// Unset the provided status flags (dcrd `UnsetStatusFlags`).
    pub fn unset_status_flags(&mut self, store: &mut NodeStore, node: NodeId, flags: BlockStatus) {
        self.modified.insert(node);
        store.node_mut(node).status.0 &= !flags.0;
    }

    /// Add the node as a potential best chain candidate (dcrd
    /// `addBestChainCandidate`).
    pub fn add_best_chain_candidate(&mut self, node: NodeId) {
        self.best_chain_candidates.insert(node);
    }

    /// Remove the node from the best chain candidates (dcrd
    /// `removeBestChainCandidate`).
    pub fn remove_best_chain_candidate(&mut self, node: NodeId) {
        self.best_chain_candidates.remove(&node);
    }

    /// Remove old cached chain tips relative to the passed best node
    /// (dcrd `pruneCachedTips`, sans the wall-clock interval which the
    /// engine drives).
    pub fn prune_cached_tips(&mut self, store: &NodeStore, best_node: NodeId) {
        let height = store.node(best_node).height - CACHED_TIPS_PRUNE_DEPTH;
        if height <= 0 {
            return;
        }
        self.cached_tips
            .retain(|_, &mut n| store.node(n).height >= height);
        self.cached_tips_start = height;
    }

    /// Clear the tracked best invalid block so it can be
    /// repopulated (used by block reconsideration).
    pub(crate) fn reset_best_invalid(&mut self) {
        self.best_invalid = None;
    }

    /// Add a node to its parent's unlinked children when not already
    /// present (used by block reconsideration).
    pub(crate) fn add_unlinked_child(&mut self, parent: NodeId, child: NodeId) {
        let children = self.unlinked_children_of.entry(parent).or_default();
        if !children.contains(&child) {
            children.push(child);
        }
    }

    pub(crate) fn maybe_update_best_invalid(&mut self, store: &NodeStore, invalid_node: NodeId) {
        let better = match self.best_invalid {
            Some(best) => store.better_candidate(invalid_node, best),
            None => true,
        };
        if better {
            self.best_invalid = Some(invalid_node);
        }
    }

    pub(crate) fn maybe_update_best_header_for_tip(&mut self, store: &NodeStore, tip: NodeId) {
        let mut n = Some(tip);
        while let Some(cur) = n {
            let better = match self.best_header {
                Some(best) => store.better_candidate(cur, best),
                None => true,
            };
            if !better {
                return;
            }
            if !store.node(cur).status.known_invalid() {
                self.best_header = Some(cur);
                return;
            }
            n = store.node(cur).parent;
        }
    }

    /// The chain tips at the given height: the first tip followed by
    /// any others (the shape dcrd `TipGeneration` reads).
    pub fn tips_at_height(&self, height: i64) -> alloc::vec::Vec<NodeId> {
        let mut out = alloc::vec::Vec::new();
        if let Some(entry) = self.chain_tips.get(&height)
            && let Some(tip) = entry.tip
        {
            out.push(tip);
            out.extend(entry.other_tips.iter().copied());
        }
        out
    }

    /// Drain the set of nodes with unflushed changes (used by the
    /// block index flush).
    pub fn take_modified(&mut self) -> alloc::vec::Vec<NodeId> {
        let modified: alloc::vec::Vec<NodeId> = self.modified.iter().copied().collect();
        self.modified.clear();
        modified
    }

    /// The header with the most cumulative work not known to be
    /// invalid (dcrd `BestHeader`).
    pub fn best_header(&self) -> Option<NodeId> {
        self.best_header
    }

    /// The invalid block with the most cumulative work, if any.
    pub fn best_invalid(&self) -> Option<NodeId> {
        self.best_invalid
    }

    /// Mark the passed node as having failed validation and all of its
    /// descendants as having a failed ancestor (dcrd
    /// `MarkBlockFailedValidation`).
    pub fn mark_block_failed_validation(&mut self, store: &mut NodeStore, node: NodeId) {
        self.set_status_flags(store, node, BlockStatus::VALIDATE_FAILED);
        self.unset_status_flags(store, node, BlockStatus::VALIDATED);
        self.remove_best_chain_candidate(node);
        self.maybe_update_best_invalid(store, node);
        self.unlinked_children_of.remove(&node);

        // Mark all descendants of the failed block as having a failed
        // ancestor by walking the chain tips that descend from it.
        let mut tips: Vec<NodeId> = Vec::new();
        let _ = self.for_each_chain_tip_after_height::<()>(store, node, |tip| {
            tips.push(tip);
            Ok(())
        });
        for tip in tips {
            if !store.is_ancestor_of(node, tip) {
                continue;
            }
            self.maybe_update_best_invalid(store, tip);
            let mut n = tip;
            while n != node {
                if !store.node(n).status.known_invalid_ancestor() {
                    self.set_status_flags(store, n, BlockStatus::INVALID_ANCESTOR);
                    self.unset_status_flags(store, n, BlockStatus::VALIDATED);
                    self.remove_best_chain_candidate(n);
                    self.unlinked_children_of.remove(&n);
                }
                n = store.node(n).parent.expect("descendant has parent");
            }
        }

        // Find the new best header when the current one is now known
        // to be invalid: walk back to the first valid ancestor, then
        // check every tip not descending from the failed block.
        let best_invalidated = self
            .best_header
            .is_some_and(|b| store.node(b).status.known_invalid());
        if best_invalidated {
            let mut n = store.node(node).parent;
            while let Some(cur) = n {
                if !store.node(cur).status.known_invalid() {
                    break;
                }
                n = store.node(cur).parent;
            }
            self.best_header = n;
            let mut tips: Vec<NodeId> = Vec::new();
            let _ = self.for_each_chain_tip::<()>(|tip| {
                tips.push(tip);
                Ok(())
            });
            for tip in tips {
                if store.is_ancestor_of(node, tip) {
                    continue;
                }
                self.maybe_update_best_header_for_tip(store, tip);
            }
        }
    }

    /// Whether the node is eligible for validation: fully linked with
    /// its data available (dcrd `CanValidate`).
    pub fn can_validate(&self, store: &NodeStore, node: NodeId) -> bool {
        let n = store.node(node);
        n.is_fully_linked && n.status.have_data()
    }

    /// Remove all best chain candidates with less work than the given
    /// node (dcrd `RemoveLessWorkCandidates`); panics if that leaves
    /// no candidates, exactly like dcrd.
    pub fn remove_less_work_candidates(&mut self, store: &NodeStore, node: NodeId) {
        let work = store.node(node).work_sum;
        self.best_chain_candidates
            .retain(|&n| store.node(n).work_sum >= work);
        assert!(
            !self.best_chain_candidates.is_empty(),
            "best chain candidates list is empty after removing less work candidates"
        );
    }

    fn link_block_data(&mut self, store: &mut NodeStore, node: NodeId, tip: NodeId) -> Vec<NodeId> {
        let tip_work = store.node(tip).work_sum;
        let mut linked_nodes = vec![node];
        let mut node_index = 0;
        while node_index < linked_nodes.len() {
            let linked_node = linked_nodes[node_index];
            {
                let order_id = self.next_received_order_id;
                let n = store.node_mut(linked_node);
                n.is_fully_linked = true;
                n.received_order_id = order_id;
            }
            self.next_received_order_id += 1;

            if store.node(linked_node).work_sum >= tip_work {
                self.add_best_chain_candidate(linked_node);
            }

            if let Some(unlinked) = self.unlinked_children_of.remove(&linked_node) {
                linked_nodes.extend(unlinked);
            }
            node_index += 1;
        }
        linked_nodes
    }

    /// Account for the block data of the passed node now being
    /// available, linking any child blocks that were waiting on it and
    /// returning all newly linked nodes in order (dcrd
    /// `AcceptBlockData`).
    pub fn accept_block_data(
        &mut self,
        store: &mut NodeStore,
        node: NodeId,
        tip: NodeId,
    ) -> Vec<NodeId> {
        let parent = store.node(node).parent.expect("node has parent");
        if self.can_validate(store, parent) {
            return self.link_block_data(store, node, tip);
        }
        if !store.node(parent).status.known_invalid() {
            self.unlinked_children_of
                .entry(parent)
                .or_default()
                .push(node);
        }
        Vec::new()
    }

    /// The best chain candidate per the candidate comparison (dcrd
    /// `FindBestChainCandidate`).
    pub fn find_best_chain_candidate(&self, store: &NodeStore) -> Option<NodeId> {
        let mut best: Option<NodeId> = None;
        for &node in &self.best_chain_candidates {
            best = match best {
                Some(b) if !store.better_candidate(node, b) => Some(b),
                _ => Some(node),
            };
        }
        best
    }

    /// The number of chain tips currently tracked.
    pub fn total_tips(&self) -> u64 {
        self.total_tips
    }

    /// The number of best chain candidates currently tracked.
    pub fn num_best_chain_candidates(&self) -> usize {
        self.best_chain_candidates.len()
    }
}
