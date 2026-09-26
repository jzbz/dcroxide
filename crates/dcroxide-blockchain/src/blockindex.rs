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
//! reproduced, and neither are its mutex wrappers: the index lives in
//! the chain engine, which the daemon shares behind one lock.
//!
//! dcrd's set of modified nodes is ported
//! ([`BlockIndex::mark_modified`], [`BlockIndex::take_modified`]), and
//! the engine writes it to the database (`Chain::flush_block_index`,
//! dcrd's `flushBlockIndex` over `blockIndex.Flush`) after every
//! accepted header, connect and disconnect.  The engine takes the rows
//! out of the set before the write, where dcrd clears the set only once
//! the write succeeds; PARITY.md records that divergence.  The periodic
//! cached-tip prune is timed by the engine's connect path
//! (`Chain::maybe_prune_cached_tips`, on the monotonic clock dcrd's
//! `time.Since` reads); the prune itself is exposed directly.

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

/// A handle to a block node within a [`NodeStore`]: its arena index
/// plus one, so the parent and skip-list links (`Option<NodeId>`) take
/// four bytes each across the million-odd resident nodes.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, core::hash::Hash)]
pub struct NodeId(core::num::NonZeroU32);

impl NodeId {
    /// The arena index the handle refers to.
    fn index(self) -> usize {
        (self.0.get() - 1) as usize
    }
}

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
    /// on demand).  Boxed like dcrd's pointer: only the few hundred
    /// most recent nodes hold one, so the rest pay for a pointer
    /// rather than the inline node.
    pub stake_node: Option<alloc::boxed::Box<dcroxide_stake::ticketnode::Node>>,
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

/// Decode compact difficulty bits into an unsigned 256-bit integer,
/// with flags for a set sign bit and for a value too large for 256
/// bits (dcrd `primitives.DiffBitsToUint256`,
/// `internal/staging/primitives/pow.go:45-88`).
fn diff_bits_to_uint256(bits: u32) -> (Uint256, bool, bool) {
    // Extract the mantissa, sign bit, and exponent.
    let mantissa = bits & 0x007f_ffff;
    let is_sign_bit_set = bits & 0x0080_0000 != 0;
    let exponent = bits >> 24;

    // Nothing to do when the mantissa is zero as any multiple of it
    // will necessarily also be 0 and therefore it can never be negative
    // or overflow.
    if mantissa == 0 {
        return (Uint256::ZERO, false, false);
    }

    // N = mantissa * 256^(exponent-3).
    if exponent <= 3 {
        let n = Uint256::from_u64(u64::from(mantissa >> (8 * (3 - exponent))));
        return (n, is_sign_bit_set, false);
    }

    // Any encoded exponent of 35 or more overflows, as do the larger
    // mantissas at exponents 33 and 34.
    let overflows = exponent >= 35
        || (exponent >= 34 && mantissa > 0xff)
        || (exponent >= 33 && mantissa > 0xffff);
    if overflows {
        return (Uint256::ZERO, is_sign_bit_set, true);
    }
    let mut n = Uint256::from_u64(u64::from(mantissa));
    n.lsh(8 * (exponent - 3));
    (n, is_sign_bit_set, false)
}

/// The proof of work as a 256-bit integer for the given difficulty
/// bits, zero for a negative, overflowing or zero target (dcrd
/// `primitives.CalcWork`, `internal/staging/primitives/pow.go:162-196`,
/// which `initBlockNode` uses for the work sum).
///
/// dcrd computes 2^256 / (diff+1) on fixed-precision integers as
/// (^diff / (diff+1)) + 1, which cannot divide by zero because a target
/// of 2^256-1 cannot be encoded in the difficulty bits.  The result
/// equals the standalone big-integer `calc_work` for every input; the
/// fixed-width form allocates nothing, and it runs for every node the
/// index loads or creates.
fn calc_work_uint256(bits: u32) -> Uint256 {
    let (mut diff, is_negative, overflows) = diff_bits_to_uint256(bits);
    if is_negative || overflows || diff.is_zero() {
        return Uint256::ZERO;
    }
    let mut divisor = Uint256::from_u64(1);
    divisor.add(&diff);
    *diff.not().div(&divisor).add_u64(1)
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

/// The threshold-state cache rows: per deployment vote id (the outer
/// key, so a lookup borrows the id instead of allocating a key), the
/// deployment version and the interval-boundary block hash mapping to
/// the computed state.
type ThresholdStateCacheMap = alloc::collections::BTreeMap<
    alloc::string::String,
    alloc::collections::BTreeMap<(u32, [u8; 32]), crate::thresholdstate::ThresholdStateTuple>,
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
    /// deployment's vote id and then its version and the
    /// interval-boundary block hash.
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
    /// dcrd's `cachedBlake3WorkDiffAnchor`: the DCP0011 anchor the
    /// contextual difficulty calculation last found.  Unlike the
    /// caches above it holds one node, which views only honour when
    /// it is an ancestor of the node they ask about, exactly as dcrd
    /// checks `IsAncestorOf` on every load.
    pub(crate) blake3_work_diff_anchor: core::cell::Cell<Option<NodeId>>,
    /// dcrd's `cachedBlake3WorkDiffCandidateAnchor`: the candidate
    /// anchor the positional difficulty check last matched.
    pub(crate) blake3_work_diff_candidate_anchor: core::cell::Cell<Option<NodeId>>,
    /// The node a branch view last served, with that branch's tip.  It
    /// is not a dcrd cache: dcrd's walks step `node.parent`, and a
    /// height-indexed view that resumes from this node does the same
    /// (one hop per step) instead of descending the skip list from the
    /// tip at every step.  Node links never change once a node exists,
    /// so the node stays an ancestor of that tip for good.
    pub(crate) branch_cursor: core::cell::Cell<Option<(NodeId, NodeId)>>,
}

impl NodeStore {
    /// A new empty node store.
    pub fn new() -> NodeStore {
        NodeStore::default()
    }

    /// The node for the given id.
    pub fn node(&self, id: NodeId) -> &BlockNode {
        &self.nodes[id.index()]
    }

    /// Mutable access to the node for the given id.
    pub fn node_mut(&mut self, id: NodeId) -> &mut BlockNode {
        &mut self.nodes[id.index()]
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
        let id = u32::try_from(self.nodes.len() + 1)
            .ok()
            .and_then(core::num::NonZeroU32::new)
            .map(NodeId)
            .expect("the block index holds fewer than u32::MAX nodes");
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

    /// Add the provided node to the index and mark it for the next
    /// flush (dcrd `AddNode`).  Duplicate entries are not checked.
    pub fn add_node(&mut self, store: &NodeStore, node: NodeId) {
        self.add_node_unmarked(store, node);
        self.mark_modified(node);
    }

    /// Add the provided node to the index without marking it (dcrd
    /// `addNode`, the inner form its exported sibling wraps).
    ///
    /// Loading the index from storage goes through here: those rows came
    /// off disk unchanged, so marking them would make the first flush
    /// after every restart rewrite the entire index byte for byte.
    pub fn add_node_unmarked(&mut self, store: &NodeStore, node: NodeId) {
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
        self.add_node_unmarked(store, node);

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
    /// (dcrd `pruneCachedTips`, sans the time stamp and the interval,
    /// which the engine keeps and `Chain::maybe_prune_cached_tips`
    /// checks).
    pub fn prune_cached_tips(&mut self, store: &NodeStore, best_node: NodeId) {
        let height = store.node(best_node).height - CACHED_TIPS_PRUNE_DEPTH;
        if height <= 0 {
            return;
        }
        self.cached_tips
            .retain(|_, &mut n| store.node(n).height >= height);
        self.cached_tips_start = height;
    }

    /// The height the cached chain tips start at, for the engine's
    /// tests of the timed prune.
    #[cfg(test)]
    pub(crate) fn cached_tips_start(&self) -> i64 {
        self.cached_tips_start
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

    /// Mark a node for the next flush (dcrd's `bi.modified[node] = struct{}{}`).
    pub fn mark_modified(&mut self, node: NodeId) {
        self.modified.insert(node);
    }

    /// How many nodes carry unflushed changes.
    ///
    /// The engine's block index flush reads this to skip the database
    /// write entirely when nothing is modified, as dcrd's
    /// `blockIndex.Flush` returns early on an empty set
    /// (`blockindex.go:1409-1414`).
    pub fn modified_len(&self) -> usize {
        self.modified.len()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The per-node footprint stays close to dcrd's `blockNode`: the
    /// stake node is a pointer rather than ~180 inline bytes, and the
    /// two node links are four bytes each.  A mainnet index keeps about
    /// a million of these resident.
    #[test]
    fn block_node_layout_stays_compact() {
        assert_eq!(core::mem::size_of::<Option<NodeId>>(), 4);
        assert_eq!(
            core::mem::size_of::<Option<alloc::boxed::Box<dcroxide_stake::ticketnode::Node>>>(),
            core::mem::size_of::<usize>()
        );
        assert!(
            core::mem::size_of::<BlockNode>() <= 360,
            "BlockNode grew to {} bytes",
            core::mem::size_of::<BlockNode>()
        );
    }

    /// Handles still address the arena in insertion order.
    #[test]
    fn node_ids_address_the_arena() {
        let mut store = NodeStore::new();
        let mut header = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header").0;
        let genesis = store.new_node(&header, None);
        header.height = 1;
        header.nonce = 1;
        let child = store.new_node(&header, Some(genesis));
        assert!(genesis < child);
        assert_eq!(store.node(genesis).height, 0);
        assert_eq!(store.node(child).height, 1);
        assert_eq!(store.node(child).parent, Some(genesis));
        assert_eq!(store.ancestor(child, 0), Some(genesis));
    }

    /// The standalone big-integer work, as the 256-bit value the index
    /// computed before the fixed-precision port.
    fn big_work(bits: u32) -> Uint256 {
        let (_, bytes) = dcroxide_standalone::calc_work(bits).to_bytes_be();
        let mut be = [0u8; 32];
        be[32 - bytes.len()..].copy_from_slice(&bytes);
        Uint256::from_be_bytes(&be)
    }

    /// The fixed-precision work matches dcrd's `primitives.TestCalcWork`
    /// table and the big-integer `calc_work` (itself pinned by dcrd's
    /// standalone vectors and the oracle) over every exponent and sign
    /// with boundary and random mantissas (review finding C2-p#4).
    #[test]
    fn fixed_precision_work_matches_dcrd_and_the_big_integer_form() {
        // dcrd internal/staging/primitives/pow_test.go TestCalcWork.
        for (name, bits, want) in [
            (
                "mainnet block 1",
                0x1b01ffffu32,
                "0000000000000000000000000000000000000000000000000000800040002000",
            ),
            (
                "mainnet block 288",
                0x1b01330e,
                "0000000000000000000000000000000000000000000000000000d56f2dcbe105",
            ),
            (
                "higher diff (exponent 24)",
                0x185fb28a,
                "000000000000000000000000000000000000000000000002acd33ddd458512da",
            ),
            (
                "zero",
                0,
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "max uint256",
                0x2100ffff,
                "0000000000000000000000000000000000000000000000000000000000000001",
            ),
            (
                "negative target difficulty",
                0x1810000,
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
        ] {
            let want: [u8; 32] = dcroxide_testutil::unhex(want).try_into().expect("32 bytes");
            assert_eq!(
                calc_work_uint256(bits),
                Uint256::from_be_bytes(&want),
                "{name}"
            );
        }

        let mut rng = dcroxide_testutil::SplitMix64::from_entropy("calc work uint256");
        let mantissas = [0u32, 1, 0xff, 0x100, 0xffff, 0x1_0000, 0x7f_ffff];
        for exponent in 0u32..=255 {
            for sign in [0u32, 0x0080_0000] {
                for mantissa in mantissas
                    .into_iter()
                    .chain((0..8).map(|_| rng.below(0x80_0000) as u32))
                {
                    let bits = exponent << 24 | sign | mantissa;
                    assert_eq!(calc_work_uint256(bits), big_work(bits), "bits {bits:#010x}");
                }
            }
        }
        for _ in 0..100_000 {
            let bits = rng.next_u64() as u32;
            assert_eq!(calc_work_uint256(bits), big_work(bits), "bits {bits:#010x}");
        }
    }
}
