// SPDX-License-Identifier: ISC

//! Headers-first chain processing from dcrd's
//! `internal/blockchain/process.go`: accepting block headers to the
//! block index with full context-free and positional validation, the
//! known-invalid short circuits, and the assumed-valid and old fork
//! rejection checkpoint tracking.  The full block processing path
//! (`ProcessBlock` and the reorganization machinery it drives)
//! arrives with the chain engine.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_wire::BlockHeader;

use dcroxide_gcs::FilterV2;
use dcroxide_stake::ticketdb::UndoTicketData;
use dcroxide_stake::ticketnode::{Node as StakeNode, StakeNodeParams};
use dcroxide_uint256::Uint256;
use dcroxide_wire::{MsgBlock, MsgTx, OutPoint};

use crate::RuleError;
use crate::blockindex::{BlockIndex, BlockStatus, NodeId, NodeStore};
use crate::chainio::SpentTxOut;
use crate::chainview_nodes::{NodeBranchView, NodeChainView};
use crate::ruleerror::RuleErrorKind;
use crate::utxoentry::UtxoEntry;
use crate::utxoview::{OutPointKey, UtxoView, count_spent_outputs};
use crate::validate::{
    ChainSubsidyParams, ForkRejection, check_block_header_positional, check_block_header_sanity,
};

fn rule_error(kind: RuleErrorKind, description: impl Into<String>) -> RuleError {
    RuleError {
        kind,
        description: description.into(),
    }
}

/// The growing chain state: the block tree arena and index together
/// with the header-processing configuration (the subset of dcrd's
/// `BlockChain` struct the headers-first path reads).  dcrd's
/// database flushes, locks, and notification plumbing are not
/// reproduced; index persistence arrives with the engine wiring.
pub struct Chain {
    /// The block tree arena.
    pub store: NodeStore,
    /// The block index over the arena.
    pub index: BlockIndex,
    /// The assumed valid block hash from configuration (dcrd
    /// `config.AssumeValid`); the zero hash disables it.
    pub assume_valid: Hash,
    /// The block node for the assumed valid block once its header is
    /// known.
    pub assume_valid_node: Option<NodeId>,
    /// The block to treat as the checkpoint for rejecting old forks,
    /// once discovered.
    pub reject_forks_checkpoint: Option<NodeId>,
    /// Whether old fork rejection semantics are disabled.
    pub allow_old_forks: bool,
    /// The expected number of blocks in two weeks, cached from the
    /// target block time.
    pub expected_blocks_in_two_weeks: i64,

    /// The view of the current best chain.
    pub best_chain: NodeChainView,
    /// Full block data by block hash: the in-memory stand-in for
    /// dcrd's database block storage and recent block cache until the
    /// persistence wiring lands.
    pub blocks: BTreeMap<[u8; 32], MsgBlock>,
    /// Per-height ticket undo data for main chain blocks: the
    /// in-memory stand-in for dcrd's ticket database undo rows
    /// (written by `WriteConnectedBestNode`).
    pub stake_undo: BTreeMap<i64, Vec<UndoTicketData>>,
    /// Per-height maturing ticket hashes for main chain blocks: the
    /// in-memory stand-in for dcrd's ticket database new tickets
    /// rows.
    pub stake_new_tickets: BTreeMap<i64, Vec<dcroxide_chainhash::Hash>>,

    /// The flushed UTXO set by outpoint: the in-memory stand-in for
    /// dcrd's utxo backend until the persistence wiring lands.
    pub utxo_backend: BTreeMap<OutPointKey, UtxoEntry>,
    /// The UTXO cache overlay with dcrd's exact semantics: fresh
    /// entries have never been flushed, spent non-fresh entries are
    /// retained as tombstones until the next flush, and an explicit
    /// `None` marks an output known to be spent whose backing entry
    /// was never flushed.  These distinctions are observable through
    /// the entry fields that survive reorganizations.
    pub utxo_cache: BTreeMap<OutPointKey, Option<UtxoEntry>>,
    /// The transaction spend journal by block hash, in dcrd's
    /// serialized journal format: the in-memory stand-in for dcrd's
    /// spend journal bucket.  The serialization is deliberately round
    /// tripped because dcrd reconstructs the spent entries' heights
    /// and indexes from the spending inputs' fraud proofs on load.
    pub spend_journal: BTreeMap<[u8; 32], Vec<u8>>,
    /// The version 2 GCS filters by block hash; like dcrd, filters
    /// are intentionally not removed on disconnect.
    pub filters: BTreeMap<[u8; 32], FilterV2>,
    /// The header commitment merkle tree leaves by block hash.
    pub header_commitments: BTreeMap<[u8; 32], Vec<Hash>>,
    /// The best chain state snapshot.
    pub state_snapshot: BestState,
    /// Whether several validation checks are skipped for bulk imports
    /// (dcrd `bulkImportMode`).
    pub bulk_import_mode: bool,
    /// Whether the chain has latched to believing it is current.
    pub is_current_latch: bool,
    /// The minimum known cumulative chain work from the parameters.
    pub min_known_work: Option<Uint256>,
}

/// Information about the current best chain block and related state
/// (dcrd `BestState`).
#[derive(Clone, Debug)]
pub struct BestState {
    /// The hash of the block.
    pub hash: Hash,
    /// The previous block hash.
    pub prev_hash: Hash,
    /// The height of the block.
    pub height: i64,
    /// The difficulty bits of the block.
    pub bits: u32,
    /// The next ticket pool size.
    pub next_pool_size: u32,
    /// The next stake difficulty.
    pub next_stake_diff: i64,
    /// The size of the block.
    pub block_size: u64,
    /// The number of transactions in the block.
    pub num_txns: u64,
    /// The total number of transactions in the chain.
    pub total_txns: u64,
    /// The past median time as unix seconds.
    pub median_time: i64,
    /// The total subsidy for the chain.
    pub total_subsidy: i64,
    /// The tickets set to expire next block.
    pub next_expiring_tickets: Vec<Hash>,
    /// The eligible tickets to vote on the next block.
    pub next_winning_tickets: Vec<Hash>,
    /// The missed tickets set to be revoked.
    pub missed_tickets: Vec<Hash>,
    /// The lottery state for the next block.
    pub next_final_state: [u8; 6],
}

/// The stake node parameters for a network.
pub fn stake_node_params(params: &Params) -> StakeNodeParams {
    StakeNodeParams {
        votes_per_block: params.tickets_per_block,
        stake_validation_begin_height: params.stake_validation_height,
        stake_enable_height: params.stake_enabled_height,
        ticket_expiry_blocks: params.ticket_expiry,
    }
}

impl Chain {
    /// Create the chain state with the genesis block node in the
    /// index, mirroring the relevant configuration derivation in dcrd
    /// `New` (the fork rejection semantics are disabled when
    /// explicitly requested or the network has no hard-coded assumed
    /// valid hash).
    pub fn new(params: &Params, config_assume_valid: Hash, config_allow_old_forks: bool) -> Chain {
        const TIME_IN_TWO_WEEKS_SECS: i64 = 14 * 24 * 60 * 60;
        let expected_blocks_in_two_weeks =
            TIME_IN_TWO_WEEKS_SECS / params.target_time_per_block_secs;
        let allow_old_forks = config_allow_old_forks || params.assume_valid == Hash::ZERO;

        let mut store = NodeStore::new();
        let mut index = BlockIndex::new();
        let genesis = store.new_node(&params.genesis_block.header, None);
        store.node_mut(genesis).status =
            BlockStatus(BlockStatus::DATA_STORED.0 | BlockStatus::VALIDATED.0);
        store.node_mut(genesis).is_fully_linked = true;
        store.node_mut(genesis).stake_node = Some(StakeNode::genesis(stake_node_params(params)));
        index.add_node(&store, genesis);
        let best_chain = NodeChainView::new(&store, Some(genesis));

        let mut blocks = BTreeMap::new();
        blocks.insert(
            params.genesis_block.header.block_hash().0,
            params.genesis_block.clone(),
        );

        // The initial best state uses the genesis block's own values
        // (dcrd `createChainState`).
        let genesis_block = &params.genesis_block;
        let num_txns = genesis_block.transactions.len() as u64;
        let state_snapshot = BestState {
            hash: genesis_block.header.block_hash(),
            prev_hash: Hash::ZERO,
            height: 0,
            bits: genesis_block.header.bits,
            next_pool_size: 0,
            next_stake_diff: params.minimum_stake_diff,
            block_size: genesis_block.serialize().len() as u64,
            num_txns,
            total_txns: num_txns,
            median_time: i64::from(genesis_block.header.timestamp),
            total_subsidy: 0,
            next_expiring_tickets: Vec::new(),
            next_winning_tickets: Vec::new(),
            missed_tickets: Vec::new(),
            next_final_state: [0u8; 6],
        };

        Chain {
            store,
            index,
            assume_valid: config_assume_valid,
            assume_valid_node: None,
            reject_forks_checkpoint: None,
            allow_old_forks,
            expected_blocks_in_two_weeks,
            best_chain,
            blocks,
            stake_undo: BTreeMap::new(),
            stake_new_tickets: BTreeMap::new(),
            utxo_backend: BTreeMap::new(),
            utxo_cache: BTreeMap::new(),
            spend_journal: BTreeMap::new(),
            filters: BTreeMap::new(),
            header_commitments: BTreeMap::new(),
            state_snapshot,
            bulk_import_mode: false,
            is_current_latch: false,
            min_known_work: params.min_known_chain_work,
        }
    }

    /// Apply the view's committed changes to the UTXO cache with dcrd
    /// `UtxoCache.Commit` semantics: spent view entries go through
    /// the spend bookkeeping and everything else is added or updated.
    pub fn commit_view(&mut self, view: &mut UtxoView) {
        for (key, entry) in view.commit() {
            if entry.is_spent() {
                Self::cache_spend_entry(&self.utxo_backend, &mut self.utxo_cache, key);
            } else {
                Self::cache_add_entry(&mut self.utxo_cache, key, entry);
            }
        }
    }

    /// Add or update an unspent entry in the cache (dcrd
    /// `UtxoCache.addEntry`): new-to-cache entries are marked fresh
    /// and updates preserve the existing freshness.
    fn cache_add_entry(
        cache: &mut BTreeMap<OutPointKey, Option<UtxoEntry>>,
        key: OutPointKey,
        mut entry: UtxoEntry,
    ) {
        entry.set_state_bits(entry.state_bits() | crate::utxoentry::UTXO_STATE_MODIFIED);
        match cache.get(&key) {
            Some(Some(existing)) => {
                if existing.is_fresh() {
                    entry.set_state_bits(entry.state_bits() | crate::utxoentry::UTXO_STATE_FRESH);
                }
            }
            // Both a missing entry and an explicit spent marker mean
            // the backend has never seen this output.
            _ => {
                entry.set_state_bits(entry.state_bits() | crate::utxoentry::UTXO_STATE_FRESH);
            }
        }
        cache.insert(key, Some(entry));
    }

    /// Spend an output in the cache (dcrd `UtxoCache.spendEntry`):
    /// fresh entries are replaced with an explicit spent marker since
    /// the backend never knew about them, other cached entries become
    /// spent tombstones, and cache misses pull the backend entry in
    /// as a tombstone so the next flush removes it.
    fn cache_spend_entry(
        backend: &BTreeMap<OutPointKey, UtxoEntry>,
        cache: &mut BTreeMap<OutPointKey, Option<UtxoEntry>>,
        key: OutPointKey,
    ) {
        match cache.get_mut(&key) {
            Some(None) => {}
            Some(Some(entry)) => {
                assert!(!entry.is_spent(), "attempt to double spend in view commit");
                if entry.is_fresh() {
                    cache.insert(key, None);
                } else {
                    entry.set_state_bits(
                        entry.state_bits()
                            | crate::utxoentry::UTXO_STATE_SPENT
                            | crate::utxoentry::UTXO_STATE_MODIFIED,
                    );
                }
            }
            None => {
                if let Some(backend_entry) = backend.get(&key) {
                    let mut entry = backend_entry.clone();
                    entry.set_state_bits(
                        entry.state_bits()
                            | crate::utxoentry::UTXO_STATE_SPENT
                            | crate::utxoentry::UTXO_STATE_MODIFIED,
                    );
                    cache.insert(key, Some(entry));
                }
            }
        }
    }

    /// Flush the cache to the backend (dcrd `UtxoCache.MaybeFlush`
    /// when forced): spent tombstones delete their backend rows,
    /// unspent entries are written with the cache state cleared, and
    /// the cache empties.
    fn flush_utxo_cache(&mut self) {
        let cache = core::mem::take(&mut self.utxo_cache);
        for (key, entry) in cache {
            match entry {
                None => {}
                Some(entry) if entry.is_spent() => {
                    self.utxo_backend.remove(&key);
                }
                Some(mut entry) => {
                    entry.set_state_bits(0);
                    self.utxo_backend.insert(key, entry);
                }
            }
        }
    }

    /// Fetch an entry through the cache and backend (dcrd
    /// `UtxoCache.FetchEntry` semantics; spent tombstones are
    /// returned like dcrd's cache hands them to views, which is what
    /// preserves original entry fields across disconnects).
    pub fn fetch_utxo_entry(&self, op: &OutPoint) -> Option<UtxoEntry> {
        Self::cache_fetch(&self.utxo_backend, &self.utxo_cache, op)
    }

    fn cache_fetch(
        backend: &BTreeMap<OutPointKey, UtxoEntry>,
        cache: &BTreeMap<OutPointKey, Option<UtxoEntry>>,
        op: &OutPoint,
    ) -> Option<UtxoEntry> {
        let key = (op.hash.0, op.index, op.tree);
        match cache.get(&key) {
            Some(entry) => entry.clone(),
            None => backend.get(&key).cloned(),
        }
    }

    /// The spent txouts for the block from the spend journal,
    /// reconstructing the fraud proof fields from the block's
    /// spending inputs (dcrd `dbFetchSpendJournalEntry`).
    pub fn fetch_spend_journal(
        &self,
        block: &MsgBlock,
        is_treasury_enabled: bool,
    ) -> Vec<SpentTxOut> {
        let serialized = self
            .spend_journal
            .get(&block.header.block_hash().0)
            .cloned()
            .unwrap_or_default();

        let mut block_txns: Vec<MsgTx> = Vec::new();
        if !block.stransactions.is_empty() && is_treasury_enabled {
            // Skip the treasurybase and remove treasury spends.
            for stx in &block.stransactions[1..] {
                if dcroxide_stake::is_tspend(stx) {
                    continue;
                }
                block_txns.push(stx.clone());
            }
        } else {
            block_txns.extend(block.stransactions.iter().cloned());
        }
        block_txns.extend(block.transactions.iter().skip(1).cloned());

        crate::chainio::deserialize_spend_journal_entry(&serialized, &block_txns)
            .expect("valid spend journal serialization")
    }

    /// The full block data for a node.  The data must have been
    /// stored previously; callers only request blocks whose data
    /// availability is tracked by the block index (dcrd
    /// `fetchBlockByNode` over its database and recent block cache).
    pub fn block_by_node(&self, node: NodeId) -> &MsgBlock {
        self.blocks
            .get(&self.store.node(node).hash.0)
            .expect("block data for node is stored")
    }

    /// Load the list of newly maturing tickets for a node by looking
    /// back to the block containing the tickets to mature (dcrd
    /// `maybeFetchNewTickets`).  `None` means never looked up while
    /// an empty list means no tickets mature at this node.
    pub fn maybe_fetch_new_tickets(&mut self, node: NodeId, params: &Params) {
        if self.store.node(node).new_tickets.is_some() {
            return;
        }

        // No tickets in the live ticket pool are possible before
        // stake enabled height.
        if self.store.node(node).height < params.stake_enabled_height {
            self.store.node_mut(node).new_tickets = Some(Vec::new());
            return;
        }

        let mature_node = self
            .store
            .relative_ancestor(node, i64::from(params.ticket_maturity))
            .expect("ancestor at the ticket maturity distance");
        let mature_block = self.block_by_node(mature_node);
        let tickets: Vec<dcroxide_chainhash::Hash> = mature_block
            .stransactions
            .iter()
            .filter(|stx| dcroxide_stake::is_sstx(stx))
            .map(|stx| stx.tx_hash())
            .collect();
        self.store.node_mut(node).new_tickets = Some(tickets);
    }

    /// Load and populate the prunable ticket information in the node
    /// if needed (dcrd `maybeFetchTicketInfo`).
    pub fn maybe_fetch_ticket_info(&mut self, node: NodeId, params: &Params) {
        self.maybe_fetch_new_tickets(node, params);

        if !self.store.node(node).ticket_info_populated {
            let block = self
                .blocks
                .get(&self.store.node(node).hash.0)
                .expect("block data for node is stored");
            let info = dcroxide_stake::find_spent_tickets_in_block(block);
            let votes = info.votes.iter().map(|v| (v.version, v.bits)).collect();
            self.store
                .populate_ticket_info(node, info.voted_tickets, info.revoked_tickets, votes);
        }
    }

    /// Record the in-memory ticket database rows for a main chain
    /// node whose stake node is loaded: the undo data and maturing
    /// tickets by height (the row content of dcrd
    /// `stake.WriteConnectedBestNode`; the database-backed rows
    /// arrive with the persistence wiring).
    pub fn write_stake_db_rows(&mut self, node: NodeId) {
        let n = self.store.node(node);
        let stake_node = n.stake_node.as_ref().expect("stake node loaded");
        self.stake_undo
            .insert(n.height, stake_node.undo_data().to_vec());
        self.stake_new_tickets
            .insert(n.height, stake_node.new_tickets().to_vec());
    }

    /// The stake node for the requested node, creating it if needed:
    /// a cached node is returned directly, a node whose parent stake
    /// node is loaded is connected forward, and anything else is
    /// reached by disconnecting from the current best chain tip back
    /// to the fork point (regenerating pruned nodes from the ticket
    /// undo rows) and replaying any side chain blocks up to the
    /// requested node (dcrd `fetchStakeNode`).
    pub fn fetch_stake_node(
        &mut self,
        node: NodeId,
        params: &Params,
    ) -> Result<StakeNode, dcroxide_stake::RuleError> {
        // Return the cached immutable stake node when it is already
        // loaded.
        if let Some(stake_node) = &self.store.node(node).stake_node {
            return Ok(stake_node.clone());
        }

        // Create the requested stake node from the parent stake node
        // when it is already loaded as an optimization.
        if let Some(parent) = self.store.node(node).parent {
            if self.store.node(parent).stake_node.is_some() {
                self.maybe_fetch_ticket_info(node, params);
                let n = self.store.node(node);
                let voted = n.tickets_voted.clone();
                let revoked = n.tickets_revoked.clone();
                let new_tickets = n.new_tickets.clone().expect("new tickets loaded");
                let iv = self.store.lottery_iv(node);
                let parent_stake_node =
                    self.store.node(parent).stake_node.as_ref().expect("loaded");
                let stake_node = parent_stake_node.connect(iv, &voted, &revoked, &new_tickets)?;
                self.store.node_mut(node).stake_node = Some(stake_node.clone());
                return Ok(stake_node);
            }
        }

        // Undo the effects from the current tip back to, and
        // including, the fork point, regenerating and populating any
        // stake nodes along the way that are not already loaded.
        let tip = self.best_chain.tip().expect("best chain tip");
        let fork = self.best_chain.find_fork(&self.store, node);
        let mut cur = Some(tip);
        while let Some(n) = cur {
            if Some(n) == fork {
                break;
            }
            let prev = self.store.node(n).parent;
            let Some(prev_id) = prev else {
                break;
            };
            if self.store.node(prev_id).stake_node.is_none() {
                // Generate the previous stake node by starting with
                // the child stake node and undoing the modifications
                // caused by the stake details in the previous block,
                // restoring the previous node's own bookkeeping from
                // the ticket database rows like dcrd does.
                let prev_height = self.store.node(prev_id).height;
                let utds = self
                    .stake_undo
                    .get(&prev_height)
                    .expect("ticket undo row for main chain height")
                    .clone();
                let tickets = self
                    .stake_new_tickets
                    .get(&prev_height)
                    .expect("ticket row for main chain height")
                    .clone();
                let prev_iv = self.store.lottery_iv(prev_id);
                let stake_node = self
                    .store
                    .node(n)
                    .stake_node
                    .as_ref()
                    .expect("stake node along the walk is loaded")
                    .disconnect(prev_iv, &utds, &tickets)?;
                self.store.node_mut(prev_id).stake_node = Some(stake_node);
            }
            cur = prev;
        }

        // Nothing more to do if the requested node is the fork point
        // itself.
        if fork == Some(node) {
            return Ok(self
                .store
                .node(node)
                .stake_node
                .clone()
                .expect("fork stake node loaded"));
        }

        // The requested node is on a side chain, so replay the
        // effects of the blocks up to the requested node.
        let mut attach_nodes = Vec::new();
        let mut n = Some(node);
        while let Some(id) = n {
            if Some(id) == fork {
                break;
            }
            attach_nodes.push(id);
            n = self.store.node(id).parent;
        }
        for &id in attach_nodes.iter().rev() {
            if self.store.node(id).stake_node.is_some() {
                continue;
            }
            self.maybe_fetch_ticket_info(id, params);
            let nd = self.store.node(id);
            let voted = nd.tickets_voted.clone();
            let revoked = nd.tickets_revoked.clone();
            let new_tickets = nd.new_tickets.clone().expect("new tickets loaded");
            let parent = nd.parent.expect("side chain node has a parent");
            let iv = self.store.lottery_iv(id);
            let parent_stake_node = self
                .store
                .node(parent)
                .stake_node
                .as_ref()
                .expect("parent stake node loaded along the attach path");
            let stake_node = parent_stake_node.connect(iv, &voted, &revoked, &new_tickets)?;
            self.store.node_mut(id).stake_node = Some(stake_node);
        }

        Ok(self
            .store
            .node(node)
            .stake_node
            .clone()
            .expect("requested stake node loaded"))
    }

    /// The error for a block already known to be invalid, either
    /// directly or through an invalid ancestor (dcrd
    /// `checkKnownInvalidBlock`).
    pub fn check_known_invalid_block(&self, node: NodeId) -> Result<(), RuleError> {
        let status = self.index.node_status(&self.store, node);
        if status.known_validate_failed() {
            return Err(rule_error(
                RuleErrorKind::KnownInvalidBlock,
                format!(
                    "block {} is known to be invalid",
                    self.store.node(node).hash
                ),
            ));
        }
        if status.known_invalid_ancestor() {
            return Err(rule_error(
                RuleErrorKind::InvalidAncestorBlock,
                format!(
                    "block {} is known to be part of an invalid branch",
                    self.store.node(node).hash
                ),
            ));
        }
        Ok(())
    }

    /// Attempt to discover and set the old fork rejection checkpoint
    /// node: two weeks worth of blocks behind the hard-coded assumed
    /// valid block once its header is known (dcrd
    /// `maybeSetForkRejectionCheckpoint`).
    pub fn maybe_set_fork_rejection_checkpoint(&mut self, params: &Params) {
        if self.reject_forks_checkpoint.is_some() || self.allow_old_forks {
            return;
        }
        let Some(hard_coded) = self.index.lookup_node(&params.assume_valid) else {
            return;
        };
        let mut checkpoint_height =
            self.store.node(hard_coded).height - self.expected_blocks_in_two_weeks;
        if checkpoint_height < 0 {
            checkpoint_height = 0;
        }
        self.reject_forks_checkpoint = self.store.ancestor(hard_coded, checkpoint_height);
    }

    /// Update the assumed valid node when the provided node matches
    /// the configured assumed valid hash (dcrd
    /// `maybeUpdateAssumeValid`).
    pub fn maybe_update_assume_valid(&mut self, node: NodeId) {
        if self.assume_valid == Hash::ZERO || self.assume_valid != self.store.node(node).hash {
            return;
        }
        self.assume_valid_node = Some(node);
    }

    /// Whether the node is both an ancestor of the assumed valid node
    /// and an ancestor of the best header, with the assumed valid
    /// node clamped back to at least two weeks worth of blocks behind
    /// the best header (dcrd `isAssumeValidAncestor`).
    pub fn is_assume_valid_ancestor(&self, node: NodeId) -> bool {
        let Some(mut assume_valid_node) = self.assume_valid_node else {
            return false;
        };
        let Some(best_header) = self.index.best_header() else {
            return false;
        };
        if !self.store.is_ancestor_of(node, best_header) {
            return false;
        }
        let best_height = self.store.node(best_header).height;
        if best_height < self.expected_blocks_in_two_weeks {
            return false;
        }
        let clamp_to_height = best_height - self.expected_blocks_in_two_weeks;
        if self.store.node(assume_valid_node).height > clamp_to_height {
            assume_valid_node = self
                .store
                .ancestor(assume_valid_node, clamp_to_height)
                .expect("clamp height is within the branch");
        }
        self.store.is_ancestor_of(node, assume_valid_node)
    }

    /// Potentially accept the header to the block index and return
    /// its block node (dcrd `maybeAcceptBlockHeader`).  Performs the
    /// context-free header sanity checks (unless the caller already
    /// ran them as part of full block sanity) and the positional
    /// checks, rejects orphan headers and headers on known invalid
    /// branches, and updates the assumed valid and fork rejection
    /// checkpoint tracking.
    pub fn maybe_accept_block_header(
        &mut self,
        header: &BlockHeader,
        check_header_sanity: bool,
        adjusted_time_unix: i64,
        params: &Params,
    ) -> Result<NodeId, RuleError> {
        // Avoid validating the header again if its validation status
        // is already known.
        let hash = header.block_hash();
        if let Some(node) = self.index.lookup_node(&hash) {
            self.check_known_invalid_block(node)?;
            return Ok(node);
        }

        if check_header_sanity {
            check_block_header_sanity(header, adjusted_time_unix, false, params)?;
        }

        // Orphan headers are not allowed and this function should
        // never be called with the genesis block.
        let prev_hash = header.prev_block;
        let Some(prev_node) = self.index.lookup_node(&prev_hash) else {
            return Err(rule_error(
                RuleErrorKind::MissingParent,
                format!("previous block {prev_hash} is not known"),
            ));
        };

        // There is no need to validate the header if an ancestor is
        // already known to be invalid.
        if self
            .index
            .node_status(&self.store, prev_node)
            .known_invalid()
        {
            return Err(rule_error(
                RuleErrorKind::InvalidAncestorBlock,
                format!("previous block {prev_hash} is known to be invalid"),
            ));
        }

        // The block header must pass all of the validation rules
        // which depend on its position within the block chain.  The
        // fork rejection facts dcrd reads from its index mid-check
        // are supplied up front; the block is never in the index on
        // this path due to the lookup above.
        let fork_rejection = self.reject_forks_checkpoint.map(|cp| ForkRejection {
            checkpoint_height: self.store.node(cp).height,
            prev_is_checkpoint_ancestor: self.store.is_ancestor_of(prev_node, cp),
            block_in_index: false,
        });
        let prev_height = self.store.node(prev_node).height;
        let view = NodeBranchView {
            store: &self.store,
            tip: prev_node,
        };
        check_block_header_positional(
            &view,
            header,
            Some(prev_height),
            false,
            fork_rejection.as_ref(),
            params,
        )?;

        // Create a new block node for the block and add it to the
        // block index.
        let new_node = self.store.new_node(header, Some(prev_node));
        self.store.node_mut(new_node).status = BlockStatus::NONE;
        self.index.add_node(&self.store, new_node);

        self.maybe_set_fork_rejection_checkpoint(params);
        self.maybe_update_assume_valid(new_node);

        Ok(new_node)
    }

    /// Insert a new block header into the chain using headers-first
    /// semantics (dcrd `ProcessBlockHeader`).  dcrd additionally
    /// flushes modified block index entries to the database here;
    /// index persistence arrives with the engine wiring.
    pub fn process_block_header(
        &mut self,
        header: &BlockHeader,
        adjusted_time_unix: i64,
        params: &Params,
    ) -> Result<(), RuleError> {
        self.maybe_accept_block_header(header, true, adjusted_time_unix, params)
            .map(|_| ())
    }

    /// Connect the block to the end of the best chain: record the
    /// spend journal, ticket database rows, filter, and header
    /// commitment leaves, apply the view to the UTXO set, move the
    /// best chain tip, and replace the best state snapshot (dcrd
    /// `connectBlock`; the treasury balance and treasury spend rows
    /// arrive with the treasury database, and the block index flush,
    /// cache flush tuning, notifications, and the stake node memory
    /// prune optimization are not reproduced).
    #[allow(clippy::too_many_arguments)]
    pub fn connect_block(
        &mut self,
        node: NodeId,
        block: &MsgBlock,
        parent: &MsgBlock,
        view: &mut UtxoView,
        stxos: Vec<SpentTxOut>,
        filter: FilterV2,
        params: &Params,
    ) -> Result<(), RuleError> {
        // Make sure it's extending the end of the best chain.
        let tip = self.best_chain.tip().expect("best chain tip");
        assert_eq!(
            block.header.prev_block,
            self.store.node(tip).hash,
            "block connects to a block other than the best chain tip"
        );

        let parent_id = self
            .store
            .node(node)
            .parent
            .expect("connected block has a parent");
        let prev_height = Some(self.store.node(parent_id).height);
        {
            let parent_view = NodeBranchView {
                store: &self.store,
                tip: parent_id,
            };
            crate::validate::determine_check_tx_flags(&parent_view, prev_height, params)?;
        }

        // Sanity check the correct number of stxos are provided.
        assert_eq!(
            stxos.len(),
            count_spent_outputs(block),
            "provided stxos do not match the outputs the block spends"
        );

        let stake_node = self
            .fetch_stake_node(node, params)
            .map_err(stake_rule_error)?;

        // Calculate the next stake difficulty and the header
        // commitment leaves for the active agendas.
        let filter_hash = filter.hash();
        let (next_stake_diff, hdr_commitments_active) = {
            let node_view = NodeBranchView {
                store: &self.store,
                tip: node,
            };
            let node_diff =
                crate::difficulty::ChainView::node(&node_view, self.store.node(node).height);
            let next_stake_diff = crate::agendas::calc_next_required_stake_difficulty(
                &node_view,
                node_diff.as_ref(),
                params,
            );
            let parent_view = NodeBranchView {
                store: &self.store,
                tip: parent_id,
            };
            let active = crate::agendas::is_header_commitments_agenda_active(
                &parent_view,
                prev_height,
                params,
            )
            .map_err(|_| unknown_deployment_error())?;
            (next_stake_diff, active)
        };
        let hdr_commitment_leaves = if hdr_commitments_active {
            alloc::vec![filter_hash]
        } else {
            Vec::new()
        };

        // Generate the new best state snapshot.
        let subsidy = crate::validate::calculate_added_subsidy(block, parent);
        let num_txns = (block.transactions.len() + block.stransactions.len()) as u64;
        let n = self.store.node(node);
        let node_hash = n.hash;
        let node_height = n.height;
        let state = BestState {
            hash: node_hash,
            prev_hash: block.header.prev_block,
            height: node_height,
            bits: n.bits,
            next_pool_size: stake_node.pool_size() as u32,
            next_stake_diff,
            block_size: u64::from(block.header.size),
            num_txns,
            total_txns: self.state_snapshot.total_txns + num_txns,
            median_time: self.store.calc_past_median_time(node),
            total_subsidy: self.state_snapshot.total_subsidy + subsidy,
            next_expiring_tickets: stake_node.expiring_next_block(),
            next_winning_tickets: stake_node.winners().to_vec(),
            missed_tickets: stake_node.missed_tickets(),
            next_final_state: stake_node.final_state(),
        };

        // The database writes: the spend journal record, the ticket
        // database rows, the filter, and the commitment leaves.
        let serialized_journal =
            crate::chainio::serialize_spend_journal_entry(&stxos).unwrap_or_default();
        self.spend_journal.insert(node_hash.0, serialized_journal);
        self.write_stake_db_rows(node);
        self.filters.insert(node_hash.0, filter);
        self.header_commitments
            .insert(node_hash.0, hdr_commitment_leaves);

        // Commit all entries in the view to the UTXO set.
        self.commit_view(view);

        // This node is now the end of the best chain.
        self.best_chain.set_tip(&self.store, Some(node));
        self.state_snapshot = state;
        Ok(())
    }

    /// Disconnect the block from the end of the main chain: restore
    /// the parent's best state, drop the ticket database rows above
    /// the parent, apply the view to the UTXO set, and remove the
    /// block's spend journal record (dcrd `disconnectBlock`; the GCS
    /// filter and commitment leaves are intentionally retained).
    pub fn disconnect_block(
        &mut self,
        node: NodeId,
        block: &MsgBlock,
        parent: &MsgBlock,
        view: &mut UtxoView,
        params: &Params,
    ) -> Result<(), RuleError> {
        // Make sure the node being disconnected is the end of the
        // best chain.
        let tip = self.best_chain.tip().expect("best chain tip");
        assert_eq!(
            self.store.node(node).hash,
            self.store.node(tip).hash,
            "block being disconnected is not the end of the best chain"
        );

        let parent_id = self.store.node(node).parent.expect("parent");
        let prev_height = Some(self.store.node(parent_id).height);
        let parent_view = NodeBranchView {
            store: &self.store,
            tip: parent_id,
        };
        crate::validate::determine_check_tx_flags(&parent_view, prev_height, params)?;

        self.fetch_stake_node(node, params)
            .map_err(stake_rule_error)?;
        let parent_stake_node = self
            .fetch_stake_node(parent_id, params)
            .map_err(stake_rule_error)?;

        // Generate the new best state snapshot for the parent.  The
        // next stake difficulty comes from the disconnected block's
        // own header commitment like dcrd.
        let num_parent_txns = (parent.transactions.len() + parent.stransactions.len()) as u64;
        let num_block_txns = (block.transactions.len() + block.stransactions.len()) as u64;
        let subsidy = crate::validate::calculate_added_subsidy(block, parent);
        let pn = self.store.node(parent_id);
        let state = BestState {
            hash: pn.hash,
            prev_hash: pn
                .parent
                .map(|gp| self.store.node(gp).hash)
                .unwrap_or(Hash::ZERO),
            height: pn.height,
            bits: pn.bits,
            next_pool_size: parent_stake_node.pool_size() as u32,
            next_stake_diff: self.store.node(node).sbits,
            block_size: u64::from(parent.header.size),
            num_txns: num_parent_txns,
            total_txns: self.state_snapshot.total_txns - num_block_txns,
            median_time: self.store.calc_past_median_time(parent_id),
            total_subsidy: self.state_snapshot.total_subsidy - subsidy,
            next_expiring_tickets: parent_stake_node.expiring_next_block(),
            next_winning_tickets: parent_stake_node.winners().to_vec(),
            missed_tickets: parent_stake_node.missed_tickets(),
            next_final_state: parent_stake_node.final_state(),
        };

        // Drop the ticket database rows above the new tip (the row
        // effect of dcrd `stake.WriteDisconnectedBestNode`).
        let node_height = self.store.node(node).height;
        self.stake_undo.retain(|h, _| *h < node_height);
        self.stake_new_tickets.retain(|h, _| *h < node_height);

        // Commit all entries in the view to the UTXO set.  dcrd then
        // forces a cache flush on every disconnect, which drops the
        // spent tombstones; blocks detached after this point resurrect
        // their spent outputs from the journal's fraud proof fields
        // rather than the retained originals, and reproducing that
        // timing matters for field-level parity.
        self.commit_view(view);
        self.flush_utxo_cache();

        // Remove the block's spend journal record after the flush like
        // dcrd, since the journal is its cache recovery source.
        let node_hash = self.store.node(node).hash;
        self.spend_journal.remove(&node_hash.0);

        // This node's parent is now the end of the best chain.
        self.best_chain.set_tip(&self.store, Some(parent_id));
        self.state_snapshot = state;
        Ok(())
    }

    /// The version 2 GCS filter for the block, loaded when previously
    /// stored and created from the post-connect view otherwise (dcrd
    /// `loadOrCreateFilter`).
    pub fn load_or_create_filter(
        &self,
        block: &MsgBlock,
        view: &UtxoView,
    ) -> Result<FilterV2, RuleError> {
        if let Some(filter) = self.filters.get(&block.header.block_hash().0) {
            return Ok(filter.clone());
        }
        struct ViewScripts<'a>(&'a UtxoView);
        impl dcroxide_gcs::blockcf2::PrevScripter for ViewScripts<'_> {
            fn prev_script(&self, out: &OutPoint) -> Option<(u16, &[u8])> {
                let entry = self.0.lookup_entry(out)?;
                Some((entry.script_version(), entry.pk_script()))
            }
        }
        dcroxide_gcs::blockcf2::regular(block, &ViewScripts(view)).map_err(|e| RuleError {
            kind: RuleErrorKind::MissingTxOut,
            description: format!("{e:?}"),
        })
    }

    /// Reorganize the chain to the given target without attempting to
    /// undo failed reorgs: disconnect blocks back to the fork point
    /// and connect the blocks of the new branch, fully validating any
    /// that have not been validated before (dcrd
    /// `reorganizeChainInternal`; the shutdown interrupt checks and
    /// notifications are not reproduced).
    pub fn reorganize_chain_internal(
        &mut self,
        target: NodeId,
        params: &Params,
    ) -> Result<(), RuleError> {
        let mut tip = self.best_chain.tip();
        let fork = self.best_chain.find_fork(&self.store, target);

        // Disconnect all of the blocks back to the point of the fork.
        let mut view = UtxoView::new();
        if let Some(t) = tip {
            view.set_best_hash(self.store.node(t).hash);
        }
        let mut next_block_to_detach: Option<MsgBlock> = None;
        while let Some(n) = tip {
            if Some(n) == fork {
                break;
            }
            let block = match next_block_to_detach.take() {
                Some(b) => b,
                None => self.block_by_node(n).clone(),
            };
            assert_eq!(
                self.store.node(n).hash,
                block.header.block_hash(),
                "detach block node hash does not match the block"
            );
            let parent_id = self.store.node(n).parent.expect("detached block parent");
            let parent = self.block_by_node(parent_id).clone();
            next_block_to_detach = Some(parent.clone());

            let parent_view = NodeBranchView {
                store: &self.store,
                tip: parent_id,
            };
            let prev_height = Some(self.store.node(parent_id).height);
            let is_treasury_enabled =
                crate::agendas::is_treasury_agenda_active(&parent_view, prev_height, params)
                    .map_err(|_| unknown_deployment_error())?;

            // Load the spent txos for the block from the spend
            // journal and update the view to unspend them.
            let stxos = self.fetch_spend_journal(&block, is_treasury_enabled);
            view.disconnect_block(
                &block,
                &parent,
                &stxos,
                &|op: &OutPoint| Self::cache_fetch(&self.utxo_backend, &self.utxo_cache, op),
                is_treasury_enabled,
            )?;

            // Update the chain state.
            self.disconnect_block(n, &block, &parent, &mut view, params)?;
            tip = Some(parent_id);
        }

        // Determine the blocks to attach after the fork point in
        // forward order.
        let mut attach_nodes = Vec::new();
        let mut n = Some(target);
        while let Some(id) = n {
            if Some(id) == fork {
                break;
            }
            attach_nodes.push(id);
            n = self.store.node(id).parent;
        }
        attach_nodes.reverse();

        for node in attach_nodes {
            let block = self.block_by_node(node).clone();
            let parent_id = self.store.node(node).parent.expect("attach parent");
            let parent = self.block_by_node(parent_id).clone();
            assert_eq!(
                self.store.node(parent_id).hash,
                parent.header.block_hash(),
                "attach block node parent hash does not match the parent block"
            );

            let prev_height = Some(self.store.node(parent_id).height);
            let is_treasury_enabled = {
                let parent_view = NodeBranchView {
                    store: &self.store,
                    tip: parent_id,
                };
                crate::agendas::is_treasury_agenda_active(&parent_view, prev_height, params)
                    .map_err(|_| unknown_deployment_error())?
            };

            // Skip validation when the block has already been
            // validated; the view, stxos, and header commitment data
            // are still needed.
            let mut stxos: Vec<SpentTxOut> = Vec::with_capacity(count_spent_outputs(&block));
            let filter;
            if self.index.node_status(&self.store, node).has_validated() {
                let parent_stxos = self.fetch_spend_journal(&parent, is_treasury_enabled);
                view.connect_block(
                    &block,
                    &parent,
                    &parent_stxos,
                    &|op: &OutPoint| Self::cache_fetch(&self.utxo_backend, &self.utxo_cache, op),
                    Some(&mut stxos),
                    is_treasury_enabled,
                )?;
                filter = self.load_or_create_filter(&block, &view)?;
            } else {
                // The block must pass all of the validation rules
                // which depend on having the full block data for all
                // of its ancestors available.
                let parent_stake_node = self
                    .fetch_stake_node(parent_id, params)
                    .map_err(stake_rule_error)?;
                let context_result = check_block_context_for(
                    &self.store,
                    parent_id,
                    &block,
                    &parent_stake_node,
                    params,
                );
                if let Err(err) = context_result {
                    self.index
                        .mark_block_failed_validation(&mut self.store, node);
                    return Err(err);
                }

                let run_scripts = !self.bulk_import_mode && !self.is_assume_valid_ancestor(node);
                let parent_stxos = self.fetch_spend_journal(&parent, is_treasury_enabled);
                let mut subsidy_cache =
                    dcroxide_standalone::SubsidyCache::new(ChainSubsidyParams(params));
                let node_info = {
                    let nd = self.store.node(node);
                    (nd.height, nd.hash, nd.voters, nd.vote_bits)
                };
                let connect_result = {
                    let parent_view = NodeBranchView {
                        store: &self.store,
                        tip: parent_id,
                    };
                    crate::validate::check_connect_block(
                        &parent_view,
                        &mut subsidy_cache,
                        node_info.0,
                        node_info.1,
                        node_info.2,
                        node_info.3,
                        &block,
                        &parent,
                        &parent_stxos,
                        &mut view,
                        &|op: &OutPoint| {
                            Self::cache_fetch(&self.utxo_backend, &self.utxo_cache, op)
                        },
                        Some(&mut stxos),
                        run_scripts,
                        params,
                    )
                };
                match connect_result {
                    Ok(filter_hash) => {
                        // The filter was computed inside the connect
                        // checks; recreate it from the post-connect
                        // view for storage (dcrd receives it through
                        // the header commitment data out-param).
                        filter = self.load_or_create_filter(&block, &view)?;
                        assert_eq!(filter.hash(), filter_hash, "filter hash mismatch");
                    }
                    Err(err) => {
                        self.index
                            .mark_block_failed_validation(&mut self.store, node);
                        return Err(err);
                    }
                }
                self.index
                    .set_status_flags(&mut self.store, node, BlockStatus::VALIDATED);
            }

            // Update the chain state and drop any best chain
            // candidates that now have less work than the new tip.
            self.connect_block(node, &block, &parent, &mut view, stxos, filter, params)?;
            self.index.remove_less_work_candidates(&self.store, node);
        }

        Ok(())
    }

    /// Reorganize the chain to the given target with handling for
    /// failed reorgs: when the target is or becomes invalid, fall
    /// back to the best valid chain candidate (dcrd
    /// `reorganizeChain`; notifications and the current-latch cache
    /// flush are not reproduced).  All accumulated reorg errors are
    /// returned (dcrd wraps multiple in a `MultiError`).
    pub fn reorganize_chain(
        &mut self,
        target: Option<NodeId>,
        adjusted_time_unix: i64,
        params: &Params,
    ) -> Vec<RuleError> {
        let mut reorg_errs = Vec::new();
        let mut target = target;
        let tip = self.best_chain.tip();
        if target.is_none() || tip == target {
            return reorg_errs;
        }

        while let Some(t) = target {
            if self.best_chain.tip() == Some(t) {
                break;
            }
            if let Err(err) = self.reorganize_chain_internal(t, params) {
                reorg_errs.push(err);

                // Determine a new best candidate since the reorg
                // failed; bail out if it does not change to avoid
                // attempting the same reorg over and over.
                let new_target = self.index.find_best_chain_candidate(&self.store);
                if new_target == Some(t) {
                    break;
                }
                target = new_target;
            }
        }

        // Potentially update whether the chain believes it is current
        // based on the actual new tip.
        if let Some(new_tip) = self.best_chain.tip() {
            self.maybe_update_is_current(new_tip, adjusted_time_unix);
        }
        reorg_errs
    }

    /// Whether the node's timestamp is more than 24 hours old
    /// relative to the adjusted time (dcrd `isOldTimestamp`).
    fn is_old_timestamp(&self, node: NodeId, adjusted_time_unix: i64) -> bool {
        const DAY_SECS: i64 = 24 * 60 * 60;
        self.store.node(node).timestamp < adjusted_time_unix - DAY_SECS
    }

    /// Potentially update whether the chain believes it is current,
    /// latching once it becomes so (dcrd `maybeUpdateIsCurrent`).
    pub fn maybe_update_is_current(&mut self, cur_best: NodeId, adjusted_time_unix: i64) {
        if !self.is_current_latch {
            // Not current with less cumulative work than the minimum
            // known work for the network.
            if let Some(min_work) = &self.min_known_work {
                if self.store.node(cur_best).work_sum < *min_work {
                    return;
                }
            }

            // Not current when not synced to the best header.
            let Some(best_header) = self.index.best_header() else {
                return;
            };
            let synced = self.store.node(cur_best).height == self.store.node(best_header).height
                || self.store.is_ancestor_of(best_header, cur_best);
            if !synced {
                return;
            }
        }

        self.is_current_latch = !self.is_old_timestamp(cur_best, adjusted_time_unix);
    }

    /// Whether the chain believes it is current (dcrd `isCurrent`).
    pub fn is_current(&self, cur_best: NodeId, adjusted_time_unix: i64) -> bool {
        self.is_current_latch && !self.is_old_timestamp(cur_best, adjusted_time_unix)
    }
}

/// Convert a stake rule error from the ticket state machine into a
/// chain rule error like dcrd's error pass-through.
fn stake_rule_error(err: dcroxide_stake::RuleError) -> RuleError {
    RuleError {
        kind: RuleErrorKind::TicketUnavailable,
        description: format!("stake node error: {err:?}"),
    }
}

fn unknown_deployment_error() -> RuleError {
    RuleError {
        kind: RuleErrorKind::UnknownDeploymentID,
        description: "deployment not defined on this network".into(),
    }
}

/// Run the contextual block checks for an attach candidate over its
/// parent branch (the dcrd `checkBlockContext` call inside the reorg
/// attach loop).
fn check_block_context_for(
    store: &NodeStore,
    parent_id: NodeId,
    block: &MsgBlock,
    parent_stake_node: &StakeNode,
    params: &Params,
) -> Result<(), RuleError> {
    let parent_view = NodeBranchView {
        store,
        tip: parent_id,
    };
    let prev_height = Some(store.node(parent_id).height);
    crate::validate::check_block_context(
        &parent_view,
        block,
        prev_height,
        false,
        false,
        parent_stake_node.pool_size() as u32,
        parent_stake_node.final_state(),
        Some(parent_stake_node),
        params,
    )
}
