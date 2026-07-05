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

use dcroxide_stake::ticketdb::UndoTicketData;
use dcroxide_stake::ticketnode::{Node as StakeNode, StakeNodeParams};
use dcroxide_wire::MsgBlock;

use crate::RuleError;
use crate::blockindex::{BlockIndex, BlockStatus, NodeId, NodeStore};
use crate::chainview_nodes::{NodeBranchView, NodeChainView};
use crate::ruleerror::RuleErrorKind;
use crate::validate::{ForkRejection, check_block_header_positional, check_block_header_sanity};

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
        }
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
}
