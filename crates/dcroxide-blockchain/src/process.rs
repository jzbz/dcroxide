// SPDX-License-Identifier: ISC

//! Headers-first chain processing from dcrd's
//! `internal/blockchain/process.go`: accepting block headers to the
//! block index with full context-free and positional validation, the
//! known-invalid short circuits, and the assumed-valid and old fork
//! rejection checkpoint tracking.  The full block processing path
//! (`ProcessBlock` and the reorganization machinery it drives)
//! arrives with the chain engine.

use alloc::format;
use alloc::string::String;

use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_wire::BlockHeader;

use crate::RuleError;
use crate::blockindex::{BlockIndex, BlockStatus, NodeId, NodeStore};
use crate::chainview_nodes::NodeBranchView;
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
        index.add_node(&store, genesis);

        Chain {
            store,
            index,
            assume_valid: config_assume_valid,
            assume_valid_node: None,
            reject_forks_checkpoint: None,
            allow_old_forks,
            expected_blocks_in_two_weeks,
        }
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
