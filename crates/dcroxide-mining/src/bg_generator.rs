// SPDX-License-Identifier: ISC
//! The background block template generator's regeneration state
//! machine (dcrd internal/mining `bgblktmplgenerator.go`).  The
//! concurrency shell — the regen queue, the subscriber fan-out
//! goroutine, the async generation goroutines, and the real timers —
//! has no synchronous counterpart: timers appear here as armed flags
//! with recorded durations for the daemon to drive, and template
//! generation requests are recorded as actions the daemon executes.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use dcroxide_chainhash::Hash;
use dcroxide_wire::MsgTx;

use crate::generator::{TemplateBest, TemplateChain, TemplateTxSource};
use crate::template::BlockTemplate;

/// The duration that must elapse after a new tip block has been
/// received before other variants that extend the same parent are
/// considered (dcrd `minVotesTimeoutDuration`).
pub const MIN_VOTES_TIMEOUT_MILLIS: u64 = 3000;

/// The duration that must elapse after the minimum number of votes
/// has been received before generating a template with fewer than the
/// maximum number of votes (dcrd `maxVoteTimeoutDuration`).
pub const MAX_VOTE_TIMEOUT_MILLIS: u64 = 2500;

/// The number of seconds that must elapse with no new transactions
/// before a template is regenerated (dcrd `templateRegenSecs`).
pub const TEMPLATE_REGEN_SECS: u64 = 30;

/// The reason a template update happened (dcrd
/// `TemplateUpdateReason` including the internal `turUnknown`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgTemplateUpdateReason {
    /// A new parent block (dcrd `TURNewParent`).
    NewParent,
    /// New votes arrived (dcrd `TURNewVotes`).
    NewVotes,
    /// New transactions arrived (dcrd `TURNewTxns`).
    NewTxns,
    /// The template was cleared or failed to generate (dcrd
    /// `turUnknown`).
    Unknown,
}

/// A recorded generation request (dcrd `genTemplateAsync`): the
/// daemon cancels any generation in progress and launches a new one
/// with the reason; block retrieval stalls for new-parent and
/// new-votes reasons via the stale-template wait group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenRequest {
    /// The template update reason to generate with.
    pub reason: BgTemplateUpdateReason,
    /// Whether template retrieval blocks until this generation
    /// completes (dcrd's `blockRetrieval`).
    pub block_retrieval: bool,
}

/// The regen handler state (dcrd `regenHandlerState`); the timers are
/// armed flags whose real countdowns the daemon drives.
pub struct BgTemplateState {
    /// Whether the chain is currently reorganizing (dcrd
    /// `isReorganizing`).
    pub is_reorganizing: bool,
    /// Whether the periodic regeneration timer is armed (dcrd's
    /// `regenTimer` with `regenChanDrained` inverted).
    pub regen_timer_armed: bool,
    /// The duration the regen timer was last armed with, in
    /// milliseconds.
    pub regen_timer_millis: u64,
    /// The timestamp the current template was generated (dcrd
    /// `lastGeneratedTime`).
    pub last_generated_time: i64,
    /// The new tip block awaiting its minimum required votes (dcrd
    /// `awaitingMinVotesHash`).
    pub awaiting_min_votes_hash: Option<Hash>,
    /// Whether the max-votes propagation timeout is armed (dcrd
    /// `maxVotesTimeout`).
    pub max_votes_timeout_armed: bool,
    /// The side chain blocks being monitored for votes (dcrd
    /// `awaitingSideChainMinVotes`).
    pub awaiting_side_chain_min_votes: BTreeSet<Hash>,
    /// Whether the side chain tracking timeout is armed (dcrd
    /// `trackSideChainsTimeout`).
    pub track_side_chains_timeout_armed: bool,
    /// Whether the failed-generation retry timeout is armed (dcrd
    /// `failedGenRetryTimeout`).
    pub failed_gen_retry_timeout_armed: bool,
    /// The hash of the block the next template builds on (dcrd
    /// `baseBlockHash`).
    pub base_block_hash: Hash,
    /// The height of the base block (dcrd `baseBlockHeight`).
    pub base_block_height: u32,
}

impl BgTemplateState {
    /// A ready-to-use regen handler state (dcrd
    /// `makeRegenHandlerState`).
    pub fn new() -> BgTemplateState {
        BgTemplateState {
            is_reorganizing: false,
            regen_timer_armed: false,
            regen_timer_millis: 0,
            last_generated_time: 0,
            awaiting_min_votes_hash: None,
            max_votes_timeout_armed: false,
            awaiting_side_chain_min_votes: BTreeSet::new(),
            track_side_chains_timeout_armed: false,
            failed_gen_retry_timeout_armed: false,
            base_block_hash: Hash([0u8; 32]),
            base_block_height: 0,
        }
    }

    /// Stop the regen timer (dcrd `stopRegenTimer`).
    fn stop_regen_timer(&mut self) {
        self.regen_timer_armed = false;
    }

    /// Reset the regen timer to the given duration (dcrd
    /// `resetRegenTimer`).
    fn reset_regen_timer(&mut self, millis: u64) {
        self.regen_timer_armed = true;
        self.regen_timer_millis = millis;
    }

    /// Clear all side chain vote tracking (dcrd
    /// `clearSideChainTracking`).
    fn clear_side_chain_tracking(&mut self) {
        self.awaiting_side_chain_min_votes.clear();
        self.track_side_chains_timeout_armed = false;
    }
}

impl Default for BgTemplateState {
    fn default() -> Self {
        BgTemplateState::new()
    }
}

/// The generator-level synchronous state the regen handlers touch
/// (the corresponding fields of dcrd `BgBlkTmplGenerator`).
pub struct BgGenerator {
    /// The maximum number of votes per block (dcrd
    /// `maxVotesPerBlock`).
    pub max_votes_per_block: u16,
    /// The minimum number of votes required to build on a block
    /// (dcrd `minVotesRequired` = tickets-per-block/2 + 1).
    pub min_votes_required: u16,
    /// The stake validation height from the chain parameters.
    pub stake_validation_height: i64,
    /// Whether templates are generated while unsynced (dcrd
    /// `AllowUnsyncedMining`).
    pub allow_unsynced_mining: bool,
    /// The current template (dcrd `template`; `None` while errored or
    /// cleared).
    pub template: Option<BlockTemplate>,
    /// The reason associated with the current template.
    pub template_reason: BgTemplateUpdateReason,
    /// The error associated with the current template.
    pub template_err: Option<String>,
    /// The recent parents notifications were sent for (dcrd
    /// `notifiedParents`, an LRU of size 3).
    pub notified_parents: Vec<Hash>,
    /// The recorded generation requests (dcrd `genTemplateAsync`
    /// launches, in order).
    pub gen_requests: Vec<GenRequest>,
    /// The stale-template wait group counter (dcrd
    /// `staleTemplateWg`): incremented per blocking generation and on
    /// reorg start, decremented when they complete.
    pub stale_template_count: i64,
}

impl BgGenerator {
    /// A new generator over the given chain parameters facts (dcrd
    /// `NewBgBlkTmplGenerator`).
    pub fn new(
        tickets_per_block: u16,
        stake_validation_height: i64,
        allow_unsynced_mining: bool,
    ) -> BgGenerator {
        BgGenerator {
            max_votes_per_block: tickets_per_block,
            min_votes_required: (tickets_per_block / 2) + 1,
            stake_validation_height,
            allow_unsynced_mining,
            template: None,
            template_reason: BgTemplateUpdateReason::Unknown,
            template_err: None,
            notified_parents: Vec::new(),
            gen_requests: Vec::new(),
            stale_template_count: 0,
        }
    }

    /// Record a generation request (dcrd `genTemplateAsync`; the
    /// daemon cancels any in-flight generation and launches the new
    /// one).
    fn gen_template_async(&mut self, reason: BgTemplateUpdateReason) {
        let block_retrieval = matches!(
            reason,
            BgTemplateUpdateReason::NewParent | BgTemplateUpdateReason::NewVotes
        );
        if block_retrieval {
            self.stale_template_count += 1;
        }
        self.gen_requests.push(GenRequest {
            reason,
            block_retrieval,
        });
    }

    /// Set the current template state (dcrd `setCurrentTemplate`; the
    /// daemon additionally queues the corresponding template-update
    /// regen event).
    pub fn set_current_template(
        &mut self,
        template: Option<BlockTemplate>,
        reason: BgTemplateUpdateReason,
        err: Option<String>,
    ) {
        self.template = template;
        self.template_reason = reason;
        self.template_err = err;
    }

    /// Whether the current template is valid, builds on the provided
    /// hash, and contains the specified number of votes (dcrd
    /// `curTplHasNumVotes`).
    fn cur_tpl_has_num_votes(&self, voted_on_hash: &Hash, num_votes: u16) -> bool {
        let Some(template) = &self.template else {
            return false;
        };
        if self.template_err.is_some() {
            return false;
        }
        if template.block.header.prev_block != *voted_on_hash {
            return false;
        }
        template.block.header.voters == num_votes
    }

    /// Process a completed asynchronous generation (the goroutine
    /// body of dcrd `genTemplateAsync` after `NewBlockTemplate`
    /// returns): updates the current template state and returns the
    /// subscriber notification when one should be sent.  The daemon
    /// also queues the template-update regen event and, for blocking
    /// generations, releases the stale-template wait.
    pub fn process_generated_template(
        &mut self,
        template: Option<BlockTemplate>,
        mut reason: BgTemplateUpdateReason,
        err: Option<String>,
        block_retrieval: bool,
    ) -> Option<(BlockTemplate, BgTemplateUpdateReason)> {
        if block_retrieval {
            self.stale_template_count -= 1;
        }

        if err.is_some() {
            reason = BgTemplateUpdateReason::Unknown;
        }
        self.set_current_template(template, reason, err);
        let template = self.template.clone()?;
        if self.template_err.is_some() {
            return None;
        }

        // It is possible for a new vote to show up while the template
        // for a new parent is still being generated, so ensure the
        // first notification sent for a new parent has that reason.
        let prev_block = template.block.header.prev_block;
        if reason == BgTemplateUpdateReason::NewVotes
            && !self.notified_parents.contains(&prev_block)
        {
            reason = BgTemplateUpdateReason::NewParent;
        }
        if reason == BgTemplateUpdateReason::NewParent {
            // An LRU of size 3.
            self.notified_parents.retain(|h| *h != prev_block);
            self.notified_parents.insert(0, prev_block);
            self.notified_parents.truncate(3);
        }

        Some((template, reason))
    }
}

/// The number of known votes on the provided block (dcrd
/// `numVotesForBlock`).
fn num_votes_for_block(tx_source: &dyn TemplateTxSource, voted_on_block: &Hash) -> u16 {
    tx_source.vote_hashes_for_block(voted_on_block).len() as u16
}

/// Handle a connected block (dcrd `handleBlockConnected`).
pub fn handle_block_connected(
    g: &mut BgGenerator,
    state: &mut BgTemplateState,
    tx_source: &dyn TemplateTxSource,
    block: &dcroxide_wire::MsgBlock,
    chain_tip: &TemplateBest,
) {
    // Clear all vote tracking when the current chain tip changes.
    state.awaiting_min_votes_hash = None;
    state.clear_side_chain_tracking();

    // Nothing more to do if the connected block is not the current
    // chain tip.
    let block_height = block.header.height;
    let block_hash = block.header.block_hash();
    if i64::from(block_height) != chain_tip.height || block_hash != chain_tip.hash {
        return;
    }

    // Generate a new template immediately when it will be prior to
    // stake validation height which means no votes are required.
    let new_template_height = block_height + 1;
    if i64::from(new_template_height) < g.stake_validation_height {
        state.stop_regen_timer();
        state.failed_gen_retry_timeout_armed = false;
        state.base_block_hash = block_hash;
        state.base_block_height = block_height;
        g.gen_template_async(BgTemplateUpdateReason::NewParent);
        return;
    }

    // Generate a new template immediately when the maximum number of
    // votes for the block are already known.
    let num_votes = num_votes_for_block(tx_source, &block_hash);
    if num_votes >= g.max_votes_per_block {
        state.stop_regen_timer();
        state.failed_gen_retry_timeout_armed = false;
        state.base_block_hash = block_hash;
        state.base_block_height = block_height;
        g.gen_template_async(BgTemplateUpdateReason::NewParent);
        return;
    }

    // Set a timeout to give the remaining votes an opportunity to
    // propagate when the minimum number of required votes for the
    // block are already known.
    if num_votes >= g.min_votes_required {
        state.stop_regen_timer();
        state.failed_gen_retry_timeout_armed = false;
        state.base_block_hash = block_hash;
        state.base_block_height = block_height;
        state.max_votes_timeout_armed = true;
        return;
    }

    // Mark the state as waiting for the minimum number of required
    // votes and set a timeout before considering variants that extend
    // the same parent, preventing vote-withholding advantages.
    state.stop_regen_timer();
    state.awaiting_min_votes_hash = Some(block_hash);
    state.track_side_chains_timeout_armed = true;
}

/// Handle a disconnected block (dcrd `handleBlockDisconnected`).
pub fn handle_block_disconnected(
    g: &mut BgGenerator,
    state: &mut BgTemplateState,
    block: &dcroxide_wire::MsgBlock,
    chain_tip: &TemplateBest,
) {
    // Clear all vote tracking when the current chain tip changes.
    state.awaiting_min_votes_hash = None;
    state.clear_side_chain_tracking();

    // Nothing more to do if the current chain tip is not the block
    // prior to the block that was disconnected.
    let prev_height = block.header.height.wrapping_sub(1);
    let prev_hash = block.header.prev_block;
    if i64::from(prev_height) != chain_tip.height || prev_hash != chain_tip.hash {
        return;
    }

    // Generate a new template building on the new tip; its votes are
    // necessarily already known.
    state.stop_regen_timer();
    state.failed_gen_retry_timeout_armed = false;
    state.base_block_hash = prev_hash;
    state.base_block_height = prev_height;
    g.gen_template_async(BgTemplateUpdateReason::NewParent);
}

/// Handle an accepted block (dcrd `handleBlockAccepted`).
pub fn handle_block_accepted(
    g: &mut BgGenerator,
    state: &mut BgTemplateState,
    block: &dcroxide_wire::MsgBlock,
    chain_tip: &TemplateBest,
) {
    // Ignore side chain blocks while still waiting for the side chain
    // tracking timeout to expire.
    if state.track_side_chains_timeout_armed {
        return;
    }

    // Ignore side chain blocks when building on it would produce a
    // block prior to stake validation height.
    let block_height = block.header.height;
    let new_template_height = block_height + 1;
    if i64::from(new_template_height) < g.stake_validation_height {
        return;
    }

    // Ignore side chain blocks when the current tip already has
    // enough votes for a template to be built on it.
    if state.awaiting_min_votes_hash.is_none() {
        return;
    }

    // Ignore blocks that are prior to the current tip.
    if i64::from(block_height) < chain_tip.height {
        return;
    }

    // Ignore the main chain tip block since it is handled by the
    // connect path.
    let block_hash = block.header.block_hash();
    if block_hash == chain_tip.hash {
        return;
    }

    // Ignore side chain blocks when the current template is already
    // building on the current tip or the accepted block is not a
    // sibling of the current best chain tip.
    let already_building_on_cur_tip = state.base_block_hash == chain_tip.hash;
    if already_building_on_cur_tip || block.header.prev_block != chain_tip.prev_hash {
        return;
    }

    // Setup tracking for votes on the block.
    state.awaiting_side_chain_min_votes.insert(block_hash);
}

/// Handle a vote (dcrd `handleVote`).
pub fn handle_vote(
    g: &mut BgGenerator,
    state: &mut BgTemplateState,
    chain: &mut dyn TemplateChain,
    tx_source: &dyn TemplateTxSource,
    vote_tx: &MsgTx,
    chain_tip: &TemplateBest,
) {
    let (voted_on_hash, _) = dcroxide_stake::ssgen_block_voted_on(vote_tx);

    // Lock the current tip in once it has the minimum required votes.
    if let Some(min_votes_hash) = state.awaiting_min_votes_hash
        && voted_on_hash == min_votes_hash
    {
        let num_votes = num_votes_for_block(tx_source, &min_votes_hash);
        if num_votes >= g.min_votes_required {
            state.stop_regen_timer();
            state.failed_gen_retry_timeout_armed = false;
            state.base_block_hash = min_votes_hash;
            state.base_block_height = chain_tip.height as u32;
            state.awaiting_min_votes_hash = None;
            state.clear_side_chain_tracking();

            // Generate a new template immediately when the maximum
            // number of votes for the block are already known.
            if num_votes >= g.max_votes_per_block {
                g.gen_template_async(BgTemplateUpdateReason::NewParent);
                return;
            }

            // Give the remaining votes an opportunity to propagate.
            state.max_votes_timeout_armed = true;
        }
        return;
    }

    // Generate a template on new votes for the block the next
    // template builds on when either the maximum number of votes is
    // received or the propagation delay timeout has expired.
    if voted_on_hash == state.base_block_hash {
        // Avoid regenerating when the current template already has
        // the maximum number of votes.
        if g.cur_tpl_has_num_votes(&voted_on_hash, g.max_votes_per_block) {
            state.max_votes_timeout_armed = false;
            return;
        }

        let num_votes = num_votes_for_block(tx_source, &voted_on_hash);
        if num_votes >= g.max_votes_per_block || !state.max_votes_timeout_armed {
            // The template needs a new-parent update the first time
            // it is generated and new-votes updates on subsequent
            // votes; the max votes timeout is only armed before the
            // first generation.
            let tpl_update_reason = if state.max_votes_timeout_armed {
                BgTemplateUpdateReason::NewParent
            } else {
                BgTemplateUpdateReason::NewVotes
            };

            state.max_votes_timeout_armed = false;
            state.stop_regen_timer();
            state.failed_gen_retry_timeout_armed = false;
            g.gen_template_async(tpl_update_reason);
        }
        return;
    }

    // Reorganize to an alternative tip when it receives the minimum
    // required votes while the current tip could not.
    if state.awaiting_side_chain_min_votes.contains(&voted_on_hash) {
        let num_votes = num_votes_for_block(tx_source, &voted_on_hash);
        if num_votes >= g.min_votes_required {
            if chain
                .force_head_reorganization(chain_tip.hash, voted_on_hash)
                .is_err()
            {
                return;
            }

            // Prevent votes on other tip candidates from causing
            // another reorg.
            state.clear_side_chain_tracking();
        }
    }
}

/// Handle a template update (dcrd `handleTemplateUpdate`); the time
/// is injected for determinism.
pub fn handle_template_update(
    state: &mut BgTemplateState,
    template: Option<&BlockTemplate>,
    err: bool,
    now_unix: i64,
) {
    // Schedule a regen if the template failed to generate.
    if err && !state.failed_gen_retry_timeout_armed {
        state.failed_gen_retry_timeout_armed = true;
        return;
    }
    let Some(template) = template else {
        return;
    };

    // Ensure the base block details match the template.
    state.base_block_hash = template.block.header.prev_block;
    state.base_block_height = template.block.header.height.wrapping_sub(1);

    // Update the state related to template regeneration due to new
    // regular transactions.
    state.last_generated_time = now_unix;
    state.reset_regen_timer(TEMPLATE_REGEN_SECS * 1000);
}

/// Handle a forced regeneration request (dcrd `handleForceRegen`).
pub fn handle_force_regen(g: &mut BgGenerator, state: &mut BgTemplateState) {
    // Ignore requests when the minimum number of votes has been
    // received and the template will be regenerated shortly anyway.
    if state.max_votes_timeout_armed {
        return;
    }

    state.stop_regen_timer();
    state.failed_gen_retry_timeout_armed = false;
    g.gen_template_async(BgTemplateUpdateReason::Unknown);
}

/// A regen event (dcrd `regenEvent` reasons).
pub enum BgRegenEvent<'a> {
    /// A chain reorganization started (dcrd `rtReorgStarted`).
    ReorgStarted,
    /// A chain reorganization finished (dcrd `rtReorgDone`).
    ReorgDone,
    /// A block was connected to the main chain.
    BlockConnected(&'a dcroxide_wire::MsgBlock),
    /// A block was disconnected from the main chain.
    BlockDisconnected(&'a dcroxide_wire::MsgBlock),
    /// A block was accepted to the block index.
    BlockAccepted(&'a dcroxide_wire::MsgBlock),
    /// A vote was received.
    Vote(&'a MsgTx),
    /// A template generation completed.
    TemplateUpdated(Option<&'a BlockTemplate>, bool),
    /// A forced regeneration was requested.
    ForceRegen,
}

/// Handle a regen event (dcrd `handleRegenEvent`); `is_current` is
/// the sampled result of dcrd's `IsCurrent` callback and `now_unix`
/// feeds the template update time.
pub fn handle_regen_event(
    g: &mut BgGenerator,
    state: &mut BgTemplateState,
    chain: &mut dyn TemplateChain,
    tx_source: &dyn TemplateTxSource,
    event: BgRegenEvent<'_>,
    is_current: bool,
    now_unix: i64,
) {
    // Handle chain reorg messages up front.
    match &event {
        BgRegenEvent::ReorgStarted => {
            // Block template retrieval until the post-reorg template.
            g.stale_template_count += 1;
            state.is_reorganizing = true;

            // Stop all timeouts and clear all vote tracking.
            state.stop_regen_timer();
            state.failed_gen_retry_timeout_armed = false;
            state.awaiting_min_votes_hash = None;
            state.max_votes_timeout_armed = false;
            state.clear_side_chain_tracking();

            // Clear the current template and associated base block.
            g.set_current_template(None, BgTemplateUpdateReason::Unknown, None);
            state.base_block_hash = Hash([0u8; 32]);
            state.base_block_height = 0;
            return;
        }
        BgRegenEvent::ReorgDone => {
            state.is_reorganizing = false;

            // Treat the tip block as if it was just connected.
            let chain_tip = chain.best_snapshot();
            match chain.block_by_hash(&chain_tip.hash) {
                Err(err) => {
                    g.set_current_template(None, BgTemplateUpdateReason::Unknown, Some(err));
                }
                Ok(tip_block) => {
                    handle_block_connected(g, state, tx_source, &tip_block, &chain_tip);
                }
            }

            g.stale_template_count -= 1;
            return;
        }
        _ => {}
    }

    // Do not generate block templates while reorganizing.
    if state.is_reorganizing {
        return;
    }

    // Do not generate block templates when the chain is not synced
    // unless specifically requested to.
    if !g.allow_unsynced_mining && !is_current {
        return;
    }

    let chain_tip = chain.best_snapshot();
    match event {
        BgRegenEvent::BlockConnected(block) => {
            handle_block_connected(g, state, tx_source, block, &chain_tip);
        }
        BgRegenEvent::BlockDisconnected(block) => {
            handle_block_disconnected(g, state, block, &chain_tip);
        }
        BgRegenEvent::BlockAccepted(block) => {
            handle_block_accepted(g, state, block, &chain_tip);
        }
        BgRegenEvent::Vote(vote_tx) => {
            handle_vote(g, state, chain, tx_source, vote_tx, &chain_tip);
        }
        BgRegenEvent::TemplateUpdated(template, err) => {
            handle_template_update(state, template, err, now_unix);
        }
        BgRegenEvent::ForceRegen => {
            handle_force_regen(g, state);
        }
        BgRegenEvent::ReorgStarted | BgRegenEvent::ReorgDone => unreachable!("handled above"),
    }
}

/// The tip siblings sorted by their number of votes in descending
/// order (dcrd `tipSiblingsSortedByVotes`).
fn tip_siblings_sorted_by_votes(
    state: &BgTemplateState,
    chain: &dyn TemplateChain,
    tx_source: &dyn TemplateTxSource,
) -> Vec<(Hash, u16)> {
    let generation = chain.tip_generation();
    if generation.len() <= 1 {
        return Vec::new();
    }

    let awaiting = state
        .awaiting_min_votes_hash
        .expect("only called while awaiting min votes");
    let mut siblings: Vec<(Hash, u16)> = generation
        .iter()
        .filter(|hash| **hash != awaiting)
        .map(|hash| (*hash, num_votes_for_block(tx_source, hash)))
        .collect();
    siblings.sort_by_key(|sibling| core::cmp::Reverse(sibling.1));
    siblings
}

/// Handle the side chain tracking timeout (dcrd
/// `handleTrackSideChainsTimeout`); the caller disarms the timeout
/// before invoking, mirroring the select arm.
pub fn handle_track_side_chains_timeout(
    g: &mut BgGenerator,
    state: &mut BgTemplateState,
    chain: &mut dyn TemplateChain,
    tx_source: &dyn TemplateTxSource,
) {
    // Don't allow side chain variants to override the current tip
    // when it already has the minimum required votes.
    if state.awaiting_min_votes_hash.is_none() {
        return;
    }

    // Reorganize to a valid sibling of the current tip with at least
    // the minimum number of required votes, preferring the most
    // votes; otherwise monitor the siblings for future votes.
    let sorted_siblings = tip_siblings_sorted_by_votes(state, chain, tx_source);
    for (sibling_hash, num_votes) in sorted_siblings {
        if num_votes >= g.min_votes_required {
            let awaiting = state.awaiting_min_votes_hash.expect("checked above");
            if chain
                .force_head_reorganization(awaiting, sibling_hash)
                .is_err()
            {
                // Try the next block in the case of failure to reorg.
                continue;
            }

            // Prevent votes on other tip candidates from causing
            // another reorg and mark the next template to build on
            // the new tip.
            state.awaiting_min_votes_hash = None;
            state.clear_side_chain_tracking();
            state.stop_regen_timer();
            state.failed_gen_retry_timeout_armed = false;
            state.base_block_hash = sibling_hash;
            return;
        }

        state.awaiting_side_chain_min_votes.insert(sibling_hash);
    }

    // Generate a new template building on the parent of the current
    // tip when there is not already an existing template.
    if state.base_block_hash == Hash([0u8; 32]) {
        let chain_tip = chain.best_snapshot();
        state.failed_gen_retry_timeout_armed = false;
        state.base_block_hash = chain_tip.prev_hash;
        state.base_block_height = (chain_tip.height - 1) as u32;
        g.gen_template_async(BgTemplateUpdateReason::NewParent);
        return;
    }

    // No viable candidates were found, so reset the regen timer for
    // the current template.
    state.reset_regen_timer(TEMPLATE_REGEN_SECS * 1000);
}

/// Handle the max-votes propagation timeout firing (the corresponding
/// select arm of dcrd `regenHandler`; the caller disarms the timeout
/// before invoking).
pub fn handle_max_votes_timeout(g: &mut BgGenerator, state: &mut BgTemplateState) {
    state.max_votes_timeout_armed = false;
    g.gen_template_async(BgTemplateUpdateReason::NewParent);
}

/// Handle the regen timer firing (the corresponding select arm of
/// dcrd `regenHandler`): regenerate when the transaction source has
/// newer transactions than the current template, otherwise check
/// again in one second.
pub fn handle_regen_timer_expired(
    g: &mut BgGenerator,
    state: &mut BgTemplateState,
    tx_source_last_updated_unix: i64,
) {
    state.regen_timer_armed = false;

    if tx_source_last_updated_unix > state.last_generated_time {
        state.failed_gen_retry_timeout_armed = false;
        g.gen_template_async(BgTemplateUpdateReason::NewTxns);
        return;
    }

    state.reset_regen_timer(1000);
}

/// Handle the failed-generation retry timeout firing (the
/// corresponding select arm of dcrd `regenHandler`).
pub fn handle_failed_gen_retry_timeout(g: &mut BgGenerator, state: &mut BgTemplateState) {
    state.failed_gen_retry_timeout_armed = false;
    g.gen_template_async(BgTemplateUpdateReason::NewParent);
}
