// SPDX-License-Identifier: ISC
//! The daemon's background block template generator (dcrd internal/
//! mining `bgblktmplgenerator.go`): a dedicated thread drives the
//! already-ported synchronous regeneration state machine
//! ([`dcroxide_mining::bg_generator`]) over the live chain and mempool,
//! serving the current template to the getwork RPC and fanning template
//! updates out to subscribers and the websocket work sink.
//!
//! dcrd's concurrency shell has no synchronous counterpart, so this
//! thread reconstructs it: the `regenEvent` queue is an mpsc channel
//! ([`GenCommand`]), the regen handler goroutine is the thread's
//! `recv_timeout` loop, the four `time.After`/`time.Timer` timeouts are
//! absolute [`Instant`] deadlines reconciled from the state machine's
//! armed flags after every mutation, and the asynchronous
//! `genTemplateAsync` goroutines collapse into a synchronous build in
//! `drain_and_build` (dcrd cancels any in-flight generation, so only
//! the last queued request matters).
//!
//! The feedback ordering matches dcrd's `genTemplateAsync` goroutine
//! body exactly: after a build, [`BgGenerator::process_generated_template`]
//! sets the current template and returns the subscriber notification
//! (dcrd's `setCurrentTemplate`), then a `TemplateUpdated` regen event
//! syncs the base block and arms the 30-second regen timer (dcrd's
//! queued `rtTemplateUpdated` running `handleTemplateUpdate`, which
//! never notifies), then the notification is fanned out to subscribers
//! and the work sink (dcrd's send on `notifySubscribers`).

use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::Params;
use dcroxide_mempool::VoteReceiver;
use dcroxide_mining::bg_generator::{
    BgGenerator, BgRegenEvent, BgTemplateState, BgTemplateUpdateReason, MAX_VOTE_TIMEOUT_MILLIS,
    MIN_VOTES_TIMEOUT_MILLIS, handle_failed_gen_retry_timeout, handle_max_votes_timeout,
    handle_regen_event, handle_regen_timer_expired, handle_track_side_chains_timeout,
};
use dcroxide_mining::{BlkTmplGenerator, ExtraNonces, MiningPolicy, TemplateChain};
use dcroxide_rpc::server::{RpcBlockTemplater, RpcTemplateSubscription, TemplateRecv};
use dcroxide_txscript::stdaddr::Address;
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx};

use crate::mining::{NodeTemplateChain, NodeTemplateTxSource};
use crate::txmempool::{NodeTxPool, now_unix};
use crate::websocket::{NodeNtfnMgr, TemplateUpdateReason};

/// The duration the failed-generation retry timeout is armed with
/// (dcrd `handleTemplateUpdate` arming `failedGenRetryTimeout` with
/// `time.After(time.Second)`).
const FAILED_GEN_RETRY_MILLIS: u64 = 1000;

/// The wait used when no timer is armed, so the thread blocks on the
/// command channel until an event arrives (dcrd's regen handler blocks
/// on the select with no active timeout in that case).
const IDLE_WAIT: Duration = Duration::from_secs(3600);

/// The known-template timeout the getwork subscription waits with
/// (dcrd rpcserver `maxTemplateTimeoutDuration = time.Millisecond *
/// 5500`).
const MAX_TEMPLATE_TIMEOUT: Duration = Duration::from_millis(5500);

/// An owned regen event carried over the command channel (the owned
/// counterpart of [`BgRegenEvent`], which borrows its block and vote
/// data); the thread borrows it back into a [`BgRegenEvent`] before
/// running the state machine.
enum OwnedRegenEvent {
    /// A chain reorganization started (dcrd `rtReorgStarted`).
    ReorgStarted,
    /// A chain reorganization finished (dcrd `rtReorgDone`).
    ReorgDone,
    /// A block was connected to the main chain.
    BlockConnected(MsgBlock),
    /// A block was disconnected from the main chain.
    BlockDisconnected(MsgBlock),
    /// A block was accepted to the block index.
    BlockAccepted(MsgBlock),
    /// A vote was received.
    Vote(MsgTx),
}

/// A command for the generator thread (dcrd's `regenEvent` sends plus
/// the context cancellation the regen handler selects on).
enum GenCommand {
    /// A regen event to feed the state machine (boxed to keep the
    /// command's variants balanced in size).
    Event(Box<OwnedRegenEvent>),
    /// A forced regeneration request (dcrd `ForceRegen`).
    ForceRegen,
    /// Wind the thread down.
    Stop,
}

/// The cheap cloneable feeder the chain handler and the mempool vote
/// hook hold (dcrd's `BlockConnected`, `BlockDisconnected`,
/// `BlockAccepted`, `ChainReorgStarted`, `ChainReorgDone`,
/// `VoteReceived`, and `ForceRegen` methods; a send after shutdown is
/// absorbed like dcrd's quit-guarded channel sends).
#[derive(Clone)]
pub struct GeneratorSink {
    sender: mpsc::Sender<GenCommand>,
}

impl GeneratorSink {
    /// A block was accepted to the block index (dcrd `BlockAccepted`).
    pub fn block_accepted(&self, block: MsgBlock) {
        let _ = self
            .sender
            .send(GenCommand::Event(Box::new(OwnedRegenEvent::BlockAccepted(
                block,
            ))));
    }

    /// A block was connected to the main chain (dcrd
    /// `BlockConnected`).
    pub fn block_connected(&self, block: MsgBlock) {
        let _ = self.sender.send(GenCommand::Event(Box::new(
            OwnedRegenEvent::BlockConnected(block),
        )));
    }

    /// A block was disconnected from the main chain (dcrd
    /// `BlockDisconnected`).
    pub fn block_disconnected(&self, block: MsgBlock) {
        let _ = self.sender.send(GenCommand::Event(Box::new(
            OwnedRegenEvent::BlockDisconnected(block),
        )));
    }

    /// A chain reorganization started (dcrd `ChainReorgStarted`).
    pub fn chain_reorg_started(&self) {
        let _ = self
            .sender
            .send(GenCommand::Event(Box::new(OwnedRegenEvent::ReorgStarted)));
    }

    /// A chain reorganization finished (dcrd `ChainReorgDone`).
    pub fn chain_reorg_done(&self) {
        let _ = self
            .sender
            .send(GenCommand::Event(Box::new(OwnedRegenEvent::ReorgDone)));
    }

    /// A vote was accepted into the mempool (dcrd `VoteReceived`).
    pub fn vote_received(&self, vote: MsgTx) {
        let _ = self
            .sender
            .send(GenCommand::Event(Box::new(OwnedRegenEvent::Vote(vote))));
    }

    /// Generate a new template immediately (dcrd `ForceRegen`).
    pub fn force_regen(&self) {
        let _ = self.sender.send(GenCommand::ForceRegen);
    }
}

/// The current template state the getwork RPC reads (the concurrent
/// snapshot dcrd's `CurrentTemplate` returns behind `templateMtx`).
#[derive(Clone, Default)]
pub struct SharedTemplate {
    /// The current template block, `None` while errored, cleared, or
    /// not yet generated.
    block: Option<MsgBlock>,
    /// The error associated with the current template, if any (dcrd
    /// `templateErr`).
    err: Option<String>,
    /// Whether the chain is reorganizing, during which the getwork RPC
    /// reports no work (dcrd `CurrentTemplate` blocks on the stale
    /// template wait group; the port reports `Ok(None)`).
    reorganizing: bool,
}

/// The subscriber registry the thread broadcasts each new template
/// block through (dcrd's `notifySubscribersHandler` fanning template
/// notifications out to every `TemplateSubscription`).
#[derive(Default)]
pub struct SubscriberRegistry {
    next_id: u64,
    subscribers: HashMap<u64, mpsc::Sender<MsgBlock>>,
}

impl SubscriberRegistry {
    /// Register a new subscription channel, returning its id (dcrd
    /// `Subscribe` adding to the subscription map).
    fn register(&mut self, sender: mpsc::Sender<MsgBlock>) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.subscribers.insert(id, sender);
        id
    }

    /// Deregister a subscription channel (dcrd `TemplateSubscription`
    /// `Stop` removing itself from the subscription map).
    fn deregister(&mut self, id: u64) {
        self.subscribers.remove(&id);
    }

    /// Broadcast the template block to every subscriber, dropping any
    /// whose receiver is gone (dcrd's non-blocking sends over each
    /// subscription channel).
    fn broadcast(&mut self, block: &MsgBlock) {
        self.subscribers
            .retain(|_, sender| sender.send(block.clone()).is_ok());
    }
}

/// The absolute [`Instant`] deadlines the thread reconstructs from the
/// state machine's armed flags: the regen handler's four `time.After`/
/// `time.Timer` timeouts.
#[derive(Default)]
struct TimerDeadlines {
    /// The periodic regeneration timer (dcrd `regenTimer`).
    regen: Option<Instant>,
    /// The millisecond duration the regen deadline was computed from,
    /// so a reset to a different duration recomputes it.
    regen_millis: u64,
    /// The max-votes propagation timeout (dcrd `maxVotesTimeout`).
    max_votes: Option<Instant>,
    /// The side chain tracking timeout (dcrd `trackSideChainsTimeout`).
    track_side_chains: Option<Instant>,
    /// The failed-generation retry timeout (dcrd
    /// `failedGenRetryTimeout`).
    failed_gen_retry: Option<Instant>,
}

/// Which timer fired.
enum FiredTimer {
    Regen,
    MaxVotes,
    TrackSideChains,
    FailedGenRetry,
}

/// A deadline in the future from now (dcrd's `time.After`/`Reset`);
/// arithmetic is checked to satisfy the crate's overflow lint.
fn deadline_from_now(millis: u64) -> Instant {
    Instant::now()
        .checked_add(Duration::from_millis(millis))
        .expect("timer deadline")
}

/// Reconcile the timer deadlines from the state machine's armed flags
/// after a mutation: newly-armed flags record a fresh deadline (the
/// regen timer additionally recomputes when its duration changed, per
/// dcrd's `regenTimer.Reset`), and disarmed flags clear theirs.
///
/// `rearmed_fixed` handles dcrd's fresh `time.After` on each arm of the
/// fixed-duration max-votes and side-chain timeouts.  The state machine
/// arms both only inside `handleBlockConnected` (the side-chain timeout
/// is cleared then possibly re-armed there; the max-votes timeout can
/// be re-armed while still armed from a prior tip within the window),
/// so a block-connected event resets both deadlines when they end
/// armed.  It is deliberately not set for vote events: a vote arms the
/// max-votes timeout only from the disarmed min-votes-reached path
/// (handled by the newly-armed case), while the common vote-collection
/// path leaves it armed without re-arming — resetting there would defer
/// the propagation timeout indefinitely.  The failed-generation retry
/// is never re-armed while armed (dcrd guards it with a nil check), so
/// the newly-armed case suffices for it.
fn reconcile_timers(deadlines: &mut TimerDeadlines, state: &BgTemplateState, rearmed_fixed: bool) {
    if state.regen_timer_armed {
        if deadlines.regen.is_none() || deadlines.regen_millis != state.regen_timer_millis {
            deadlines.regen = Some(deadline_from_now(state.regen_timer_millis));
            deadlines.regen_millis = state.regen_timer_millis;
        }
    } else {
        deadlines.regen = None;
        deadlines.regen_millis = 0;
    }

    if state.max_votes_timeout_armed {
        if deadlines.max_votes.is_none() || rearmed_fixed {
            deadlines.max_votes = Some(deadline_from_now(MAX_VOTE_TIMEOUT_MILLIS));
        }
    } else {
        deadlines.max_votes = None;
    }

    if state.track_side_chains_timeout_armed {
        if deadlines.track_side_chains.is_none() || rearmed_fixed {
            deadlines.track_side_chains = Some(deadline_from_now(MIN_VOTES_TIMEOUT_MILLIS));
        }
    } else {
        deadlines.track_side_chains = None;
    }

    if state.failed_gen_retry_timeout_armed {
        if deadlines.failed_gen_retry.is_none() {
            deadlines.failed_gen_retry = Some(deadline_from_now(FAILED_GEN_RETRY_MILLIS));
        }
    } else {
        deadlines.failed_gen_retry = None;
    }
}

/// The nearest armed deadline and which timer it belongs to.
fn nearest_deadline(deadlines: &TimerDeadlines) -> Option<(Instant, FiredTimer)> {
    let mut nearest: Option<(Instant, FiredTimer)> = None;
    let mut consider = |at: Option<Instant>, which: FiredTimer| {
        if let Some(at) = at
            && nearest.as_ref().is_none_or(|(best, _)| at < *best)
        {
            nearest = Some((at, which));
        }
    };
    consider(deadlines.regen, FiredTimer::Regen);
    consider(deadlines.max_votes, FiredTimer::MaxVotes);
    consider(deadlines.track_side_chains, FiredTimer::TrackSideChains);
    consider(deadlines.failed_gen_retry, FiredTimer::FailedGenRetry);
    nearest
}

/// Map the generator's template update reason to the websocket work
/// notification reason (dcrd's `TemplateUpdateReason` shared between
/// the mining and rpcserver packages).  The unknown reason — produced
/// by a forced regeneration — still notifies work clients as "unknown"
/// (dcrd `updateReasonToWorkNtfnString`), so a successful build always
/// notifies.
fn map_reason(reason: BgTemplateUpdateReason) -> TemplateUpdateReason {
    match reason {
        BgTemplateUpdateReason::NewParent => TemplateUpdateReason::NewParent,
        BgTemplateUpdateReason::NewVotes => TemplateUpdateReason::NewVotes,
        BgTemplateUpdateReason::NewTxns => TemplateUpdateReason::NewTxns,
        BgTemplateUpdateReason::Unknown => TemplateUpdateReason::Unknown,
    }
}

/// A uniformly-drawn index into the mining addresses (dcrd's
/// `rand.IntN(len(g.cfg.MiningAddrs))`); the modulo is over the
/// non-empty address slice length.
#[allow(clippy::arithmetic_side_effects)]
fn rand_index(len: usize) -> usize {
    let mut buf = [0u8; 8];
    getrandom::fill(&mut buf).expect("system random source");
    (u64::from_le_bytes(buf) % len as u64) as usize
}

/// A random extra nonce (dcrd injects random coinbase and treasurybase
/// extra nonces before each template generation).
fn rand_nonce() -> u64 {
    let mut buf = [0u8; 8];
    getrandom::fill(&mut buf).expect("system random source");
    u64::from_le_bytes(buf)
}

/// The shared handles and configuration the thread's build path needs,
/// grouped to keep [`drain_and_build`]'s signature manageable.
struct BuildCtx {
    chain: Arc<Mutex<Chain>>,
    pool: Arc<Mutex<NodeTxPool>>,
    params: Params,
    policy: MiningPolicy,
    mining_addrs: Vec<Address>,
    mining_time_offset: i64,
    allow_unsynced_mining: bool,
    current: Arc<Mutex<SharedTemplate>>,
    subscribers: Arc<Mutex<SubscriberRegistry>>,
    ntfn: Option<NodeNtfnMgr>,
}

/// Run the last queued generation request, mirroring dcrd's
/// `genTemplateAsync` goroutine: dcrd cancels any in-flight generation
/// so only the final request matters.  Builds the template, feeds the
/// results back through the state machine in dcrd's order, publishes
/// the current template, and fans any resulting notification out to
/// the subscribers and the work sink.
fn drain_and_build(
    ctx: &BuildCtx,
    g: &mut BgGenerator,
    state: &mut BgTemplateState,
    deadlines: &mut TimerDeadlines,
) {
    let requests = core::mem::take(&mut g.gen_requests);
    let Some(request) = requests.into_iter().last() else {
        return;
    };

    // Pick a mining address at random and generate a template paying
    // to it (dcrd `payToAddr := g.cfg.MiningAddrs[rand.IntN(len)]`).
    let pay_addr = if ctx.mining_addrs.is_empty() {
        None
    } else {
        Some(&ctx.mining_addrs[rand_index(ctx.mining_addrs.len())])
    };
    let nonces = ExtraNonces {
        coinbase: rand_nonce(),
        treasury: rand_nonce(),
    };

    // A fresh builder per generation over cheap Arc-backed clones,
    // sidestepping the builder's borrow of the parameters.
    let mut builder = BlkTmplGenerator::new(
        ctx.policy.clone(),
        &ctx.params,
        NodeTemplateChain::new(Arc::clone(&ctx.chain), ctx.params.clone()),
        NodeTemplateTxSource::new(Arc::clone(&ctx.pool)),
        ctx.mining_time_offset,
    );
    let (template, err) = match builder.new_block_template(pay_addr, &nonces) {
        Ok(template) => (template, None),
        Err(e) => (None, Some(e)),
    };
    drop(builder);

    // Set the current template and obtain the subscriber notification
    // (dcrd `setCurrentTemplate`), then feed the queued template-update
    // event to sync the base block and arm the regen timer (dcrd's
    // `rtTemplateUpdated` running `handleTemplateUpdate`, which never
    // notifies).
    let notification = g.process_generated_template(
        template,
        request.reason,
        err.clone(),
        request.block_retrieval,
    );
    let built = g.template.clone();
    let now = now_unix();
    let is_current = ctx.allow_unsynced_mining
        || ctx
            .chain
            .lock()
            .expect("chain mutex poisoned")
            .is_current_at(now);
    {
        let mut chain = NodeTemplateChain::new(Arc::clone(&ctx.chain), ctx.params.clone());
        let tx_source = NodeTemplateTxSource::new(Arc::clone(&ctx.pool));
        handle_regen_event(
            g,
            state,
            &mut chain,
            &tx_source,
            BgRegenEvent::TemplateUpdated(built.as_ref(), err.is_some()),
            is_current,
            now,
        );
    }
    // The template-update feed re-arms only the variable regen timer,
    // never the fixed-duration timeouts, so no fixed re-arm applies.
    reconcile_timers(deadlines, state, false);

    // Publish the current template for the getwork RPC.
    {
        let mut current = ctx.current.lock().expect("shared template poisoned");
        current.block = g.template.as_ref().map(|t| t.block.clone());
        current.err = g.template_err.clone();
        current.reorganizing = state.is_reorganizing;
    }

    // Fan the notification out to the subscribers and the websocket
    // work sink (dcrd's send on `notifySubscribers`).
    if let Some((template, reason)) = notification {
        ctx.subscribers
            .lock()
            .expect("subscriber registry poisoned")
            .broadcast(&template.block);
        if let Some(ntfn) = &ctx.ntfn {
            ntfn.notify_work(template.block.clone(), map_reason(reason));
        }
    }
}

/// Feed one regen event through the state machine and rebuild
/// (mirroring dcrd's `handleRegenEvent` followed by any queued
/// `genTemplateAsync`).
fn process_event(
    ctx: &BuildCtx,
    g: &mut BgGenerator,
    state: &mut BgTemplateState,
    deadlines: &mut TimerDeadlines,
    event: &OwnedRegenEvent,
) {
    let now = now_unix();
    let is_current = ctx.allow_unsynced_mining
        || ctx
            .chain
            .lock()
            .expect("chain mutex poisoned")
            .is_current_at(now);
    {
        let mut chain = NodeTemplateChain::new(Arc::clone(&ctx.chain), ctx.params.clone());
        let tx_source = NodeTemplateTxSource::new(Arc::clone(&ctx.pool));
        let borrowed = match event {
            OwnedRegenEvent::ReorgStarted => BgRegenEvent::ReorgStarted,
            OwnedRegenEvent::ReorgDone => BgRegenEvent::ReorgDone,
            OwnedRegenEvent::BlockConnected(block) => BgRegenEvent::BlockConnected(block),
            OwnedRegenEvent::BlockDisconnected(block) => BgRegenEvent::BlockDisconnected(block),
            OwnedRegenEvent::BlockAccepted(block) => BgRegenEvent::BlockAccepted(block),
            OwnedRegenEvent::Vote(vote) => BgRegenEvent::Vote(vote),
        };
        handle_regen_event(g, state, &mut chain, &tx_source, borrowed, is_current, now);
    }
    // A block-connected event re-arms the fixed-duration timeouts with
    // a fresh countdown (dcrd's `time.After` in `handleBlockConnected`).
    let rearmed_fixed = matches!(event, OwnedRegenEvent::BlockConnected(_));
    reconcile_timers(deadlines, state, rearmed_fixed);
    // The reorg-started and reorg-done events flip the reorganizing
    // flag; surface it so the getwork RPC reports no work during a
    // reorg even before the next build publishes the template.
    ctx.current
        .lock()
        .expect("shared template poisoned")
        .reorganizing = state.is_reorganizing;
    drain_and_build(ctx, g, state, deadlines);
}

/// Feed a force-regeneration request through the state machine and
/// rebuild (dcrd's `rtForceRegen` running `handleForceRegen`).
fn process_force_regen(
    ctx: &BuildCtx,
    g: &mut BgGenerator,
    state: &mut BgTemplateState,
    deadlines: &mut TimerDeadlines,
) {
    let now = now_unix();
    let is_current = ctx.allow_unsynced_mining
        || ctx
            .chain
            .lock()
            .expect("chain mutex poisoned")
            .is_current_at(now);
    {
        let mut chain = NodeTemplateChain::new(Arc::clone(&ctx.chain), ctx.params.clone());
        let tx_source = NodeTemplateTxSource::new(Arc::clone(&ctx.pool));
        handle_regen_event(
            g,
            state,
            &mut chain,
            &tx_source,
            BgRegenEvent::ForceRegen,
            is_current,
            now,
        );
    }
    // A forced regeneration never arms the fixed-duration timeouts.
    reconcile_timers(deadlines, state, false);
    drain_and_build(ctx, g, state, deadlines);
}

/// Run the fired timer's handler and rebuild (the corresponding select
/// arms of dcrd's `regenHandler`).
fn process_timer(
    ctx: &BuildCtx,
    g: &mut BgGenerator,
    state: &mut BgTemplateState,
    deadlines: &mut TimerDeadlines,
    fired: FiredTimer,
) {
    match fired {
        FiredTimer::Regen => {
            deadlines.regen = None;
            deadlines.regen_millis = 0;
            let last_updated = ctx
                .pool
                .lock()
                .expect("tx pool mutex poisoned")
                .last_updated_unix();
            handle_regen_timer_expired(g, state, last_updated);
        }
        FiredTimer::MaxVotes => {
            deadlines.max_votes = None;
            handle_max_votes_timeout(g, state);
        }
        FiredTimer::TrackSideChains => {
            deadlines.track_side_chains = None;
            // The select arm disarms the timeout before invoking.
            state.track_side_chains_timeout_armed = false;
            let mut chain = NodeTemplateChain::new(Arc::clone(&ctx.chain), ctx.params.clone());
            let tx_source = NodeTemplateTxSource::new(Arc::clone(&ctx.pool));
            handle_track_side_chains_timeout(g, state, &mut chain, &tx_source);
        }
        FiredTimer::FailedGenRetry => {
            deadlines.failed_gen_retry = None;
            handle_failed_gen_retry_timeout(g, state);
        }
    }
    // No timer-fire handler re-arms a fixed-duration timeout.
    reconcile_timers(deadlines, state, false);
    drain_and_build(ctx, g, state, deadlines);
}

/// The running generator thread and the handles the RPC serving reads.
pub struct Generator {
    sink: GeneratorSink,
    current: Arc<Mutex<SharedTemplate>>,
    subscribers: Arc<Mutex<SubscriberRegistry>>,
    thread: Option<JoinHandle<()>>,
}

impl Generator {
    /// The cloneable feeder handle (dcrd's `BgBlkTmplGenerator`
    /// methods).
    pub fn sink(&self) -> GeneratorSink {
        self.sink.clone()
    }

    /// The current-template handle the getwork RPC reads.
    pub fn current_handle(&self) -> Arc<Mutex<SharedTemplate>> {
        Arc::clone(&self.current)
    }

    /// The subscriber registry the getwork RPC subscribes through.
    pub fn subscribers_handle(&self) -> Arc<Mutex<SubscriberRegistry>> {
        Arc::clone(&self.subscribers)
    }

    /// Wind the thread down and wait for it (the context cancellation
    /// dcrd's handlers select on).
    pub fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        let _ = self.sink.sender.send(GenCommand::Stop);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Generator {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Run the chain handler's deferred-maintenance drain hook if one is
/// installed (a cheap no-op that takes empty queues when no reorg
/// occurred).
fn run_drain(drain_hook: &Option<Box<dyn Fn() + Send>>) {
    if let Some(hook) = drain_hook {
        hook();
    }
}

/// Start the background template generator thread over the daemon's
/// live chain and mempool (dcrd `newServer` constructing the
/// `BgBlkTmplGenerator` and `server.Run` launching its handlers).
///
/// `drain_hook` runs the chain notification handler's deferred
/// maintenance after every processed event and timer.  A reorg the
/// generator itself starts (`force_head_reorganization` from a vote or
/// the side-chain timeout) fires the chain callback synchronously on
/// this thread, which only queues; the sync adapter's post-process
/// drain never covers those reorgs, so the hook drives the drain
/// directly (dcrd runs the handler inline with the chain lock free).
#[allow(clippy::too_many_arguments)]
pub fn start_generator(
    chain: Arc<Mutex<Chain>>,
    tx_pool: Arc<Mutex<NodeTxPool>>,
    params: Params,
    mining_addrs: Vec<Address>,
    policy: MiningPolicy,
    mining_time_offset: i64,
    allow_unsynced_mining: bool,
    ntfn: Option<NodeNtfnMgr>,
    drain_hook: Option<Box<dyn Fn() + Send>>,
) -> Generator {
    let (sender, receiver) = mpsc::channel();
    let current = Arc::new(Mutex::new(SharedTemplate::default()));
    let subscribers = Arc::new(Mutex::new(SubscriberRegistry::default()));

    let thread_current = Arc::clone(&current);
    let thread_subscribers = Arc::clone(&subscribers);
    let thread = std::thread::spawn(move || {
        let mut g = BgGenerator::new(
            params.tickets_per_block,
            params.stake_validation_height,
            allow_unsynced_mining,
        );
        let mut state = BgTemplateState::new();
        let mut deadlines = TimerDeadlines::default();
        let ctx = BuildCtx {
            chain,
            pool: tx_pool,
            params,
            policy,
            mining_addrs,
            mining_time_offset,
            allow_unsynced_mining,
            current: thread_current,
            subscribers: thread_subscribers,
            ntfn,
        };

        // dcrd's initial startup handler waits for the chain to be
        // current before generating templates, then injects the tip as
        // a synthetic block-connected event to prime the state machine.
        if !allow_unsynced_mining {
            loop {
                let now = now_unix();
                if ctx
                    .chain
                    .lock()
                    .expect("chain mutex poisoned")
                    .is_current_at(now)
                {
                    break;
                }
                match receiver.recv_timeout(Duration::from_secs(1)) {
                    Ok(GenCommand::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    // Events before the chain is current are dropped;
                    // the tip inject below reflects the current state.
                    Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
        }

        // Treat the current tip as just connected (dcrd's startup
        // `rtBlockConnected` inject).
        {
            let tip_chain = NodeTemplateChain::new(Arc::clone(&ctx.chain), ctx.params.clone());
            let best = tip_chain.best_snapshot();
            match tip_chain.block_by_hash(&best.hash) {
                Err(err) => {
                    g.set_current_template(
                        None,
                        BgTemplateUpdateReason::Unknown,
                        Some(err.clone()),
                    );
                    let mut current = ctx.current.lock().expect("shared template poisoned");
                    current.block = None;
                    current.err = Some(err);
                    current.reorganizing = false;
                }
                Ok(tip_block) => {
                    process_event(
                        &ctx,
                        &mut g,
                        &mut state,
                        &mut deadlines,
                        &OwnedRegenEvent::BlockConnected(tip_block),
                    );
                }
            }
        }
        run_drain(&drain_hook);
        // A settling pass over the deadlines; the tip inject above
        // already reconciled, so nothing is re-armed here.
        reconcile_timers(&mut deadlines, &state, false);

        loop {
            let wait = match nearest_deadline(&deadlines) {
                Some((at, _)) => at.saturating_duration_since(Instant::now()),
                None => IDLE_WAIT,
            };
            match receiver.recv_timeout(wait) {
                Ok(GenCommand::Event(event)) => {
                    process_event(&ctx, &mut g, &mut state, &mut deadlines, event.as_ref());
                }
                Ok(GenCommand::ForceRegen) => {
                    process_force_regen(&ctx, &mut g, &mut state, &mut deadlines);
                }
                Ok(GenCommand::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // The nearest deadline elapsed; fire its handler.
                    if let Some((_, fired)) = nearest_deadline(&deadlines) {
                        process_timer(&ctx, &mut g, &mut state, &mut deadlines, fired);
                    }
                }
            }
            // Drive the chain handler's deferred maintenance for any
            // reorg this event or timer initiated on the chain.
            run_drain(&drain_hook);
        }
    });

    Generator {
        sink: GeneratorSink { sender },
        current,
        subscribers,
        thread: Some(thread),
    }
}

/// The mempool vote hook forwarding accepted votes to the generator
/// (dcrd's mempool `OnVoteReceived` calling `s.bg.VoteReceived`).
pub struct NodeVoteReceiver {
    sink: GeneratorSink,
}

impl NodeVoteReceiver {
    /// A vote receiver feeding the given generator.
    pub fn new(sink: GeneratorSink) -> NodeVoteReceiver {
        NodeVoteReceiver { sink }
    }
}

impl VoteReceiver for NodeVoteReceiver {
    fn vote_received(&mut self, vote: &MsgTx) {
        self.sink.vote_received(vote.clone());
    }
}

/// The RPC block templater seam over the running generator (dcrd's
/// rpcserver config `BlockTemplater` backed by `s.bg`).
pub struct NodeRpcBlockTemplater {
    current: Arc<Mutex<SharedTemplate>>,
    subscribers: Arc<Mutex<SubscriberRegistry>>,
    sink: GeneratorSink,
    chain: Arc<Mutex<Chain>>,
    pool: Arc<Mutex<NodeTxPool>>,
    params: Params,
    policy: MiningPolicy,
    mining_time_offset: i64,
}

impl NodeRpcBlockTemplater {
    /// Adapt the running generator for the getwork RPC.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        current: Arc<Mutex<SharedTemplate>>,
        subscribers: Arc<Mutex<SubscriberRegistry>>,
        sink: GeneratorSink,
        chain: Arc<Mutex<Chain>>,
        pool: Arc<Mutex<NodeTxPool>>,
        params: Params,
        policy: MiningPolicy,
        mining_time_offset: i64,
    ) -> NodeRpcBlockTemplater {
        NodeRpcBlockTemplater {
            current,
            subscribers,
            sink,
            chain,
            pool,
            params,
            policy,
            mining_time_offset,
        }
    }
}

impl RpcBlockTemplater for NodeRpcBlockTemplater {
    fn force_regen(&mut self) {
        self.sink.force_regen();
    }

    fn current_template(&mut self) -> Result<Option<MsgBlock>, String> {
        let current = self.current.lock().expect("shared template poisoned");
        if current.reorganizing {
            return Ok(None);
        }
        if let Some(err) = &current.err {
            return Err(err.clone());
        }
        Ok(current.block.clone())
    }

    fn subscribe(&mut self) -> Box<dyn RpcTemplateSubscription + Send> {
        let (sender, receiver) = mpsc::channel();
        // Register the subscription before delivering the current
        // template so a broadcast racing between registration and
        // delivery reaches the new subscriber rather than being lost
        // (dcrd registers into `g.subscriptions` before reading the
        // current template in `Subscribe`).
        let id = self
            .subscribers
            .lock()
            .expect("subscriber registry poisoned")
            .register(sender.clone());
        // Immediately deliver the current template under the same gate
        // the getwork current-template read uses: skip it during a
        // reorganization or when the template errored, so a stale
        // orphan-parent template is never handed out (dcrd `Subscribe`
        // delivers `currentTemplate()`).
        {
            let current = self.current.lock().expect("shared template poisoned");
            if !current.reorganizing
                && current.err.is_none()
                && let Some(block) = &current.block
            {
                let _ = sender.send(block.clone());
            }
        }
        Box::new(NodeTemplateSubscription {
            id,
            receiver,
            subscribers: Arc::clone(&self.subscribers),
        })
    }

    fn update_block_time(&mut self, header: &mut BlockHeader) {
        // A throwaway builder over the live chain, as in the generator
        // thread (dcrd `UpdateBlockTime` = `g.tg.UpdateBlockTime`).
        let builder = BlkTmplGenerator::new(
            self.policy.clone(),
            &self.params,
            NodeTemplateChain::new(Arc::clone(&self.chain), self.params.clone()),
            NodeTemplateTxSource::new(Arc::clone(&self.pool)),
            self.mining_time_offset,
        );
        builder.update_block_time(header);
    }
}

/// A getwork template subscription over one registry channel (dcrd's
/// `TemplateSubscription`).
pub struct NodeTemplateSubscription {
    id: u64,
    receiver: mpsc::Receiver<MsgBlock>,
    subscribers: Arc<Mutex<SubscriberRegistry>>,
}

impl RpcTemplateSubscription for NodeTemplateSubscription {
    fn recv(&mut self) -> TemplateRecv {
        match self.receiver.recv() {
            Ok(block) => TemplateRecv::Template(Box::new(block)),
            Err(_) => TemplateRecv::Canceled,
        }
    }

    fn recv_with_timeout(&mut self) -> TemplateRecv {
        match self.receiver.recv_timeout(MAX_TEMPLATE_TIMEOUT) {
            Ok(block) => TemplateRecv::Template(Box::new(block)),
            Err(mpsc::RecvTimeoutError::Timeout) => TemplateRecv::Timeout,
            Err(mpsc::RecvTimeoutError::Disconnected) => TemplateRecv::Canceled,
        }
    }

    fn stop(&mut self) {
        self.subscribers
            .lock()
            .expect("subscriber registry poisoned")
            .deregister(self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The generator's seams move across the thread boundary and back
    /// into the RPC server behind a mutex.
    #[test]
    fn generator_seams_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<GeneratorSink>();
        assert_send::<Generator>();
        assert_send::<NodeVoteReceiver>();
        assert_send::<NodeRpcBlockTemplater>();
        assert_send::<NodeTemplateSubscription>();
    }

    /// The reason mapping matches dcrd's shared reason enum, including
    /// the unknown reason a forced regeneration produces (dcrd still
    /// notifies work clients for it).
    #[test]
    fn map_reason_matches_dcrd() {
        assert_eq!(
            map_reason(BgTemplateUpdateReason::NewParent),
            TemplateUpdateReason::NewParent
        );
        assert_eq!(
            map_reason(BgTemplateUpdateReason::NewVotes),
            TemplateUpdateReason::NewVotes
        );
        assert_eq!(
            map_reason(BgTemplateUpdateReason::NewTxns),
            TemplateUpdateReason::NewTxns
        );
        assert_eq!(
            map_reason(BgTemplateUpdateReason::Unknown),
            TemplateUpdateReason::Unknown
        );
    }

    /// The deadlines reconcile from the state machine's armed flags:
    /// arming records a deadline, a regen reset to a new duration
    /// recomputes it, and disarming clears it.
    #[test]
    fn timers_reconcile_from_armed_flags() {
        let mut state = BgTemplateState::new();
        let mut deadlines = TimerDeadlines::default();

        // Nothing armed: no deadlines.
        reconcile_timers(&mut deadlines, &state, false);
        assert!(nearest_deadline(&deadlines).is_none());

        // Arm the regen timer at 30 seconds and each fixed timeout.
        state.regen_timer_armed = true;
        state.regen_timer_millis = 30_000;
        state.max_votes_timeout_armed = true;
        state.track_side_chains_timeout_armed = true;
        state.failed_gen_retry_timeout_armed = true;
        reconcile_timers(&mut deadlines, &state, false);
        assert!(deadlines.regen.is_some());
        assert_eq!(deadlines.regen_millis, 30_000);
        assert!(deadlines.max_votes.is_some());
        assert!(deadlines.track_side_chains.is_some());
        assert!(deadlines.failed_gen_retry.is_some());
        // The failed-gen-retry timeout is the nearest at 1 second.
        assert!(matches!(
            nearest_deadline(&deadlines),
            Some((_, FiredTimer::FailedGenRetry))
        ));

        // Resetting the regen timer to a shorter duration recomputes
        // its deadline.
        let before = deadlines.regen.expect("regen armed");
        state.regen_timer_millis = 1_000;
        reconcile_timers(&mut deadlines, &state, false);
        assert_eq!(deadlines.regen_millis, 1_000);
        assert!(deadlines.regen.expect("regen armed") < before);

        // A fixed-timer re-arm (a block-connected event) resets the
        // max-votes and side-chain deadlines to a fresh countdown even
        // though they were already armed, while a plain reconcile keeps
        // them.
        let max_votes_before = deadlines.max_votes.expect("max votes armed");
        std::thread::sleep(std::time::Duration::from_millis(2));
        reconcile_timers(&mut deadlines, &state, false);
        assert_eq!(
            deadlines.max_votes.expect("max votes armed"),
            max_votes_before,
            "a non-rearming reconcile keeps the max-votes deadline"
        );
        reconcile_timers(&mut deadlines, &state, true);
        assert!(
            deadlines.max_votes.expect("max votes armed") > max_votes_before,
            "a fixed re-arm resets the max-votes deadline forward"
        );

        // Disarming clears the deadlines.
        state.regen_timer_armed = false;
        state.max_votes_timeout_armed = false;
        state.track_side_chains_timeout_armed = false;
        state.failed_gen_retry_timeout_armed = false;
        reconcile_timers(&mut deadlines, &state, false);
        assert!(nearest_deadline(&deadlines).is_none());
        assert_eq!(deadlines.regen_millis, 0);
    }
}
