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
//! (`GenCommand`), the regen handler goroutine is the thread's
//! `recv_timeout` loop, the four `time.After`/`time.Timer` timeouts are
//! absolute [`Instant`] deadlines reconciled from the state machine's
//! armed flags after every mutation, and the asynchronous
//! `genTemplateAsync` goroutines collapse into a synchronous build in
//! `drain_and_build`.
//!
//! dcrd's regen handler keeps running while a generation goroutine
//! builds, and a later `genTemplateAsync` cancels that goroutine, which
//! then neither sets the current template nor notifies.  The thread
//! cannot service events mid-build, so when a build returns, every
//! command and timer that came due during it runs through the state
//! machine *before* the result is installed.  If any of them requested
//! a new generation, the finished build is dropped as a cancelled
//! goroutine's result is and the newest request is built instead;
//! otherwise the result is installed after those events, as dcrd's
//! goroutine installs it after the handler has processed them.  That
//! covers the reorganization bracket a build's own forced
//! reorganization emits: it is serviced before the template that build
//! produced is installed, not after, where its clear would wipe it.
//! Only the timing differs: dcrd's cancelled goroutine also runs its
//! `NewBlockTemplate` to completion, but concurrently with the build
//! that replaces it, while the thread finishes it first.
//!
//! Template retrieval waits the way dcrd's `currentTemplate` waits on
//! `staleTemplateWg`: the state machine's stale-template count (raised
//! by new-parent and new-votes generations and by a reorganization,
//! released when they finish) is published with the template, and the
//! getwork reads block while it is nonzero.
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
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::Params;
use dcroxide_mempool::VoteReceiver;
use dcroxide_mining::bg_generator::{
    BgGenerator, BgRegenEvent, BgTemplateState, BgTemplateUpdateReason, GenRequest,
    MAX_VOTE_TIMEOUT_MILLIS, MIN_VOTES_TIMEOUT_MILLIS, handle_failed_gen_retry_timeout,
    handle_max_votes_timeout, handle_regen_event, handle_regen_timer_expired,
    handle_track_side_chains_timeout, set_failed_template,
};
use dcroxide_mining::{BlkTmplGenerator, ExtraNonces, MiningPolicy, TemplateChain};
use dcroxide_rpc::server::{RpcBlockTemplater, RpcTemplateSubscription, TemplateRecv};
use dcroxide_rpc::worksem::{CANCEL_POLL_INTERVAL, request_cancelled, request_is_cancellable};
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
/// running the state machine.  The blocks arrive as shared `Arc`s
/// from the chain notification fan-out, so queueing an event never
/// copies a block.
enum OwnedRegenEvent {
    /// A chain reorganization started (dcrd `rtReorgStarted`).
    ReorgStarted,
    /// A chain reorganization finished (dcrd `rtReorgDone`).
    ReorgDone,
    /// A block was connected to the main chain.
    BlockConnected(Arc<MsgBlock>),
    /// A block was disconnected from the main chain.
    BlockDisconnected(Arc<MsgBlock>),
    /// A block was accepted to the block index.
    BlockAccepted(Arc<MsgBlock>),
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
    pub fn block_accepted(&self, block: Arc<MsgBlock>) {
        let _ = self
            .sender
            .send(GenCommand::Event(Box::new(OwnedRegenEvent::BlockAccepted(
                block,
            ))));
    }

    /// A block was connected to the main chain (dcrd
    /// `BlockConnected`).
    pub fn block_connected(&self, block: Arc<MsgBlock>) {
        let _ = self.sender.send(GenCommand::Event(Box::new(
            OwnedRegenEvent::BlockConnected(block),
        )));
    }

    /// A block was disconnected from the main chain (dcrd
    /// `BlockDisconnected`).
    pub fn block_disconnected(&self, block: Arc<MsgBlock>) {
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
    /// Whether the chain is reorganizing.  A retrieval waits a
    /// reorganization out through `stale`, as dcrd's does; this flag
    /// only decides what a retrieval that stopped waiting early (its
    /// request was cancelled, or the generator is gone) reports: no
    /// work.
    reorganizing: bool,
    /// Whether template retrieval must wait (dcrd's `staleTemplateWg`
    /// is nonzero): a new-parent or new-votes generation is in flight,
    /// or a reorganization has started and not finished.
    stale: bool,
    /// Whether the generator thread has exited, after which nothing
    /// clears `stale`, so no retrieval may wait on it.
    closed: bool,
    /// Signalled on every publish, waking retrievals that wait out a
    /// stale window.
    changed: Arc<Condvar>,
}

impl SharedTemplate {
    /// Whether template retrieval currently waits for a pending
    /// template (dcrd's `staleTemplateWg` is nonzero).
    pub fn is_stale(&self) -> bool {
        self.stale
    }
}

/// Lock the mirror once dcrd's stale-template window is over (dcrd
/// `currentTemplate` calling `staleTemplateWg.Wait()` before it reads
/// the template, `bgblktmplgenerator.go:401-402`, which both
/// `CurrentTemplate` and `Subscribe` go through).
///
/// The window is a build or a reorganization, both of which end, so
/// the wait is bounded the way dcrd's is.  It also ends when the
/// generator thread is gone, and -- like the port's other template
/// waits, which dcrd's `Wait` has no counterpart for -- when the RPC
/// request is cancelled, so a client that hangs up stops holding its
/// work permit; what such a caller then reads nobody receives.
fn wait_for_current(current: &Mutex<SharedTemplate>) -> MutexGuard<'_, SharedTemplate> {
    let mut guard = current.lock().expect("shared template poisoned");
    let cancellable = request_is_cancellable();
    while guard.stale && !guard.closed {
        if cancellable && request_cancelled() {
            break;
        }
        let changed = Arc::clone(&guard.changed);
        guard = if cancellable {
            changed
                .wait_timeout(guard, CANCEL_POLL_INTERVAL)
                .expect("shared template poisoned")
                .0
        } else {
            changed.wait(guard).expect("shared template poisoned")
        };
    }
    guard
}

/// Marks the getwork mirror closed when the generator thread exits by
/// any path, so no retrieval waits on a stale window nothing will end.
struct CloseOnExit(Arc<Mutex<SharedTemplate>>);

impl Drop for CloseOnExit {
    fn drop(&mut self) {
        let mut current = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        current.closed = true;
        current.changed.notify_all();
    }
}

/// dcrd's per-subscription buffer: twice the number of regenerations
/// the votes on one parent can induce (`Subscribe`'s
/// `maxVoteInducedRegens*2`, `bgblktmplgenerator.go:503-504`).  Six on
/// mainnet, where `TicketsPerBlock` is 5 and `minVotesRequired` is 3.
fn subscription_buffer(tickets_per_block: u16) -> usize {
    let tpb = usize::from(tickets_per_block);
    // Saturating throughout so a degenerate zero cannot underflow, and
    // never zero so the channel is never a rendezvous.
    let min_votes = tpb.wrapping_div(2).saturating_add(1);
    tpb.saturating_sub(min_votes)
        .saturating_add(1)
        .saturating_mul(2)
}

/// The subscriber registry the thread broadcasts each new template
/// block through (dcrd's `notifySubscribersHandler` fanning template
/// notifications out to every `TemplateSubscription`).
#[derive(Default)]
pub struct SubscriberRegistry {
    next_id: u64,
    subscribers: HashMap<u64, mpsc::SyncSender<MsgBlock>>,
}

impl SubscriberRegistry {
    /// Register a new subscription channel, returning its id (dcrd
    /// `Subscribe` adding to the subscription map).
    fn register(&mut self, sender: mpsc::SyncSender<MsgBlock>) -> u64 {
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

    /// Broadcast the template block to every subscriber (dcrd's
    /// non-blocking sends over each subscription channel).
    ///
    /// A full buffer drops the notification and keeps the subscriber,
    /// which is dcrd's `select { case s.privC <- ntfn: default: }`
    /// (`bgblktmplgenerator.go:460-469`, whose type doc says outright
    /// that notifications are dropped to make up for slow receivers).
    /// Only a receiver that is gone deregisters -- testing `is_ok()`
    /// instead would silently drop every subscriber that is merely
    /// busy, which is worse than the unbounded queue this replaces.
    fn broadcast(&mut self, block: &MsgBlock) {
        self.subscribers.retain(|_, sender| {
            !matches!(
                sender.try_send(block.clone()),
                Err(mpsc::TrySendError::Disconnected(_))
            )
        });
    }
}

/// The absolute [`Instant`] deadlines the thread reconstructs from the
/// state machine's armed flags: the regen handler's four `time.After`/
/// `time.Timer` timeouts.
#[derive(Default)]
struct TimerDeadlines {
    /// The periodic regeneration timer (dcrd `regenTimer`).
    regen: Option<Instant>,
    /// The state machine's regen arm generation the deadline was
    /// computed for, so every reset recomputes it.
    regen_gen: u64,
    /// The max-votes propagation timeout (dcrd `maxVotesTimeout`).
    max_votes: Option<Instant>,
    /// The max-votes arm generation the deadline was computed for.
    max_votes_gen: u64,
    /// The side chain tracking timeout (dcrd `trackSideChainsTimeout`).
    track_side_chains: Option<Instant>,
    /// The side chain tracking arm generation the deadline was computed
    /// for.
    track_side_chains_gen: u64,
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

/// Reconcile the timer deadlines from the state machine after a
/// mutation.  An armed timer whose arm generation differs from the one
/// its deadline was computed for gets a fresh deadline: every dcrd arm —
/// a `time.After` assigned to the max-votes or side-chain timeout, or
/// `resetRegenTimer` — restarts the countdown, whether or not the timer
/// was already running, and nothing else touches a running one.  A
/// disarmed timer clears its deadline.  The failed-generation retry is
/// only ever armed from disarmed (dcrd guards it with a nil check), so a
/// missing deadline is its only signal.
fn reconcile_timers(deadlines: &mut TimerDeadlines, state: &BgTemplateState) {
    if state.regen_timer_armed {
        if deadlines.regen.is_none() || deadlines.regen_gen != state.regen_timer_gen {
            deadlines.regen = Some(deadline_from_now(state.regen_timer_millis));
            deadlines.regen_gen = state.regen_timer_gen;
        }
    } else {
        deadlines.regen = None;
    }

    if state.max_votes_timeout_armed {
        if deadlines.max_votes.is_none() || deadlines.max_votes_gen != state.max_votes_timeout_gen {
            deadlines.max_votes = Some(deadline_from_now(MAX_VOTE_TIMEOUT_MILLIS));
            deadlines.max_votes_gen = state.max_votes_timeout_gen;
        }
    } else {
        deadlines.max_votes = None;
    }

    if state.track_side_chains_timeout_armed {
        if deadlines.track_side_chains.is_none()
            || deadlines.track_side_chains_gen != state.track_side_chains_timeout_gen
        {
            deadlines.track_side_chains = Some(deadline_from_now(MIN_VOTES_TIMEOUT_MILLIS));
            deadlines.track_side_chains_gen = state.track_side_chains_timeout_gen;
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

/// A uniformly-drawn index into the mining addresses (dcrd
/// `rand.IntN(len(g.cfg.MiningAddrs))`,
/// `internal/mining/bgblktmplgenerator.go:728`).
///
/// From the process-wide generator, and reduced the way dcrd reduces.
/// The code this replaced took a full-width kernel draw and reduced it
/// by modulo, which is biased where `IntN` is not, and read the kernel
/// per template build -- a build a peer can drive by relaying a block
/// (`BlockConnected`) on a node started with `--miningaddr`.
fn rand_index(len: usize) -> usize {
    dcroxide_crypto::rand::int_n(len)
}

/// A random extra nonce (dcrd `rand.Uint64()` in
/// `standardCoinbaseOpReturn` and `standardTreasurybaseOpReturn`,
/// `internal/mining/mining.go:481`, `:498`).
///
/// Two of these are drawn per template build, from the same package
/// generator dcrd's mining package imports (`mining.go:20`).
fn rand_nonce() -> u64 {
    dcroxide_crypto::rand::uint64()
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
    /// The netsync is-current gate (dcrd wires `IsCurrent:
    /// s.syncManager.IsCurrent` into the generator's config).
    sync_gate: crate::sync::SyncGate,
    current: Arc<Mutex<SharedTemplate>>,
    subscribers: Arc<Mutex<SubscriberRegistry>>,
    ntfn: Option<NodeNtfnMgr>,
    /// The chain handler's deferred-maintenance drain (see
    /// [`start_generator`]).
    drain_hook: Option<Box<dyn Fn() + Send>>,
}

impl BuildCtx {
    /// The generator's `IsCurrent` callback: the netsync gate evaluated at
    /// the server's median-adjusted time, since dcrd's
    /// `SyncManager.IsCurrent` asks the chain, whose `isCurrent` reads
    /// `b.timeSource.AdjustedTime()`.  The regen timers keep the wall
    /// clock, as dcrd's `time.Now()` does.
    fn sync_is_current(&self) -> bool {
        self.sync_gate
            .is_current(&self.chain, crate::mediantime::adjusted_time_unix())
    }
}

/// Publish the generator's current template state to the getwork mirror
/// (`ctx.current`).  dcrd reads the template directly under `templateMtx`,
/// so there is no separate publish step that can be skipped; the port
/// keeps a snapshot the RPC thread reads instead, so it must be resynced
/// after every state-machine step — including the ones that change the
/// template without queuing a rebuild, such as a reorg-started event
/// clearing it or a reorg-done event awaiting votes.  Leaving the mirror
/// stale would let getwork serve a template built on an orphaned
/// pre-reorg parent.
///
/// The block is deep-copied *before* the lock is taken so the getwork
/// read path (which locks the same mirror) never contends behind a
/// whole-block clone.  dcrd swaps a `*BlockTemplate` pointer under
/// `templateMtx`; the port copies, so the copy is kept out of the
/// critical section and only a few moves happen under the lock.
///
/// The stale-template count travels with the template, and every
/// publish wakes the retrievals waiting for it to reach zero.
fn publish_current_template(
    current: &Arc<Mutex<SharedTemplate>>,
    g: &BgGenerator,
    state: &BgTemplateState,
) {
    let block = g.template.as_ref().map(|t| t.block.clone());
    let err = g.template_err.clone();
    let reorganizing = state.is_reorganizing;
    let stale = g.stale_template_count > 0;
    let mut current = current.lock().expect("shared template poisoned");
    current.block = block;
    current.err = err;
    current.reorganizing = reorganizing;
    current.stale = stale;
    current.changed.notify_all();
}

/// Build a template for the generation request (the body of dcrd's
/// `genTemplateAsync` goroutine up to `NewBlockTemplate` returning).
fn build_template(ctx: &BuildCtx) -> (Option<dcroxide_mining::BlockTemplate>, Option<String>) {
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
    match builder.new_block_template(pay_addr, &nonces) {
        Ok(template) => (template, None),
        Err(e) => (None, Some(e)),
    }
}

/// Release the stale-template hold of a generation that will never
/// install (dcrd's cancelled goroutine still runs its deferred
/// `staleTemplateWg.Done()`).
fn release_cancelled(g: &mut BgGenerator, request: &GenRequest) {
    if request.block_retrieval {
        g.stale_template_count = g.stale_template_count.saturating_sub(1);
    }
}

/// Run the queued generation requests, mirroring dcrd's
/// `genTemplateAsync` goroutines.  Builds the newest request, services
/// whatever queued up during the build, and then either drops the
/// build (a new request arrived, which in dcrd cancels the goroutine)
/// and builds again, or feeds the result back through the state
/// machine in dcrd's order, publishes the current template, and fans
/// any resulting notification out to the subscribers and the work
/// sink.
///
/// Returns `false` when a stop command arrived during a build, which
/// in dcrd cancels the goroutine before it installs anything.
fn drain_and_build(
    ctx: &BuildCtx,
    g: &mut BgGenerator,
    state: &mut BgTemplateState,
    deadlines: &mut TimerDeadlines,
    receiver: &mpsc::Receiver<GenCommand>,
) -> bool {
    loop {
        let mut requests = core::mem::take(&mut g.gen_requests);
        let Some(request) = requests.pop() else {
            // No queued generation, but the preceding event may still
            // have changed the current template (a reorg-started event
            // clears it; a reorg-done event awaiting votes rebuilds the
            // base without queuing a build), so resync the getwork
            // mirror to whatever the generator now holds rather than
            // leaving a stale pre-reorg template exposed once the
            // reorganizing flag clears.
            publish_current_template(&ctx.current, g, state);
            return true;
        };
        // The earlier requests were superseded before they could
        // start: dcrd cancelled each in turn.
        for superseded in &requests {
            release_cancelled(g, superseded);
        }

        // Publish the stale-template hold before building so retrieval
        // waits for this template (dcrd's `staleTemplateWg.Add(1)` in
        // `genTemplateAsync` precedes the goroutine).
        publish_current_template(&ctx.current, g, state);

        let (template, err) = build_template(ctx);

        // Run the chain handler's deferred maintenance for a
        // reorganization the build itself forced
        // (`force_head_reorganization` inside `new_block_template`)
        // before the events that reorganization queued are serviced.
        run_drain(&ctx.drain_hook);

        // Service what arrived while the build ran, as dcrd's regen
        // handler does concurrently with the goroutine.
        let running = service_pending(ctx, g, state, deadlines, receiver);
        if !running || !g.gen_requests.is_empty() {
            // Cancelled: dcrd's goroutine sees `ctx.Err() != nil` and
            // returns before `setCurrentTemplate` and before notifying
            // (`bgblktmplgenerator.go:737-739`).
            release_cancelled(g, &request);
            if !running {
                publish_current_template(&ctx.current, g, state);
                return false;
            }
            continue;
        }

        // Set the current template and obtain the subscriber
        // notification (dcrd `setCurrentTemplate`), then feed the
        // queued template-update event to sync the base block and arm
        // the regen timer (dcrd's `rtTemplateUpdated` running
        // `handleTemplateUpdate`, which never notifies).
        let notification = g.process_generated_template(
            template,
            request.reason,
            err.clone(),
            request.block_retrieval,
        );
        let built = g.template.clone();
        let now = now_unix();
        let is_current = ctx.allow_unsynced_mining || ctx.sync_is_current();
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
        reconcile_timers(deadlines, state);

        // Publish the current template for the getwork RPC.
        publish_current_template(&ctx.current, g, state);

        // Fan the notification out to the subscribers and the
        // websocket work sink (dcrd's send on `notifySubscribers`).
        if let Some((template, reason)) = notification {
            ctx.subscribers
                .lock()
                .expect("subscriber registry poisoned")
                .broadcast(&template.block);
            // The copy is only worth making for a connected client.
            if let Some(ntfn) = &ctx.ntfn
                && ntfn.has_clients()
            {
                ntfn.notify_work(template.block.clone(), map_reason(reason));
            }
        }
        return true;
    }
}

/// Feed the commands and timers that came due during a build through
/// the state machine without building (dcrd's regen handler servicing
/// its queue and timeouts while a generation goroutine runs).  Queued
/// commands go first, as the main loop's `recv_timeout` hands out a
/// queued command before it reports an elapsed deadline.  Returns
/// `false` on a stop command.
fn service_pending(
    ctx: &BuildCtx,
    g: &mut BgGenerator,
    state: &mut BgTemplateState,
    deadlines: &mut TimerDeadlines,
    receiver: &mpsc::Receiver<GenCommand>,
) -> bool {
    loop {
        match receiver.try_recv() {
            Ok(GenCommand::Event(event)) => step_event(ctx, g, state, deadlines, event.as_ref()),
            Ok(GenCommand::ForceRegen) => step_force_regen(ctx, g, state, deadlines),
            Ok(GenCommand::Stop) => return false,
            // A disconnected channel ends the thread at its next
            // receive; nothing more can arrive here.
            Err(mpsc::TryRecvError::Empty) | Err(mpsc::TryRecvError::Disconnected) => {
                match nearest_deadline(deadlines) {
                    Some((at, fired)) if at <= Instant::now() => {
                        step_timer(ctx, g, state, deadlines, fired);
                    }
                    _ => return true,
                }
            }
        }
        // Drive the chain handler's deferred maintenance for any
        // reorganization the step initiated, as the main loop does.
        run_drain(&ctx.drain_hook);
    }
}

/// Feed one regen event through the state machine (dcrd's
/// `handleRegenEvent`), leaving any generation it requests queued.
fn step_event(
    ctx: &BuildCtx,
    g: &mut BgGenerator,
    state: &mut BgTemplateState,
    deadlines: &mut TimerDeadlines,
    event: &OwnedRegenEvent,
) {
    finish_chain_maintenance(ctx, event);
    let now = now_unix();
    let is_current = ctx.allow_unsynced_mining || ctx.sync_is_current();
    {
        let mut chain = NodeTemplateChain::new(Arc::clone(&ctx.chain), ctx.params.clone());
        let tx_source = NodeTemplateTxSource::new(Arc::clone(&ctx.pool));
        let borrowed = match event {
            OwnedRegenEvent::ReorgStarted => BgRegenEvent::ReorgStarted,
            OwnedRegenEvent::ReorgDone => BgRegenEvent::ReorgDone,
            OwnedRegenEvent::BlockConnected(block) => BgRegenEvent::BlockConnected(block.as_ref()),
            OwnedRegenEvent::BlockDisconnected(block) => {
                BgRegenEvent::BlockDisconnected(block.as_ref())
            }
            OwnedRegenEvent::BlockAccepted(block) => BgRegenEvent::BlockAccepted(block.as_ref()),
            OwnedRegenEvent::Vote(vote) => BgRegenEvent::Vote(vote),
        };
        handle_regen_event(g, state, &mut chain, &tx_source, borrowed, is_current, now);
    }
    reconcile_timers(deadlines, state);
}

/// Feed one regen event through the state machine and rebuild
/// (mirroring dcrd's `handleRegenEvent` followed by any queued
/// `genTemplateAsync`).  Returns `false` when the thread must stop.
fn process_event(
    ctx: &BuildCtx,
    g: &mut BgGenerator,
    state: &mut BgTemplateState,
    deadlines: &mut TimerDeadlines,
    receiver: &mpsc::Receiver<GenCommand>,
    event: &OwnedRegenEvent,
) -> bool {
    step_event(ctx, g, state, deadlines, event);
    // `drain_and_build` republishes the full current-template state
    // (block, error, the reorganizing flag and the stale-template
    // hold) on every path, including the no-build path a reorg event
    // takes, so the getwork mirror always reflects the state machine
    // after this event.
    drain_and_build(ctx, g, state, deadlines, receiver)
}

/// Feed a force-regeneration request through the state machine
/// (dcrd's `rtForceRegen` running `handleForceRegen`).
fn step_force_regen(
    ctx: &BuildCtx,
    g: &mut BgGenerator,
    state: &mut BgTemplateState,
    deadlines: &mut TimerDeadlines,
) {
    let now = now_unix();
    let is_current = ctx.allow_unsynced_mining || ctx.sync_is_current();
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
    reconcile_timers(deadlines, state);
}

/// Feed a force-regeneration request through the state machine and
/// rebuild.  Returns `false` when the thread must stop.
fn process_force_regen(
    ctx: &BuildCtx,
    g: &mut BgGenerator,
    state: &mut BgTemplateState,
    deadlines: &mut TimerDeadlines,
    receiver: &mpsc::Receiver<GenCommand>,
) -> bool {
    step_force_regen(ctx, g, state, deadlines);
    drain_and_build(ctx, g, state, deadlines, receiver)
}

/// Run the fired timer's handler (the corresponding select arms of
/// dcrd's `regenHandler`).
fn step_timer(
    ctx: &BuildCtx,
    g: &mut BgGenerator,
    state: &mut BgTemplateState,
    deadlines: &mut TimerDeadlines,
    fired: FiredTimer,
) {
    match fired {
        FiredTimer::Regen => {
            deadlines.regen = None;
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
    reconcile_timers(deadlines, state);
}

/// Run the fired timer's handler and rebuild.  Returns `false` when
/// the thread must stop.
fn process_timer(
    ctx: &BuildCtx,
    g: &mut BgGenerator,
    state: &mut BgTemplateState,
    deadlines: &mut TimerDeadlines,
    receiver: &mpsc::Receiver<GenCommand>,
    fired: FiredTimer,
) -> bool {
    step_timer(ctx, g, state, deadlines, fired);
    drain_and_build(ctx, g, state, deadlines, receiver)
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

/// Finish the chain handler's deferred mempool maintenance before the
/// state machine handles a connected or disconnected block or the end
/// of a reorganization.  dcrd's handler updates the pool for a block
/// before it hands the block to the generator (`s.bg.BlockConnected`
/// and `s.bg.BlockDisconnected` follow the pool updates in `server.go`'s
/// NTBlockConnected and NTBlockDisconnected cases), and the chain sends
/// NTChainReorgDone only after the handler has run for every block of
/// the reorganization, so the votes the generator counts and the pool a
/// build reads already reflect it.  The chain callback feeds this thread
/// ahead of that maintenance, which the post-process drain runs once
/// the chain mutex is free.  Taking the chain mutex waits out the
/// processing call that sent the event, so everything that call queued
/// is queued (the callback sends the event before it queues the block's
/// maintenance, and the drain itself waits on the chain only when it
/// finds something queued), and the drain lock then waits for a drain
/// already under way or runs it here.
fn finish_chain_maintenance(ctx: &BuildCtx, event: &OwnedRegenEvent) {
    let after_maintenance = matches!(
        event,
        OwnedRegenEvent::BlockConnected(_)
            | OwnedRegenEvent::BlockDisconnected(_)
            | OwnedRegenEvent::ReorgDone
    );
    if !after_maintenance || ctx.drain_hook.is_none() {
        return;
    }
    drop(ctx.chain.lock().expect("chain mutex poisoned"));
    run_drain(&ctx.drain_hook);
}

/// Start the background template generator thread over the daemon's
/// live chain and mempool (dcrd `newServer` constructing the
/// `BgBlkTmplGenerator` and `server.Run` launching its handlers).
///
/// `drain_hook` runs the chain notification handler's deferred
/// maintenance after every processed event and timer, after each
/// template build before the events it queued are serviced, and before
/// a connected or disconnected block or the end of a reorganization is
/// handled (see `finish_chain_maintenance`).  A reorg the
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
    sync_gate: crate::sync::SyncGate,
    ntfn: Option<NodeNtfnMgr>,
    drain_hook: Option<Box<dyn Fn() + Send>>,
) -> Generator {
    let (sender, receiver) = mpsc::channel();
    let current = Arc::new(Mutex::new(SharedTemplate::default()));
    let subscribers = Arc::new(Mutex::new(SubscriberRegistry::default()));

    let thread_current = Arc::clone(&current);
    let thread_subscribers = Arc::clone(&subscribers);
    let thread = std::thread::spawn(move || {
        // However the thread ends, retrieval must stop waiting on it.
        let _close_on_exit = CloseOnExit(Arc::clone(&thread_current));
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
            sync_gate,
            current: thread_current,
            subscribers: thread_subscribers,
            ntfn,
            drain_hook,
        };

        // dcrd's initial startup handler waits for the chain to be
        // current before generating templates, then injects the tip as
        // a synthetic block-connected event to prime the state machine.
        if !allow_unsynced_mining {
            loop {
                if ctx.sync_is_current() {
                    break;
                }
                match receiver.recv_timeout(Duration::from_secs(1)) {
                    Ok(GenCommand::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    // Reorg events must still reach the state machine so
                    // the reorganizing flag and the stale-template guard
                    // stay balanced across the sync-completion boundary.
                    // dcrd's regen handler has no separate pre-current
                    // wait: `handleRegenEvent` tracks the reorg state for
                    // every event (its `rtReorgStarted`/`rtReorgDone`
                    // arms run before the `IsCurrent` gate).  A reorg that
                    // starts before the chain is current and finishes
                    // after would otherwise drive the stale-template
                    // counter negative and build a template mid-reorg.
                    Ok(GenCommand::Event(event))
                        if matches!(
                            event.as_ref(),
                            OwnedRegenEvent::ReorgStarted | OwnedRegenEvent::ReorgDone
                        ) =>
                    {
                        if !process_event(
                            &ctx,
                            &mut g,
                            &mut state,
                            &mut deadlines,
                            &receiver,
                            event.as_ref(),
                        ) {
                            return;
                        }
                    }
                    // Other events before the chain is current are
                    // dropped; the tip inject below reflects the current
                    // state.
                    Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
        }

        // Treat the current tip as just connected (dcrd's startup
        // `rtBlockConnected` inject).
        {
            let mut tip_chain = NodeTemplateChain::new(Arc::clone(&ctx.chain), ctx.params.clone());
            let best = tip_chain.best_snapshot();
            match tip_chain.block_by_hash(&best.hash) {
                Err(err) => {
                    // dcrd's `setCurrentTemplate(nil, turUnknown, err)`
                    // and the template-update event it queues, which
                    // arms the failed-generation retry.
                    let tx_source = NodeTemplateTxSource::new(Arc::clone(&ctx.pool));
                    let is_current = ctx.allow_unsynced_mining || ctx.sync_is_current();
                    set_failed_template(
                        &mut g,
                        &mut state,
                        &mut tip_chain,
                        &tx_source,
                        err,
                        is_current,
                        now_unix(),
                    );
                    reconcile_timers(&mut deadlines, &state);
                    publish_current_template(&ctx.current, &g, &state);
                }
                Ok(tip_block) => {
                    if !process_event(
                        &ctx,
                        &mut g,
                        &mut state,
                        &mut deadlines,
                        &receiver,
                        &OwnedRegenEvent::BlockConnected(Arc::new(tip_block)),
                    ) {
                        return;
                    }
                }
            }
        }
        run_drain(&ctx.drain_hook);
        // A settling pass over the deadlines; the tip inject above
        // already reconciled, so nothing is re-armed here.
        reconcile_timers(&mut deadlines, &state);

        loop {
            let wait = match nearest_deadline(&deadlines) {
                Some((at, _)) => at.saturating_duration_since(Instant::now()),
                None => IDLE_WAIT,
            };
            let running = match receiver.recv_timeout(wait) {
                Ok(GenCommand::Event(event)) => process_event(
                    &ctx,
                    &mut g,
                    &mut state,
                    &mut deadlines,
                    &receiver,
                    event.as_ref(),
                ),
                Ok(GenCommand::ForceRegen) => {
                    process_force_regen(&ctx, &mut g, &mut state, &mut deadlines, &receiver)
                }
                Ok(GenCommand::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // The nearest deadline elapsed; fire its handler.
                    match nearest_deadline(&deadlines) {
                        Some((_, fired)) => process_timer(
                            &ctx,
                            &mut g,
                            &mut state,
                            &mut deadlines,
                            &receiver,
                            fired,
                        ),
                        None => true,
                    }
                }
            };
            if !running {
                return;
            }
            // Drive the chain handler's deferred maintenance for any
            // reorg this event or timer initiated on the chain.
            run_drain(&ctx.drain_hook);
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
    fn force_regen(&self) {
        self.sink.force_regen();
    }

    fn current_template(&self) -> Result<Option<MsgBlock>, String> {
        let current = wait_for_current(&self.current);
        if current.reorganizing {
            return Ok(None);
        }
        if let Some(err) = &current.err {
            return Err(err.clone());
        }
        Ok(current.block.clone())
    }

    fn current_template_err(&self) -> Result<(), String> {
        // `current_template`'s answer without copying the block out.
        let current = wait_for_current(&self.current);
        match &current.err {
            Some(err) if !current.reorganizing => Err(err.clone()),
            _ => Ok(()),
        }
    }

    fn subscribe(&self) -> Box<dyn RpcTemplateSubscription + Send> {
        let (sender, receiver) =
            mpsc::sync_channel(subscription_buffer(self.params.tickets_per_block));
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
        // the getwork current-template read uses: wait out a pending
        // new-parent, new-votes or reorganization template, then skip
        // it during a reorganization or when the template errored, so
        // a stale orphan-parent template is never handed out (dcrd
        // `Subscribe` delivers `currentTemplate()`, which waits on
        // `staleTemplateWg`).
        {
            let current = wait_for_current(&self.current);
            if !current.reorganizing
                && current.err.is_none()
                && let Some(block) = &current.block
            {
                let _ = sender.try_send(block.clone());
            }
        }
        Box::new(NodeTemplateSubscription {
            id,
            receiver,
            subscribers: Arc::clone(&self.subscribers),
        })
    }

    fn update_block_time(&self, header: &mut BlockHeader) {
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
    fn recv(&self) -> TemplateRecv {
        // dcrd selects the notification against the request context
        // (`rpcserver.go:3910-3917`), so a client that leaves during this
        // wait -- which is unbounded, since it runs until the generator
        // publishes -- stops waiting and frees the work semaphore at
        // once.  A `mpsc::Receiver` cannot select, so the wait is sliced
        // and the flag re-read between slices, the same shape
        // `WorkSem::acquire` uses for dcrd's other cancellation arm.
        //
        // `Disconnected` stays a cancellation for its own reason: it
        // means the generator is gone, which is dcrd's nil-template
        // path rather than its context path.
        //
        // With no token installed there is nothing to poll for, so the
        // wait stays a plain blocking receive.  That is the CPU miner's
        // generator thread, which also waits here and would otherwise
        // start waking twenty times a second to re-read a flag that
        // cannot change.
        if !request_is_cancellable() {
            return match self.receiver.recv() {
                Ok(block) => TemplateRecv::Template(Box::new(block)),
                Err(_) => TemplateRecv::Canceled,
            };
        }
        loop {
            if request_cancelled() {
                return TemplateRecv::Canceled;
            }
            match self.receiver.recv_timeout(CANCEL_POLL_INTERVAL) {
                Ok(block) => return TemplateRecv::Template(Box::new(block)),
                Err(mpsc::RecvTimeoutError::Disconnected) => return TemplateRecv::Canceled,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    }

    fn recv_with_timeout(&self) -> TemplateRecv {
        // The same slicing against dcrd's second context arm
        // (`rpcserver.go:3928-3935`), inside the known-template timeout
        // rather than instead of it: the deadline is still
        // MAX_TEMPLATE_TIMEOUT from entry, so a client that stays
        // connected sees exactly the wait it saw before.
        if !request_is_cancellable() {
            return match self.receiver.recv_timeout(MAX_TEMPLATE_TIMEOUT) {
                Ok(block) => TemplateRecv::Template(Box::new(block)),
                Err(mpsc::RecvTimeoutError::Timeout) => TemplateRecv::Timeout,
                Err(mpsc::RecvTimeoutError::Disconnected) => TemplateRecv::Canceled,
            };
        }
        // Measured as elapsed-since-entry rather than as an absolute
        // deadline: `Instant::now() + MAX_TEMPLATE_TIMEOUT` is fallible
        // addition, and a `Duration` subtraction that saturates to
        // `None` says "the budget is spent" without one.
        let started = Instant::now();
        loop {
            if request_cancelled() {
                return TemplateRecv::Canceled;
            }
            let Some(left) = MAX_TEMPLATE_TIMEOUT.checked_sub(started.elapsed()) else {
                return TemplateRecv::Timeout;
            };
            if left.is_zero() {
                return TemplateRecv::Timeout;
            }
            match self.receiver.recv_timeout(left.min(CANCEL_POLL_INTERVAL)) {
                Ok(block) => return TemplateRecv::Template(Box::new(block)),
                Err(mpsc::RecvTimeoutError::Disconnected) => return TemplateRecv::Canceled,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    }

    fn recv_with_timeout_until(&self, cancel: &std::sync::atomic::AtomicBool) -> TemplateRecv {
        // As `recv_with_timeout`, but watching one more thing. The extra
        // flag is shared rather than thread-local because the caller that
        // raises it -- a `generate 0` on another connection -- is on a
        // different thread, so it is passed by reference instead.
        let started = Instant::now();
        loop {
            if cancel.load(std::sync::atomic::Ordering::Acquire) || request_cancelled() {
                return TemplateRecv::Canceled;
            }
            let Some(left) = MAX_TEMPLATE_TIMEOUT.checked_sub(started.elapsed()) else {
                return TemplateRecv::Timeout;
            };
            if left.is_zero() {
                return TemplateRecv::Timeout;
            }
            match self.receiver.recv_timeout(left.min(CANCEL_POLL_INTERVAL)) {
                Ok(block) => return TemplateRecv::Template(Box::new(block)),
                Err(mpsc::RecvTimeoutError::Disconnected) => return TemplateRecv::Canceled,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    }

    fn stop(&self) {
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

    /// A cheap block template built from the regnet genesis block for
    /// exercising the getwork mirror publish without a live chain.
    fn genesis_template(height: i64) -> dcroxide_mining::BlockTemplate {
        dcroxide_mining::BlockTemplate {
            block: dcroxide_chaincfg::regnet_params().genesis_block,
            fees: Vec::new(),
            sig_op_counts: Vec::new(),
            height,
            valid_pay_address: false,
        }
    }

    /// The publish primitive faithfully mirrors the generator's current
    /// template — populating it from a built template, clearing the block
    /// when the template is cleared (as a reorg-started event does), and
    /// carrying the reorganizing flag.  This guards the helper itself; the
    /// call-site wiring that publishes on the no-rebuild path (a reorg
    /// clearing the template without queuing a build) is covered by the
    /// integration test `a_reorg_clears_and_then_recovers_getwork`.
    #[test]
    fn publish_tracks_a_cleared_template() {
        let mut g = BgGenerator::new(5, 16, true);
        let mut state = BgTemplateState::new();
        let current = Arc::new(Mutex::new(SharedTemplate::default()));

        // A generated template populates the mirror.
        g.set_current_template(
            Some(genesis_template(1)),
            BgTemplateUpdateReason::NewParent,
            None,
        );
        publish_current_template(&current, &g, &state);
        assert!(
            current.lock().expect("mirror").block.is_some(),
            "a generated template populates the getwork mirror"
        );

        // A reorg-started clear drops the template and raises the flag;
        // the mirror must follow rather than retaining the stale block.
        g.set_current_template(None, BgTemplateUpdateReason::Unknown, None);
        state.is_reorganizing = true;
        publish_current_template(&current, &g, &state);
        {
            let snap = current.lock().expect("mirror");
            assert!(
                snap.block.is_none(),
                "a cleared template clears the mirror block"
            );
            assert!(
                snap.reorganizing,
                "the reorganizing flag reaches the mirror"
            );
        }

        // A post-reorg rebuild repopulates the mirror and lowers the flag.
        g.set_current_template(
            Some(genesis_template(2)),
            BgTemplateUpdateReason::NewParent,
            None,
        );
        state.is_reorganizing = false;
        publish_current_template(&current, &g, &state);
        let snap = current.lock().expect("mirror");
        assert!(
            snap.block.is_some(),
            "a rebuilt template repopulates the mirror"
        );
        assert!(
            !snap.reorganizing,
            "the reorganizing flag clears with the reorg"
        );
    }

    /// The deadlines reconcile from the state machine's armed flags and
    /// arm generations: arming records a deadline, every re-arm (a new
    /// generation) restarts it even while it is still pending, a
    /// reconcile with no new arm keeps it, and disarming clears it.
    #[test]
    fn timers_reconcile_from_armed_flags() {
        let mut state = BgTemplateState::new();
        let mut deadlines = TimerDeadlines::default();

        // Nothing armed: no deadlines.
        reconcile_timers(&mut deadlines, &state);
        assert!(nearest_deadline(&deadlines).is_none());

        // Arm the regen timer at 30 seconds and each fixed timeout.
        state.regen_timer_armed = true;
        state.regen_timer_millis = 30_000;
        state.regen_timer_gen += 1;
        state.max_votes_timeout_armed = true;
        state.max_votes_timeout_gen += 1;
        state.track_side_chains_timeout_armed = true;
        state.track_side_chains_timeout_gen += 1;
        state.failed_gen_retry_timeout_armed = true;
        reconcile_timers(&mut deadlines, &state);
        assert!(deadlines.regen.is_some());
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
        state.regen_timer_gen += 1;
        reconcile_timers(&mut deadlines, &state);
        assert!(deadlines.regen.expect("regen armed") < before);

        // A reconcile with no new arm keeps every running deadline, and
        // a re-arm of an armed timer restarts it: dcrd's `time.After`
        // and `resetRegenTimer` replace a pending countdown, including a
        // regen reset to the duration it already had.
        let regen_before = deadlines.regen.expect("regen armed");
        let max_votes_before = deadlines.max_votes.expect("max votes armed");
        let side_before = deadlines.track_side_chains.expect("side chains armed");
        std::thread::sleep(std::time::Duration::from_millis(2));
        reconcile_timers(&mut deadlines, &state);
        assert_eq!(deadlines.regen, Some(regen_before));
        assert_eq!(deadlines.max_votes, Some(max_votes_before));
        assert_eq!(deadlines.track_side_chains, Some(side_before));
        state.regen_timer_gen += 1;
        state.max_votes_timeout_gen += 1;
        state.track_side_chains_timeout_gen += 1;
        reconcile_timers(&mut deadlines, &state);
        assert!(deadlines.regen.expect("regen armed") > regen_before);
        assert!(deadlines.max_votes.expect("max votes armed") > max_votes_before);
        assert!(deadlines.track_side_chains.expect("side chains armed") > side_before);

        // Disarming clears the deadlines.
        state.regen_timer_armed = false;
        state.max_votes_timeout_armed = false;
        state.track_side_chains_timeout_armed = false;
        state.failed_gen_retry_timeout_armed = false;
        reconcile_timers(&mut deadlines, &state);
        assert!(nearest_deadline(&deadlines).is_none());
    }

    /// A subscriber that stops draining must bound its backlog and stay
    /// registered.
    ///
    /// dcrd gives each subscription a channel of `maxVoteInducedRegens*2`
    /// and drops on a full buffer -- `select { case s.privC <- ntfn:
    /// default: }` (`bgblktmplgenerator.go:460-469`) -- so a slow
    /// receiver loses notifications rather than growing a queue. The
    /// previous unbounded channel grew without limit behind a receiver
    /// that was alive but idle.
    ///
    /// The second assertion guards the shape of the fix: deregistering
    /// on any send error, rather than only on a disconnected receiver,
    /// would silently drop every subscriber that is merely busy.
    #[test]
    fn a_full_subscriber_drops_notifications_and_stays_registered() {
        let mut reg = SubscriberRegistry::default();
        let cap = subscription_buffer(5);
        assert_eq!(cap, 6, "mainnet's maxVoteInducedRegens*2");

        let (tx, rx) = mpsc::sync_channel(cap);
        reg.register(tx);
        let block = dcroxide_chaincfg::regnet_params().genesis_block.clone();

        // Nobody drains.
        for _ in 0..64 {
            reg.broadcast(&block);
        }

        assert_eq!(
            reg.subscribers.len(),
            1,
            "a subscriber that is merely full must stay registered"
        );
        let mut queued = 0;
        while rx.try_recv().is_ok() {
            queued += 1;
        }
        assert_eq!(queued, cap, "the backlog is capped at dcrd's buffer");

        // A receiver that is gone does deregister.
        drop(rx);
        reg.broadcast(&block);
        assert!(
            reg.subscribers.is_empty(),
            "a disconnected receiver deregisters"
        );
    }

    /// A subscription whose sender is alive but silent, so a wait on it
    /// ends only by cancellation or by the timeout -- never by a
    /// delivery, and never by `Disconnected`.
    fn silent_subscription() -> (mpsc::SyncSender<MsgBlock>, NodeTemplateSubscription) {
        let (tx, rx) = mpsc::sync_channel(1);
        let mut reg = SubscriberRegistry::default();
        let id = reg.register(tx.clone());
        (
            tx,
            NodeTemplateSubscription {
                id,
                receiver: rx,
                subscribers: Arc::new(Mutex::new(reg)),
            },
        )
    }

    /// dcrd's first context arm (`rpcserver.go:3914`): the unbounded
    /// template wait gives up when the request is cancelled, rather than
    /// holding the work semaphore until the generator publishes.
    ///
    /// Race-free by construction: the flag is already raised before
    /// `recv` is called, so the pre-wait check decides it and no timing
    /// is involved.  Without the flag the same call would block until
    /// the test harness killed it.
    #[test]
    fn an_unbounded_template_wait_gives_up_when_the_request_is_cancelled() {
        let (_tx, sub) = silent_subscription();
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let _scope = dcroxide_rpc::worksem::scope_request_cancel(Arc::clone(&flag));

        let started = Instant::now();
        assert!(
            matches!(sub.recv(), TemplateRecv::Canceled),
            "an already-cancelled request must not join the wait"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the cancelled wait returned, but only after blocking"
        );
    }

    /// The same arm when the hangup lands *during* the wait, which is
    /// the case that actually frees a pinned permit.  The bound is
    /// generous -- the poll interval is 50ms and the assertion allows
    /// 60x that -- so it measures "returns promptly", not a deadline.
    #[test]
    fn a_template_wait_notices_a_hangup_that_arrives_mid_wait() {
        let (_tx, sub) = silent_subscription();
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let _scope = dcroxide_rpc::worksem::scope_request_cancel(Arc::clone(&flag));

        let raiser = Arc::clone(&flag);
        let hangup = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            raiser.store(true, std::sync::atomic::Ordering::Release);
        });

        let started = Instant::now();
        assert!(
            matches!(sub.recv(), TemplateRecv::Canceled),
            "a hangup during the wait must end it"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the wait outlived the hangup by too much to be polling"
        );
        hangup.join().expect("raiser thread");
    }

    /// The SLICED bounded wait still honours dcrd's known-template
    /// timeout: a request that is cancellable but not cancelled must
    /// wait exactly as long as one that cannot be cancelled at all.
    /// This is the path the fix actually changed -- the loop's deadline
    /// arithmetic -- and it also proves the loop terminates rather than
    /// re-slicing forever.
    #[test]
    fn a_cancellable_bounded_wait_still_times_out_at_dcrds_deadline() {
        let (_tx, sub) = silent_subscription();
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let _scope = dcroxide_rpc::worksem::scope_request_cancel(Arc::clone(&flag));

        let started = Instant::now();
        assert!(
            matches!(sub.recv_with_timeout(), TemplateRecv::Timeout),
            "a cancellable but uncancelled wait still ends in dcrd's timeout"
        );
        let waited = started.elapsed();
        assert!(
            waited >= MAX_TEMPLATE_TIMEOUT,
            "the sliced wait returned early: {waited:?} < {MAX_TEMPLATE_TIMEOUT:?}"
        );
        // Generous, but it would catch a slice that reset the deadline
        // each iteration and so never ended.
        assert!(
            waited < MAX_TEMPLATE_TIMEOUT.saturating_mul(2),
            "the sliced wait overran its deadline: {waited:?}"
        );
    }

    /// The uncancellable path keeps its original single-shot shape, so
    /// the CPU miner's generator thread blocks as it always did rather
    /// than waking to poll a flag that cannot change.
    #[test]
    fn the_bounded_wait_still_times_out_when_nothing_cancels() {
        let (_tx, sub) = silent_subscription();
        // No cancellation scope at all -- the in-process case, where
        // `request_cancelled` is always false.
        let started = Instant::now();
        assert!(
            matches!(sub.recv_with_timeout(), TemplateRecv::Timeout),
            "an uncancelled bounded wait ends in dcrd's timeout"
        );
        let waited = started.elapsed();
        assert!(
            waited >= MAX_TEMPLATE_TIMEOUT,
            "the sliced wait returned early: {waited:?} < {MAX_TEMPLATE_TIMEOUT:?}"
        );
    }

    /// And it still cancels, which is dcrd's second context arm
    /// (`rpcserver.go:3932`).  Race-free the same way as the first.
    #[test]
    fn the_bounded_wait_gives_up_when_the_request_is_cancelled() {
        let (_tx, sub) = silent_subscription();
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let _scope = dcroxide_rpc::worksem::scope_request_cancel(Arc::clone(&flag));

        let started = Instant::now();
        assert!(
            matches!(sub.recv_with_timeout(), TemplateRecv::Canceled),
            "a cancelled bounded wait must not run out the timeout"
        );
        assert!(
            started.elapsed() < MAX_TEMPLATE_TIMEOUT,
            "the cancelled wait ran the full timeout instead of returning"
        );
    }

    /// A generator thread over a regnet battery chain two blocks tall
    /// with the real pool, and a templater over its handles.
    struct LiveGenerator {
        _dir: tempfile::TempDir,
        chain: Arc<Mutex<Chain>>,
        pool: Arc<Mutex<NodeTxPool>>,
        generator: Generator,
    }

    impl LiveGenerator {
        fn start() -> LiveGenerator {
            let params = dcroxide_chaincfg::regnet_params();
            let (now, blocks) = crate::txmempool::test_support::accepted_prefix(2);
            let (dir, chain) = crate::txmempool::test_support::regnet_chain(now, &blocks, 2);
            let chain = Arc::new(Mutex::new(chain));
            let pool = crate::txmempool::new_shared_tx_pool(
                Arc::clone(&chain),
                &params,
                false,
                100,
                10000,
                false,
                false,
            );
            let mining_addr = dcroxide_txscript::stdaddr::decode_address(
                "RsKrWb7Vny1jnzL1sDLgKTAteh9RZcRr5g6",
                &params,
            )
            .expect("mining address");
            let generator = start_generator(
                Arc::clone(&chain),
                Arc::clone(&pool),
                params.clone(),
                vec![mining_addr],
                Self::policy(),
                0,
                true,
                crate::sync::SyncGate::always_current(),
                None,
                None,
            );
            LiveGenerator {
                _dir: dir,
                chain,
                pool,
                generator,
            }
        }

        fn policy() -> MiningPolicy {
            let params = dcroxide_chaincfg::regnet_params();
            MiningPolicy {
                block_max_size: params.maximum_block_sizes[0] as u32,
                tx_min_free_fee: 10000,
                aggressive_mining: true,
            }
        }

        fn templater(&self) -> NodeRpcBlockTemplater {
            NodeRpcBlockTemplater::new(
                self.generator.current_handle(),
                self.generator.subscribers_handle(),
                self.generator.sink(),
                Arc::clone(&self.chain),
                Arc::clone(&self.pool),
                dcroxide_chaincfg::regnet_params(),
                Self::policy(),
                0,
            )
        }

        /// The first template, once the startup build has published it.
        fn startup_template(&self) -> MsgBlock {
            let templater = self.templater();
            let started = Instant::now();
            loop {
                if let Ok(Some(block)) = templater.current_template() {
                    return block;
                }
                assert!(
                    started.elapsed() < Duration::from_secs(20),
                    "no startup template"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        /// Re-announce the tip as connected, which below stake
        /// validation height requests a new-parent build (dcrd
        /// `handleBlockConnected` calling `genTemplateAsync`).
        fn reconnect_tip(&self) {
            let tip = {
                let chain = self.chain.lock().expect("chain");
                let best = chain.best_snapshot().hash;
                chain.block_by_hash(&best).expect("tip block")
            };
            self.generator.sink().block_connected(Arc::new(tip));
        }

        /// Poll the getwork mirror until the predicate holds.
        fn await_mirror(&self, what: &str, pred: impl Fn(&SharedTemplate) -> bool) {
            let started = Instant::now();
            while !pred(&self.generator.current.lock().expect("mirror")) {
                assert!(
                    started.elapsed() < Duration::from_secs(20),
                    "timed out waiting for {what}"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    fn block_id(block: &MsgBlock) -> dcroxide_chainhash::Hash {
        block.header.block_hash()
    }

    /// dcrd's `currentTemplate` waits on `staleTemplateWg`, which a
    /// new-parent generation holds from `genTemplateAsync` until the
    /// goroutine ends (`bgblktmplgenerator.go:401-402`, `:716-724`), so
    /// getwork never hands out the template the build is replacing.
    /// The build is held at the pool lock, so the retrieval can only
    /// return early by not waiting.
    #[test]
    fn retrieval_waits_for_an_in_flight_new_parent_template() {
        let live = LiveGenerator::start();
        let before = live.startup_template();

        let gate = live.pool.lock().expect("pool");
        live.reconnect_tip();
        live.await_mirror("the in-flight build's stale hold", |m| m.stale);

        let templater = live.templater();
        let (tx, rx) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let _ = tx.send(templater.current_template());
        });
        assert!(
            matches!(
                rx.recv_timeout(Duration::from_millis(300)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "retrieval must wait while the new-parent build runs"
        );

        drop(gate);
        let fresh = rx
            .recv_timeout(Duration::from_secs(20))
            .expect("retrieval returns once the build installs")
            .expect("no template error")
            .expect("a template");
        reader.join().expect("reader thread");
        assert_ne!(
            block_id(&fresh),
            block_id(&before),
            "the waiting retrieval gets the new build, not the one it replaces"
        );
        let mirror = live.generator.current.lock().expect("mirror");
        assert_eq!(
            mirror.block.as_ref().map(block_id),
            Some(block_id(&fresh)),
            "and that is the installed template"
        );
        assert!(!mirror.stale, "the hold is released with the install");
    }

    /// A generation superseded while it builds is dropped like dcrd's
    /// cancelled goroutine (`if ctx.Err() != nil { return }` before
    /// `setCurrentTemplate` and the subscriber send,
    /// `bgblktmplgenerator.go:737-739`): subscribers hear only of the
    /// build that replaced it.
    #[test]
    fn a_build_superseded_mid_flight_is_neither_installed_nor_notified() {
        let live = LiveGenerator::start();
        let before = live.startup_template();
        let (tx, rx) = mpsc::sync_channel(16);
        live.generator
            .subscribers
            .lock()
            .expect("registry")
            .register(tx);

        let gate = live.pool.lock().expect("pool");
        live.reconnect_tip();
        live.await_mirror("the first build's stale hold", |m| m.stale);
        // A second new-parent request while the first build runs.
        live.reconnect_tip();
        drop(gate);

        let installed = live
            .templater()
            .current_template()
            .expect("no template error")
            .expect("a template");
        assert_ne!(block_id(&installed), block_id(&before));
        // The generator publishes a template before it notifies the
        // subscribers, so the startup build's own notification can still
        // reach the registration made after its publish.  It is the only
        // one that can: the thread notifies each template before it
        // publishes the next.  Its random extra nonces keep its id apart
        // from every later build's.
        let mut notified = rx
            .recv_timeout(Duration::from_secs(20))
            .expect("the replacing build notifies");
        if block_id(&notified) == block_id(&before) {
            notified = rx
                .recv_timeout(Duration::from_secs(20))
                .expect("the replacing build notifies");
        }
        assert_eq!(
            block_id(&notified),
            block_id(&installed),
            "the first notification is the installed template"
        );
        assert!(
            matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "the superseded build was never notified"
        );
        let mirror = live.generator.current.lock().expect("mirror");
        assert!(!mirror.stale, "both builds released their holds");
    }

    /// The events that arrive while a build runs reach the state machine
    /// before its result is installed, as dcrd's regen handler services
    /// them concurrently with the goroutine.  A reorganization start
    /// queued mid-build clears the old template and requests nothing,
    /// so the finished build then installs over the cleared state and
    /// stays current through the reorganization (retrieval waits it
    /// out), instead of being installed first and wiped by the clear.
    #[test]
    fn a_reorg_start_queued_during_a_build_is_serviced_before_the_install() {
        let live = LiveGenerator::start();
        let before = live.startup_template();

        let gate = live.pool.lock().expect("pool");
        live.reconnect_tip();
        live.await_mirror("the build's stale hold", |m| m.stale);
        live.generator.sink().chain_reorg_started();
        drop(gate);

        live.await_mirror("the build installed after the reorg start", |m| {
            m.reorganizing
                && m.block
                    .as_ref()
                    .is_some_and(|block| block_id(block) != block_id(&before))
        });
        assert!(
            live.generator.current.lock().expect("mirror").stale,
            "retrieval waits out the reorganization"
        );

        // The reorganization finishes: the tip is re-evaluated, which
        // below stake validation height builds anew.
        live.generator.sink().chain_reorg_done();
        let after = live
            .templater()
            .current_template()
            .expect("no template error")
            .expect("a template once the reorganization is done");
        assert_eq!(after.header.height, 3);
        assert!(!live.generator.current.lock().expect("mirror").stale);
    }

    /// Retrieval never waits on a generator that is gone.
    #[test]
    fn retrieval_does_not_wait_on_a_stopped_generator() {
        let current = Arc::new(Mutex::new(SharedTemplate::default()));
        current.lock().expect("mirror").stale = true;
        let closer = CloseOnExit(Arc::clone(&current));
        let waiter_current = Arc::clone(&current);
        let (tx, rx) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let reorganizing = wait_for_current(&waiter_current).reorganizing;
            let _ = tx.send(reorganizing);
        });
        assert!(
            matches!(
                rx.recv_timeout(Duration::from_millis(200)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "a stale mirror holds retrieval"
        );
        drop(closer);
        rx.recv_timeout(Duration::from_secs(10))
            .expect("closing the mirror releases the wait");
        waiter.join().expect("waiter thread");
    }
}
