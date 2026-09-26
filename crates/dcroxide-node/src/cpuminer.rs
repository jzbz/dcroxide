// SPDX-License-Identifier: ISC
//! The daemon's CPU miner (dcrd `internal/mining/cpuminer`): both the
//! discrete `generate N` state machine (`GenerateNBlocks`) and the
//! continuous background miner behind `setgenerate` (`Run` +
//! `speedMonitor` + `miningWorkerController` + `generateBlocks` +
//! `solver`).
//!
//! The proof-of-work solve loop itself lives in the pure, chain-free
//! `dcroxide_mining::cpuminer` core; this module drives it over OS
//! threads.  [`NodeCpuMiner`] is the RPC-facing face, shared across the
//! handler threads and guarding its own state the way dcrd's `CPUMiner`
//! guards its own; [`MinerRuntime`] is the daemon-held handle owning
//! the two background threads (the speed monitor and the worker
//! controller, which together replace dcrd's `Run` goroutine and its two
//! subordinates).  `generate_n_blocks` runs synchronously on the RPC
//! thread; `set_num_workers` starts or stops the continuous workers, and
//! `hashes_per_second` reads the live rate over a request/reply channel.
//!
//! The mutual-exclusion state — dcrd's `normalMining`/`discreteMining`
//! pair — lives in one `MiningMode` behind one lock, mirroring the
//! `sync.Mutex` dcrd's `CPUMiner` embeds and holds across each whole
//! check-and-set.  A long `generate N` no longer stalls unrelated RPCs:
//! the lock is released before the mining loop runs.
//!
//! Divergences from dcrd, all documented at the call sites: the
//! `queryHashesPerSec` rendezvous becomes a `mpsc` request/reply; the
//! `updateNumWorkers` signal becomes a poke with the count carried on an
//! atomic; and dcrd's `notifyBlocks`/`BlockConnected` feed becomes a
//! watch thread that polls the chain tip (see `DiscreteWatch`),
//! because `std::sync::mpsc` cannot select the template subscription
//! against a block-notification source, so a discrete run ends within a
//! poll interval of the block that reaches its target, from any source,
//! rather than on the connect itself.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_mining::cpuminer::{SpeedStats, solve_block};
use dcroxide_mining::{BlkTmplGenerator, MiningPolicy};
use dcroxide_rpc::server::{
    GenerateFailure, RpcBlockTemplater, RpcCpuMiner, RpcTemplateSubscription, TemplateRecv,
};
use dcroxide_rpc::worksem::request_cancelled;
use dcroxide_wire::{BlockHeader, MsgBlock};

use crate::bgtemplate::{GeneratorSink, NodeRpcBlockTemplater, SharedTemplate, SubscriberRegistry};
use crate::dispatch::SyncPeers;
use crate::mining::{NodeTemplateChain, NodeTemplateTxSource};
use crate::sync::NodeSyncManager;
use crate::txmempool::NodeTxPool;

/// The default number of mining workers (dcrd `defaultNumWorkers`),
/// reported by `getmininginfo`/`getgenerate` even while idle.
const DEFAULT_NUM_WORKERS: u32 = 1;

/// How often the speed monitor recomputes the hash rate (dcrd
/// `hpsUpdateSecs = 10`).
const HPS_UPDATE_INTERVAL: Duration = Duration::from_secs(10);

/// The maximum blocks a connectionless (simnet/regnet) solver mines on
/// one parent before stopping, so tickets running out during a
/// simulation cannot spin the miner pointlessly (dcrd `maxSimnetToMine`).
const MAX_SIMNET_TO_MINE: u8 = 4;

/// A command to the worker controller thread (dcrd's `updateNumWorkers`
/// signal and the controller's `ctx.Done`).
enum ControllerCmd {
    /// Reconcile the running worker count to the shared `num_workers`
    /// atomic.
    Update,
    /// Stop all workers and exit.
    Stop,
}

/// A command to the speed-monitor thread (dcrd's `queryHashesPerSec`
/// request and the monitor's `ctx.Done`).
enum MonitorCmd {
    /// Answer the current hash rate over the reply channel.
    Query(mpsc::Sender<f64>),
    /// Exit.
    Stop,
}

/// The two mining-mode flags dcrd's `CPUMiner` keeps under its embedded
/// `sync.Mutex` (`internal/mining/cpuminer/cpuminer.go`).  They are one
/// struct behind one lock rather than two atomics because the guards that
/// read them are cross-checks — `GenerateNBlocks` rejects on `normalMining`
/// and `SetNumWorkers` rejects on `discreteMining` — and dcrd holds the
/// lock across each whole check-and-set (`:833-856`, `:697-706`).  Split
/// across two atomics the checks become check-then-act, and two concurrent
/// RPC threads can both pass.
#[derive(Default)]
struct MiningMode {
    /// dcrd `normalMining`: continuous mining via `setgenerate`.
    normal: bool,
    /// dcrd `discreteMining`: a `generate N` call in flight.
    discrete: bool,
    /// dcrd `generateCancelFn` (`cpuminer.go:159-163`): the handle a
    /// concurrent `generate 0` uses to stop the call in flight.
    ///
    /// A flag rather than a closure because the thing it cancels is a
    /// wait on a channel, and because it is read from the mining thread
    /// while being set from whichever connection ran `generate 0`.
    /// Cleared with `discrete`, so a `generate 0` arriving after the
    /// call returned raises a flag nobody reads -- which is what dcrd's
    /// deferred `generateCancelFn(); = nil` amounts to.
    generate_cancel: Option<Arc<AtomicBool>>,
}

/// dcrd `ErrCancelDiscreteMining` (`cpuminer.go:63`).  Reproduced
/// verbatim because it reaches the client: `handleGenerate` formats it
/// into `rpcCancelError` (`rpcserver.go:1854-1855`), so the text is part
/// of the RPC surface rather than an internal label.
const ERR_CANCEL_DISCRETE_MINING: &str = "discrete mining process canceled";

/// dcrd's `GenerateNBlocks` entry gate: both rejection checks and the
/// activation, under ONE hold of the mode lock, as dcrd does with its
/// `m.Lock()` … `m.discreteMining = true` … `m.Unlock()`
/// (`cpuminer.go:833-856`).  Returns `Ok(false)` for the `n == 0` case,
/// which claims nothing.
///
/// It takes `&mut MiningMode` rather than the mutex deliberately: with
/// no lock to acquire, the check and the set physically cannot span two
/// acquisitions, so the atomicity is enforced by the signature instead of
/// by a comment.  Splitting them would let two concurrent `generate`
/// calls — each RPC connection has its own handler thread, and no
/// server-wide lock serializes them any more — both read `false` and both
/// proceed, after which the first to finish clears the flag while the
/// second is still mining.
fn begin_discrete(
    mode: &mut MiningMode,
    n: u32,
) -> Result<Option<Arc<AtomicBool>>, GenerateFailure> {
    // Reject a discrete call while continuous mining is active (dcrd's
    // `normalMining` guard).
    if mode.normal {
        return Err(GenerateFailure {
            is_ctx_err: false,
            is_cancel_discrete: false,
            message: "server is already CPU mining -- please call `setgenerate 0` \
                      before calling discrete `generate` commands"
                .to_string(),
        });
    }

    // Reject a second discrete call while one is already active (dcrd's
    // `discreteMining && n != 0` guard).
    if mode.discrete && n != 0 {
        return Err(GenerateFailure {
            is_ctx_err: false,
            is_cancel_discrete: false,
            message: "server is already discrete mining -- please wait until \
                      the existing call completes or cancel it"
                .to_string(),
        });
    }

    // Zero blocks claims nothing and returns no hashes, but it does
    // cancel a call in flight, which is the whole point of the form
    // (dcrd `cpuminer.go:845-851`):
    //
    // ```go
    // if n == 0 {
    //     if m.generateCancelFn != nil {
    //         m.generateCancelFn()
    //     }
    //     m.Unlock()
    //     return nil, nil
    // }
    // ```
    //
    // Raising the flag under the same lock that publishes it is what
    // makes it impossible to cancel a call that has not started or one
    // that has already cleared its handle.
    if n == 0 {
        if let Some(cancel) = mode.generate_cancel.as_ref() {
            cancel.store(true, Ordering::Release);
        }
        return Ok(None);
    }

    let cancel = Arc::new(AtomicBool::new(false));
    mode.generate_cancel = Some(Arc::clone(&cancel));
    mode.discrete = true;
    Ok(Some(cancel))
}

struct DiscreteMiningGuard(Arc<Mutex<MiningMode>>);

impl Drop for DiscreteMiningGuard {
    fn drop(&mut self) {
        // Clear on every exit path including an unwinding panic, as
        // dcrd's `defer func() { m.discreteMining = false }` does.  A
        // poisoned lock is still recovered so a panicking generate
        // cannot latch the flag and reject every later call.
        let mut mode = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        mode.discrete = false;
        // dcrd's deferred `m.generateCancelFn(); m.generateCancelFn = nil`.
        // Dropping the handle is what stops a later `generate 0` from
        // cancelling a call that has already returned.
        mode.generate_cancel = None;
    }
}

/// How often a [`DiscreteWatch`] looks at the chain tip and the stop
/// flags.
const DISCRETE_WATCH_INTERVAL: Duration = Duration::from_millis(10);

/// Wakes a discrete run's template wait on the other arms of dcrd's
/// `GenerateNBlocks` select: a connected block at or past the target
/// height (`case block := <-m.notifyBlocks`, which the server fills from
/// every `BlockConnected`, whatever the block's source), the `generate
/// 0` cancellation (`<-genCtx.Done()`), and the miner's quit
/// (`<-m.quit`).
///
/// The template subscription is an `mpsc` receiver that cannot select
/// against another source, so a thread polls those instead and raises
/// the flag the wait already honours.  Without it the wait left only on
/// the next template, which past stake validation height waits for the
/// votes on the new block, or on the 5.5 s template timeout: every
/// `generate` returned seconds after its last block had connected.  The
/// chain lock is only tried, so a block being connected never keeps the
/// watch from seeing a cancellation.
struct DiscreteWatch {
    done: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl DiscreteWatch {
    /// Start watching; `wake` is raised, once, when the run should stop
    /// waiting for templates.
    fn start(
        chain: Arc<Mutex<Chain>>,
        target_height: i64,
        generate_cancel: Arc<AtomicBool>,
        quit: Arc<AtomicBool>,
        wake: Arc<AtomicBool>,
    ) -> DiscreteWatch {
        let done = Arc::new(AtomicBool::new(false));
        let watching = Arc::clone(&done);
        let thread = thread::spawn(move || {
            while !watching.load(Ordering::Acquire) {
                let reached = chain
                    .try_lock()
                    .is_ok_and(|chain| chain.best_snapshot().height >= target_height);
                if reached
                    || generate_cancel.load(Ordering::Acquire)
                    || quit.load(Ordering::Acquire)
                {
                    wake.store(true, Ordering::Release);
                    return;
                }
                thread::sleep(DISCRETE_WATCH_INTERVAL);
            }
        });
        DiscreteWatch {
            done,
            thread: Some(thread),
        }
    }
}

impl Drop for DiscreteWatch {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The daemon's CPU miner over the live generator, chain, and
/// block-submit seam (dcrd `CPUMiner`), holding the RPC-facing state and
/// the channels to the background threads.
pub struct NodeCpuMiner {
    current: Arc<Mutex<SharedTemplate>>,
    subscribers: Arc<Mutex<SubscriberRegistry>>,
    sink: GeneratorSink,
    chain: Arc<Mutex<Chain>>,
    sync_manager: Arc<Mutex<NodeSyncManager>>,
    pool: Arc<Mutex<NodeTxPool>>,
    params: Params,
    policy: MiningPolicy,
    mining_time_offset: i64,
    /// The handshaken-peer registry behind the connection wait (dcrd
    /// `cfg.ConnectedCount`, which is `server.ConnectedCount` over its
    /// `peerState`), not the socket registry, which also holds sockets
    /// still in their version handshake.
    connected: SyncPeers,
    /// Whether the network permits mining without connected peers (dcrd
    /// `PermitConnectionlessMining`, true on simnet and regnet).
    permit_connectionless: bool,
    /// The target continuous worker count, shared with the controller
    /// (dcrd `numWorkers atomic.Uint32`).
    num_workers: Arc<AtomicU32>,
    /// The `normalMining`/`discreteMining` pair under one lock, mirroring
    /// dcrd's embedded `sync.Mutex` (see [`MiningMode`]).
    mining_mode: Arc<Mutex<MiningMode>>,
    /// The block hash of the template last successfully submitted, used
    /// to skip re-solving a template the subscription re-delivers while
    /// the generator has not yet produced a new one (dcrd's
    /// `discretePrevTemplate` pointer identity, tracked by the block
    /// hash).
    discrete_prev_template: Arc<Mutex<Option<Hash>>>,
    /// The per-worker speed statistics the monitor sums (dcrd
    /// `speedStats` map).
    speed_stats: Arc<Mutex<HashMap<u64, Arc<SpeedStats>>>>,
    /// The count of blocks mined on each parent, for the connectionless
    /// cap (dcrd `minedOnParents`).
    mined_on_parents: Arc<Mutex<HashMap<Hash, u8>>>,
    /// Flipped at daemon shutdown to stop in-flight mining (dcrd
    /// `m.quit`).
    quit: Arc<AtomicBool>,
    controller_tx: mpsc::Sender<ControllerCmd>,
    monitor_tx: mpsc::Sender<MonitorCmd>,
    /// The receiving halves of the two command channels, handed to their
    /// threads by [`Self::start`] and `None` afterwards.  A
    /// [`std::sync::mpsc::Receiver`] is `Send` but not `Sync`, so the
    /// mutex is what lets the miner sit behind a shared reference in the
    /// RPC config now that the server takes `&self`; it is uncontended
    /// (taken once, at startup).
    controller_rx: Mutex<Option<mpsc::Receiver<ControllerCmd>>>,
    monitor_rx: Mutex<Option<mpsc::Receiver<MonitorCmd>>>,
}

impl NodeCpuMiner {
    /// Build the CPU miner over the running generator's handles, the
    /// shared chain, the sync manager (for `process_block`), the mempool,
    /// and the handshaken-peer registry (dcrd `cpuminer.New` over its
    /// `Config`).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        current: Arc<Mutex<SharedTemplate>>,
        subscribers: Arc<Mutex<SubscriberRegistry>>,
        sink: GeneratorSink,
        chain: Arc<Mutex<Chain>>,
        sync_manager: Arc<Mutex<NodeSyncManager>>,
        pool: Arc<Mutex<NodeTxPool>>,
        params: Params,
        policy: MiningPolicy,
        mining_time_offset: i64,
        connected: SyncPeers,
        permit_connectionless: bool,
    ) -> NodeCpuMiner {
        let (controller_tx, controller_rx) = mpsc::channel();
        let (monitor_tx, monitor_rx) = mpsc::channel();
        NodeCpuMiner {
            current,
            subscribers,
            sink,
            chain,
            sync_manager,
            pool,
            params,
            policy,
            mining_time_offset,
            connected,
            permit_connectionless,
            num_workers: Arc::new(AtomicU32::new(DEFAULT_NUM_WORKERS)),
            mining_mode: Arc::new(Mutex::new(MiningMode::default())),
            discrete_prev_template: Arc::new(Mutex::new(None)),
            speed_stats: Arc::new(Mutex::new(HashMap::new())),
            mined_on_parents: Arc::new(Mutex::new(HashMap::new())),
            quit: Arc::new(AtomicBool::new(false)),
            controller_tx,
            monitor_tx,
            controller_rx: Mutex::new(Some(controller_rx)),
            monitor_rx: Mutex::new(Some(monitor_rx)),
        }
    }

    /// Start the background speed-monitor and worker-controller threads
    /// idle (dcrd `Run` launching `speedMonitor` and
    /// `miningWorkerController`), returning the daemon's shutdown handle.
    /// Must be called exactly once.
    pub fn start(&mut self) -> MinerRuntime {
        self.start_with_hps_interval(HPS_UPDATE_INTERVAL)
    }

    /// [`Self::start`] with an injectable speed-monitor interval for
    /// tests.
    fn start_with_hps_interval(&mut self, interval: Duration) -> MinerRuntime {
        crate::logging::trace("MINR", "Starting CPU miner in idle state");
        let monitor_rx = self
            .monitor_rx
            .lock()
            .expect("monitor channel poisoned")
            .take()
            .expect("miner started once");
        let controller_rx = self
            .controller_rx
            .lock()
            .expect("controller channel poisoned")
            .take()
            .expect("miner started once");
        let speed_stats = Arc::clone(&self.speed_stats);
        let speed_thread =
            thread::spawn(move || run_speed_monitor(monitor_rx, speed_stats, interval));
        let shared = self.solve_shared();
        let controller_thread = thread::spawn(move || run_controller(controller_rx, shared));
        MinerRuntime {
            controller_tx: self.controller_tx.clone(),
            monitor_tx: self.monitor_tx.clone(),
            speed_thread: Some(speed_thread),
            controller_thread: Some(controller_thread),
            quit: Arc::clone(&self.quit),
        }
    }

    /// The bundle of shared handles the background workers and solvers
    /// own (cloned so they outlive the boxed miner).
    fn solve_shared(&self) -> SolveShared {
        SolveShared {
            current: Arc::clone(&self.current),
            subscribers: Arc::clone(&self.subscribers),
            sink: self.sink.clone(),
            chain: Arc::clone(&self.chain),
            sync_manager: Arc::clone(&self.sync_manager),
            pool: Arc::clone(&self.pool),
            params: self.params.clone(),
            policy: self.policy.clone(),
            mining_time_offset: self.mining_time_offset,
            num_workers: Arc::clone(&self.num_workers),
            quit: Arc::clone(&self.quit),
            speed_stats: Arc::clone(&self.speed_stats),
            mined_on_parents: Arc::clone(&self.mined_on_parents),
            connected: self.connected.clone(),
            permit_connectionless: self.permit_connectionless,
        }
    }

    /// The best main-chain height (dcrd `cfg.BestSnapshot().Height`).
    fn best_height(&self) -> i64 {
        self.chain
            .lock()
            .expect("chain mutex poisoned")
            .best_snapshot()
            .height
    }

    /// A block-template subscription over the running generator (dcrd
    /// `m.g.Subscribe`), built through the getwork templater's
    /// register-before-deliver-current path.
    fn subscribe(&self) -> Box<dyn RpcTemplateSubscription + Send> {
        subscribe_over(
            &self.current,
            &self.subscribers,
            &self.sink,
            &self.chain,
            &self.pool,
            &self.params,
            &self.policy,
            self.mining_time_offset,
        )
    }

    /// Spawn a worker thread that solves the template and, on a
    /// solution, submits it through the block-submit seam (dcrd's solve
    /// goroutine in `GenerateNBlocks`).
    fn spawn_solve(
        &self,
        block: MsgBlock,
        is_blake3_pow_active: bool,
        template_hash: Hash,
        target_height: i64,
        cancel: Arc<AtomicBool>,
        generate_cancel: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        let quit = Arc::clone(&self.quit);
        let chain = Arc::clone(&self.chain);
        let sync_manager = Arc::clone(&self.sync_manager);
        let pool = Arc::clone(&self.pool);
        let params = self.params.clone();
        let policy = self.policy.clone();
        let offset = self.mining_time_offset;
        let prev = Arc::clone(&self.discrete_prev_template);
        thread::spawn(move || {
            solve_and_submit(SolveJob {
                block,
                is_blake3_pow_active,
                template_hash,
                target_height,
                cancel,
                generate_cancel,
                quit,
                chain,
                sync_manager,
                pool,
                params,
                policy,
                mining_time_offset: offset,
                discrete_prev_template: prev,
            });
        })
    }
}

/// The daemon-held handle owning the miner's background threads (dcrd's
/// `Run` goroutine and its `speedMonitor`/`miningWorkerController`
/// subordinates), stopped on shutdown.
pub struct MinerRuntime {
    controller_tx: mpsc::Sender<ControllerCmd>,
    monitor_tx: mpsc::Sender<MonitorCmd>,
    speed_thread: Option<JoinHandle<()>>,
    controller_thread: Option<JoinHandle<()>>,
    quit: Arc<AtomicBool>,
}

impl MinerRuntime {
    /// Flip the shutdown flag so any in-flight solve stops hashing
    /// promptly, without yet joining the threads (dcrd cancels the
    /// miner's context early in the shutdown sequence).
    pub fn signal_quit(&self) {
        self.quit.store(true, Ordering::Release);
    }

    /// Stop the background threads and join them (dcrd `Run` returning on
    /// context cancellation after `wg.Wait`).
    pub fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        self.quit.store(true, Ordering::Release);
        let _ = self.controller_tx.send(ControllerCmd::Stop);
        let _ = self.monitor_tx.send(MonitorCmd::Stop);
        // `shutdown` stops and then drops, so only the call that joins
        // the threads logs dcrd's closing trace line.
        let was_running = self.controller_thread.is_some() || self.speed_thread.is_some();
        if let Some(thread) = self.controller_thread.take() {
            let _ = thread.join();
        }
        if let Some(thread) = self.speed_thread.take() {
            let _ = thread.join();
        }
        if was_running {
            crate::logging::trace("MINR", "CPU miner stopped");
        }
    }
}

impl Drop for MinerRuntime {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The shared handles a continuous worker or solver owns (cloned per
/// worker so the threads outlive the boxed miner).
#[derive(Clone)]
struct SolveShared {
    current: Arc<Mutex<SharedTemplate>>,
    subscribers: Arc<Mutex<SubscriberRegistry>>,
    sink: GeneratorSink,
    chain: Arc<Mutex<Chain>>,
    sync_manager: Arc<Mutex<NodeSyncManager>>,
    pool: Arc<Mutex<NodeTxPool>>,
    params: Params,
    policy: MiningPolicy,
    mining_time_offset: i64,
    num_workers: Arc<AtomicU32>,
    quit: Arc<AtomicBool>,
    speed_stats: Arc<Mutex<HashMap<u64, Arc<SpeedStats>>>>,
    mined_on_parents: Arc<Mutex<HashMap<Hash, u8>>>,
    connected: SyncPeers,
    permit_connectionless: bool,
}

impl SolveShared {
    fn subscribe(&self) -> Box<dyn RpcTemplateSubscription + Send> {
        subscribe_over(
            &self.current,
            &self.subscribers,
            &self.sink,
            &self.chain,
            &self.pool,
            &self.params,
            &self.policy,
            self.mining_time_offset,
        )
    }
}

/// Build a template subscription over the generator handles through the
/// getwork templater's register-before-deliver-current path (dcrd
/// `g.Subscribe`).
#[allow(clippy::too_many_arguments)]
fn subscribe_over(
    current: &Arc<Mutex<SharedTemplate>>,
    subscribers: &Arc<Mutex<SubscriberRegistry>>,
    sink: &GeneratorSink,
    chain: &Arc<Mutex<Chain>>,
    pool: &Arc<Mutex<NodeTxPool>>,
    params: &Params,
    policy: &MiningPolicy,
    mining_time_offset: i64,
) -> Box<dyn RpcTemplateSubscription + Send> {
    let templater = NodeRpcBlockTemplater::new(
        Arc::clone(current),
        Arc::clone(subscribers),
        sink.clone(),
        Arc::clone(chain),
        Arc::clone(pool),
        params.clone(),
        policy.clone(),
        mining_time_offset,
    );
    templater.subscribe()
}

/// Refresh the header timestamp over a throwaway builder on the live
/// chain (dcrd `g.UpdateBlockTime`).
fn refresh_block_time(
    chain: &Arc<Mutex<Chain>>,
    pool: &Arc<Mutex<NodeTxPool>>,
    params: &Params,
    policy: &MiningPolicy,
    offset: i64,
    header: &mut BlockHeader,
) {
    let builder = BlkTmplGenerator::new(
        policy.clone(),
        params,
        NodeTemplateChain::new(Arc::clone(chain), params.clone()),
        NodeTemplateTxSource::new(Arc::clone(pool)),
        offset,
    );
    builder.update_block_time(header);
}

/// The speed-monitor thread: it recomputes the hash rate on a fixed
/// interval and answers rate queries with the cached value (dcrd
/// `speedMonitor`).
fn run_speed_monitor(
    rx: mpsc::Receiver<MonitorCmd>,
    speed_stats: Arc<Mutex<HashMap<u64, Arc<SpeedStats>>>>,
    interval: Duration,
) {
    crate::logging::trace("MINR", "CPU miner speed monitor started");
    let mut hashes_per_sec = 0.0f64;
    let mut deadline = Instant::now()
        .checked_add(interval)
        .expect("speed monitor deadline");
    loop {
        let wait = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(wait) {
            Ok(MonitorCmd::Query(reply)) => {
                // Answer with the cached rate; the deadline is not
                // advanced, so recomputation stays on its own cadence
                // (dcrd's independent `ticker.C` arm).
                let _ = reply.send(hashes_per_sec);
            }
            Ok(MonitorCmd::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                crate::logging::trace("MINR", "CPU miner speed monitor done");
                return;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                hashes_per_sec = recompute_hashes_per_sec(&speed_stats);
                if let Some(line) = hash_speed_line(hashes_per_sec) {
                    crate::logging::debug("MINR", &line);
                }
                deadline = Instant::now()
                    .checked_add(interval)
                    .expect("speed monitor deadline");
            }
        }
    }
}

/// Sum each worker's hashes-per-second since the last recompute, taking
/// and resetting the per-worker counters (dcrd's `Swap(0)` fold).
fn recompute_hashes_per_sec(speed_stats: &Arc<Mutex<HashMap<u64, Arc<SpeedStats>>>>) -> f64 {
    let mut hashes_per_sec = 0.0f64;
    let stats = speed_stats.lock().expect("speed stats poisoned");
    for worker in stats.values() {
        let total_hashes = worker.total_hashes.swap(0, Ordering::Relaxed);
        let elapsed_secs = worker.elapsed_micros.swap(0, Ordering::Relaxed) / 1_000_000;
        if total_hashes == 0 || elapsed_secs == 0 {
            continue;
        }
        hashes_per_sec += total_hashes as f64 / elapsed_secs as f64;
    }
    hashes_per_sec
}

/// dcrd's speed-monitor line for a recomputed rate, or `None` for the
/// zero or NaN rate it does not log (`speedMonitor`,
/// `internal/mining/cpuminer/cpuminer.go:198-200`).  Rust's `{:6.0}`
/// pads and rounds a finite rate as Go's `%6.0f` does.
fn hash_speed_line(hashes_per_sec: f64) -> Option<String> {
    if hashes_per_sec == 0.0 || hashes_per_sec.is_nan() {
        return None;
    }
    Some(format!(
        "Hash speed: {:6.0} kilohashes/s",
        hashes_per_sec / 1000.0
    ))
}

/// dcrd's worker-controller line after launching or stopping workers,
/// which names the new target as the total running
/// (`miningWorkerController`, `cpuminer.go:600-615`).
fn worker_change_line(verb: &str, changed: usize, target: usize) -> String {
    format!(
        "{verb} {changed} {} ({target} total running)",
        crate::server::pick_noun(changed as u64, "worker", "workers")
    )
}

/// dcrd's info line when a connectionless solver stops on a parent that
/// has had `maxSimnetToMine` solutions fail to submit (`solver`,
/// `cpuminer.go:412-420`).
const TOO_MANY_ON_PARENT: &str = "too many blocks mined on parent, stopping until there are \
                                  enough votes on these to make a new block";

/// A running continuous worker: its cancellation flag and join handle.
struct WorkerHandle {
    cancel: Arc<AtomicBool>,
    join: JoinHandle<()>,
}

/// The worker-controller thread: it launches or stops `generateBlocks`
/// workers to match the shared target count (dcrd
/// `miningWorkerController`).
fn run_controller(rx: mpsc::Receiver<ControllerCmd>, shared: SolveShared) {
    let mut running: Vec<WorkerHandle> = Vec::new();
    let mut retired: Vec<JoinHandle<()>> = Vec::new();
    let mut next_id: u64 = 0;
    loop {
        match rx.recv() {
            Ok(ControllerCmd::Update) => {
                // Reap any scaled-down workers that have since finished,
                // and drop any running worker that exited on its own (its
                // template subscription was canceled) so it stops counting
                // toward the target and a replacement is launched — dcrd's
                // workers only exit on `ctx.Done`, so a self-exited worker
                // has no analogue there and must not leave the running
                // count overstated.
                retired.retain(|handle| !handle.is_finished());
                running.retain(|handle| !handle.join.is_finished());

                // No change logs nothing, as dcrd's `continue` does.
                let target = shared.num_workers.load(Ordering::Acquire) as usize;
                if target > running.len() {
                    let num_to_launch = target.saturating_sub(running.len());
                    for _ in 0..num_to_launch {
                        let cancel = Arc::new(AtomicBool::new(false));
                        let worker_shared = shared.clone();
                        let worker_cancel = Arc::clone(&cancel);
                        let id = next_id;
                        next_id = next_id.wrapping_add(1);
                        let join = thread::spawn(move || {
                            generate_blocks(id, worker_cancel, worker_shared)
                        });
                        running.push(WorkerHandle { cancel, join });
                    }
                    crate::logging::debug(
                        "MINR",
                        &worker_change_line("Launched", num_to_launch, target),
                    );
                } else if target < running.len() {
                    // Signal the most recently created workers to exit
                    // and retire their handles for later joining.
                    let num_to_stop = running.len().saturating_sub(target);
                    for _ in 0..num_to_stop {
                        if let Some(handle) = running.pop() {
                            handle.cancel.store(true, Ordering::Release);
                            retired.push(handle.join);
                        }
                    }
                    crate::logging::debug(
                        "MINR",
                        &worker_change_line("Stopped", num_to_stop, target),
                    );
                }
            }
            Ok(ControllerCmd::Stop) | Err(_) => {
                for handle in &running {
                    handle.cancel.store(true, Ordering::Release);
                }
                for handle in running {
                    let _ = handle.join.join();
                }
                for join in retired {
                    let _ = join.join();
                }
                return;
            }
        }
    }
}

/// Removes a worker's speed statistics from the shared map on every exit
/// path from `generate_blocks`, including an unwinding panic, so a dead
/// worker's entry can never linger and inflate the reported hash rate
/// (dcrd deletes `speedStats[id]` in a `defer`).
struct SpeedStatsGuard {
    id: u64,
    speed_stats: Arc<Mutex<HashMap<u64, Arc<SpeedStats>>>>,
}

impl Drop for SpeedStatsGuard {
    fn drop(&mut self) {
        if let Ok(mut stats) = self.speed_stats.lock() {
            stats.remove(&self.id);
        }
    }
}

/// One continuous mining worker: it subscribes for templates and solves
/// each on a solver thread, switching to new templates as they arrive
/// (dcrd `generateBlocks`).
fn generate_blocks(id: u64, cancel: Arc<AtomicBool>, shared: SolveShared) {
    crate::logging::trace("MINR", "Starting generate blocks worker");
    let stats = Arc::new(SpeedStats::default());
    shared
        .speed_stats
        .lock()
        .expect("speed stats poisoned")
        .insert(id, Arc::clone(&stats));
    // The guard removes the entry on every exit path, including a panic.
    let _stats_guard = SpeedStatsGuard {
        id,
        speed_stats: Arc::clone(&shared.speed_stats),
    };

    let subscription = shared.subscribe();
    let mut last_prev: Option<Hash> = None;
    // The currently running solver, and the previously-cancelled solvers
    // still winding down.  dcrd cancels the outgoing solver and lets it
    // finish concurrently (a fire-and-forget goroutine joined only via
    // `solverWg` at teardown) so template notifications are serviced
    // immediately without waiting for the old solver to stop; the port
    // mirrors that — the cancelled handle moves to `draining` and is
    // joined only when the worker exits, never blocking the loop.
    let mut solver: Option<(JoinHandle<()>, Arc<AtomicBool>)> = None;
    let mut draining: Vec<JoinHandle<()>> = Vec::new();

    loop {
        if cancel.load(Ordering::Acquire) || shared.quit.load(Ordering::Acquire) {
            break;
        }
        match subscription.recv_with_timeout() {
            TemplateRecv::Template(block) => {
                let prev = block.header.prev_block;
                // On a genuinely new parent, drop the mined-on-parent
                // counts for all other parents so the map cannot grow
                // unbounded (dcrd's `TURNewParent` cleanup).  Only clean
                // once the parent has actually changed from one this
                // worker already saw: the subscription carries no update
                // reason, so the parent changing is the reconstruction of
                // `Reason == TURNewParent`, and the very first template a
                // worker receives is not a parent change — cleaning on it
                // would wrongly reset another worker's counts for the
                // current parent.
                if shared.permit_connectionless
                    && let Some(last) = last_prev
                    && last != prev
                {
                    shared
                        .mined_on_parents
                        .lock()
                        .expect("mined-on-parents poisoned")
                        .retain(|parent, _| *parent == prev);
                }
                last_prev = Some(prev);

                // Cancel the previous solver and let it wind down in the
                // background (dcrd's `solverCancel()` without a join), so a
                // long in-flight `process_block` or connection wait cannot
                // stall servicing this fresher template.  Reap any drained
                // solvers that have since finished to bound the vector.
                if let Some((handle, solver_cancel)) = solver.take() {
                    solver_cancel.store(true, Ordering::Release);
                    draining.push(handle);
                }
                draining.retain(|handle| !handle.is_finished());

                let is_blake3_pow_active = match shared
                    .chain
                    .lock()
                    .expect("chain mutex poisoned")
                    .is_blake3_pow_agenda_active(&prev, &shared.params)
                {
                    Ok(active) => active,
                    Err(_) => continue,
                };

                let solver_cancel = Arc::new(AtomicBool::new(false));
                let job = ContinuousSolve {
                    template: *block,
                    stats: Arc::clone(&stats),
                    is_blake3_pow_active,
                    cancel: Arc::clone(&solver_cancel),
                    worker_cancel: Arc::clone(&cancel),
                    shared: shared.clone(),
                };
                let handle = thread::spawn(move || continuous_solve(job));
                solver = Some((handle, solver_cancel));
            }
            TemplateRecv::Timeout => {}
            TemplateRecv::Canceled => break,
        }
    }

    // Cancel the live solver and join every outstanding solver (dcrd's
    // deferred `solverWg.Wait()`).  The worker's own cancel is already set
    // by the controller on a scale-down, so the solvers observe it too.
    if let Some((handle, solver_cancel)) = solver.take() {
        solver_cancel.store(true, Ordering::Release);
        draining.push(handle);
    }
    for handle in draining {
        let _ = handle.join();
    }
    subscription.stop();
    crate::logging::trace("MINR", "Generate blocks worker done");
}

/// The state one continuous solver thread owns for its template.
struct ContinuousSolve {
    template: MsgBlock,
    stats: Arc<SpeedStats>,
    is_blake3_pow_active: bool,
    /// Set when a fresher template supersedes this solver (dcrd's
    /// `solverCancel`).
    cancel: Arc<AtomicBool>,
    /// The owning worker's cancellation flag, set by the controller on a
    /// scale-down.  dcrd derives the solver context from the worker
    /// context, so a worker cancellation also stops its solver; the port
    /// checks this flag alongside `cancel` so `setgenerate 0` and shutdown
    /// stop an in-flight solve promptly instead of after the worker's next
    /// (up to multi-second) template poll — and, crucially, keep it from
    /// submitting a block after mining was disabled.
    worker_cancel: Arc<AtomicBool>,
    shared: SolveShared,
}

/// One continuous solver: it repeatedly solves the template's proof of
/// work and submits solutions, handling the connection wait and the
/// connectionless per-parent cap (dcrd `solver`).
fn continuous_solve(job: ContinuousSolve) {
    let ContinuousSolve {
        template,
        stats,
        is_blake3_pow_active,
        cancel,
        worker_cancel,
        shared,
    } = job;
    let start = Instant::now();
    let prev = template.header.prev_block;
    let stop = |shared: &SolveShared| {
        cancel.load(Ordering::Acquire)
            || worker_cancel.load(Ordering::Acquire)
            || shared.quit.load(Ordering::Acquire)
    };

    loop {
        if stop(&shared) {
            return;
        }

        // Wait for a connected peer when not connectionless, since a
        // solved block cannot be relayed otherwise (dcrd's connection
        // wait).
        while !shared.permit_connectionless && shared.connected.is_empty() {
            if stop(&shared) {
                return;
            }
            thread::sleep(Duration::from_secs(1));
        }

        // Stop mining alternatives once too many have failed to submit on
        // this parent in connectionless mode (dcrd's `maxSimnetToMine`).
        if shared.permit_connectionless {
            let maxed = shared
                .mined_on_parents
                .lock()
                .expect("mined-on-parents poisoned")
                .get(&prev)
                .copied()
                .unwrap_or(0)
                >= MAX_SIMNET_TO_MINE;
            if maxed {
                crate::logging::info("MINR", TOO_MANY_ON_PARENT);
                return;
            }
        }

        // Solve a fresh copy of the template so the shared template block
        // is never mutated (dcrd's shallow copy).
        let mut block = template.clone();
        let en_offset = random_u64();
        let mut update_block_time = |header: &mut BlockHeader| {
            refresh_block_time(
                &shared.chain,
                &shared.pool,
                &shared.params,
                &shared.policy,
                shared.mining_time_offset,
                header,
            );
        };
        let mut should_cancel = || stop(&shared);
        let mut now_micros = || start.elapsed().as_micros() as u64;
        let solved = solve_block(
            &mut block.header,
            &stats,
            is_blake3_pow_active,
            en_offset,
            &mut update_block_time,
            &mut should_cancel,
            &mut now_micros,
        );
        if !solved {
            // Cancelled or an undecodable target; the top-of-loop check
            // returns on cancellation.
            continue;
        }

        // Avoid submitting a stale solution found after a stop signal.
        // dcrd checks the solver context, which derives from the
        // worker's, so a worker cancelled by `SetNumWorkers` is covered
        // as well as a superseded template and shutdown.
        if stop(&shared) {
            return;
        }
        if submit_block(&shared.sync_manager, &block, is_blake3_pow_active) {
            return;
        }
        // The solution failed to submit; count it against this parent and
        // try another (dcrd's `minedOnParents[prevBlock]++`).  The count
        // saturates rather than wrapping, but the `maxSimnetToMine` cap
        // above stops the solver long before it could get near the limit.
        let mut mined = shared
            .mined_on_parents
            .lock()
            .expect("mined-on-parents poisoned");
        let count = mined.entry(prev).or_insert(0);
        *count = count.saturating_add(1);
    }
}

/// The state a discrete solve worker thread owns for one template (all
/// handles are cloned in so the thread outlives the miner's borrow).
struct SolveJob {
    block: MsgBlock,
    is_blake3_pow_active: bool,
    template_hash: Hash,
    target_height: i64,
    cancel: Arc<AtomicBool>,
    /// The discrete call's own cancellation, so a `generate 0` reaches
    /// the worker as promptly as it reaches the loop.
    ///
    /// dcrd derives the solve context from the generate context --
    /// `solveCtx, cancel := context.WithCancel(genCtx)` -- so cancelling
    /// the latter cancels the former at once. Without this the worker
    /// would keep hashing until the loop noticed and stopped it, and
    /// could submit in between a block dcrd would have suppressed.
    generate_cancel: Arc<AtomicBool>,
    quit: Arc<AtomicBool>,
    chain: Arc<Mutex<Chain>>,
    sync_manager: Arc<Mutex<NodeSyncManager>>,
    pool: Arc<Mutex<NodeTxPool>>,
    params: Params,
    policy: MiningPolicy,
    mining_time_offset: i64,
    discrete_prev_template: Arc<Mutex<Option<Hash>>>,
}

/// Solve one template's proof of work and, on success, submit it (dcrd's
/// discrete solve goroutine body in `GenerateNBlocks`).
fn solve_and_submit(mut job: SolveJob) {
    let stats = SpeedStats::default();
    let en_offset = random_u64();
    let start = Instant::now();

    let mut update_block_time = |header: &mut BlockHeader| {
        refresh_block_time(
            &job.chain,
            &job.pool,
            &job.params,
            &job.policy,
            job.mining_time_offset,
            header,
        );
    };

    let cancel = Arc::clone(&job.cancel);
    let generate_cancel = Arc::clone(&job.generate_cancel);
    let quit = Arc::clone(&job.quit);
    let mut should_cancel = move || {
        cancel.load(Ordering::Acquire)
            || generate_cancel.load(Ordering::Acquire)
            || quit.load(Ordering::Acquire)
    };

    let mut now_micros = || start.elapsed().as_micros() as u64;

    let solved = solve_block(
        &mut job.block.header,
        &stats,
        job.is_blake3_pow_active,
        en_offset,
        &mut update_block_time,
        &mut should_cancel,
        &mut now_micros,
    );
    if !solved {
        return;
    }

    // Avoid submitting a solution found in the window between a stop
    // signal and the worker actually stopping, or one that would extend
    // the chain past the target height (dcrd's two post-solve guards).
    if job.cancel.load(Ordering::Acquire)
        || job.generate_cancel.load(Ordering::Acquire)
        || job.quit.load(Ordering::Acquire)
    {
        return;
    }
    {
        let best = job
            .chain
            .lock()
            .expect("chain mutex poisoned")
            .best_snapshot()
            .height;
        if best >= job.target_height {
            return;
        }
    }

    // Submit through the same path a network block takes; on acceptance
    // record the template so the subscription's re-delivery of it is
    // skipped (dcrd `submitBlock` + `discretePrevTemplate.Store`).
    let accepted = submit_block(&job.sync_manager, &job.block, job.is_blake3_pow_active);
    if accepted {
        *job.discrete_prev_template
            .lock()
            .expect("prev template poisoned") = Some(job.template_hash);
    }
}

/// Submit a solved block through the same path a network block takes and
/// log the outcome under `MINR`, the logger dcrd hands its CPU miner
/// (`log.go`, `cpuminer.UseLogger(minrLog)`), returning whether it was
/// accepted (dcrd `submitBlock`,
/// `internal/mining/cpuminer/cpuminer.go:218-256`).
fn submit_block(
    sync_manager: &Mutex<NodeSyncManager>,
    block: &MsgBlock,
    is_blake3_pow_active: bool,
) -> bool {
    let result = sync_manager
        .lock()
        .expect("sync manager mutex poisoned")
        .process_block(block);
    match submit_log_line(&result, &block.header, is_blake3_pow_active) {
        (true, line) => crate::logging::info("MINR", &line),
        (false, line) => crate::logging::error("MINR", &line),
    }
    result.is_ok()
}

/// The line dcrd's `submitBlock` logs for a submission's outcome, with
/// whether it is the info-level acceptance (the rest log at error level).
fn submit_log_line(
    result: &Result<(), dcroxide_netsync::ProcessBlockFailure>,
    header: &BlockHeader,
    is_blake3_pow_active: bool,
) -> (bool, String) {
    let failure = match result {
        Ok(()) => {
            // The proof-of-work hash is named when it differs from the
            // block hash, which is always under BLAKE3 (DCP0011).
            let block_hash = header.block_hash();
            let pow_hash = if is_blake3_pow_active {
                header.pow_hash_v2()
            } else {
                header.pow_hash_v1()
            };
            let pow_hash_str = if pow_hash == block_hash {
                String::new()
            } else {
                format!(", pow hash {pow_hash}")
            };
            let height = header.height;
            return (
                true,
                format!(
                    "Block submitted via CPU miner accepted (hash {block_hash}, height \
                     {height}{pow_hash_str})"
                ),
            );
        }
        Err(failure) => failure,
    };

    // dcrd tests `errors.Is(err, blockchain.ErrMissingParent)` first.  The
    // failure carries no kind, but the chain's missing-parent error text
    // names this block's parent (`previous block %s is not known`), which
    // no other rejection of it does.
    let prev = header.prev_block;
    if failure.message == format!("previous block {prev} is not known") {
        return (
            false,
            format!("Block submitted via CPU miner is an orphan building on parent {prev}"),
        );
    }

    // Anything other than a rule violation is an unexpected error.
    if !failure.is_rule_error {
        return (
            false,
            format!(
                "Unexpected error while processing block submitted via CPU miner: {}",
                failure.message
            ),
        );
    }
    (
        false,
        format!(
            "Block submitted via CPU miner rejected: {}",
            failure.message
        ),
    )
}

/// A fresh random 64-bit extra-nonce offset (dcrd `rand.Uint64()` in
/// `solveBlock`, `internal/mining/cpuminer/cpuminer.go:273`).
///
/// From the process-wide generator, not a fresh kernel read: dcrd's
/// cpuminer imports `crypto/rand` and calls the package function
/// (`cpuminer.go:21`, `:273`).  An offset is drawn each time a worker
/// takes up a template, and templates follow block connects, so on a
/// `--generate` node a peer relaying a block paces this -- the same
/// path that paced the template generator's own draws before those
/// moved.  Under `panic = "abort"` a failed read here would be an
/// outage; the package generator cannot fail once seeded, which the
/// daemon does at startup.
fn random_u64() -> u64 {
    dcroxide_crypto::rand::uint64()
}

/// The maximum number of mining workers (dcrd `MaxNumWorkers =
/// runtime.NumCPU() * 2`).
fn max_num_workers() -> u32 {
    let cpus = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    u32::try_from(cpus)
        .unwrap_or(u32::MAX / 2)
        .saturating_mul(2)
}

impl RpcCpuMiner for NodeCpuMiner {
    fn generate_n_blocks(&self, n: u32) -> Result<Vec<Hash>, GenerateFailure> {
        // One hold of the mode lock spans the whole gate, as dcrd's
        // `m.Lock()` … `m.discreteMining = true` … `m.Unlock()` does.
        let generate_cancel = {
            let mut mode = self
                .mining_mode
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match begin_discrete(&mut mode, n)? {
                Some(cancel) => cancel,
                // `generate 0`: it cancelled whatever was running and
                // claims nothing of its own.
                None => return Ok(Vec::new()),
            }
        };

        // Clear the flag on every exit path — including an unwinding
        // panic — exactly as dcrd's `defer { m.discreteMining = false }`
        // does, so a panic can never latch it and reject all later
        // `generate` calls.
        let _discrete_guard = DiscreteMiningGuard(Arc::clone(&self.mining_mode));
        crate::logging::trace("MINR", &format!("Extending the main chain {n} blocks"));
        let orig_height = self.best_height();
        let target_height = orig_height.saturating_add(i64::from(n));

        let subscription = self.subscribe();
        let mut solve: Option<(JoinHandle<()>, Arc<AtomicBool>)> = None;

        // The template wait also ends on a connected block reaching the
        // target height, a `generate 0` and the miner's quit (dcrd's
        // `notifyBlocks`, `genCtx.Done()` and `m.quit` arms).
        let wake = Arc::new(AtomicBool::new(false));
        let watch = DiscreteWatch::start(
            Arc::clone(&self.chain),
            target_height,
            Arc::clone(&generate_cancel),
            Arc::clone(&self.quit),
            Arc::clone(&wake),
        );

        loop {
            if self.quit.load(Ordering::Acquire) {
                break;
            }
            match subscription.recv_with_timeout_until(&wake) {
                TemplateRecv::Template(block) => {
                    // Stop once the chain reaches the target height.
                    if self.best_height() >= target_height {
                        break;
                    }
                    // Skip a template the subscription re-delivers before
                    // the generator has produced a new one (for example,
                    // while it waits on votes).
                    let template_hash = block.header.block_hash();
                    if *self
                        .discrete_prev_template
                        .lock()
                        .expect("prev template poisoned")
                        == Some(template_hash)
                    {
                        continue;
                    }
                    *self
                        .discrete_prev_template
                        .lock()
                        .expect("prev template poisoned") = None;

                    // Stop the previous solve worker before starting a
                    // new one on the fresh template.
                    if let Some((handle, cancel)) = solve.take() {
                        cancel.store(true, Ordering::Release);
                        let _ = handle.join();
                    }

                    // Determine the blake3 pow agenda state; on the
                    // (practically impossible) error just wait for the
                    // next template.
                    let prev_hash = block.header.prev_block;
                    let is_blake3_pow_active = match self
                        .chain
                        .lock()
                        .expect("chain mutex poisoned")
                        .is_blake3_pow_agenda_active(&prev_hash, &self.params)
                    {
                        Ok(active) => active,
                        Err(_) => continue,
                    };

                    let cancel = Arc::new(AtomicBool::new(false));
                    let handle = self.spawn_solve(
                        *block,
                        is_blake3_pow_active,
                        template_hash,
                        target_height,
                        Arc::clone(&cancel),
                        Arc::clone(&generate_cancel),
                    );
                    solve = Some((handle, cancel));
                }
                TemplateRecv::Timeout => {
                    // No new template within the bound; the target may
                    // already have been reached by a block from another
                    // source, so re-check before waiting again.
                    if self.best_height() >= target_height {
                        break;
                    }
                }
                TemplateRecv::Canceled => break,
            }
        }

        // Stop the watch and the outstanding solve worker and drop the
        // subscription.  The discrete-mining flag is cleared by
        // `_discrete_guard` on return.
        drop(watch);
        if let Some((handle, cancel)) = solve.take() {
            cancel.store(true, Ordering::Release);
            let _ = handle.join();
        }
        subscription.stop();
        let num_extended = self.best_height().wrapping_sub(orig_height);
        crate::logging::trace(
            "MINR",
            &format!("Extended the main chain {num_extended} blocks"),
        );

        // Return the hashes that ultimately extended the main chain,
        // regardless of their origin (dcrd's `BlockHashByHeight` sweep;
        // a zero hash stands in for a lookup miss).
        //
        // Before that, the cancellation check dcrd runs in the same
        // place (`cpuminer.go`, after the solve waitgroup):
        //
        // ```go
        // if genCtx.Err() != nil {
        //     return nil, ErrCancelDiscreteMining
        // }
        // ```
        //
        // `TemplateRecv::Canceled` conflates three of dcrd's arms -- its
        // `<-genCtx.Done()`, which is an error, and its `<-m.quit` and
        // `<-m.notifyBlocks` at the target height, which are not -- so
        // the break alone cannot say which happened.
        // Asking the flag afterwards separates them exactly as dcrd's
        // post-loop `genCtx.Err()` does: a request that went away is a
        // failure, a generator that shut down still reports the blocks
        // that landed.  `handle_generate` then turns this into dcrd's
        // `rpcConnectionClosedError` (`rpcserver.go:1851-1852`) rather
        // than answering a departed client with a hash list.
        // dcrd returns ErrCancelDiscreteMining for either cancellation and
        // lets `handleGenerate` tell them apart by asking the REQUEST
        // context first (`rpcserver.go:1850-1856`):
        //
        // ```go
        // case ctx.Err() != nil:
        //     return nil, rpcConnectionClosedError()
        // case errors.Is(err, cpuminer.ErrCancelDiscreteMining):
        //     return nil, rpcCancelError(...)
        // ```
        //
        // So the order here is dcrd's order, and the two flags carry the
        // distinction across: a client that left reports the connection
        // closed, a `generate 0` reports the cancellation.
        if request_cancelled() {
            return Err(GenerateFailure {
                is_ctx_err: true,
                is_cancel_discrete: true,
                message: ERR_CANCEL_DISCRETE_MINING.to_string(),
            });
        }
        if generate_cancel.load(Ordering::Acquire) {
            return Err(GenerateFailure {
                is_ctx_err: false,
                is_cancel_discrete: true,
                message: ERR_CANCEL_DISCRETE_MINING.to_string(),
            });
        }
        let chain = self.chain.lock().expect("chain mutex poisoned");
        let mut hashes = Vec::with_capacity(n as usize);
        for height in (orig_height.saturating_add(1))..=target_height {
            hashes.push(chain.block_hash_by_height(height).unwrap_or(Hash::ZERO));
        }
        Ok(hashes)
    }

    fn is_mining(&self) -> bool {
        // Mining in either the continuous or discrete mode (dcrd
        // `normalMining || discreteMining`, read under the same lock that
        // guards both).
        let mode = self
            .mining_mode
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        mode.normal || mode.discrete
    }

    fn hashes_per_second(&self) -> f64 {
        // Zero unless continuous mining is running (dcrd's short-circuit).
        if !self
            .mining_mode
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .normal
        {
            return 0.0;
        }
        // Ask the speed monitor for the cached rate over a one-shot reply
        // channel (dcrd's `queryHashesPerSec` rendezvous); a gone monitor
        // reports zero (dcrd's `<-m.quit`).
        let (reply_tx, reply_rx) = mpsc::channel();
        if self.monitor_tx.send(MonitorCmd::Query(reply_tx)).is_err() {
            return 0.0;
        }
        reply_rx.recv().unwrap_or(0.0)
    }

    fn num_workers(&self) -> i32 {
        self.num_workers.load(Ordering::Acquire) as i32
    }

    fn set_num_workers(&self, workers: i32) {
        // The discrete-mode check and the `normal` write happen under one
        // hold, as dcrd's `SetNumWorkers` does with `m.Lock()` +
        // `defer m.Unlock()` over its whole body (`cpuminer.go:697-706`).
        // The same lock guards `generate_n_blocks`' cross-check, so the
        // two RPCs cannot both pass their guards.
        let mut mode = self
            .mining_mode
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Ignored while a discrete generate is running (dcrd's guard).
        if mode.discrete {
            return;
        }
        // A negative count selects the default; the count is clamped to
        // the maximum (dcrd `SetNumWorkers`).  The count is stored before
        // the controller is poked so it reads the up-to-date target.
        let target = if workers < 0 {
            DEFAULT_NUM_WORKERS
        } else {
            (workers as u32).min(max_num_workers())
        };
        self.num_workers.store(target, Ordering::Release);
        mode.normal = target != 0;
        let _ = self.controller_tx.send(ControllerCmd::Update);
    }
}

#[cfg(test)]
mod tests {

    /// dcrd's `generate 0` cancels the call in flight and claims nothing
    /// (`cpuminer.go:845-851`).  Exercised on the gate itself, where the
    /// whole decision lives, so it does not depend on thread timing.
    #[test]
    fn generate_zero_trips_the_handle_of_the_call_in_flight() {
        let mut mode = MiningMode {
            normal: false,
            discrete: false,
            generate_cancel: None,
        };

        // A real call claims discrete mining and publishes its handle.
        let cancel = begin_discrete(&mut mode, 5)
            .expect("a first discrete call is admitted")
            .expect("and is handed its cancellation handle");
        assert!(mode.discrete, "discrete mining is claimed");
        assert!(!cancel.load(Ordering::Acquire), "and is not cancelled yet");

        // `generate 0` claims nothing and trips that handle.
        assert!(
            begin_discrete(&mut mode, 0)
                .expect("generate 0 is always admitted")
                .is_none(),
            "generate 0 claims no handle of its own"
        );
        assert!(
            cancel.load(Ordering::Acquire),
            "generate 0 must cancel the call in flight"
        );
        assert!(
            mode.discrete,
            "but must not clear the flag out from under it -- \
             the running call's guard owns that"
        );
    }

    /// With nothing running there is nothing to cancel, and `generate 0`
    /// must not leave anything behind that would cancel the NEXT call.
    #[test]
    fn generate_zero_with_nothing_running_cancels_nothing() {
        let mut mode = MiningMode {
            normal: false,
            discrete: false,
            generate_cancel: None,
        };
        assert!(
            begin_discrete(&mut mode, 0)
                .expect("generate 0 is admitted")
                .is_none()
        );
        assert!(!mode.discrete, "and claims nothing");

        let cancel = begin_discrete(&mut mode, 3)
            .expect("a later call is admitted")
            .expect("with its own handle");
        assert!(
            !cancel.load(Ordering::Acquire),
            "the later call must not start out cancelled"
        );
    }

    /// The guard drops the handle with the flag, so a `generate 0` that
    /// arrives after the call returned cannot cancel an unrelated later
    /// one (dcrd's deferred `generateCancelFn(); = nil`).
    #[test]
    fn a_finished_call_leaves_no_handle_to_cancel() {
        let mode = Arc::new(Mutex::new(MiningMode {
            normal: false,
            discrete: false,
            generate_cancel: None,
        }));
        let first = {
            let mut m = mode.lock().expect("mode");
            begin_discrete(&mut m, 5)
                .expect("admitted")
                .expect("handle")
        };
        drop(DiscreteMiningGuard(Arc::clone(&mode)));
        assert!(
            mode.lock().expect("mode").generate_cancel.is_none(),
            "the guard drops the handle"
        );

        // A late `generate 0` now finds nothing, and the next call is
        // unaffected.
        {
            let mut m = mode.lock().expect("mode");
            assert!(begin_discrete(&mut m, 0).expect("admitted").is_none());
        }
        let second = {
            let mut m = mode.lock().expect("mode");
            begin_discrete(&mut m, 5)
                .expect("admitted")
                .expect("handle")
        };
        assert!(
            !second.load(Ordering::Acquire),
            "a late generate 0 must not cancel the next call"
        );
        assert!(
            !first.load(Ordering::Acquire),
            "nor retroactively the finished one"
        );
    }

    use super::*;

    /// The two guards are cross-checks over the same state, so a claimed
    /// discrete run blocks continuous mining and vice versa — dcrd's
    /// `normalMining`/`discreteMining` pair under one lock.
    #[test]
    fn the_two_mining_modes_exclude_each_other() {
        // A discrete claim rejects a second one, but `n == 0` still
        // passes through claiming nothing, as dcrd's guard does.
        let mut mode = MiningMode::default();
        assert!(
            begin_discrete(&mut mode, 1)
                .expect("a first generate is admitted")
                .is_some(),
            "and is handed a cancellation handle"
        );
        assert!(
            begin_discrete(&mut mode, 1).is_err(),
            "second generate rejected"
        );
        assert!(
            begin_discrete(&mut mode, 0)
                .expect("generate 0 is admitted")
                .is_none(),
            "generate 0 claims nothing even while discrete mining"
        );

        // Continuous mining blocks a discrete claim.
        let mut fresh = MiningMode {
            normal: true,
            discrete: false,
            generate_cancel: None,
        };
        assert!(
            begin_discrete(&mut fresh, 1).is_err(),
            "generate rejected while setgenerate is active"
        );
    }

    /// `DiscreteMiningGuard` clears the flag on an unwinding panic, not
    /// just on a normal return — dcrd's `defer func() { m.discreteMining
    /// = false }()` runs during a Go panic too.  Without this, a panic
    /// inside `generate_n_blocks` would latch `discrete` and reject every
    /// later `generate` for the life of the process, and `set_num_workers`
    /// would be ignored forever.  The guard recovers the poisoned lock
    /// for the same reason.
    #[test]
    fn a_panicking_generate_does_not_latch_discrete_mining() {
        let mode = Arc::new(Mutex::new(MiningMode::default()));
        mode.lock().expect("fresh lock").discrete = true;

        let held = Arc::clone(&mode);
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard = DiscreteMiningGuard(held);
            panic!("mining blew up");
        }));
        assert!(unwound.is_err(), "the closure must actually panic");

        // The lock is poisoned by the panic; the guard still cleared the
        // flag through it, and a later reader can still get at the state.
        let mode = mode.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(
            !mode.discrete,
            "the drop guard must clear discrete mining even while unwinding"
        );
    }

    /// The speed monitor sums each worker's hashes-per-second and resets
    /// the per-worker counters on each recompute (dcrd's `Swap(0)` fold).
    #[test]
    fn recompute_sums_worker_rates_and_resets() {
        let map = Arc::new(Mutex::new(HashMap::new()));
        let fast = Arc::new(SpeedStats::default());
        fast.total_hashes.store(6_000_000, Ordering::Relaxed);
        fast.elapsed_micros.store(2_000_000, Ordering::Relaxed); // 2s -> 3,000,000 h/s
        let slow = Arc::new(SpeedStats::default());
        slow.total_hashes.store(1_000_000, Ordering::Relaxed);
        slow.elapsed_micros.store(1_000_000, Ordering::Relaxed); // 1s -> 1,000,000 h/s
        {
            let mut map = map.lock().expect("map");
            map.insert(0u64, fast);
            map.insert(1u64, slow);
        }
        assert_eq!(recompute_hashes_per_sec(&map), 4_000_000.0);
        // The counters were reset, so a second recompute sees nothing.
        assert_eq!(recompute_hashes_per_sec(&map), 0.0);
    }

    /// A worker with less than a second of elapsed time is skipped (dcrd's
    /// `elapsedSecs == 0` guard against division blow-ups).
    #[test]
    fn recompute_skips_sub_second_workers() {
        let map = Arc::new(Mutex::new(HashMap::new()));
        let stats = Arc::new(SpeedStats::default());
        stats.total_hashes.store(1000, Ordering::Relaxed);
        stats.elapsed_micros.store(500, Ordering::Relaxed);
        map.lock().expect("map").insert(0u64, stats);
        assert_eq!(recompute_hashes_per_sec(&map), 0.0);
    }

    /// The speed-monitor thread answers rate queries over the reply
    /// channel and stops on command.
    #[test]
    fn the_speed_monitor_answers_queries() {
        let map = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || run_speed_monitor(rx, map, Duration::from_millis(30)));

        let (reply_tx, reply_rx) = mpsc::channel();
        tx.send(MonitorCmd::Query(reply_tx)).expect("query");
        assert_eq!(
            reply_rx.recv().expect("reply"),
            0.0,
            "no workers, zero rate"
        );

        tx.send(MonitorCmd::Stop).expect("stop");
        handle.join().expect("join");
    }

    /// The worker maximum is `NumCPU * 2`, at least two on any host.
    #[test]
    fn max_num_workers_is_at_least_two() {
        assert!(max_num_workers() >= 2);
    }

    /// The miner's three faces cross the daemon's threads.
    #[test]
    fn miner_faces_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<NodeCpuMiner>();
        assert_send::<MinerRuntime>();
        assert_send::<SolveShared>();
    }

    /// dcrd derives each continuous solver's context from its worker's
    /// (`solverCtx, solverCancel = context.WithCancel(ctx)`), so the
    /// `ctx.Err()` check after a solve also refuses to submit once
    /// `SetNumWorkers` has cancelled the worker.  The solver here is held
    /// on the per-parent map -- past its top-of-loop check, before it
    /// solves -- while its worker is cancelled, which leaves the
    /// post-solve check as the only one between the solution and the
    /// submission: a regnet target solves in a few hashes, long before
    /// the solve loop's own cancellation check.
    #[test]
    fn a_worker_cancelled_mid_solve_submits_nothing() {
        let params = dcroxide_chaincfg::regnet_params();
        let dir = tempfile::tempdir().expect("temp dir");
        let db = dcroxide_database::Database::create(&dcroxide_database::Options::new(
            dir.path().join("blocks"),
            params.net.0,
        ))
        .expect("create database");
        let chain = Arc::new(Mutex::new(
            Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
        ));
        let tx_pool = crate::txmempool::new_shared_tx_pool(
            Arc::clone(&chain),
            &params,
            false,
            100,
            10000,
            false,
            false,
        );
        let sync_manager = Arc::new(Mutex::new(crate::sync::new_sync_manager(
            Arc::clone(&chain),
            &params,
            false,
            8,
            1000,
            Arc::clone(&tx_pool),
            crate::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone(), &tx_pool),
        )));
        let policy = MiningPolicy {
            block_max_size: params.maximum_block_sizes[0] as u32,
            tx_min_free_fee: 10000,
            aggressive_mining: true,
        };
        let generator = crate::bgtemplate::start_generator(
            Arc::clone(&chain),
            Arc::clone(&tx_pool),
            params.clone(),
            Vec::new(),
            policy.clone(),
            0,
            true,
            crate::sync::SyncGate::always_current(),
            None,
            None,
        );
        let miner = NodeCpuMiner::new(
            generator.current_handle(),
            generator.subscribers_handle(),
            generator.sink(),
            Arc::clone(&chain),
            sync_manager,
            tx_pool,
            params.clone(),
            policy,
            0,
            SyncPeers::new(),
            true,
        );
        let shared = miner.solve_shared();
        let mined_on_parents = Arc::clone(&shared.mined_on_parents);

        // A block on the genesis block at the easiest target.  It holds
        // no transactions, so the chain refuses it if it is ever
        // submitted, and the refusal is counted against its parent.
        let genesis = params.genesis_hash;
        let template = MsgBlock {
            header: BlockHeader {
                version: 1,
                prev_block: genesis,
                merkle_root: Hash::ZERO,
                stake_root: Hash::ZERO,
                vote_bits: 0,
                final_state: [0u8; 6],
                voters: 0,
                fresh_stake: 0,
                revocations: 0,
                pool_size: 0,
                bits: params.pow_limit_bits,
                sbits: 0,
                height: 1,
                size: 0,
                timestamp: 0,
                nonce: 0,
                extra_data: [0u8; 32],
                stake_version: 0,
            },
            transactions: Vec::new(),
            stransactions: Vec::new(),
        };

        // Nothing outside the solver shows when it has passed its
        // top-of-loop check, and one that starts late sees the
        // cancellation there and returns without solving, which passes
        // with or without the post-solve check (RG10#1).  A solve shows in
        // the speed stats, which `solve_block` folds before it returns a
        // solution, so an attempt that hashed nothing proves nothing and
        // runs again with a longer wait.
        let mut solved = false;
        for attempt in 0..5u32 {
            let cancel = Arc::new(AtomicBool::new(false));
            let worker_cancel = Arc::new(AtomicBool::new(false));
            let stats = Arc::new(SpeedStats::default());
            let held = mined_on_parents.lock().expect("mined-on-parents");
            let solver = {
                let job = ContinuousSolve {
                    template: template.clone(),
                    stats: Arc::clone(&stats),
                    is_blake3_pow_active: false,
                    cancel: Arc::clone(&cancel),
                    worker_cancel: Arc::clone(&worker_cancel),
                    shared: shared.clone(),
                };
                thread::spawn(move || continuous_solve(job))
            };
            // Let the solver pass its top-of-loop check and block on the
            // map.
            thread::sleep(Duration::from_millis(300u64 << attempt));
            worker_cancel.store(true, Ordering::Release);
            drop(held);
            solver.join().expect("the solver did not panic");

            assert_eq!(
                mined_on_parents
                    .lock()
                    .expect("mined-on-parents")
                    .get(&genesis)
                    .copied(),
                None,
                "a solver whose worker was cancelled must not submit its solution"
            );
            assert!(!cancel.load(Ordering::Acquire));
            if stats.total_hashes.load(Ordering::Relaxed) > 0 {
                solved = true;
                break;
            }
        }
        assert!(
            solved,
            "the solver never reached the map before its worker was cancelled, so no \
             attempt exercised the post-solve check"
        );
        drop(miner);
        generator.shutdown();
    }

    /// M2-p#3: a CPU-mined submission logs dcrd's `submitBlock` lines
    /// under `MINR` (`internal/mining/cpuminer/cpuminer.go:222-255`):
    /// the acceptance at info, naming the proof-of-work hash when it is
    /// not the block hash, and each failure class at error.
    #[test]
    fn submission_outcomes_log_dcrds_lines() {
        use dcroxide_netsync::ProcessBlockFailure;

        let header = BlockHeader {
            prev_block: Hash([7; 32]),
            height: 42,
            ..BlockHeader::from_bytes(&[0u8; 180]).expect("zero header").0
        };
        let hash = header.block_hash();
        let failure = |is_rule_error: bool, message: String| {
            Err(ProcessBlockFailure {
                is_duplicate_block: false,
                is_rule_error,
                is_corruption: false,
                message,
            })
        };

        assert_eq!(
            submit_log_line(&Ok(()), &header, false),
            (
                true,
                format!("Block submitted via CPU miner accepted (hash {hash}, height 42)")
            )
        );
        assert_eq!(
            submit_log_line(&Ok(()), &header, true),
            (
                true,
                format!(
                    "Block submitted via CPU miner accepted (hash {hash}, height 42, pow hash {})",
                    header.pow_hash_v2()
                )
            )
        );
        let prev = header.prev_block;
        assert_eq!(
            submit_log_line(
                &failure(true, format!("previous block {prev} is not known")),
                &header,
                true
            ),
            (
                false,
                format!("Block submitted via CPU miner is an orphan building on parent {prev}")
            )
        );
        assert_eq!(
            submit_log_line(&failure(false, "disk gone".into()), &header, true),
            (
                false,
                "Unexpected error while processing block submitted via CPU miner: disk gone"
                    .to_string()
            )
        );
        assert_eq!(
            submit_log_line(&failure(true, "bad block".into()), &header, true),
            (
                false,
                "Block submitted via CPU miner rejected: bad block".to_string()
            )
        );
    }

    /// M2-p#3: the continuous miner's other `MINR` lines read as dcrd's
    /// (`internal/mining/cpuminer/cpuminer.go`): the speed monitor's rate
    /// in Go's `%6.0f` (width six, halves to even) and silent for a zero
    /// or NaN rate (:198-200), the worker controller's launch and stop
    /// counts (:600-615), and the solver's stop on a maxed parent
    /// (:417-418).
    #[test]
    fn continuous_miner_lines_read_as_dcrds() {
        assert_eq!(hash_speed_line(0.0), None);
        assert_eq!(hash_speed_line(f64::NAN), None);
        assert_eq!(
            hash_speed_line(1_234_567.0).as_deref(),
            Some("Hash speed:   1235 kilohashes/s")
        );
        assert_eq!(
            hash_speed_line(500.0).as_deref(),
            Some("Hash speed:      0 kilohashes/s")
        );
        assert_eq!(
            hash_speed_line(2_500.0).as_deref(),
            Some("Hash speed:      2 kilohashes/s")
        );
        assert_eq!(
            hash_speed_line(12_345_678_900.0).as_deref(),
            Some("Hash speed: 12345679 kilohashes/s")
        );

        assert_eq!(
            worker_change_line("Launched", 1, 1),
            "Launched 1 worker (1 total running)"
        );
        assert_eq!(
            worker_change_line("Stopped", 3, 0),
            "Stopped 3 workers (0 total running)"
        );

        assert_eq!(
            TOO_MANY_ON_PARENT,
            "too many blocks mined on parent, stopping until there are enough votes on these \
             to make a new block"
        );
    }
}
