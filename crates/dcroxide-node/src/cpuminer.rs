// SPDX-License-Identifier: ISC
//! The daemon's CPU miner (dcrd `internal/mining/cpuminer`): both the
//! discrete `generate N` state machine (`GenerateNBlocks`) and the
//! continuous background miner behind `setgenerate` (`Run` +
//! `speedMonitor` + `miningWorkerController` + `generateBlocks` +
//! `solver`).
//!
//! The proof-of-work solve loop itself lives in the pure, chain-free
//! `dcroxide_mining::cpuminer` core; this module drives it over OS
//! threads.  [`NodeCpuMiner`] is the RPC-facing face held behind the one
//! RPC server mutex; [`MinerRuntime`] is the daemon-held handle owning
//! the two background threads (the speed monitor and the worker
//! controller, which together replace dcrd's `Run` goroutine and its two
//! subordinates).  `generate_n_blocks` runs synchronously on the RPC
//! thread; `set_num_workers` starts or stops the continuous workers, and
//! `hashes_per_second` reads the live rate over a request/reply channel.
//!
//! Divergences from dcrd, all documented at the call sites: the discrete
//! and continuous work runs off dedicated threads while the RPC-facing
//! methods hold the one server mutex, so a long `generate N` stalls
//! other RPCs for its duration (the wider global-mutex-stall note); the
//! `queryHashesPerSec` rendezvous becomes a `mpsc` request/reply; the
//! `updateNumWorkers` signal becomes a poke with the count carried on an
//! atomic; and dcrd's `notifyBlocks`/`BlockConnected` feed is not ported
//! because `std::sync::mpsc` cannot select the template subscription
//! against a block-notification source and the discrete loop's
//! `best_height` checks already cover dcrd's own "be safe" fallback, so a
//! peer block arriving mid-discrete-run terminates on the bounded
//! template poll rather than instantly.

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
use dcroxide_wire::{BlockHeader, MsgBlock};

use crate::bgtemplate::{GeneratorSink, NodeRpcBlockTemplater, SharedTemplate, SubscriberRegistry};
use crate::mining::{NodeTemplateChain, NodeTemplateTxSource};
use crate::runtime::ConnectedPeers;
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

/// Clears the discrete-mining flag when dropped, so it is reset on every
/// exit path from `generate_n_blocks` — including an unwinding panic —
/// exactly as dcrd's `defer { m.discreteMining = false }` guarantees.
struct DiscreteMiningGuard(Arc<AtomicBool>);

impl Drop for DiscreteMiningGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
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
    connected: ConnectedPeers,
    /// Whether the network permits mining without connected peers (dcrd
    /// `PermitConnectionlessMining`, true on simnet and regnet).
    permit_connectionless: bool,
    /// The target continuous worker count, shared with the controller
    /// (dcrd `numWorkers atomic.Uint32`).
    num_workers: Arc<AtomicU32>,
    /// Whether continuous mining is active; only ever touched by the RPC
    /// methods under the server mutex (dcrd's mutex-protected
    /// `normalMining`).
    normal_mining: bool,
    discrete_mining: Arc<AtomicBool>,
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
    controller_rx: Option<mpsc::Receiver<ControllerCmd>>,
    monitor_rx: Option<mpsc::Receiver<MonitorCmd>>,
}

impl NodeCpuMiner {
    /// Build the CPU miner over the running generator's handles, the
    /// shared chain, the sync manager (for `process_block`), the mempool,
    /// and the connected-peer registry (dcrd `cpuminer.New` over its
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
        connected: ConnectedPeers,
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
            normal_mining: false,
            discrete_mining: Arc::new(AtomicBool::new(false)),
            discrete_prev_template: Arc::new(Mutex::new(None)),
            speed_stats: Arc::new(Mutex::new(HashMap::new())),
            mined_on_parents: Arc::new(Mutex::new(HashMap::new())),
            quit: Arc::new(AtomicBool::new(false)),
            controller_tx,
            monitor_tx,
            controller_rx: Some(controller_rx),
            monitor_rx: Some(monitor_rx),
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
        let monitor_rx = self.monitor_rx.take().expect("miner started once");
        let controller_rx = self.controller_rx.take().expect("miner started once");
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
        if let Some(thread) = self.controller_thread.take() {
            let _ = thread.join();
        }
        if let Some(thread) = self.speed_thread.take() {
            let _ = thread.join();
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
    connected: ConnectedPeers,
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
    let mut templater = NodeRpcBlockTemplater::new(
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
            Ok(MonitorCmd::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                hashes_per_sec = recompute_hashes_per_sec(&speed_stats);
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

                let target = shared.num_workers.load(Ordering::Acquire) as usize;
                if target > running.len() {
                    for _ in 0..target.saturating_sub(running.len()) {
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
                } else {
                    // Signal the most recently created workers to exit
                    // and retire their handles for later joining.
                    for _ in 0..running.len().saturating_sub(target) {
                        if let Some(handle) = running.pop() {
                            handle.cancel.store(true, Ordering::Release);
                            retired.push(handle.join);
                        }
                    }
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

    let mut subscription = shared.subscribe();
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
        if cancel.load(Ordering::Acquire) || shared.quit.load(Ordering::Acquire) {
            return;
        }
        let accepted = shared
            .sync_manager
            .lock()
            .expect("sync manager mutex poisoned")
            .process_block(&block)
            .is_ok();
        if accepted {
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
    let quit = Arc::clone(&job.quit);
    let mut should_cancel = move || cancel.load(Ordering::Acquire) || quit.load(Ordering::Acquire);

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
    if job.cancel.load(Ordering::Acquire) || job.quit.load(Ordering::Acquire) {
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
    let accepted = job
        .sync_manager
        .lock()
        .expect("sync manager mutex poisoned")
        .process_block(&job.block)
        .is_ok();
    if accepted {
        *job.discrete_prev_template
            .lock()
            .expect("prev template poisoned") = Some(job.template_hash);
    }
}

/// A fresh random 64-bit extra-nonce offset (dcrd `rand.Uint64`).
fn random_u64() -> u64 {
    let mut buf = [0u8; 8];
    getrandom::fill(&mut buf).expect("system random source");
    u64::from_le_bytes(buf)
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
    fn generate_n_blocks(&mut self, n: u32) -> Result<Vec<Hash>, GenerateFailure> {
        // Reject a discrete call while continuous mining is active (dcrd's
        // `normalMining` guard).  Both this reader and the writer
        // (`set_num_workers`) run under the server mutex, so the check is
        // race-free.
        if self.normal_mining {
            return Err(GenerateFailure {
                is_ctx_err: false,
                is_cancel_discrete: false,
                message: "server is already CPU mining -- please call `setgenerate 0` \
                          before calling discrete `generate` commands"
                    .to_string(),
            });
        }

        // Reject a second discrete call while one is already active
        // (dcrd's `discreteMining && n != 0` guard).  The RPC server
        // mutex is held for this whole call, so a concurrent dispatch is
        // not actually reachable, but the guard is kept for fidelity.
        if self.discrete_mining.load(Ordering::Acquire) && n != 0 {
            return Err(GenerateFailure {
                is_ctx_err: false,
                is_cancel_discrete: false,
                message: "server is already discrete mining -- please wait until \
                          the existing call completes or cancel it"
                    .to_string(),
            });
        }

        // Zero blocks returns no hashes (dcrd's `n == 0` path also
        // cancels an in-flight discrete call through `generateCancelFn`,
        // but no concurrent call is reachable while the single RPC
        // server mutex is held for this whole method, so there is
        // nothing to cancel).
        if n == 0 {
            return Ok(Vec::new());
        }

        // Mark discrete mining active for its whole duration, clearing
        // the flag on every exit path — including an unwinding panic —
        // exactly as dcrd's `defer { m.discreteMining = false }` does, so
        // a panic can never latch the flag and reject all later
        // `generate` calls.
        self.discrete_mining.store(true, Ordering::Release);
        let _discrete_guard = DiscreteMiningGuard(Arc::clone(&self.discrete_mining));
        let orig_height = self.best_height();
        let target_height = orig_height.saturating_add(i64::from(n));

        let mut subscription = self.subscribe();
        let mut solve: Option<(JoinHandle<()>, Arc<AtomicBool>)> = None;

        loop {
            if self.quit.load(Ordering::Acquire) {
                break;
            }
            match subscription.recv_with_timeout() {
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

        // Stop the outstanding solve worker and drop the subscription.
        // The discrete-mining flag is cleared by `_discrete_guard` on
        // return.
        if let Some((handle, cancel)) = solve.take() {
            cancel.store(true, Ordering::Release);
            let _ = handle.join();
        }
        subscription.stop();

        // Return the hashes that ultimately extended the main chain,
        // regardless of their origin (dcrd's `BlockHashByHeight` sweep;
        // a zero hash stands in for a lookup miss).
        let chain = self.chain.lock().expect("chain mutex poisoned");
        let mut hashes = Vec::with_capacity(n as usize);
        for height in (orig_height.saturating_add(1))..=target_height {
            hashes.push(chain.block_hash_by_height(height).unwrap_or(Hash::ZERO));
        }
        Ok(hashes)
    }

    fn is_mining(&mut self) -> bool {
        // Mining in either the continuous or discrete mode (dcrd
        // `normalMining || discreteMining`).
        self.normal_mining || self.discrete_mining.load(Ordering::Acquire)
    }

    fn hashes_per_second(&mut self) -> f64 {
        // Zero unless continuous mining is running (dcrd's short-circuit).
        if !self.normal_mining {
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

    fn num_workers(&mut self) -> i32 {
        self.num_workers.load(Ordering::Acquire) as i32
    }

    fn set_num_workers(&mut self, workers: i32) {
        // Ignored while a discrete generate is running (dcrd's guard).
        if self.discrete_mining.load(Ordering::Acquire) {
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
        self.normal_mining = target != 0;
        let _ = self.controller_tx.send(ControllerCmd::Update);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
