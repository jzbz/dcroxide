// SPDX-License-Identifier: ISC
//! The daemon's CPU miner (dcrd `internal/mining/cpuminer`): the
//! discrete `generate N` state machine that mines a requested number of
//! blocks onto the main chain over the live block template generator
//! and the block-submit seam.
//!
//! Only the discrete `GenerateNBlocks` path is wired here (dcrd
//! `CPUMiner.GenerateNBlocks`, the regnet/simnet `generate` RPC).  The
//! continuous background miner behind `setgenerate` — the worker
//! controller, the speed monitor, and the block-connected feed — is a
//! later piece; `set_num_workers` records the worker count with dcrd's
//! clamping but starts no background hashing, and `hashes_per_second`
//! stays zero, matching dcrd's idle miner.
//!
//! The proof-of-work solve loop itself lives in the pure, chain-free
//! `dcroxide_mining::cpuminer` core; this module drives it over OS
//! threads: `generate_n_blocks` subscribes to the template generator,
//! solves each fresh template on a cancellable worker thread, submits a
//! solution through the sync manager's `process_block`, and returns the
//! hashes that extended the chain.
//!
//! Two divergences follow from the daemon's single RPC server mutex and
//! the deferral of the block-connected feed, both shared with the wider
//! global-mutex-stall note: `generate N` runs synchronously while that
//! mutex is held, so a long run stalls every other RPC for its duration
//! (dcrd runs the miner off the RPC goroutine); and without the
//! `notifyBlocks` feed, termination for a block arriving from a peer
//! mid-run waits out the bounded template poll rather than exiting
//! immediately.  Both are lifted with the continuous miner and the
//! per-connection concurrency redesign.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Instant;

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
use crate::sync::NodeSyncManager;
use crate::txmempool::NodeTxPool;

/// The default number of mining workers (dcrd `defaultNumWorkers`),
/// reported by `getmininginfo`/`getgenerate` even while idle.
const DEFAULT_NUM_WORKERS: i32 = 1;

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
/// block-submit seam (dcrd `CPUMiner`, discrete-mining subset).
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
    num_workers: i32,
    discrete_mining: Arc<AtomicBool>,
    /// The block hash of the template last successfully submitted, used
    /// to skip re-solving a template the subscription re-delivers while
    /// the generator has not yet produced a new one (dcrd's
    /// `discretePrevTemplate` pointer identity, tracked here by the
    /// template block's hash).
    discrete_prev_template: Arc<Mutex<Option<Hash>>>,
    /// Flipped at daemon shutdown to stop an in-flight `generate`
    /// promptly (dcrd's `m.quit`).
    quit: Arc<AtomicBool>,
}

impl NodeCpuMiner {
    /// Build the CPU miner over the running generator's handles, the
    /// shared chain, the sync manager (for `process_block`), and the
    /// mempool (dcrd `cpuminer.New` over its `Config`).
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
    ) -> NodeCpuMiner {
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
            num_workers: DEFAULT_NUM_WORKERS,
            discrete_mining: Arc::new(AtomicBool::new(false)),
            discrete_prev_template: Arc::new(Mutex::new(None)),
            quit: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A shutdown handle the daemon flips to stop an in-flight
    /// `generate` (dcrd cancels the miner's context on shutdown).
    pub fn quit_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.quit)
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
        let mut templater = NodeRpcBlockTemplater::new(
            Arc::clone(&self.current),
            Arc::clone(&self.subscribers),
            self.sink.clone(),
            Arc::clone(&self.chain),
            Arc::clone(&self.pool),
            self.params.clone(),
            self.policy.clone(),
            self.mining_time_offset,
        );
        templater.subscribe()
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

/// The state a solve worker thread owns for one template (all handles
/// are cloned in so the thread outlives the miner's borrow).
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
/// solve goroutine body).
fn solve_and_submit(mut job: SolveJob) {
    let stats = SpeedStats::default();
    let en_offset = random_u64();
    let start = Instant::now();

    // The block time is refreshed periodically over a throwaway builder
    // on the live chain, exactly as the getwork templater does (dcrd
    // `g.UpdateBlockTime`).
    let time_chain = Arc::clone(&job.chain);
    let time_pool = Arc::clone(&job.pool);
    let time_params = job.params.clone();
    let time_policy = job.policy.clone();
    let time_offset = job.mining_time_offset;
    let mut update_block_time = move |header: &mut BlockHeader| {
        let builder = BlkTmplGenerator::new(
            time_policy.clone(),
            &time_params,
            NodeTemplateChain::new(Arc::clone(&time_chain), time_params.clone()),
            NodeTemplateTxSource::new(Arc::clone(&time_pool)),
            time_offset,
        );
        builder.update_block_time(header);
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
fn max_num_workers() -> i32 {
    let cpus = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    i32::try_from(cpus)
        .unwrap_or(i32::MAX / 2)
        .saturating_mul(2)
}

impl RpcCpuMiner for NodeCpuMiner {
    fn generate_n_blocks(&mut self, n: u32) -> Result<Vec<Hash>, GenerateFailure> {
        // Reject a second discrete call while one is already active
        // (dcrd's `discreteMining && n != 0` guard).  The RPC server
        // mutex is held for this whole call, so a concurrent dispatch is
        // not actually reachable, but the guard is kept for fidelity.
        // The `normalMining` guard is unreachable until continuous
        // mining lands (a later piece), so it is omitted.
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
        // Only discrete mining is possible until continuous mining lands
        // (dcrd `normalMining || discreteMining`, with `normalMining`
        // always false here).
        self.discrete_mining.load(Ordering::Acquire)
    }

    fn hashes_per_second(&mut self) -> f64 {
        // dcrd reports zero unless the continuous miner is running.
        0.0
    }

    fn num_workers(&mut self) -> i32 {
        self.num_workers
    }

    fn set_num_workers(&mut self, workers: i32) {
        // Ignored while a discrete generate is running (dcrd's guard).
        if self.discrete_mining.load(Ordering::Acquire) {
            return;
        }
        // A negative count selects the default; the count is clamped to
        // the maximum (dcrd `SetNumWorkers`).  The count is recorded so
        // getmininginfo/getgenerate report it; continuous background
        // hashing does not start until a later piece.
        self.num_workers = if workers < 0 {
            DEFAULT_NUM_WORKERS
        } else {
            workers.min(max_num_workers())
        };
    }
}
