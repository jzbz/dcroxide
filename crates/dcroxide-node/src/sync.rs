// SPDX-License-Identifier: ISC
//! The daemon's seams for the ported netsync sync manager — the
//! adapters dcrd's `netsync.Config` receives as its chain, mempool,
//! and mixpool instances.
//!
//! [`NodeSyncChain`] adapts the shared chain behind its mutex to the
//! manager's [`SyncChain`] trait, injecting the system clock where
//! dcrd's blockchain reads its median-time source (the daemon has no
//! time samples yet, so the adjusted time is the system time, exactly
//! like a dcrd node before its first version exchange).  The mempool
//! and mixpool are not wired yet, so [`NullTxPool`] and [`NullMixPool`]
//! answer like empty pools that reject everything; the real pools
//! replace them with later pieces.  The manager itself is constructed
//! here ([`new_sync_manager`]) but not yet driven — the peer
//! registration, the action executor, and the stall timer arrive with
//! the following pieces.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::{RuleError, RuleErrorKind, render_multi_error};
use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_netsync::manager::{
    BestSnapshot, Config, ProcessBlockFailure, SyncChain, SyncManager, SyncMixPool, SyncTxPool,
};
use dcroxide_uint256::Uint256;
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx};

/// The daemon's concrete sync manager over the shared chain, mempool,
/// and mixing pool.
pub type NodeSyncManager =
    SyncManager<NodeSyncChain, crate::txmempool::NodeSyncTxPool, crate::mixnode::NodeSyncMixPool>;

/// The maximum number of recently confirmed transactions to track
/// (dcrd `maxRecentlyConfirmedTxns`: about one hour of main network
/// blocks full of minimum-size transactions).
const MAX_RECENTLY_CONFIRMED_TXNS: u32 = 23000;

/// The false positive rate for the recently-confirmed filter (dcrd
/// `recentlyConfirmedTxnsFPRate`).
const RECENTLY_CONFIRMED_TXNS_FP_RATE: f64 = 0.000001;

/// The chain adapter handing the manager the shared chain instance
/// (dcrd passes `s.chain` directly; the mutex stands in for Go's
/// internal chain locking).
pub struct NodeSyncChain {
    chain: Arc<Mutex<Chain>>,
    params: Params,
    ntfn_handler: Option<crate::chainntfns::ChainNtfnHandler>,
}

impl NodeSyncChain {
    /// Adapt the shared chain for the sync manager.
    pub fn new(chain: Arc<Mutex<Chain>>, params: Params) -> NodeSyncChain {
        NodeSyncChain {
            chain,
            params,
            ntfn_handler: None,
        }
    }

    /// Install the chain event handler whose deferred winning-tickets
    /// lookups drain after each processing call (dcrd runs the lookup
    /// in its handler with the chain lock released; the daemon's
    /// callback runs under the chain mutex, so the lookup waits here).
    pub fn set_chain_ntfn_handler(&mut self, handler: crate::chainntfns::ChainNtfnHandler) {
        self.ntfn_handler = Some(handler);
    }

    fn locked(&self) -> std::sync::MutexGuard<'_, Chain> {
        self.chain.lock().expect("chain mutex poisoned")
    }
}

/// The current unix time standing in for dcrd's median-adjusted time
/// source (no samples are collected yet, so they are identical).
fn adjusted_time_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl SyncChain for NodeSyncChain {
    fn best_header(&mut self) -> (Hash, i64) {
        self.locked().best_header()
    }

    fn header_by_hash(&mut self, hash: &Hash) -> Option<BlockHeader> {
        self.locked().header_by_hash(hash)
    }

    fn block_locator_from_hash(&mut self, hash: &Hash) -> Vec<Hash> {
        self.locked().block_locator_from_hash(hash)
    }

    fn put_next_needed_blocks(&mut self, max_results: usize) -> Vec<Hash> {
        self.locked().put_next_needed_blocks(max_results)
    }

    fn best_snapshot(&mut self) -> BestSnapshot {
        let chain = self.locked();
        let best = chain.best_snapshot();
        BestSnapshot {
            hash: best.hash,
            height: best.height,
            next_stake_diff: best.next_stake_diff,
        }
    }

    fn is_current(&mut self) -> bool {
        self.locked().is_current_at(adjusted_time_unix())
    }

    fn maybe_update_is_current(&mut self) {
        self.locked()
            .maybe_update_is_current_at(adjusted_time_unix());
    }

    fn adjusted_time_unix(&mut self) -> i64 {
        adjusted_time_unix()
    }

    fn chain_work(&mut self, hash: &Hash) -> Option<Uint256> {
        self.locked().chain_work(hash)
    }

    fn have_header(&mut self, hash: &Hash) -> bool {
        self.locked().have_header(hash)
    }

    fn have_block(&mut self, hash: &Hash) -> bool {
        self.locked().have_block(hash)
    }

    fn process_block_header(&mut self, header: &BlockHeader) -> Result<(), String> {
        self.locked()
            .process_block_header(header, adjusted_time_unix(), &self.params)
            .map_err(|e| e.description)
    }

    fn process_block(&mut self, block: &MsgBlock) -> Result<i64, ProcessBlockFailure> {
        let (fork_len, errs) =
            self.locked()
                .process_block(block, adjusted_time_unix(), &self.params);

        // Run the deferred mempool maintenance and winning-tickets
        // lookups the callback queued, now that the chain mutex is
        // free (dcrd handles both inline with its chain lock
        // released).
        if let Some(handler) = &self.ntfn_handler {
            handler.drain_pending(&self.chain, adjusted_time_unix());
        }

        combine_process_block_result(fork_len, errs)
    }
}

/// Fold the chain's block-processing outcome into the manager's result,
/// rendering every error exactly as dcrd's `blockchain.ProcessBlock`
/// renders its combined `finalErr` (via [`render_multi_error`]).
///
/// dcrd surfaces a `blockchain.ErrDuplicateBlock` rejection only as a
/// lone early return, so the duplicate-block classification the manager
/// needs comes from the first error; the message renders the whole flat
/// error slice so the rare block that both fails acceptance and whose
/// ensuing reorganization also errors reports dcrd's `multiple errors
/// (N):` text rather than only the first error's.
fn combine_process_block_result(
    fork_len: i64,
    errs: Vec<RuleError>,
) -> Result<i64, ProcessBlockFailure> {
    match errs.first() {
        None => Ok(fork_len),
        Some(first) => Err(ProcessBlockFailure {
            is_duplicate_block: first.kind == RuleErrorKind::DuplicateBlock,
            // Every failure the chain surfaces here is a rule error
            // (dcrd's non-rule process failures come from its database
            // layer, which the port reports through panics instead).
            is_rule_error: true,
            message: render_multi_error(&errs),
        }),
    }
}

/// A transaction pool that behaves like an empty pool rejecting
/// everything, standing in until the mempool is wired.
#[derive(Default)]
pub struct NullTxPool;

impl SyncTxPool for NullTxPool {
    fn process_transaction(
        &mut self,
        _tx: &MsgTx,
        _allow_orphan: bool,
        _allow_high_fees: bool,
        _tag: u64,
    ) -> Result<Vec<Hash>, String> {
        Err("the transaction mempool is not yet wired".to_string())
    }

    fn have_transaction(&mut self, _hash: &Hash) -> bool {
        false
    }

    fn prune_stake_tx(&mut self, _required_stake_difficulty: i64, _height: i64) {}

    fn prune_expired_tx(&mut self, _height: i64) {}
}

/// A mixing pool that behaves like an empty pool rejecting everything,
/// standing in until the mixpool is wired.
#[derive(Default)]
pub struct NullMixPool;

impl SyncMixPool for NullMixPool {
    type Msg = dcroxide_wire::Message;
    type Err = String;

    fn mix_hash(&mut self, _msg: &Self::Msg) -> Hash {
        Hash([0u8; 32])
    }

    fn accept_message(&mut self, _msg: &Self::Msg, _source: u64) -> Result<Vec<Self::Msg>, String> {
        Err("the mixing pool is not yet wired".to_string())
    }

    fn recent_message(&mut self, _hash: &Hash) -> bool {
        false
    }

    fn remove_spent_prs(&mut self, _txs: &[MsgTx]) {}

    fn expire_messages_in_background(&mut self, _height: u32) {}
}

/// The daemon-side view of dcrd `SyncManager.IsCurrent`, over the
/// manager's shared is-current flag and sync height (dcrd's
/// `isCurrent` is an `atomic.Bool` readable from any goroutine): the
/// accepted-block relay, fee-estimator enable, and background-generator
/// gates evaluate it without taking the manager lock, which the gates
/// cannot do because the manager itself takes the chain lock.
#[derive(Clone)]
pub struct SyncGate {
    current: Arc<std::sync::atomic::AtomicBool>,
    sync_height: Arc<std::sync::atomic::AtomicI64>,
}

impl SyncGate {
    /// A gate over the manager's shared state handles.
    pub fn from_manager(manager: &NodeSyncManager) -> SyncGate {
        let (current, sync_height) = manager.current_state_handles();
        SyncGate {
            current,
            sync_height,
        }
    }

    /// A gate that always reports current, for tests and tools that
    /// have no sync manager.
    pub fn always_current() -> SyncGate {
        SyncGate {
            current: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            sync_height: Arc::new(std::sync::atomic::AtomicI64::new(0)),
        }
    }

    /// A gate that has not latched and has no sync peer, so it opens
    /// exactly when the chain itself reports current — the manager's
    /// own state on a fresh chain before any peer connects.
    pub fn unsynced() -> SyncGate {
        SyncGate {
            current: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            sync_height: Arc::new(std::sync::atomic::AtomicI64::new(0)),
        }
    }

    /// dcrd `SyncManager.IsCurrent` over an already-locked chain:
    /// `maybeUpdateIsCurrent` — nothing to do when the flag is already
    /// set; otherwise the chain is considered synced once it believes
    /// it is current and the best height reaches the sync height —
    /// then the flag read.
    pub fn is_current_locked(&self, chain: &mut Chain, now_unix: i64) -> bool {
        use std::sync::atomic::Ordering;
        if self.current.load(Ordering::SeqCst) {
            return true;
        }
        let best_height = chain.best_snapshot().height;
        if best_height >= self.sync_height.load(Ordering::SeqCst) && chain.is_current_at(now_unix) {
            self.current.store(true, Ordering::SeqCst);
            return true;
        }
        false
    }

    /// [`SyncGate::is_current_locked`] taking the chain lock itself.
    pub fn is_current(&self, chain: &Arc<Mutex<Chain>>, now_unix: i64) -> bool {
        use std::sync::atomic::Ordering;
        if self.current.load(Ordering::SeqCst) {
            return true;
        }
        let mut chain = chain.lock().expect("chain mutex poisoned");
        self.is_current_locked(&mut chain, now_unix)
    }
}

/// Construct the daemon's sync manager over the shared chain (dcrd
/// `newServer` building its `netsync.Config`).
pub fn new_sync_manager(
    chain: Arc<Mutex<Chain>>,
    params: &Params,
    no_mining_state_sync: bool,
    max_outbound_peers: u64,
    max_orphan_txs: usize,
    tx_pool: Arc<Mutex<crate::txmempool::NodeTxPool>>,
    mix_pool: Arc<Mutex<crate::mixnode::NodeMixPool>>,
) -> NodeSyncManager {
    SyncManager::new(Config {
        chain: NodeSyncChain::new(chain, params.clone()),
        tx_mem_pool: crate::txmempool::NodeSyncTxPool::new(tx_pool),
        mix_pool: crate::mixnode::NodeSyncMixPool::new(mix_pool),
        min_known_chain_work: params.min_known_chain_work,
        net: params.net,
        target_time_per_block_secs: params.target_time_per_block_secs,
        no_mining_state_sync,
        max_outbound_peers,
        max_orphan_txs,
        recently_confirmed_txns: Arc::new(Mutex::new(dcroxide_containers::apbf::new_filter(
            MAX_RECENTLY_CONFIRMED_TXNS,
            RECENTLY_CONFIRMED_TXNS_FP_RATE,
        ))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_err(kind: RuleErrorKind, description: &str) -> RuleError {
        RuleError {
            kind,
            description: description.to_string(),
        }
    }

    #[test]
    fn no_errors_yields_the_fork_length() {
        assert_eq!(combine_process_block_result(3, Vec::new()).unwrap(), 3);
    }

    #[test]
    fn a_single_error_reports_its_bare_description() {
        // The common single-error rejection: a lone duplicate-block
        // error classifies the failure and renders unadorned, exactly
        // as dcrd's `submitblock` reports it after `rejected: `.
        let failure = combine_process_block_result(
            0,
            vec![rule_err(
                RuleErrorKind::DuplicateBlock,
                "already have block abc",
            )],
        )
        .unwrap_err();
        assert!(failure.is_duplicate_block);
        assert_eq!(failure.message, "already have block abc");
    }

    #[test]
    fn multiple_errors_render_dcrd_multi_error_text() {
        // The rare block that both fails contextual acceptance and
        // whose ensuing reorganization also errors: dcrd combines the
        // acceptance error (element 0) with the reorganization errors
        // into one flat `MultiError`, so `submitblock` reports the
        // whole `multiple errors (N):` block rather than only the
        // first error's text.  The classification still comes from the
        // first error, which is never a duplicate-block rejection.
        let failure = combine_process_block_result(
            0,
            vec![
                rule_err(RuleErrorKind::UnexpectedDifficulty, "accept-err"),
                rule_err(RuleErrorKind::BadMerkleRoot, "reorg-err-1"),
                rule_err(RuleErrorKind::BadMerkleRoot, "reorg-err-2"),
            ],
        )
        .unwrap_err();
        assert!(!failure.is_duplicate_block);
        assert_eq!(
            failure.message,
            "multiple errors (3):\n - accept-err\n - reorg-err-1\n - reorg-err-2\n"
        );
    }
}
