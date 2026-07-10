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

use dcroxide_blockchain::RuleErrorKind;
use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_netsync::manager::{
    BestSnapshot, Config, ProcessBlockFailure, SyncChain, SyncManager, SyncMixPool, SyncTxPool,
};
use dcroxide_uint256::Uint256;
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx};

/// The daemon's concrete sync manager over the shared chain and the
/// not-yet-wired pools.
pub type NodeSyncManager =
    SyncManager<NodeSyncChain, crate::txmempool::NodeSyncTxPool, NullMixPool>;

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

        // Run the deferred winning-tickets lookups the callback
        // queued, now that the chain mutex is free.
        if let Some(handler) = &self.ntfn_handler {
            handler.drain_pending_winning_tickets(&self.chain, adjusted_time_unix());
        }

        match errs.into_iter().next() {
            None => Ok(fork_len),
            Some(err) => Err(ProcessBlockFailure {
                is_duplicate_block: err.kind == RuleErrorKind::DuplicateBlock,
                message: err.description,
            }),
        }
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

/// Construct the daemon's sync manager over the shared chain (dcrd
/// `newServer` building its `netsync.Config`).
pub fn new_sync_manager(
    chain: Arc<Mutex<Chain>>,
    params: &Params,
    no_mining_state_sync: bool,
    max_outbound_peers: u64,
    max_orphan_txs: usize,
    tx_pool: Arc<Mutex<crate::txmempool::NodeTxPool>>,
) -> NodeSyncManager {
    SyncManager::new(Config {
        chain: NodeSyncChain::new(chain, params.clone()),
        tx_mem_pool: crate::txmempool::NodeSyncTxPool::new(tx_pool),
        mix_pool: NullMixPool,
        min_known_chain_work: params.min_known_chain_work,
        net: params.net,
        target_time_per_block_secs: params.target_time_per_block_secs,
        no_mining_state_sync,
        max_outbound_peers,
        max_orphan_txs,
        recently_confirmed_txns: dcroxide_containers::apbf::new_filter(
            MAX_RECENTLY_CONFIRMED_TXNS,
            RECENTLY_CONFIRMED_TXNS_FP_RATE,
        ),
    })
}
