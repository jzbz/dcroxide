// SPDX-License-Identifier: ISC
//! The daemon's transaction memory pool assembly: the [`PoolChain`]
//! adapter binding the ported pool to the live chain (dcrd `newServer`
//! building its `mempool.Config` closures), the policy construction
//! with dcrd's exact values, and the adapters serving the pool to the
//! netsync manager and the RPC server.
//!
//! The transaction relay to peers (dcrd `AnnounceNewTransactions`'
//! inventory half) and the fee estimator hooks arrive with later
//! pieces; the RPC connection-manager relay seams stay no-ops until
//! then.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use dcroxide_blockchain::chainview_nodes::NodeBranchView;
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::sequencelock::SequenceLock;
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_mempool::{
    MAX_STANDARD_TX_SIZE, Policy, PoolChain, PoolError, RuleErrorSource, TxPool, chain_rule_error,
};
use dcroxide_netsync::manager::SyncTxPool;
use dcroxide_rpc::server::{RpcMempoolTx, RpcTxMempooler, RpcVerboseMempoolTx};
use dcroxide_txscript::ScriptFlags;
use dcroxide_wire::{BlockHeader, CurrencyNet, MsgTx, OutPoint};

/// The maximum age in blocks of votes accepted on networks that keep
/// long reorg-vote windows (dcrd `defaultMaximumVoteAge`, applied to
/// testnet).
const DEFAULT_MAXIMUM_VOTE_AGE: u16 = 1440;

/// The daemon's concrete pool over the live chain.
pub type NodeTxPool = TxPool<NodePoolChain>;

/// The current unix time (dcrd's direct `time.Now()` calls; also the
/// wall clock standing in for dcrd's median-adjusted time source
/// until network time samples are collected).
pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The unspent view for the transaction's inputs and its own outputs
/// from the tip's point of view (dcrd `BlockChain.FetchUtxoView`,
/// which dcrd wires into both its mempool and mining configs; the
/// pool trait's `tree_valid` and the template trait's
/// `include_regular_txns` are the same flag).  When the flag is
/// unset, the tip's regular tree is disconnected from the view first.
/// Spent entries stay in the view like the cache hands them out; the
/// consumers' checks filter them.
pub(crate) fn chain_fetch_utxo_view(
    chain: &Chain,
    params: &Params,
    tx: &MsgTx,
    tx_hash: &Hash,
    tree: i8,
    include_regular_txns: bool,
) -> Result<UtxoView, String> {
    let best = chain.best_snapshot().clone();
    let mut view = UtxoView::new();
    view.set_best_hash(best.hash);
    if best.height == 0 {
        return Ok(view);
    }

    if !include_regular_txns {
        // Disconnect the disapproved regular tree of the tip block
        // (dcrd `disconnectDisapprovedBlock`; the memoized
        // disapproved-view cache is an optimization dcrd layers on
        // top and is not reproduced).
        let is_treasury_enabled = chain
            .is_treasury_agenda_active(&best.hash, params)
            .map_err(|e| e.description)?;
        let tip_block = chain
            .block_by_hash(&best.hash)
            .ok_or_else(|| format!("no block data for tip {}", best.hash))?;
        let stxos = chain.fetch_spend_journal(&tip_block, is_treasury_enabled);
        view.disconnect_disapproved_block(
            &tip_block,
            &stxos,
            &|op: &OutPoint| chain.fetch_utxo_entry(op),
            is_treasury_enabled,
        )
        .map_err(|e| e.description)?;
    }

    // The transaction's own outputs (for duplicate detection), then
    // its inputs; outpoints the chain does not know stay absent from
    // the view.
    for tx_out_idx in 0..tx.tx_out.len() {
        let op = OutPoint {
            hash: *tx_hash,
            index: tx_out_idx as u32,
            tree,
        };
        if view.lookup_entry(&op).is_none()
            && let Some(entry) = chain.fetch_utxo_entry(&op)
        {
            view.insert_entry(&op, entry);
        }
    }
    for tx_in in &tx.tx_in {
        let op = tx_in.previous_out_point;
        if view.lookup_entry(&op).is_none()
            && let Some(entry) = chain.fetch_utxo_entry(&op)
        {
            view.insert_entry(&op, entry);
        }
    }
    Ok(view)
}

/// The script verification flags for the next block (dcrd
/// `standardScriptVerifyFlags`, shared by the mempool and mining
/// configs): the base policy flags plus SHA256 under the LN features
/// agenda and the treasury opcodes under the treasury agenda, both
/// evaluated at the current tip.
pub(crate) fn chain_standard_verify_flags(
    chain: &Chain,
    params: &Params,
) -> Result<ScriptFlags, String> {
    let tip_hash = chain.best_snapshot().hash;
    let mut flags = dcroxide_mempool::BASE_STANDARD_VERIFY_FLAGS;
    if chain
        .is_ln_features_agenda_active(&tip_hash, params)
        .map_err(|e| e.description)?
    {
        flags = ScriptFlags(flags.0 | ScriptFlags::VERIFY_SHA256.0);
    }
    if chain
        .is_treasury_agenda_active(&tip_hash, params)
        .map_err(|e| e.description)?
    {
        flags = ScriptFlags(flags.0 | ScriptFlags::VERIFY_TREASURY.0);
    }
    Ok(flags)
}

/// The chain backend for the pool over the shared chain (dcrd's
/// `mempool.Config` closures over `s.chain`, server.go `newServer`).
pub struct NodePoolChain {
    chain: Arc<Mutex<Chain>>,
    params: Params,
}

impl NodePoolChain {
    /// Adapt the shared chain for the pool.
    pub fn new(chain: Arc<Mutex<Chain>>, params: Params) -> NodePoolChain {
        NodePoolChain { chain, params }
    }

    fn locked(&self) -> MutexGuard<'_, Chain> {
        self.chain.lock().expect("chain mutex poisoned")
    }
}

impl PoolChain for NodePoolChain {
    fn next_stake_difficulty(&self) -> Result<i64, String> {
        Ok(self.locked().best_snapshot().next_stake_diff)
    }

    /// The unspent view for the transaction's inputs and its own
    /// outputs from the tip's point of view
    /// ([`chain_fetch_utxo_view`]; the pool's votes disapproving the
    /// tip's regular tree is the unset flag).
    fn fetch_utxo_view(
        &self,
        tx: &MsgTx,
        tx_hash: &Hash,
        tree: i8,
        tree_valid: bool,
    ) -> Result<UtxoView, String> {
        chain_fetch_utxo_view(&self.locked(), &self.params, tx, tx_hash, tree, tree_valid)
    }

    fn best_hash(&self) -> Hash {
        self.locked().best_snapshot().hash
    }

    fn best_height(&self) -> i64 {
        self.locked().best_snapshot().height
    }

    fn header_by_hash(&self, hash: &Hash) -> Result<BlockHeader, String> {
        self.locked()
            .header_by_hash(hash)
            .ok_or_else(|| format!("unable to find block {hash}"))
    }

    fn past_median_time(&self) -> i64 {
        self.locked().best_snapshot().median_time
    }

    fn calc_sequence_lock(
        &self,
        tx: &MsgTx,
        _tx_hash: &Hash,
        view: &UtxoView,
    ) -> Result<SequenceLock, PoolError> {
        let chain = self.locked();
        let Some(tip) = chain.best_chain.tip() else {
            return Err(PoolError::Other("the best chain is empty".to_string()));
        };
        let node_view = NodeBranchView {
            store: &chain.store,
            tip,
        };
        let node_height = chain.store.node(tip).height;
        dcroxide_blockchain::sequencelock::calc_sequence_lock(
            &node_view,
            node_height,
            tx,
            |op| {
                view.lookup_entry(op)
                    .filter(|entry| !entry.is_spent())
                    .map(|entry| entry.block_height())
            },
            true,
            &self.params,
        )
        .map_err(|e| PoolError::Rule(chain_rule_error(e)))
    }

    fn is_treasury_agenda_active(&self) -> Result<bool, String> {
        let chain = self.locked();
        let tip_hash = chain.best_snapshot().hash;
        chain
            .is_treasury_agenda_active(&tip_hash, &self.params)
            .map_err(|e| e.description)
    }

    fn is_auto_revocations_agenda_active(&self) -> Result<bool, String> {
        let chain = self.locked();
        let tip_hash = chain.best_snapshot().hash;
        chain
            .is_auto_revocations_agenda_active(&tip_hash, &self.params)
            .map_err(|e| e.description)
    }

    fn is_subsidy_split_agenda_active(&self) -> Result<bool, String> {
        let chain = self.locked();
        let tip_hash = chain.best_snapshot().hash;
        chain
            .is_subsidy_split_agenda_active(&tip_hash, &self.params)
            .map_err(|e| e.description)
    }

    fn is_subsidy_split_r2_agenda_active(&self) -> Result<bool, String> {
        let chain = self.locked();
        let tip_hash = chain.best_snapshot().hash;
        chain
            .is_subsidy_split_r2_agenda_active(&tip_hash, &self.params)
            .map_err(|e| e.description)
    }

    fn tspend_mined_on_ancestor(&self, tspend: &Hash) -> Result<(), String> {
        let chain = self.locked();
        let Some(tip) = chain.best_chain.tip() else {
            return Ok(());
        };
        chain.check_tspend_exists(tip, tspend)
    }

    /// The script verification flags for standardness
    /// ([`chain_standard_verify_flags`]).
    fn standard_verify_flags(&self) -> Result<ScriptFlags, String> {
        chain_standard_verify_flags(&self.locked(), &self.params)
    }

    fn now_unix(&self) -> i64 {
        now_unix()
    }
}

/// dcrd's mempool policy values (server.go `newServer`'s
/// `mempool.Policy` literal).
pub fn node_policy(
    params: &Params,
    accept_non_std: bool,
    max_orphan_txs: i64,
    min_relay_tx_fee: i64,
    allow_old_votes: bool,
    enable_ancestor_tracking: bool,
) -> Policy {
    let max_vote_age = match params.net {
        CurrencyNet::TEST_NET3 => DEFAULT_MAXIMUM_VOTE_AGE,
        // Mainnet, simnet, regnet, and anything else use the
        // coinbase maturity.
        _ => params.coinbase_maturity,
    };
    Policy {
        accept_non_std,
        max_orphan_txs,
        max_orphan_tx_size: MAX_STANDARD_TX_SIZE as i64,
        max_sig_ops_per_tx: dcroxide_blockchain::validate::MAX_SIG_OPS_PER_BLOCK / 5,
        min_relay_tx_fee,
        allow_old_votes,
        max_vote_age,
        enable_ancestor_tracking,
    }
}

/// A shared pool over the shared chain (dcrd `newServer` building the
/// pool from its config).
#[allow(clippy::too_many_arguments)] // Mirrors dcrd's policy knobs.
pub fn new_shared_tx_pool(
    chain: Arc<Mutex<Chain>>,
    params: &Params,
    accept_non_std: bool,
    max_orphan_txs: i64,
    min_relay_tx_fee: i64,
    allow_old_votes: bool,
    enable_ancestor_tracking: bool,
) -> Arc<Mutex<NodeTxPool>> {
    let policy = node_policy(
        params,
        accept_non_std,
        max_orphan_txs,
        min_relay_tx_fee,
        allow_old_votes,
        enable_ancestor_tracking,
    );
    Arc::new(Mutex::new(TxPool::new(
        NodePoolChain::new(chain, params.clone()),
        policy,
        params,
    )))
}

/// The netsync adapter over the shared pool (dcrd hands netsync the
/// pool directly; the mutex stands in for the pool's internal
/// locking).
pub struct NodeSyncTxPool {
    pool: Arc<Mutex<NodeTxPool>>,
}

impl NodeSyncTxPool {
    /// Adapt the shared pool for the sync manager.
    pub fn new(pool: Arc<Mutex<NodeTxPool>>) -> NodeSyncTxPool {
        NodeSyncTxPool { pool }
    }

    fn locked(&self) -> MutexGuard<'_, NodeTxPool> {
        self.pool.lock().expect("tx pool mutex poisoned")
    }
}

impl SyncTxPool for NodeSyncTxPool {
    fn process_transaction(
        &mut self,
        tx: &MsgTx,
        allow_orphan: bool,
        allow_high_fees: bool,
        tag: u64,
    ) -> Result<Vec<Hash>, String> {
        self.locked()
            .process_transaction(tx, allow_orphan, allow_high_fees, tag)
            .map_err(|e| pool_error_text(&e))
    }

    fn have_transaction(&mut self, hash: &Hash) -> bool {
        self.locked().have_transaction(hash)
    }

    fn prune_stake_tx(&mut self, required_stake_difficulty: i64, height: i64) {
        self.locked()
            .prune_stake_tx(required_stake_difficulty, height);
    }

    fn prune_expired_tx(&mut self, height: i64) {
        self.locked().prune_expired_tx(height);
    }
}

/// A log-friendly description of a pool failure (the netsync seam
/// only feeds the text to logs and the rejection filter).
fn pool_error_text(err: &PoolError) -> String {
    match err {
        PoolError::Rule(rule) => rule.description.clone(),
        PoolError::Other(text) => text.clone(),
    }
}

/// The RPC mempool adapter over the shared pool (dcrd wires the pool
/// itself as the rpcserver's `TxMempooler`).
pub struct NodeRpcTxMempooler {
    pool: Arc<Mutex<NodeTxPool>>,
}

impl NodeRpcTxMempooler {
    /// Adapt the shared pool for the RPC handlers.
    pub fn new(pool: Arc<Mutex<NodeTxPool>>) -> NodeRpcTxMempooler {
        NodeRpcTxMempooler { pool }
    }

    fn locked(&self) -> MutexGuard<'_, NodeTxPool> {
        self.pool.lock().expect("tx pool mutex poisoned")
    }
}

impl RpcTxMempooler for NodeRpcTxMempooler {
    fn tx_descs(&mut self) -> Vec<RpcMempoolTx> {
        self.locked()
            .tx_descs()
            .iter()
            .map(|desc| RpcMempoolTx {
                tx: desc.tx.clone(),
                tx_type: desc.tx_type,
                fee: desc.fee,
            })
            .collect()
    }

    fn count(&mut self) -> i64 {
        self.locked().count() as i64
    }

    fn tspend_hashes(&mut self) -> Vec<Hash> {
        self.locked().tspend_hashes()
    }

    fn verbose_tx_descs(&mut self) -> Vec<RpcVerboseMempoolTx> {
        let pool = self.locked();
        pool.tx_descs()
            .iter()
            .map(|desc| {
                // The dependencies are the pool transactions this one
                // redeems (dcrd `VerboseTxDescs`).
                let mut depends = Vec::new();
                for tx_in in &desc.tx.tx_in {
                    let prev = tx_in.previous_out_point.hash;
                    if pool.is_transaction_in_pool(&prev) && !depends.contains(&prev) {
                        depends.push(prev);
                    }
                }
                RpcVerboseMempoolTx {
                    tx: desc.tx.clone(),
                    tx_type: desc.tx_type,
                    added_unix: desc.added_unix,
                    height: desc.height,
                    fee: desc.fee,
                    depends,
                }
            })
            .collect()
    }

    fn have_transactions(&mut self, hashes: &[Hash]) -> Vec<bool> {
        self.locked().have_transactions(hashes)
    }

    fn fetch_transaction(&mut self, tx_hash: &Hash) -> Result<(MsgTx, i8), String> {
        let pool = self.locked();
        let Some(tx) = pool.fetch_transaction(tx_hash) else {
            return Err("transaction is not in the pool".to_string());
        };
        let tree = if dcroxide_stake::determine_tx_type(&tx) == dcroxide_stake::TxType::Regular {
            dcroxide_wire::TX_TREE_REGULAR
        } else {
            dcroxide_wire::TX_TREE_STAKE
        };
        Ok((tx, tree))
    }
}

/// Whether the pool failure is dcrd's duplicate class for the
/// sendrawtransaction error mapping (`ErrDuplicate` or
/// `ErrAlreadyExists`).
pub fn is_duplicate_pool_error(err: &PoolError) -> bool {
    use dcroxide_mempool::ErrorKind;
    matches!(
        err,
        PoolError::Rule(rule) if matches!(
            &rule.err,
            RuleErrorSource::Mempool(ErrorKind::Duplicate)
                | RuleErrorSource::Mempool(ErrorKind::AlreadyExists)
        )
    )
}
