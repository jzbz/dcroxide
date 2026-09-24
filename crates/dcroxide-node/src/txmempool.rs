// SPDX-License-Identifier: ISC
//! The daemon's transaction memory pool assembly: the [`PoolChain`]
//! adapter binding the ported pool to the live chain (dcrd `newServer`
//! building its `mempool.Config` closures), the policy construction
//! with dcrd's exact values, and the adapters serving the pool to the
//! netsync manager and the RPC server.
//!
//! The pool's other consumers are wired elsewhere.  The transaction
//! relay to peers (dcrd `AnnounceNewTransactions`' inventory half)
//! runs in `dispatch` for peer-delivered transactions and in
//! `chainntfns`' `announce_transactions` for the ones maintenance
//! re-admits; RPC submissions go through the connection-manager seams
//! in `rpcrun` (`relay_transactions`, and `add_rebroadcast_inventory`
//! for the rebroadcast inventory).  The fee estimator hooks are the
//! `fees::NodeFeeEstimatorSink` the daemon installs on the pool.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use dcroxide_blockchain::chainview_nodes::NodeBranchView;
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::sequencelock::SequenceLock;
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_connmgr::{Csprng, SystemCsprng};
use dcroxide_mempool::{
    MAX_STANDARD_TX_SIZE, Policy, PoolChain, PoolError, RuleErrorSource, TxPool, chain_rule_error,
};
use dcroxide_netsync::manager::{ProcessTxFailure, SyncTxPool};
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

/// The memoized view of the tip with its regular tree disconnected
/// (dcrd `BlockChain.disapprovedView` behind `disapprovedViewLock`):
/// built once per tip and handed out as clones, keyed by the view's
/// best hash exactly as dcrd compares `disapprovedView.BestHash()`
/// against the tip.  dcrd keeps one on the chain; the port keeps one
/// per chain adapter (the pool's lives as long as the pool, the
/// template generator's for one template build), which serves the
/// same view for a tip -- the view is a pure function of the tip --
/// and keeps the cache out of the consensus crate.
#[derive(Default)]
pub(crate) struct DisapprovedViewCache(Mutex<Option<UtxoView>>);

/// The unspent view for the transaction's inputs and its own outputs
/// from the tip's point of view (dcrd `BlockChain.FetchUtxoView`,
/// which dcrd wires into both its mempool and mining configs; the
/// pool trait's `tree_valid` and the template trait's
/// `include_regular_txns` are the same flag).  When the flag is
/// unset, the tip's regular tree is disconnected from the view first,
/// from the memoized disapproved view when it is for this tip.
/// Spent entries stay in the view like the cache hands them out; the
/// consumers' checks filter them.
pub(crate) fn chain_fetch_utxo_view(
    chain: &Chain,
    params: &Params,
    disapproved: &DisapprovedViewCache,
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
        // (dcrd `disconnectDisapprovedBlock`) only once per tip, and
        // afterwards clone the cached result so the caller can mutate
        // its copy (dcrd `FetchUtxoView`, `utxoviewpoint.go:984-1011`).
        // A failed build leaves the cache as it was, as dcrd's early
        // returns do.
        let mut cached = disapproved.0.lock().expect("disapproved view poisoned");
        match cached.as_ref() {
            Some(cached_view) if cached_view.best_hash() == best.hash => {
                view = cached_view.clone();
            }
            _ => {
                let is_treasury_enabled = chain
                    .is_treasury_agenda_active(&best.hash, params)
                    .map_err(|e| e.description)?;
                let tip_block = chain
                    .block_by_hash(&best.hash)
                    .ok_or_else(|| format!("no block data for tip {}", best.hash))?;
                let stxos = chain
                    .fetch_spend_journal(&tip_block, is_treasury_enabled)
                    .map_err(|e| e.description)?;
                view.disconnect_disapproved_block(
                    &tip_block,
                    &stxos,
                    &|op: &OutPoint| chain.fetch_utxo_entry(op),
                    is_treasury_enabled,
                )
                .map_err(|e| e.description)?;
                *cached = Some(view.clone());
            }
        }
    }

    // The transaction's own outputs (for duplicate detection), then
    // its inputs: the outpoints the view lacks (dcrd's
    // `ViewFilteredSet`) resolve in one batch (dcrd `fetchUtxosMain`
    // over `UtxoCache.FetchEntries`), so every cache miss shares one
    // database read transaction.  Outpoints the chain does not know
    // stay absent from the view.  A duplicate input is not filtered:
    // only an invalid transaction has one, and the batch resolves
    // each copy to the same entry, so a list and dcrd's set agree.
    let mut needed: Vec<OutPoint> =
        Vec::with_capacity(tx.tx_out.len().saturating_add(tx.tx_in.len()));
    for tx_out_idx in 0..tx.tx_out.len() {
        let op = OutPoint {
            hash: *tx_hash,
            index: tx_out_idx as u32,
            tree,
        };
        if view.lookup_entry(&op).is_none() {
            needed.push(op);
        }
    }
    for tx_in in &tx.tx_in {
        let op = tx_in.previous_out_point;
        if view.lookup_entry(&op).is_none() {
            needed.push(op);
        }
    }
    if !needed.is_empty() {
        for (op, entry) in needed.iter().zip(chain.fetch_utxo_entries(&needed)) {
            if let Some(entry) = entry {
                view.insert_entry(op, entry);
            }
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
    /// The pool's random source: a ChaCha20 keystream seeded from the
    /// OS once, at construction, the same way the address manager's
    /// bucket key and the connection manager's source are.  Behind a
    /// mutex because `PoolChain::random_u64` takes `&self`.
    rng: Mutex<SystemCsprng>,
    /// The memoized disapproved-tip view the pool's fetches share.
    disapproved_view: DisapprovedViewCache,
}

impl NodePoolChain {
    /// Adapt the shared chain for the pool.
    ///
    /// Seeding the pool's random source is the only step here that can
    /// fail, and it happens where dcrd's does: the daemon builds the
    /// pool at startup, before any listener accepts, and dcrd's
    /// `crypto/rand` panics in package `init` if the kernel will not
    /// answer (`crypto/rand/prng.go:116-122`).  On a machine where
    /// that fails the daemon has already died earlier anyway --
    /// `AddrManager::new` seeds its own source first.
    pub fn new(chain: Arc<Mutex<Chain>>, params: Params) -> NodePoolChain {
        NodePoolChain::with_rng(chain, params, SystemCsprng::default())
    }

    /// The same, over a caller-supplied random source.
    ///
    /// Nothing in the daemon calls this; it exists so a test can pin
    /// the draw sequence with `SystemCsprng::from_seed` and so prove
    /// the source is seeded once rather than read per draw.
    pub fn with_rng(chain: Arc<Mutex<Chain>>, params: Params, rng: SystemCsprng) -> NodePoolChain {
        NodePoolChain {
            chain,
            params,
            rng: Mutex::new(rng),
            disapproved_view: DisapprovedViewCache::default(),
        }
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
    /// (`chain_fetch_utxo_view`; the pool's votes disapproving the
    /// tip's regular tree is the unset flag).
    fn fetch_utxo_view(
        &self,
        tx: &MsgTx,
        tx_hash: &Hash,
        tree: i8,
        tree_valid: bool,
    ) -> Result<UtxoView, String> {
        chain_fetch_utxo_view(
            &self.locked(),
            &self.params,
            &self.disapproved_view,
            tx,
            tx_hash,
            tree,
            tree_valid,
        )
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
    /// (`chain_standard_verify_flags`).
    fn standard_verify_flags(&self) -> Result<ScriptFlags, String> {
        chain_standard_verify_flags(&self.locked(), &self.params)
    }

    fn now_unix(&self) -> i64 {
        now_unix()
    }

    /// Drawn from the ChaCha20 keystream seeded at construction.  This
    /// picks which orphan is evicted under pressure
    /// (`TxPool::limit_num_orphans`), so a predictable draw is one an
    /// attacker grinds against to keep their own orphans resident.
    ///
    /// dcrd draws nothing at that seam: `limitNumOrphans` walks a Go
    /// map and breaks (`internal/mempool/mempool.go:490-501`), and its
    /// mempool imports no randomness package at all.  What is borrowed
    /// from dcrd here is the *source's* contract, not the seam.
    /// `crypto/rand` acquires kernel entropy fatally exactly once, in
    /// package `init` (`crypto/rand/prng.go:116-122`); afterwards it
    /// keeps reading the kernel on each rekey but ignores a failure
    /// (`prng.go:68-70`, `:101`), so no draw can fail -- "The default
    /// global PRNG will never panic after package init"
    /// (`crypto/rand/README.md:18`).  Reading the kernel per draw
    /// instead put a fallible call on a path a peer paces by pushing
    /// orphans, and under `panic = "abort"` that is an outage dcrd's
    /// map walk has no way to cause.
    fn random_u64(&self) -> u64 {
        // A poisoned lock has no invariant to protect here: the
        // guarded state is a keystream, every value it yields is
        // conformant, and `SystemCsprng` rekeys long before its block
        // counter runs out, so it has no reachable panic of its own to
        // poison with.  Recovering the guard rather than expecting on
        // it keeps the abort off the path this seam exists to make
        // infallible.
        self.rng
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .uint64()
    }

    /// The chain's shared signature verification cache, so block
    /// connects reuse the mempool's successful verifications (dcrd
    /// wires `s.sigCache` into `mempool.Config.SigCache`).
    fn sig_cache(&self) -> Option<Arc<dcroxide_txscript::SigCache>> {
        self.locked().sig_cache.clone()
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
/// locking).  Clones share the pool.
#[derive(Clone)]
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

    fn process_transaction_accepted(
        &mut self,
        tx: &MsgTx,
        allow_orphan: bool,
        allow_high_fees: bool,
        tag: u64,
    ) -> Result<Vec<(Hash, MsgTx)>, ProcessTxFailure> {
        self.locked()
            .process_transaction_accepted(tx, allow_orphan, allow_high_fees, tag)
            .map_err(|e| ProcessTxFailure {
                // dcrd's `errors.As(err, &mempool.RuleError{})` split
                // in `OnTx`: anything else is an internal fault.
                is_rule_error: matches!(e, PoolError::Rule(_)),
                message: pool_error_text(&e),
            })
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
/// only feeds the text to logs and the rejection filter, with the
/// rule/non-rule split carried beside it where a log depends on it).
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

/// The pool transactions the transaction redeems: one entry per input
/// whose previous outpoint's transaction is in the pool, in input
/// order, repeats included (dcrd `VerboseTxDescs` appends a `Depends`
/// entry for every such input, `internal/mempool/mempool.go:2289-2293`,
/// and `handleGetRawMempool` copies the slice one for one, so a child
/// spending two outputs of one pool parent lists that parent twice).
fn verbose_depends(tx: &MsgTx, in_pool: impl Fn(&Hash) -> bool) -> Vec<Hash> {
    tx.tx_in
        .iter()
        .map(|tx_in| tx_in.previous_out_point.hash)
        .filter(|prev| in_pool(prev))
        .collect()
}

impl RpcTxMempooler for NodeRpcTxMempooler {
    /// The pool's descriptors (dcrd `TxDescs`).  Only the shared
    /// descriptor handles are taken under the pool mutex -- dcrd copies
    /// its descriptor pointers under the read lock -- and the lean RPC
    /// descriptors are built after the guard is released, so a
    /// fee-stats call copies no transaction and holds the pool only
    /// for the handle list.
    fn tx_descs(&self) -> Vec<RpcMempoolTx> {
        let descs = self.locked().tx_descs();
        descs
            .iter()
            .map(|desc| RpcMempoolTx {
                serialize_size: desc.tx.serialize_size(),
                tx_hash: desc.tx_hash,
                tx_type: desc.tx_type,
                fee: desc.fee,
            })
            .collect()
    }

    fn count(&self) -> i64 {
        self.locked().count() as i64
    }

    fn tspend_hashes(&self) -> Vec<Hash> {
        self.locked().tspend_hashes()
    }

    /// The verbose descriptors (dcrd `VerboseTxDescs`): the handles and
    /// their dependencies are read under one hold of the pool mutex,
    /// as dcrd reads both under its read lock, and the rest is built
    /// after it is released.
    fn verbose_tx_descs(&self) -> Vec<RpcVerboseMempoolTx> {
        let (descs, depends): (Vec<_>, Vec<_>) = {
            let pool = self.locked();
            pool.tx_descs()
                .into_iter()
                .map(|desc| {
                    let depends =
                        verbose_depends(&desc.tx, |hash| pool.is_transaction_in_pool(hash));
                    (desc, depends)
                })
                .unzip()
        };
        descs
            .iter()
            .zip(depends)
            .map(|(desc, depends)| RpcVerboseMempoolTx {
                serialize_size: desc.tx.serialize_size(),
                tx_hash: desc.tx_hash,
                tx_type: desc.tx_type,
                added_unix: desc.added_unix,
                height: desc.height,
                fee: desc.fee,
                depends,
            })
            .collect()
    }

    fn have_transactions(&self, hashes: &[Hash]) -> Vec<bool> {
        self.locked().have_transactions(hashes)
    }

    fn fetch_transaction(&self, tx_hash: &Hash) -> Result<(MsgTx, i8), String> {
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

/// A live regnet chain over dcrd's full-block battery, for the crate's
/// unit tests that need real chain state.
#[cfg(test)]
pub(crate) mod test_support {
    use dcroxide_blockchain::process::Chain;
    use dcroxide_database::{Database, Options};
    use dcroxide_testutil::unhex;
    use dcroxide_wire::MsgBlock;

    /// The leading consecutive main-chain prefix of accepted blocks
    /// from dcrd's `fullblocktests.Generate` battery (fully signed
    /// regnet blocks), with the battery's recorded generation time.
    pub(crate) fn accepted_prefix(limit: usize) -> (i64, Vec<MsgBlock>) {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dcroxide-blockchain/tests/data/fullblock_vectors.txt"
        );
        let data = std::fs::read_to_string(path).expect("fullblock vectors");
        let mut now: i64 = 0;
        let mut tip = dcroxide_chaincfg::regnet_params().genesis_hash;
        let mut blocks = Vec::new();
        for line in data.lines() {
            let f: Vec<&str> = line.split(' ').collect();
            match f[0] {
                "now" => now = f[1].parse().expect("generation time"),
                // accept <name> <mainchain> <orphan> <blockhex>
                "accept" => {
                    let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                    if f[2] != "true" || block.header.prev_block != tip {
                        continue;
                    }
                    tip = block.header.block_hash();
                    blocks.push(block);
                    if blocks.len() == limit {
                        break;
                    }
                }
                _ => {}
            }
        }
        assert_eq!(blocks.len(), limit, "battery must provide the prefix");
        (now, blocks)
    }

    /// A regnet chain with the first `history` of `blocks` processed.
    pub(crate) fn regnet_chain(
        now: i64,
        blocks: &[MsgBlock],
        history: usize,
    ) -> (tempfile::TempDir, Chain) {
        let params = dcroxide_chaincfg::regnet_params();
        let dir = tempfile::tempdir().expect("temp dir");
        let opts = Options::new(dir.path().join("blocks"), params.net.0);
        let db = Database::create(&opts).expect("create database");
        let mut chain =
            Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain");
        for block in &blocks[..history] {
            let (_, errs) = chain.process_block(block, now, &params);
            assert!(errs.is_empty(), "history block must accept: {errs:?}");
        }
        (dir, chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcroxide_blockchain::UtxoEntry;
    use dcroxide_wire::{TxIn, TxOut, TxSerializeType};

    /// A transaction spending the given outpoints with one output.
    fn spending(inputs: &[OutPoint]) -> MsgTx {
        MsgTx {
            ser_type: TxSerializeType::Full,
            version: 1,
            tx_in: inputs
                .iter()
                .map(|op| TxIn {
                    previous_out_point: *op,
                    ..TxIn::default()
                })
                .collect(),
            tx_out: vec![TxOut {
                value: 1,
                version: 0,
                pk_script: vec![0x51],
            }],
            lock_time: 0,
            expiry: 0,
        }
    }

    /// dcrd `VerboseTxDescs` appends a dependency per redeeming input
    /// (`internal/mempool/mempool.go:2289-2293`) and `getrawmempool`
    /// renders the slice one for one: a child spending two outputs of
    /// one pool parent lists that parent twice, in input order, and an
    /// input whose parent is not in the pool adds nothing.
    #[test]
    fn verbose_depends_lists_a_parent_once_per_spending_input() {
        let parent = Hash([0x11; 32]);
        let other_parent = Hash([0x22; 32]);
        let confirmed = Hash([0x33; 32]);
        let op = |hash, index| OutPoint {
            hash,
            index,
            tree: dcroxide_wire::TX_TREE_REGULAR,
        };
        let child = spending(&[
            op(parent, 0),
            op(confirmed, 0),
            op(other_parent, 3),
            op(parent, 1),
        ]);
        let in_pool = |hash: &Hash| *hash == parent || *hash == other_parent;
        assert_eq!(
            verbose_depends(&child, in_pool),
            vec![parent, other_parent, parent],
            "one dependency per redeeming input, repeats kept"
        );
    }

    /// dcrd `FetchUtxoView` disconnects the tip's regular tree once per
    /// tip and afterwards clones the cached `disapprovedView`
    /// (`utxoviewpoint.go:984-1011`).  An entry planted in the memo
    /// comes back from the next disapproved fetch -- so that fetch was
    /// served from the memo, not rebuilt -- while a fetch that includes
    /// the regular tree never reads it and a new tip rebuilds it.
    #[test]
    fn the_disapproved_view_is_built_once_per_tip() {
        let params = dcroxide_chaincfg::regnet_params();
        let (now, blocks) = test_support::accepted_prefix(3);
        let (_dir, mut chain) = test_support::regnet_chain(now, &blocks, 2);
        let cache = DisapprovedViewCache::default();
        let tx = spending(&[OutPoint {
            hash: Hash([0x44; 32]),
            index: 0,
            tree: dcroxide_wire::TX_TREE_REGULAR,
        }]);
        let tx_hash = tx.tx_hash();
        let fetch = |chain: &Chain, include_regular_txns| {
            chain_fetch_utxo_view(
                chain,
                &params,
                &cache,
                &tx,
                &tx_hash,
                dcroxide_wire::TX_TREE_REGULAR,
                include_regular_txns,
            )
            .expect("view")
        };

        let tip = chain.best_snapshot().hash;
        let first = fetch(&chain, false);
        let memo_hash = cache
            .0
            .lock()
            .expect("memo")
            .as_ref()
            .map(UtxoView::best_hash);
        assert_eq!(memo_hash, Some(tip), "the first fetch memoizes the tip");

        let planted = OutPoint {
            hash: Hash([0xee; 32]),
            index: 7,
            tree: dcroxide_wire::TX_TREE_REGULAR,
        };
        let sentinel = UtxoEntry::new(
            42,
            vec![0x51],
            1,
            0,
            0,
            false,
            false,
            dcroxide_stake::TxType::Regular,
            None,
        );
        cache
            .0
            .lock()
            .expect("memo")
            .as_mut()
            .expect("memoized")
            .insert_entry(&planted, sentinel.clone());

        let second = fetch(&chain, false);
        assert_eq!(
            second.lookup_entry(&planted),
            Some(&sentinel),
            "the same tip is served from the memo"
        );
        let first_entries: Vec<_> = first.entries().collect();
        let second_entries: Vec<_> = second
            .entries()
            .filter(|(_, entry)| **entry != sentinel)
            .collect();
        assert_eq!(first_entries, second_entries, "the memo is the built view");

        assert!(
            fetch(&chain, true).lookup_entry(&planted).is_none(),
            "a fetch that keeps the regular tree does not read the memo"
        );

        let (_, errs) = chain.process_block(&blocks[2], now, &params);
        assert!(errs.is_empty(), "battery block must accept: {errs:?}");
        let new_tip = chain.best_snapshot().hash;
        assert!(
            fetch(&chain, false).lookup_entry(&planted).is_none(),
            "a new tip rebuilds the memo"
        );
        let memo_hash = cache
            .0
            .lock()
            .expect("memo")
            .as_ref()
            .map(UtxoView::best_hash);
        assert_eq!(memo_hash, Some(new_tip), "the memo follows the tip");
    }

    /// Resolving the view's missing outpoints in one batch yields the
    /// view the per-outpoint lookups built: every existing output the
    /// transaction spends, nothing for one the chain does not know, and
    /// nothing for the transaction's own not-yet-existing outputs.
    #[test]
    fn the_batched_view_resolves_like_per_outpoint_lookups() {
        let params = dcroxide_chaincfg::regnet_params();
        let (now, blocks) = test_support::accepted_prefix(2);
        let (_dir, chain) = test_support::regnet_chain(now, &blocks, 2);
        let coinbase = &blocks[0].transactions[0];
        let coinbase_hash = coinbase.tx_hash();
        let mut inputs: Vec<OutPoint> = (0..coinbase.tx_out.len() as u32)
            .map(|index| OutPoint {
                hash: coinbase_hash,
                index,
                tree: dcroxide_wire::TX_TREE_REGULAR,
            })
            .collect();
        let unknown = OutPoint {
            hash: Hash([0x55; 32]),
            index: 0,
            tree: dcroxide_wire::TX_TREE_REGULAR,
        };
        inputs.push(unknown);
        let tx = spending(&inputs);
        let tx_hash = tx.tx_hash();

        let view = chain_fetch_utxo_view(
            &chain,
            &params,
            &DisapprovedViewCache::default(),
            &tx,
            &tx_hash,
            dcroxide_wire::TX_TREE_REGULAR,
            true,
        )
        .expect("view");
        let mut found = 0;
        for op in &inputs {
            let expected = chain.fetch_utxo_entry(op);
            assert_eq!(view.lookup_entry(op), expected.as_ref(), "input {op:?}");
            found += usize::from(expected.is_some());
        }
        assert!(found > 0, "the battery's block one outputs are unspent");
        assert!(view.lookup_entry(&unknown).is_none());
        assert!(
            view.lookup_entry(&OutPoint {
                hash: tx_hash,
                index: 0,
                tree: dcroxide_wire::TX_TREE_REGULAR,
            })
            .is_none(),
            "the transaction's own output does not exist yet"
        );
        assert_eq!(
            view.entries().count(),
            found,
            "the view holds exactly the entries that exist"
        );
    }
}
