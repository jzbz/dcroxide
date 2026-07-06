// SPDX-License-Identifier: ISC

//! The transaction memory pool from dcrd's `internal/mempool`
//! `mempool.go`: the main, orphan, and stage pools with their
//! outpoint indexes, vote and treasury spend tracking, the full
//! acceptance gauntlet (`maybeAcceptTransaction`), orphan processing,
//! and the pruning surface.  The mining view bookkeeping, exists
//! address index, fee estimator hooks, and notification callbacks are
//! integration plumbing that arrives with the mining and RPC phases;
//! dcrd's locks are unnecessary under Rust ownership.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use dcroxide_blockchain::sequencelock::SequenceLock;
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_blockchain::validate::{
    AgendaFlags, ChainSubsidyParams, check_transaction, check_transaction_inputs,
    count_p2sh_sig_ops, count_sig_ops, is_expired_tx, sequence_lock_active,
    validate_transaction_scripts, verify_tspend_signature,
};
use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_stake::TxType;
use dcroxide_standalone::{SubsidyCache, SubsidySplitVariant};
use dcroxide_txscript::ScriptFlags;
use dcroxide_wire::{BlockHeader, MsgTx, OutPoint};

use crate::error::{
    ErrorKind, PoolError, RuleError, chain_rule_error, tx_rule_error, wrap_tx_rule_error,
};
use crate::policy::calc_min_required_tx_relay_fee;
use crate::{check_inputs_standard, check_transaction_standard};
use dcroxide_mining::TxMiningView;
pub use dcroxide_mining::{TxDesc, UNMINED_HEIGHT, VoteDesc};

/// The factor that fees per kB are disallowed above the minimum
/// transaction fee (dcrd `maxRelayFeeMultiplier`).
const MAX_RELAY_FEE_MULTIPLIER: i64 = 10000;

/// The maximum number of vote double spends allowed in the pool (dcrd
/// `maxVoteDoubleSpends`).
const MAX_VOTE_DOUBLE_SPENDS: usize = 5;

/// The number of blocks to pass in terms of height before old tickets
/// are pruned (dcrd `heightDiffToPruneTicket`).
const HEIGHT_DIFF_TO_PRUNE_TICKET: i64 = 288;

/// The number of blocks to pass in terms of height before votes on a
/// block are pruned (dcrd `heightDiffToPruneVotes`).
const HEIGHT_DIFF_TO_PRUNE_VOTES: i64 = 10;

/// The maximum amount of time an orphan is allowed to stay in the
/// orphan pool before it expires, in seconds (dcrd `orphanTTL`).
const ORPHAN_TTL_SECS: i64 = 15 * 60;

/// The minimum amount of time between scans of the orphan pool to
/// evict expired transactions, in seconds (dcrd
/// `orphanExpireScanInterval`).
const ORPHAN_EXPIRE_SCAN_INTERVAL_SECS: i64 = 5 * 60;

/// The maximum number of concurrent treasury spends allowed in the
/// mempool (dcrd `MempoolMaxConcurrentTSpends`).
pub const MEMPOOL_MAX_CONCURRENT_TSPENDS: usize = 7;

/// The null block index sentinel (wire `NullBlockIndex`).
const NULL_BLOCK_INDEX: u32 = 0xffffffff;

/// An identifier for tagging orphan transactions, commonly a peer ID
/// (dcrd `Tag`).
pub type Tag = u64;

/// The chain state and callbacks the pool needs, standing in for the
/// closures of dcrd's mempool `Config` (the exists address index, fee
/// estimator, and notification callbacks are integration plumbing and
/// are not part of this interface).
pub trait PoolChain {
    /// The stake difficulty for the block after the current best block
    /// (dcrd `Config.NextStakeDifficulty`).
    fn next_stake_difficulty(&self) -> Result<i64, String>;
    /// Unspent output information for the transaction's inputs and its
    /// own outputs from the point of view of the main chain tip (dcrd
    /// `Config.FetchUtxoView`).
    fn fetch_utxo_view(
        &self,
        tx: &MsgTx,
        tx_hash: &Hash,
        tree: i8,
        tree_valid: bool,
    ) -> Result<UtxoView, String>;
    /// The current best block hash (dcrd `Config.BestHash`).
    fn best_hash(&self) -> Hash;
    /// The current best block height (dcrd `Config.BestHeight`).
    fn best_height(&self) -> i64;
    /// The header for the given block hash (dcrd
    /// `Config.HeaderByHash`).
    fn header_by_hash(&self, hash: &Hash) -> Result<BlockHeader, String>;
    /// The median time of the current chain tip as unix seconds (dcrd
    /// `Config.PastMedianTime`).
    fn past_median_time(&self) -> i64;
    /// The sequence lock for the transaction using the given view
    /// (dcrd `Config.CalcSequenceLock`).
    fn calc_sequence_lock(
        &self,
        tx: &MsgTx,
        tx_hash: &Hash,
        view: &UtxoView,
    ) -> Result<SequenceLock, PoolError>;
    /// Whether the treasury agenda is active (dcrd
    /// `Config.IsTreasuryAgendaActive`).
    fn is_treasury_agenda_active(&self) -> Result<bool, String>;
    /// Whether the automatic ticket revocations agenda is active (dcrd
    /// `Config.IsAutoRevocationsAgendaActive`).
    fn is_auto_revocations_agenda_active(&self) -> Result<bool, String>;
    /// Whether the modified subsidy split agenda is active (dcrd
    /// `Config.IsSubsidySplitAgendaActive`).
    fn is_subsidy_split_agenda_active(&self) -> Result<bool, String>;
    /// Whether the modified subsidy split round 2 agenda is active
    /// (dcrd `Config.IsSubsidySplitR2AgendaActive`).
    fn is_subsidy_split_r2_agenda_active(&self) -> Result<bool, String>;
    /// An error when the given treasury spend was mined on an ancestor
    /// block (dcrd `Config.TSpendMinedOnAncestor`).
    fn tspend_mined_on_ancestor(&self, tspend: &Hash) -> Result<(), String>;
    /// The script verification flags for the block after the current
    /// best block (dcrd `Policy.StandardVerifyFlags`).
    fn standard_verify_flags(&self) -> Result<ScriptFlags, String>;
    /// The current wall clock as unix seconds (dcrd's direct
    /// `time.Now()` calls, injected for determinism).
    fn now_unix(&self) -> i64;
}

/// The mempool policy configuration (dcrd `Policy`; the standard
/// verify flags closure lives on [`PoolChain`] and the ancestor
/// tracking toggle belongs to the mining view).
#[derive(Clone, Debug)]
pub struct Policy {
    /// Whether to accept non-standard transactions (dcrd
    /// `AcceptNonStd`).
    pub accept_non_std: bool,
    /// The maximum number of orphan transactions that can be queued
    /// (dcrd `MaxOrphanTxs`).
    pub max_orphan_txs: i64,
    /// The maximum size allowed for orphan transactions (dcrd
    /// `MaxOrphanTxSize`).
    pub max_orphan_tx_size: i64,
    /// The maximum number of signature operations in a single
    /// transaction (dcrd `MaxSigOpsPerTx`).
    pub max_sig_ops_per_tx: i64,
    /// The minimum transaction fee in atoms per 1000 bytes (dcrd
    /// `MinRelayTxFee`).
    pub min_relay_tx_fee: i64,
    /// Whether votes on old blocks are admitted and relayed (dcrd
    /// `AllowOldVotes`).
    pub allow_old_votes: bool,
    /// The number of blocks from the next block height for which votes
    /// are accepted when old votes are disallowed (dcrd `MaxVoteAge`).
    pub max_vote_age: u16,
    /// Whether the mining view tracks transaction relationships in
    /// the mempool (dcrd `EnableAncestorTracking`).
    pub enable_ancestor_tracking: bool,
}

/// An orphan transaction with its eviction metadata (dcrd
/// `orphanTx`).
struct OrphanTx {
    tx: Rc<MsgTx>,
    tx_hash: Hash,
    tag: Tag,
    expiration_unix: i64,
}

/// A map key for outpoints.
type OutKey = ([u8; 32], u32, i8);

fn out_key(op: &OutPoint) -> OutKey {
    (op.hash.0, op.index, op.tree)
}

/// The transaction tree for the given transaction type.
fn tree_for_type(tx_type: TxType) -> i8 {
    if tx_type == TxType::Regular {
        dcroxide_wire::TX_TREE_REGULAR
    } else {
        dcroxide_wire::TX_TREE_STAKE
    }
}

/// The transaction memory pool (dcrd `TxPool`).
pub struct TxPool<'p, C: PoolChain> {
    /// The chain backend.
    pub chain: C,
    /// The pool policy.
    pub policy: Policy,
    params: &'p Params,
    subsidy_cache: SubsidyCache<ChainSubsidyParams<'p>>,
    last_updated_unix: i64,

    pool: BTreeMap<[u8; 32], Rc<TxDesc>>,
    orphans: BTreeMap<[u8; 32], Rc<OrphanTx>>,
    orphans_by_prev: BTreeMap<OutKey, BTreeMap<[u8; 32], Rc<MsgTx>>>,
    outpoints: BTreeMap<OutKey, Rc<TxDesc>>,
    staged: BTreeMap<[u8; 32], Rc<TxDesc>>,
    staged_outpoints: BTreeMap<OutKey, Rc<TxDesc>>,
    transient: BTreeMap<[u8; 32], MsgTx>,
    mining_view: TxMiningView,
    votes: BTreeMap<[u8; 32], Vec<VoteDesc>>,
    tspends: BTreeSet<[u8; 32]>,
    next_expire_scan_unix: i64,
}

impl<'p, C: PoolChain> TxPool<'p, C> {
    /// A new memory pool for validating and storing standalone
    /// transactions until they are mined into a block (dcrd `New`).
    pub fn new(chain: C, policy: Policy, params: &'p Params) -> TxPool<'p, C> {
        let next_expire_scan_unix = chain.now_unix() + ORPHAN_EXPIRE_SCAN_INTERVAL_SECS;
        let mining_view = TxMiningView::new(policy.enable_ancestor_tracking);
        TxPool {
            chain,
            policy,
            params,
            subsidy_cache: SubsidyCache::new(ChainSubsidyParams(params)),
            last_updated_unix: 0,
            pool: BTreeMap::new(),
            orphans: BTreeMap::new(),
            orphans_by_prev: BTreeMap::new(),
            outpoints: BTreeMap::new(),
            staged: BTreeMap::new(),
            staged_outpoints: BTreeMap::new(),
            transient: BTreeMap::new(),
            mining_view,
            votes: BTreeMap::new(),
            tspends: BTreeSet::new(),
            next_expire_scan_unix,
        }
    }

    /// Insert a vote into the map of block votes (dcrd `insertVote`).
    fn insert_vote(&mut self, ssgen: &MsgTx, vote_hash: &Hash) {
        // Get the block it is voting on; here we're agnostic of
        // height.
        let (block_hash, _block_height) = dcroxide_stake::ssgen_block_voted_on(ssgen);

        let votes = self.votes.entry(block_hash.0).or_default();

        // Nothing to do if a vote for the ticket is already known.
        let ticket_hash = ssgen.tx_in[1].previous_out_point.hash;
        if votes.iter().any(|vt| vt.ticket_hash == ticket_hash) {
            return;
        }

        let vote_bits = dcroxide_stake::ssgen_vote_bits(ssgen);
        let approves_parent = vote_bits & 0x0001 != 0;
        votes.push(VoteDesc {
            vote_hash: *vote_hash,
            ticket_hash,
            approves_parent,
        });
    }

    /// The hashes for all votes on the provided block hash currently
    /// in the mempool (dcrd `VoteHashesForBlock`).
    pub fn vote_hashes_for_block(&self, block_hash: &Hash) -> Vec<Hash> {
        match self.votes.get(&block_hash.0) {
            None => Vec::new(),
            Some(votes) => votes.iter().map(|vt| vt.vote_hash).collect(),
        }
    }

    /// The vote metadata for all votes on the provided block hashes
    /// (dcrd `VotesForBlocks`).
    pub fn votes_for_blocks(&self, hashes: &[Hash]) -> Vec<Vec<VoteDesc>> {
        hashes
            .iter()
            .map(|hash| self.votes.get(&hash.0).cloned().unwrap_or_default())
            .collect()
    }

    /// The hashes of all tracked treasury spends (dcrd
    /// `TSpendHashes`).
    pub fn tspend_hashes(&self) -> Vec<Hash> {
        self.tspends.iter().map(|h| Hash(*h)).collect()
    }

    /// Remove the orphan and, when requested, all orphans that redeem
    /// its outputs (dcrd `removeOrphan`).
    fn remove_orphan(&mut self, tx_hash: &Hash, remove_redeemers: bool) {
        // Nothing to do if the passed tx does not exist in the orphan
        // pool.
        let Some(otx) = self.orphans.get(&tx_hash.0).cloned() else {
            return;
        };

        // Remove the reference from the previous orphan index.
        for tx_in in &otx.tx.tx_in {
            let key = out_key(&tx_in.previous_out_point);
            if let Some(orphans) = self.orphans_by_prev.get_mut(&key) {
                orphans.remove(&tx_hash.0);

                // Remove the map entry altogether if there are no
                // longer any orphans which depend on it.
                if orphans.is_empty() {
                    self.orphans_by_prev.remove(&key);
                }
            }
        }

        // Remove any orphans that redeem outputs from this one if
        // requested.
        if remove_redeemers {
            let tx_type = dcroxide_stake::determine_tx_type(&otx.tx);
            let tree = tree_for_type(tx_type);
            for tx_out_idx in 0..otx.tx.tx_out.len() as u32 {
                let key = (tx_hash.0, tx_out_idx, tree);
                let redeemers: Vec<Hash> = self
                    .orphans_by_prev
                    .get(&key)
                    .map(|m| m.keys().map(|k| Hash(*k)).collect())
                    .unwrap_or_default();
                for orphan_hash in redeemers {
                    self.remove_orphan(&orphan_hash, true);
                }
            }
        }

        // Remove the transaction from the orphan pool.
        self.orphans.remove(&tx_hash.0);
    }

    /// Remove the passed orphan transaction from the orphan pool (dcrd
    /// `RemoveOrphan`).
    pub fn remove_orphan_pub(&mut self, tx_hash: &Hash) {
        self.remove_orphan(tx_hash, false);
    }

    /// Remove all orphan transactions tagged with the provided
    /// identifier (dcrd `RemoveOrphansByTag`).
    pub fn remove_orphans_by_tag(&mut self, tag: Tag) -> u64 {
        let mut num_evicted = 0u64;
        let tagged: Vec<Hash> = self
            .orphans
            .values()
            .filter(|otx| otx.tag == tag)
            .map(|otx| otx.tx_hash)
            .collect();
        for hash in tagged {
            self.remove_orphan(&hash, true);
            num_evicted += 1;
        }
        num_evicted
    }

    /// Limit the number of orphans by evicting expired entries and, if
    /// still needed, an arbitrary orphan (dcrd `limitNumOrphans`;
    /// dcrd's random map eviction is an ordering-irrelevant choice by
    /// its own documentation, realized here as the first hash in
    /// order).
    fn limit_num_orphans(&mut self) {
        // Scan through the orphan pool and remove any expired orphans
        // when it's time.
        let now = self.chain.now_unix();
        if now > self.next_expire_scan_unix {
            let expired: Vec<Hash> = self
                .orphans
                .values()
                .filter(|otx| now > otx.expiration_unix)
                .map(|otx| otx.tx_hash)
                .collect();
            for hash in expired {
                // Remove redeemers too because the missing parents are
                // very unlikely to ever materialize.
                self.remove_orphan(&hash, true);
            }

            // Set next expiration scan to occur after the scan
            // interval.
            self.next_expire_scan_unix = now + ORPHAN_EXPIRE_SCAN_INTERVAL_SECS;
        }

        // Nothing to do if adding another orphan will not cause the
        // pool to exceed the limit (dcrd's len+1 <= max shape).
        #[allow(clippy::int_plus_one)]
        if (self.orphans.len() as i64) + 1 <= self.policy.max_orphan_txs {
            return;
        }

        // Evict an arbitrary orphan.  Don't remove redeemers in the
        // case of a random eviction since it is quite possible it
        // might be needed again shortly.
        if let Some(hash) = self.orphans.values().next().map(|otx| otx.tx_hash) {
            self.remove_orphan(&hash, false);
        }
    }

    /// Add an orphan transaction to the orphan pool (dcrd
    /// `addOrphan`).
    fn add_orphan(&mut self, tx: &MsgTx, tx_hash: &Hash, tag: Tag) {
        // Nothing to do if no orphans are allowed.
        if self.policy.max_orphan_txs <= 0 {
            return;
        }

        // Limit the number of orphan transactions to prevent memory
        // exhaustion.
        self.limit_num_orphans();

        let tx = Rc::new(tx.clone());
        self.orphans.insert(
            tx_hash.0,
            Rc::new(OrphanTx {
                tx: tx.clone(),
                tx_hash: *tx_hash,
                tag,
                expiration_unix: self.chain.now_unix() + ORPHAN_TTL_SECS,
            }),
        );
        for tx_in in &tx.tx_in {
            self.orphans_by_prev
                .entry(out_key(&tx_in.previous_out_point))
                .or_default()
                .insert(tx_hash.0, tx.clone());
        }
    }

    /// Potentially add an orphan to the orphan pool (dcrd
    /// `maybeAddOrphan`).
    fn maybe_add_orphan(&mut self, tx: &MsgTx, tx_hash: &Hash, tag: Tag) -> Result<(), RuleError> {
        // Ignore orphan transactions that are too large to help avoid
        // memory exhaustion attacks.
        let serialized_len = tx.serialize_size() as i64;
        if serialized_len > self.policy.max_orphan_tx_size {
            let str = format!(
                "orphan transaction size of {serialized_len} bytes is larger \
                 than max allowed size of {} bytes",
                self.policy.max_orphan_tx_size
            );
            return Err(tx_rule_error(ErrorKind::OrphanPolicyViolation, str));
        }

        // Add the orphan if the none of the above disqualified it.
        self.add_orphan(tx, tx_hash, tag);
        Ok(())
    }

    /// Remove all orphans which spend outputs spent by the passed
    /// transaction, recursively (dcrd `removeOrphanDoubleSpends`).
    fn remove_orphan_double_spends(&mut self, tx: &MsgTx) {
        for tx_in in &tx.tx_in {
            let key = out_key(&tx_in.previous_out_point);
            let orphans: Vec<Hash> = self
                .orphans_by_prev
                .get(&key)
                .map(|m| m.keys().map(|k| Hash(*k)).collect())
                .unwrap_or_default();
            for orphan_hash in orphans {
                self.remove_orphan(&orphan_hash, true);
            }
        }
    }

    /// Whether the transaction exists in the main pool (dcrd
    /// `isTransactionInPool`).
    pub fn is_transaction_in_pool(&self, hash: &Hash) -> bool {
        self.pool.contains_key(&hash.0)
    }

    /// Whether the transaction exists in the orphan pool (dcrd
    /// `isOrphanInPool`).
    pub fn is_orphan_in_pool(&self, hash: &Hash) -> bool {
        self.orphans.contains_key(&hash.0)
    }

    /// Whether the transaction exists in the stage pool (dcrd
    /// `isTransactionStaged`).
    pub fn is_transaction_staged(&self, hash: &Hash) -> bool {
        self.staged.contains_key(&hash.0)
    }

    /// Add the provided transaction to the stage pool (dcrd
    /// `stageTransaction`).
    fn stage_transaction(&mut self, tx_desc: Rc<TxDesc>) {
        self.staged.insert(tx_desc.tx_hash.0, tx_desc.clone());
        for tx_in in &tx_desc.tx.tx_in {
            self.staged_outpoints
                .insert(out_key(&tx_in.previous_out_point), tx_desc.clone());
        }
    }

    /// Remove the provided transaction from the stage pool (dcrd
    /// `removeStagedTransaction`).
    fn remove_staged_transaction(&mut self, staged: &TxDesc) {
        self.staged.remove(&staged.tx_hash.0);
        for tx_in in &staged.tx.tx_in {
            self.staged_outpoints
                .remove(&out_key(&tx_in.previous_out_point));
        }
    }

    /// Whether the provided transaction has an input in the main pool
    /// (dcrd `hasMempoolInput`).
    fn has_mempool_input(&self, tx: &MsgTx) -> bool {
        tx.tx_in
            .iter()
            .any(|tx_in| self.is_transaction_in_pool(&tx_in.previous_out_point.hash))
    }

    /// The descriptors in the given outpoint index that redeem outputs
    /// of the given regular transaction (the shared body of dcrd's
    /// `forEachRedeemer` helpers, collected to satisfy borrows).
    fn collect_redeemers(
        outpoints: &BTreeMap<OutKey, Rc<TxDesc>>,
        tx: &MsgTx,
        tx_hash: &Hash,
    ) -> Vec<Rc<TxDesc>> {
        let tree = dcroxide_wire::TX_TREE_REGULAR;
        let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut result = Vec::new();
        for i in 0..tx.tx_out.len() as u32 {
            let Some(redeemer) = outpoints.get(&(tx_hash.0, i, tree)) else {
                continue;
            };

            // Skip previously seen redeemers.
            if !seen.insert(redeemer.tx_hash.0) {
                continue;
            }
            result.push(redeemer.clone());
        }
        result
    }

    /// Whether the transaction exists in the main, orphan, or stage
    /// pools (dcrd `haveTransaction`).
    pub fn have_transaction(&self, hash: &Hash) -> bool {
        self.is_transaction_in_pool(hash)
            || self.is_orphan_in_pool(hash)
            || self.is_transaction_staged(hash)
    }

    /// Per-hash existence over the main, orphan, and stage pools (dcrd
    /// `HaveTransactions`).
    pub fn have_transactions(&self, hashes: &[Hash]) -> Vec<bool> {
        hashes.iter().map(|h| self.have_transaction(h)).collect()
    }

    /// Whether all of the passed transaction hashes exist in the main
    /// pool (dcrd `HaveAllTransactions`).
    pub fn have_all_transactions(&self, hashes: &[Hash]) -> bool {
        hashes.iter().all(|h| self.pool.contains_key(&h.0))
    }

    /// Remove the transaction and, when requested, all transactions
    /// that redeem its outputs (dcrd `removeTransaction`).
    pub fn remove_transaction(&mut self, tx: &MsgTx, tx_hash: &Hash, remove_redeemers: bool) {
        if remove_redeemers {
            // Remove any transactions which rely on this one.
            let tx_type = dcroxide_stake::determine_tx_type(tx);
            let tree = tree_for_type(tx_type);
            for i in 0..tx.tx_out.len() as u32 {
                let key = (tx_hash.0, i, tree);
                if let Some(redeemer) = self.outpoints.get(&key).cloned() {
                    self.remove_transaction(&redeemer.tx.clone(), &redeemer.tx_hash.clone(), true);
                    continue;
                }
                if let Some(redeemer) = self.staged_outpoints.get(&key).cloned() {
                    self.remove_staged_transaction(&redeemer);
                }
            }
        }

        // Remove the transaction if needed.
        if let Some(tx_desc) = self.pool.remove(&tx_hash.0) {
            // Mark the referenced outpoints as unspent by the pool.
            for tx_in in &tx_desc.tx.tx_in {
                self.outpoints.remove(&out_key(&tx_in.previous_out_point));
            }

            // Stop tracking this transaction in the mining view.  If
            // redeeming transactions are going to be removed from the
            // graph, then do not update their stats.
            let update_descendant_stats = !remove_redeemers;
            self.mining_view
                .remove_transaction(tx_hash, update_descendant_stats);

            self.last_updated_unix = self.chain.now_unix();

            // Stop tracking if it's a tspend.
            self.tspends.remove(&tx_hash.0);
        }
    }

    /// Remove all transactions which spend outputs spent by the passed
    /// transaction, recursively (dcrd `RemoveDoubleSpends`).
    pub fn remove_double_spends(&mut self, tx: &MsgTx, tx_hash: &Hash) {
        for tx_in in &tx.tx_in {
            let key = out_key(&tx_in.previous_out_point);
            if let Some(redeemer) = self.outpoints.get(&key).cloned() {
                if redeemer.tx_hash != *tx_hash {
                    self.remove_transaction(&redeemer.tx.clone(), &redeemer.tx_hash.clone(), true);
                }
            }
            if let Some(redeemer) = self.staged_outpoints.get(&key).cloned() {
                if redeemer.tx_hash != *tx_hash {
                    self.remove_staged_transaction(&redeemer);
                }
            }
        }
    }

    /// Add the passed transaction to the memory pool without
    /// validation (dcrd `addTransaction`; the mining view, exists
    /// address index, and fee estimation hooks are not reproduced).
    fn add_transaction(&mut self, tx_desc: Rc<TxDesc>) {
        // Add the transaction to the pool and mark the referenced
        // outpoints as spent by the pool.  The mining view is updated
        // between the two, matching dcrd's call order, so the
        // redeemer scan sees only previously tracked outpoints.
        self.pool.insert(tx_desc.tx_hash.0, tx_desc.clone());
        let pool = &self.pool;
        let outpoints = &self.outpoints;
        self.mining_view
            .add_transaction(&tx_desc, &|hash| pool.get(&hash.0).cloned(), &|tx, f| {
                let tree = dcroxide_wire::TX_TREE_REGULAR;
                for i in 0..tx.tx.tx_out.len() as u32 {
                    if let Some(redeemer) = outpoints.get(&(tx.tx_hash.0, i, tree)) {
                        f(redeemer.clone());
                    }
                }
            });
        for tx_in in &tx_desc.tx.tx_in {
            self.outpoints
                .insert(out_key(&tx_in.previous_out_point), tx_desc.clone());
        }
        self.last_updated_unix = self.chain.now_unix();
    }

    /// Whether the transaction attempts to spend coins already spent
    /// by transactions in the pool (dcrd `checkPoolDoubleSpend`).
    fn check_pool_double_spend(
        &self,
        tx: &MsgTx,
        tx_type: TxType,
        is_treasury_enabled: bool,
    ) -> Result<(), RuleError> {
        for (i, tx_in) in tx.tx_in.iter().enumerate() {
            // We don't care about double spends of stake bases.
            if i == 0 && (tx_type == TxType::SSGen || tx_type == TxType::SSRtx) {
                continue;
            }

            // Ignore treasury bases.
            if is_treasury_enabled
                && i == 0
                && (tx_type == TxType::TreasuryBase || tx_type == TxType::TSpend)
            {
                continue;
            }

            let key = out_key(&tx_in.previous_out_point);
            if let Some(desc) = self.outpoints.get(&key) {
                let str = format!(
                    "transaction {} in the pool already spends the same coins",
                    desc.tx_hash
                );
                return Err(tx_rule_error(ErrorKind::MempoolDoubleSpend, str));
            }
            if let Some(desc) = self.staged_outpoints.get(&key) {
                let str = format!(
                    "transaction {} in the stage pool already spends the same coins",
                    desc.tx_hash
                );
                return Err(tx_rule_error(ErrorKind::MempoolDoubleSpend, str));
            }
        }
        Ok(())
    }

    /// Whether the vote is for a block that already has a pool vote
    /// spending the same ticket (dcrd `checkVoteDoubleSpend`).
    fn check_vote_double_spend(&self, vote: &MsgTx, vote_hash: &Hash) -> Result<(), RuleError> {
        let ticket_spent = vote.tx_in[1].previous_out_point.hash;
        let (hash_voted_on, height_voted_on) = dcroxide_stake::ssgen_block_voted_on(vote);
        for existing in self.votes.get(&hash_voted_on.0).into_iter().flatten() {
            if existing.ticket_hash == ticket_spent {
                // Ensure the vote is still actually in the mempool
                // since the votes map is not kept in sync with the
                // contents of the pool.
                if !self.pool.contains_key(&existing.vote_hash.0) {
                    continue;
                }

                let str = format!(
                    "vote {vote_hash} spending ticket {ticket_spent} already votes \
                     on block {hash_voted_on} (height {height_voted_on})"
                );
                return Err(tx_rule_error(ErrorKind::AlreadyVoted, str));
            }
        }
        Ok(())
    }

    /// Whether the regular tree of the block with the provided hash is
    /// known to be disapproved by the pool's votes (dcrd
    /// `IsRegTxTreeKnownDisapproved`).
    pub fn is_reg_tx_tree_known_disapproved(&self, hash: &Hash) -> bool {
        let empty = Vec::new();
        let vts = self.votes.get(&hash.0).unwrap_or(&empty);

        // There are not possibly enough votes to tell if the regular
        // transaction tree is approved or not, so assume it's valid.
        if vts.len() <= usize::from(self.params.tickets_per_block / 2) {
            return false;
        }

        // Otherwise, tally the votes and determine if it's approved or
        // not.
        let mut yes = 0usize;
        let mut no = 0usize;
        for vote in vts {
            if vote.approves_parent {
                yes += 1;
            } else {
                no += 1;
            }
        }
        yes <= no
    }

    /// Load utxo details for the inputs of the passed transaction from
    /// the main chain and adjust them with the contents of the pool
    /// (dcrd `fetchInputUtxos`).
    fn fetch_input_utxos(
        &self,
        tx: &MsgTx,
        tx_hash: &Hash,
        tree: i8,
        is_treasury_enabled: bool,
    ) -> Result<UtxoView, PoolError> {
        let known_disapproved = self.is_reg_tx_tree_known_disapproved(&self.chain.best_hash());
        let mut view = self
            .chain
            .fetch_utxo_view(tx, tx_hash, tree, !known_disapproved)
            .map_err(PoolError::Other)?;

        // Attempt to populate any missing inputs from the transaction
        // pool.
        for tx_in in &tx.tx_in {
            let prev_out = &tx_in.previous_out_point;
            if view.lookup_entry(prev_out).is_some_and(|e| !e.is_spent()) {
                continue;
            }

            if let Some(pool_desc) = self.pool.get(&prev_out.hash.0) {
                view.add_tx_out(
                    &pool_desc.tx,
                    prev_out.index,
                    UNMINED_HEIGHT,
                    NULL_BLOCK_INDEX,
                    is_treasury_enabled,
                );
            }

            if let Some(staged_desc) = self.staged.get(&prev_out.hash.0) {
                view.add_tx_out(
                    &staged_desc.tx,
                    prev_out.index,
                    UNMINED_HEIGHT,
                    NULL_BLOCK_INDEX,
                    is_treasury_enabled,
                );
            }

            if let Some(transient_tx) = self.transient.get(&prev_out.hash.0) {
                view.add_tx_out(
                    transient_tx,
                    prev_out.index,
                    UNMINED_HEIGHT,
                    NULL_BLOCK_INDEX,
                    is_treasury_enabled,
                );
            }
        }

        Ok(view)
    }

    /// Whether the outpoint is spent by any transaction in the main or
    /// stage pools (dcrd `IsSpent`).
    pub fn is_spent(&self, outpoint: &OutPoint) -> bool {
        let key = out_key(outpoint);
        self.outpoints.contains_key(&key) || self.staged_outpoints.contains_key(&key)
    }

    /// The requested transaction from the main or stage pools,
    /// excluding orphans (dcrd `FetchTransaction`).
    pub fn fetch_transaction(&self, tx_hash: &Hash) -> Option<MsgTx> {
        self.pool
            .get(&tx_hash.0)
            .or_else(|| self.staged.get(&tx_hash.0))
            .map(|desc| desc.tx.clone())
    }

    /// Attempt to bring a staged transaction into the main pool (dcrd
    /// `maybeUnstageTransaction`).
    fn maybe_unstage_transaction(
        &mut self,
        tx_desc: Rc<TxDesc>,
        is_treasury_enabled: bool,
    ) -> Result<(), PoolError> {
        if tx_desc.tx_type == TxType::SStx && !self.has_mempool_input(&tx_desc.tx) {
            // Remove the dependent transaction and attempt to add it
            // to the main pool.  In the event of an error, the
            // transaction will be discarded.
            self.remove_staged_transaction(&tx_desc);
            self.fetch_input_utxos(
                &tx_desc.tx,
                &tx_desc.tx_hash,
                tx_desc.tree,
                is_treasury_enabled,
            )?;
            self.add_transaction(tx_desc);
        }
        Ok(())
    }

    /// Accept any staged dependents of the passed transaction to the
    /// mempool, returning those added (dcrd `MaybeAcceptDependents`).
    pub fn maybe_accept_dependents(
        &mut self,
        tx: &MsgTx,
        tx_hash: &Hash,
        is_treasury_enabled: bool,
    ) -> Vec<Hash> {
        let mut accepted = Vec::new();
        for redeemer in Self::collect_redeemers(&self.staged_outpoints, tx, tx_hash) {
            let redeemer_hash = redeemer.tx_hash;
            let _ = self.maybe_unstage_transaction(redeemer, is_treasury_enabled);
            if self.is_transaction_in_pool(&redeemer_hash) {
                accepted.push(redeemer_hash);
            }
        }
        accepted
    }

    /// The flags to use when checking transactions based on the active
    /// agendas (dcrd `determineCheckTxFlags`).
    pub fn determine_check_tx_flags(&self) -> Result<AgendaFlags, PoolError> {
        let is_treasury_enabled = self
            .chain
            .is_treasury_agenda_active()
            .map_err(PoolError::Other)?;
        let is_auto_revocations_enabled = self
            .chain
            .is_auto_revocations_agenda_active()
            .map_err(PoolError::Other)?;
        let is_subsidy_split_enabled = self
            .chain
            .is_subsidy_split_agenda_active()
            .map_err(PoolError::Other)?;
        let is_subsidy_split_r2_enabled = self
            .chain
            .is_subsidy_split_r2_agenda_active()
            .map_err(PoolError::Other)?;

        // Note that explicit version upgrades are always enforced by
        // policy.
        let mut flags = AgendaFlags::EXPLICIT_VER_UPGRADES.0;
        if is_treasury_enabled {
            flags |= AgendaFlags::TREASURY_ENABLED.0;
        }
        if is_auto_revocations_enabled {
            flags |= AgendaFlags::AUTO_REVOCATIONS_ENABLED.0;
        }
        if is_subsidy_split_enabled {
            flags |= AgendaFlags::SUBSIDY_SPLIT_ENABLED.0;
        }
        if is_subsidy_split_r2_enabled {
            flags |= AgendaFlags::SUBSIDY_SPLIT_R2_ENABLED.0;
        }
        Ok(AgendaFlags(flags))
    }

    /// The internal acceptance gauntlet (dcrd
    /// `maybeAcceptTransaction`): returns the missing parents when the
    /// transaction is an orphan.
    fn maybe_accept_transaction(
        &mut self,
        tx: &MsgTx,
        is_new: bool,
        allow_high_fees: bool,
        reject_dup_orphans: bool,
        check_tx_flags: AgendaFlags,
    ) -> Result<Vec<OutPoint>, PoolError> {
        let mut tx = tx.clone();
        let tx_hash = tx.tx_hash();

        // Don't accept the transaction if it already exists in the
        // pool.  This applies to orphan transactions as well when the
        // reject duplicate orphans flag is set.
        if self.is_transaction_in_pool(&tx_hash)
            || self.is_transaction_staged(&tx_hash)
            || (reject_dup_orphans && self.is_orphan_in_pool(&tx_hash))
        {
            let str = format!("already have transaction {tx_hash}");
            return Err(tx_rule_error(ErrorKind::Duplicate, str).into());
        }

        // Perform preliminary validation checks on the transaction
        // using the invariant rules from the chain.
        check_transaction(&tx, self.params, check_tx_flags)
            .map_err(|e| PoolError::Rule(chain_rule_error(e)))?;

        // Determine active agendas based on flags.
        let is_treasury_enabled = check_tx_flags.is_treasury_enabled();
        let is_auto_revocations_enabled = check_tx_flags.is_auto_revocations_enabled();
        let is_subsidy_enabled = check_tx_flags.is_subsidy_split_enabled();
        let is_subsidy_r2_enabled = check_tx_flags.is_subsidy_split_r2_enabled();

        // Determine which subsidy split variant to use depending on
        // the active agendas.
        let subsidy_split_variant = if is_subsidy_r2_enabled {
            SubsidySplitVariant::Dcp0012
        } else if is_subsidy_enabled {
            SubsidySplitVariant::Dcp0010
        } else {
            SubsidySplitVariant::Original
        };

        // Determine the type of transaction and its tree.
        let tx_type = dcroxide_stake::determine_tx_type(&tx);
        let tree = tree_for_type(tx_type);

        // A standalone transaction must not be a treasurybase
        // transaction.
        if is_treasury_enabled && tx_type == TxType::TreasuryBase {
            let str = format!("transaction {tx_hash} is an individual treasurybase");
            return Err(tx_rule_error(ErrorKind::Treasurybase, str).into());
        }

        // A standalone transaction must not be a coinbase transaction.
        if dcroxide_standalone::is_coin_base_tx(&tx, is_treasury_enabled) {
            let str = format!("transaction {tx_hash} is an individual coinbase");
            return Err(tx_rule_error(ErrorKind::Coinbase, str).into());
        }

        // A standalone transaction will be mined into the next block
        // at best, so its height is at least one more than the current
        // height.
        let best_height = self.chain.best_height();
        let next_block_height = best_height + 1;

        // Don't accept transactions that will be expired as of the
        // next block.
        if is_expired_tx(&tx, next_block_height) {
            let str = format!("transaction {tx_hash} expired at height {}", tx.expiry);
            return Err(tx_rule_error(ErrorKind::Expired, str).into());
        }

        // Reject votes and treasury spends before stake validation
        // height.
        let is_vote = tx_type == TxType::SSGen;
        let is_tspend = is_treasury_enabled && tx_type == TxType::TSpend;
        let stake_validation_height = self.params.stake_validation_height;
        if (is_vote || is_tspend) && next_block_height < stake_validation_height {
            let str_type = if is_tspend {
                "treasury spends"
            } else {
                "votes"
            };
            let str = format!(
                "{str_type} are not valid until block height {stake_validation_height} \
                 (next block height {next_block_height})"
            );
            return Err(tx_rule_error(ErrorKind::Invalid, str).into());
        }

        // Reject revocations before they can possibly be valid.
        let is_revocation = tx_type == TxType::SSRtx;
        if is_revocation && next_block_height < stake_validation_height + 1 {
            let str = format!(
                "revocations are not valid until block height {} (next block \
                 height {next_block_height})",
                stake_validation_height + 1
            );
            return Err(tx_rule_error(ErrorKind::Invalid, str).into());
        }

        // Don't allow non-standard transactions if the mempool config
        // forbids their acceptance and relaying.
        let median_time = self.chain.past_median_time();
        if !self.policy.accept_non_std {
            if let Err(err) = check_transaction_standard(
                &tx,
                tx_type,
                next_block_height,
                median_time,
                self.policy.min_relay_tx_fee,
            ) {
                let str = format!("transaction {tx_hash} is not standard: {}", err.description);
                return Err(wrap_tx_rule_error(ErrorKind::NonStandard, str, &err).into());
            }
        }

        // If the transaction is a ticket, ensure that it meets the
        // next stake difficulty.
        let is_ticket = tx_type == TxType::SStx;
        if is_ticket {
            let sdiff = self
                .chain
                .next_stake_difficulty()
                .map_err(PoolError::Other)?;
            if tx.tx_out[0].value < sdiff {
                let str = format!(
                    "transaction {tx_hash} has not enough funds to meet stake \
                     difficulty (ticket diff {} < next diff {sdiff})",
                    tx.tx_out[0].value
                );
                return Err(tx_rule_error(ErrorKind::InsufficientFee, str).into());
            }
        }

        // Aside from a few exceptions for votes and revocations, the
        // transaction may not use any of the same outputs as other
        // transactions already in the pool.
        if !is_vote && !is_revocation {
            self.check_pool_double_spend(&tx, tx_type, is_treasury_enabled)?;
        } else if is_vote {
            // Reject votes on blocks that already have a vote that
            // spends the same ticket available.
            self.check_vote_double_spend(&tx, &tx_hash)?;

            let mut vote_already_found = 0usize;
            for pool_desc in self.pool.values() {
                if pool_desc.tx_type == TxType::SSGen
                    && pool_desc.tx.tx_in[1].previous_out_point == tx.tx_in[1].previous_out_point
                {
                    vote_already_found += 1;
                }
                if vote_already_found >= MAX_VOTE_DOUBLE_SPENDS {
                    let str = format!(
                        "transaction {:?} in the pool with more than \
                         {MAX_VOTE_DOUBLE_SPENDS} votes",
                        tx.tx_in[1].previous_out_point
                    );
                    return Err(tx_rule_error(ErrorKind::TooManyVotes, str).into());
                }
            }
        } else if is_revocation {
            for pool_desc in self.pool.values() {
                if pool_desc.tx_type == TxType::SSRtx
                    && pool_desc.tx.tx_in[0].previous_out_point == tx.tx_in[0].previous_out_point
                {
                    let str = format!(
                        "transaction {:?} in the pool as a revocation. Only one \
                         revocation is allowed.",
                        tx.tx_in[0].previous_out_point
                    );
                    return Err(tx_rule_error(ErrorKind::DuplicateRevocation, str).into());
                }
            }
        }

        // Votes that are on too old of blocks are rejected.
        if is_vote {
            let (_, vote_height) = dcroxide_stake::ssgen_block_voted_on(&tx);
            if i64::from(vote_height) < next_block_height - i64::from(self.policy.max_vote_age)
                && !self.policy.allow_old_votes
            {
                let str = format!(
                    "transaction {tx_hash} votes on old block height of {vote_height} \
                     which is before the current cutoff height of {}",
                    next_block_height - i64::from(self.policy.max_vote_age)
                );
                return Err(tx_rule_error(ErrorKind::OldVote, str).into());
            }
        }

        // Fetch all of the unspent transaction outputs referenced by
        // the inputs to this transaction along with the transaction
        // itself for duplicate detection.
        let mut utxo_view = self.fetch_input_utxos(&tx, &tx_hash, tree, is_treasury_enabled)?;

        // Don't allow the transaction if it exists in the main chain
        // and is not already fully spent.
        for tx_out_idx in 0..tx.tx_out.len() as u32 {
            let outpoint = OutPoint {
                hash: tx_hash,
                index: tx_out_idx,
                tree,
            };
            if utxo_view
                .lookup_entry(&outpoint)
                .is_some_and(|e| !e.is_spent())
            {
                return Err(
                    tx_rule_error(ErrorKind::AlreadyExists, "transaction already exists").into(),
                );
            }
            utxo_view.remove_entry(&outpoint);
        }

        // Transaction is an orphan if any of the referenced
        // transaction outputs don't exist or are already spent.
        let mut missing_parents: Vec<OutPoint> = Vec::new();
        let mut update_fraud_proof = false;
        for (i, tx_in) in tx.tx_in.iter().enumerate() {
            if (i == 0 && is_vote) || is_tspend {
                continue;
            }

            match utxo_view
                .lookup_entry(&tx_in.previous_out_point)
                .filter(|e| !e.is_spent())
            {
                None => {
                    missing_parents.push(tx_in.previous_out_point);
                }
                Some(entry) => {
                    // Check the fraud proof data.  If anything does not
                    // match, flag the update.
                    if i64::from(tx_in.block_height) != entry.block_height()
                        || tx_in.block_index != entry.block_index()
                        || tx_in.value_in != entry.amount()
                    {
                        update_fraud_proof = true;
                    }
                }
            }
        }

        if !missing_parents.is_empty() {
            return Ok(missing_parents);
        }

        // Update the fraud proof data on the transaction inputs as
        // necessary so it is correct when relaying the transaction.
        if update_fraud_proof {
            for (i, tx_in) in tx.tx_in.iter_mut().enumerate() {
                // Skip stakebase inputs and treasury spends.
                if (i == 0 && is_vote) || is_tspend {
                    continue;
                }

                let Some(entry) = utxo_view
                    .lookup_entry(&tx_in.previous_out_point)
                    .filter(|e| !e.is_spent())
                else {
                    continue;
                };

                // Set the fraud proof data on the transaction input.
                tx_in.value_in = entry.amount();
                tx_in.block_height = entry.block_height() as u32;
                tx_in.block_index = entry.block_index();
            }
        }

        // Don't allow the transaction into the mempool unless its
        // sequence lock is active.  Sequence locks do not apply to
        // votes or treasury spends since they do not involve spending
        // normal utxos.
        let check_seq_locks = !is_vote && !is_tspend;
        if check_seq_locks {
            let seq_lock = self.chain.calc_sequence_lock(&tx, &tx_hash, &utxo_view)?;
            if !sequence_lock_active(&seq_lock, next_block_height, median_time) {
                let str = "transaction sequence locks on inputs not met";
                return Err(tx_rule_error(ErrorKind::SeqLockUnmet, str).into());
            }
        }

        // Perform several checks on the transaction inputs using the
        // invariant rules from the chain.  Also returns the fees
        // associated with the transaction.
        let best_hash = self.chain.best_hash();
        let best_header = self
            .chain
            .header_by_hash(&best_hash)
            .map_err(PoolError::Other)?;
        let tx_fee = check_transaction_inputs(
            &mut self.subsidy_cache,
            &tx,
            next_block_height,
            |op| utxo_view.lookup_entry(op).cloned(),
            true,
            self.params,
            &best_header,
            is_treasury_enabled,
            is_auto_revocations_enabled,
            subsidy_split_variant,
        )
        .map_err(|e| PoolError::Rule(chain_rule_error(e)))?;

        // Don't allow transactions with non-standard inputs if the
        // mempool config forbids their acceptance and relaying.
        if !self.policy.accept_non_std {
            if let Err(err) = check_inputs_standard(
                &tx,
                tx_type,
                |op| {
                    utxo_view
                        .lookup_entry(op)
                        .map(|e| (e.script_version(), e.pk_script().to_vec()))
                },
                is_treasury_enabled,
            ) {
                let str = format!(
                    "transaction {tx_hash} has a non-standard input: {}",
                    err.description
                );
                return Err(wrap_tx_rule_error(ErrorKind::NonStandard, str, &err).into());
            }
        }

        // Don't allow transactions with an excessive number of
        // signature operations which would result in making it
        // impossible to mine.
        let num_p2sh_sig_ops = count_p2sh_sig_ops(
            &tx,
            false,
            tx_type == TxType::SSGen,
            |op| utxo_view.lookup_entry(op).cloned(),
            is_treasury_enabled,
        )
        .map_err(|e| PoolError::Rule(chain_rule_error(e)))?;

        let num_sig_ops = count_sig_ops(&tx, false, is_vote, is_treasury_enabled);
        let total_sig_ops = num_p2sh_sig_ops + num_sig_ops;
        if total_sig_ops > self.policy.max_sig_ops_per_tx {
            let str = format!(
                "transaction {tx_hash} has too many sigops: {total_sig_ops} > {}",
                self.policy.max_sig_ops_per_tx
            );
            return Err(tx_rule_error(ErrorKind::NonStandard, str).into());
        }

        // Don't allow transactions with fees too low to get into a
        // mined block.  This only applies to regular transactions,
        // ticket purchases, treasury spends, and treasury adds; the
        // types integral to block production are required to be
        // feeless.
        let is_treasury_add = is_treasury_enabled && tx_type == TxType::TAdd;
        let serialized_size = tx.serialize_size() as i64;
        let min_fee = calc_min_required_tx_relay_fee(serialized_size, self.policy.min_relay_tx_fee);
        if tx_fee < min_fee
            && (tx_type == TxType::Regular || is_ticket || is_treasury_add || is_tspend)
        {
            let tx_type_str = match () {
                _ if tx_type == TxType::Regular => "regular ",
                _ if is_ticket => "ticket purchase ",
                _ if is_treasury_add => "treasury add ",
                _ if is_tspend => "treasury spend ",
                _ => "",
            };
            let str = format!(
                "{tx_type_str}transaction {tx_hash} pays a fee of {tx_fee} atoms \
                 which is under the required fee of {min_fee} atoms for a \
                 {serialized_size}-byte transaction"
            );
            return Err(tx_rule_error(ErrorKind::InsufficientFee, str).into());
        }

        // Make sure the current fee is sensible unless high fees are
        // explicitly allowed.
        if !allow_high_fees {
            let max_fee = calc_min_required_tx_relay_fee(
                serialized_size.wrapping_mul(MAX_RELAY_FEE_MULTIPLIER),
                self.policy.min_relay_tx_fee,
            );
            if tx_fee > max_fee {
                let str = format!(
                    "transaction {tx_hash} has {tx_fee} fee which is above the \
                     allowHighFee check threshold amount of {max_fee}"
                );
                return Err(tx_rule_error(ErrorKind::FeeTooHigh, str).into());
            }
        }

        // Verify crypto signatures for each input and reject the
        // transaction if any don't verify.
        let flags = self
            .chain
            .standard_verify_flags()
            .map_err(PoolError::Other)?;
        validate_transaction_scripts(
            &tx,
            |op| utxo_view.lookup_entry(op).cloned(),
            flags,
            is_auto_revocations_enabled,
        )
        .map_err(|e| PoolError::Rule(chain_rule_error(e)))?;

        // Only allow treasury spends that have a valid expiry.
        if is_treasury_enabled && is_tspend {
            self.check_tspend_policy(&tx, &tx_hash, next_block_height)?;
        }

        let tx_desc = Rc::new(TxDesc {
            tx: tx.clone(),
            tx_hash,
            tree,
            tx_type,
            added_unix: self.chain.now_unix(),
            height: best_height,
            fee: tx_fee,
            total_sig_ops,
            tx_size: serialized_size,
        });

        // Tickets cannot be included in a block until all inputs have
        // been approved by stakeholders, so tickets with mempool
        // inputs are placed in a separate stage pool.
        if tx_type == TxType::SStx && self.has_mempool_input(&tx) {
            self.stage_transaction(tx_desc);
            return Ok(Vec::new());
        }

        // Add to transaction pool.
        self.add_transaction(tx_desc);

        // A regular transaction entering the mempool causes mempool
        // tickets that redeem it to move to the stage pool.
        if !is_new && tx_type == TxType::Regular {
            for redeemer in Self::collect_redeemers(&self.outpoints, &tx, &tx_hash) {
                if redeemer.tx_type == TxType::SStx {
                    self.remove_transaction(&redeemer.tx.clone(), &redeemer.tx_hash.clone(), true);
                    self.stage_transaction(redeemer);
                }
            }
        }

        // Keep track of votes separately.
        if is_vote {
            self.insert_vote(&tx, &tx_hash);
        }

        // Keep track of tspends separately.
        if is_tspend {
            self.tspends.insert(tx_hash.0);
        }

        Ok(Vec::new())
    }

    /// The treasury spend policy checks from the tail of dcrd's
    /// `maybeAcceptTransaction`: expiry sanity, the concurrent tspend
    /// limit, the Pi key signature, and the mined-on-ancestor check.
    fn check_tspend_policy(
        &self,
        tx: &MsgTx,
        tx_hash: &Hash,
        next_block_height: i64,
    ) -> Result<(), PoolError> {
        let tvi = self.params.treasury_vote_interval;
        let mul = self.params.treasury_vote_interval_multiplier;

        // Ensure the tspend expiry isn't too far in the future, before
        // its voting is supposed to start: the vote starting greater
        // than or equal to two full voting windows in the future.
        let vote_start = match dcroxide_standalone::calc_tspend_window(tx.expiry, tvi, mul) {
            Ok((vote_start, _)) => vote_start,
            Err(err) => {
                let str = format!("Invalid tspend expiry {}: {err:?} ", tx.expiry);
                return Err(tx_rule_error(ErrorKind::TSpendInvalidExpiry, str).into());
            }
        };
        let vote_start_thresh = (2 * tvi * mul) as i64;
        let blocks_to_vote_start = i64::from(vote_start) - next_block_height;
        let vote_start_distant_future =
            i64::from(vote_start) > next_block_height && blocks_to_vote_start >= vote_start_thresh;
        if vote_start_distant_future {
            let str = format!(
                "Tspend voting too far in the future: voting starts in \
                 {blocks_to_vote_start} blocks while the voting threshold is \
                 {vote_start_thresh} blocks"
            );
            return Err(tx_rule_error(ErrorKind::TSpendInvalidExpiry, str).into());
        }

        // Only allow up to the maximum number of concurrent tspends in
        // the mempool.
        if self.tspends.len() >= MEMPOOL_MAX_CONCURRENT_TSPENDS {
            let str = format!(
                "Mempool can only hold {MEMPOOL_MAX_CONCURRENT_TSPENDS} concurrent \
                 TSpend transactions"
            );
            return Err(tx_rule_error(ErrorKind::TooManyTSpends, str).into());
        }

        // Verify that this tspend uses a well-known Pi key and that
        // the signature is valid.
        let (signature, pub_key) = match dcroxide_stake::check_tspend(tx) {
            Ok(parts) => parts,
            Err(err) => {
                let str = format!("Mempool invalid TSpend: {err:?}");
                return Err(tx_rule_error(ErrorKind::Invalid, str).into());
            }
        };
        if !self.params.pi_key_exists(&pub_key) {
            let str = format!("Unknown Pi Key: {}", hex_string(&pub_key));
            return Err(tx_rule_error(ErrorKind::Invalid, str).into());
        }
        if let Err(err) = verify_tspend_signature(tx, &signature, &pub_key) {
            let str = format!("Mempool invalid TSpend signature: {err}");
            return Err(tx_rule_error(ErrorKind::Invalid, str).into());
        }

        // Verify that this tspend hash has not been included in an
        // ancestor block yet.
        if let Err(err) = self.chain.tspend_mined_on_ancestor(tx_hash) {
            return Err(tx_rule_error(ErrorKind::TSpendMinedOnAncestor, err).into());
        }

        Ok(())
    }

    /// The public acceptance entry point (dcrd
    /// `MaybeAcceptTransaction`).
    pub fn maybe_accept_transaction_pub(
        &mut self,
        tx: &MsgTx,
        is_new: bool,
    ) -> Result<Vec<OutPoint>, PoolError> {
        let check_tx_flags = self.determine_check_tx_flags()?;
        self.maybe_accept_transaction(tx, is_new, true, true, check_tx_flags)
    }

    /// Handle the insertion of a set of not new transactions that may
    /// have dependencies within the set, provided in block order (dcrd
    /// `MaybeAcceptTransactions`; the errors dcrd folds into a
    /// `MultiError` are returned as a list).
    pub fn maybe_accept_transactions(&mut self, txns: &[MsgTx]) -> Vec<PoolError> {
        let check_tx_flags = match self.determine_check_tx_flags() {
            Ok(flags) => flags,
            Err(err) => return vec![err],
        };

        let hashes: Vec<Hash> = txns.iter().map(|tx| tx.tx_hash()).collect();
        for (tx, hash) in txns.iter().zip(&hashes).take(txns.len().saturating_sub(1)) {
            self.transient.insert(hash.0, tx.clone());
        }
        let mut errors = Vec::new();
        for (tx, hash) in txns.iter().zip(&hashes).rev() {
            self.transient.remove(&hash.0);
            if let Err(err) = self.maybe_accept_transaction(tx, false, true, true, check_tx_flags) {
                if !is_double_spend_or_duplicate_error(&err) {
                    self.remove_transaction(tx, hash, true);
                    continue;
                }
                errors.push(err);
            }
        }
        errors
    }

    /// Accept orphans that depended on the passed transaction,
    /// repeating for newly accepted transactions (dcrd
    /// `processOrphans`).
    fn process_orphans_internal(
        &mut self,
        accepted_tx: &MsgTx,
        accepted_hash: &Hash,
        check_tx_flags: AgendaFlags,
    ) -> Vec<Hash> {
        let mut accepted_txns: Vec<Hash> = Vec::new();
        let mut accepted_msgs: Vec<MsgTx> = Vec::new();

        // Start with processing at least the passed transaction.
        let mut process_list: Vec<(MsgTx, Hash)> = vec![(accepted_tx.clone(), *accepted_hash)];
        while let Some((process_item, process_hash)) = process_list.first().cloned() {
            process_list.remove(0);

            let tx_type = dcroxide_stake::determine_tx_type(&process_item);
            let tree = tree_for_type(tx_type);

            for tx_out_idx in 0..process_item.tx_out.len() as u32 {
                // Look up all orphans that redeem the output that is
                // now available.
                let key = (process_hash.0, tx_out_idx, tree);
                let orphans: Vec<(Hash, Rc<MsgTx>)> = self
                    .orphans_by_prev
                    .get(&key)
                    .map(|m| m.iter().map(|(k, v)| (Hash(*k), v.clone())).collect())
                    .unwrap_or_default();

                // Potentially accept an orphan into the tx pool.
                for (orphan_hash, orphan_tx) in orphans {
                    match self.maybe_accept_transaction(
                        &orphan_tx,
                        true,
                        true,
                        false,
                        check_tx_flags,
                    ) {
                        Err(_) => {
                            // The orphan is now invalid, so there is no
                            // way any other orphans which redeem any of
                            // its outputs can be accepted.  Remove
                            // them.
                            self.remove_orphan(&orphan_hash, true);
                            break;
                        }
                        Ok(missing) if !missing.is_empty() => {
                            // Transaction is still an orphan.  Try the
                            // next orphan which redeems this output.
                            continue;
                        }
                        Ok(_) => {
                            // Transaction was accepted into the main
                            // pool.  Add it to the accepted list,
                            // remove it from the orphan pool, and
                            // process any orphans that depend on it
                            // too.  Only one transaction for this
                            // outpoint can be accepted.
                            accepted_txns.push(orphan_hash);
                            accepted_msgs.push((*orphan_tx).clone());
                            self.remove_orphan(&orphan_hash, false);
                            process_list.push(((*orphan_tx).clone(), orphan_hash));
                            break;
                        }
                    }
                }
            }
        }

        // Recursively remove any orphans that also redeem any outputs
        // redeemed by the accepted transactions since those are now
        // definitive double spends.
        self.remove_orphan_double_spends(accepted_tx);
        for tx in &accepted_msgs {
            self.remove_orphan_double_spends(tx);
        }

        accepted_txns
    }

    /// The public orphan processing entry point (dcrd
    /// `ProcessOrphans`).
    pub fn process_orphans(
        &mut self,
        accepted_tx: &MsgTx,
        check_tx_flags: AgendaFlags,
    ) -> Vec<Hash> {
        let hash = accepted_tx.tx_hash();
        self.process_orphans_internal(accepted_tx, &hash, check_tx_flags)
    }

    /// The main workhorse for handling insertion of new free-standing
    /// transactions, returning the hashes accepted to the main pool
    /// with the passed transaction first (dcrd `ProcessTransaction`).
    pub fn process_transaction(
        &mut self,
        tx: &MsgTx,
        allow_orphan: bool,
        allow_high_fees: bool,
        tag: Tag,
    ) -> Result<Vec<Hash>, PoolError> {
        let check_tx_flags = self.determine_check_tx_flags()?;
        let tx_hash = tx.tx_hash();

        // Potentially accept the transaction to the memory pool.
        let missing_parents =
            self.maybe_accept_transaction(tx, true, allow_high_fees, true, check_tx_flags)?;

        if missing_parents.is_empty() {
            // Accept any orphan transactions that depend on this
            // transaction and repeat for those accepted transactions
            // until there are no more.
            let new_txs = self.process_orphans_internal(tx, &tx_hash, check_tx_flags);
            let mut accepted = Vec::with_capacity(new_txs.len() + 1);

            // Add the parent transaction first so remote nodes do not
            // add orphans.
            accepted.push(tx_hash);
            accepted.extend(new_txs);
            return Ok(accepted);
        }

        // The transaction is an orphan.  Reject it if the flag to
        // allow orphans is not set.
        if !allow_orphan {
            // Only use the first missing parent transaction in the
            // error message.
            let str = format!(
                "orphan transaction {tx_hash} references output {:?} of unknown \
                 or fully-spent transaction",
                missing_parents[0]
            );
            return Err(tx_rule_error(ErrorKind::Orphan, str).into());
        }

        // Potentially add the orphan transaction to the orphan pool.
        self.maybe_add_orphan(tx, &tx_hash, tag)?;
        Ok(Vec::new())
    }

    /// Prune tickets, votes, and revocations that can no longer be
    /// mined (dcrd `pruneStakeTx`).
    fn prune_stake_tx_internal(
        &mut self,
        required_stake_difficulty: i64,
        height: i64,
        is_auto_revocations_enabled: bool,
    ) {
        let pool_descs: Vec<Rc<TxDesc>> = self.pool.values().cloned().collect();
        for tx_desc in pool_descs {
            let tx_type = tx_desc.tx_type;
            if tx_type == TxType::SStx && tx_desc.height + HEIGHT_DIFF_TO_PRUNE_TICKET < height {
                self.remove_transaction(&tx_desc.tx.clone(), &tx_desc.tx_hash.clone(), true);
                continue;
            }
            if tx_type == TxType::SStx && tx_desc.tx.tx_out[0].value < required_stake_difficulty {
                self.remove_transaction(&tx_desc.tx.clone(), &tx_desc.tx_hash.clone(), true);
                continue;
            }
            if (tx_type == TxType::SSRtx || tx_type == TxType::SSGen)
                && tx_desc.height + HEIGHT_DIFF_TO_PRUNE_VOTES < height
            {
                self.remove_transaction(&tx_desc.tx.clone(), &tx_desc.tx_hash.clone(), true);
                continue;
            }
            if is_auto_revocations_enabled && tx_type == TxType::SSRtx {
                // When the automatic ticket revocations agenda is
                // active, any revocations that remain in the mempool
                // are no longer valid after a new block.
                self.remove_transaction(&tx_desc.tx.clone(), &tx_desc.tx_hash.clone(), true);
                continue;
            }
        }
        let staged_descs: Vec<Rc<TxDesc>> = self.staged.values().cloned().collect();
        for tx_desc in staged_descs {
            let tx_type = tx_desc.tx_type;
            if tx_type == TxType::SStx && tx_desc.tx.tx_out[0].value < required_stake_difficulty {
                self.remove_staged_transaction(&tx_desc);
                continue;
            }
            if tx_type == TxType::SStx && tx_desc.height + HEIGHT_DIFF_TO_PRUNE_TICKET < height {
                self.remove_staged_transaction(&tx_desc);
                continue;
            }
            if is_auto_revocations_enabled && tx_type == TxType::SSRtx {
                self.remove_transaction(&tx_desc.tx.clone(), &tx_desc.tx_hash.clone(), true);
                continue;
            }
        }
    }

    /// The public stake pruning entry point, called on every new block
    /// (dcrd `PruneStakeTx`).
    pub fn prune_stake_tx(&mut self, required_stake_difficulty: i64, height: i64) {
        let Ok(is_auto_revocations_enabled) = self.chain.is_auto_revocations_agenda_active() else {
            return;
        };
        self.prune_stake_tx_internal(
            required_stake_difficulty,
            height,
            is_auto_revocations_enabled,
        );
    }

    /// Prune expired transactions from the main and stage pools (dcrd
    /// `PruneExpiredTx`); the height is the current best chain tip
    /// height.
    pub fn prune_expired_tx(&mut self, height: i64) {
        let next_block_height = height + 1;

        let pool_descs: Vec<Rc<TxDesc>> = self.pool.values().cloned().collect();
        for tx_desc in pool_descs {
            if is_expired_tx(&tx_desc.tx, next_block_height) {
                self.remove_transaction(&tx_desc.tx.clone(), &tx_desc.tx_hash.clone(), true);
            }
        }

        let staged_descs: Vec<Rc<TxDesc>> = self.staged.values().cloned().collect();
        for tx_desc in staged_descs {
            if is_expired_tx(&tx_desc.tx, next_block_height) {
                self.remove_staged_transaction(&tx_desc);
            }
        }
    }

    /// The number of transactions in the main pool (dcrd `Count`).
    pub fn count(&self) -> usize {
        self.pool.len()
    }

    /// The hashes of all transactions in the main pool (dcrd
    /// `TxHashes`).
    pub fn tx_hashes(&self) -> Vec<Hash> {
        self.pool.keys().map(|k| Hash(*k)).collect()
    }

    /// Descriptors for all transactions in the main pool (dcrd
    /// `TxDescs`).
    pub fn tx_descs(&self) -> Vec<Rc<TxDesc>> {
        self.pool.values().cloned().collect()
    }

    /// The hashes of all orphans in the orphan pool.
    pub fn orphan_hashes(&self) -> Vec<Hash> {
        self.orphans.keys().map(|k| Hash(*k)).collect()
    }

    /// The hashes of all transactions in the stage pool.
    pub fn staged_hashes(&self) -> Vec<Hash> {
        self.staged.keys().map(|k| Hash(*k)).collect()
    }

    /// Mining descriptors for all transactions in the pool (dcrd
    /// `miningDescs`).
    pub fn mining_descs(&self) -> Vec<Rc<TxDesc>> {
        self.pool.values().cloned().collect()
    }

    /// A snapshot of the pool's transactions and their relationships
    /// (dcrd `MiningView`, part of the mining `TxSource` contract).
    pub fn mining_view(&self) -> TxMiningView {
        let pool = &self.pool;
        self.mining_view
            .clone_view(self.mining_descs(), &|hash| pool.get(&hash.0).cloned())
    }

    /// The last time a transaction was added to or removed from the
    /// main pool, as unix seconds (dcrd `LastUpdated`).
    pub fn last_updated_unix(&self) -> i64 {
        self.last_updated_unix
    }
}

/// Whether the error indicates a transaction was rejected due to a
/// double spend or already existing (dcrd
/// `isDoubleSpendOrDuplicateError`).
fn is_double_spend_or_duplicate_error(err: &PoolError) -> bool {
    match err {
        PoolError::Rule(rule) => match &rule.err {
            crate::RuleErrorSource::Mempool(kind) => {
                matches!(kind, ErrorKind::Duplicate | ErrorKind::AlreadyExists)
            }
            crate::RuleErrorSource::Chain(chain_err) => {
                chain_err.kind == dcroxide_blockchain::RuleErrorKind::MissingTxOut
            }
        },
        PoolError::Other(_) => false,
    }
}

fn hex_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

impl<C: PoolChain> dcroxide_mining::TemplateTxSource for TxPool<'_, C> {
    fn mining_view(&self) -> dcroxide_mining::TxMiningView {
        TxPool::mining_view(self)
    }

    fn have_transaction(&self, hash: &Hash) -> bool {
        TxPool::have_transaction(self, hash)
    }

    fn have_all_transactions(&self, hashes: &[Hash]) -> bool {
        TxPool::have_all_transactions(self, hashes)
    }

    fn vote_hashes_for_block(&self, hash: &Hash) -> Vec<Hash> {
        TxPool::vote_hashes_for_block(self, hash)
    }

    fn votes_for_blocks(&self, hashes: &[Hash]) -> Vec<Vec<VoteDesc>> {
        TxPool::votes_for_blocks(self, hashes)
    }

    fn is_reg_tx_tree_known_disapproved(&self, hash: &Hash) -> bool {
        TxPool::is_reg_tx_tree_known_disapproved(self, hash)
    }
}
