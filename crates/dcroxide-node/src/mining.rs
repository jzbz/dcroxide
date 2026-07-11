// SPDX-License-Identifier: ISC
//! The daemon's block template seams: the [`NodeTemplateChain`]
//! adapter binding the ported template generator to the live chain
//! (dcrd `newServer` building its mining `Config` closures over
//! `s.chain`) and the [`NodeTemplateTxSource`] adapter serving the
//! shared mempool as the generator's transaction source (dcrd hands
//! the pool in as the config's `TxSource` directly).
//!
//! The background template generator thread and the
//! `getblocktemplate` serving arrive with later pieces; these
//! adapters give `BlkTmplGenerator` a real chain to build over.

use std::sync::{Arc, Mutex, MutexGuard};

use dcroxide_blockchain::UtxoEntry;
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_mempool::PoolSubsidyParams;
use dcroxide_mining::{TemplateBest, TemplateChain, TemplateTxSource, TxMiningView, VoteDesc};
use dcroxide_standalone::{SubsidyCache, SubsidySplitVariant};
use dcroxide_txscript::ScriptFlags;
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint};

use crate::txmempool::{NodeTxPool, chain_fetch_utxo_view, chain_standard_verify_flags, now_unix};

/// The chain backend for the template generator over the shared chain
/// (dcrd `newServer` building its mining `Config` chain closures over
/// `s.chain`).
pub struct NodeTemplateChain {
    chain: Arc<Mutex<Chain>>,
    params: Params,
    /// The subsidy cache the input checks consume (dcrd's config
    /// carries `s.subsidyCache`; the daemon seams each own one over
    /// the same params, which is result-identical).
    subsidy_cache: SubsidyCache<PoolSubsidyParams>,
}

impl NodeTemplateChain {
    /// Adapt the shared chain for the template generator.
    pub fn new(chain: Arc<Mutex<Chain>>, params: Params) -> NodeTemplateChain {
        let subsidy_cache = SubsidyCache::new(PoolSubsidyParams(params.clone()));
        NodeTemplateChain {
            chain,
            params,
            subsidy_cache,
        }
    }

    fn locked(&self) -> MutexGuard<'_, Chain> {
        self.chain.lock().expect("chain mutex poisoned")
    }
}

impl TemplateChain for NodeTemplateChain {
    fn best_snapshot(&self) -> TemplateBest {
        let chain = self.locked();
        let best = chain.best_snapshot();
        TemplateBest {
            hash: best.hash,
            prev_hash: best.prev_hash,
            height: best.height,
            median_time_unix: best.median_time,
            next_stake_diff: best.next_stake_diff,
            next_final_state: best.next_final_state,
            next_pool_size: best.next_pool_size,
            next_winning_tickets: best.next_winning_tickets.clone(),
            next_expiring_tickets: best.next_expiring_tickets.clone(),
            missed_tickets: best.missed_tickets.clone(),
        }
    }

    fn block_by_hash(&self, hash: &Hash) -> Result<MsgBlock, String> {
        self.locked()
            .block_by_hash(hash)
            .ok_or_else(|| format!("block {hash} is not known"))
    }

    fn calc_next_required_difficulty(
        &self,
        hash: &Hash,
        timestamp_unix: i64,
    ) -> Result<u32, String> {
        self.locked()
            .calc_next_required_difficulty_by_hash(hash, timestamp_unix, &self.params)
    }

    fn calc_stake_version_by_hash(&self, hash: &Hash) -> Result<u32, String> {
        self.locked().calc_stake_version_by_hash(hash, &self.params)
    }

    fn check_connect_block_template(&mut self, block: &MsgBlock) -> Result<(), String> {
        self.locked()
            .check_connect_block_template(block, now_unix(), &self.params)
            .map_err(|e| e.description)
    }

    fn check_ticket_exhaustion(&self, hash: &Hash, ticket_purchases: u8) -> Result<(), String> {
        self.locked()
            .check_ticket_exhaustion_by_hash(hash, ticket_purchases, &self.params)
            .map_err(|e| e.description)
    }

    /// Validate the transaction's inputs against the passed view,
    /// returning the fee (dcrd's config closure over
    /// `blockchain.CheckTransactionInputs`).
    #[allow(clippy::too_many_arguments)] // Mirrors the trait surface.
    fn check_transaction_inputs(
        &mut self,
        tx: &MsgTx,
        tx_height: i64,
        view: &UtxoView,
        check_fraud_proof: bool,
        prev_header: &BlockHeader,
        is_treasury_enabled: bool,
        is_auto_revocations_enabled: bool,
        subsidy_split_variant: SubsidySplitVariant,
    ) -> Result<i64, String> {
        dcroxide_blockchain::validate::check_transaction_inputs(
            &mut self.subsidy_cache,
            tx,
            tx_height,
            |op| view.lookup_entry(op).cloned(),
            check_fraud_proof,
            &self.params,
            prev_header,
            is_treasury_enabled,
            is_auto_revocations_enabled,
            subsidy_split_variant,
        )
        .map_err(|e| e.description)
    }

    fn check_tspend_has_votes(&self, prev_hash: &Hash, tspend: &MsgTx) -> Result<(), String> {
        let chain = self.locked();
        let prev_node = chain
            .index
            .lookup_node(prev_hash)
            .ok_or_else(|| format!("block {prev_hash} is not known"))?;
        chain.check_tspend_has_votes(prev_node, tspend, &self.params)
    }

    fn count_sig_ops(
        &self,
        tx: &MsgTx,
        is_coin_base_tx: bool,
        is_ssgen: bool,
        is_treasury_enabled: bool,
    ) -> i64 {
        dcroxide_blockchain::validate::count_sig_ops(
            tx,
            is_coin_base_tx,
            is_ssgen,
            is_treasury_enabled,
        )
    }

    fn fetch_utxo_entry(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>, String> {
        Ok(self.locked().fetch_utxo_entry(outpoint))
    }

    /// The unspent view for the transaction's inputs and its own
    /// outputs from the tip's point of view
    /// ([`chain_fetch_utxo_view`], the same `BlockChain.FetchUtxoView`
    /// dcrd wires into its mempool config).
    fn fetch_utxo_view(
        &self,
        tx: &MsgTx,
        tx_hash: &Hash,
        tree: i8,
        include_regular_txns: bool,
    ) -> Result<UtxoView, String> {
        chain_fetch_utxo_view(
            &self.locked(),
            &self.params,
            tx,
            tx_hash,
            tree,
            include_regular_txns,
        )
    }

    fn fetch_utxo_view_parent_template(&self, block: &MsgBlock) -> Result<UtxoView, String> {
        self.locked()
            .fetch_utxo_view_parent_template(block, &self.params)
    }

    fn force_head_reorganization(
        &mut self,
        former_best: Hash,
        new_best: Hash,
    ) -> Result<(), String> {
        let errs = self.locked().force_head_reorganization(
            former_best,
            new_best,
            now_unix(),
            &self.params,
        );
        match errs.into_iter().next() {
            None => Ok(()),
            Some(err) => Err(err.description),
        }
    }

    fn header_by_hash(&self, hash: &Hash) -> Result<BlockHeader, String> {
        self.locked()
            .header_by_hash(hash)
            .ok_or_else(|| format!("block {hash} is not known"))
    }

    fn is_finalized_transaction(
        &self,
        tx: &MsgTx,
        block_height: i64,
        block_time_unix: i64,
    ) -> bool {
        dcroxide_blockchain::validate::is_finalized_transaction(tx, block_height, block_time_unix)
    }

    fn is_header_commitments_agenda_active(&self, prev_hash: &Hash) -> Result<bool, String> {
        self.locked()
            .is_header_commitments_agenda_active(prev_hash, &self.params)
            .map_err(|e| e.description)
    }

    fn is_treasury_agenda_active(&self, prev_hash: &Hash) -> Result<bool, String> {
        self.locked()
            .is_treasury_agenda_active(prev_hash, &self.params)
            .map_err(|e| e.description)
    }

    fn is_auto_revocations_agenda_active(&self, prev_hash: &Hash) -> Result<bool, String> {
        self.locked()
            .is_auto_revocations_agenda_active(prev_hash, &self.params)
            .map_err(|e| e.description)
    }

    fn is_subsidy_split_agenda_active(&self, prev_hash: &Hash) -> Result<bool, String> {
        self.locked()
            .is_subsidy_split_agenda_active(prev_hash, &self.params)
            .map_err(|e| e.description)
    }

    fn is_subsidy_split_r2_agenda_active(&self, prev_hash: &Hash) -> Result<bool, String> {
        self.locked()
            .is_subsidy_split_r2_agenda_active(prev_hash, &self.params)
            .map_err(|e| e.description)
    }

    /// The maximum treasury expenditure for a block extending the
    /// given one (dcrd `BlockChain.MaxTreasuryExpenditure`): zero when
    /// the extending block is not on a treasury vote interval.
    fn max_treasury_expenditure(&self, prev_hash: &Hash) -> Result<i64, String> {
        let chain = self.locked();
        let pre_tvi_node = chain
            .index
            .lookup_node(prev_hash)
            .ok_or_else(|| format!("block {prev_hash} is not known"))?;
        let next_height = chain.store.node(pre_tvi_node).height.saturating_add(1);
        if !dcroxide_standalone::is_treasury_vote_interval(
            next_height as u64,
            self.params.treasury_vote_interval,
        ) {
            return Ok(0);
        }
        chain
            .max_treasury_expenditure(pre_tvi_node, &self.params)
            .map_err(|e| e.description)
    }

    fn tip_generation(&self) -> Vec<Hash> {
        self.locked().tip_generation()
    }

    fn validate_transaction_scripts(
        &self,
        tx: &MsgTx,
        view: &UtxoView,
        flags: ScriptFlags,
        is_auto_revocations_enabled: bool,
    ) -> Result<(), String> {
        dcroxide_blockchain::validate::validate_transaction_scripts(
            tx,
            |op| view.lookup_entry(op).cloned(),
            flags,
            is_auto_revocations_enabled,
        )
        .map_err(|e| e.description)
    }

    /// The script verification flags for the next block
    /// ([`chain_standard_verify_flags`], the same
    /// `standardScriptVerifyFlags` dcrd wires into its mempool
    /// config).
    fn standard_verify_flags(&self) -> Result<ScriptFlags, String> {
        chain_standard_verify_flags(&self.locked(), &self.params)
    }

    fn adjusted_time_unix(&self) -> i64 {
        now_unix()
    }
}

/// The transaction source for the template generator over the shared
/// pool (dcrd wires the pool itself as the mining config's
/// `TxSource`; the mutex stands in for the pool's internal locking).
pub struct NodeTemplateTxSource {
    pool: Arc<Mutex<NodeTxPool>>,
}

impl NodeTemplateTxSource {
    /// Adapt the shared pool for the template generator.
    pub fn new(pool: Arc<Mutex<NodeTxPool>>) -> NodeTemplateTxSource {
        NodeTemplateTxSource { pool }
    }

    fn locked(&self) -> MutexGuard<'_, NodeTxPool> {
        self.pool.lock().expect("tx pool mutex poisoned")
    }
}

impl TemplateTxSource for NodeTemplateTxSource {
    fn mining_view(&self) -> TxMiningView {
        self.locked().mining_view()
    }

    fn have_transaction(&self, hash: &Hash) -> bool {
        self.locked().have_transaction(hash)
    }

    fn have_all_transactions(&self, hashes: &[Hash]) -> bool {
        self.locked().have_all_transactions(hashes)
    }

    fn vote_hashes_for_block(&self, hash: &Hash) -> Vec<Hash> {
        self.locked().vote_hashes_for_block(hash)
    }

    fn votes_for_blocks(&self, hashes: &[Hash]) -> Vec<Vec<VoteDesc>> {
        self.locked().votes_for_blocks(hashes)
    }

    fn is_reg_tx_tree_known_disapproved(&self, hash: &Hash) -> bool {
        self.locked().is_reg_tx_tree_known_disapproved(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The background template generator thread moves these seams
    /// across a thread boundary.
    #[test]
    fn template_seams_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<NodeTemplateChain>();
        assert_send::<NodeTemplateTxSource>();
    }
}
