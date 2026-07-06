// SPDX-License-Identifier: ISC

//! The block template generator (dcrd `BlkTmplGenerator` and
//! `NewBlockTemplate` from `mining.go`): the complete template
//! assembly over the transaction source's mining view — parent
//! selection by votes with forced reorganization, priority queue
//! mining with ancestor bundles, the stake tree assembly with votes,
//! tickets, revocations, and treasury transactions, fee
//! redistribution, fraud proof filling, and header finalization.
//! The chain callbacks of dcrd's mining `Config` live behind
//! [`TemplateChain`], and the transaction source behind
//! [`TemplateTxSource`].  dcrd's random coinbase and treasurybase
//! extra nonces are injected for determinism.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;

use dcroxide_blockchain::UtxoEntry;
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_blockchain::validate::ChainSubsidyParams;
use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_standalone::{SubsidyCache, SubsidySplitVariant};
use dcroxide_txscript::ScriptFlags;
use dcroxide_txscript::stdaddr::Address;
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint};

use crate::pq::{TxPrioItem, TxPriorityQueue, tx_pq_by_stake_and_fee};
use crate::template::sort_parents_by_votes;
use crate::template::{
    BlockTemplate, calc_block_commitment_root_v1, calc_block_merkle_root, calc_fee_per_kb,
    contains_tx_ins, create_coinbase_tx, create_treasury_base_tx, hash_in_slice,
    minimum_median_time, standard_coinbase_op_return, tx_index_from_tx_list,
};
use crate::types::{TxDesc, VoteDesc};
use crate::view::TxMiningView;

/// The max number of bytes it takes to serialize a block header and
/// max possible transaction count varint (dcrd `blockHeaderOverhead`).
const BLOCK_HEADER_OVERHEAD: u32 =
    dcroxide_wire::MAX_BLOCK_HEADER_PAYLOAD as u32 + MAX_VAR_INT_PAYLOAD;

/// The maximum payload of a variable length integer (Go
/// `wire.MaxVarIntPayload`).
const MAX_VAR_INT_PAYLOAD: u32 = 9;

/// Extra data appended to the coinbase script (dcrd `coinbaseFlags`).
const COINBASE_FLAGS: &[u8] = b"/dcrd/";

/// The block version generated for the main network (dcrd
/// `generatedBlockVersion`).
const GENERATED_BLOCK_VERSION: i32 = 11;

/// The block version generated for test networks (dcrd
/// `generatedBlockVersionTest`).
const GENERATED_BLOCK_VERSION_TEST: i32 = 12;

/// The maximum treasury adds allowed in a block (dcrd
/// `blockchain.MaxTAddsPerBlock`).
const MAX_TADDS_PER_BLOCK: usize = 20;

/// The maximum signature operations allowed in a block (dcrd
/// `blockchain.MaxSigOpsPerBlock`).
const MAX_SIG_OPS_PER_BLOCK: i64 = dcroxide_blockchain::validate::MAX_SIG_OPS_PER_BLOCK;

/// The best chain snapshot the template generation consumes (the
/// subset of dcrd's `blockchain.BestState` it reads; the ticket
/// fields come from the chain's next lottery data).
#[derive(Clone, Debug, Default)]
pub struct TemplateBest {
    /// The best block hash.
    pub hash: Hash,
    /// The previous block hash.
    pub prev_hash: Hash,
    /// The best block height.
    pub height: i64,
    /// The past median time of the best block, as unix seconds.
    pub median_time_unix: i64,
    /// The stake difficulty required for the next block.
    pub next_stake_diff: i64,
    /// The lottery final state for the next block.
    pub next_final_state: [u8; 6],
    /// The ticket pool size for the next block.
    pub next_pool_size: u32,
    /// The tickets eligible to vote on the next block.
    pub next_winning_tickets: Vec<Hash>,
    /// The tickets that expire as of the next block.
    pub next_expiring_tickets: Vec<Hash>,
    /// The currently missed tickets.
    pub missed_tickets: Vec<Hash>,
}

/// The template generation policy (dcrd mining `Policy`; the
/// standard verify flags closure lives on [`TemplateChain`]).
#[derive(Clone, Debug)]
pub struct MiningPolicy {
    /// The maximum block size in bytes for generated templates.
    pub block_max_size: u32,
    /// The minimum fee in atoms per 1000 bytes for a transaction to
    /// be treated as free for mining purposes.
    pub tx_min_free_fee: i64,
    /// Whether to mine aggressively by building on the parent when
    /// there are too few voters.
    pub aggressive_mining: bool,
}

/// The extra nonces dcrd autogenerates for the coinbase and
/// treasurybase OP_RETURN outputs, injected for determinism.
#[derive(Copy, Clone, Debug, Default)]
pub struct ExtraNonces {
    /// The coinbase extra nonce.
    pub coinbase: u64,
    /// The treasurybase extra nonce.
    pub treasury: u64,
}

/// The chain state and callbacks the template generation needs,
/// standing in for the closures of dcrd's mining `Config`.
pub trait TemplateChain {
    /// The current best chain snapshot (dcrd `BestSnapshot`).
    fn best_snapshot(&self) -> TemplateBest;
    /// The block with the given hash from any chain (dcrd
    /// `BlockByHash`).
    fn block_by_hash(&self, hash: &Hash) -> Result<MsgBlock, String>;
    /// The required difficulty for the block after the given one
    /// (dcrd `CalcNextRequiredDifficulty`).
    fn calc_next_required_difficulty(
        &self,
        hash: &Hash,
        timestamp_unix: i64,
    ) -> Result<u32, String>;
    /// The expected stake version for the block after the given hash
    /// (dcrd `CalcStakeVersionByHash`).
    fn calc_stake_version_by_hash(&self, hash: &Hash) -> Result<u32, String>;
    /// Fully validate connecting the block to the tip or its parent
    /// (dcrd `CheckConnectBlockTemplate`).
    fn check_connect_block_template(&mut self, block: &MsgBlock) -> Result<(), String>;
    /// Ensure the ticket purchases will not exhaust the live pool
    /// (dcrd `CheckTicketExhaustion`).
    fn check_ticket_exhaustion(&self, hash: &Hash, ticket_purchases: u8) -> Result<(), String>;
    /// Validate the transaction inputs, returning the fee (dcrd
    /// `CheckTransactionInputs`; the subsidy cache is owned by the
    /// implementation).
    #[allow(clippy::too_many_arguments)]
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
    ) -> Result<i64, String>;
    /// Whether the treasury spend has enough votes to be included in
    /// a block after the given one (dcrd `CheckTSpendHasVotes`).
    fn check_tspend_has_votes(&self, prev_hash: &Hash, tspend: &MsgTx) -> Result<(), String>;
    /// The signature operation count for the transaction (dcrd
    /// `CountSigOps`).
    fn count_sig_ops(
        &self,
        tx: &MsgTx,
        is_coin_base_tx: bool,
        is_ssgen: bool,
        is_treasury_enabled: bool,
    ) -> i64;
    /// The unspent output for the outpoint from the main chain tip,
    /// if any (dcrd `FetchUtxoEntry`).
    fn fetch_utxo_entry(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>, String>;
    /// Unspent output information for the transaction's inputs and
    /// its own outputs (dcrd `FetchUtxoView`).
    fn fetch_utxo_view(
        &self,
        tx: &MsgTx,
        tx_hash: &Hash,
        tree: i8,
        include_regular_txns: bool,
    ) -> Result<UtxoView, String>;
    /// Unspent output information as of connecting the given sibling
    /// template block (dcrd `FetchUtxoViewParentTemplate`).
    fn fetch_utxo_view_parent_template(&self, block: &MsgBlock) -> Result<UtxoView, String>;
    /// Force a reorganization to the given sibling (dcrd
    /// `ForceHeadReorganization`).
    fn force_head_reorganization(
        &mut self,
        former_best: Hash,
        new_best: Hash,
    ) -> Result<(), String>;
    /// The header for the given block hash from any chain (dcrd
    /// `HeaderByHash`).
    fn header_by_hash(&self, hash: &Hash) -> Result<BlockHeader, String>;
    /// Whether the transaction is finalized (dcrd
    /// `IsFinalizedTransaction`).
    fn is_finalized_transaction(&self, tx: &MsgTx, block_height: i64, block_time_unix: i64)
    -> bool;
    /// Whether the header commitments agenda is active for the block
    /// after the given one.
    fn is_header_commitments_agenda_active(&self, prev_hash: &Hash) -> Result<bool, String>;
    /// Whether the treasury agenda is active for the block after the
    /// given one.
    fn is_treasury_agenda_active(&self, prev_hash: &Hash) -> Result<bool, String>;
    /// Whether the automatic ticket revocations agenda is active for
    /// the block after the given one.
    fn is_auto_revocations_agenda_active(&self, prev_hash: &Hash) -> Result<bool, String>;
    /// Whether the modified subsidy split agenda is active for the
    /// block after the given one.
    fn is_subsidy_split_agenda_active(&self, prev_hash: &Hash) -> Result<bool, String>;
    /// Whether the modified subsidy split round 2 agenda is active
    /// for the block after the given one.
    fn is_subsidy_split_r2_agenda_active(&self, prev_hash: &Hash) -> Result<bool, String>;
    /// The maximum treasury expenditure for a block extending the
    /// given one (dcrd `MaxTreasuryExpenditure`).
    fn max_treasury_expenditure(&self, prev_hash: &Hash) -> Result<i64, String>;
    /// The generation of blocks stemming from the parent of the
    /// current tip (dcrd `TipGeneration`).
    fn tip_generation(&self) -> Vec<Hash>;
    /// Validate the transaction scripts (dcrd
    /// `ValidateTransactionScripts`).
    fn validate_transaction_scripts(
        &self,
        tx: &MsgTx,
        view: &UtxoView,
        flags: ScriptFlags,
        is_auto_revocations_enabled: bool,
    ) -> Result<(), String>;
    /// The script verification flags for the next block (dcrd
    /// `Policy.StandardVerifyFlags`).
    fn standard_verify_flags(&self) -> Result<ScriptFlags, String>;
    /// The current adjusted time as unix seconds (dcrd
    /// `TimeSource.AdjustedTime`).
    fn adjusted_time_unix(&self) -> i64;
}

/// The transaction source surface the template generation consumes
/// (the used subset of dcrd's mining `TxSource`).
pub trait TemplateTxSource {
    /// A snapshot of the source's transactions and relationships
    /// (dcrd `MiningView`).
    fn mining_view(&self) -> TxMiningView;
    /// Whether the source has the transaction (dcrd
    /// `HaveTransaction`).
    fn have_transaction(&self, hash: &Hash) -> bool;
    /// Whether the source has all of the transactions (dcrd
    /// `HaveAllTransactions`).
    fn have_all_transactions(&self, hashes: &[Hash]) -> bool;
    /// The vote hashes for the block (dcrd `VoteHashesForBlock`).
    fn vote_hashes_for_block(&self, hash: &Hash) -> Vec<Hash>;
    /// The vote metadata for the blocks (dcrd `VotesForBlocks`).
    fn votes_for_blocks(&self, hashes: &[Hash]) -> Vec<Vec<VoteDesc>>;
    /// Whether the regular tree of the block is known disapproved
    /// (dcrd `IsRegTxTreeKnownDisapproved`).
    fn is_reg_tx_tree_known_disapproved(&self, hash: &Hash) -> bool;
}

/// Add all entries in `view_b` to `view_a`, replacing entries that
/// are missing or spent in `view_a` (dcrd `mergeUtxoView`).
pub fn merge_utxo_view(view_a: &mut UtxoView, view_b: &UtxoView) {
    let updates: Vec<(OutPoint, UtxoEntry)> = view_b
        .entries()
        .filter_map(|(key, entry_b)| {
            let outpoint = OutPoint {
                hash: Hash(key.0),
                index: key.1,
                tree: key.2,
            };
            match view_a.lookup_entry(&outpoint) {
                Some(entry_a) if !entry_a.is_spent() => None,
                _ => Some((outpoint, entry_b.clone())),
            }
        })
        .collect();
    for (outpoint, entry) in updates {
        view_a.insert_entry(&outpoint, entry);
    }
}

/// Mark the inputs to the transaction as spent in the view and add
/// its outputs as available utxos (dcrd `spendTransaction`).
pub fn spend_transaction(
    utxo_view: &mut UtxoView,
    tx: &MsgTx,
    height: i64,
    is_treasury_enabled: bool,
) {
    for tx_in in &tx.tx_in {
        if let Some(entry) = utxo_view.lookup_entry_mut(&tx_in.previous_out_point) {
            entry.spend();
        }
    }
    utxo_view.add_tx_outs(
        tx,
        height,
        dcroxide_wire::NULL_BLOCK_INDEX,
        is_treasury_enabled,
    );
}

/// The block template generator (dcrd `BlkTmplGenerator`).
pub struct BlkTmplGenerator<'p, C: TemplateChain, S: TemplateTxSource> {
    /// The template policy.
    pub policy: MiningPolicy,
    /// The chain parameters.
    pub params: &'p Params,
    /// The subsidy cache for coinbase and treasurybase construction.
    pub subsidy_cache: SubsidyCache<ChainSubsidyParams<'p>>,
    /// The chain backend.
    pub chain: C,
    /// The transaction source.
    pub tx_source: S,
    /// Seconds to offset the mining timestamp by (positive values
    /// are in the past; dcrd `MiningTimeOffset`).
    pub mining_time_offset: i64,
}

impl<'p, C: TemplateChain, S: TemplateTxSource> BlkTmplGenerator<'p, C, S> {
    /// A new generator over the given policy, chain, and source
    /// (dcrd `NewBlkTmplGenerator`).
    pub fn new(
        policy: MiningPolicy,
        params: &'p Params,
        chain: C,
        tx_source: S,
        mining_time_offset: i64,
    ) -> BlkTmplGenerator<'p, C, S> {
        BlkTmplGenerator {
            policy,
            params,
            subsidy_cache: SubsidyCache::new(ChainSubsidyParams(params)),
            chain,
            tx_source,
            mining_time_offset,
        }
    }

    /// The current time adjusted to be at least one second after the
    /// median time of the last several blocks, minus the configured
    /// offset (dcrd `medianAdjustedTime`).
    fn median_adjusted_time(&self) -> i64 {
        let best = self.chain.best_snapshot();
        let mut new_timestamp = self.chain.adjusted_time_unix();
        let min_timestamp = minimum_median_time(best.median_time_unix);
        if new_timestamp < min_timestamp {
            new_timestamp = min_timestamp;
        }
        new_timestamp - self.mining_time_offset
    }

    /// Update the header timestamp to the current median adjusted
    /// time (dcrd `UpdateBlockTime`).
    pub fn update_block_time(&self, header: &mut BlockHeader) {
        header.timestamp = self.median_adjusted_time() as u32;
    }

    /// Fill the fraud proofs of a stake transaction from the current
    /// view, returning false when an input is missing (dcrd
    /// `maybeInsertStakeTx`).
    fn maybe_insert_stake_tx(
        &self,
        stx: &mut MsgTx,
        stx_hash: &Hash,
        tree: i8,
        tree_valid: bool,
        is_treasury_enabled: bool,
    ) -> bool {
        let Ok(view) = self.chain.fetch_utxo_view(stx, stx_hash, tree, tree_valid) else {
            return false;
        };
        let is_ssgen = dcroxide_stake::is_ssgen(stx);
        let mut is_tspend = false;
        let mut is_treasury_base = false;
        if is_treasury_enabled {
            is_tspend = dcroxide_stake::is_tspend(stx);
            is_treasury_base = dcroxide_stake::is_treasury_base(stx);
        }
        let mut missing_input = false;
        for (i, tx_in) in stx.tx_in.iter_mut().enumerate() {
            // Stakebase, treasurybase, and treasury spend inputs are
            // not evaluated.
            if (i == 0 && (is_ssgen || is_treasury_base)) || is_tspend {
                tx_in.block_height = dcroxide_wire::NULL_BLOCK_HEIGHT;
                tx_in.block_index = dcroxide_wire::NULL_BLOCK_INDEX;
                continue;
            }

            match view.lookup_entry(&tx_in.previous_out_point) {
                None => {
                    missing_input = true;
                    break;
                }
                Some(entry) => {
                    tx_in.value_in = entry.amount();
                    tx_in.block_height = entry.block_height() as u32;
                    tx_in.block_index = entry.block_index();
                }
            }
        }
        !missing_input
    }

    /// Build a template on the parent of the current tip when there
    /// are too few voters, per the aggressive mining policy (dcrd
    /// `handleTooFewVoters`).  Returns `None` when not mining
    /// aggressively.
    #[allow(clippy::too_many_arguments)]
    fn handle_too_few_voters(
        &mut self,
        next_height: i64,
        mining_address: Option<&Address>,
        is_treasury_enabled: bool,
        subsidy_split_variant: SubsidySplitVariant,
        nonces: &ExtraNonces,
    ) -> Result<Option<BlockTemplate>, String> {
        let stake_validation_height = self.params.stake_validation_height;
        let best = self.chain.best_snapshot();
        if next_height >= stake_validation_height && self.policy.aggressive_mining {
            let top_block = self
                .chain
                .block_by_hash(&best.hash)
                .map_err(|_| format!("unable to get tip block {}", best.prev_hash))?;
            let tip_header = top_block.header;
            let top_height = i64::from(tip_header.height);

            // Start with a copy of the tip block header.
            let mut block = MsgBlock {
                header: tip_header,
                transactions: Vec::new(),
                stransactions: Vec::new(),
            };

            // Create and populate a new coinbase.
            let mut coinbase_script = alloc::vec![0u8; COINBASE_FLAGS.len() + 2];
            coinbase_script[2..].copy_from_slice(COINBASE_FLAGS);
            let op_return_pk_script =
                standard_coinbase_op_return(tip_header.height, nonces.coinbase)?;
            let coinbase_tx = create_coinbase_tx(
                &mut self.subsidy_cache,
                &coinbase_script,
                &op_return_pk_script,
                top_height,
                mining_address,
                tip_header.voters,
                self.params,
                is_treasury_enabled,
                subsidy_split_variant,
            );
            block.transactions.push(coinbase_tx);

            if is_treasury_enabled {
                let treasury_base = create_treasury_base_tx(
                    &mut self.subsidy_cache,
                    top_height,
                    tip_header.voters,
                    nonces.treasury,
                )?;
                block.stransactions.push(treasury_base);
            }

            // Copy all of the regular transactions over, skipping the
            // coinbase.
            for tx in top_block.transactions.iter().skip(1) {
                block.transactions.push(tx.clone());
            }

            // Copy all of the stake transactions over, skipping the
            // treasurybase when the treasury is enabled.
            let skip = usize::from(is_treasury_enabled);
            for stx in top_block.stransactions.iter().skip(skip) {
                block.stransactions.push(stx.clone());
            }

            // Set a fresh timestamp and recalculate the size.
            let ts = self.median_adjusted_time();
            block.header.timestamp = ts as u32;
            block.header.size = block.serialize().len() as u32;

            // Calculate the merkle root depending on the result of
            // the header commitments agenda vote.
            let prev_hash = tip_header.prev_block;
            let hdr_cmt_active = self.chain.is_header_commitments_agenda_active(&prev_hash)?;
            block.header.merkle_root =
                calc_block_merkle_root(&block.transactions, &block.stransactions, hdr_cmt_active);

            // Calculate the required difficulty for the block.
            let req_difficulty = self
                .chain
                .calc_next_required_difficulty(&prev_hash, ts)
                .map_err(|e| format!("ErrGettingDifficulty: {e}"))?;
            block.header.bits = req_difficulty;

            // Calculate the stake root or commitment root depending
            // on the result of the header commitments agenda vote.
            let cmt_root = if hdr_cmt_active {
                let block_utxos = self
                    .chain
                    .fetch_utxo_view_parent_template(&block)
                    .map_err(|e| format!("ErrFetchTxStore: {e}"))?;
                calc_block_commitment_root_v1(&block, &ViewPrevScripter(&block_utxos))
                    .map_err(|e| format!("ErrCalcCommitmentRoot: {e}"))?
            } else {
                dcroxide_standalone::calc_tx_tree_merkle_root(&block.stransactions)
            };
            block.header.stake_root = cmt_root;

            // Make sure the block validates.
            self.chain
                .check_connect_block_template(&block)
                .map_err(|e| format!("ErrCheckConnectBlock: {e}"))?;

            return Ok(Some(BlockTemplate {
                block,
                fees: alloc::vec![0],
                sig_op_counts: alloc::vec![0],
                height: top_height,
                valid_pay_address: mining_address.is_some(),
            }));
        }

        Ok(None)
    }

    /// Create a version 2 revocation for the ticket and make its
    /// submission output available in the block view (dcrd
    /// `createRevocationFromTicket`; automatic revocations only).
    fn create_revocation_from_ticket(
        &self,
        ticket_hash: &Hash,
        block_utxos: &mut UtxoView,
        prev_header_bytes: &[u8],
        is_treasury_enabled: bool,
    ) -> Result<Rc<TxDesc>, String> {
        // Fetch the utxo for the ticket submission to be revoked.
        let ticket_submission = OutPoint {
            hash: *ticket_hash,
            index: 0,
            tree: dcroxide_wire::TX_TREE_STAKE,
        };
        let ticket_utxo = self
            .chain
            .fetch_utxo_entry(&ticket_submission)
            .map_err(|e| format!("ErrGetTicketInfo: {e}"))?;
        let ticket_utxo = match ticket_utxo {
            Some(entry) if !entry.is_spent() => entry,
            _ => {
                return Err(format!(
                    "ErrGetTicketInfo: ticket {ticket_hash} does not exist or is spent"
                ));
            }
        };

        // Add the ticket submission utxo to the block utxos view so
        // that it is available for lookup later.
        block_utxos.insert_entry(&ticket_submission, ticket_utxo.clone());

        // Get the minimal outputs for the ticket.
        let Some(min_outs_data) = ticket_utxo.ticket_minimal_outputs_data() else {
            return Err(format!(
                "ErrGetTicketInfo: ticket {ticket_hash} missing minimal outputs"
            ));
        };
        let (ticket_min_outs, _) =
            dcroxide_blockchain::chainio::deserialize_to_minimal_outputs(min_outs_data);

        // Create a revocation transaction for the ticket.
        let revocation_tx = dcroxide_stake::create_revocation_from_ticket(
            ticket_hash,
            &ticket_min_outs,
            0,
            dcroxide_stake::TX_VERSION_AUTO_REVOCATIONS,
            self.params,
            prev_header_bytes,
            true,
        )
        .map_err(|e| format!("{e:?}"))?;
        let tx_hash = revocation_tx.tx_hash();
        let total_sig_ops =
            self.chain
                .count_sig_ops(&revocation_tx, false, false, is_treasury_enabled);
        let tx_size = revocation_tx.serialize_size() as i64;
        Ok(Rc::new(TxDesc {
            tx: revocation_tx,
            tx_hash,
            tree: dcroxide_wire::TX_TREE_STAKE,
            tx_type: dcroxide_stake::TxType::SSRtx,
            added_unix: 0,
            height: 0,
            fee: 0,
            total_sig_ops,
            tx_size,
        }))
    }

    /// Create revocations for all tickets becoming missed or expired
    /// as of the new block and add them to the priority queue (dcrd
    /// `addAutoRevocationsToQueue`).
    #[allow(clippy::too_many_arguments)]
    fn add_auto_revocations_to_queue(
        &self,
        winning_tickets: &BTreeMap<[u8; 32], bool>,
        block_utxos: &mut UtxoView,
        prev_header_bytes: &[u8],
        num_ssgen: usize,
        is_treasury_enabled: bool,
        priority_queue: &mut TxPriorityQueue,
        prioritized_txns: &mut BTreeSet<[u8; 32]>,
        prio_item_map: &mut BTreeMap<[u8; 32], TxPrioItem>,
    ) -> Result<(), String> {
        // Return now if there are no tickets to revoke.
        let best = self.chain.best_snapshot();
        let missed_count = best.next_winning_tickets.len().saturating_sub(num_ssgen);
        let expired_count = best.next_expiring_tickets.len();
        if missed_count + expired_count == 0 {
            return Ok(());
        }

        // Tickets that must be revoked due to becoming missed or
        // expired this block.
        let mut revoke_tickets: Vec<Hash> = Vec::with_capacity(missed_count + expired_count);
        for (ticket_hash, has_vote) in winning_tickets {
            if !has_vote {
                revoke_tickets.push(Hash(*ticket_hash));
            }
        }
        revoke_tickets.extend_from_slice(&best.next_expiring_tickets);

        for ticket_hash in &revoke_tickets {
            let tx_desc = self.create_revocation_from_ticket(
                ticket_hash,
                block_utxos,
                prev_header_bytes,
                is_treasury_enabled,
            )?;

            let prio_item = TxPrioItem {
                tx_desc: tx_desc.clone(),
                tx_type: tx_desc.tx_type,
                auto_revocation: true,
                fee: 0,
                priority: 0.0,
                fee_per_kb: 0.0,
            };
            let revocation_tx_hash = tx_desc.tx_hash;
            prioritized_txns.insert(revocation_tx_hash.0);
            priority_queue.push(prio_item.clone());
            prio_item_map.insert(revocation_tx_hash.0, prio_item);
        }

        Ok(())
    }

    /// Build a new block template paying to the given address, or
    /// redeemable by anyone when no address is given (dcrd
    /// `NewBlockTemplate`; the extra nonces dcrd randomizes are
    /// injected).  Returns `None` when there are not enough voters on
    /// any of the current top blocks.
    pub fn new_block_template(
        &mut self,
        pay_to_address: Option<&Address>,
        nonces: &ExtraNonces,
    ) -> Result<Option<BlockTemplate>, String> {
        let script_flags = self.chain.standard_verify_flags()?;
        let best = self.chain.best_snapshot();
        let mut prev_hash = best.hash;
        let next_block_height = best.height + 1;
        let stake_validation_height = self.params.stake_validation_height;

        let is_treasury_enabled = self.chain.is_treasury_agenda_active(&prev_hash)?;
        let is_auto_revocations_enabled =
            self.chain.is_auto_revocations_agenda_active(&prev_hash)?;
        let is_subsidy_enabled = self.chain.is_subsidy_split_agenda_active(&prev_hash)?;
        let is_subsidy_r2_enabled = self.chain.is_subsidy_split_r2_agenda_active(&prev_hash)?;
        let subsidy_split_variant = if is_subsidy_r2_enabled {
            SubsidySplitVariant::Dcp0012
        } else if is_subsidy_enabled {
            SubsidySplitVariant::Dcp0010
        } else {
            SubsidySplitVariant::Original
        };

        let mut is_tvi = false;
        let mut max_treasury_spend: i64 = 0;
        if is_treasury_enabled {
            is_tvi = dcroxide_standalone::is_treasury_vote_interval(
                next_block_height as u64,
                self.params.treasury_vote_interval,
            );
        }

        if next_block_height >= stake_validation_height {
            // Obtain the entire generation of blocks stemming from
            // this parent and the list eligible to build on.
            let children = self.chain.tip_generation();
            let eligible_parents = sort_parents_by_votes(
                |hashes| self.tx_source.votes_for_blocks(hashes),
                prev_hash,
                &children,
                self.params,
            );
            if eligible_parents.is_empty() {
                return self.handle_too_few_voters(
                    next_block_height,
                    pay_to_address,
                    is_treasury_enabled,
                    subsidy_split_variant,
                    nonces,
                );
            }

            // Force a reorganization to the parent with the most
            // votes if needed.
            for new_head in &eligible_parents {
                if *new_head == prev_hash {
                    break;
                }
                if self
                    .chain
                    .force_head_reorganization(prev_hash, *new_head)
                    .is_err()
                {
                    continue;
                }

                // Ensure the needed votes are actually in the mempool.
                let vote_hashes = self.tx_source.vote_hashes_for_block(new_head);
                if vote_hashes.is_empty() {
                    return Err(format!("no vote metadata for block {new_head}"));
                }
                if !self.tx_source.have_all_transactions(&vote_hashes) {
                    continue;
                }

                prev_hash = *new_head;
                break;
            }

            // Obtain the maximum allowed treasury expenditure.
            if is_treasury_enabled && is_tvi {
                max_treasury_spend = self.chain.max_treasury_expenditure(&prev_hash)?;
            }
        }

        let mut mining_view = self.tx_source.mining_view();
        let source_txns: Vec<Rc<TxDesc>> = mining_view.tx_descs().to_vec();
        let mut priority_queue = TxPriorityQueue::new(source_txns.len(), tx_pq_by_stake_and_fee);
        let mut prioritized_txns: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut block_txns: Vec<Rc<TxDesc>> = Vec::with_capacity(source_txns.len());
        let mut block_utxos = UtxoView::new();
        let mut tx_fees: Vec<i64> = Vec::with_capacity(source_txns.len());
        let mut tx_fees_map: BTreeMap<[u8; 32], i64> = BTreeMap::new();
        let mut tx_sig_op_counts: Vec<i64> = Vec::with_capacity(source_txns.len());
        let mut tx_sig_op_counts_map: BTreeMap<[u8; 32], i64> = BTreeMap::new();
        tx_fees.push(-1); // Updated once known.

        let known_disapproved = self.tx_source.is_reg_tx_tree_known_disapproved(&prev_hash);
        let mut prio_item_map: BTreeMap<[u8; 32], TxPrioItem> = BTreeMap::new();

        'mempool_loop: for tx_desc in &source_txns {
            // A block can't have more than one coinbase or contain
            // non-finalized transactions.
            let tx = &tx_desc.tx;
            let tx_hash = tx_desc.tx_hash;
            if dcroxide_standalone::is_coin_base_tx(tx, is_treasury_enabled) {
                continue;
            }
            if !self
                .chain
                .is_finalized_transaction(tx, next_block_height, best.median_time_unix)
            {
                continue;
            }

            let is_ssgen = tx_desc.tx_type == dcroxide_stake::TxType::SSGen;
            if is_ssgen {
                let (block_hash, block_height) = dcroxide_stake::ssgen_block_voted_on(tx);
                if !(block_hash == prev_hash && i64::from(block_height) == next_block_height - 1) {
                    continue;
                }
            }
            let is_tspend =
                is_treasury_enabled && tx_desc.tx_type == dcroxide_stake::TxType::TSpend;

            // Fetch all of the utxos referenced by this transaction.
            let Ok(utxos) =
                self.chain
                    .fetch_utxo_view(tx, &tx_hash, tx_desc.tree, !known_disapproved)
            else {
                continue;
            };

            // Skip transactions with missing inputs that are also not
            // available from the source.
            for (i, tx_in) in tx.tx_in.iter().enumerate() {
                if (i == 0 && is_ssgen) || is_tspend {
                    continue;
                }
                let origin_hash = tx_in.previous_out_point.hash;
                let entry = utxos.lookup_entry(&tx_in.previous_out_point);
                if (entry.is_none() || entry.is_some_and(|e| e.is_spent()))
                    && !self.tx_source.have_transaction(&origin_hash)
                {
                    continue 'mempool_loop;
                }
            }

            // Calculate the final transaction priority and fee rate.
            let priority = crate::policy::calc_priority(
                tx,
                |op| {
                    utxos
                        .lookup_entry(op)
                        .map(|e| (e.block_height(), e.amount()))
                },
                next_block_height,
            );
            let (ancestor_stats, has_stats) = mining_view.ancestor_stats(&tx_hash);
            let prio_item = TxPrioItem {
                tx_desc: tx_desc.clone(),
                tx_type: tx_desc.tx_type,
                auto_revocation: false,
                fee: tx_desc.fee + ancestor_stats.fees,
                priority,
                fee_per_kb: calc_fee_per_kb(tx_desc, &ancestor_stats),
            };
            prio_item_map.insert(tx_hash.0, prio_item.clone());
            let has_parents = mining_view.has_parents(&tx_hash);
            if !has_parents || has_stats {
                priority_queue.push(prio_item);
                prioritized_txns.insert(tx_hash.0);
                block_utxos.add_tx_outs(
                    tx,
                    next_block_height,
                    dcroxide_wire::NULL_BLOCK_INDEX,
                    is_treasury_enabled,
                );
            }

            // Merge the referenced outputs from the input transactions
            // into the block utxo view to avoid a second lookup.
            merge_utxo_view(&mut block_utxos, &utxos);
        }

        let mut block_size = BLOCK_HEADER_OVERHEAD;
        let mut block_sig_ops: i64 = 0;
        let mut total_fees: i64 = 0;
        let mut num_sstx = 0usize;
        let mut num_ssgen = 0usize;
        let mut num_tadds = 0usize;

        let mut found_winning_tickets: BTreeMap<[u8; 32], bool> = BTreeMap::new();
        for ticket_hash in &best.next_winning_tickets {
            found_winning_tickets.insert(ticket_hash.0, false);
        }
        let mut expiring_ticket_hashes: BTreeSet<[u8; 32]> = BTreeSet::new();
        for ticket_hash in &best.next_expiring_tickets {
            expiring_ticket_hashes.insert(ticket_hash.0);
        }

        let mut template_txn_map: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut added_auto_revocations = false;

        let best_header = self.chain.header_by_hash(&best.hash).map_err(|_| {
            format!(
                "ErrGetTopBlock: unable to get tip block header {}",
                best.hash
            )
        })?;
        let best_header_bytes = best_header.serialize();

        // The queue loop; the outer loop realizes dcrd's goto used to
        // re-enter it after adding the automatic revocations once the
        // queue drains.
        'auto_revocations: loop {
            'next_priority_queue_item: while let Some(prio_item) = priority_queue.pop() {
                let tx_desc = prio_item.tx_desc.clone();
                let tx = &tx_desc.tx;
                let tx_hash = tx_desc.tx_hash;
                prioritized_txns.remove(&tx_hash.0);
                if template_txn_map.contains(&tx_hash.0) {
                    continue;
                }

                let is_sstx = prio_item.tx_type == dcroxide_stake::TxType::SStx;
                let is_ssgen = prio_item.tx_type == dcroxide_stake::TxType::SSGen;
                let is_ssrtx = prio_item.tx_type == dcroxide_stake::TxType::SSRtx;
                let mut is_tspend = false;
                let mut is_tadd = false;
                if is_treasury_enabled {
                    is_tspend = prio_item.tx_type == dcroxide_stake::TxType::TSpend;
                    is_tadd = prio_item.tx_type == dcroxide_stake::TxType::TAdd;
                }

                // Once a non-vote pops, votes are done since they are
                // the highest priority; insert the automatic
                // revocations exactly once at that point and requeue.
                let done_adding_votes = !is_ssgen;
                if is_auto_revocations_enabled && !added_auto_revocations && done_adding_votes {
                    self.add_auto_revocations_to_queue(
                        &found_winning_tickets,
                        &mut block_utxos,
                        &best_header_bytes,
                        num_ssgen,
                        is_treasury_enabled,
                        &mut priority_queue,
                        &mut prioritized_txns,
                        &mut prio_item_map,
                    )?;
                    added_auto_revocations = true;
                    priority_queue.push(prio_item.clone());
                    prioritized_txns.insert(tx_hash.0);
                    continue;
                }

                // Skip treasury spends outside a TVI, outside their
                // window, without enough votes, or overspending.
                if is_tspend {
                    if !is_tvi {
                        continue;
                    }
                    let exp = tx.expiry;
                    if !dcroxide_standalone::inside_tspend_window(
                        next_block_height,
                        exp,
                        self.params.treasury_vote_interval,
                        self.params.treasury_vote_interval_multiplier,
                    ) {
                        continue;
                    }
                    if self.chain.check_tspend_has_votes(&prev_hash, tx).is_err() {
                        continue;
                    }
                    let tspend_amount = tx.tx_in[0].value_in;
                    if max_treasury_spend - tspend_amount < 0 {
                        continue;
                    }
                    max_treasury_spend -= tspend_amount;
                }

                // Enforce the per-block treasury add and ticket
                // count limits and the ticket price.
                if is_tadd && num_tadds >= MAX_TADDS_PER_BLOCK {
                    continue;
                }
                if is_sstx && num_sstx >= usize::from(self.params.max_fresh_stake_per_block) {
                    continue;
                }
                if is_sstx && tx.tx_out[0].value < best.next_stake_diff {
                    continue;
                }

                // Skip revocations spending tickets that are not
                // eligible to be revoked.
                if is_ssrtx {
                    let ticket_hash = tx.tx_in[0].previous_out_point.hash;
                    let voted = found_winning_tickets.get(&ticket_hash.0).copied();
                    let missed_this_block = voted == Some(false);
                    let expiring_this_block = expiring_ticket_hashes.contains(&ticket_hash.0);
                    let missed_or_expired_this_block = missed_this_block || expiring_this_block;
                    let eligible = (is_auto_revocations_enabled && missed_or_expired_this_block)
                        || hash_in_slice(&ticket_hash, &best.missed_tickets);
                    if !eligible {
                        continue;
                    }
                }

                if mining_view.is_rejected(&tx_hash) {
                    // The transaction or one of its ancestors has been
                    // rejected.
                    continue;
                }

                // Refresh the ancestor bundle and fee rate, requeueing
                // or skipping when the rate decreased.
                let ancestors = mining_view.ancestors(&tx_hash);
                let (ancestor_stats, _) = mining_view.ancestor_stats(&tx_hash);
                let old_fee = prio_item.fee_per_kb;
                let mut prio_item = prio_item;
                prio_item.fee_per_kb = calc_fee_per_kb(&tx_desc, &ancestor_stats);
                let fee_decreased = old_fee > prio_item.fee_per_kb;
                if fee_decreased && ancestor_stats.num_ancestors == 0 {
                    priority_queue.push(prio_item);
                    prioritized_txns.insert(tx_hash.0);
                    continue;
                }
                if fee_decreased {
                    continue;
                }

                // Enforce the maximum block size, with overflow check.
                let tx_size = tx.serialize_size() as u32;
                let block_plus_tx_size = block_size
                    .wrapping_add(tx_size)
                    .wrapping_add(ancestor_stats.size_bytes as u32);
                if block_plus_tx_size < block_size
                    || block_plus_tx_size >= self.policy.block_max_size
                {
                    mining_view.reject(&tx_hash);
                    continue;
                }

                // Enforce the maximum signature operations per block,
                // with overflow check.
                let num_sig_ops = tx_desc.total_sig_ops;
                let num_sig_ops_bundle = num_sig_ops + ancestor_stats.total_sig_ops;
                if block_sig_ops + num_sig_ops_bundle < block_sig_ops
                    || block_sig_ops + num_sig_ops_bundle > MAX_SIG_OPS_PER_BLOCK
                {
                    mining_view.reject(&tx_hash);
                    continue;
                }

                // Votes must use a winning ticket that has not voted
                // yet.
                if is_ssgen {
                    let ticket_hash = tx.tx_in[1].previous_out_point.hash;
                    if found_winning_tickets.get(&ticket_hash.0) == Some(&true) {
                        continue;
                    }
                    if !best.next_winning_tickets.contains(&ticket_hash) {
                        continue;
                    }
                }

                // Skip free transactions outside the stake tree.
                if prio_item.fee_per_kb < self.policy.tx_min_free_fee as f64
                    && tx_desc.tree != dcroxide_wire::TX_TREE_STAKE
                {
                    mining_view.reject(&tx_hash);
                    continue;
                }

                // Validate the whole ancestor bundle.
                let mut tx_bundle = ancestors;
                tx_bundle.push(tx_desc.clone());
                for bundled_tx in &tx_bundle {
                    if self
                        .chain
                        .check_transaction_inputs(
                            &bundled_tx.tx,
                            next_block_height,
                            &block_utxos,
                            false,
                            &best_header,
                            is_treasury_enabled,
                            is_auto_revocations_enabled,
                            subsidy_split_variant,
                        )
                        .is_err()
                    {
                        mining_view.reject(&bundled_tx.tx_hash);
                        continue 'next_priority_queue_item;
                    }
                    if self
                        .chain
                        .validate_transaction_scripts(
                            &bundled_tx.tx,
                            &block_utxos,
                            script_flags,
                            is_auto_revocations_enabled,
                        )
                        .is_err()
                    {
                        mining_view.reject(&bundled_tx.tx_hash);
                        continue 'next_priority_queue_item;
                    }
                }

                for bundled_tx_desc in &tx_bundle {
                    let bundled_tx_hash = bundled_tx_desc.tx_hash;

                    // Spend the inputs in the block utxo view and make
                    // the outputs available.
                    spend_transaction(
                        &mut block_utxos,
                        &bundled_tx_desc.tx,
                        next_block_height,
                        is_treasury_enabled,
                    );

                    block_txns.push(bundled_tx_desc.clone());
                    block_size += bundled_tx_desc.tx.serialize_size() as u32;
                    let bundled_tx_sig_ops = bundled_tx_desc.total_sig_ops;
                    block_sig_ops += bundled_tx_sig_ops;

                    if bundled_tx_desc.tx_type == dcroxide_stake::TxType::SStx {
                        num_sstx += 1;
                    }
                    if bundled_tx_desc.tx_type == dcroxide_stake::TxType::SSGen {
                        let ticket = bundled_tx_desc.tx.tx_in[1].previous_out_point.hash;
                        found_winning_tickets.insert(ticket.0, true);
                        num_ssgen += 1;
                    }
                    if is_treasury_enabled
                        && bundled_tx_desc.tx_type == dcroxide_stake::TxType::TAdd
                    {
                        num_tadds += 1;
                    }

                    template_txn_map.insert(bundled_tx_hash.0);
                    tx_fees_map.insert(bundled_tx_hash.0, bundled_tx_desc.fee);
                    tx_sig_op_counts_map.insert(bundled_tx_hash.0, bundled_tx_sig_ops);

                    // Remove from the mining view and promote children
                    // with no remaining dependencies.
                    let bundled_tx_deps = mining_view.children(&bundled_tx_hash);
                    mining_view.remove_transaction(&bundled_tx_hash, false);
                    for child_tx in bundled_tx_deps {
                        let child_tx_hash = child_tx.tx_hash;
                        if prioritized_txns.contains(&child_tx_hash.0) {
                            continue;
                        }
                        if !mining_view.has_parents(&child_tx_hash) {
                            if let Some(child_prio_item) = prio_item_map.get(&child_tx_hash.0) {
                                priority_queue.push(child_prio_item.clone());
                                prioritized_txns.insert(child_tx_hash.0);
                            }
                        }
                    }
                }
            }

            // dcrd's goto: when the queue drained without hitting a
            // non-vote item, the automatic revocations still need to
            // be added and mined.
            if is_auto_revocations_enabled && !added_auto_revocations {
                self.add_auto_revocations_to_queue(
                    &found_winning_tickets,
                    &mut block_utxos,
                    &best_header_bytes,
                    num_ssgen,
                    is_treasury_enabled,
                    &mut priority_queue,
                    &mut prioritized_txns,
                    &mut prio_item_map,
                )?;
                added_auto_revocations = true;
                continue 'auto_revocations;
            }
            break;
        }

        // Build the stake tree: votes first (after the treasurybase
        // when the treasury is active), then tickets, revocations,
        // and treasury transactions.
        let mut block_txns_stake: Vec<MsgTx> = Vec::with_capacity(block_txns.len());
        let mut coinbase_script = alloc::vec![0u8; 2];
        coinbase_script.extend_from_slice(COINBASE_FLAGS);
        let op_return_pk_script =
            standard_coinbase_op_return(next_block_height as u32, nonces.coinbase)?;

        let mut voters = 0usize;
        let mut vote_bits_voters: Vec<u16> =
            Vec::with_capacity(usize::from(self.params.tickets_per_block));
        let mut votes: Vec<MsgTx> = Vec::new();
        if next_block_height >= stake_validation_height {
            for tx_desc in &block_txns {
                if dcroxide_stake::is_ssgen(&tx_desc.tx) {
                    let mut tx_copy = tx_desc.tx.clone();
                    if self.maybe_insert_stake_tx(
                        &mut tx_copy,
                        &tx_desc.tx_hash,
                        tx_desc.tree,
                        !known_disapproved,
                        is_treasury_enabled,
                    ) {
                        let vb = dcroxide_stake::ssgen_vote_bits(&tx_copy);
                        vote_bits_voters.push(vb);
                        votes.push(tx_copy);
                        voters += 1;
                    }
                }
                if voters >= u16::MAX as usize {
                    break;
                }
            }
        }

        let mut treasury_base: Option<MsgTx> = None;
        if is_treasury_enabled {
            let tb = create_treasury_base_tx(
                &mut self.subsidy_cache,
                next_block_height,
                voters as u16,
                nonces.treasury,
            )?;
            treasury_base = Some(tb.clone());
            block_txns_stake.push(tb);
        }
        block_txns_stake.extend(votes);

        // Determine the vote bits for the header.
        let votebits: u16 = if next_block_height < stake_validation_height {
            0x0001 // TxTreeRegular enabled pre-staking.
        } else {
            let mut vote_yea = 0usize;
            let mut total_votes = 0usize;
            for vb in &vote_bits_voters {
                if vb & 0x0001 != 0 {
                    vote_yea += 1;
                }
                total_votes += 1;
            }
            if vote_yea == 0 {
                0x0000
            } else if total_votes / vote_yea <= 1 {
                0x0001
            } else {
                0x0000
            }
        };

        // Tickets: must not spend regular tree outputs from this
        // block and must meet the stake difficulty.
        let block_txns_refs: Vec<&MsgTx> = block_txns.iter().map(|d| &d.tx).collect();
        let block_txns_hashes: Vec<Hash> = block_txns.iter().map(|d| d.tx_hash).collect();
        let mut fresh_stake = 0usize;
        for tx_desc in &block_txns {
            let tx = &tx_desc.tx;
            if tx_desc.tree == dcroxide_wire::TX_TREE_STAKE && dcroxide_stake::is_sstx(tx) {
                if contains_tx_ins(&block_txns_refs, &block_txns_hashes, tx) {
                    continue;
                }
                if tx.tx_out[0].value >= best.next_stake_diff {
                    let mut tx_copy = tx.clone();
                    if self.maybe_insert_stake_tx(
                        &mut tx_copy,
                        &tx_desc.tx_hash,
                        tx_desc.tree,
                        !known_disapproved,
                        is_treasury_enabled,
                    ) {
                        block_txns_stake.push(tx_copy);
                        fresh_stake += 1;
                    }
                }
            }
            if fresh_stake >= usize::from(self.params.max_fresh_stake_per_block) {
                break;
            }
        }

        self.chain
            .check_ticket_exhaustion(&best.hash, fresh_stake as u8)
            .map_err(|e| format!("ErrTicketExhaustion: {e}"))?;

        // Revocations.
        let mut revocations = 0usize;
        for tx_desc in &block_txns {
            if next_block_height < stake_validation_height {
                break;
            }
            let tx = &tx_desc.tx;
            if tx_desc.tree == dcroxide_wire::TX_TREE_STAKE && dcroxide_stake::is_ssrtx(tx) {
                let mut tx_copy = tx.clone();
                if self.maybe_insert_stake_tx(
                    &mut tx_copy,
                    &tx_desc.tx_hash,
                    tx_desc.tree,
                    !known_disapproved,
                    is_treasury_enabled,
                ) {
                    block_txns_stake.push(tx_copy);
                    revocations += 1;
                }
            }
            if revocations >= u8::MAX as usize {
                break;
            }
        }

        // Treasury adds and spends.
        if is_treasury_enabled {
            for tx_desc in &block_txns {
                let tx = &tx_desc.tx;
                if tx_desc.tree == dcroxide_wire::TX_TREE_STAKE
                    && (dcroxide_stake::is_tadd(tx) || dcroxide_stake::is_tspend(tx))
                {
                    let mut tx_copy = tx.clone();
                    if self.maybe_insert_stake_tx(
                        &mut tx_copy,
                        &tx_desc.tx_hash,
                        tx_desc.tree,
                        !known_disapproved,
                        is_treasury_enabled,
                    ) {
                        block_txns_stake.push(tx_copy);
                    }
                }
            }
        }

        // The coinbase.
        let mut coinbase_tx = create_coinbase_tx(
            &mut self.subsidy_cache,
            &coinbase_script,
            &op_return_pk_script,
            next_block_height,
            pay_to_address,
            voters as u16,
            self.params,
            is_treasury_enabled,
            subsidy_split_variant,
        );
        let coinbase_hash = coinbase_tx.tx_hash();
        let num_coinbase_sig_ops =
            self.chain
                .count_sig_ops(&coinbase_tx, true, false, is_treasury_enabled);
        block_size += coinbase_tx.serialize_size() as u32;
        // Only consumed by dcrd's final debug log.
        block_sig_ops += num_coinbase_sig_ops;
        let _ = block_sig_ops;
        tx_fees_map.insert(coinbase_hash.0, 0);
        tx_sig_op_counts_map.insert(coinbase_hash.0, num_coinbase_sig_ops);
        if let Some(tb) = &treasury_base {
            let tb_hash = tb.tx_hash();
            tx_fees_map.insert(tb_hash.0, 0);
            let n = self
                .chain
                .count_sig_ops(tb, true, false, is_treasury_enabled);
            tx_sig_op_counts_map.insert(tb_hash.0, n);
        }

        // Assemble the regular tree.
        let mut block_txns_regular: Vec<MsgTx> = Vec::with_capacity(block_txns.len() + 1);
        let mut block_txns_regular_hashes: Vec<Hash> = Vec::with_capacity(block_txns.len() + 1);
        block_txns_regular.push(coinbase_tx.clone());
        block_txns_regular_hashes.push(coinbase_hash);
        for tx_desc in &block_txns {
            if tx_desc.tree == dcroxide_wire::TX_TREE_REGULAR {
                block_txns_regular.push(tx_desc.tx.clone());
                block_txns_regular_hashes.push(tx_desc.tx_hash);
            }
        }

        for tx_hash in &block_txns_regular_hashes {
            let fee = *tx_fees_map
                .get(&tx_hash.0)
                .ok_or_else(|| format!("couldn't find fee for tx {tx_hash}"))?;
            total_fees += fee;
            tx_fees.push(fee);
            let tsos = *tx_sig_op_counts_map
                .get(&tx_hash.0)
                .ok_or_else(|| format!("couldn't find sig ops count for tx {tx_hash}"))?;
            tx_sig_op_counts.push(tsos);
        }
        for tx in &block_txns_stake {
            let tx_hash = tx.tx_hash();
            let fee = *tx_fees_map
                .get(&tx_hash.0)
                .ok_or_else(|| format!("couldn't find fee for stx {tx_hash}"))?;
            total_fees += fee;
            tx_fees.push(fee);
            let tsos = *tx_sig_op_counts_map
                .get(&tx_hash.0)
                .ok_or_else(|| format!("couldn't find sig ops count for stx {tx_hash}"))?;
            tx_sig_op_counts.push(tsos);
        }

        // Scale the fees by the voter participation.
        if next_block_height >= stake_validation_height {
            total_fees *= voters as i64;
            total_fees /= i64::from(self.params.tickets_per_block);
        }

        // dcrd appends the coinbase sigop count a second time here.
        tx_sig_op_counts.push(num_coinbase_sig_ops);

        if next_block_height > 1 {
            block_size -= MAX_VAR_INT_PAYLOAD
                - dcroxide_wire::var_int_serialize_size(
                    (block_txns_regular.len() + block_txns_stake.len()) as u64,
                ) as u32;

            // Add the fees to the miner payout.
            let pow_output_idx = if is_treasury_enabled { 1 } else { 2 };
            coinbase_tx.tx_out[pow_output_idx].value += total_fees;
            block_txns_regular[0] = coinbase_tx.clone();
            block_txns_regular_hashes[0] = coinbase_tx.tx_hash();
            tx_fees[0] = -total_fees;
        }
        let _ = block_size;

        let ts = self.median_adjusted_time();
        let req_difficulty = self
            .chain
            .calc_next_required_difficulty(&prev_hash, ts)
            .map_err(|e| format!("ErrGettingDifficulty: {e}"))?;

        // Return to the parent when there are too few voters.
        let minimum_votes_required = usize::from(self.params.tickets_per_block / 2 + 1);
        if next_block_height >= stake_validation_height && voters < minimum_votes_required {
            return self.handle_too_few_voters(
                next_block_height,
                pay_to_address,
                is_treasury_enabled,
                subsidy_split_variant,
                nonces,
            );
        }

        // Fill in the fraud proofs for the regular transactions from
        // the chain view, marking zero-conf inputs for the second
        // pass.
        if next_block_height != 1 {
            for i in 1..block_txns_regular.len() {
                let tx = block_txns_regular[i].clone();
                let tx_hash = block_txns_regular_hashes[i];
                let view = self
                    .chain
                    .fetch_utxo_view(
                        &tx,
                        &tx_hash,
                        dcroxide_wire::TX_TREE_REGULAR,
                        !known_disapproved,
                    )
                    .map_err(|e| format!("ErrFetchTxStore: {e}"))?;
                let tx_copy = &mut block_txns_regular[i];
                for tx_in in &mut tx_copy.tx_in {
                    match view.lookup_entry(&tx_in.previous_out_point) {
                        None => {
                            // Flag for the in-block pass below.
                            tx_in.block_index = dcroxide_wire::NULL_BLOCK_INDEX;
                        }
                        Some(entry) => {
                            tx_in.value_in = entry.amount();
                            tx_in.block_height = entry.block_height() as u32;
                            tx_in.block_index = entry.block_index();
                        }
                    }
                }
            }

            // Resolve the zero-conf fraud proofs against the block's
            // own regular tree.
            for i in 1..block_txns_regular.len() {
                let mut updates: Vec<(usize, i64, u32)> = Vec::new();
                for (in_idx, tx_in) in block_txns_regular[i].tx_in.iter().enumerate() {
                    if tx_in.block_index == dcroxide_wire::NULL_BLOCK_INDEX {
                        let Some(idx) = tx_index_from_tx_list(
                            &tx_in.previous_out_point.hash,
                            &block_txns_regular_hashes,
                        ) else {
                            return Err(format!(
                                "ErrFraudProofIndex: failed find hash in tx list for fraud \
                                 proof; tx in hash {}",
                                tx_in.previous_out_point.hash
                            ));
                        };
                        let origin_idx = tx_in.previous_out_point.index as usize;
                        let amt = block_txns_regular[idx].tx_out[origin_idx].value;
                        updates.push((in_idx, amt, idx as u32));
                    }
                }
                for (in_idx, amt, idx) in updates {
                    let tx_in = &mut block_txns_regular[i].tx_in[in_idx];
                    tx_in.value_in = amt;
                    tx_in.block_height = next_block_height as u32;
                    tx_in.block_index = idx;
                }
            }
        }

        // Choose the block version to generate based on the network
        // and figure out the stake version.
        let block_version = if self.params.net == dcroxide_wire::CurrencyNet::MAIN_NET {
            GENERATED_BLOCK_VERSION
        } else {
            GENERATED_BLOCK_VERSION_TEST
        };
        let generated_stake_version = self.chain.calc_stake_version_by_hash(&prev_hash)?;

        // Create a new block ready to be solved.
        let mut header = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header").0;
        header.version = block_version;
        header.prev_block = prev_hash;
        header.vote_bits = votebits;
        header.final_state = best.next_final_state;
        header.voters = voters as u16;
        header.fresh_stake = fresh_stake as u8;
        header.revocations = revocations as u8;
        header.pool_size = best.next_pool_size;
        header.timestamp = ts as u32;
        header.sbits = best.next_stake_diff;
        header.bits = req_difficulty;
        header.stake_version = generated_stake_version;
        header.height = next_block_height as u32;

        let mut msg_block = MsgBlock {
            header,
            transactions: block_txns_regular,
            stransactions: block_txns_stake,
        };

        let hdr_cmt_active = self.chain.is_header_commitments_agenda_active(&prev_hash)?;
        msg_block.header.merkle_root = calc_block_merkle_root(
            &msg_block.transactions,
            &msg_block.stransactions,
            hdr_cmt_active,
        );
        let cmt_root = if hdr_cmt_active {
            calc_block_commitment_root_v1(&msg_block, &ViewPrevScripter(&block_utxos))
                .map_err(|e| format!("ErrCalcCommitmentRoot: {e}"))?
        } else {
            dcroxide_standalone::calc_tx_tree_merkle_root(&msg_block.stransactions)
        };
        msg_block.header.stake_root = cmt_root;
        msg_block.header.size = msg_block.serialize().len() as u32;

        self.chain
            .check_connect_block_template(&msg_block)
            .map_err(|e| format!("ErrCheckConnectBlock: {e}"))?;

        Ok(Some(BlockTemplate {
            block: msg_block,
            fees: tx_fees,
            sig_op_counts: tx_sig_op_counts,
            height: next_block_height,
            valid_pay_address: pay_to_address.is_some(),
        }))
    }
}

/// A blockcf2 previous-script provider over a utxo view (the shape
/// dcrd's `UtxoViewpoint` provides via its `PrevScript` method).
pub struct ViewPrevScripter<'a>(pub &'a UtxoView);

impl dcroxide_gcs::blockcf2::PrevScripter for ViewPrevScripter<'_> {
    fn prev_script(&self, prev_out: &OutPoint) -> Option<(u16, &[u8])> {
        // dcrd's viewpoint serves scripts for spent entries too: the
        // template spends its own inputs in this view before the
        // commitment filter is built.
        let entry = self.0.lookup_entry(prev_out)?;
        Some((entry.script_version(), entry.pk_script()))
    }
}
