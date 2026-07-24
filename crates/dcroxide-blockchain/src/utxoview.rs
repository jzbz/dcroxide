// SPDX-License-Identifier: ISC
//! The unspent transaction output view (dcrd `utxoviewpoint.go`): the
//! in-memory set of utxo entries relevant to a block, with the
//! transaction and block connect/disconnect transitions producing and
//! consuming the spend journal.
//!
//! dcrd resolves entries missing from the view through its utxo cache
//! and database; here the callers supply a resolver closure returning
//! the backing entry for an outpoint (or `None` when it does not
//! exist), and the disapproved-parent disconnect takes the parent's
//! spend journal directly rather than fetching it.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use dcroxide_chainhash::Hash;
use dcroxide_stake::TxType;
use dcroxide_wire::{MsgBlock, MsgTx, OutPoint};

use crate::chainio::SpentTxOut;
use crate::utxoentry::{
    UTXO_STATE_MODIFIED, UTXO_STATE_SPENT, UTXO_STATE_SPENT_BY_ZERO_CONF, UtxoEntry,
    encode_utxo_flags, is_ticket_submission_output,
};
use crate::{RuleError, RuleErrorKind};

/// The key identifying an outpoint within the view.
pub type OutPointKey = ([u8; 32], u32, i8);

fn key(op: &OutPoint) -> OutPointKey {
    (op.hash.0, op.index, op.tree)
}

/// A resolver for entries missing from the view, standing in for
/// dcrd's utxo cache and database lookups.
pub trait UtxoResolver {
    /// The backing entry for the outpoint, if it exists.
    fn resolve(&self, outpoint: &OutPoint) -> Option<UtxoEntry>;
}

impl<F: Fn(&OutPoint) -> Option<UtxoEntry>> UtxoResolver for F {
    fn resolve(&self, outpoint: &OutPoint) -> Option<UtxoEntry> {
        self(outpoint)
    }
}

/// The number of utxos the regular transactions in the block spend
/// (dcrd `countSpentRegularOutputs`).
pub fn count_spent_regular_outputs(block: &MsgBlock) -> usize {
    // Skip the coinbase since it has no inputs.
    block.transactions[1..]
        .iter()
        .map(|tx| tx.tx_in.len())
        .sum()
}

/// The number of utxos the stake transactions in the block spend
/// (dcrd `countSpentStakeOutputs`).
pub fn count_spent_stake_outputs(block: &MsgBlock) -> usize {
    let mut num_spent = 0;
    for stx in &block.stransactions {
        if dcroxide_stake::is_ssgen(stx) {
            // Exclude the stakebase.
            num_spent += 1;
            continue;
        }
        if dcroxide_standalone::is_treasury_base(stx) || dcroxide_stake::is_tspend(stx) {
            continue;
        }
        num_spent += stx.tx_in.len();
    }
    num_spent
}

/// The number of utxos the passed block spends (dcrd
/// `countSpentOutputs`).
pub fn count_spent_outputs(block: &MsgBlock) -> usize {
    count_spent_regular_outputs(block) + count_spent_stake_outputs(block)
}

/// Whether the output is the treasury add change output, which is not
/// spendable through the utxo set (dcrd `isTreasuryAddOutput` checks
/// output zero, the amount destined for the treasury account).
fn is_treasury_add_output(tx_type: TxType, tx_out_idx: u32) -> bool {
    tx_type == TxType::TAdd && tx_out_idx == 0
}

/// Convert a view entry to its spend journal form (dcrd
/// `utxoEntryToSpentTxOut`).
pub fn entry_to_spent_tx_out(entry: &UtxoEntry) -> SpentTxOut {
    SpentTxOut {
        amount: entry.amount(),
        pk_script: entry.pk_script().to_vec(),
        ticket_min_outs: entry.ticket_minimal_outputs_data().map(|d| d.to_vec()),
        block_height: entry.block_height() as u32,
        block_index: entry.block_index(),
        script_version: entry.script_version(),
        packed_flags: encode_utxo_flags(
            entry.is_coin_base(),
            entry.has_expiry(),
            // The raw type bits survive like dcrd's unchecked cast.
            match entry.transaction_type() {
                0 => TxType::Regular,
                1 => TxType::SStx,
                2 => TxType::SSGen,
                3 => TxType::SSRtx,
                4 => TxType::TAdd,
                5 => TxType::TSpend,
                _ => TxType::TreasuryBase,
            },
        ),
    }
}

/// Compute the transaction hash of every transaction in the slice, in
/// order.  The connect and disconnect paths compute these once per
/// block tree and thread them through the helpers so no transaction
/// is re-serialized and re-hashed per use (dcrd wraps transactions in
/// `dcrutil.Tx`, which memoizes the hash).
pub fn collect_tx_hashes(txs: &[MsgTx]) -> Vec<Hash> {
    txs.iter().map(|tx| tx.tx_hash()).collect()
}

/// A view into the set of unspent transaction outputs from a specific
/// point of view in the chain (dcrd `UtxoViewpoint`).
#[derive(Default, Clone)]
pub struct UtxoView {
    entries: BTreeMap<OutPointKey, UtxoEntry>,
    best_hash: Hash,
}

impl UtxoView {
    /// A new empty view (dcrd `NewUtxoViewpoint`).
    pub fn new() -> UtxoView {
        UtxoView::default()
    }

    /// The hash of the best block in the chain the view represents
    /// (dcrd `BestHash`).
    pub fn best_hash(&self) -> Hash {
        self.best_hash
    }

    /// Set the best block hash (dcrd `SetBestHash`).
    pub fn set_best_hash(&mut self, hash: Hash) {
        self.best_hash = hash;
    }

    /// The entry for the outpoint, if present in the view (dcrd
    /// `LookupEntry`).
    pub fn lookup_entry(&self, outpoint: &OutPoint) -> Option<&UtxoEntry> {
        self.entries.get(&key(outpoint))
    }

    /// A mutable reference to the entry for the outpoint, if any
    /// (the mutable side of dcrd's `LookupEntry`, used by the mining
    /// code to mark template inputs spent).
    pub fn lookup_entry_mut(&mut self, outpoint: &OutPoint) -> Option<&mut UtxoEntry> {
        self.entries.get_mut(&key(outpoint))
    }

    /// Remove the entry for the outpoint (dcrd `RemoveEntry`).
    pub fn remove_entry(&mut self, outpoint: &OutPoint) {
        self.entries.remove(&key(outpoint));
    }

    /// Drain the view's committed changes with dcrd `UtxoCache.Commit`
    /// semantics: modified entries leave the view and are returned as
    /// upserts — spent ones as spent tombstones exactly like dcrd's
    /// cache retains them until its next flush, which is what allows
    /// later disconnects to restore the original entry fields —
    /// entries spent by a later transaction in the same block leave
    /// the view with no backing set effect, and unmodified entries
    /// stay in the view untouched.
    pub fn commit(&mut self) -> Vec<(OutPointKey, UtxoEntry)> {
        let mut updates = Vec::new();
        let keys: Vec<OutPointKey> = self.entries.keys().copied().collect();
        for key in keys {
            let entry = &self.entries[&key];
            if !entry.is_modified() {
                continue;
            }
            if entry.is_spent_by_zero_conf() {
                assert!(
                    entry.is_spent(),
                    "zero confirmation spend not also marked spent"
                );
                self.entries.remove(&key);
                continue;
            }
            let entry = self.entries.remove(&key).expect("present");
            updates.push((key, entry));
        }
        updates
    }

    /// Insert an entry directly; the resolver-driven analogue of
    /// dcrd's cache fetch populating the view.
    pub fn insert_entry(&mut self, outpoint: &OutPoint, entry: UtxoEntry) {
        self.entries.insert(key(outpoint), entry);
    }

    /// All entries in the view in key order, with their outpoints.
    pub fn entries(&self) -> impl Iterator<Item = (&OutPointKey, &UtxoEntry)> {
        self.entries.iter()
    }

    #[allow(clippy::too_many_arguments)]
    fn add_tx_out_raw(
        &mut self,
        outpoint: OutPoint,
        value: i64,
        version: u16,
        pk_script: &[u8],
        packed_flags: u8,
        block_height: i64,
        block_index: u32,
        ticket_min_outs: Option<Vec<u8>>,
    ) {
        // Unspendable outputs never make it into the view.
        if dcroxide_txscript::is_unspendable(value, pk_script) {
            return;
        }
        let entry = self.entries.entry(key(&outpoint)).or_insert_with(|| {
            UtxoEntry::new(0, Vec::new(), 0, 0, 0, false, false, TxType::Regular, None)
        });
        entry.amount = value;
        entry.block_height = block_height as u32;
        entry.block_index = block_index;
        entry.script_version = version;
        entry.packed_flags = packed_flags;
        entry.ticket_min_outs = ticket_min_outs;
        entry.state &= !(UTXO_STATE_SPENT | UTXO_STATE_SPENT_BY_ZERO_CONF);
        entry.state |= UTXO_STATE_MODIFIED;
        if entry.pk_script != pk_script {
            entry.pk_script = pk_script.to_vec();
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn add_tx_outs_internal(
        &mut self,
        tx: &MsgTx,
        tx_hash: &Hash,
        start: u32,
        end: u32,
        block_height: i64,
        block_index: u32,
        is_treasury_enabled: bool,
    ) {
        let is_coin_base = dcroxide_standalone::is_coin_base_tx(tx, is_treasury_enabled);
        let has_expiry = tx.expiry != dcroxide_wire::NO_EXPIRY_VALUE;
        let tx_type = dcroxide_stake::determine_tx_type(tx);
        let tree: i8 = if tx_type != TxType::Regular { 1 } else { 0 };
        let flags = encode_utxo_flags(is_coin_base, has_expiry, tx_type);
        for tx_out_idx in start..end {
            // The treasury add change output is not spendable.
            if is_treasury_add_output(tx_type, tx_out_idx) {
                continue;
            }
            // Ticket submission outputs carry the serialized minimal
            // outputs so votes and revocations can be validated.
            let ticket_min_outs = if is_ticket_submission_output(tx_type as u8, tx_out_idx) {
                let mut data =
                    alloc::vec![0u8; crate::chainio::serialize_size_for_minimal_outputs(tx)];
                crate::chainio::put_tx_to_minimal_outputs(&mut data, tx);
                Some(data)
            } else {
                None
            };
            let tx_out = &tx.tx_out[tx_out_idx as usize];
            let outpoint = OutPoint {
                hash: *tx_hash,
                index: tx_out_idx,
                tree,
            };
            self.add_tx_out_raw(
                outpoint,
                tx_out.value,
                tx_out.version,
                &tx_out.pk_script,
                flags,
                block_height,
                block_index,
                ticket_min_outs,
            );
        }
    }

    /// Add the specified output of the transaction to the view (dcrd
    /// `AddTxOut`).
    pub fn add_tx_out(
        &mut self,
        tx: &MsgTx,
        tx_out_idx: u32,
        block_height: i64,
        block_index: u32,
        is_treasury_enabled: bool,
    ) {
        if tx_out_idx >= tx.tx_out.len() as u32 {
            return;
        }
        self.add_tx_outs_internal(
            tx,
            &tx.tx_hash(),
            tx_out_idx,
            tx_out_idx + 1,
            block_height,
            block_index,
            is_treasury_enabled,
        );
    }

    /// Add all outputs of the transaction to the view (dcrd
    /// `AddTxOuts`).
    pub fn add_tx_outs(
        &mut self,
        tx: &MsgTx,
        block_height: i64,
        block_index: u32,
        is_treasury_enabled: bool,
    ) {
        self.add_tx_outs_with_hash(
            tx,
            &tx.tx_hash(),
            block_height,
            block_index,
            is_treasury_enabled,
        );
    }

    /// [`UtxoView::add_tx_outs`] with the transaction hash supplied
    /// by the caller, for the block connect and disconnect paths that
    /// compute each tree's hashes once per block.
    pub fn add_tx_outs_with_hash(
        &mut self,
        tx: &MsgTx,
        tx_hash: &Hash,
        block_height: i64,
        block_index: u32,
        is_treasury_enabled: bool,
    ) {
        self.add_tx_outs_internal(
            tx,
            tx_hash,
            0,
            tx.tx_out.len() as u32,
            block_height,
            block_index,
            is_treasury_enabled,
        );
    }

    fn assert_missing(outpoint: &OutPoint) -> RuleError {
        crate::ruleerror::rule_error(
            RuleErrorKind::UtxoBackendCorruption,
            alloc::format!("view missing input {outpoint:?}"),
        )
    }

    /// Connect a stake tree transaction, spending its inputs and
    /// adding its outputs (dcrd `connectStakeTransaction`).  The
    /// caller supplies the transaction's hash, computed once per
    /// block.
    pub fn connect_stake_transaction(
        &mut self,
        tx: &MsgTx,
        tx_hash: &Hash,
        block_height: i64,
        block_index: u32,
        mut stxos: Option<&mut Vec<SpentTxOut>>,
        is_treasury_enabled: bool,
    ) -> Result<(), RuleError> {
        // Treasurybases have no inputs to spend.
        if is_treasury_enabled && block_index == 0 {
            return Ok(());
        }
        // Treasury spends source from the treasury account.
        if is_treasury_enabled && dcroxide_stake::is_tspend(tx) {
            self.add_tx_outs_with_hash(tx, tx_hash, block_height, block_index, is_treasury_enabled);
            return Ok(());
        }
        let is_vote = dcroxide_stake::is_ssgen(tx);
        for (tx_in_idx, tx_in) in tx.tx_in.iter().enumerate() {
            // Votes have no input at the stakebase index.
            if is_vote && tx_in_idx == 0 {
                continue;
            }
            let prev_out = &tx_in.previous_out_point;
            let Some(entry) = self.entries.get_mut(&key(prev_out)) else {
                return Err(Self::assert_missing(prev_out));
            };
            if let Some(stxos) = stxos.as_deref_mut() {
                stxos.push(entry_to_spent_tx_out(entry));
            }
            entry.spend();
        }
        self.add_tx_outs_with_hash(tx, tx_hash, block_height, block_index, is_treasury_enabled);
        Ok(())
    }

    /// Connect every stake tree transaction of the block (dcrd
    /// `connectStakeTransactions`).  `stake_tx_hashes` carries the
    /// hash of each stake transaction, computed once per block.
    pub fn connect_stake_transactions(
        &mut self,
        block: &MsgBlock,
        stake_tx_hashes: &[Hash],
        mut stxos: Option<&mut Vec<SpentTxOut>>,
        is_treasury_enabled: bool,
    ) -> Result<(), RuleError> {
        debug_assert_eq!(
            block.stransactions.len(),
            stake_tx_hashes.len(),
            "one hash per stake transaction"
        );
        let height = i64::from(block.header.height);
        for (i, (tx, tx_hash)) in block.stransactions.iter().zip(stake_tx_hashes).enumerate() {
            self.connect_stake_transaction(
                tx,
                tx_hash,
                height,
                i as u32,
                stxos.as_deref_mut(),
                is_treasury_enabled,
            )?;
        }
        Ok(())
    }

    /// Connect a regular tree transaction, tracking in-flight spends
    /// of outputs created earlier in the same block (dcrd
    /// `connectRegularTransaction`).  The caller supplies the
    /// transaction's hash, computed once per block.
    #[allow(clippy::too_many_arguments)]
    pub fn connect_regular_transaction(
        &mut self,
        tx: &MsgTx,
        tx_hash: &Hash,
        block_height: i64,
        block_index: u32,
        in_flight_tx: &mut BTreeMap<[u8; 32], u32>,
        mut stxos: Option<&mut Vec<SpentTxOut>>,
        is_treasury_enabled: bool,
    ) -> Result<(), RuleError> {
        if dcroxide_standalone::is_coin_base_tx(tx, is_treasury_enabled) {
            self.add_tx_outs_with_hash(tx, tx_hash, block_height, block_index, is_treasury_enabled);
            in_flight_tx.insert(tx_hash.0, block_index);
            return Ok(());
        }
        for tx_in in &tx.tx_in {
            let prev_out = &tx_in.previous_out_point;
            let Some(entry) = self.entries.get_mut(&key(prev_out)) else {
                return Err(Self::assert_missing(prev_out));
            };
            if let Some(stxos) = stxos.as_deref_mut() {
                stxos.push(entry_to_spent_tx_out(entry));
            }
            entry.spend();
            // Mark spends of outputs created earlier in this block.
            if let Some(&in_flight_idx) = in_flight_tx.get(&prev_out.hash.0)
                && block_index > in_flight_idx
            {
                entry.state |= UTXO_STATE_SPENT_BY_ZERO_CONF;
            }
        }
        self.add_tx_outs_with_hash(tx, tx_hash, block_height, block_index, is_treasury_enabled);
        in_flight_tx.insert(tx_hash.0, block_index);
        Ok(())
    }

    /// Connect every regular tree transaction of the block (dcrd
    /// `connectRegularTransactions`).  `regular_tx_hashes` carries
    /// the hash of each regular transaction, computed once per block.
    pub fn connect_regular_transactions(
        &mut self,
        block: &MsgBlock,
        regular_tx_hashes: &[Hash],
        mut stxos: Option<&mut Vec<SpentTxOut>>,
        is_treasury_enabled: bool,
    ) -> Result<(), RuleError> {
        debug_assert_eq!(
            block.transactions.len(),
            regular_tx_hashes.len(),
            "one hash per regular transaction"
        );
        let height = i64::from(block.header.height);
        let mut in_flight_tx: BTreeMap<[u8; 32], u32> = BTreeMap::new();
        for (i, (tx, tx_hash)) in block.transactions.iter().zip(regular_tx_hashes).enumerate() {
            self.connect_regular_transaction(
                tx,
                tx_hash,
                height,
                i as u32,
                &mut in_flight_tx,
                stxos.as_deref_mut(),
                is_treasury_enabled,
            )?;
        }
        Ok(())
    }

    /// Disconnect one of the block's transaction trees, restoring the
    /// spent outputs from the spend journal (dcrd
    /// `disconnectTransactions`).  The create-if-missing map shape
    /// mirrors dcrd's.  `tx_hashes` carries the hash of each
    /// transaction in the tree being disconnected, computed once per
    /// block.
    #[allow(clippy::map_entry)]
    pub fn disconnect_transactions(
        &mut self,
        block: &MsgBlock,
        tx_hashes: &[Hash],
        stxos: &[SpentTxOut],
        stake_tree: bool,
        is_treasury_enabled: bool,
    ) -> Result<(), RuleError> {
        let num_spent_regular = count_spent_regular_outputs(block);
        let (mut stxo_idx, transactions) = if stake_tree {
            (
                stxos.len() as i64 - num_spent_regular as i64 - 1,
                &block.stransactions,
            )
        } else {
            (stxos.len() as i64 - 1, &block.transactions)
        };

        let mut spends_in_flight: BTreeMap<OutPointKey, usize> = BTreeMap::new();
        for tx_idx in (0..transactions.len()).rev() {
            let tx = &transactions[tx_idx];
            let tx_hash = tx_hashes[tx_idx];
            let tx_type = if stake_tree {
                dcroxide_stake::determine_tx_type(tx)
            } else {
                TxType::Regular
            };
            let is_vote = tx_type == TxType::SSGen;
            let mut is_treasury_base = false;
            let mut is_treasury_spend = false;
            if is_treasury_enabled {
                is_treasury_spend = tx_type == TxType::TSpend && stake_tree;
                is_treasury_base = tx_type == TxType::TreasuryBase && stake_tree && tx_idx == 0;
            }
            let tree: i8 = if tx_type != TxType::Regular { 1 } else { 0 };
            let is_coin_base = !stake_tree && tx_idx == 0;
            let has_expiry = tx.expiry != dcroxide_wire::NO_EXPIRY_VALUE;

            // Mark every spendable output of this transaction spent.
            for (tx_out_idx, tx_out) in tx.tx_out.iter().enumerate() {
                if dcroxide_txscript::is_unspendable(tx_out.value, &tx_out.pk_script) {
                    continue;
                }
                let outpoint = OutPoint {
                    hash: tx_hash,
                    index: tx_out_idx as u32,
                    tree,
                };
                let k = key(&outpoint);
                if !self.entries.contains_key(&k) {
                    let ticket_min_outs =
                        if is_ticket_submission_output(tx_type as u8, tx_out_idx as u32) {
                            let mut data = alloc::vec![
                                0u8;
                                crate::chainio::serialize_size_for_minimal_outputs(tx)
                            ];
                            crate::chainio::put_tx_to_minimal_outputs(&mut data, tx);
                            Some(data)
                        } else {
                            None
                        };
                    let mut entry = UtxoEntry::new(
                        tx_out.value,
                        tx_out.pk_script.clone(),
                        block.header.height,
                        tx_idx as u32,
                        tx_out.version,
                        is_coin_base,
                        has_expiry,
                        tx_type,
                        ticket_min_outs,
                    );
                    entry.state |= UTXO_STATE_MODIFIED;
                    self.entries.insert(k, entry);
                }
                let entry = self.entries.get_mut(&k).expect("just inserted");
                entry.spend();
                if let Some(&in_flight_idx) = spends_in_flight.get(&k)
                    && tx_idx < in_flight_idx
                {
                    entry.state |= UTXO_STATE_SPENT_BY_ZERO_CONF;
                }
            }

            // Coinbases, treasurybases, and treasury spends have no
            // inputs to restore.
            if is_coin_base || is_treasury_base || is_treasury_spend {
                continue;
            }

            // Restore the inputs from the journal in reverse order.
            for tx_in_idx in (0..tx.tx_in.len()).rev() {
                if is_vote && tx_in_idx == 0 {
                    continue;
                }
                let stxo = &stxos[stxo_idx as usize];
                stxo_idx -= 1;
                let tx_in = &tx.tx_in[tx_in_idx];
                let k = key(&tx_in.previous_out_point);
                if !self.entries.contains_key(&k) {
                    // Rebuild the entry from the journal, carrying the
                    // journal's packed flags through directly.
                    let mut entry = UtxoEntry::new(
                        tx_in.value_in,
                        stxo.pk_script.clone(),
                        stxo.block_height,
                        stxo.block_index,
                        stxo.script_version,
                        false,
                        false,
                        TxType::Regular,
                        stxo.ticket_min_outs.clone(),
                    );
                    entry.packed_flags = stxo.packed_flags;
                    self.entries.insert(k, entry);
                }
                let entry = self.entries.get_mut(&k).expect("just inserted");
                entry.state &= !(UTXO_STATE_SPENT | UTXO_STATE_SPENT_BY_ZERO_CONF);
                entry.state |= UTXO_STATE_MODIFIED;
                if !stake_tree {
                    spends_in_flight.insert(k, tx_idx);
                }
            }
        }
        Ok(())
    }

    fn resolve_missing(&mut self, resolver: &impl UtxoResolver, outpoint: &OutPoint) {
        let k = key(outpoint);
        if self.entries.contains_key(&k) {
            return;
        }
        if let Some(entry) = resolver.resolve(outpoint) {
            self.entries.insert(k, entry);
        }
    }

    /// Load the utxos for the regular transactions' inputs into the
    /// view, adding outputs created earlier in the same block directly
    /// (dcrd `fetchRegularInputUtxos` over the resolver).
    /// `regular_tx_hashes` carries the hash of each regular
    /// transaction, computed once per block.
    pub fn fetch_regular_input_utxos(
        &mut self,
        block: &MsgBlock,
        regular_tx_hashes: &[Hash],
        resolver: &impl UtxoResolver,
        is_treasury_enabled: bool,
    ) {
        let height = i64::from(block.header.height);
        let mut tx_in_flight: BTreeMap<[u8; 32], usize> = BTreeMap::new();
        for (i, tx_hash) in regular_tx_hashes.iter().enumerate() {
            tx_in_flight.insert(tx_hash.0, i);
        }
        for (i, tx) in block.transactions.iter().enumerate().skip(1) {
            for tx_in in &tx.tx_in {
                let origin_hash = &tx_in.previous_out_point.hash;
                if let Some(&in_flight_index) = tx_in_flight.get(&origin_hash.0) {
                    // NOTE: dcrd compares the enumeration index of the
                    // slice that skips the coinbase, so an input can
                    // reference the output of the transaction at the
                    // next index; reproduced exactly.
                    // dcrd compares the coinbase-skipping slice index,
                    // equivalent to i - 1 >= in_flight_index here.
                    if i > in_flight_index {
                        let origin_tx = &block.transactions[in_flight_index];
                        self.add_tx_outs_with_hash(
                            origin_tx,
                            &regular_tx_hashes[in_flight_index],
                            height,
                            in_flight_index as u32,
                            is_treasury_enabled,
                        );
                        continue;
                    }
                }
                self.resolve_missing(resolver, &tx_in.previous_out_point);
            }
        }
    }

    /// Load the utxos for all of the block's inputs into the view
    /// (dcrd `fetchInputUtxos` over the resolver).
    /// `regular_tx_hashes` carries the hash of each regular
    /// transaction, computed once per block; the stake tree only
    /// resolves inputs and needs no hashes.
    pub fn fetch_input_utxos(
        &mut self,
        block: &MsgBlock,
        regular_tx_hashes: &[Hash],
        resolver: &impl UtxoResolver,
        is_treasury_enabled: bool,
    ) {
        self.fetch_regular_input_utxos(block, regular_tx_hashes, resolver, is_treasury_enabled);
        for (tx_idx, stx) in block.stransactions.iter().enumerate() {
            let should_be_treasury_base = is_treasury_enabled && tx_idx == 0;
            if should_be_treasury_base && dcroxide_standalone::is_treasury_base(stx) {
                continue;
            }
            if is_treasury_enabled && dcroxide_stake::is_tspend(stx) {
                continue;
            }
            let is_vote = dcroxide_stake::is_ssgen(stx);
            for (tx_in_idx, tx_in) in stx.tx_in.iter().enumerate() {
                if is_vote && tx_in_idx == 0 {
                    continue;
                }
                self.resolve_missing(resolver, &tx_in.previous_out_point);
            }
        }
    }

    /// Disconnect the regular transactions of a disapproved parent
    /// block, given its spend journal (dcrd
    /// `disconnectDisapprovedBlock` with the journal supplied by the
    /// caller).
    pub fn disconnect_disapproved_block(
        &mut self,
        parent: &MsgBlock,
        parent_stxos: &[SpentTxOut],
        resolver: &impl UtxoResolver,
        is_treasury_enabled: bool,
    ) -> Result<(), RuleError> {
        let parent_regular_tx_hashes = collect_tx_hashes(&parent.transactions);
        self.fetch_regular_input_utxos(
            parent,
            &parent_regular_tx_hashes,
            resolver,
            is_treasury_enabled,
        );
        assert_eq!(
            parent_stxos.len(),
            count_spent_outputs(parent),
            "provided stxos do not match the outputs the parent spends"
        );
        self.disconnect_transactions(
            parent,
            &parent_regular_tx_hashes,
            parent_stxos,
            false,
            is_treasury_enabled,
        )
    }

    /// Update the view to represent connecting the passed block,
    /// undoing the parent's regular transactions first when the block
    /// disapproves it (dcrd `connectBlock`).
    ///
    /// The parent's spend journal is only needed to undo a disapproved
    /// parent, so it is supplied lazily and decoded solely on that
    /// path — matching dcrd, which fetches it inside `connectBlock`
    /// only when the block disapproves its parent rather than eagerly
    /// at every caller.  This avoids decoding the parent journal with
    /// the wrong treasury flag on the common approve path (the child's
    /// flag differs from the parent's exactly at the treasury agenda
    /// activation boundary).
    pub fn connect_block(
        &mut self,
        block: &MsgBlock,
        parent: &MsgBlock,
        parent_stxos: impl FnOnce() -> Vec<SpentTxOut>,
        resolver: &impl UtxoResolver,
        mut stxos: Option<&mut Vec<SpentTxOut>>,
        is_treasury_enabled: bool,
    ) -> Result<(), RuleError> {
        if !crate::validate::header_approves_parent(&block.header) {
            let parent_stxos = parent_stxos();
            self.disconnect_disapproved_block(
                parent,
                &parent_stxos,
                resolver,
                is_treasury_enabled,
            )?;
        }
        let regular_tx_hashes = collect_tx_hashes(&block.transactions);
        let stake_tx_hashes = collect_tx_hashes(&block.stransactions);
        self.fetch_input_utxos(block, &regular_tx_hashes, resolver, is_treasury_enabled);
        self.connect_stake_transactions(
            block,
            &stake_tx_hashes,
            stxos.as_deref_mut(),
            is_treasury_enabled,
        )?;
        self.connect_regular_transactions(block, &regular_tx_hashes, stxos, is_treasury_enabled)?;
        self.set_best_hash(block.header.block_hash());
        Ok(())
    }

    /// Update the view to represent disconnecting the passed block,
    /// reconnecting the parent's regular transactions when the block
    /// disapproved them (dcrd `disconnectBlock`).
    pub fn disconnect_block(
        &mut self,
        block: &MsgBlock,
        parent: &MsgBlock,
        stxos: &[SpentTxOut],
        resolver: &impl UtxoResolver,
        is_treasury_enabled: bool,
    ) -> Result<(), RuleError> {
        assert_eq!(
            stxos.len(),
            count_spent_outputs(block),
            "provided stxos do not match the outputs the block spends"
        );
        let regular_tx_hashes = collect_tx_hashes(&block.transactions);
        let stake_tx_hashes = collect_tx_hashes(&block.stransactions);
        self.fetch_input_utxos(block, &regular_tx_hashes, resolver, is_treasury_enabled);
        self.disconnect_transactions(block, &regular_tx_hashes, stxos, false, is_treasury_enabled)?;
        self.disconnect_transactions(block, &stake_tx_hashes, stxos, true, is_treasury_enabled)?;
        if !crate::validate::header_approves_parent(&block.header) {
            let parent_regular_tx_hashes = collect_tx_hashes(&parent.transactions);
            self.fetch_regular_input_utxos(
                parent,
                &parent_regular_tx_hashes,
                resolver,
                is_treasury_enabled,
            );
            self.connect_regular_transactions(
                parent,
                &parent_regular_tx_hashes,
                None,
                is_treasury_enabled,
            )?;
        }
        self.set_best_hash(block.header.prev_block);
        Ok(())
    }
}
