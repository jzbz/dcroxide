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
use core::cmp::Ordering;

use dcroxide_chaincfg::Params;
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

/// An [`OutPointKey`] as the UTXO maps hold it: the same key, with the
/// comparison their searches run written out.
///
/// The order is the tuple's own: the hash bytes, then the output index,
/// then the tree.  It has to be, because both maps are walked in it:
/// the view hands its changes to the cache in key order, and the cache
/// writes the rows of a flush in key order.  The tuple's derived
/// comparison goes through the C library's `memcmp` for the 32 hash
/// bytes, a call for every key that a descent of either map visits.
/// This one reads the hash as four big-endian words, which compare as
/// the bytes they are made of do, and is inlined into the search.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UtxoKey(pub(crate) OutPointKey);

impl Ord for UtxoKey {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        let (hash, index, tree) = &self.0;
        let (other_hash, other_index, other_tree) = &other.0;
        let (words, _) = hash.as_chunks::<8>();
        let (other_words, _) = other_hash.as_chunks::<8>();
        for (word, other_word) in words.iter().zip(other_words) {
            // Big-endian, so the first byte that differs decides, as
            // it does between the byte strings.
            let word = u64::from_be_bytes(*word);
            let other_word = u64::from_be_bytes(*other_word);
            if word != other_word {
                return word.cmp(&other_word);
            }
        }
        index.cmp(other_index).then(tree.cmp(other_tree))
    }
}

impl PartialOrd for UtxoKey {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn key(op: &OutPoint) -> UtxoKey {
    UtxoKey((op.hash.0, op.index, op.tree))
}

/// A resolver for entries missing from the view, standing in for
/// dcrd's utxo cache and database lookups.
pub trait UtxoResolver {
    /// The backing entry for the outpoint, if it exists.
    fn resolve(&self, outpoint: &OutPoint) -> Option<UtxoEntry>;

    /// The backing entries for a batch of outpoints, one result per
    /// outpoint in order.  The default resolves each outpoint
    /// individually; database-backed resolvers override this to read
    /// every miss of a block in a single database transaction
    /// (mirroring dcrd's `UtxoCache.FetchEntries`, which serves the
    /// whole filtered set in one call — its leveldb backend needs no
    /// per-read transaction, the redb-backed store amortizes one).
    fn resolve_batch(&self, outpoints: &[OutPoint]) -> Vec<Option<UtxoEntry>> {
        outpoints.iter().map(|op| self.resolve(op)).collect()
    }
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
#[allow(
    clippy::arithmetic_side_effects,
    reason = "counts the block's in-memory stake transactions and their inputs, each at least one byte, so the sum fits usize"
)]
pub fn count_spent_stake_outputs(block: &MsgBlock) -> usize {
    let mut num_spent = 0;
    for stx in &block.stransactions {
        if dcroxide_stake::is_ssgen(stx) {
            // Exclude the stakebase.
            num_spent += 1;
            continue;
        }
        // Exclude treasurybases and treasury spends since neither has
        // any inputs.  dcrd uses the strict stake.IsTreasuryBase here
        // (chain.go:966), not the minimal standalone check.
        if dcroxide_stake::is_treasury_base(stx) || dcroxide_stake::is_tspend(stx) {
            continue;
        }
        num_spent += stx.tx_in.len();
    }
    num_spent
}

/// The number of utxos the passed block spends (dcrd
/// `countSpentOutputs`).
#[allow(
    clippy::arithmetic_side_effects,
    reason = "both counts are of the block's in-memory transactions and inputs, each at least one byte, so the sum fits usize"
)]
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
        // dcrd encodes `encodeFlags(IsCoinBase(), HasExpiry(),
        // TransactionType())` (utxoviewpoint.go:246-247), and
        // `TransactionType` is an unchecked cast of the raw type bits,
        // so every value 0-15 survives into the journal.  The txout
        // flags share the utxo flags' layout (bit 0 coinbase, bit 1
        // expiry, bits 2-5 type), which makes that encoding exactly
        // the entry's low six bits.
        packed_flags: entry.packed_flags & 0x3f,
    }
}

/// Compute the transaction hash of every transaction in the slice, in
/// order.  The disconnect paths compute these once per block tree and
/// thread them through the helpers so no transaction is re-serialized
/// and re-hashed per use (dcrd wraps transactions in `dcrutil.Tx`,
/// which memoizes the hash).  The connect paths are handed a
/// [`crate::blockhashes::BlockTxHashes`] instead.
pub fn collect_tx_hashes(txs: &[MsgTx]) -> Vec<Hash> {
    txs.iter().map(|tx| tx.tx_hash()).collect()
}

/// A view into the set of unspent transaction outputs from a specific
/// point of view in the chain (dcrd `UtxoViewpoint`).
#[derive(Default, Clone)]
pub struct UtxoView {
    entries: BTreeMap<UtxoKey, UtxoEntry>,
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
        // One pass over the map in key order, taking each entry out as
        // it is reached, so no entry is searched for and the map is not
        // rebalanced around each removal.  The view of a connected
        // block holds little but modified entries; the unmodified ones
        // go back in, in the order they came out.
        let mut updates = Vec::with_capacity(self.entries.len());
        for (key, entry) in core::mem::take(&mut self.entries) {
            if !entry.is_modified() {
                self.entries.insert(key, entry);
                continue;
            }
            if entry.is_spent_by_zero_conf() {
                assert!(
                    entry.is_spent(),
                    "zero confirmation spend not also marked spent"
                );
                continue;
            }
            updates.push((key.0, entry));
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
        self.entries.iter().map(|(key, entry)| (&key.0, entry))
    }

    /// Add the outputs `start..end` of the transaction that are not
    /// provably unspendable to the view (dcrd `addTxOuts`,
    /// `utxoviewpoint.go:92-162`, the common body of `AddTxOut` and
    /// `AddTxOuts`).  An output the view already holds is marked
    /// unspent and has every field rewritten, since a reorganization
    /// can replace it with a different transaction of the same hash.
    /// The caller must have checked that the range exists.
    ///
    /// The unspendable test comes before the ticket minimal outputs
    /// are built, so an unspendable output costs no serialization, as
    /// in dcrd since `248a9d40`.
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
            // Unspendable outputs never make it into the view.
            let tx_out = &tx.tx_out[tx_out_idx as usize];
            if dcroxide_txscript::is_unspendable(tx_out.value, &tx_out.pk_script) {
                continue;
            }
            let outpoint = OutPoint {
                hash: *tx_hash,
                index: tx_out_idx,
                tree,
            };
            let entry = self.entries.entry(key(&outpoint)).or_insert_with(|| {
                UtxoEntry::new(0, Vec::new(), 0, 0, 0, false, false, TxType::Regular, None)
            });
            entry.amount = tx_out.value;
            entry.block_height = block_height as u32;
            entry.block_index = block_index;
            entry.script_version = tx_out.version;
            entry.packed_flags = flags;
            // Ticket submission outputs carry the serialized minimal
            // outputs so votes and revocations can be validated.
            entry.ticket_min_outs = if is_ticket_submission_output(tx_type as u8, tx_out_idx) {
                let mut data =
                    alloc::vec![0u8; crate::chainio::serialize_size_for_minimal_outputs(tx)];
                crate::chainio::put_tx_to_minimal_outputs(&mut data, tx);
                Some(data)
            } else {
                None
            };
            // The output is always unspent and modified once added.
            entry.state &= !(UTXO_STATE_SPENT | UTXO_STATE_SPENT_BY_ZERO_CONF);
            entry.state |= UTXO_STATE_MODIFIED;
            if entry.pk_script != tx_out.pk_script {
                entry.pk_script = tx_out.pk_script.clone();
            }
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
        self.add_tx_out_with_hash(
            tx,
            &tx.tx_hash(),
            tx_out_idx,
            block_height,
            block_index,
            is_treasury_enabled,
        );
    }

    /// [`Self::add_tx_out`] with the transaction's hash supplied by a
    /// caller that already has it (dcrd's `dcrutil.Tx` memoizes the
    /// hash; the port passes it along instead of recomputing it).  An
    /// out-of-range output index adds nothing, as in dcrd `AddTxOut`.
    pub fn add_tx_out_with_hash(
        &mut self,
        tx: &MsgTx,
        tx_hash: &Hash,
        tx_out_idx: u32,
        block_height: i64,
        block_index: u32,
        is_treasury_enabled: bool,
    ) {
        if tx_out_idx >= tx.tx_out.len() as u32 {
            return;
        }
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "tx_out_idx < tx.tx_out.len() as u32 <= u32::MAX was checked above, so tx_out_idx + 1 fits u32"
        )]
        self.add_tx_outs_internal(
            tx,
            tx_hash,
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

    /// The internal-consistency assertion dcrd raises when the view
    /// lost an input it was asked to spend (`utxoviewpoint.go:290-294`,
    /// `connectTransaction`).
    ///
    /// dcrd renders this through `AssertError`, whose `Error()`
    /// prefixes `assertion failed: ` (`error.go:17-25`), and formats
    /// the outpoint as `hash:index` via `wire.OutPoint.String`.  The
    /// port has no separate assertion type -- it carries dcrd's
    /// `ErrUtxoBackendCorruption` kind, which `is_rule_violation`
    /// classifies out of the peer-blaming branch -- but the text can
    /// match, so it does.
    fn assert_missing(outpoint: &OutPoint) -> RuleError {
        crate::ruleerror::rule_error(
            RuleErrorKind::UtxoBackendCorruption,
            alloc::format!("assertion failed: view missing input {outpoint}"),
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
    /// transaction's hash, computed once per block.  Spends of
    /// in-flight outputs are marked as zero-confirmation spends only
    /// when `mark_zero_conf` is set, which callers derive from whether
    /// the block approves its parent.
    #[allow(clippy::too_many_arguments)]
    pub fn connect_regular_transaction(
        &mut self,
        tx: &MsgTx,
        tx_hash: &Hash,
        block_height: i64,
        block_index: u32,
        in_flight_tx: &mut BTreeMap<[u8; 32], u32>,
        mark_zero_conf: bool,
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
            if mark_zero_conf
                && let Some(&in_flight_idx) = in_flight_tx.get(&prev_out.hash.0)
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
        let mark_zero_conf = crate::validate::header_approves_parent(&block.header);
        let mut in_flight_tx: BTreeMap<[u8; 32], u32> = BTreeMap::new();
        for (i, (tx, tx_hash)) in block.transactions.iter().zip(regular_tx_hashes).enumerate() {
            self.connect_regular_transaction(
                tx,
                tx_hash,
                height,
                i as u32,
                &mut in_flight_tx,
                mark_zero_conf,
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
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "stxos.len() and num_spent_regular count in-memory items, at most isize::MAX each, so the differences minus 1 fit i64"
        )]
        let (mut stxo_idx, transactions) = if stake_tree {
            (
                stxos.len() as i64 - num_spent_regular as i64 - 1,
                &block.stransactions,
            )
        } else {
            (stxos.len() as i64 - 1, &block.transactions)
        };

        let mut spends_in_flight: BTreeMap<UtxoKey, usize> = BTreeMap::new();
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
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "stxo_idx indexes stxos just before each decrement, so it is >= 0 there and stxo_idx - 1 >= -1"
            )]
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

    /// Queue an outpoint whose entry is missing from the view for a
    /// batched resolve (the `add` of dcrd's `ViewFilteredSet`:
    /// outpoints already in the view are skipped).  Duplicates within
    /// a block are not filtered here: they only arise from invalid
    /// blocks, and [`Self::resolve_queued`] writes the same backend
    /// result for each copy, so a set and a list resolve alike.
    fn queue_missing(&self, needed: &mut Vec<OutPoint>, outpoint: &OutPoint) {
        if self.entries.contains_key(&key(outpoint)) {
            return;
        }
        needed.push(*outpoint);
    }

    /// Resolve the queued outpoints in one batch and write each result
    /// into the view (the resolve half of dcrd's `fetchUtxosMain` over
    /// `UtxoCache.FetchEntries`).
    ///
    /// The write is unconditional, as in dcrd: an entry that exists is
    /// inserted over whatever the view holds, and a missing one
    /// removes it (an absent entry is the port's form of dcrd's nil
    /// entry).  The overwrite matters for a forward reference, an input
    /// that spends an output of a transaction later in the same block:
    /// it is queued because the output is not in the view yet, and a
    /// later input that legitimately spends the same origin can then
    /// add that output before the resolve runs.  dcrd resets it to the
    /// backend's nil, so the forward reference fails with
    /// `ErrMissingTxOut`; keeping the in-flight entry instead would let
    /// the earlier transaction spend an output its origin re-adds as
    /// unspent when it connects.
    fn resolve_queued(&mut self, resolver: &impl UtxoResolver, needed: &[OutPoint]) {
        if needed.is_empty() {
            return;
        }
        let resolved = resolver.resolve_batch(needed);
        debug_assert_eq!(needed.len(), resolved.len(), "resolver batch size mismatch");
        for (outpoint, entry) in needed.iter().zip(resolved) {
            let k = key(outpoint);
            match entry {
                Some(entry) => {
                    self.entries.insert(k, entry);
                }
                None => {
                    self.entries.remove(&k);
                }
            }
        }
    }

    /// Queue the missing utxos for the regular transactions' inputs,
    /// adding outputs created earlier in the same block to the view
    /// directly (the set-construction half of dcrd
    /// `fetchRegularInputUtxos`).  `regular_tx_hashes` carries the
    /// hash of each regular transaction, computed once per block.
    fn queue_regular_input_utxos(
        &mut self,
        block: &MsgBlock,
        regular_tx_hashes: &[Hash],
        needed: &mut Vec<OutPoint>,
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
                    // Only a transaction earlier in the block may be
                    // referenced.  dcrd compares the index of the
                    // coinbase-skipping slice (`i >= inFlightIndex`),
                    // which is one less than the block position used
                    // here, so the two comparisons are the same rule.
                    if i > in_flight_index {
                        // Add only the referenced output (dcrd
                        // `AddTxOut(originTx, originIdx)`, since
                        // 01208035).  Adding every output would also
                        // mark unspent any sibling output a disapproved
                        // parent's disconnect left spent in the view,
                        // and it would keep such siblings out of the
                        // fetch set, where dcrd resolves them to nil.
                        let origin_tx = &block.transactions[in_flight_index];
                        self.add_tx_out_with_hash(
                            origin_tx,
                            &regular_tx_hashes[in_flight_index],
                            tx_in.previous_out_point.index,
                            height,
                            in_flight_index as u32,
                            is_treasury_enabled,
                        );
                        continue;
                    }
                }
                self.queue_missing(needed, &tx_in.previous_out_point);
            }
        }
    }

    /// Queue the missing utxos for the stake transactions' inputs
    /// (the stake half of dcrd `fetchInputUtxos`'s set construction).
    fn queue_stake_input_utxos(
        &self,
        block: &MsgBlock,
        needed: &mut Vec<OutPoint>,
        is_treasury_enabled: bool,
    ) {
        for (tx_idx, stx) in block.stransactions.iter().enumerate() {
            // Treasurybases and treasury spends have no inputs.  dcrd
            // uses the strict stake.IsTreasuryBase here
            // (utxoviewpoint.go:904), not the minimal standalone check.
            let should_be_treasury_base = is_treasury_enabled && tx_idx == 0;
            if should_be_treasury_base && dcroxide_stake::is_treasury_base(stx) {
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
                self.queue_missing(needed, &tx_in.previous_out_point);
            }
        }
    }

    /// Load the utxos for the regular transactions' inputs into the
    /// view, adding outputs created earlier in the same block directly
    /// (dcrd `fetchRegularInputUtxos` over the resolver: the missing
    /// outpoints collect into one set and resolve in one batch).
    /// `regular_tx_hashes` carries the hash of each regular
    /// transaction, computed once per block.
    pub fn fetch_regular_input_utxos(
        &mut self,
        block: &MsgBlock,
        regular_tx_hashes: &[Hash],
        resolver: &impl UtxoResolver,
        is_treasury_enabled: bool,
    ) {
        let mut needed = Vec::new();
        self.queue_regular_input_utxos(block, regular_tx_hashes, &mut needed, is_treasury_enabled);
        self.resolve_queued(resolver, &needed);
    }

    /// Load the utxos for all of the block's inputs into the view
    /// (dcrd `fetchInputUtxos` over the resolver: every missing
    /// outpoint across both trees resolves in one batch, so a
    /// database-backed resolver reads them all in one transaction).
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
        let mut needed = Vec::new();
        self.queue_regular_input_utxos(block, regular_tx_hashes, &mut needed, is_treasury_enabled);
        self.queue_stake_input_utxos(block, &mut needed, is_treasury_enabled);
        self.resolve_queued(resolver, &needed);
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

    /// Add the output that older consensus rules let a stake
    /// transaction spend in the block that created it, when the block
    /// is at a height that has one (dcrd `addSBSSViolations`,
    /// `utxoviewpoint.go:613-631`): output 0 of the regular
    /// transaction [`crate::validate::sbss_violation_hash`] names for
    /// the network and height.  Without it the block, which is part of
    /// the network's history, would be rejected.  Callers add it after
    /// any undo of a disapproved parent and before the block's inputs
    /// are fetched, so it is already in the view when the fetch runs.
    pub(crate) fn add_sbss_violations(
        &mut self,
        params: &Params,
        block: &MsgBlock,
        regular_tx_hashes: &[Hash],
        is_treasury_enabled: bool,
    ) {
        self.add_sbss_violations_with(
            &sbss_violation_lookup(params),
            block,
            regular_tx_hashes,
            is_treasury_enabled,
        );
    }

    /// [`Self::add_sbss_violations`] over the given lookup of the
    /// violating transaction's hash by height.
    fn add_sbss_violations_with(
        &mut self,
        sbss_violation: &impl Fn(i64) -> Option<Hash>,
        block: &MsgBlock,
        regular_tx_hashes: &[Hash],
        is_treasury_enabled: bool,
    ) {
        // Nothing to do for blocks that do not have a violation.
        let height = i64::from(block.header.height);
        let Some(violation_hash) = sbss_violation(height) else {
            return;
        };
        for (idx, (tx, tx_hash)) in block.transactions.iter().zip(regular_tx_hashes).enumerate() {
            if *tx_hash == violation_hash {
                self.add_tx_out_with_hash(tx, tx_hash, 0, height, idx as u32, is_treasury_enabled);
                return;
            }
        }
    }

    /// Mark spent the output [`Self::add_sbss_violations`] adds, once
    /// the block that holds it has been disconnected, so the disconnect
    /// does not leave it in the set (dcrd `removeSBSSViolations`,
    /// `utxoviewpoint.go:974-1004`): the disconnect of the stake tree
    /// restores it as an input of the stake transaction that spent it.
    ///
    /// # Panics
    ///
    /// When the output is missing from the view, with dcrd's text.
    fn remove_sbss_violations_with(
        &mut self,
        sbss_violation: &impl Fn(i64) -> Option<Hash>,
        block: &MsgBlock,
        regular_tx_hashes: &[Hash],
    ) {
        // Nothing to do for blocks that do not have a violation.
        let height = i64::from(block.header.height);
        let Some(violation_hash) = sbss_violation(height) else {
            return;
        };
        if !regular_tx_hashes.contains(&violation_hash) {
            return;
        }
        let out = OutPoint {
            hash: violation_hash,
            index: 0,
            tree: 0,
        };
        let Some(entry) = self.entries.get_mut(&key(&out)) else {
            panic!(
                "SBS spend violation output {out} for block {} (height {height}) is missing \
                 from the view after disconnecting it",
                block.header.block_hash()
            );
        };
        entry.spend();
    }

    /// Update the view to represent connecting the passed block,
    /// undoing the parent's regular transactions first when the block
    /// disapproves it, and adding the output a grandfathered same-block
    /// stake spend needs before the inputs are fetched (dcrd
    /// `connectBlock`).
    ///
    /// The parent's spend journal is only needed to undo a disapproved
    /// parent, so it is supplied lazily and decoded solely on that
    /// path — matching dcrd, which fetches it inside `connectBlock`
    /// only when the block disapproves its parent rather than eagerly
    /// at every caller.  This avoids decoding the parent journal with
    /// the wrong treasury flag on the common approve path (the child's
    /// flag differs from the parent's exactly at the treasury agenda
    /// activation boundary).
    #[allow(clippy::too_many_arguments)]
    pub fn connect_block(
        &mut self,
        params: &Params,
        block: &MsgBlock,
        parent: &MsgBlock,
        parent_stxos: impl FnOnce() -> Result<Vec<SpentTxOut>, RuleError>,
        resolver: &impl UtxoResolver,
        stxos: Option<&mut Vec<SpentTxOut>>,
        is_treasury_enabled: bool,
    ) -> Result<(), RuleError> {
        let tx_hashes = crate::blockhashes::BlockTxHashes::compute(block);
        self.connect_block_with_hashes(
            params,
            block,
            &tx_hashes,
            parent,
            parent_stxos,
            resolver,
            stxos,
            is_treasury_enabled,
        )
    }

    /// [`Self::connect_block`] given the hashes of the block's
    /// transactions (dcrd `connectBlock` reading them from its
    /// `dcrutil.Block`), which must have been computed from this very
    /// block.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn connect_block_with_hashes(
        &mut self,
        params: &Params,
        block: &MsgBlock,
        tx_hashes: &crate::blockhashes::BlockTxHashes,
        parent: &MsgBlock,
        parent_stxos: impl FnOnce() -> Result<Vec<SpentTxOut>, RuleError>,
        resolver: &impl UtxoResolver,
        stxos: Option<&mut Vec<SpentTxOut>>,
        is_treasury_enabled: bool,
    ) -> Result<(), RuleError> {
        self.connect_block_with_lookup(
            &sbss_violation_lookup(params),
            block,
            tx_hashes,
            parent,
            parent_stxos,
            resolver,
            stxos,
            is_treasury_enabled,
        )
    }

    /// [`Self::connect_block_with_hashes`] over the given lookup of
    /// the grandfathered same-block stake spends.
    #[allow(clippy::too_many_arguments)]
    fn connect_block_with_lookup(
        &mut self,
        sbss_violation: &impl Fn(i64) -> Option<Hash>,
        block: &MsgBlock,
        tx_hashes: &crate::blockhashes::BlockTxHashes,
        parent: &MsgBlock,
        parent_stxos: impl FnOnce() -> Result<Vec<SpentTxOut>, RuleError>,
        resolver: &impl UtxoResolver,
        mut stxos: Option<&mut Vec<SpentTxOut>>,
        is_treasury_enabled: bool,
    ) -> Result<(), RuleError> {
        tx_hashes.assert_for(block);
        if !crate::validate::header_approves_parent(&block.header) {
            let parent_stxos = parent_stxos()?;
            self.disconnect_disapproved_block(
                parent,
                &parent_stxos,
                resolver,
                is_treasury_enabled,
            )?;
        }
        self.add_sbss_violations_with(
            sbss_violation,
            block,
            tx_hashes.regular(),
            is_treasury_enabled,
        );
        self.fetch_input_utxos(block, tx_hashes.regular(), resolver, is_treasury_enabled);
        self.connect_stake_transactions(
            block,
            tx_hashes.stake(),
            stxos.as_deref_mut(),
            is_treasury_enabled,
        )?;
        self.connect_regular_transactions(block, tx_hashes.regular(), stxos, is_treasury_enabled)?;
        self.set_best_hash(block.header.block_hash());
        Ok(())
    }

    /// Update the view to represent disconnecting the passed block,
    /// marking spent again the output a grandfathered same-block stake
    /// spend restored, and reconnecting the parent's regular
    /// transactions when the block disapproved them (dcrd
    /// `disconnectBlock`).
    pub fn disconnect_block(
        &mut self,
        params: &Params,
        block: &MsgBlock,
        parent: &MsgBlock,
        stxos: &[SpentTxOut],
        resolver: &impl UtxoResolver,
        is_treasury_enabled: bool,
    ) -> Result<(), RuleError> {
        self.disconnect_block_with_lookup(
            &sbss_violation_lookup(params),
            block,
            parent,
            stxos,
            resolver,
            is_treasury_enabled,
        )
    }

    /// [`Self::disconnect_block`] over the given lookup of the
    /// grandfathered same-block stake spends.
    fn disconnect_block_with_lookup(
        &mut self,
        sbss_violation: &impl Fn(i64) -> Option<Hash>,
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
        self.remove_sbss_violations_with(sbss_violation, block, &regular_tx_hashes);
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

/// The lookup of the grandfathered same-block stake spends on the
/// given network, by height.
fn sbss_violation_lookup(params: &Params) -> impl Fn(i64) -> Option<Hash> + '_ {
    |height| crate::validate::sbss_violation_hash(params, height).copied()
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic over small fixed values"
)]
mod tests {
    use super::*;

    use core::cell::RefCell;
    use dcroxide_testutil::SplitMix64;
    use dcroxide_wire::{BlockHeader, TxIn, TxOut};

    /// A block with the given stake tree and an empty regular tree.
    fn stake_block(stransactions: Vec<MsgTx>) -> MsgBlock {
        let (header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header");
        MsgBlock {
            header,
            transactions: Vec::new(),
            stransactions,
        }
    }

    /// The null outpoint a treasurybase spends.
    fn null_outpoint() -> OutPoint {
        OutPoint {
            hash: Hash::ZERO,
            index: u32::MAX,
            tree: 0,
        }
    }

    /// A treasurybase whose first output carries the given script
    /// version.  Version 0 is a real treasurybase; any other version
    /// still passes the minimal standalone check, which ignores script
    /// versions, but fails dcrd's strict `stake.IsTreasuryBase`.
    fn treasury_base(first_output_version: u16) -> MsgTx {
        let mut op_return = alloc::vec![0x6a, 0x0c]; // OP_RETURN OP_DATA_12
        op_return.extend_from_slice(&[0u8; 12]);
        MsgTx {
            version: dcroxide_stake::TX_VERSION_TREASURY,
            tx_in: alloc::vec![TxIn {
                previous_out_point: null_outpoint(),
                sequence: u32::MAX,
                value_in: 1_000,
                block_height: 0,
                block_index: u32::MAX,
                signature_script: Vec::new(),
            }],
            tx_out: alloc::vec![
                TxOut {
                    value: 1_000,
                    version: first_output_version,
                    pk_script: alloc::vec![0xc1], // OP_TADD
                },
                TxOut {
                    value: 0,
                    version: 0,
                    pk_script: op_return,
                },
            ],
            ..MsgTx::default()
        }
    }

    #[test]
    fn malformed_treasury_base_fixture_splits_the_two_checks() {
        let good = treasury_base(0);
        assert!(dcroxide_standalone::is_treasury_base(&good));
        assert!(dcroxide_stake::is_treasury_base(&good));
        let bad = treasury_base(1);
        assert!(dcroxide_standalone::is_treasury_base(&bad));
        assert!(!dcroxide_stake::is_treasury_base(&bad));
        assert!(!dcroxide_stake::is_ssgen(&bad) && !dcroxide_stake::is_tspend(&bad));
        assert!(!dcroxide_stake::is_tadd(&bad));
    }

    /// dcrd `dbPutTreasuryBalance` records a treasurybase value only for
    /// what the strict `stake.IsTreasuryBase` accepts (treasury.go:424),
    /// so a stake transaction that merely passes the minimal check adds
    /// nothing to the block's treasury state.
    #[test]
    fn treasury_state_uses_the_strict_treasury_base_check() {
        use crate::treasurydb::{TreasuryValue, TreasuryValueType, treasury_state_for_block};

        let good = treasury_state_for_block(&stake_block(alloc::vec![treasury_base(0)]), 0);
        assert_eq!(
            good.values,
            alloc::vec![TreasuryValue {
                typ: TreasuryValueType::TBase,
                amount: 1_000,
            }]
        );
        let bad = treasury_state_for_block(&stake_block(alloc::vec![treasury_base(1)]), 0);
        assert!(bad.values.is_empty(), "{:?}", bad.values);
    }

    /// dcrd `countSpentStakeOutputs` skips only what the strict
    /// `stake.IsTreasuryBase` accepts (chain.go:966), so a stake
    /// transaction that merely passes the minimal check has its input
    /// counted.
    #[test]
    fn count_spent_stake_outputs_uses_the_strict_treasury_base_check() {
        assert_eq!(
            count_spent_stake_outputs(&stake_block(alloc::vec![treasury_base(0)])),
            0
        );
        assert_eq!(
            count_spent_stake_outputs(&stake_block(alloc::vec![treasury_base(1)])),
            1
        );
    }

    /// dcrd `fetchInputUtxos` skips the stake-tree input set only for
    /// what the strict `stake.IsTreasuryBase` accepts
    /// (utxoviewpoint.go:904), so the input of a transaction that
    /// merely passes the minimal check is requested from the backend.
    #[test]
    fn fetch_input_utxos_uses_the_strict_treasury_base_check() {
        for (version, want) in [(0u16, Vec::new()), (1, alloc::vec![null_outpoint()])] {
            let block = stake_block(alloc::vec![treasury_base(version)]);
            let requested = RefCell::new(Vec::new());
            let resolver = |op: &OutPoint| -> Option<UtxoEntry> {
                requested.borrow_mut().push(*op);
                None
            };
            let mut view = UtxoView::new();
            view.fetch_input_utxos(&block, &[], &resolver, true);
            assert_eq!(
                requested.into_inner(),
                want,
                "output 0 script version {version}"
            );
        }
    }

    /// A value in `0..n`.
    fn below(rng: &mut SplitMix64, n: usize) -> usize {
        rng.below(n as u64) as usize
    }

    fn random_hash(rng: &mut SplitMix64) -> [u8; 32] {
        let mut hash = [0u8; 32];
        rng.fill(&mut hash);
        hash
    }

    /// Indexes and trees on both sides of every signed and unsigned
    /// boundary of their types.
    const EDGE_INDEXES: [u32; 6] = [0, 1, 2, 0x7fff_ffff, 0x8000_0000, u32::MAX];
    const EDGE_TREES: [i8; 5] = [i8::MIN, -1, 0, 1, i8::MAX];

    /// Keys chosen to separate the tuple order from every near miss of
    /// it, then random ones.
    fn order_test_keys() -> Vec<OutPointKey> {
        let mut keys: Vec<OutPointKey> = Vec::new();
        // One byte set to each boundary value at each position of an
        // all-zero and an all-one hash.  A pair of these differs in one
        // or two bytes, so it tells a big-endian word from a
        // little-endian one, an unsigned byte from a signed one, and
        // the first word from the last.
        for base in [0x00u8, 0xff] {
            for position in 0..32 {
                for value in [0x00u8, 0x01, 0x7f, 0x80, 0xff] {
                    let mut hash = [base; 32];
                    hash[position] = value;
                    keys.push((hash, 0, 0));
                }
            }
        }
        // Equal hashes, so the index and then the tree decide.
        for hash in [[0x00u8; 32], [0x5a; 32], [0xff; 32]] {
            for index in EDGE_INDEXES {
                for tree in EDGE_TREES {
                    keys.push((hash, index, tree));
                }
            }
        }
        // Random keys, half of them sharing a prefix of random length
        // with the key before, so later words and the tie-breakers
        // decide as often as the first word does.
        let mut rng = SplitMix64::from_entropy("utxo map key order");
        for _ in 0..600 {
            let mut hash = random_hash(&mut rng);
            if below(&mut rng, 2) == 0 {
                let previous = keys.last().expect("keys above").0;
                let shared = below(&mut rng, 33);
                hash[..shared].copy_from_slice(&previous[..shared]);
            }
            let index = match below(&mut rng, 3) {
                0 => EDGE_INDEXES[below(&mut rng, EDGE_INDEXES.len())],
                1 => below(&mut rng, 4) as u32,
                _ => rng.next_u64() as u32,
            };
            let tree = match below(&mut rng, 3) {
                0 => EDGE_TREES[below(&mut rng, EDGE_TREES.len())],
                1 => below(&mut rng, 2) as i8,
                _ => rng.next_u64() as i8,
            };
            keys.push((hash, index, tree));
        }
        keys
    }

    /// The UTXO maps are walked in key order, by the commit of a view
    /// into the cache and by a flush of the cache, so the key they are
    /// held under must order exactly as the outpoint tuple does.
    #[test]
    fn the_map_key_orders_exactly_as_the_outpoint_tuple() {
        let keys = order_test_keys();
        let mut decided_by = [0usize; 3];
        for a in &keys {
            for b in &keys {
                let want = a.cmp(b);
                let (ka, kb) = (UtxoKey(*a), UtxoKey(*b));
                assert_eq!(ka.cmp(&kb), want, "{a:?} against {b:?}");
                assert_eq!(ka.partial_cmp(&kb), Some(want), "{a:?} against {b:?}");
                assert_eq!(ka == kb, a == b, "{a:?} against {b:?}");
                if a.0 != b.0 {
                    decided_by[0] += 1;
                } else if a.1 != b.1 {
                    decided_by[1] += 1;
                } else if a.2 != b.2 {
                    decided_by[2] += 1;
                }
            }
        }
        // Each part of the key decided some of the pairs.
        assert!(
            decided_by.iter().all(|&pairs| pairs >= 500),
            "{decided_by:?}"
        );

        // And so the maps iterate alike.
        let by_tuple: BTreeMap<OutPointKey, usize> =
            keys.iter().enumerate().map(|(i, k)| (*k, i)).collect();
        let by_key: BTreeMap<UtxoKey, usize> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| (UtxoKey(*k), i))
            .collect();
        assert!(by_tuple.len() > 900, "{} distinct keys", by_tuple.len());
        assert!(
            by_tuple
                .iter()
                .map(|(k, v)| (*k, *v))
                .eq(by_key.iter().map(|(k, v)| (k.0, *v))),
            "the two maps iterate in different orders"
        );
    }

    /// The commit as it was before it stopped searching the view: copy
    /// the keys, then look each entry up again and remove it.
    fn commit_by_search(view: &mut UtxoView) -> Vec<(OutPointKey, UtxoEntry)> {
        let mut updates = Vec::new();
        let keys: Vec<UtxoKey> = view.entries.keys().copied().collect();
        for key in keys {
            let entry = &view.entries[&key];
            if !entry.is_modified() {
                continue;
            }
            if entry.is_spent_by_zero_conf() {
                assert!(
                    entry.is_spent(),
                    "zero confirmation spend not also marked spent"
                );
                view.entries.remove(&key);
                continue;
            }
            let entry = view.entries.remove(&key).expect("present");
            updates.push((key.0, entry));
        }
        updates
    }

    /// Every state a view entry reaches a commit in.
    const COMMIT_STATES: [u8; 9] = [
        // Loaded and left alone, as it was or as a spent tombstone.
        0,
        UTXO_STATE_SPENT,
        UTXO_STATE_SPENT | UTXO_STATE_SPENT_BY_ZERO_CONF,
        // Created or restored.
        UTXO_STATE_MODIFIED,
        UTXO_STATE_MODIFIED | crate::utxoentry::UTXO_STATE_FRESH,
        // Spent.
        UTXO_STATE_MODIFIED | UTXO_STATE_SPENT,
        UTXO_STATE_MODIFIED | UTXO_STATE_SPENT | crate::utxoentry::UTXO_STATE_FRESH,
        // Created and spent within the block.
        UTXO_STATE_MODIFIED | UTXO_STATE_SPENT | UTXO_STATE_SPENT_BY_ZERO_CONF,
        UTXO_STATE_MODIFIED
            | UTXO_STATE_SPENT
            | UTXO_STATE_SPENT_BY_ZERO_CONF
            | crate::utxoentry::UTXO_STATE_FRESH,
    ];

    /// A view of `len` entries over random keys, each in the state
    /// `state_of` picks from [`COMMIT_STATES`] and each distinguishable
    /// from the others.
    fn commit_test_view(
        len: usize,
        rng: &mut SplitMix64,
        state_of: impl Fn(&mut SplitMix64) -> u8,
    ) -> UtxoView {
        let mut view = UtxoView::new();
        view.set_best_hash(Hash([0x77; 32]));
        while view.entries.len() < len {
            let n = view.entries.len();
            let mut hash = random_hash(rng);
            // A few outputs of one transaction, so keys differ in the
            // index and the tree alone too.
            if n > 0 && below(rng, 4) == 0 {
                hash = view.entries.keys().next_back().expect("an entry").0.0;
            }
            let outpoint = OutPoint {
                hash: Hash(hash),
                index: below(rng, 6) as u32,
                tree: below(rng, 2) as i8,
            };
            let mut entry = UtxoEntry::new(
                n as i64,
                alloc::vec![0x51; 1 + n % 40],
                n as u32,
                below(rng, 8) as u32,
                0,
                false,
                false,
                TxType::Regular,
                None,
            );
            entry.set_state_bits(state_of(rng));
            view.insert_entry(&outpoint, entry);
        }
        view
    }

    /// The commit hands the cache the same entries in the same order,
    /// and leaves the same entries in the view, as the commit that
    /// looked every key up again (dcrd `UtxoCache.Commit`,
    /// `utxocache.go:548-625`: unmodified entries are skipped and stay,
    /// zero-confirmation spends are deleted from the view, the rest are
    /// spent or added in the cache and deleted from the view).
    #[test]
    fn commit_drains_the_view_as_the_searching_commit_did() {
        let mut rng = SplitMix64::from_entropy("utxo view commit");
        let any = |rng: &mut SplitMix64| COMMIT_STATES[below(rng, COMMIT_STATES.len())];
        let modified = |rng: &mut SplitMix64| COMMIT_STATES[3 + below(rng, 4)];
        let unmodified = |rng: &mut SplitMix64| COMMIT_STATES[below(rng, 3)];
        let mut tally = [0usize; 3];
        for round in 0..60 {
            let len = [0, 1, 2, 3, 17, 150, 400][round % 7];
            let mut view = match round % 4 {
                // The shape of a connected block: everything modified.
                0 => commit_test_view(len, &mut rng, modified),
                1 => commit_test_view(len, &mut rng, unmodified),
                _ => commit_test_view(len, &mut rng, any),
            };
            let mut reference = view.clone();
            let before = view.entries.len();

            let got = view.commit();
            let want = commit_by_search(&mut reference);
            assert_eq!(got, want, "round {round}: the changes and their order");
            assert!(
                view.entries().eq(reference.entries()),
                "round {round}: what stays in the view"
            );
            assert_eq!(view.best_hash(), reference.best_hash(), "round {round}");
            assert!(
                got.windows(2).all(|pair| pair[0].0 < pair[1].0),
                "round {round}: the changes are in outpoint key order"
            );
            assert!(
                view.entries().all(|(_, entry)| !entry.is_modified()),
                "round {round}: only unmodified entries stay"
            );
            tally[0] += got.len();
            tally[1] += view.entries.len();
            tally[2] += before - got.len() - view.entries.len();

            // What stayed is still a working view: a second commit has
            // nothing to hand over and removes nothing.
            let stayed = view.clone();
            assert!(view.commit().is_empty(), "round {round}: a second commit");
            assert!(view.entries().eq(stayed.entries()), "round {round}");
        }
        // Changes handed over, entries kept, zero-confirmation spends
        // dropped: the rounds exercised all three.
        assert!(tally.iter().all(|&entries| entries >= 300), "{tally:?}");
    }

    /// dcrd fails the commit on a zero-confirmation spend that is not
    /// marked spent (`utxocache.go:590-597`), which the port asserts;
    /// the commit still checks every such entry.
    #[test]
    #[should_panic(expected = "zero confirmation spend not also marked spent")]
    fn commit_refuses_a_zero_conf_spend_that_is_not_spent() {
        let mut rng = SplitMix64(3);
        let mut view = commit_test_view(20, &mut rng, |_| UTXO_STATE_MODIFIED);
        let last = *view.entries.keys().next_back().expect("an entry");
        view.entries
            .get_mut(&last)
            .expect("the entry")
            .set_state_bits(UTXO_STATE_MODIFIED | UTXO_STATE_SPENT_BY_ZERO_CONF);
        view.commit();
    }

    /// dcrd `utxoEntryToSpentTxOut` encodes `encodeFlags(IsCoinBase(),
    /// HasExpiry(), TransactionType())` with `TransactionType` an
    /// unchecked cast of the raw bits 2-5, so type values 7-15 reach
    /// the journal unchanged and bits 6-7 are dropped.
    #[test]
    fn spent_tx_out_keeps_the_raw_transaction_type_bits() {
        let mut entry = UtxoEntry::new(
            1_000,
            alloc::vec![0x51],
            10,
            1,
            0,
            false,
            false,
            TxType::Regular,
            None,
        );
        for tx_type in 0u8..16 {
            for (coin_base, has_expiry) in [(false, false), (true, false), (false, true)] {
                let mut want = tx_type << 2;
                if coin_base {
                    want |= 1;
                }
                if has_expiry {
                    want |= 2;
                }
                entry.set_packed_flags_bits(want | 0xc0);
                let stxo = entry_to_spent_tx_out(&entry);
                assert_eq!(
                    stxo.packed_flags, want,
                    "type {tx_type}, coinbase {coin_base}, expiry {has_expiry}"
                );
                assert_eq!(stxo.transaction_type(), tx_type);
            }
        }
    }

    /// The height the grandfathered same-block stake spend of the
    /// tests below sits at.  No network has one there; the tests hand
    /// the view their own lookup of the violating transaction by
    /// height, as the network tables are looked up in production.
    const SBSS_HEIGHT: u32 = 4_242;

    /// An output paying `value` to an anyone-can-spend script.
    fn op_true_out(value: i64) -> TxOut {
        TxOut {
            value,
            version: 0,
            pk_script: alloc::vec![0x51],
        }
    }

    /// An input spending `outpoint`, with fraud proof data for an
    /// output of `value` created at `height` by the transaction at
    /// `index` of its block.
    fn input_spending(outpoint: OutPoint, value: i64, height: u32, index: u32) -> TxIn {
        TxIn {
            previous_out_point: outpoint,
            sequence: u32::MAX,
            value_in: value,
            block_height: height,
            block_index: index,
            signature_script: Vec::new(),
        }
    }

    /// A ticket purchase spending `outpoint`, worth `value`: the
    /// stake-tagged payment, its commitment and its change.
    fn ticket_spending(outpoint: OutPoint, value: i64, height: u32, index: u32) -> MsgTx {
        let p2pkh = |opcode: u8| {
            let mut script = alloc::vec![opcode, 0x76, 0xa9, 0x14];
            script.extend_from_slice(&[0x11; 20]);
            script.extend_from_slice(&[0x88, 0xac]);
            script
        };
        let mut commitment = alloc::vec![0x6a, 0x1e];
        commitment.extend_from_slice(&[0x22; 20]);
        commitment.extend_from_slice(&value.to_le_bytes());
        commitment.extend_from_slice(&[0x00, 0x58]);
        MsgTx {
            tx_in: alloc::vec![input_spending(outpoint, value, height, index)],
            tx_out: alloc::vec![
                TxOut {
                    value,
                    version: 0,
                    pk_script: p2pkh(0xba),
                },
                TxOut {
                    value: 0,
                    version: 0,
                    pk_script: commitment,
                },
                TxOut {
                    value: 0,
                    version: 0,
                    pk_script: p2pkh(0xbd),
                },
            ],
            ..MsgTx::default()
        }
    }

    /// The output the block's regular transaction spends, confirmed
    /// long before, and its entry.
    fn sbss_external() -> (OutPoint, UtxoEntry) {
        let outpoint = OutPoint {
            hash: Hash([0xee; 32]),
            index: 0,
            tree: 0,
        };
        let entry = UtxoEntry::new(
            5_000,
            alloc::vec![0x51],
            100,
            1,
            0,
            false,
            false,
            TxType::Regular,
            None,
        );
        (outpoint, entry)
    }

    /// A block at [`SBSS_HEIGHT`] that approves its parent, with the
    /// regular tree `[coinbase, origin]` and a ticket in the stake tree
    /// that spends output 0 of `origin`, as the grandfathered blocks
    /// do.  Returns the block and the hash of `origin`.
    fn sbss_block() -> (MsgBlock, Hash) {
        let (external, _) = sbss_external();
        let coinbase = MsgTx {
            tx_in: alloc::vec![TxIn {
                previous_out_point: null_outpoint(),
                sequence: u32::MAX,
                value_in: 0,
                block_height: 0,
                block_index: u32::MAX,
                signature_script: alloc::vec![0x01, 0x02],
            }],
            tx_out: alloc::vec![op_true_out(0)],
            ..MsgTx::default()
        };
        let origin = MsgTx {
            tx_in: alloc::vec![input_spending(external, 5_000, 100, 1)],
            tx_out: alloc::vec![op_true_out(3_000), op_true_out(2_000)],
            ..MsgTx::default()
        };
        let origin_hash = origin.tx_hash();
        let origin_out = OutPoint {
            hash: origin_hash,
            index: 0,
            tree: 0,
        };
        let ticket = ticket_spending(origin_out, 3_000, SBSS_HEIGHT, 1);
        assert_eq!(dcroxide_stake::determine_tx_type(&ticket), TxType::SStx);
        let (mut header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header");
        header.height = SBSS_HEIGHT;
        header.vote_bits = 1;
        let block = MsgBlock {
            header,
            transactions: alloc::vec![coinbase, origin],
            stransactions: alloc::vec![ticket],
        };
        (block, origin_hash)
    }

    /// The lookup naming `hash` at `height` and nothing anywhere else.
    fn violation_at(height: u32, hash: Hash) -> impl Fn(i64) -> Option<Hash> {
        move |h| (h == i64::from(height)).then_some(hash)
    }

    fn no_violation(_: i64) -> Option<Hash> {
        None
    }

    fn origin_out(origin_hash: Hash, index: u32) -> OutPoint {
        OutPoint {
            hash: origin_hash,
            index,
            tree: 0,
        }
    }

    /// dcrd `addSBSSViolations` (`utxoviewpoint.go:613-631`): for a
    /// block at a height with a violation, output 0 of the regular
    /// transaction it names is added, at the block's height and the
    /// transaction's index; nothing else, and nothing for any other
    /// height or a block without that transaction.
    #[test]
    fn the_grandfathered_output_is_added_for_its_height_alone() {
        let (block, origin_hash) = sbss_block();
        let hashes = collect_tx_hashes(&block.transactions);

        let mut view = UtxoView::new();
        view.add_sbss_violations_with(
            &violation_at(SBSS_HEIGHT, origin_hash),
            &block,
            &hashes,
            false,
        );
        let added: Vec<_> = view.entries().map(|(key, _)| *key).collect();
        assert_eq!(added, alloc::vec![(origin_hash.0, 0, 0)]);
        let entry = view
            .lookup_entry(&origin_out(origin_hash, 0))
            .expect("added");
        assert_eq!(entry.amount(), 3_000);
        assert_eq!(entry.block_height(), i64::from(SBSS_HEIGHT));
        assert_eq!(entry.block_index(), 1);
        assert_eq!(entry.state_bits(), UTXO_STATE_MODIFIED);

        for lookup in [
            violation_at(SBSS_HEIGHT + 1, origin_hash),
            violation_at(SBSS_HEIGHT, Hash([0x33; 32])),
        ] {
            let mut view = UtxoView::new();
            view.add_sbss_violations_with(&lookup, &block, &hashes, false);
            assert_eq!(view.entries().count(), 0);
        }
        let mut view = UtxoView::new();
        view.add_sbss_violations_with(&no_violation, &block, &hashes, false);
        assert_eq!(view.entries().count(), 0);
    }

    /// Write a committed view to a backend map, as a flush would.
    fn commit_to(backend: &mut BTreeMap<OutPointKey, UtxoEntry>, view: &mut UtxoView) {
        for (key, entry) in view.commit() {
            if entry.is_spent() {
                backend.remove(&key);
            } else {
                let mut entry = entry;
                entry.set_state_bits(0);
                backend.insert(key, entry);
            }
        }
    }

    /// dcrd `connectBlock` adds the grandfathered output before the
    /// fetch (`utxoviewpoint.go:947-957`), so the ticket finds the
    /// output it spends.  The regular tree, connected after the stake
    /// tree, then adds the output back unspent, which is what the
    /// historical chain holds.  Without the lookup the ticket's input
    /// is missing from the view.
    #[test]
    fn a_block_with_a_grandfathered_spend_connects_through_the_lookup() {
        let (block, origin_hash) = sbss_block();
        let tx_hashes = crate::blockhashes::BlockTxHashes::compute(&block);
        let parent = stake_block(Vec::new());
        let (external, external_entry) = sbss_external();
        let backend = move |op: &OutPoint| (*op == external).then(|| external_entry.clone());

        let mut view = UtxoView::new();
        let err = view
            .connect_block_with_lookup(
                &no_violation,
                &block,
                &tx_hashes,
                &parent,
                || Ok(Vec::new()),
                &backend,
                None,
                false,
            )
            .expect_err("the ticket's input is missing without the lookup");
        assert_eq!(err.kind, RuleErrorKind::UtxoBackendCorruption);

        let mut view = UtxoView::new();
        let mut stxos = Vec::new();
        view.connect_block_with_lookup(
            &violation_at(SBSS_HEIGHT, origin_hash),
            &block,
            &tx_hashes,
            &parent,
            || Ok(Vec::new()),
            &backend,
            Some(&mut stxos),
            false,
        )
        .expect("connect");
        let entry = view
            .lookup_entry(&origin_out(origin_hash, 0))
            .expect("in the view");
        assert!(!entry.is_spent(), "the regular tree adds it back unspent");
        // The ticket's spend is journaled first, with the output's own
        // height and index, then the regular transaction's.
        assert_eq!(stxos.len(), 2);
        assert_eq!(
            (stxos[0].amount, stxos[0].block_height, stxos[0].block_index),
            (3_000, SBSS_HEIGHT, 1)
        );
        assert_eq!(stxos[1].amount, 5_000);
    }

    /// dcrd `disconnectBlock` marks the grandfathered output spent once
    /// both trees are disconnected (`removeSBSSViolations`,
    /// `utxoviewpoint.go:1051`): the stake tree's disconnect restores it
    /// as the ticket's input, and without the lookup it is left unspent
    /// in a view of the parent, where it never existed.
    #[test]
    fn disconnecting_the_block_spends_the_grandfathered_output_again() {
        let (block, origin_hash) = sbss_block();
        let tx_hashes = crate::blockhashes::BlockTxHashes::compute(&block);
        let parent = stake_block(Vec::new());
        let (external, external_entry) = sbss_external();
        let lookup = violation_at(SBSS_HEIGHT, origin_hash);

        let mut backend = BTreeMap::new();
        backend.insert((external.hash.0, 0, 0), external_entry);
        let mut view = UtxoView::new();
        let mut stxos = Vec::new();
        {
            let resolve = |op: &OutPoint| backend.get(&(op.hash.0, op.index, op.tree)).cloned();
            view.connect_block_with_lookup(
                &lookup,
                &block,
                &tx_hashes,
                &parent,
                || Ok(Vec::new()),
                &resolve,
                Some(&mut stxos),
                false,
            )
            .expect("connect");
        }
        commit_to(&mut backend, &mut view);
        assert!(backend.contains_key(&(origin_hash.0, 0, 0)));

        for (lookup, want_spent) in [
            (&lookup as &dyn Fn(i64) -> Option<Hash>, true),
            (&no_violation, false),
        ] {
            let resolve = |op: &OutPoint| backend.get(&(op.hash.0, op.index, op.tree)).cloned();
            let mut view = UtxoView::new();
            view.disconnect_block_with_lookup(&lookup, &block, &parent, &stxos, &resolve, false)
                .expect("disconnect");
            let entry = view
                .lookup_entry(&origin_out(origin_hash, 0))
                .expect("in the view");
            assert_eq!(entry.is_spent(), want_spent, "the grandfathered output");
            assert!(entry.is_modified());
            assert!(
                view.lookup_entry(&origin_out(origin_hash, 1))
                    .expect("in the view")
                    .is_spent()
            );
            assert!(!view.lookup_entry(&external).expect("restored").is_spent());
        }
    }

    /// dcrd panics when the grandfathered output is missing from the
    /// view after the disconnect (`utxoviewpoint.go:994-999`), with
    /// this text.
    #[test]
    fn a_grandfathered_output_missing_after_a_disconnect_panics() {
        let (block, origin_hash) = sbss_block();
        let hashes = collect_tx_hashes(&block.transactions);
        let lookup = violation_at(SBSS_HEIGHT, origin_hash);
        let want = alloc::format!(
            "SBS spend violation output {origin_hash}:0 for block {} (height {SBSS_HEIGHT}) \
             is missing from the view after disconnecting it",
            block.header.block_hash()
        );
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            UtxoView::new().remove_sbss_violations_with(&lookup, &block, &hashes);
        }))
        .expect_err("a missing output panics");
        assert_eq!(panic.downcast_ref::<String>(), Some(&want));

        // Another height or a block without the transaction is left
        // alone.
        UtxoView::new().remove_sbss_violations_with(
            &violation_at(SBSS_HEIGHT + 1, origin_hash),
            &block,
            &hashes,
        );
        UtxoView::new().remove_sbss_violations_with(
            &violation_at(SBSS_HEIGHT, Hash([0x33; 32])),
            &block,
            &hashes,
        );
    }
}
