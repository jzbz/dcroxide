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

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::cmp::Ordering;

use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_stake::TxType;
use dcroxide_wire::{MsgBlock, MsgTx, OutPoint};

use crate::RuleError;
use crate::chainio::SpentTxOut;
use crate::utxoentry::{
    UTXO_STATE_MODIFIED, UTXO_STATE_SPENT, UTXO_STATE_SPENT_BY_ZERO_CONF, UtxoEntry,
    encode_utxo_flags, is_ticket_submission_output,
};

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
        // TransactionType())` (utxoviewpoint.go:231-232), and
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
#[derive(Default)]
pub struct UtxoView {
    entries: BTreeMap<UtxoKey, UtxoEntry>,
    best_hash: Hash,
    /// The regular tree outputs that later transactions in the same
    /// block spend and that may bypass cache updates (dcrd
    /// `zeroConfOuts`, `utxoviewpoint.go:34-39`).  They are found when
    /// the inputs are fetched, before outputs of earlier transactions
    /// in the block are added to the view, and the connect or
    /// disconnect of that block's regular tree consumes them.  An
    /// empty set holds no allocation.
    zero_conf_outs: BTreeSet<UtxoKey>,
}

impl Clone for UtxoView {
    /// A copy of the view's entries and best hash (dcrd `clone`,
    /// `utxoviewpoint.go:1287-1300`), without the zero-confirmation
    /// set, which dcrd's copy does not carry either.
    fn clone(&self) -> UtxoView {
        UtxoView {
            entries: self.entries.clone(),
            best_hash: self.best_hash,
            zero_conf_outs: BTreeSet::new(),
        }
    }
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
    ///
    /// `cache_holds_unspent` answers whether the cache the changes go
    /// to holds an unspent entry for an output, which the commit asks
    /// only of the zero-confirmation spends.
    ///
    /// # Panics
    ///
    /// With dcrd's texts (`utxocache.go:594-606`, since `e60cedc5` and
    /// `22fd2431`), when a zero-confirmation spend is not also marked
    /// spent, or when the cache holds an unspent entry for it: such an
    /// output only ever existed in the view.
    pub fn commit(
        &mut self,
        cache_holds_unspent: impl Fn(&OutPointKey) -> bool,
    ) -> Vec<(OutPointKey, UtxoEntry)> {
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
                // Zero-confirmation spends must also be marked spent and
                // must not have an unspent cache entry (dcrd
                // `utxocache.go:594-606`).
                let outpoint = || {
                    let (hash, index, tree) = key.0;
                    OutPoint {
                        hash: Hash(hash),
                        index,
                        tree,
                    }
                };
                if !entry.is_spent() {
                    let outpoint = outpoint();
                    panic!(
                        "output {outpoint} (tree {}) from view@{} is simultaneously marked \
                         spent by a transaction later in the same block and not spent",
                        outpoint.tree, self.best_hash
                    );
                }
                if cache_holds_unspent(&key.0) {
                    let outpoint = outpoint();
                    panic!(
                        "output {outpoint} (tree {}) from view@{} is marked as only having \
                         ever existed in the view, but has an unspent cache entry",
                        outpoint.tree, self.best_hash
                    );
                }
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

    /// Connect a stake tree transaction, spending its inputs and
    /// adding its outputs (dcrd `connectStakeTransaction`).  The
    /// caller supplies the transaction's hash, computed once per
    /// block.
    ///
    /// # Panics
    ///
    /// When the view does not hold an input the transaction spends, or
    /// holds it already spent, with dcrd's texts
    /// (`utxoviewpoint.go:274-284`, since `e60cedc5` and `22fd2431`):
    /// either is an invariant violation there is no recovering from.
    pub fn connect_stake_transaction(
        &mut self,
        tx: &MsgTx,
        tx_hash: &Hash,
        block_height: i64,
        block_index: u32,
        mut stxos: Option<&mut Vec<SpentTxOut>>,
        is_treasury_enabled: bool,
    ) {
        // Treasurybases have no inputs to spend.
        if is_treasury_enabled && block_index == 0 {
            return;
        }
        // Treasury spends source from the treasury account.
        if is_treasury_enabled && dcroxide_stake::is_tspend(tx) {
            self.add_tx_outs_with_hash(tx, tx_hash, block_height, block_index, is_treasury_enabled);
            return;
        }
        let is_vote = dcroxide_stake::is_ssgen(tx);
        for (tx_in_idx, tx_in) in tx.tx_in.iter().enumerate() {
            // Votes have no input at the stakebase index.
            if is_vote && tx_in_idx == 0 {
                continue;
            }
            // The referenced output must be in the view and not
            // already spent.
            let prev_out = &tx_in.previous_out_point;
            let Some(entry) = self.entries.get_mut(&key(prev_out)) else {
                panic!("view missing input {prev_out} (tree {})", prev_out.tree);
            };
            if entry.is_spent() {
                panic!(
                    "attempt to spend already spent output {prev_out} (tree {})",
                    prev_out.tree
                );
            }
            if let Some(stxos) = stxos.as_deref_mut() {
                stxos.push(entry_to_spent_tx_out(entry));
            }
            entry.spend();
        }
        self.add_tx_outs_with_hash(tx, tx_hash, block_height, block_index, is_treasury_enabled);
    }

    /// Connect every stake tree transaction of the block (dcrd
    /// `connectStakeTransactions`).  `stake_tx_hashes` carries the
    /// hash of each stake transaction, computed once per block.
    ///
    /// # Panics
    ///
    /// When the view does not hold an input a transaction spends, or
    /// holds it already spent, as [`Self::connect_stake_transaction`]
    /// does.
    pub fn connect_stake_transactions(
        &mut self,
        block: &MsgBlock,
        stake_tx_hashes: &[Hash],
        mut stxos: Option<&mut Vec<SpentTxOut>>,
        is_treasury_enabled: bool,
    ) {
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
            );
        }
    }

    /// Connect a regular tree transaction, spending its inputs and
    /// adding its outputs (dcrd `connectRegularTransaction`).  A spend
    /// of an output in the view's zero-confirmation set, which the
    /// fetch of the block's inputs fills, is marked as a
    /// zero-confirmation spend.  The caller supplies the transaction's
    /// hash, computed once per block.
    ///
    /// # Panics
    ///
    /// When the view does not hold an input the transaction spends, or
    /// holds it already spent, with dcrd's texts
    /// (`utxoviewpoint.go:342-352`, since `e60cedc5` and `22fd2431`).
    pub fn connect_regular_transaction(
        &mut self,
        tx: &MsgTx,
        tx_hash: &Hash,
        block_height: i64,
        block_index: u32,
        mut stxos: Option<&mut Vec<SpentTxOut>>,
        is_treasury_enabled: bool,
    ) {
        if dcroxide_standalone::is_coin_base_tx(tx, is_treasury_enabled) {
            self.add_tx_outs_with_hash(tx, tx_hash, block_height, block_index, is_treasury_enabled);
            return;
        }
        for tx_in in &tx.tx_in {
            // The referenced output must be in the view and not
            // already spent.
            let prev_out = &tx_in.previous_out_point;
            let prev_key = key(prev_out);
            let Some(entry) = self.entries.get_mut(&prev_key) else {
                panic!("view missing input {prev_out} (tree {})", prev_out.tree);
            };
            if entry.is_spent() {
                panic!(
                    "attempt to spend already spent output {prev_out} (tree {})",
                    prev_out.tree
                );
            }
            if let Some(stxos) = stxos.as_deref_mut() {
                stxos.push(entry_to_spent_tx_out(entry));
            }
            entry.spend();
            // Mark eligible outputs spent by later transactions in the
            // regular tree of the same block as zero-confirmation
            // spends (`utxoviewpoint.go:365-369`).
            if self.zero_conf_outs.contains(&prev_key) {
                entry.state |= UTXO_STATE_SPENT_BY_ZERO_CONF;
            }
        }
        self.add_tx_outs_with_hash(tx, tx_hash, block_height, block_index, is_treasury_enabled);
    }

    /// Connect every regular tree transaction of the block, marking the
    /// eligible outputs that later transactions in the tree spend as
    /// zero-confirmation spends, and clear the view's
    /// zero-confirmation set (dcrd `connectRegularTransactions`).
    /// `regular_tx_hashes` carries the hash of each regular
    /// transaction, computed once per block.
    ///
    /// # Panics
    ///
    /// When the view does not hold an input a transaction spends, or
    /// holds it already spent, as [`Self::connect_regular_transaction`]
    /// does.
    pub fn connect_regular_transactions(
        &mut self,
        block: &MsgBlock,
        regular_tx_hashes: &[Hash],
        mut stxos: Option<&mut Vec<SpentTxOut>>,
        is_treasury_enabled: bool,
    ) {
        debug_assert_eq!(
            block.transactions.len(),
            regular_tx_hashes.len(),
            "one hash per regular transaction"
        );
        let height = i64::from(block.header.height);
        for (i, (tx, tx_hash)) in block.transactions.iter().zip(regular_tx_hashes).enumerate() {
            self.connect_regular_transaction(
                tx,
                tx_hash,
                height,
                i as u32,
                stxos.as_deref_mut(),
                is_treasury_enabled,
            );
        }
        self.clear_zero_conf_outs();
    }

    /// Drop the view's zero-confirmation set once the regular tree it
    /// was found for has been connected or disconnected (dcrd sets
    /// `zeroConfOuts` to nil).
    pub(crate) fn clear_zero_conf_outs(&mut self) {
        self.zero_conf_outs = BTreeSet::new();
    }

    /// Disconnect one of the block's transaction trees, restoring the
    /// spent outputs from the spend journal (dcrd
    /// `disconnectTransactions`).  The create-if-missing map shape
    /// mirrors dcrd's.  An output of the block in the view's
    /// zero-confirmation set is marked as a zero-confirmation spend,
    /// and disconnecting the regular tree clears the set (dcrd
    /// `disconnectRegularTransactions`).  `tx_hashes` carries the hash
    /// of each transaction in the tree being disconnected, computed
    /// once per block.
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
                // Mark eligible outputs spent by later transactions in
                // the same block as zero-confirmation spends
                // (`utxoviewpoint.go:498-502`).
                if self.zero_conf_outs.contains(&k) {
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
            }
        }
        if !stake_tree {
            self.clear_zero_conf_outs();
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

    /// Whether the view holds any output of the transaction in the
    /// regular tree (dcrd `hasAnyRegularTxOut`,
    /// `utxoviewpoint.go:1106-1118`).  dcrd tests for a non-nil entry;
    /// the view stores no entry where dcrd stores a nil one, so
    /// presence is the same test.
    fn has_any_regular_tx_out(&self, tx: &MsgTx, tx_hash: &Hash) -> bool {
        (0..tx.tx_out.len() as u32).any(|index| {
            self.entries.contains_key(&key(&OutPoint {
                hash: *tx_hash,
                index,
                tree: 0,
            }))
        })
    }

    /// Queue the missing utxos for the regular transactions' inputs,
    /// adding outputs created earlier in the same block to the view
    /// directly and replacing the view's zero-confirmation set with the
    /// ones eligible to bypass cache updates (the set-construction
    /// half of dcrd `fetchRegularInputUtxos`, `addRegularInputUtxos`,
    /// `utxoviewpoint.go:1128-1198`).  `regular_tx_hashes` carries the
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
        let mut zero_conf_eligible: BTreeMap<[u8; 32], bool> = BTreeMap::new();
        let mut zero_conf_outs: BTreeSet<UtxoKey> = BTreeSet::new();
        for (i, tx) in block.transactions.iter().enumerate().skip(1) {
            for tx_in in &tx.tx_in {
                let prev_out = &tx_in.previous_out_point;
                if let Some(&in_flight_index) = tx_in_flight.get(&prev_out.hash.0) {
                    // Only a transaction earlier in the block may be
                    // referenced.  dcrd compares the index of the
                    // coinbase-skipping slice (`i >= inFlightIdx`),
                    // which is one less than the block position used
                    // here, so the two comparisons are the same rule.
                    if i > in_flight_index {
                        // A spend may bypass the cache only when the
                        // output exists in the view alone, which is
                        // guaranteed only for outputs the transaction
                        // newly creates: the creating transaction is
                        // eligible when the view holds none of its
                        // outputs before any of them is added here
                        // (`utxoviewpoint.go:1161-1183`).  The answer
                        // is kept per transaction, since later
                        // transactions can spend several of its
                        // outputs.
                        let origin_tx = &block.transactions[in_flight_index];
                        let origin_hash = &regular_tx_hashes[in_flight_index];
                        let eligible = match zero_conf_eligible.get(&prev_out.hash.0) {
                            Some(&eligible) => eligible,
                            None => {
                                let eligible = !self.has_any_regular_tx_out(origin_tx, origin_hash);
                                zero_conf_eligible.insert(prev_out.hash.0, eligible);
                                eligible
                            }
                        };
                        if eligible {
                            zero_conf_outs.insert(key(prev_out));
                        }

                        // Add only the referenced output (dcrd
                        // `AddTxOut(originTx, originIdx)`, since
                        // 01208035).  Adding every output would also
                        // mark unspent any sibling output a disapproved
                        // parent's disconnect left spent in the view,
                        // and it would keep such siblings out of the
                        // fetch set, where dcrd resolves them to nil.
                        self.add_tx_out_with_hash(
                            origin_tx,
                            origin_hash,
                            prev_out.index,
                            height,
                            in_flight_index as u32,
                            is_treasury_enabled,
                        );
                        continue;
                    }
                }
                self.queue_missing(needed, prev_out);
            }
        }
        self.zero_conf_outs = zero_conf_outs;
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
            // (utxoviewpoint.go:1262), not the minimal standalone check.
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
    /// view (dcrd `fetchRegularInputUtxos`, `utxoviewpoint.go:1200-1222`,
    /// over the resolver: the missing outpoints collect into one set
    /// and resolve in one batch).  `regular_tx_hashes` carries the hash
    /// of each regular transaction, computed once per block.
    ///
    /// Outputs a transaction of the regular tree creates and a later
    /// one spends are added from the creating transaction and replace
    /// any entries the view holds for them; every other entry already
    /// in the view is left as it is.
    ///
    /// The view's zero-confirmation set is replaced with the outputs
    /// eligible to bypass cache updates when spent.  Eligibility
    /// depends on what the view holds when this runs, so any entries
    /// that already exist must be added first, and the set must be
    /// consumed by connecting or disconnecting the regular tree of the
    /// same block before any further fetch.
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
    /// (dcrd `fetchInputUtxos`, `utxoviewpoint.go:1224-1285`, over the
    /// resolver: every missing outpoint across both trees resolves in
    /// one batch, so a database-backed resolver reads them all in one
    /// transaction).  `regular_tx_hashes` carries the hash of each
    /// regular transaction, computed once per block; the stake tree
    /// only resolves inputs and needs no hashes.
    ///
    /// The regular tree is fetched as [`Self::fetch_regular_input_utxos`]
    /// fetches it, with the same requirements on callers.  The stake
    /// tree may not spend outputs created in the same block, so all of
    /// its inputs are resolved, except the historical grandfathered
    /// outputs, which callers add first (`add_sbss_violations`) so they
    /// exist when eligibility is decided.
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

    /// Panic unless the view is consistent with the completed
    /// transition the block represents (dcrd `assertBlockUtxoView`,
    /// `utxoviewpoint.go:633-917`, since `22fd2431`): every input the
    /// block spends must have a spent entry whose details match the
    /// input's fraud proof, and every spendable output it creates must
    /// have an entry with the output's details, marked modified, and
    /// spent exactly when a later transaction in the regular tree spends
    /// it.  The grandfathered same-block stake spends are the one
    /// exception (see [`Self::add_sbss_violations`]): the regular tree
    /// adds their output back unspent after the stake tree spends it.
    ///
    /// Only for a fully validated block whose transactions have been
    /// applied to the view.  The reorganization calls it for every block
    /// it attaches, just before the block is connected
    /// (`chain.go:1236-1238`).  These are assertions rather than errors,
    /// as dcrd's commit gives the reason: there is no recovering from a
    /// view that violates them, and processing more blocks over it could
    /// corrupt the utxo set.  The texts are dcrd's.
    pub(crate) fn assert_block_utxo_view(
        &self,
        params: &Params,
        block: &MsgBlock,
        tx_hashes: &crate::blockhashes::BlockTxHashes,
        is_treasury_enabled: bool,
    ) {
        self.assert_block_utxo_view_with(
            &sbss_violation_lookup(params),
            block,
            tx_hashes,
            is_treasury_enabled,
        );
    }

    /// [`Self::assert_block_utxo_view`] over the given lookup of the
    /// grandfathered same-block stake spends.
    fn assert_block_utxo_view_with(
        &self,
        sbss_violation: &impl Fn(i64) -> Option<Hash>,
        block: &MsgBlock,
        tx_hashes: &crate::blockhashes::BlockTxHashes,
        is_treasury_enabled: bool,
    ) {
        tx_hashes.assert_for(block);
        let height = i64::from(block.header.height);
        // The header is hashed only for a panic's text.
        let block_hash = || block.header.block_hash();

        // Every output the regular tree spends, with the index of the
        // transaction that spends it, which decides which of the
        // block's own outputs must be spent.  Sorted, a lookup finds
        // the last spender of an output, as a later write to dcrd's map
        // replaces an earlier one.
        let mut spent_regular_outs: Vec<(UtxoKey, u32)> =
            Vec::with_capacity(count_spent_regular_outputs(block));
        for (tx_idx, tx) in block.transactions.iter().enumerate() {
            // A coinbase has a single null input instead of real ones,
            // and the input checks below make sure of it.  Only its
            // first input is skipped, so that a mistake in detecting
            // the coinbase cannot let other inputs through.
            let is_coin_base = tx_idx == 0;
            if is_coin_base && !dcroxide_standalone::is_coin_base_tx(tx, is_treasury_enabled) {
                panic!(
                    "block {} first tx {} is not a coinbase",
                    block_hash(),
                    tx_hashes.regular()[0]
                );
            }
            for (tx_in_idx, tx_in) in tx.tx_in.iter().enumerate() {
                if is_coin_base && tx_in_idx == 0 {
                    continue;
                }
                spent_regular_outs.push((key(&tx_in.previous_out_point), tx_idx as u32));
            }
        }
        spent_regular_outs.sort_unstable();
        let regular_spender = |outpoint: &UtxoKey| {
            let end = spent_regular_outs.partition_point(|(spent, _)| spent <= outpoint);
            let (spent, spender) = spent_regular_outs.get(end.checked_sub(1)?)?;
            (spent == outpoint).then_some(*spender)
        };

        // Every input the block spends that has a real input must have
        // a spent entry in the view with the details the input commits
        // to.
        let assert_inputs = |transactions: &[MsgTx], hashes: &[Hash], stake_tree: bool| {
            let tree_name = if stake_tree { "stake" } else { "regular" };
            for (tx_idx, (tx, tx_hash)) in transactions.iter().zip(hashes).enumerate() {
                let tx_type = if stake_tree {
                    dcroxide_stake::determine_tx_type(tx)
                } else {
                    TxType::Regular
                };
                let is_coin_base = !stake_tree && tx_idx == 0;
                for (tx_in_idx, tx_in) in tx.tx_in.iter().enumerate() {
                    // Coinbases, the stakebase of votes, treasurybases
                    // and treasury spends spend a null outpoint, and
                    // only at their first input; every other input
                    // spends a real one.
                    let prev_out = &tx_in.previous_out_point;
                    let want_null_out = tx_in_idx == 0
                        && (is_coin_base
                            || matches!(
                                tx_type,
                                TxType::SSGen | TxType::TreasuryBase | TxType::TSpend
                            ));
                    let got_null = crate::validate::is_null_outpoint(prev_out);
                    if got_null != want_null_out {
                        let spends = if got_null {
                            alloc::string::String::from("null outpoint")
                        } else {
                            alloc::format!("non-null outpoint {prev_out} (tree {})", prev_out.tree)
                        };
                        panic!(
                            "block {} {tree_name} tree idx {tx_idx}: tx {tx_hash}:{tx_in_idx} \
                             spends {spends}",
                            block_hash()
                        );
                    }
                    if want_null_out {
                        continue;
                    }
                    let input = || {
                        alloc::format!(
                            "block {} {tree_name} tree idx {tx_idx}: tx {tx_hash}:{tx_in_idx} \
                             spending input {prev_out} (tree {})",
                            block_hash(),
                            prev_out.tree
                        )
                    };

                    let Some(entry) = self.entries.get(&key(prev_out)) else {
                        panic!("{}: input is missing from utxo view", input());
                    };

                    // A spent input is marked spent, except the
                    // grandfathered output a stake transaction spends in
                    // its own block, which the regular tree adds back.
                    // The assertion would have caught those spends had
                    // it been in place, though it does not test the rule
                    // they broke.
                    let is_historical_sbss = stake_tree
                        && prev_out.index == 0
                        && prev_out.tree == dcroxide_wire::TX_TREE_REGULAR
                        && sbss_violation(height) == Some(prev_out.hash);
                    if !entry.is_spent() && !is_historical_sbss {
                        panic!("{}: utxo is not marked spent", input());
                    }

                    // The entry is the one the input's fraud proof names.
                    if entry.amount() != tx_in.value_in {
                        panic!(
                            "{}: utxo amount mismatch (entry {}, input witness {})",
                            input(),
                            entry.amount(),
                            tx_in.value_in
                        );
                    }
                    if entry.block_height() != i64::from(tx_in.block_height) {
                        panic!(
                            "{}: utxo block height mismatch (entry {}, input witness {})",
                            input(),
                            entry.block_height(),
                            tx_in.block_height
                        );
                    }
                    if entry.block_index() != tx_in.block_index {
                        panic!(
                            "{}: utxo block index mismatch (entry {}, input witness {})",
                            input(),
                            entry.block_index(),
                            tx_in.block_index
                        );
                    }

                    // A stake transaction does not spend an output of its
                    // own block, the grandfathered spends aside.
                    if stake_tree && i64::from(tx_in.block_height) == height && !is_historical_sbss
                    {
                        panic!("{}: stake tx spends output from same block", input());
                    }
                }
            }
        };

        // Every spendable output the block creates must have an entry
        // with the output's details and the spent state the block leaves
        // it in.
        let assert_outputs = |transactions: &[MsgTx], hashes: &[Hash], stake_tree: bool| {
            let (tx_tree, tree_name) = if stake_tree {
                (dcroxide_wire::TX_TREE_STAKE, "stake")
            } else {
                (dcroxide_wire::TX_TREE_REGULAR, "regular")
            };
            for (tx_idx, (tx, tx_hash)) in transactions.iter().zip(hashes).enumerate() {
                let tx_type = if stake_tree {
                    dcroxide_stake::determine_tx_type(tx)
                } else {
                    TxType::Regular
                };

                // A treasurybase creates no utxos.
                if stake_tree && is_treasury_enabled && tx_idx == 0 {
                    continue;
                }

                let is_coin_base = !stake_tree && tx_idx == 0;
                let has_expiry = tx.expiry != dcroxide_wire::NO_EXPIRY_VALUE;
                let want_packed_flags = encode_utxo_flags(is_coin_base, has_expiry, tx_type);
                for (tx_out_idx, tx_out) in tx.tx_out.iter().enumerate() {
                    // A treasury add and a provably unspendable output are
                    // never utxos.
                    let tx_out_idx = tx_out_idx as u32;
                    if is_treasury_add_output(tx_type, tx_out_idx)
                        || dcroxide_txscript::is_unspendable(tx_out.value, &tx_out.pk_script)
                    {
                        continue;
                    }

                    let outpoint = OutPoint {
                        hash: *tx_hash,
                        index: tx_out_idx,
                        tree: tx_tree,
                    };
                    let output = || {
                        alloc::format!(
                            "block {} {tree_name} tree idx {tx_idx}: output {outpoint}",
                            block_hash()
                        )
                    };
                    let out_key = key(&outpoint);
                    let Some(entry) = self.entries.get(&out_key) else {
                        panic!("{}: output is missing from utxo view", output());
                    };

                    // An output a later transaction of the regular tree
                    // spends is spent, and every other output is not.
                    let want_spent = !stake_tree
                        && regular_spender(&out_key).is_some_and(|spender| spender > tx_idx as u32);
                    if entry.is_spent() != want_spent {
                        panic!(
                            "{}: spent state mismatch (entry {}, want {want_spent})",
                            output(),
                            entry.is_spent()
                        );
                    }

                    // Every output is marked modified.
                    if !entry.is_modified() {
                        panic!("{}: utxo is not marked modified", output());
                    }

                    // The entry carries the output's details.
                    if entry.amount() != tx_out.value {
                        panic!(
                            "{}: amount mismatch (entry {}, tx output {})",
                            output(),
                            entry.amount(),
                            tx_out.value
                        );
                    }
                    if entry.script_version() != tx_out.version {
                        panic!(
                            "{}: script version mismatch (entry {}, tx output {})",
                            output(),
                            entry.script_version(),
                            tx_out.version
                        );
                    }
                    if entry.pk_script() != tx_out.pk_script.as_slice() {
                        panic!(
                            "{}: public key script mismatch (entry {}, tx output {})",
                            output(),
                            crate::validate::hex_string(entry.pk_script()),
                            crate::validate::hex_string(&tx_out.pk_script)
                        );
                    }
                    if entry.block_height() != height {
                        panic!(
                            "{}: block height mismatch (entry {}, block {height})",
                            output(),
                            entry.block_height()
                        );
                    }
                    if entry.block_index() != tx_idx as u32 {
                        panic!(
                            "{}: block index mismatch (entry {}, tx idx {tx_idx})",
                            output(),
                            entry.block_index()
                        );
                    }
                    if entry.packed_flags != want_packed_flags {
                        panic!(
                            "{}: packed flags mismatch (entry {:x}, want {want_packed_flags:x})",
                            output(),
                            entry.packed_flags
                        );
                    }

                    // A ticket submission output carries the ticket's
                    // minimal outputs, and no other output does.
                    let want_min_outs = is_ticket_submission_output(tx_type as u8, tx_out_idx);
                    let min_outs = entry.ticket_minimal_outputs_data();
                    if min_outs.is_some() != want_min_outs {
                        panic!(
                            "{}: ticket minimal outputs presence mismatch (entry present {}, \
                             want {want_min_outs})",
                            output(),
                            min_outs.is_some()
                        );
                    }
                    if let Some(min_outs) = min_outs.filter(|_| want_min_outs) {
                        let mut want_data = alloc::vec![
                            0u8;
                            crate::chainio::serialize_size_for_minimal_outputs(tx)
                        ];
                        let written = crate::chainio::put_tx_to_minimal_outputs(&mut want_data, tx);
                        if written != want_data.len() {
                            panic!(
                                "{}: ticket minimal outputs serialization size mismatch \
                                 (written {written}, expected {})",
                                output(),
                                want_data.len()
                            );
                        }
                        if min_outs != want_data.as_slice() {
                            panic!(
                                "{}: ticket minimal outputs data mismatch (entry size {}, \
                                 expected size {})",
                                output(),
                                min_outs.len(),
                                want_data.len()
                            );
                        }
                    }
                }
            }
        };

        assert_inputs(&block.transactions, tx_hashes.regular(), false);
        assert_inputs(&block.stransactions, tx_hashes.stake(), true);
        assert_outputs(&block.transactions, tx_hashes.regular(), false);
        assert_outputs(&block.stransactions, tx_hashes.stake(), true);
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
        );
        self.connect_regular_transactions(block, tx_hashes.regular(), stxos, is_treasury_enabled);
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
            );
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
    /// (utxoviewpoint.go:1262), so the input of a transaction that
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
    /// `utxocache.go:552-634`: unmodified entries are skipped and stay,
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

            let got = view.commit(no_cache_entry);
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
            assert!(
                view.commit(no_cache_entry).is_empty(),
                "round {round}: a second commit"
            );
            assert!(view.entries().eq(stayed.entries()), "round {round}");
        }
        // Changes handed over, entries kept, zero-confirmation spends
        // dropped: the rounds exercised all three.
        assert!(tally.iter().all(|&entries| entries >= 300), "{tally:?}");
    }

    /// dcrd panics at the commit of a zero-confirmation spend that is
    /// not marked spent, with this text (`utxocache.go:594-601`, since
    /// `e60cedc5`); the commit still checks every such entry.
    #[test]
    fn commit_refuses_a_zero_conf_spend_that_is_not_spent() {
        let mut rng = SplitMix64(3);
        let mut view = commit_test_view(20, &mut rng, |_| UTXO_STATE_MODIFIED);
        let last = *view.entries.keys().next_back().expect("an entry");
        view.entries
            .get_mut(&last)
            .expect("the entry")
            .set_state_bits(UTXO_STATE_MODIFIED | UTXO_STATE_SPENT_BY_ZERO_CONF);
        let (hash, index, tree) = last.0;
        let outpoint = OutPoint {
            hash: Hash(hash),
            index,
            tree,
        };
        let want = alloc::format!(
            "output {outpoint} (tree {tree}) from view@{} is simultaneously marked spent by a \
             transaction later in the same block and not spent",
            Hash([0x77; 32])
        );
        assert_eq!(panic_text(|| drop(view.commit(no_cache_entry))), want);
    }

    /// The probe of an empty cache.
    fn no_cache_entry(_: &OutPointKey) -> bool {
        false
    }

    /// dcrd also panics at the commit of a zero-confirmation spend the
    /// cache holds an unspent entry for, with this text
    /// (`utxocache.go:602-606`, since `22fd2431`).  The commit asks the
    /// cache about zero-confirmation spends alone, and only once each
    /// is known to be spent.
    #[test]
    fn commit_refuses_a_zero_conf_spend_the_cache_holds_unspent() {
        let mut rng = SplitMix64(5);
        let zero_conf = UTXO_STATE_MODIFIED | UTXO_STATE_SPENT | UTXO_STATE_SPENT_BY_ZERO_CONF;
        let mut view = commit_test_view(20, &mut rng, |rng| COMMIT_STATES[below(rng, 7)]);
        let keys: Vec<UtxoKey> = view.entries.keys().copied().collect();
        let (first, last) = (keys[0], keys[keys.len() - 1]);
        for key in [first, last] {
            view.entries
                .get_mut(&key)
                .expect("the entry")
                .set_state_bits(zero_conf);
        }

        // A cache that holds neither: both leave the view, and the cache
        // was asked about those two alone.
        let asked = RefCell::new(Vec::new());
        let mut copy = view.clone();
        copy.commit(|key| {
            asked.borrow_mut().push(*key);
            false
        });
        assert_eq!(asked.into_inner(), [first.0, last.0]);
        assert!(copy.lookup_entry(&outpoint_of(first)).is_none());
        assert!(copy.lookup_entry(&outpoint_of(last)).is_none());

        // A cache holding the last unspent.
        let outpoint = outpoint_of(last);
        let want = alloc::format!(
            "output {outpoint} (tree {}) from view@{} is marked as only having ever existed in \
             the view, but has an unspent cache entry",
            outpoint.tree,
            Hash([0x77; 32])
        );
        assert_eq!(panic_text(|| drop(view.commit(|key| *key == last.0))), want);
    }

    /// The outpoint a view key names.
    fn outpoint_of(key: UtxoKey) -> OutPoint {
        let (hash, index, tree) = key.0;
        OutPoint {
            hash: Hash(hash),
            index,
            tree,
        }
    }

    /// The text of the panic `f` raises.
    fn panic_text(f: impl FnOnce()) -> String {
        let payload =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).expect_err("the call panics");
        payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
            .expect("a text payload")
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
        let coinbase = test_coinbase(0);
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

    /// Write a committed view to a backend map, as a flush would, with
    /// nothing left in a cache.
    fn commit_to(backend: &mut BTreeMap<OutPointKey, UtxoEntry>, view: &mut UtxoView) {
        for (key, entry) in view.commit(no_cache_entry) {
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

        let text = panic_text(|| {
            let _ = UtxoView::new().connect_block_with_lookup(
                &no_violation,
                &block,
                &tx_hashes,
                &parent,
                || Ok(Vec::new()),
                &backend,
                None,
                false,
            );
        });
        assert_eq!(
            text,
            alloc::format!("view missing input {origin_hash}:0 (tree 0)"),
            "the ticket's input is missing without the lookup"
        );

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

    /// A coinbase whose input commits to `subsidy` and which pays
    /// nothing spendable.
    fn test_coinbase(subsidy: i64) -> MsgTx {
        MsgTx {
            tx_in: alloc::vec![TxIn {
                previous_out_point: null_outpoint(),
                sequence: u32::MAX,
                value_in: subsidy,
                block_height: 0,
                block_index: u32::MAX,
                signature_script: alloc::vec![0x01, 0x02],
            }],
            tx_out: alloc::vec![op_true_out(0)],
            ..MsgTx::default()
        }
    }

    /// The height of the blocks the zero-confirmation tests below
    /// build, on the simulation network.
    const ZERO_CONF_HEIGHT: u32 = 120;

    const SPENT: u8 = UTXO_STATE_MODIFIED | UTXO_STATE_SPENT;
    const SPENT_BY_ZERO_CONF: u8 =
        UTXO_STATE_MODIFIED | UTXO_STATE_SPENT | UTXO_STATE_SPENT_BY_ZERO_CONF;

    /// A block at [`ZERO_CONF_HEIGHT`] approving its parent, with the
    /// regular tree `[coinbase, A, spends...]`: A spends the external
    /// output into two outputs, and each later transaction spends the
    /// output of A at the given index.  Returns the block and A's hash.
    fn zero_conf_block(spends: &[u32]) -> (MsgBlock, Hash) {
        let params = dcroxide_chaincfg::simnet_params();
        let mut subsidy_cache = dcroxide_standalone::SubsidyCache::new(&params);
        let height = i64::from(ZERO_CONF_HEIGHT);
        let subsidy = subsidy_cache.calc_work_subsidy_v3(
            height,
            0,
            dcroxide_standalone::SubsidySplitVariant::Original,
        ) + subsidy_cache.calc_treasury_subsidy(height, 0, false);
        let (external, _) = sbss_external();
        let a = MsgTx {
            tx_in: alloc::vec![input_spending(external, 5_000, 100, 1)],
            tx_out: alloc::vec![op_true_out(3_000), op_true_out(2_000)],
            ..MsgTx::default()
        };
        let a_hash = a.tx_hash();
        let mut transactions = alloc::vec![test_coinbase(subsidy), a];
        for &index in spends {
            let value = [3_000, 2_000][index as usize];
            transactions.push(MsgTx {
                tx_in: alloc::vec![input_spending(
                    origin_out(a_hash, index),
                    value,
                    ZERO_CONF_HEIGHT,
                    1,
                )],
                tx_out: alloc::vec![op_true_out(value)],
                ..MsgTx::default()
            });
        }
        let (mut header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header");
        header.height = ZERO_CONF_HEIGHT;
        header.vote_bits = 1;
        let block = MsgBlock {
            header,
            transactions,
            stransactions: Vec::new(),
        };
        (block, a_hash)
    }

    /// The backend holding the external output alone.
    fn external_backend() -> BTreeMap<OutPointKey, UtxoEntry> {
        let (external, entry) = sbss_external();
        let mut backend = BTreeMap::new();
        backend.insert((external.hash.0, external.index, external.tree), entry);
        backend
    }

    fn state_of(view: &UtxoView, outpoint: &OutPoint) -> u8 {
        view.lookup_entry(outpoint)
            .expect("in the view")
            .state_bits()
    }

    /// dcrd decides eligibility once per creating transaction, before
    /// any of its outputs is added to the view, and keeps the answer
    /// for later spends of its other outputs
    /// (`utxoviewpoint.go:1166-1177`): spends of A:0 and A:1 by two
    /// later transactions are both zero-confirmation spends, although
    /// the first adds A:0 to the view before the second is looked at.
    #[test]
    fn eligibility_is_decided_once_per_creating_transaction() {
        let (block, a_hash) = zero_conf_block(&[0, 1]);
        let hashes = collect_tx_hashes(&block.transactions);
        let backend = external_backend();
        let resolve = |op: &OutPoint| backend.get(&(op.hash.0, op.index, op.tree)).cloned();

        let mut view = UtxoView::new();
        view.fetch_input_utxos(&block, &hashes, &resolve, false);
        view.connect_regular_transactions(&block, &hashes, None, false);
        for index in 0..2 {
            assert_eq!(
                state_of(&view, &origin_out(a_hash, index)),
                SPENT_BY_ZERO_CONF,
                "A:{index}"
            );
        }
    }

    /// dcrd's `hasAnyRegularTxOut` looks at every output of the
    /// creating transaction (`utxoviewpoint.go:1106-1118`).  A's output
    /// 0 is provably unspendable, so no view holds it; a view that holds
    /// A:1 before the fetch, as the undo of a disapproved parent that
    /// confirmed A leaves it, makes the spend of A:1 later in the block
    /// an ordinary spend, and a view that holds neither makes it a
    /// zero-confirmation spend.
    #[test]
    fn eligibility_looks_at_every_output_of_the_creating_transaction() {
        let (mut block, _) = zero_conf_block(&[]);
        block.transactions[1].tx_out[0] = TxOut {
            value: 0,
            version: 0,
            pk_script: alloc::vec![0x6a],
        };
        let a_hash = block.transactions[1].tx_hash();
        block.transactions.push(MsgTx {
            tx_in: alloc::vec![input_spending(
                origin_out(a_hash, 1),
                2_000,
                ZERO_CONF_HEIGHT,
                1
            )],
            tx_out: alloc::vec![op_true_out(2_000)],
            ..MsgTx::default()
        });
        let hashes = collect_tx_hashes(&block.transactions);
        let backend = external_backend();
        let resolve = |op: &OutPoint| backend.get(&(op.hash.0, op.index, op.tree)).cloned();

        for (holds_a1, want) in [(true, SPENT), (false, SPENT_BY_ZERO_CONF)] {
            let mut view = UtxoView::new();
            if holds_a1 {
                let mut a1 = UtxoEntry::new(
                    2_000,
                    alloc::vec![0x51],
                    ZERO_CONF_HEIGHT - 1,
                    1,
                    0,
                    false,
                    false,
                    TxType::Regular,
                    None,
                );
                a1.spend();
                view.insert_entry(&origin_out(a_hash, 1), a1);
            }
            view.fetch_input_utxos(&block, &hashes, &resolve, false);
            view.connect_regular_transactions(&block, &hashes, None, false);
            assert!(
                view.lookup_entry(&origin_out(a_hash, 0)).is_none(),
                "no view holds A:0"
            );
            assert_eq!(
                state_of(&view, &origin_out(a_hash, 1)),
                want,
                "the view held A:1 before the fetch: {holds_a1}"
            );
        }
    }

    /// The disconnect marks a spend inside the block when its creating
    /// transaction is eligible against the view the disconnect fetched
    /// into (`utxoviewpoint.go:498-502`): a view holding none of A's
    /// outputs marks A:0, re-created spent, and the view the block was
    /// connected in, which still holds them, does not.
    #[test]
    fn the_disconnect_marks_the_in_block_spends_that_are_eligible() {
        let (block, a_hash) = zero_conf_block(&[0]);
        let tx_hashes = crate::blockhashes::BlockTxHashes::compute(&block);
        let parent = stake_block(Vec::new());
        let mut backend = external_backend();

        let mut view = UtxoView::new();
        let mut stxos = Vec::new();
        {
            let resolve = |op: &OutPoint| backend.get(&(op.hash.0, op.index, op.tree)).cloned();
            view.connect_block_with_lookup(
                &no_violation,
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
        assert_eq!(state_of(&view, &origin_out(a_hash, 0)), SPENT_BY_ZERO_CONF);
        let mut connected = view.clone();
        commit_to(&mut backend, &mut view);
        let resolve = |op: &OutPoint| backend.get(&(op.hash.0, op.index, op.tree)).cloned();

        let mut fresh = UtxoView::new();
        fresh
            .disconnect_block_with_lookup(&no_violation, &block, &parent, &stxos, &resolve, false)
            .expect("disconnect");
        assert_eq!(state_of(&fresh, &origin_out(a_hash, 0)), SPENT_BY_ZERO_CONF);
        assert_eq!(state_of(&fresh, &origin_out(a_hash, 1)), SPENT);

        connected
            .disconnect_block_with_lookup(&no_violation, &block, &parent, &stxos, &resolve, false)
            .expect("disconnect");
        assert_eq!(state_of(&connected, &origin_out(a_hash, 0)), SPENT);
    }

    /// The zero-confirmation set lives from the fetch of a block's
    /// inputs until its regular tree is connected or disconnected:
    /// `connectRegularTransactions`, `disconnectRegularTransactions` and
    /// the regular tree of `checkTransactionsAndConnect` clear it
    /// (`utxoviewpoint.go:396`, `:562`, `validate.go:4092-4094`), the
    /// stake tree's leave it, and a copy of the view does not carry it
    /// (`utxoviewpoint.go:1287-1300`).
    #[test]
    fn the_zero_conf_set_lasts_from_the_fetch_to_its_regular_tree() {
        let (block, a_hash) = zero_conf_block(&[0]);
        let hashes = collect_tx_hashes(&block.transactions);
        let backend = external_backend();
        let resolve = |op: &OutPoint| backend.get(&(op.hash.0, op.index, op.tree)).cloned();
        let a0 = key(&origin_out(a_hash, 0));

        let mut view = UtxoView::new();
        view.fetch_input_utxos(&block, &hashes, &resolve, false);
        assert!(view.zero_conf_outs.iter().eq([&a0]));
        assert!(view.clone().zero_conf_outs.is_empty(), "a copy has none");
        view.connect_stake_transactions(&block, &[], None, false);
        assert!(!view.zero_conf_outs.is_empty(), "the stake tree leaves it");
        let mut stxos = Vec::new();
        view.connect_regular_transactions(&block, &hashes, Some(&mut stxos), false);
        assert!(view.zero_conf_outs.is_empty(), "the connect clears it");

        let mut view = UtxoView::new();
        view.fetch_input_utxos(&block, &hashes, &resolve, false);
        view.disconnect_transactions(&block, &[], &stxos, true, false)
            .expect("disconnect stake");
        assert!(!view.zero_conf_outs.is_empty(), "the stake tree leaves it");
        view.disconnect_transactions(&block, &hashes, &stxos, false, false)
            .expect("disconnect regular");
        assert!(view.zero_conf_outs.is_empty(), "the disconnect clears it");

        let params = dcroxide_chaincfg::simnet_params();
        let mut subsidy_cache = dcroxide_standalone::SubsidyCache::new(&params);
        let (mut prev_header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header");
        prev_header.height = ZERO_CONF_HEIGHT - 1;
        let mut view = UtxoView::new();
        view.fetch_input_utxos(&block, &hashes, &resolve, false);
        crate::validate::check_transactions_and_connect(
            &mut subsidy_cache,
            0,
            i64::from(ZERO_CONF_HEIGHT),
            Hash::default(),
            0,
            &prev_header,
            &block.stransactions,
            &[],
            &mut view,
            None,
            true,
            false,
            false,
            dcroxide_standalone::SubsidySplitVariant::Original,
            &params,
        )
        .expect("the stake tree checks");
        assert!(!view.zero_conf_outs.is_empty(), "the stake tree leaves it");
        crate::validate::check_transactions_and_connect(
            &mut subsidy_cache,
            0,
            i64::from(ZERO_CONF_HEIGHT),
            Hash::default(),
            0,
            &prev_header,
            &block.transactions,
            &hashes,
            &mut view,
            None,
            false,
            false,
            false,
            dcroxide_standalone::SubsidySplitVariant::Original,
            &params,
        )
        .expect("the regular tree checks");
        assert_eq!(state_of(&view, &origin_out(a_hash, 0)), SPENT_BY_ZERO_CONF);
        assert!(view.zero_conf_outs.is_empty(), "the check clears it");
    }

    /// dcrd adds the grandfathered output before the fetch, so it is in
    /// the view when eligibility is decided (`utxoviewpoint.go:1235-1239`,
    /// `:947-957`): a later regular transaction's spend of another
    /// output of the listed transaction is then not a zero-confirmation
    /// spend.
    #[test]
    fn the_grandfathered_output_is_in_the_view_when_eligibility_is_decided() {
        let (mut block, origin_hash) = sbss_block();
        block.transactions.push(MsgTx {
            tx_in: alloc::vec![input_spending(
                origin_out(origin_hash, 1),
                2_000,
                SBSS_HEIGHT,
                1
            )],
            tx_out: alloc::vec![op_true_out(2_000)],
            ..MsgTx::default()
        });
        let tx_hashes = crate::blockhashes::BlockTxHashes::compute(&block);
        let parent = stake_block(Vec::new());
        let (external, external_entry) = sbss_external();
        let backend = move |op: &OutPoint| (*op == external).then(|| external_entry.clone());

        let mut view = UtxoView::new();
        view.connect_block_with_lookup(
            &violation_at(SBSS_HEIGHT, origin_hash),
            &block,
            &tx_hashes,
            &parent,
            || Ok(Vec::new()),
            &backend,
            None,
            false,
        )
        .expect("connect");
        assert_eq!(state_of(&view, &origin_out(origin_hash, 1)), SPENT);
    }

    /// dcrd panics when the view lacks an input a transaction spends,
    /// in either tree, with this text (`utxoviewpoint.go:274-280`,
    /// `:342-348`, since `e60cedc5`), where it returned an
    /// `AssertError`.
    #[test]
    fn a_missing_input_panics_in_both_trees() {
        let (block, origin_hash) = zero_conf_block(&[]);
        let a = &block.transactions[1];
        let (external, _) = sbss_external();
        let text = panic_text(|| {
            UtxoView::new().connect_regular_transaction(a, &origin_hash, 120, 1, None, false);
        });
        assert_eq!(
            text,
            alloc::format!("view missing input {external} (tree 0)")
        );

        let ticket_input = OutPoint {
            hash: Hash([0x44; 32]),
            index: 3,
            tree: 1,
        };
        let ticket = ticket_spending(ticket_input, 3_000, 100, 2);
        let text = panic_text(|| {
            UtxoView::new().connect_stake_transaction(
                &ticket,
                &ticket.tx_hash(),
                120,
                1,
                None,
                false,
            );
        });
        assert_eq!(
            text,
            alloc::format!("view missing input {ticket_input} (tree 1)")
        );
    }

    /// dcrd panics when a transaction spends an input the view holds
    /// already spent, in either tree, with this text
    /// (`utxoviewpoint.go:281-284`, `:349-352`, since `22fd2431`).
    #[test]
    fn an_input_the_view_holds_spent_panics_in_both_trees() {
        let (block, origin_hash) = zero_conf_block(&[]);
        let a = &block.transactions[1];
        let (external, mut external_entry) = sbss_external();
        external_entry.spend();
        let mut view = UtxoView::new();
        view.insert_entry(&external, external_entry.clone());
        let text = panic_text(|| {
            view.connect_regular_transaction(a, &origin_hash, 120, 1, None, false);
        });
        assert_eq!(
            text,
            alloc::format!("attempt to spend already spent output {external} (tree 0)")
        );

        let ticket_input = OutPoint {
            hash: Hash([0x44; 32]),
            index: 3,
            tree: 1,
        };
        let ticket = ticket_spending(ticket_input, 5_000, 100, 1);
        let mut view = UtxoView::new();
        view.insert_entry(&ticket_input, external_entry);
        let text = panic_text(|| {
            view.connect_stake_transaction(&ticket, &ticket.tx_hash(), 120, 1, None, false);
        });
        assert_eq!(
            text,
            alloc::format!("attempt to spend already spent output {ticket_input} (tree 1)")
        );
    }

    /// A block's second connect over the same view spends its inputs a
    /// second time.
    #[test]
    #[should_panic(expected = "attempt to spend already spent output")]
    fn connecting_a_regular_transaction_twice_panics() {
        let (block, a_hash) = zero_conf_block(&[]);
        let a = &block.transactions[1];
        let (external, external_entry) = sbss_external();
        let mut view = UtxoView::new();
        view.insert_entry(&external, external_entry);
        view.connect_regular_transaction(a, &a_hash, 120, 1, None, false);
        view.connect_regular_transaction(a, &a_hash, 120, 1, None, false);
    }

    /// The stake tree's counterpart.
    #[test]
    #[should_panic(expected = "attempt to spend already spent output")]
    fn connecting_a_stake_transaction_twice_panics() {
        let (external, external_entry) = sbss_external();
        let ticket = ticket_spending(external, 5_000, 100, 1);
        let ticket_hash = ticket.tx_hash();
        let mut view = UtxoView::new();
        view.insert_entry(&external, external_entry);
        view.connect_stake_transaction(&ticket, &ticket_hash, 120, 1, None, false);
        view.connect_stake_transaction(&ticket, &ticket_hash, 120, 1, None, false);
    }

    /// The output the ticket of [`asserted_block`] spends, confirmed
    /// long before, and its entry.
    fn ticket_external() -> (OutPoint, UtxoEntry) {
        let outpoint = OutPoint {
            hash: Hash([0xdd; 32]),
            index: 0,
            tree: 0,
        };
        let entry = UtxoEntry::new(
            3_000,
            alloc::vec![0x51],
            100,
            2,
            0,
            false,
            false,
            TxType::Regular,
            None,
        );
        (outpoint, entry)
    }

    /// A block at [`ZERO_CONF_HEIGHT`] with the regular tree
    /// `[coinbase, A, B]` and the stake tree `[ticket]`: the coinbase pays
    /// a spendable output and a provably unspendable one, A spends the
    /// external output into two outputs, B spends A's first, and the
    /// ticket spends [`ticket_external`].
    fn asserted_block() -> MsgBlock {
        let (mut block, a_hash) = zero_conf_block(&[0]);
        block.transactions[0].tx_out = alloc::vec![
            op_true_out(1_000),
            TxOut {
                value: 0,
                version: 0,
                pk_script: alloc::vec![0x6a, 0x01, 0x07],
            },
        ];
        assert_eq!(
            block.transactions[2].tx_in[0].previous_out_point,
            origin_out(a_hash, 0)
        );
        let (external, _) = ticket_external();
        block.stransactions = alloc::vec![ticket_spending(external, 3_000, 100, 2)];
        block
    }

    /// The view [`asserted_block`] leaves once it is connected, with the
    /// given lookup of the grandfathered spends and treasury flag.
    fn asserted_view(
        block: &MsgBlock,
        sbss_violation: &impl Fn(i64) -> Option<Hash>,
        external_entries: &[(OutPoint, UtxoEntry)],
        is_treasury_enabled: bool,
    ) -> UtxoView {
        let tx_hashes = crate::blockhashes::BlockTxHashes::compute(block);
        let parent = stake_block(Vec::new());
        let resolve = |op: &OutPoint| {
            external_entries
                .iter()
                .find(|(outpoint, _)| outpoint == op)
                .map(|(_, entry)| entry.clone())
        };
        let mut view = UtxoView::new();
        view.connect_block_with_lookup(
            sbss_violation,
            block,
            &tx_hashes,
            &parent,
            || Ok(Vec::new()),
            &resolve,
            None,
            is_treasury_enabled,
        )
        .expect("connect");
        view
    }

    fn asserted_externals() -> Vec<(OutPoint, UtxoEntry)> {
        alloc::vec![sbss_external(), ticket_external()]
    }

    /// The text `assert_block_utxo_view` panics with over the view and
    /// block with the given treasury flag, or `None` when it holds.
    fn assertion_text(
        view: &UtxoView,
        block: &MsgBlock,
        is_treasury_enabled: bool,
    ) -> Option<String> {
        let tx_hashes = crate::blockhashes::BlockTxHashes::compute(block);
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            view.assert_block_utxo_view_with(&no_violation, block, &tx_hashes, is_treasury_enabled);
        }))
        .err()
        .map(|payload| {
            payload
                .downcast_ref::<String>()
                .cloned()
                .expect("a text payload")
        })
    }

    /// dcrd `assertBlockUtxoView` (`utxoviewpoint.go:633-917`, since
    /// `22fd2431`): the view a block leaves once connected holds, and
    /// each family of its checks panics with dcrd's text when the view,
    /// or the block, is changed in the one way that check catches.
    #[test]
    fn the_block_utxo_view_assertions_panic_with_dcrds_texts() {
        let block = asserted_block();
        let view = asserted_view(&block, &no_violation, &asserted_externals(), false);
        assert_eq!(
            assertion_text(&view, &block, false),
            None,
            "the connected view holds"
        );

        let block_hash = block.header.block_hash();
        let hashes = crate::blockhashes::BlockTxHashes::compute(&block);
        let (coinbase, a, b) = (
            hashes.regular()[0],
            hashes.regular()[1],
            hashes.regular()[2],
        );
        let ticket = hashes.stake()[0];
        let (external, _) = sbss_external();
        let (ticket_input, _) = ticket_external();
        let coinbase_out = origin_out(coinbase, 0);
        let a_out = origin_out(a, 0);
        let ticket_out = OutPoint {
            hash: ticket,
            index: 0,
            tree: 1,
        };
        let a_input = alloc::format!(
            "block {block_hash} regular tree idx 1: tx {a}:0 spending input {external} (tree 0)"
        );
        let ticket_spend = alloc::format!(
            "block {block_hash} stake tree idx 0: tx {ticket}:0 spending input {ticket_input} \
             (tree 0)"
        );
        let coinbase_output =
            alloc::format!("block {block_hash} regular tree idx 0: output {coinbase}:0");
        let ticket_output =
            alloc::format!("block {block_hash} stake tree idx 0: output {ticket}:0");
        let min_outs_len = view
            .lookup_entry(&ticket_out)
            .and_then(UtxoEntry::ticket_minimal_outputs_data)
            .expect("the ticket's minimal outputs")
            .len();

        type Change = Box<dyn Fn(&mut MsgBlock, &mut UtxoView)>;
        let cases: Vec<(&str, Change, String)> = alloc::vec![
            (
                "the first transaction is not a coinbase",
                Box::new(|block: &mut MsgBlock, _: &mut UtxoView| block.transactions.swap(0, 1)),
                alloc::format!("block {block_hash} first tx {a} is not a coinbase"),
            ),
            (
                "a real input spends the null outpoint",
                Box::new(|block: &mut MsgBlock, _: &mut UtxoView| {
                    block.transactions[2].tx_in[0].previous_out_point = null_outpoint();
                }),
                {
                    let mut changed = block.clone();
                    changed.transactions[2].tx_in[0].previous_out_point = null_outpoint();
                    let b = changed.transactions[2].tx_hash();
                    alloc::format!(
                        "block {block_hash} regular tree idx 2: tx {b}:0 spends null outpoint"
                    )
                },
            ),
            (
                "a coinbase input is not the null outpoint",
                Box::new(|block: &mut MsgBlock, _: &mut UtxoView| {
                    block.transactions[0].tx_in[0].previous_out_point.tree = 1;
                }),
                {
                    let mut changed = block.clone();
                    changed.transactions[0].tx_in[0].previous_out_point.tree = 1;
                    let cb = changed.transactions[0].tx_hash();
                    let prev = changed.transactions[0].tx_in[0].previous_out_point;
                    alloc::format!(
                        "block {block_hash} regular tree idx 0: tx {cb}:0 spends non-null outpoint \
                         {prev} (tree 1)"
                    )
                },
            ),
            (
                "an input is missing",
                Box::new(move |_: &mut MsgBlock, view: &mut UtxoView| view.remove_entry(&external)),
                alloc::format!("{a_input}: input is missing from utxo view"),
            ),
            (
                "an input is not spent",
                Box::new(move |_: &mut MsgBlock, view: &mut UtxoView| {
                    view.entries.get_mut(&key(&external)).expect("input").state =
                        UTXO_STATE_MODIFIED;
                }),
                alloc::format!("{a_input}: utxo is not marked spent"),
            ),
            (
                "an input's amount differs from its witness",
                Box::new(|block: &mut MsgBlock, _: &mut UtxoView| {
                    block.transactions[1].tx_in[0].value_in = 4_999;
                }),
                alloc::format!("{a_input}: utxo amount mismatch (entry 5000, input witness 4999)"),
            ),
            (
                "an input's height differs from its witness",
                Box::new(|block: &mut MsgBlock, _: &mut UtxoView| {
                    block.transactions[1].tx_in[0].block_height = 99;
                }),
                alloc::format!(
                    "{a_input}: utxo block height mismatch (entry 100, input witness 99)"
                ),
            ),
            (
                "an input's index differs from its witness",
                Box::new(|block: &mut MsgBlock, _: &mut UtxoView| {
                    block.transactions[1].tx_in[0].block_index = 2;
                }),
                alloc::format!("{a_input}: utxo block index mismatch (entry 1, input witness 2)"),
            ),
            (
                "a stake input is not spent",
                Box::new(move |_: &mut MsgBlock, view: &mut UtxoView| {
                    view.entries
                        .get_mut(&key(&ticket_input))
                        .expect("input")
                        .state = UTXO_STATE_MODIFIED;
                }),
                alloc::format!("{ticket_spend}: utxo is not marked spent"),
            ),
            (
                "a stake input was created in the same block",
                Box::new(move |block: &mut MsgBlock, view: &mut UtxoView| {
                    block.stransactions[0].tx_in[0].block_height = ZERO_CONF_HEIGHT;
                    view.entries
                        .get_mut(&key(&ticket_input))
                        .expect("input")
                        .block_height = ZERO_CONF_HEIGHT;
                }),
                alloc::format!("{ticket_spend}: stake tx spends output from same block"),
            ),
            (
                "an output is missing",
                Box::new(
                    move |_: &mut MsgBlock, view: &mut UtxoView| view.remove_entry(&coinbase_out)
                ),
                alloc::format!("{coinbase_output}: output is missing from utxo view"),
            ),
            (
                "an output no later transaction spends is spent",
                Box::new(move |_: &mut MsgBlock, view: &mut UtxoView| {
                    view.entries
                        .get_mut(&key(&coinbase_out))
                        .expect("output")
                        .spend();
                }),
                alloc::format!("{coinbase_output}: spent state mismatch (entry true, want false)"),
            ),
            // The inputs are checked first, so an output a later
            // transaction spends and the view holds unspent fails as
            // that transaction's input.
            (
                "an output a later transaction spends is not spent",
                Box::new(move |_: &mut MsgBlock, view: &mut UtxoView| {
                    view.entries.get_mut(&key(&a_out)).expect("output").state = UTXO_STATE_MODIFIED;
                }),
                alloc::format!(
                    "block {block_hash} regular tree idx 2: tx {b}:0 spending input {a_out} \
                     (tree 0): utxo is not marked spent"
                ),
            ),
            (
                "an output is not modified",
                Box::new(move |_: &mut MsgBlock, view: &mut UtxoView| {
                    view.entries
                        .get_mut(&key(&coinbase_out))
                        .expect("output")
                        .state = 0;
                }),
                alloc::format!("{coinbase_output}: utxo is not marked modified"),
            ),
            (
                "an output's amount differs",
                Box::new(move |_: &mut MsgBlock, view: &mut UtxoView| {
                    view.entries
                        .get_mut(&key(&coinbase_out))
                        .expect("output")
                        .amount = 999;
                }),
                alloc::format!("{coinbase_output}: amount mismatch (entry 999, tx output 1000)"),
            ),
            (
                "an output's script version differs",
                Box::new(move |_: &mut MsgBlock, view: &mut UtxoView| {
                    view.entries
                        .get_mut(&key(&coinbase_out))
                        .expect("output")
                        .script_version = 1;
                }),
                alloc::format!("{coinbase_output}: script version mismatch (entry 1, tx output 0)"),
            ),
            (
                "an output's script differs",
                Box::new(move |_: &mut MsgBlock, view: &mut UtxoView| {
                    view.entries
                        .get_mut(&key(&coinbase_out))
                        .expect("output")
                        .pk_script = alloc::vec![0x52, 0x0a];
                }),
                alloc::format!(
                    "{coinbase_output}: public key script mismatch (entry 520a, tx output 51)"
                ),
            ),
            (
                "an output's height differs",
                Box::new(move |_: &mut MsgBlock, view: &mut UtxoView| {
                    view.entries
                        .get_mut(&key(&coinbase_out))
                        .expect("output")
                        .block_height = 119;
                }),
                alloc::format!("{coinbase_output}: block height mismatch (entry 119, block 120)"),
            ),
            (
                "an output's index differs",
                Box::new(move |_: &mut MsgBlock, view: &mut UtxoView| {
                    view.entries
                        .get_mut(&key(&coinbase_out))
                        .expect("output")
                        .block_index = 3;
                }),
                alloc::format!("{coinbase_output}: block index mismatch (entry 3, tx idx 0)"),
            ),
            (
                "an output's packed flags differ",
                Box::new(move |_: &mut MsgBlock, view: &mut UtxoView| {
                    view.entries
                        .get_mut(&key(&ticket_out))
                        .expect("output")
                        .packed_flags = 0x1a;
                }),
                alloc::format!("{ticket_output}: packed flags mismatch (entry 1a, want 4)"),
            ),
            (
                "a ticket submission output lacks its minimal outputs",
                Box::new(move |_: &mut MsgBlock, view: &mut UtxoView| {
                    view.entries
                        .get_mut(&key(&ticket_out))
                        .expect("output")
                        .ticket_min_outs = None;
                }),
                alloc::format!(
                    "{ticket_output}: ticket minimal outputs presence mismatch (entry present \
                     false, want true)"
                ),
            ),
            (
                "another output carries minimal outputs",
                Box::new(move |_: &mut MsgBlock, view: &mut UtxoView| {
                    view.entries
                        .get_mut(&key(&coinbase_out))
                        .expect("output")
                        .ticket_min_outs = Some(Vec::new());
                }),
                alloc::format!(
                    "{coinbase_output}: ticket minimal outputs presence mismatch (entry present \
                     true, want false)"
                ),
            ),
            (
                "a ticket's minimal outputs differ",
                Box::new(move |_: &mut MsgBlock, view: &mut UtxoView| {
                    let entry = view.entries.get_mut(&key(&ticket_out)).expect("output");
                    entry.ticket_min_outs.as_mut().expect("minimal outputs")[0] ^= 1;
                }),
                alloc::format!(
                    "{ticket_output}: ticket minimal outputs data mismatch (entry size \
                     {min_outs_len}, expected size {min_outs_len})"
                ),
            ),
        ];
        for (name, change, want) in &cases {
            let mut changed_block = block.clone();
            let mut changed_view = view.clone();
            change(&mut changed_block, &mut changed_view);
            assert_eq!(
                assertion_text(&changed_view, &changed_block, false).as_deref(),
                Some(want.as_str()),
                "{name}"
            );
        }
    }

    /// A treasury add spending [`ticket_external`], paying 2_000 to the
    /// treasury and 900 to its change.
    fn treasury_add() -> MsgTx {
        let (external, _) = ticket_external();
        let mut change = alloc::vec![0xbd, 0x76, 0xa9, 0x14]; // OP_SSTXCHANGE p2pkh
        change.extend_from_slice(&[0x11; 20]);
        change.extend_from_slice(&[0x88, 0xac]);
        MsgTx {
            version: dcroxide_stake::TX_VERSION_TREASURY,
            tx_in: alloc::vec![input_spending(external, 3_000, 100, 2)],
            tx_out: alloc::vec![
                TxOut {
                    value: 2_000,
                    version: 0,
                    pk_script: alloc::vec![0xc1], // OP_TADD
                },
                TxOut {
                    value: 900,
                    version: 0,
                    pk_script: change,
                },
            ],
            ..MsgTx::default()
        }
    }

    /// A treasury spend paying 1_500 from the treasury.
    fn treasury_spend() -> MsgTx {
        let mut signature_script = alloc::vec![0x40]; // OP_DATA_64
        signature_script.extend_from_slice(&[0x55; 64]);
        signature_script.extend_from_slice(&[0x21, 0x02]); // OP_DATA_33, even key
        signature_script.extend_from_slice(&[0x66; 32]);
        signature_script.push(0xc2); // OP_TSPEND
        let mut op_return = alloc::vec![0x6a, 0x20]; // OP_RETURN OP_DATA_32
        op_return.extend_from_slice(&[0x77; 32]);
        let mut payee = alloc::vec![0xc3, 0x76, 0xa9, 0x14]; // OP_TGEN p2pkh
        payee.extend_from_slice(&[0x12; 20]);
        payee.extend_from_slice(&[0x88, 0xac]);
        MsgTx {
            version: dcroxide_stake::TX_VERSION_TREASURY,
            tx_in: alloc::vec![TxIn {
                previous_out_point: null_outpoint(),
                sequence: u32::MAX,
                value_in: 1_600,
                block_height: 0,
                block_index: u32::MAX,
                signature_script,
            }],
            tx_out: alloc::vec![
                TxOut {
                    value: 0,
                    version: 0,
                    pk_script: op_return,
                },
                TxOut {
                    value: 1_500,
                    version: 0,
                    pk_script: payee,
                },
            ],
            expiry: ZERO_CONF_HEIGHT + 10,
            ..MsgTx::default()
        }
    }

    /// [`asserted_block`] under the treasury agenda: a version 3
    /// coinbase, and the stake tree `[treasurybase, treasury add,
    /// treasury spend]` in place of the ticket, the treasurybase paying
    /// 1_000 at output 0.
    fn asserted_treasury_block() -> MsgBlock {
        let mut block = asserted_block();
        block.transactions[0].version = dcroxide_stake::TX_VERSION_TREASURY;
        block.stransactions = alloc::vec![treasury_base(0), treasury_add(), treasury_spend()];
        let types: Vec<TxType> = block
            .stransactions
            .iter()
            .map(dcroxide_stake::determine_tx_type)
            .collect();
        assert_eq!(
            types,
            alloc::vec![TxType::TreasuryBase, TxType::TAdd, TxType::TSpend]
        );
        block
    }

    /// dcrd `assertBlockUtxoView` under the treasury agenda: a
    /// treasurybase's outputs never enter the view and are not checked,
    /// a treasury spend's first input is a null outpoint, and a treasury
    /// add's output 0 is not a utxo (`utxoviewpoint.go:705-707`,
    /// `:804-806`, `:817-818`).  The view a block with all three leaves
    /// holds; the treasurybase is skipped only with the agenda active,
    /// and the other parts of those transactions are checked as any
    /// other transaction's.
    #[test]
    fn the_block_utxo_view_assertions_cover_the_treasury_transactions() {
        let block = asserted_treasury_block();
        let view = asserted_view(&block, &no_violation, &asserted_externals(), true);
        assert_eq!(
            assertion_text(&view, &block, true),
            None,
            "the connected view holds"
        );

        let block_hash = block.header.block_hash();
        let hashes = crate::blockhashes::BlockTxHashes::compute(&block);
        let (treasury_base_hash, tadd, tspend) =
            (hashes.stake()[0], hashes.stake()[1], hashes.stake()[2]);
        let (ticket_input, _) = ticket_external();
        let stake_out = |hash: Hash, index: u32| OutPoint {
            hash,
            index,
            tree: 1,
        };
        assert_eq!(
            assertion_text(&view, &block, false),
            Some(alloc::format!(
                "block {block_hash} stake tree idx 0: output {treasury_base_hash}:0: output is \
                 missing from utxo view"
            )),
            "without the agenda the treasurybase's output 0 must be a utxo"
        );

        let not_null = OutPoint {
            hash: Hash([0x99; 32]),
            index: 0,
            tree: 0,
        };
        let mut changed_tspend = block.stransactions[2].clone();
        changed_tspend.tx_in[0].previous_out_point = not_null;
        type Change = Box<dyn Fn(&mut MsgBlock, &mut UtxoView)>;
        let cases: Vec<(&str, Change, String)> = alloc::vec![
            (
                "a treasury spend's input is not the null outpoint",
                Box::new(move |block: &mut MsgBlock, _: &mut UtxoView| {
                    block.stransactions[2].tx_in[0].previous_out_point = not_null;
                }),
                alloc::format!(
                    "block {block_hash} stake tree idx 2: tx {}:0 spends non-null outpoint \
                     {not_null} (tree 0)",
                    changed_tspend.tx_hash()
                ),
            ),
            (
                "a treasury add's input is not spent",
                Box::new(move |_: &mut MsgBlock, view: &mut UtxoView| {
                    view.entries
                        .get_mut(&key(&ticket_input))
                        .expect("input")
                        .state = UTXO_STATE_MODIFIED;
                }),
                alloc::format!(
                    "block {block_hash} stake tree idx 1: tx {tadd}:0 spending input \
                     {ticket_input} (tree 0): utxo is not marked spent"
                ),
            ),
            (
                "a treasury add's change is missing",
                Box::new(move |_: &mut MsgBlock, view: &mut UtxoView| {
                    view.remove_entry(&stake_out(tadd, 1));
                }),
                alloc::format!(
                    "block {block_hash} stake tree idx 1: output {tadd}:1: output is missing \
                     from utxo view"
                ),
            ),
            (
                "a treasury spend's payment is missing",
                Box::new(move |_: &mut MsgBlock, view: &mut UtxoView| {
                    view.remove_entry(&stake_out(tspend, 1));
                }),
                alloc::format!(
                    "block {block_hash} stake tree idx 2: output {tspend}:1: output is missing \
                     from utxo view"
                ),
            ),
        ];
        for (name, change, want) in &cases {
            let mut changed_block = block.clone();
            let mut changed_view = view.clone();
            change(&mut changed_block, &mut changed_view);
            assert_eq!(
                assertion_text(&changed_view, &changed_block, true).as_deref(),
                Some(want.as_str()),
                "{name}"
            );
        }
    }

    /// Which of a block's outputs must be spent follows dcrd's map of
    /// the regular tree's spends, which the last spender of an output
    /// writes (`utxoviewpoint.go:648-674`, `:831-839`): an output of the
    /// regular tree is spent when that spender comes after its creator,
    /// and an output of the stake tree never is.  Validation refuses
    /// every block below before its view is built, so the views are laid
    /// out, or changed, here by hand.
    #[test]
    fn the_spent_state_an_output_needs_follows_its_last_spender() {
        let (external, external_entry) = sbss_external();
        let (other, other_entry) = ticket_external();
        let spending = |outpoint: OutPoint, value: i64, height: u32, index: u32| MsgTx {
            tx_in: alloc::vec![input_spending(outpoint, value, height, index)],
            tx_out: alloc::vec![op_true_out(value)],
            ..MsgTx::default()
        };
        let laid_out = |transactions: Vec<MsgTx>| {
            let (mut header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header");
            header.height = ZERO_CONF_HEIGHT;
            header.vote_bits = 1;
            let mut coinbase = test_coinbase(0);
            coinbase.tx_out = alloc::vec![op_true_out(1_000)];
            let mut regular = alloc::vec![coinbase];
            regular.extend(transactions);
            let block = MsgBlock {
                header,
                transactions: regular,
                stransactions: Vec::new(),
            };
            let hashes = crate::blockhashes::BlockTxHashes::compute(&block);
            let mut view = UtxoView::new();
            for (outpoint, mut entry) in [
                (external, external_entry.clone()),
                (other, other_entry.clone()),
            ] {
                entry.spend();
                view.insert_entry(&outpoint, entry);
            }
            for (idx, (tx, hash)) in block.transactions.iter().zip(hashes.regular()).enumerate() {
                view.add_tx_outs_with_hash(
                    tx,
                    hash,
                    i64::from(ZERO_CONF_HEIGHT),
                    idx as u32,
                    false,
                );
            }
            for tx in &block.transactions[1..] {
                view.lookup_entry_mut(&tx.tx_in[0].previous_out_point)
                    .expect("spent output")
                    .spend();
            }
            (block, view)
        };

        // B's output is spent by A, which comes before B.
        let b = spending(external, 5_000, 100, 1);
        let b_out = origin_out(b.tx_hash(), 0);
        let a = spending(b_out, 5_000, ZERO_CONF_HEIGHT, 2);
        let (block, view) = laid_out(alloc::vec![a, b]);
        assert_eq!(
            assertion_text(&view, &block, false),
            Some(alloc::format!(
                "block {} regular tree idx 2: output {b_out}: spent state mismatch (entry true, \
                 want false)",
                block.header.block_hash()
            ))
        );

        // A's output is spent by P before A and by Q after it.
        let a = spending(other, 3_000, 100, 2);
        let a_out = origin_out(a.tx_hash(), 0);
        let p = spending(a_out, 3_000, ZERO_CONF_HEIGHT, 2);
        let mut q = spending(a_out, 3_000, ZERO_CONF_HEIGHT, 2);
        q.tx_out[0].value = 2_999;
        let (block, view) = laid_out(alloc::vec![p, a, q]);
        assert_eq!(assertion_text(&view, &block, false), None);

        // The ticket's payment is spent by C after it, in the regular
        // tree, and the view holds it spent: an output of the stake tree
        // must be unspent whatever the regular tree spends.
        let mut block = asserted_block();
        let mut view = asserted_view(&block, &no_violation, &asserted_externals(), false);
        let ticket = crate::blockhashes::BlockTxHashes::compute(&block).stake()[0];
        let ticket_out = OutPoint {
            hash: ticket,
            index: 0,
            tree: 1,
        };
        let c = spending(ticket_out, 3_000, ZERO_CONF_HEIGHT, 0);
        let c_index = block.transactions.len() as u32;
        view.add_tx_outs_with_hash(
            &c,
            &c.tx_hash(),
            i64::from(ZERO_CONF_HEIGHT),
            c_index,
            false,
        );
        view.lookup_entry_mut(&ticket_out)
            .expect("the ticket's payment")
            .spend();
        block.transactions.push(c);
        assert_eq!(
            assertion_text(&view, &block, false),
            Some(alloc::format!(
                "block {} stake tree idx 0: output {ticket}:0: spent state mismatch (entry true, \
                 want false)",
                block.header.block_hash()
            ))
        );
    }

    /// The grandfathered spends are the assertion's one exception: in
    /// the view a grandfathered block leaves, the ticket's input is
    /// unspent and was created in the same block, which passes with the
    /// lookup and fails without it, as dcrd's comment says the
    /// assertion would have caught those spends.  The exception covers
    /// output 0 of the regular transaction the lookup names, spent from
    /// the stake tree, and nothing else (`utxoviewpoint.go:738-740`).
    #[test]
    fn the_grandfathered_spend_is_the_assertions_one_exception() {
        let (block, origin_hash) = sbss_block();
        let tx_hashes = crate::blockhashes::BlockTxHashes::compute(&block);
        let parent = stake_block(Vec::new());
        let (external, external_entry) = sbss_external();
        let backend = move |op: &OutPoint| (*op == external).then(|| external_entry.clone());
        let lookup = violation_at(SBSS_HEIGHT, origin_hash);
        let mut view = UtxoView::new();
        view.connect_block_with_lookup(
            &lookup,
            &block,
            &tx_hashes,
            &parent,
            || Ok(Vec::new()),
            &backend,
            None,
            false,
        )
        .expect("connect");

        view.assert_block_utxo_view_with(&lookup, &block, &tx_hashes, false);

        let ticket = tx_hashes.stake()[0];
        let text = panic_text(|| {
            view.assert_block_utxo_view_with(&no_violation, &block, &tx_hashes, false);
        });
        assert_eq!(
            text,
            alloc::format!(
                "block {} stake tree idx 0: tx {ticket}:0 spending input {origin_hash}:0 (tree 0): \
                 utxo is not marked spent",
                block.header.block_hash()
            )
        );

        // The exception is the stake tree's alone: a regular transaction
        // spending the same output, which the view holds unspent, fails.
        let mut regular_spend = block.clone();
        regular_spend.transactions.push(MsgTx {
            tx_in: alloc::vec![input_spending(
                origin_out(origin_hash, 0),
                3_000,
                SBSS_HEIGHT,
                1
            )],
            tx_out: alloc::vec![op_true_out(3_000)],
            ..MsgTx::default()
        });
        let spend_hashes = crate::blockhashes::BlockTxHashes::compute(&regular_spend);
        let spender = spend_hashes.regular()[2];
        let text = panic_text(|| {
            view.assert_block_utxo_view_with(&lookup, &regular_spend, &spend_hashes, false);
        });
        assert_eq!(
            text,
            alloc::format!(
                "block {} regular tree idx 2: tx {spender}:0 spending input {origin_hash}:0 \
                 (tree 0): utxo is not marked spent",
                block.header.block_hash()
            )
        );

        // Nor is any other output of the transaction the lookup names: a
        // ticket spending its output 1, which the view holds unspent,
        // fails with the lookup.
        let spending_instead = |outpoint: OutPoint, value: i64| {
            let mut changed = block.clone();
            changed.stransactions[0].tx_in[0] = input_spending(outpoint, value, SBSS_HEIGHT, 1);
            changed
        };
        let changed = spending_instead(origin_out(origin_hash, 1), 2_000);
        let changed_hashes = crate::blockhashes::BlockTxHashes::compute(&changed);
        let changed_ticket = changed_hashes.stake()[0];
        let text = panic_text(|| {
            view.assert_block_utxo_view_with(&lookup, &changed, &changed_hashes, false);
        });
        assert_eq!(
            text,
            alloc::format!(
                "block {} stake tree idx 0: tx {changed_ticket}:0 spending input {origin_hash}:1 \
                 (tree 0): utxo is not marked spent",
                block.header.block_hash()
            )
        );

        // Nor is output 0 of the stake tree under that hash, given to the
        // view here unspent.
        let stake_out = OutPoint {
            hash: origin_hash,
            index: 0,
            tree: 1,
        };
        let mut stake_view = view.clone();
        stake_view.insert_entry(
            &stake_out,
            UtxoEntry::new(
                3_000,
                alloc::vec![0x51],
                SBSS_HEIGHT,
                1,
                0,
                false,
                false,
                TxType::Regular,
                None,
            ),
        );
        let changed = spending_instead(stake_out, 3_000);
        let changed_hashes = crate::blockhashes::BlockTxHashes::compute(&changed);
        let changed_ticket = changed_hashes.stake()[0];
        let text = panic_text(|| {
            stake_view.assert_block_utxo_view_with(&lookup, &changed, &changed_hashes, false);
        });
        assert_eq!(
            text,
            alloc::format!(
                "block {} stake tree idx 0: tx {changed_ticket}:0 spending input {origin_hash}:0 \
                 (tree 1): utxo is not marked spent",
                block.header.block_hash()
            )
        );
    }
}
