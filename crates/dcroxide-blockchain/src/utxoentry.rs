// SPDX-License-Identifier: ISC
//! Unspent transaction output entries (dcrd internal/blockchain
//! `utxoentry.go`).

use alloc::boxed::Box;
use alloc::vec::Vec;

use dcroxide_stake::TxType;

use crate::pkscript::PkScript;

/// In-memory state bit: the entry was modified since load (dcrd
/// `utxoStateModified`).
pub const UTXO_STATE_MODIFIED: u8 = 1 << 0;
/// In-memory state bit: the output has been spent.
pub const UTXO_STATE_SPENT: u8 = 1 << 1;
/// In-memory state bit: spent by a transaction in the same block.
pub const UTXO_STATE_SPENT_BY_ZERO_CONF: u8 = 1 << 2;
/// In-memory state bit: the entry is fresh (not yet in the backend).
pub const UTXO_STATE_FRESH: u8 = 1 << 3;

/// Packed flag bit: the output is from a coinbase (dcrd
/// `utxoFlagCoinBase`).
const UTXO_FLAG_COIN_BASE: u8 = 1 << 0;
/// Packed flag bit: the containing transaction has an expiry.
const UTXO_FLAG_HAS_EXPIRY: u8 = 1 << 1;
/// Packed flag bits 2-5: the stake transaction type.
const UTXO_FLAG_TX_TYPE_BITMASK: u8 = 0x3c;
const UTXO_FLAG_TX_TYPE_SHIFT: u8 = 2;

/// Encode the packed entry flags (dcrd `encodeUtxoFlags`); identical
/// bit layout to the serialized txout flags.
pub fn encode_utxo_flags(coinbase: bool, has_expiry: bool, tx_type: TxType) -> u8 {
    let mut packed = (tx_type as u8) << UTXO_FLAG_TX_TYPE_SHIFT;
    if coinbase {
        packed |= UTXO_FLAG_COIN_BASE;
    }
    if has_expiry {
        packed |= UTXO_FLAG_HAS_EXPIRY;
    }
    packed
}

/// Whether the output is the submission output of a ticket purchase
/// (dcrd `isTicketSubmissionOutput`).
pub fn is_ticket_submission_output(tx_type: u8, tx_out_idx: u32) -> bool {
    tx_type == TxType::SStx as u8 && tx_out_idx == 0
}

/// An unspent transaction output (dcrd `UtxoEntry`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoEntry {
    pub(crate) amount: i64,
    /// The script, held in place when it is short, as pay-to-pubkey-hash
    /// and pay-to-script-hash scripts are (see [`PkScript`]).
    pub(crate) pk_script: PkScript,
    /// The serialized minimal outputs of the ticket purchase, kept when
    /// this entry is a ticket submission output (dcrd
    /// `ticketMinimalOutputs.data`).  A boxed slice rather than a
    /// vector: the eight bytes it saves keep the entry at the size it
    /// had before the script moved in place (72 bytes on 64-bit
    /// targets), and with it the nodes of the view's and the cache's
    /// maps.
    pub(crate) ticket_min_outs: Option<Box<[u8]>>,
    pub(crate) block_height: u32,
    pub(crate) block_index: u32,
    pub(crate) script_version: u16,
    pub(crate) state: u8,
    /// The raw packed flags byte; the transaction type bits may carry
    /// values beyond the defined stake types, exactly like dcrd's
    /// unchecked `stake.TxType` cast.
    pub(crate) packed_flags: u8,
}

impl UtxoEntry {
    /// The raw in-memory state byte (test and persistence aid).
    pub fn state_bits(&self) -> u8 {
        self.state
    }

    /// Overwrite the raw in-memory state byte (test and persistence
    /// aid).
    pub fn set_state_bits(&mut self, state: u8) {
        self.state = state;
    }

    /// The raw packed flags byte (test and persistence aid).
    pub fn packed_flags_bits(&self) -> u8 {
        self.packed_flags
    }

    /// Overwrite the raw packed flags byte (test and persistence
    /// aid).
    pub fn set_packed_flags_bits(&mut self, flags: u8) {
        self.packed_flags = flags;
    }

    /// Construct an entry for the given output data.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        amount: i64,
        pk_script: Vec<u8>,
        block_height: u32,
        block_index: u32,
        script_version: u16,
        coinbase: bool,
        has_expiry: bool,
        tx_type: TxType,
        ticket_min_outs: Option<Vec<u8>>,
    ) -> UtxoEntry {
        UtxoEntry::with_script(
            amount,
            PkScript::from(pk_script),
            block_height,
            block_index,
            script_version,
            coinbase,
            has_expiry,
            tx_type,
            ticket_min_outs.map(Vec::into_boxed_slice),
        )
    }

    /// [`UtxoEntry::new`] for a script and minimal outputs already in
    /// the forms the entry holds them in.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_script(
        amount: i64,
        pk_script: PkScript,
        block_height: u32,
        block_index: u32,
        script_version: u16,
        coinbase: bool,
        has_expiry: bool,
        tx_type: TxType,
        ticket_min_outs: Option<Box<[u8]>>,
    ) -> UtxoEntry {
        UtxoEntry {
            amount,
            pk_script,
            ticket_min_outs,
            block_height,
            block_index,
            script_version,
            state: 0,
            packed_flags: encode_utxo_flags(coinbase, has_expiry, tx_type),
        }
    }

    /// Whether the entry was modified since load (dcrd `isModified`).
    pub fn is_modified(&self) -> bool {
        self.state & UTXO_STATE_MODIFIED == UTXO_STATE_MODIFIED
    }

    /// Whether the entry is fresh (dcrd `isFresh`).
    pub fn is_fresh(&self) -> bool {
        self.state & UTXO_STATE_FRESH == UTXO_STATE_FRESH
    }

    /// Whether the output was spent by a transaction in the same block
    /// (dcrd `isSpentByZeroConf`).
    pub fn is_spent_by_zero_conf(&self) -> bool {
        self.state & UTXO_STATE_SPENT_BY_ZERO_CONF == UTXO_STATE_SPENT_BY_ZERO_CONF
    }

    /// Whether the output is from a coinbase (dcrd `IsCoinBase`).
    pub fn is_coin_base(&self) -> bool {
        self.packed_flags & UTXO_FLAG_COIN_BASE == UTXO_FLAG_COIN_BASE
    }

    /// Whether the output has been spent (dcrd `IsSpent`).
    pub fn is_spent(&self) -> bool {
        self.state & UTXO_STATE_SPENT == UTXO_STATE_SPENT
    }

    /// Whether the containing transaction has an expiry (dcrd
    /// `HasExpiry`).
    pub fn has_expiry(&self) -> bool {
        self.packed_flags & UTXO_FLAG_HAS_EXPIRY == UTXO_FLAG_HAS_EXPIRY
    }

    /// The height of the containing block (dcrd `BlockHeight`).
    pub fn block_height(&self) -> i64 {
        i64::from(self.block_height)
    }

    /// The index of the containing transaction in its block (dcrd
    /// `BlockIndex`).
    pub fn block_index(&self) -> u32 {
        self.block_index
    }

    /// The raw stake transaction type bits of the containing
    /// transaction (dcrd `TransactionType`, which performs the same
    /// unchecked cast).
    pub fn transaction_type(&self) -> u8 {
        (self.packed_flags & UTXO_FLAG_TX_TYPE_BITMASK) >> UTXO_FLAG_TX_TYPE_SHIFT
    }

    /// Mark the output as spent (dcrd `Spend`); idempotent.
    pub fn spend(&mut self) {
        if self.is_spent() {
            return;
        }
        self.state |= UTXO_STATE_SPENT | UTXO_STATE_MODIFIED;
    }

    /// The output amount in atoms (dcrd `Amount`).
    pub fn amount(&self) -> i64 {
        self.amount
    }

    /// The output public key script (dcrd `PkScript`).
    pub fn pk_script(&self) -> &[u8] {
        self.pk_script.as_slice()
    }

    /// The output script version (dcrd `ScriptVersion`).
    pub fn script_version(&self) -> u16 {
        self.script_version
    }

    /// The serialized minimal outputs of the ticket purchase when this
    /// entry is a ticket submission output.
    pub fn ticket_minimal_outputs_data(&self) -> Option<&[u8]> {
        self.ticket_min_outs.as_deref()
    }

    /// The decoded minimal outputs of the ticket purchase when this
    /// entry is a ticket submission output; `None` for every other
    /// output type (dcrd `TicketMinimalOutputs`).
    pub fn ticket_minimal_outputs(&self) -> Option<Vec<dcroxide_stake::MinimalOutput>> {
        self.ticket_min_outs
            .as_ref()
            .map(|data| crate::chainio::deserialize_to_minimal_outputs(data).0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Holding the script in place does not grow the entry: the maps
    /// of the view and the cache keep nodes of the same size, and the
    /// cache's `Option` still costs nothing.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn an_entry_keeps_its_size() {
        assert_eq!(core::mem::size_of::<UtxoEntry>(), 72);
        assert_eq!(core::mem::size_of::<Option<UtxoEntry>>(), 72);
    }

    /// The vector forms [`UtxoEntry::new`] takes land as the same
    /// bytes, and a pay-to-pubkey-hash script is held in place.
    #[test]
    fn new_keeps_the_bytes_it_is_given() {
        let script = [&[0x76, 0xa9, 0x14][..], &[0x5a; 20], &[0x88, 0xac]].concat();
        let min_outs = alloc::vec![1u8, 2, 3];
        let entry = UtxoEntry::new(
            7,
            script.clone(),
            1,
            2,
            0,
            false,
            false,
            TxType::SStx,
            Some(min_outs.clone()),
        );
        assert_eq!(entry.pk_script(), script.as_slice());
        assert!(entry.pk_script.is_inline());
        assert_eq!(
            entry.ticket_minimal_outputs_data(),
            Some(min_outs.as_slice())
        );
        let long = alloc::vec![0x51; 67];
        let entry = UtxoEntry::new(
            7,
            long.clone(),
            1,
            2,
            0,
            false,
            false,
            TxType::Regular,
            None,
        );
        assert_eq!(entry.pk_script(), long.as_slice());
        assert!(!entry.pk_script.is_inline());
        assert_eq!(entry.ticket_minimal_outputs_data(), None);
    }
}
