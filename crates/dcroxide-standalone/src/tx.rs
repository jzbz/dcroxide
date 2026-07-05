// SPDX-License-Identifier: ISC
//! Context-free transaction identification and sanity checks (dcrd
//! blockchain/standalone `tx.go`).

use alloc::collections::BTreeSet;
use alloc::format;

use dcroxide_chainhash::Hash;
use dcroxide_wire::MsgTx;

use crate::error::{ErrorKind, RuleError, rule_error};

// These constants are opcodes defined here to avoid a dependency on
// txscript, exactly as dcrd's standalone package does.  They are used in
// consensus code which can't be changed without a vote anyway.
const OP_DATA_12: u8 = 0x0c;
const OP_RETURN: u8 = 0x6a;
const OP_TADD: u8 = 0xc1;
const OP_TSPEND: u8 = 0xc2;
const OP_TGEN: u8 = 0xc3;

/// The number of atoms in one coin (dcrd's private `atomsPerCoin`).
const ATOMS_PER_COIN: i64 = 100_000_000;

/// The maximum transaction amount allowed in atoms (dcrd's private
/// `maxAtoms`).
const MAX_ATOMS: i64 = 21_000_000 * ATOMS_PER_COIN;

/// The treasury transaction version (dcrd `wire.TxVersionTreasury`).
const TX_VERSION_TREASURY: u16 = 3;

/// Whether or not a transaction is a coinbase: a special transaction
/// created by miners with a single input whose previous output has the
/// maximum index and a zero hash (dcrd `IsCoinBaseTx`).
pub fn is_coin_base_tx(tx: &MsgTx, is_treasury_enabled: bool) -> bool {
    // A coinbase must be version 3 once the treasury agenda is active.
    if is_treasury_enabled && tx.version != TX_VERSION_TREASURY {
        return false;
    }

    // A coinbase must only have one transaction input.
    if tx.tx_in.len() != 1 {
        return false;
    }

    // The previous output of a coinbase must have a max value index and
    // a zero hash.
    let prev_out = &tx.tx_in[0].previous_out_point;
    if prev_out.index != u32::MAX || prev_out.hash != Hash::ZERO {
        return false;
    }

    // Whether the transaction is likely to be a treasury spend for the
    // purposes of differentiating it from a coinbase (dcrd's inner
    // `isTreasurySpendLike`).  Relies on the checks above to avoid
    // panics.
    let is_treasury_spend_like = |tx: &MsgTx| -> bool {
        // Treasury spends have at least two outputs.
        if tx.tx_out.len() < 2 {
            return false;
        }

        // Treasury spends have scripts in the first input and all
        // outputs.
        let l = tx.tx_in[0].signature_script.len();
        if l == 0 || tx.tx_out[0].pk_script.is_empty() || tx.tx_out[1].pk_script.is_empty() {
            return false;
        }

        // Treasury spends have an OP_TSPEND as the last byte of the
        // signature script of the first input, an OP_RETURN as the first
        // byte of the public key script of the first output, and at
        // least one output with an OP_TGEN as the first byte of its
        // public key script.
        tx.tx_in[0].signature_script[l - 1] == OP_TSPEND
            && tx.tx_out[0].pk_script[0] == OP_RETURN
            && tx.tx_out[1].pk_script[0] == OP_TGEN
    };

    // Avoid detecting treasury spends as a coinbase transaction when the
    // treasury agenda is active.
    if is_treasury_enabled && is_treasury_spend_like(tx) {
        return false;
    }

    true
}

/// Whether the first input's previous outpoint is the null outpoint
/// (dcrd's private `isNullOutpoint`).
fn is_null_outpoint(tx: &MsgTx) -> bool {
    let null_in_op = &tx.tx_in[0].previous_out_point;
    null_in_op.index == u32::MAX && null_in_op.hash == Hash::ZERO && null_in_op.tree == 0
}

/// A minimal check to see if a transaction is a treasury base (dcrd
/// `IsTreasuryBase`).
pub fn is_treasury_base(tx: &MsgTx) -> bool {
    if tx.version != TX_VERSION_TREASURY {
        return false;
    }

    if tx.tx_in.len() != 1 || tx.tx_out.len() != 2 {
        return false;
    }

    if !tx.tx_in[0].signature_script.is_empty() {
        return false;
    }

    if tx.tx_out[0].pk_script.len() != 1 || tx.tx_out[0].pk_script[0] != OP_TADD {
        return false;
    }

    if tx.tx_out[1].pk_script.len() != 14
        || tx.tx_out[1].pk_script[0] != OP_RETURN
        || tx.tx_out[1].pk_script[1] != OP_DATA_12
    {
        return false;
    }

    is_null_outpoint(tx)
}

/// Perform some preliminary, context-free sanity checks on a transaction
/// (dcrd `CheckTransactionSanity`).
pub fn check_transaction_sanity(tx: &MsgTx, max_tx_size: u64) -> Result<(), RuleError> {
    // A transaction must have at least one input.
    if tx.tx_in.is_empty() {
        return Err(rule_error(
            ErrorKind::NoTxInputs,
            "transaction has no inputs",
        ));
    }

    // A transaction must have at least one output.
    if tx.tx_out.is_empty() {
        return Err(rule_error(
            ErrorKind::NoTxOutputs,
            "transaction has no outputs",
        ));
    }

    // A transaction must not exceed the maximum allowed size when
    // serialized.
    let serialized_tx_size = tx.serialize_size() as u64;
    if serialized_tx_size > max_tx_size {
        let str = format!(
            "serialized transaction is too big - got {serialized_tx_size}, max {max_tx_size}"
        );
        return Err(rule_error(ErrorKind::TxTooBig, str));
    }

    // Ensure the transaction amounts are in range.  Each transaction
    // output must not be negative or more than the max allowed per
    // transaction, and the total of all outputs must abide by the same
    // restrictions.
    let mut total_atoms: i64 = 0;
    for tx_out in &tx.tx_out {
        let atoms = tx_out.value;
        if atoms < 0 {
            let str = format!("transaction output has negative value of {atoms}");
            return Err(rule_error(ErrorKind::BadTxOutValue, str));
        }
        if atoms > MAX_ATOMS {
            let str = format!(
                "transaction output value of {atoms} is higher than max allowed value \
                 of {MAX_ATOMS}"
            );
            return Err(rule_error(ErrorKind::BadTxOutValue, str));
        }

        // Two's complement int64 overflow guarantees that any overflow
        // is detected and reported, exactly like dcrd (hence the
        // wrapping addition).
        total_atoms = total_atoms.wrapping_add(atoms);
        if total_atoms < 0 {
            let str = format!(
                "total value of all transaction outputs exceeds max allowed value of \
                 {MAX_ATOMS}"
            );
            return Err(rule_error(ErrorKind::BadTxOutValue, str));
        }
        if total_atoms > MAX_ATOMS {
            let str = format!(
                "total value of all transaction outputs is {total_atoms} which is \
                 higher than max allowed value of {MAX_ATOMS}"
            );
            return Err(rule_error(ErrorKind::BadTxOutValue, str));
        }
    }

    // Check for duplicate transaction inputs.
    let mut existing_tx_out: BTreeSet<([u8; 32], u32, i8)> = BTreeSet::new();
    for tx_in in &tx.tx_in {
        let key = (
            tx_in.previous_out_point.hash.0,
            tx_in.previous_out_point.index,
            tx_in.previous_out_point.tree,
        );
        if !existing_tx_out.insert(key) {
            return Err(rule_error(
                ErrorKind::DuplicateTxInputs,
                "transaction contains duplicate inputs",
            ));
        }
    }

    Ok(())
}
