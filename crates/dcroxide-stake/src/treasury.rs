// SPDX-License-Identifier: ISC
//! Treasury transaction format checks (dcrd stake `treasury.go` at
//! the dcrd 2.2 parity target): treasury add, treasury spend, and
//! treasurybase.  dcrd 2.2 collapsed the private wrapper functions
//! into the exported checks and rewrote every failure message with
//! per-failure-mode splits; the acceptance sets are unchanged except
//! the treasurybase null-outpoint check moved ahead of the script
//! version checks, changing the failure precedence for
//! multi-defect transactions.

use alloc::format;
use alloc::vec::Vec;

use dcroxide_txscript::{
    OP_DATA_33, OP_DATA_64, OP_TADD, OP_TGEN, OP_TSPEND, is_strict_compressed_pub_key_encoding,
    is_strict_null_data,
};
use dcroxide_wire::MsgTx;

use crate::error::{ErrorKind, RuleError, stake_rule_error};
use crate::{CONSENSUS_VERSION, is_null_outpoint, is_pub_key_hash_script, is_script_hash_script};

/// The exact length of a TSpend script (dcrd `TSpendScriptLen`):
/// `OP_DATA_64 <signature> OP_DATA_33 <public key> OP_TSPEND`.
pub const TSPEND_SCRIPT_LEN: usize = 100;

/// The treasury transaction version (dcrd `wire.TxVersionTreasury`).
pub const TX_VERSION_TREASURY: u16 = 3;

/// Verify the transaction satisfies the structural requirements to be
/// a valid treasury add transaction (dcrd `CheckTAdd`); does not
/// recognize treasurybase TADDs.
pub fn check_tadd(mtx: &MsgTx) -> Result<(), RuleError> {
    // The transaction version must be the required treasury version.
    if mtx.version != TX_VERSION_TREASURY {
        return Err(stake_rule_error(
            ErrorKind::TAddInvalidTxVersion,
            format!(
                "treasury add transaction version is {} instead of {}",
                mtx.version, TX_VERSION_TREASURY
            ),
        ));
    }

    // A treasury add must have at least one input and one or two
    // outputs.
    if mtx.tx_in.is_empty() {
        return Err(stake_rule_error(
            ErrorKind::TAddInvalidCount,
            "treasury add transaction does not have any inputs",
        ));
    }
    if mtx.tx_out.len() != 1 && mtx.tx_out.len() != 2 {
        return Err(stake_rule_error(
            ErrorKind::TAddInvalidCount,
            format!(
                "treasury add transaction has {} outputs instead of 1 or 2",
                mtx.tx_out.len()
            ),
        ));
    }

    // All output scripts must be version 0 and non-empty.
    for (tx_out_idx, tx_out) in mtx.tx_out.iter().enumerate() {
        if tx_out.version != CONSENSUS_VERSION {
            return Err(stake_rule_error(
                ErrorKind::TAddInvalidVersion,
                format!(
                    "treasury add transaction output {tx_out_idx} script version is {} \
                     instead of {CONSENSUS_VERSION}",
                    tx_out.version
                ),
            ));
        }
        if tx_out.pk_script.is_empty() {
            return Err(stake_rule_error(
                ErrorKind::TAddInvalidScriptLength,
                format!("treasury add transaction output {tx_out_idx} script is empty"),
            ));
        }
    }

    // The first output must be a script that only consists of OP_TADD.
    let first_tx_out = &mtx.tx_out[0];
    if first_tx_out.pk_script.len() != 1 {
        return Err(stake_rule_error(
            ErrorKind::TAddInvalidLength,
            format!(
                "treasury add transaction output 0 script length is {} bytes instead \
                 of 1 byte",
                first_tx_out.pk_script.len()
            ),
        ));
    }
    if first_tx_out.pk_script[0] != OP_TADD {
        return Err(stake_rule_error(
            ErrorKind::TAddInvalidOpcode,
            format!(
                "treasury add transaction output 0 script is 0x{:x} instead of OP_TADD \
                 (0x{:x})",
                first_tx_out.pk_script[0], OP_TADD
            ),
        ));
    }

    // The second output must be a valid stake change output when
    // present.
    if mtx.tx_out.len() == 2 {
        let change_tx_out = &mtx.tx_out[1];
        if !crate::is_stake_change_script(change_tx_out.version, &change_tx_out.pk_script) {
            return Err(stake_rule_error(
                ErrorKind::TAddInvalidChange,
                "treasury add transaction output 1 is not a stake change script",
            ));
        }
    }

    Ok(())
}

/// Whether the transaction is a proper TADD (dcrd `IsTAdd`).
pub fn is_tadd(tx: &MsgTx) -> bool {
    check_tadd(tx).is_ok()
}

/// Verify the transaction satisfies the structural requirements to be
/// a valid treasury spend, returning the signature and public key on
/// success (dcrd `CheckTSpend`); the signature itself, whether the
/// key is a recognized Pi key, and the input value encoded in the
/// first output's data push are NOT checked here.
pub fn check_tspend(mtx: &MsgTx) -> Result<(Vec<u8>, Vec<u8>), RuleError> {
    // The transaction version must be the required treasury version.
    if mtx.version != TX_VERSION_TREASURY {
        return Err(stake_rule_error(
            ErrorKind::TSpendInvalidTxVersion,
            format!(
                "treasury spend transaction version is {} instead of {}",
                mtx.version, TX_VERSION_TREASURY
            ),
        ));
    }

    // A treasury spend must have exactly one input and at least two
    // outputs.
    if mtx.tx_in.len() != 1 {
        return Err(stake_rule_error(
            ErrorKind::TSpendInvalidLength,
            format!(
                "treasury spend transaction has {} inputs instead of 1",
                mtx.tx_in.len()
            ),
        ));
    }
    if mtx.tx_out.len() < 2 {
        return Err(stake_rule_error(
            ErrorKind::TSpendInvalidLength,
            format!(
                "treasury spend transaction does not have enough outputs (min: 2, \
                 have: {})",
                mtx.tx_out.len()
            ),
        ));
    }

    // All output scripts must be version 0 and non-empty.
    for (tx_out_idx, tx_out) in mtx.tx_out.iter().enumerate() {
        if tx_out.version != CONSENSUS_VERSION {
            return Err(stake_rule_error(
                ErrorKind::TSpendInvalidVersion,
                format!(
                    "treasury spend transaction output {tx_out_idx} script version is \
                     {} instead of {CONSENSUS_VERSION}",
                    tx_out.version
                ),
            ));
        }
        if tx_out.pk_script.is_empty() {
            return Err(stake_rule_error(
                ErrorKind::TSpendInvalidScriptLength,
                format!("treasury spend transaction output {tx_out_idx} script is empty"),
            ));
        }
    }

    // The single input must have the exact treasury spend script
    // format:
    //
    // DATA_64 <64-byte schnorr signature> DATA_33 <33-byte pubkey> OP_TSPEND
    let tx_in: &[u8] = &mtx.tx_in[0].signature_script;
    if tx_in.len() != TSPEND_SCRIPT_LEN
        || tx_in[0] != OP_DATA_64
        || tx_in[65] != OP_DATA_33
        || tx_in[99] != OP_TSPEND
    {
        return Err(stake_rule_error(
            ErrorKind::TSpendInvalidScript,
            "treasury spend transaction input 0 script is malformed",
        ));
    }

    // The public key must adhere to the strict compressed public key
    // encoding.
    let signature = &tx_in[1..1 + 64];
    let pub_key = &tx_in[66..66 + 33];
    if !is_strict_compressed_pub_key_encoding(pub_key) {
        return Err(stake_rule_error(
            ErrorKind::TSpendInvalidPubkey,
            format!(
                "treasury spend transaction input 0 public key {} does not use strict \
                 compressed encoding",
                hex_lower(pub_key)
            ),
        ));
    }

    // The first output must be an OP_RETURN followed by a 32 byte data
    // push.
    let first_tx_out = &mtx.tx_out[0];
    if !is_strict_null_data(first_tx_out.version, &first_tx_out.pk_script, 32) {
        return Err(stake_rule_error(
            ErrorKind::TSpendInvalidTransaction,
            "treasury spend transaction output 0 script is not an OP_RETURN followed \
             by a 32 byte data push",
        ));
    }

    // All outputs after the first one must have OP_TGEN tagged p2pkh
    // or p2sh scripts.
    for (tx_out_idx, tx_out) in mtx.tx_out[1..].iter().enumerate() {
        let script: &[u8] = &tx_out.pk_script;
        if script[0] != OP_TGEN {
            return Err(stake_rule_error(
                ErrorKind::TSpendInvalidTGen,
                format!(
                    "treasury spend transaction output {} script is not tagged with \
                     OP_TGEN",
                    tx_out_idx + 1
                ),
            ));
        }
        if !is_pub_key_hash_script(&script[1..]) && !is_script_hash_script(&script[1..]) {
            return Err(stake_rule_error(
                ErrorKind::TSpendInvalidSpendScript,
                format!(
                    "treasury spend transaction output {} script is not \
                     pay-to-script-hash or pay-to-pubkey-hash",
                    tx_out_idx + 1
                ),
            ));
        }
    }

    Ok((signature.to_vec(), pub_key.to_vec()))
}

/// Whether the transaction is a proper TSPEND (dcrd `IsTSpend`).
pub fn is_tspend(tx: &MsgTx) -> bool {
    check_tspend(tx).is_ok()
}

/// Verify the transaction satisfies the structural requirements to be
/// a valid treasurybase transaction (dcrd `CheckTreasuryBase`).
pub fn check_treasury_base(mtx: &MsgTx) -> Result<(), RuleError> {
    // The transaction version must be the required treasury version.
    if mtx.version != TX_VERSION_TREASURY {
        return Err(stake_rule_error(
            ErrorKind::TreasuryBaseInvalidTxVersion,
            format!(
                "treasurybase transaction version is {} instead of {}",
                mtx.version, TX_VERSION_TREASURY
            ),
        ));
    }

    // A treasurybase must have exactly one input and two outputs.
    if mtx.tx_in.len() != 1 {
        return Err(stake_rule_error(
            ErrorKind::TreasuryBaseInvalidCount,
            format!(
                "treasurybase transaction has {} inputs instead of 1",
                mtx.tx_in.len()
            ),
        ));
    }
    if mtx.tx_out.len() != 2 {
        return Err(stake_rule_error(
            ErrorKind::TreasuryBaseInvalidCount,
            format!(
                "treasurybase transaction has {} output(s) instead of 2",
                mtx.tx_out.len()
            ),
        ));
    }

    // The first input signature script must be empty and its previous
    // output must be a null outpoint (max value index, a zero hash,
    // regular tx tree).
    if !mtx.tx_in[0].signature_script.is_empty() {
        return Err(stake_rule_error(
            ErrorKind::TreasuryBaseInvalidLength,
            format!(
                "treasurybase input 0 signature script is {} byte(s) instead of 0",
                mtx.tx_in[0].signature_script.len()
            ),
        ));
    }
    if !is_null_outpoint(mtx) {
        let prev_out = &mtx.tx_in[0].previous_out_point;
        return Err(stake_rule_error(
            ErrorKind::TreasuryBaseInvalid,
            format!(
                "treasurybase input 0 previous output {}:{}:{} is not a null outpoint",
                prev_out.hash, prev_out.index, prev_out.tree
            ),
        ));
    }

    // All output scripts must be version 0.
    for (tx_out_idx, tx_out) in mtx.tx_out.iter().enumerate() {
        if tx_out.version != CONSENSUS_VERSION {
            return Err(stake_rule_error(
                ErrorKind::TreasuryBaseInvalidVersion,
                format!(
                    "treasurybase transaction output {tx_out_idx} script version is {} \
                     instead of {CONSENSUS_VERSION}",
                    tx_out.version
                ),
            ));
        }
    }

    // The first output must be a script that only consists of OP_TADD.
    let first_tx_out = &mtx.tx_out[0];
    if first_tx_out.pk_script.len() != 1 {
        return Err(stake_rule_error(
            ErrorKind::TreasuryBaseInvalidOpcode0,
            format!(
                "treasurybase transaction output 0 script length is {} bytes instead \
                 of 1 byte",
                first_tx_out.pk_script.len()
            ),
        ));
    }
    if first_tx_out.pk_script[0] != OP_TADD {
        return Err(stake_rule_error(
            ErrorKind::TreasuryBaseInvalidOpcode0,
            format!(
                "treasurybase transaction output 0 script is 0x{:x} instead of OP_TADD \
                 (0x{:x})",
                first_tx_out.pk_script[0], OP_TADD
            ),
        ));
    }

    // The second output must be an OP_RETURN followed by a 12 byte
    // data push.
    let op_ret_tx_out = &mtx.tx_out[1];
    if !is_strict_null_data(op_ret_tx_out.version, &op_ret_tx_out.pk_script, 12) {
        return Err(stake_rule_error(
            ErrorKind::TreasuryBaseInvalidOpcode1,
            "treasurybase transaction output 1 is not an OP_RETURN followed by a 12 \
             byte data push",
        ));
    }

    Ok(())
}

/// Whether the transaction is a treasury base (dcrd `IsTreasuryBase`).
pub fn is_treasury_base(tx: &MsgTx) -> bool {
    check_treasury_base(tx).is_ok()
}

/// Lowercase hex of a byte slice (Go's `%x` of a `[]byte`).
fn hex_lower(bytes: &[u8]) -> alloc::string::String {
    use core::fmt::Write;
    let mut out = alloc::string::String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}
