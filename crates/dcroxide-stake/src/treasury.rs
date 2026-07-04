// SPDX-License-Identifier: ISC
//! Treasury transaction format checks (dcrd stake `treasury.go`):
//! TADD, TSPEND, and treasury base.

use alloc::format;
use alloc::vec::Vec;

use dcroxide_txscript::{
    OP_DATA_12, OP_DATA_33, OP_DATA_64, OP_RETURN, OP_TADD, OP_TGEN, OP_TSPEND,
    is_strict_compressed_pub_key_encoding, is_strict_null_data,
};
use dcroxide_wire::MsgTx;

use crate::error::{ErrorKind, RuleError, stake_rule_error};
use crate::{CONSENSUS_VERSION, is_null_outpoint, is_pub_key_hash_script, is_script_hash_script};

/// The exact length of a TSpend script (dcrd `TSpendScriptLen`):
/// `OP_DATA_64 <signature> OP_DATA_33 <public key> OP_TSPEND`.
pub const TSPEND_SCRIPT_LEN: usize = 100;

/// The treasury transaction version (dcrd `wire.TxVersionTreasury`).
pub const TX_VERSION_TREASURY: u16 = 3;

/// Verify the transaction is a valid TADD (dcrd `checkTAdd`/`CheckTAdd`);
/// does not recognize treasurybase TADDs.
pub fn check_tadd(mtx: &MsgTx) -> Result<(), RuleError> {
    // Require version TxVersionTreasury.
    if mtx.version != TX_VERSION_TREASURY {
        return Err(stake_rule_error(
            ErrorKind::TAddInvalidTxVersion,
            format!("invalid TADD script version: {}", mtx.version),
        ));
    }

    // One OP_TADD output followed by 0 or 1 stake change outputs, and at
    // least one input.
    if !(mtx.tx_out.len() == 1 || mtx.tx_out.len() == 2) || mtx.tx_in.is_empty() {
        return Err(stake_rule_error(
            ErrorKind::TAddInvalidCount,
            format!(
                "invalid TADD script: TxIn {} TxOut {}",
                mtx.tx_in.len(),
                mtx.tx_out.len()
            ),
        ));
    }

    // Verify all output script versions and lengths.
    for (k, tx_out) in mtx.tx_out.iter().enumerate() {
        if tx_out.version != CONSENSUS_VERSION {
            return Err(stake_rule_error(
                ErrorKind::TAddInvalidVersion,
                format!("invalid script version found in TADD TxOut: {k}"),
            ));
        }
        if tx_out.pk_script.is_empty() {
            return Err(stake_rule_error(
                ErrorKind::TAddInvalidScriptLength,
                format!("zero script length found in TADD: {k}"),
            ));
        }
    }

    // First output must be a TADD.
    if mtx.tx_out[0].pk_script.len() != 1 {
        return Err(stake_rule_error(
            ErrorKind::TAddInvalidLength,
            format!(
                "TADD script length is not 1 byte, got {}",
                mtx.tx_out[0].pk_script.len()
            ),
        ));
    }
    if mtx.tx_out[0].pk_script[0] != OP_TADD {
        return Err(stake_rule_error(
            ErrorKind::TAddInvalidOpcode,
            format!(
                "first output must be a TADD, got {:#x}",
                mtx.tx_out[0].pk_script[0]
            ),
        ));
    }

    // Only one stake change output allowed.
    if mtx.tx_out.len() == 2
        && !crate::is_stake_change_script(mtx.tx_out[1].version, &mtx.tx_out[1].pk_script)
    {
        return Err(stake_rule_error(
            ErrorKind::TAddInvalidChange,
            "second output must be an OP_SSTXCHANGE script",
        ));
    }

    Ok(())
}

/// Whether the transaction is a proper TADD (dcrd `IsTAdd`).
pub fn is_tadd(tx: &MsgTx) -> bool {
    check_tadd(tx).is_ok()
}

/// Verify the transaction is a valid TSPEND, returning the signature and
/// public key on success (dcrd `CheckTSpend`); the signature itself and
/// whether the key is a recognized Pi key are NOT checked here.
pub fn check_tspend(mtx: &MsgTx) -> Result<(Vec<u8>, Vec<u8>), RuleError> {
    // Require version TxVersionTreasury.
    if mtx.version != TX_VERSION_TREASURY {
        return Err(stake_rule_error(
            ErrorKind::TSpendInvalidTxVersion,
            format!("invalid TSpend script version: {}", mtx.version),
        ));
    }

    // A single input carrying the signature/pubkey/OP_TSPEND, and at least
    // two outputs (an OP_RETURN randomizer plus TGEN-tagged payouts).
    if mtx.tx_in.len() != 1 || mtx.tx_out.len() < 2 {
        return Err(stake_rule_error(
            ErrorKind::TSpendInvalidLength,
            format!(
                "invalid TSPEND script lengths in: {} out: {}",
                mtx.tx_in.len(),
                mtx.tx_out.len()
            ),
        ));
    }

    // All output scripts must be the consensus version and non-empty.
    for (k, tx_out) in mtx.tx_out.iter().enumerate() {
        if tx_out.version != CONSENSUS_VERSION {
            return Err(stake_rule_error(
                ErrorKind::TSpendInvalidVersion,
                format!("invalid script version found in TxOut: {k}"),
            ));
        }
        if tx_out.pk_script.is_empty() {
            return Err(stake_rule_error(
                ErrorKind::TSpendInvalidScriptLength,
                format!(
                    "invalid TxOut script length {k}: {}",
                    tx_out.pk_script.len()
                ),
            ));
        }
    }

    let tx_in: &[u8] = &mtx.tx_in[0].signature_script;
    if !(tx_in.len() == TSPEND_SCRIPT_LEN
        && tx_in[0] == OP_DATA_64
        && tx_in[65] == OP_DATA_33
        && tx_in[99] == OP_TSPEND)
    {
        return Err(stake_rule_error(
            ErrorKind::TSpendInvalidScript,
            "TSPEND invalid tspend script",
        ));
    }

    // Pull out signature and pubkey.
    let signature = &tx_in[1..1 + 64];
    let pub_key = &tx_in[66..66 + 33];
    if !is_strict_compressed_pub_key_encoding(pub_key) {
        return Err(stake_rule_error(
            ErrorKind::TSpendInvalidPubkey,
            "TSPEND invalid public key",
        ));
    }

    // TxOut[0] must be an OP_RETURN followed by a 32 byte data push.
    if !is_strict_null_data(mtx.tx_out[0].version, &mtx.tx_out[0].pk_script, 32) {
        return Err(stake_rule_error(
            ErrorKind::TSpendInvalidTransaction,
            "First TSPEND output should have been an OP_RETURN followed by a 32 byte \
             data push",
        ));
    }

    // The remaining outputs must be TGEN-tagged P2PKH or P2SH scripts.
    for (k, tx_out) in mtx.tx_out[1..].iter().enumerate() {
        if tx_out.pk_script[0] != OP_TGEN {
            return Err(stake_rule_error(
                ErrorKind::TSpendInvalidTGen,
                format!("Output {} is not tagged with OP_TGEN", k + 1),
            ));
        }
        if !(is_pub_key_hash_script(&tx_out.pk_script[1..])
            || is_script_hash_script(&tx_out.pk_script[1..]))
        {
            return Err(stake_rule_error(
                ErrorKind::TSpendInvalidSpendScript,
                format!("Output {} is not P2SH or P2PKH", k + 1),
            ));
        }
    }

    Ok((signature.to_vec(), pub_key.to_vec()))
}

/// Whether the transaction is a proper TSPEND (dcrd `IsTSpend`).
pub fn is_tspend(tx: &MsgTx) -> bool {
    check_tspend(tx).is_ok()
}

/// Verify the transaction is a treasury base (dcrd
/// `checkTreasuryBase`/`CheckTreasuryBase`).
pub fn check_treasury_base(mtx: &MsgTx) -> Result<(), RuleError> {
    // Require version TxVersionTreasury.
    if mtx.version != TX_VERSION_TREASURY {
        return Err(stake_rule_error(
            ErrorKind::TreasuryBaseInvalidTxVersion,
            format!("invalid treasurybase script version: {}", mtx.version),
        ));
    }

    // One input, exactly two outputs.
    if mtx.tx_in.len() != 1 || mtx.tx_out.len() != 2 {
        return Err(stake_rule_error(
            ErrorKind::TreasuryBaseInvalidCount,
            format!(
                "invalid treasurybase in/out script count: {}/{}",
                mtx.tx_in.len(),
                mtx.tx_out.len()
            ),
        ));
    }

    // No signature script on the zeroth input.
    if !mtx.tx_in[0].signature_script.is_empty() {
        return Err(stake_rule_error(
            ErrorKind::TreasuryBaseInvalidLength,
            "treasurybase input 0 contains a script",
        ));
    }

    // All output script versions must be the consensus version.
    for (k, tx_out) in mtx.tx_out.iter().enumerate() {
        if tx_out.version != CONSENSUS_VERSION {
            return Err(stake_rule_error(
                ErrorKind::TreasuryBaseInvalidVersion,
                format!("invalid script version found in treasurybase: output {k}"),
            ));
        }
    }

    // First output must be a TADD.
    if mtx.tx_out[0].pk_script.len() != 1 || mtx.tx_out[0].pk_script[0] != OP_TADD {
        return Err(stake_rule_error(
            ErrorKind::TreasuryBaseInvalidOpcode0,
            "first treasurybase output must be a TADD",
        ));
    }

    // Second output: OP_RETURN OP_DATA_12 <4-byte LE height><8-byte
    // random> = 14 bytes total.
    if mtx.tx_out[1].pk_script.len() != 14
        || mtx.tx_out[1].pk_script[0] != OP_RETURN
        || mtx.tx_out[1].pk_script[1] != OP_DATA_12
    {
        return Err(stake_rule_error(
            ErrorKind::TreasuryBaseInvalidOpcode1,
            "second treasurybase output must be an OP_RETURN OP_DATA_12 data script",
        ));
    }

    if !is_null_outpoint(mtx) {
        return Err(stake_rule_error(
            ErrorKind::TreasuryBaseInvalid,
            "invalid treasurybase constants",
        ));
    }

    Ok(())
}

/// Whether the transaction is a treasury base (dcrd `IsTreasuryBase`).
pub fn is_treasury_base(tx: &MsgTx) -> bool {
    check_treasury_base(tx).is_ok()
}
