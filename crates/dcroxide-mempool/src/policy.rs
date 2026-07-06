// SPDX-License-Identifier: ISC

//! The mempool relay policy from dcrd's `internal/mempool`
//! `policy.go`: minimum relay fees, dust outputs, and the
//! transaction, output script, and input standardness checks.

use alloc::format;
use alloc::vec::Vec;

use dcroxide_stake::TxType;
use dcroxide_txscript::stdscript::{
    ScriptType, determine_script_type, extract_multi_sig_script_details_v0,
};
use dcroxide_txscript::{
    ScriptFlags, get_precise_sig_op_count, is_push_only_script, is_unspendable,
};
use dcroxide_wire::{DEFAULT_PK_SCRIPT_VERSION, MsgTx, OutPoint, TxOut, TxSerializeType};

use crate::error::{ErrorKind, RuleError, tx_rule_error, wrap_tx_rule_error};

/// The maximum number of signature operations that are considered
/// standard in a pay-to-script-hash script (dcrd
/// `maxStandardP2SHSigOps`).
const MAX_STANDARD_P2SH_SIG_OPS: usize = 15;

/// The maximum size allowed for transactions that are considered
/// standard and will therefore be relayed and considered for mining
/// (dcrd `MaxStandardTxSize`).
pub const MAX_STANDARD_TX_SIZE: usize = 100000;

/// The maximum size allowed for a transaction input signature script
/// to be considered standard; allows a 15-of-15 CHECKMULTISIG
/// pay-to-script-hash with compressed keys (dcrd
/// `maxStandardSigScriptSize`).
const MAX_STANDARD_SIG_SCRIPT_SIZE: usize = 1650;

/// The minimum fee in atoms per 1000 bytes that is required for a
/// transaction to be treated as free for relay and mining purposes,
/// also used for dust determination (dcrd `DefaultMinRelayTxFee`).
pub const DEFAULT_MIN_RELAY_TX_FEE: i64 = 10000;

/// The maximum number of public keys allowed in a multi-signature
/// output script for it to be considered standard (dcrd
/// `maxStandardMultiSigKeys`).
const MAX_STANDARD_MULTI_SIG_KEYS: u16 = 3;

/// The maximum number of OP_RETURN null data outputs a standard
/// regular transaction may carry (dcrd `maxNullDataOutputs`, from
/// `mempool.go`).
const MAX_NULL_DATA_OUTPUTS: usize = 4;

/// The script flags that should be used when executing transaction
/// scripts to enforce the additional checks required for a script to
/// be considered standard regardless of the state of any agenda votes
/// (dcrd `BaseStandardVerifyFlags`).
pub const BASE_STANDARD_VERIFY_FLAGS: ScriptFlags = ScriptFlags(
    ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS.0
        | ScriptFlags::VERIFY_CLEAN_STACK.0
        | ScriptFlags::VERIFY_CHECK_LOCK_TIME_VERIFY.0
        | ScriptFlags::VERIFY_CHECK_SEQUENCE_VERIFY.0,
);

/// The maximum transaction amount in atoms (dcrd `dcrutil.MaxAmount`).
const MAX_AMOUNT: i64 = dcroxide_stake::MAX_AMOUNT;

/// The minimum transaction fee required for a transaction with the
/// passed serialized size to be accepted into the memory pool and
/// relayed, with the min relay fee given in atoms per 1000 bytes
/// (dcrd `calcMinRequiredTxRelayFee`).
// The comparison keeps dcrd's shape.
#[allow(clippy::manual_range_contains)]
pub fn calc_min_required_tx_relay_fee(serialized_size: i64, min_relay_tx_fee: i64) -> i64 {
    // Calculate the minimum fee for a transaction to be allowed into
    // the mempool and relayed by scaling the base fee (which is the
    // minimum free transaction relay fee).  The relay fee is in
    // atoms/KB, so multiply by the serialized size (which is in bytes)
    // and divide by 1000 to get minimum atoms.
    let mut min_fee = serialized_size
        .wrapping_mul(min_relay_tx_fee)
        .wrapping_div(1000);

    if min_fee == 0 && min_relay_tx_fee > 0 {
        min_fee = min_relay_tx_fee;
    }

    // Set the minimum fee to the maximum possible value if the
    // calculated fee is not in the valid range for monetary amounts.
    if min_fee < 0 || min_fee > MAX_AMOUNT {
        min_fee = MAX_AMOUNT;
    }

    min_fee
}

/// Check a transaction's inputs are "standard": each referenced public
/// key script is of a standard form and, for pay-to-script-hash, does
/// not have more than the standard number of signature operations.
/// The clean stack and push-only signature script properties are
/// enforced by the script engine flags instead (dcrd
/// `checkInputsStandard`).
///
/// The entries for all inputs must exist in the view supplied by the
/// lookup; existence has already been checked prior to calling this
/// function, matching dcrd.
pub fn check_inputs_standard(
    tx: &MsgTx,
    tx_type: TxType,
    lookup_entry: impl Fn(&OutPoint) -> Option<(u16, Vec<u8>)>,
    is_treasury_enabled: bool,
) -> Result<(), RuleError> {
    // NOTE: The reference implementation also does a coinbase check
    // here, but coinbases have already been rejected prior to calling
    // this function so no need to recheck.

    // Ignore the first input if this is a SSGen (vote) or tspend since
    // those inputs are not standard by definition.
    let ignore_first =
        tx_type == TxType::SSGen || (is_treasury_enabled && tx_type == TxType::TSpend);

    for (i, tx_in) in tx.tx_in.iter().enumerate() {
        if i == 0 && ignore_first {
            continue;
        }

        // It is safe to elide existence and index checks here since
        // they have already been checked prior to calling this
        // function.
        let (origin_script_ver, origin_script) =
            lookup_entry(&tx_in.previous_out_point).expect("input entry exists");
        match determine_script_type(origin_script_ver, &origin_script) {
            ScriptType::ScriptHash => {
                let num_sig_ops = get_precise_sig_op_count(
                    &tx_in.signature_script,
                    &origin_script,
                    is_treasury_enabled,
                );
                if num_sig_ops > MAX_STANDARD_P2SH_SIG_OPS {
                    let str = format!(
                        "transaction input #{i} has {num_sig_ops} signature \
                         operations which is more than the allowed max amount \
                         of {MAX_STANDARD_P2SH_SIG_OPS}"
                    );
                    return Err(tx_rule_error(ErrorKind::NonStandard, str));
                }
            }
            ScriptType::NonStandard => {
                let str = format!("transaction input #{i} has a non-standard script form");
                return Err(tx_rule_error(ErrorKind::NonStandard, str));
            }
            _ => {}
        }
    }

    Ok(())
}

/// Check a transaction output script is a "standard" public key
/// script: a recognized form, and for multi-signature scripts, one to
/// three public keys with a valid required signature count (dcrd
/// `checkPkScriptStandard`).
pub fn check_pk_script_standard(
    version: u16,
    pk_script: &[u8],
    script_type: ScriptType,
) -> Result<(), RuleError> {
    // Only version 0 scripts are standard at the current time.
    if version != DEFAULT_PK_SCRIPT_VERSION {
        let str = "versions other than default pkscript version are currently \
                   non-standard except for provably unspendable outputs";
        return Err(tx_rule_error(ErrorKind::NonStandard, str));
    }

    if script_type == ScriptType::MultiSig && version == 0 {
        // A standard multi-signature public key script must contain
        // from 1 to the standard maximum number of public keys.
        let details = extract_multi_sig_script_details_v0(pk_script, false);
        let num_pub_keys = details.num_pub_keys;
        if num_pub_keys < 1 {
            let str = "multi-signature script with no pubkeys";
            return Err(tx_rule_error(ErrorKind::NonStandard, str));
        }
        if num_pub_keys > MAX_STANDARD_MULTI_SIG_KEYS {
            let str = format!(
                "multi-signature script with {num_pub_keys} public keys which \
                 is more than the allowed max of {MAX_STANDARD_MULTI_SIG_KEYS}"
            );
            return Err(tx_rule_error(ErrorKind::NonStandard, str));
        }

        // A standard multi-signature public key script must have at
        // least 1 signature and no more signatures than available
        // public keys.
        //
        // NOTE: Due to recent updates in the standardness
        // identification code, the script should not have been
        // identified as standard when there is not at least 1
        // signature, but be paranoid and double check it here in case
        // the standardness code changes in the future.
        let num_sigs = details.required_sigs;
        if num_sigs < 1 {
            return Err(tx_rule_error(
                ErrorKind::NonStandard,
                "multi-signature script with no signatures",
            ));
        }
        if num_sigs > num_pub_keys {
            let str = format!(
                "multi-signature script with {num_sigs} signatures which is \
                 more than the available {num_pub_keys} public keys"
            );
            return Err(tx_rule_error(ErrorKind::NonStandard, str));
        }
    } else if script_type == ScriptType::NonStandard {
        return Err(tx_rule_error(
            ErrorKind::NonStandard,
            "non-standard script form",
        ));
    }

    Ok(())
}

/// Whether the transaction output amount is considered dust based on
/// the given minimum transaction relay fee in atoms per 1000 bytes:
/// dust is an output whose cost to the network to spend exceeds one
/// third of the minimum relay fee (dcrd `isDust`).
pub fn is_dust(tx_out: &TxOut, min_relay_tx_fee: i64) -> bool {
    // Unspendable outputs are considered dust.
    if is_unspendable(tx_out.value, &tx_out.pk_script) {
        return true;
    }

    // The total serialized size consists of the output and the
    // associated input script to redeem it.  Since there is no input
    // script to redeem it yet, use the minimum size of a typical
    // input script: 165 bytes for a pay-to-pubkey-hash input with a
    // compressed pubkey (see dcrd's byte breakdowns).
    let total_size = tx_out.serialize_size() + 165;

    // The output is considered dust if the cost to the network to
    // spend the coins is more than 1/3 of the minimum free transaction
    // relay fee, which is in atoms/KB.  The following is equivalent to
    // (value/totalSize) * (1/3) * 1000 without floating point math.
    tx_out.value.wrapping_mul(1000) / (3 * total_size as i64) < min_relay_tx_fee
}

/// Check a transaction is "standard": a supported serialize type,
/// finalized, within the standard size limit, push-only signature
/// scripts within the standard size, standard non-dust output scripts,
/// and at most the allowed null data outputs for regular transactions
/// (dcrd `checkTransactionStandard`).
pub fn check_transaction_standard(
    tx: &MsgTx,
    tx_type: TxType,
    height: i64,
    median_time_unix: i64,
    min_relay_tx_fee: i64,
) -> Result<(), RuleError> {
    // The transaction must be a currently supported serialize type.
    if tx.ser_type != TxSerializeType::Full {
        let str = format!(
            "transaction is not serialized with all required data -- type {:?}",
            tx.ser_type
        );
        return Err(tx_rule_error(ErrorKind::NonStandard, str));
    }

    // The transaction must be finalized to be standard and therefore
    // considered for inclusion in a block.
    if !dcroxide_blockchain::validate::is_finalized_transaction(tx, height, median_time_unix) {
        return Err(tx_rule_error(
            ErrorKind::NonStandard,
            "transaction is not finalized",
        ));
    }

    // Since extremely large transactions with a lot of inputs can cost
    // almost as much to process as the sender fees, limit the maximum
    // size of a transaction.  This also helps mitigate CPU exhaustion
    // attacks.
    let serialized_len = tx.serialize_size();
    if serialized_len > MAX_STANDARD_TX_SIZE {
        let str = format!(
            "transaction size of {serialized_len} is larger than max allowed \
             size of {MAX_STANDARD_TX_SIZE}"
        );
        return Err(tx_rule_error(ErrorKind::NonStandard, str));
    }

    for (i, tx_in) in tx.tx_in.iter().enumerate() {
        // TSpends should only have one input and that input has a
        // specific format which is checked by IsTSpend, so if this tx
        // is a tspend, skip it.
        if tx_type == TxType::TSpend {
            continue;
        }

        // Each transaction input signature script must not exceed the
        // maximum size allowed for a standard transaction.
        let sig_script_len = tx_in.signature_script.len();
        if sig_script_len > MAX_STANDARD_SIG_SCRIPT_SIZE {
            let str = format!(
                "transaction input {i}: signature script size of \
                 {sig_script_len} bytes is large than max allowed size of \
                 {MAX_STANDARD_SIG_SCRIPT_SIZE} bytes"
            );
            return Err(tx_rule_error(ErrorKind::NonStandard, str));
        }

        // Each transaction input signature script must only contain
        // opcodes which push data onto the stack.
        if !is_push_only_script(&tx_in.signature_script) {
            let str = format!("transaction input {i}: signature script is not push only");
            return Err(tx_rule_error(ErrorKind::NonStandard, str));
        }
    }

    // None of the output public key scripts can be a non-standard
    // script or be "dust" (except when the script is a null data
    // script).
    let mut num_null_data_outputs = 0usize;
    for (i, tx_out) in tx.tx_out.iter().enumerate() {
        let script_type = determine_script_type(tx_out.version, &tx_out.pk_script);
        if let Err(err) = check_pk_script_standard(tx_out.version, &tx_out.pk_script, script_type) {
            let str = format!("transaction output {i}: {}", err.description);
            return Err(wrap_tx_rule_error(ErrorKind::NonStandard, str, &err));
        }

        // Accumulate the number of outputs which only carry data.  For
        // all other script types, ensure the output value is not
        // "dust".
        if script_type == ScriptType::NullData {
            num_null_data_outputs += 1;
        } else if tx_type == TxType::Regular && is_dust(tx_out, min_relay_tx_fee) {
            let str = format!(
                "transaction output {i}: payment of {} is dust",
                tx_out.value
            );
            return Err(tx_rule_error(ErrorKind::DustOutput, str));
        }
    }

    // A standard transaction must not have more than one output script
    // that only carries data.  However, certain types of standard
    // stake transactions are allowed to have multiple OP_RETURN
    // outputs, so only throw an error here if the tx is regular.
    if num_null_data_outputs > MAX_NULL_DATA_OUTPUTS && tx_type == TxType::Regular {
        let str = "more than one transaction output in a nulldata script for a \
                   regular type tx";
        return Err(tx_rule_error(ErrorKind::NonStandard, str));
    }

    Ok(())
}
