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

/// Whether the transaction's version or its input and output counts
/// rule it out as a treasury add: the conditions of [`check_tadd`]'s
/// first three failures (dcrd `CheckTAdd`, `treasury.go:56-71`), with
/// no message built.
fn fails_tadd_shape(tx: &MsgTx) -> bool {
    tx.version != TX_VERSION_TREASURY
        || tx.tx_in.is_empty()
        || (tx.tx_out.len() != 1 && tx.tx_out.len() != 2)
}

/// Whether the transaction is a proper TADD (dcrd `IsTAdd`).
///
/// The answer is that of `check_tadd(tx).is_ok()` (`treasury.go:120-122`).
/// The check formats a message when it refuses a transaction for its
/// version or its counts, as it does every transaction of another
/// version, and the message would be dropped here; so those are tested
/// first, and only a transaction that passes them goes through the
/// check.
pub fn is_tadd(tx: &MsgTx) -> bool {
    !fails_tadd_shape(tx) && check_tadd(tx).is_ok()
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
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "tx_out_idx enumerates tx_out[1..], so tx_out_idx + 1 <= tx_out.len()"
    )]
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

/// Whether the transaction's version or its input and output counts
/// rule it out as a treasury spend: the conditions of [`check_tspend`]'s
/// first three failures (dcrd `CheckTSpend`, `treasury.go:142-158`),
/// with no message built.
fn fails_tspend_shape(tx: &MsgTx) -> bool {
    tx.version != TX_VERSION_TREASURY || tx.tx_in.len() != 1 || tx.tx_out.len() < 2
}

/// Whether the transaction is a proper TSPEND (dcrd `IsTSpend`).
///
/// The answer is that of `check_tspend(tx).is_ok()`
/// (`treasury.go:227-230`), with the version and the counts tested
/// first for the reason given at [`is_tadd`].
pub fn is_tspend(tx: &MsgTx) -> bool {
    !fails_tspend_shape(tx) && check_tspend(tx).is_ok()
}

/// The signature and public key of a treasury spend, or `None` when the
/// transaction is not one: `check_tspend(tx).ok()`, for a caller that
/// only asks whether the check passed (dcrd reads `err == nil`,
/// `validate.go:3469-3470`), with the version and the counts tested
/// first for the reason given at [`is_tadd`].
pub fn tspend_signature_and_pub_key(tx: &MsgTx) -> Option<(Vec<u8>, Vec<u8>)> {
    if fails_tspend_shape(tx) {
        return None;
    }
    check_tspend(tx).ok()
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

/// Whether the transaction's version or its input and output counts
/// rule it out as a treasurybase: the conditions of
/// [`check_treasury_base`]'s first three failures (dcrd
/// `CheckTreasuryBase`, `treasury.go:244-260`), with no message built.
fn fails_treasury_base_shape(tx: &MsgTx) -> bool {
    tx.version != TX_VERSION_TREASURY || tx.tx_in.len() != 1 || tx.tx_out.len() != 2
}

/// Whether the transaction is a treasury base (dcrd `IsTreasuryBase`).
///
/// The answer is that of `check_treasury_base(tx).is_ok()`
/// (`treasury.go:316-318`), with the version and the counts tested
/// first for the reason given at [`is_tadd`].
pub fn is_treasury_base(tx: &MsgTx) -> bool {
    !fails_treasury_base_shape(tx) && check_treasury_base(tx).is_ok()
}

/// Lowercase hex of a byte slice (Go's `%x` of a `[]byte`).
fn hex_lower(bytes: &[u8]) -> alloc::string::String {
    use core::fmt::Write;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "a slice length is at most isize::MAX, so doubling it fits in usize"
    )]
    let mut out = alloc::string::String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic over fixed fixtures and small counts"
)]
mod shape_tests {
    //! The three predicates against the checks they stand for.
    //!
    //! Each predicate tests the version and the counts before it runs
    //! its check.  That is the same answer only while the shape test
    //! holds exactly where the check fails at one of its first three
    //! tests, so both are pinned here over every transaction of
    //! `tests/data/staketx_vectors.txt`, a valid transaction of each
    //! treasury type and a regular one, each edited one field at a
    //! time, two at a time, and a few at random.

    use alloc::vec;
    use alloc::vec::Vec;

    use dcroxide_chainhash::Hash;
    use dcroxide_testutil::{SplitMix64, unhex};
    use dcroxide_txscript::{
        OP_CHECKSIG, OP_DATA_11, OP_DATA_12, OP_DATA_20, OP_DATA_32, OP_DUP, OP_EQUAL,
        OP_EQUALVERIFY, OP_HASH160, OP_RETURN, OP_SSTXCHANGE, OP_TRUE,
    };
    use dcroxide_wire::{OutPoint, TX_TREE_REGULAR, TX_TREE_STAKE, TxIn, TxOut};

    use super::*;

    /// `is_tadd` before the shape test: the check with its error
    /// dropped (dcrd `IsTAdd`, `treasury.go:120-122`).
    fn is_tadd_by_check(tx: &MsgTx) -> bool {
        check_tadd(tx).is_ok()
    }

    /// `is_tspend` before the shape test (dcrd `IsTSpend`,
    /// `treasury.go:227-230`).
    fn is_tspend_by_check(tx: &MsgTx) -> bool {
        check_tspend(tx).is_ok()
    }

    /// `is_treasury_base` before the shape test (dcrd `IsTreasuryBase`,
    /// `treasury.go:316-318`).
    fn is_treasury_base_by_check(tx: &MsgTx) -> bool {
        check_treasury_base(tx).is_ok()
    }

    fn out(version: u16, pk_script: Vec<u8>) -> TxOut {
        TxOut {
            value: 0,
            version,
            pk_script,
        }
    }

    /// A pay-to-script-hash script.
    fn p2sh() -> Vec<u8> {
        let mut script = vec![OP_HASH160, OP_DATA_20];
        script.extend_from_slice(&[0x11; 20]);
        script.push(OP_EQUAL);
        script
    }

    /// A pay-to-pubkey-hash script.
    fn p2pkh() -> Vec<u8> {
        let mut script = vec![OP_DUP, OP_HASH160, OP_DATA_20];
        script.extend_from_slice(&[0x22; 20]);
        script.extend_from_slice(&[OP_EQUALVERIFY, OP_CHECKSIG]);
        script
    }

    /// The script behind the given stake opcode.
    fn tagged(tag: u8, mut script: Vec<u8>) -> Vec<u8> {
        script.insert(0, tag);
        script
    }

    /// An `OP_RETURN` followed by a direct push of `push_op` bytes.
    fn null_data(push_op: u8) -> Vec<u8> {
        let mut script = vec![OP_RETURN, push_op];
        script.resize(2 + usize::from(push_op), 0x5a);
        script
    }

    /// An input that spends the null outpoint.
    fn null_input(signature_script: Vec<u8>) -> TxIn {
        TxIn {
            previous_out_point: OutPoint {
                hash: Hash::ZERO,
                index: u32::MAX,
                tree: TX_TREE_REGULAR,
            },
            signature_script,
            ..TxIn::default()
        }
    }

    /// A well-formed treasury spend signature script.
    fn tspend_sig_script() -> Vec<u8> {
        let mut script = vec![OP_DATA_64];
        script.extend_from_slice(&[0x33; 64]);
        script.extend_from_slice(&[OP_DATA_33, 0x02]);
        script.extend_from_slice(&[0x44; 32]);
        script.push(OP_TSPEND);
        assert_eq!(script.len(), TSPEND_SCRIPT_LEN);
        script
    }

    fn treasury_tx(tx_in: Vec<TxIn>, tx_out: Vec<TxOut>) -> MsgTx {
        MsgTx {
            version: TX_VERSION_TREASURY,
            tx_in,
            tx_out,
            ..MsgTx::default()
        }
    }

    /// The transactions the edits start from: one valid transaction of
    /// each accepted form, a regular transaction, and every vector of
    /// dcrd's `staketx_test.go`.
    fn bases() -> Vec<MsgTx> {
        let mut bases = vec![
            // Treasury adds: with change, without, and with two inputs.
            treasury_tx(
                vec![TxIn::default()],
                vec![out(0, vec![OP_TADD]), out(0, tagged(OP_SSTXCHANGE, p2sh()))],
            ),
            treasury_tx(vec![TxIn::default()], vec![out(0, vec![OP_TADD])]),
            treasury_tx(
                vec![TxIn::default(), TxIn::default()],
                vec![
                    out(0, vec![OP_TADD]),
                    out(0, tagged(OP_SSTXCHANGE, p2pkh())),
                ],
            ),
            // A treasurybase.
            treasury_tx(
                vec![null_input(Vec::new())],
                vec![out(0, vec![OP_TADD]), out(0, null_data(OP_DATA_12))],
            ),
            // Treasury spends: one payment, and two.
            treasury_tx(
                vec![null_input(tspend_sig_script())],
                vec![
                    out(0, null_data(OP_DATA_32)),
                    out(0, tagged(OP_TGEN, p2sh())),
                ],
            ),
            treasury_tx(
                vec![null_input(tspend_sig_script())],
                vec![
                    out(0, null_data(OP_DATA_32)),
                    out(0, tagged(OP_TGEN, p2pkh())),
                    out(0, tagged(OP_TGEN, p2sh())),
                ],
            ),
            // A regular transaction.
            MsgTx {
                tx_in: vec![TxIn::default()],
                tx_out: vec![out(0, p2pkh()), out(0, p2sh())],
                ..MsgTx::default()
            },
        ];
        assert!(is_tadd_by_check(&bases[0]) && is_tadd_by_check(&bases[1]));
        assert!(is_tadd_by_check(&bases[2]));
        assert!(is_treasury_base_by_check(&bases[3]));
        assert!(is_tspend_by_check(&bases[4]) && is_tspend_by_check(&bases[5]));

        let vectors = include_str!("../tests/data/staketx_vectors.txt");
        let before = bases.len();
        for line in vectors.lines() {
            let mut parts = line.split(' ');
            if parts.next() != Some("tx") {
                continue;
            }
            let tx_hex = parts.nth(1).expect("vector tx hex");
            let (tx, _) = MsgTx::from_bytes(&unhex(tx_hex)).expect("vector tx deserializes");
            bases.push(tx);
        }
        assert_eq!(bases.len() - before, 31, "every staketx_test.go vector");
        bases
    }

    /// One edit of a transaction.  An edit of a field the transaction
    /// does not have leaves it alone.
    type Edit = fn(&mut MsgTx);

    /// The edits: every version around the treasury version, every count
    /// around the ones the checks draw their lines at, and one edit for
    /// each later test of each check.
    const EDITS: &[Edit] = &[
        // The version.
        |tx| tx.version = 0,
        |tx| tx.version = 1,
        |tx| tx.version = 2,
        |tx| tx.version = TX_VERSION_TREASURY,
        |tx| tx.version = 4,
        |tx| tx.version = u16::MAX,
        // The number of inputs.
        |tx| tx.tx_in.clear(),
        |tx| tx.tx_in.truncate(1),
        |tx| tx.tx_in.push(TxIn::default()),
        |tx| tx.tx_in.insert(0, null_input(Vec::new())),
        |tx| tx.tx_in.insert(0, null_input(tspend_sig_script())),
        // The number of outputs.
        |tx| tx.tx_out.clear(),
        |tx| tx.tx_out.truncate(1),
        |tx| tx.tx_out.truncate(2),
        |tx| tx.tx_out.push(TxOut::default()),
        |tx| tx.tx_out.push(out(0, vec![OP_TRUE])),
        |tx| tx.tx_out.push(out(1, vec![OP_TRUE])),
        |tx| tx.tx_out.push(out(0, tagged(OP_TGEN, p2sh()))),
        |tx| tx.tx_out.push(out(0, tagged(OP_SSTXCHANGE, p2pkh()))),
        |tx| tx.tx_out.insert(0, out(0, vec![OP_TADD])),
        |tx| tx.tx_out.insert(0, out(0, null_data(OP_DATA_32))),
        // The first input.
        |tx| {
            if let Some(tx_in) = tx.tx_in.first_mut() {
                tx_in.signature_script.clear();
            }
        },
        |tx| {
            if let Some(tx_in) = tx.tx_in.first_mut() {
                tx_in.signature_script = vec![OP_TRUE];
            }
        },
        |tx| {
            if let Some(tx_in) = tx.tx_in.first_mut() {
                tx_in.signature_script = tspend_sig_script();
            }
        },
        |tx| {
            if let Some(tx_in) = tx.tx_in.first_mut() {
                tx_in.signature_script.pop();
            }
        },
        |tx| {
            if let Some(tx_in) = tx.tx_in.first_mut() {
                tx_in.signature_script.push(OP_TSPEND);
            }
        },
        |tx| {
            if let Some(op) = tx
                .tx_in
                .first_mut()
                .and_then(|i| i.signature_script.first_mut())
            {
                *op = OP_DATA_33;
            }
        },
        |tx| {
            if let Some(op) = tx
                .tx_in
                .first_mut()
                .and_then(|i| i.signature_script.get_mut(65))
            {
                *op = OP_DATA_64;
            }
        },
        |tx| {
            if let Some(prefix) = tx
                .tx_in
                .first_mut()
                .and_then(|i| i.signature_script.get_mut(66))
            {
                *prefix = 0x04;
            }
        },
        |tx| {
            if let Some(op) = tx
                .tx_in
                .first_mut()
                .and_then(|i| i.signature_script.last_mut())
            {
                *op = OP_RETURN;
            }
        },
        |tx| {
            if let Some(tx_in) = tx.tx_in.first_mut() {
                tx_in.previous_out_point.hash.0[0] ^= 0x01;
            }
        },
        |tx| {
            if let Some(tx_in) = tx.tx_in.first_mut() {
                tx_in.previous_out_point.index = 1;
            }
        },
        |tx| {
            if let Some(tx_in) = tx.tx_in.first_mut() {
                tx_in.previous_out_point.tree = TX_TREE_STAKE;
            }
        },
        |tx| {
            if let Some(tx_in) = tx.tx_in.first_mut() {
                *tx_in = null_input(Vec::new());
            }
        },
        // The first output.
        |tx| {
            if let Some(tx_out) = tx.tx_out.first_mut() {
                tx_out.version = 1;
            }
        },
        |tx| {
            if let Some(tx_out) = tx.tx_out.first_mut() {
                tx_out.pk_script.clear();
            }
        },
        |tx| {
            if let Some(tx_out) = tx.tx_out.first_mut() {
                tx_out.pk_script.push(OP_TRUE);
            }
        },
        |tx| {
            if let Some(tx_out) = tx.tx_out.first_mut() {
                tx_out.pk_script.pop();
            }
        },
        |tx| {
            if let Some(op) = tx.tx_out.first_mut().and_then(|o| o.pk_script.first_mut()) {
                *op = OP_TSPEND;
            }
        },
        |tx| {
            if let Some(tx_out) = tx.tx_out.first_mut() {
                *tx_out = out(0, vec![OP_TADD]);
            }
        },
        |tx| {
            if let Some(tx_out) = tx.tx_out.first_mut() {
                *tx_out = out(0, null_data(OP_DATA_32));
            }
        },
        // The second output.
        |tx| {
            if let Some(tx_out) = tx.tx_out.get_mut(1) {
                tx_out.version = 2;
            }
        },
        |tx| {
            if let Some(tx_out) = tx.tx_out.get_mut(1) {
                tx_out.pk_script.clear();
            }
        },
        |tx| {
            if let Some(tx_out) = tx.tx_out.get_mut(1)
                && !tx_out.pk_script.is_empty()
            {
                tx_out.pk_script.remove(0);
            }
        },
        |tx| {
            if let Some(tx_out) = tx.tx_out.get_mut(1) {
                tx_out.pk_script.push(OP_TRUE);
            }
        },
        |tx| {
            if let Some(op) = tx.tx_out.get_mut(1).and_then(|o| o.pk_script.first_mut()) {
                *op = OP_RETURN;
            }
        },
        |tx| {
            if let Some(tx_out) = tx.tx_out.get_mut(1) {
                *tx_out = out(0, null_data(OP_DATA_12));
            }
        },
        |tx| {
            if let Some(tx_out) = tx.tx_out.get_mut(1) {
                *tx_out = out(0, null_data(OP_DATA_11));
            }
        },
        |tx| {
            if let Some(tx_out) = tx.tx_out.get_mut(1) {
                *tx_out = out(0, tagged(OP_TGEN, p2sh()));
            }
        },
        |tx| {
            if let Some(tx_out) = tx.tx_out.get_mut(1) {
                *tx_out = out(0, tagged(OP_SSTXCHANGE, p2sh()));
            }
        },
        |tx| {
            if let Some(tx_out) = tx.tx_out.get_mut(1) {
                // Tagged, but neither pay-to-script-hash nor
                // pay-to-pubkey-hash.
                tx_out.pk_script = vec![OP_TGEN, OP_DATA_33, 0x02, OP_CHECKSIG];
            }
        },
        // The last output.
        |tx| {
            if let Some(tx_out) = tx.tx_out.last_mut() {
                tx_out.version = 1;
            }
        },
        |tx| {
            if let Some(tx_out) = tx.tx_out.last_mut() {
                tx_out.pk_script.clear();
            }
        },
    ];

    /// What the transactions compared so far covered.
    #[derive(Default)]
    struct Seen {
        compared: usize,
        tadds: usize,
        tspends: usize,
        treasury_bases: usize,
        kinds: Vec<ErrorKind>,
    }

    impl Seen {
        fn note(&mut self, kind: Option<ErrorKind>) {
            if let Some(kind) = kind
                && !self.kinds.contains(&kind)
            {
                self.kinds.push(kind);
            }
        }
    }

    /// Hold one transaction's predicates to its checks.
    fn compare(tx: &MsgTx, seen: &mut Seen) {
        let tadd = check_tadd(tx).err().map(|e| e.kind);
        let tspend = check_tspend(tx);
        let tspend_kind = tspend.as_ref().err().map(|e| e.kind);
        let treasury_base = check_treasury_base(tx).err().map(|e| e.kind);

        // The predicates answer as the checks do.
        assert_eq!(is_tadd(tx), is_tadd_by_check(tx), "is_tadd: {tx:?}");
        assert_eq!(is_tspend(tx), is_tspend_by_check(tx), "is_tspend: {tx:?}");
        assert_eq!(
            is_treasury_base(tx),
            is_treasury_base_by_check(tx),
            "is_treasury_base: {tx:?}"
        );
        assert_eq!(
            tspend_signature_and_pub_key(tx),
            tspend.ok(),
            "tspend_signature_and_pub_key: {tx:?}"
        );

        // Each shape test holds exactly where its check fails at the
        // version or at a count, which are the kinds below and no
        // other test's: a looser shape test would let the check build
        // a message for the predicate to drop, a tighter one would
        // refuse a transaction the check goes on to judge.
        assert_eq!(
            fails_tadd_shape(tx),
            matches!(
                tadd,
                Some(ErrorKind::TAddInvalidTxVersion | ErrorKind::TAddInvalidCount)
            ),
            "treasury add shape: {tx:?}"
        );
        assert_eq!(
            fails_tspend_shape(tx),
            matches!(
                tspend_kind,
                Some(ErrorKind::TSpendInvalidTxVersion | ErrorKind::TSpendInvalidLength)
            ),
            "treasury spend shape: {tx:?}"
        );
        assert_eq!(
            fails_treasury_base_shape(tx),
            matches!(
                treasury_base,
                Some(ErrorKind::TreasuryBaseInvalidTxVersion | ErrorKind::TreasuryBaseInvalidCount)
            ),
            "treasurybase shape: {tx:?}"
        );

        seen.compared += 1;
        seen.tadds += usize::from(tadd.is_none());
        seen.tspends += usize::from(tspend_kind.is_none());
        seen.treasury_bases += usize::from(treasury_base.is_none());
        seen.note(tadd);
        seen.note(tspend_kind);
        seen.note(treasury_base);
    }

    #[test]
    fn the_predicates_answer_as_their_checks_do() {
        let bases = bases();
        let mut seen = Seen::default();

        // Every base as it is, with one edit, and with every ordered
        // pair of edits.
        for base in &bases {
            compare(base, &mut seen);
            for first in EDITS {
                let mut once = base.clone();
                first(&mut once);
                compare(&once, &mut seen);
                for second in EDITS {
                    let mut twice = once.clone();
                    second(&mut twice);
                    compare(&twice, &mut seen);
                }
            }
        }

        // Longer runs of edits, at random.
        let mut rng = SplitMix64::from_entropy("treasury predicates");
        for _ in 0..20_000 {
            let mut tx = bases[rng.below(bases.len() as u64) as usize].clone();
            for _ in 0..3 + rng.below(4) {
                EDITS[rng.below(EDITS.len() as u64) as usize](&mut tx);
            }
            compare(&tx, &mut seen);
        }

        // The transactions reached every outcome of every check, so no
        // comparison above held for want of a case.
        assert!(seen.compared > 100_000, "{}", seen.compared);
        assert!(seen.tadds > 100, "{} treasury adds", seen.tadds);
        assert!(seen.tspends > 100, "{} treasury spends", seen.tspends);
        assert!(
            seen.treasury_bases > 100,
            "{} treasurybases",
            seen.treasury_bases
        );
        for kind in [
            ErrorKind::TAddInvalidTxVersion,
            ErrorKind::TAddInvalidCount,
            ErrorKind::TAddInvalidVersion,
            ErrorKind::TAddInvalidScriptLength,
            ErrorKind::TAddInvalidLength,
            ErrorKind::TAddInvalidOpcode,
            ErrorKind::TAddInvalidChange,
            ErrorKind::TSpendInvalidTxVersion,
            ErrorKind::TSpendInvalidLength,
            ErrorKind::TSpendInvalidVersion,
            ErrorKind::TSpendInvalidScriptLength,
            ErrorKind::TSpendInvalidScript,
            ErrorKind::TSpendInvalidPubkey,
            ErrorKind::TSpendInvalidTransaction,
            ErrorKind::TSpendInvalidTGen,
            ErrorKind::TSpendInvalidSpendScript,
            ErrorKind::TreasuryBaseInvalidTxVersion,
            ErrorKind::TreasuryBaseInvalidCount,
            ErrorKind::TreasuryBaseInvalidLength,
            ErrorKind::TreasuryBaseInvalid,
            ErrorKind::TreasuryBaseInvalidVersion,
            ErrorKind::TreasuryBaseInvalidOpcode0,
            ErrorKind::TreasuryBaseInvalidOpcode1,
        ] {
            assert!(
                seen.kinds.contains(&kind),
                "no transaction failed with {kind:?}"
            );
        }
    }
}
