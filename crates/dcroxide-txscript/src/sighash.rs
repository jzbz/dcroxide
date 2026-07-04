// SPDX-License-Identifier: ISC
//! Signature hash calculation (dcrd `sighash.go`): Decred's split
//! prefix/witness commitment digests combined under BLAKE-256.

use alloc::format;
use alloc::vec::Vec;

use dcroxide_chainhash::{Hash, hash_b, hash_h};
use dcroxide_wire::MsgTx;

use crate::error::{ErrorKind, ScriptError, script_error};
use crate::script::check_script_parses;

/// Hash type bits at the end of a signature (dcrd `SigHashType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigHashType(pub u8);

/// Signs all outputs (dcrd `SigHashAll`).
pub const SIG_HASH_ALL: SigHashType = SigHashType(0x1);
/// Signs no outputs (dcrd `SigHashNone`).
pub const SIG_HASH_NONE: SigHashType = SigHashType(0x2);
/// Signs the single corresponding output (dcrd `SigHashSingle`).
pub const SIG_HASH_SINGLE: SigHashType = SigHashType(0x3);
/// Commits only to the input being signed (dcrd `SigHashAnyOneCanPay`).
pub const SIG_HASH_ANY_ONE_CAN_PAY: SigHashType = SigHashType(0x80);

/// The bits of the hash type which identify which outputs are signed (dcrd
/// `sigHashMask`).
pub(crate) const SIG_HASH_MASK: u8 = 0x1f;

/// The serialization type committed to in place of witness data (dcrd
/// `SigHashSerializePrefix`).
pub const SIG_HASH_SERIALIZE_PREFIX: u32 = 1;

/// The serialization type committing only to witness data (dcrd
/// `SigHashSerializeWitness`).
pub const SIG_HASH_SERIALIZE_WITNESS: u32 = 3;

/// Append a varint in the signature hash encoding (same format as the wire
/// varint; dcrd `putVarInt`).
fn put_var_int(buf: &mut Vec<u8>, val: u64) {
    if val < 0xfd {
        buf.push(val as u8);
    } else if val <= u64::from(u16::MAX) {
        buf.push(0xfd);
        buf.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= u64::from(u32::MAX) {
        buf.push(0xfe);
        buf.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

/// Compute the signature hash for the specified input (dcrd
/// `calcSignatureHash`). The prefix-hash caching optimization dcrd carries
/// behind its permanently-disabled `optimizeSigVerification` flag is not
/// reproduced (it is dead code at the parity tag).
pub(crate) fn calc_signature_hash(
    sign_script: &[u8],
    hash_type: SigHashType,
    tx: &MsgTx,
    idx: usize,
) -> Result<[u8; 32], ScriptError> {
    // The SigHashSingle signature type signs only the corresponding input
    // and output, so it is improper to use it on input indices that don't
    // have a corresponding output.
    if hash_type.0 & SIG_HASH_MASK == SIG_HASH_SINGLE.0 && idx >= tx.tx_out.len() {
        return Err(script_error(
            ErrorKind::InvalidSigHashSingleIndex,
            format!(
                "attempt to sign single input at index {idx} >= {} outputs",
                tx.tx_out.len()
            ),
        ));
    }

    // Choose the inputs that will be committed to based on the signature
    // hash type. SigHashAnyOneCanPay commits only to the input being
    // signed; otherwise all inputs are committed to.
    let (tx_ins, sign_tx_in_idx) = if hash_type.0 & SIG_HASH_ANY_ONE_CAN_PAY.0 != 0 {
        (&tx.tx_in[idx..idx + 1], 0usize)
    } else {
        (&tx.tx_in[..], idx)
    };

    // Choose the outputs to commit to based on the signature hash type:
    // SigHashNone commits to none, SigHashSingle to the outputs up to and
    // including the corresponding one (with prior outputs cleared), and
    // everything else (including undefined hash types) to all outputs.
    let tx_outs: &[dcroxide_wire::TxOut] = match hash_type.0 & SIG_HASH_MASK {
        x if x == SIG_HASH_NONE.0 => &[],
        x if x == SIG_HASH_SINGLE.0 => &tx.tx_out[..idx + 1],
        _ => &tx.tx_out[..],
    };

    // The prefix hash commits to the non-witness data:
    // 1) txversion|(SigHashSerializePrefix<<16) (LE u32)
    // 2) number of inputs (varint), then per input: prevout hash, index
    //    (LE u32), tree (byte), sequence (LE u32, zeroed for non-signed
    //    inputs under SigHashNone/SigHashSingle)
    // 3) number of outputs (varint), then per output: amount (LE u64),
    //    script version (LE u16), pkscript (varint length + bytes); under
    //    SigHashSingle non-corresponding outputs commit to value -1 and a
    //    nil script
    // 4) lock time and expiry (LE u32 each).
    let mut prefix_buf = Vec::new();
    let version = u32::from(tx.version) | (SIG_HASH_SERIALIZE_PREFIX << 16);
    prefix_buf.extend_from_slice(&version.to_le_bytes());

    put_var_int(&mut prefix_buf, tx_ins.len() as u64);
    for (tx_in_idx, tx_in) in tx_ins.iter().enumerate() {
        let prev_out = &tx_in.previous_out_point;
        prefix_buf.extend_from_slice(&prev_out.hash.0);
        prefix_buf.extend_from_slice(&prev_out.index.to_le_bytes());
        prefix_buf.push(prev_out.tree as u8);

        let mut sequence = tx_in.sequence;
        if (hash_type.0 & SIG_HASH_MASK == SIG_HASH_NONE.0
            || hash_type.0 & SIG_HASH_MASK == SIG_HASH_SINGLE.0)
            && tx_in_idx != sign_tx_in_idx
        {
            sequence = 0;
        }
        prefix_buf.extend_from_slice(&sequence.to_le_bytes());
    }

    put_var_int(&mut prefix_buf, tx_outs.len() as u64);
    for (tx_out_idx, tx_out) in tx_outs.iter().enumerate() {
        let mut value = tx_out.value;
        let mut pk_script: &[u8] = &tx_out.pk_script;
        if hash_type.0 & SIG_HASH_MASK == SIG_HASH_SINGLE.0 && tx_out_idx != idx {
            value = -1;
            pk_script = &[];
        }
        prefix_buf.extend_from_slice(&(value as u64).to_le_bytes());
        prefix_buf.extend_from_slice(&tx_out.version.to_le_bytes());
        put_var_int(&mut prefix_buf, pk_script.len() as u64);
        prefix_buf.extend_from_slice(pk_script);
    }

    prefix_buf.extend_from_slice(&tx.lock_time.to_le_bytes());
    prefix_buf.extend_from_slice(&tx.expiry.to_le_bytes());
    let prefix_hash = hash_h(&prefix_buf);

    // The witness hash commits to the input witness data:
    // 1) txversion|(SigHashSerializeWitness<<16) (LE u32)
    // 2) number of inputs (varint), then per input the signing script for
    //    the input being signed and a nil script for all others.
    let mut witness_buf = Vec::new();
    let version = u32::from(tx.version) | (SIG_HASH_SERIALIZE_WITNESS << 16);
    witness_buf.extend_from_slice(&version.to_le_bytes());

    put_var_int(&mut witness_buf, tx_ins.len() as u64);
    for tx_in_idx in 0..tx_ins.len() {
        let commit_script: &[u8] = if tx_in_idx == sign_tx_in_idx {
            sign_script
        } else {
            &[]
        };
        put_var_int(&mut witness_buf, commit_script.len() as u64);
        witness_buf.extend_from_slice(commit_script);
    }
    let witness_hash = hash_h(&witness_buf);

    // The final signature hash is blake256 over the hash type (LE u32),
    // the prefix hash, and the witness hash.
    let mut sig_hash_buf = Vec::with_capacity(32 * 2 + 4);
    sig_hash_buf.extend_from_slice(&u32::from(hash_type.0).to_le_bytes());
    sig_hash_buf.extend_from_slice(&prefix_hash.0);
    sig_hash_buf.extend_from_slice(&witness_hash.0);
    Ok(hash_b(&sig_hash_buf))
}

/// Compute the signature hash for the specified input of the target
/// transaction (dcrd `CalcSignatureHash`).
///
/// Like dcrd, `idx` must be a valid input index for the transaction (dcrd
/// panics otherwise; this port panics on the same out-of-range slicing).
///
/// NOTE: This function is only valid for version 0 scripts.
pub fn calc_signature_hash_checked(
    script: &[u8],
    hash_type: SigHashType,
    tx: &MsgTx,
    idx: usize,
) -> Result<[u8; 32], ScriptError> {
    const SCRIPT_VERSION: u16 = 0;
    check_script_parses(SCRIPT_VERSION, script)?;
    calc_signature_hash(script, hash_type, tx, idx)
}

/// Convenience wrapper returning the sighash as a [`Hash`].
pub fn calc_signature_hash_as_hash(
    script: &[u8],
    hash_type: SigHashType,
    tx: &MsgTx,
    idx: usize,
) -> Result<Hash, ScriptError> {
    calc_signature_hash_checked(script, hash_type, tx, idx).map(Hash)
}
