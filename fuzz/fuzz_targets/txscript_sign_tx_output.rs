// SPDX-License-Identifier: ISC
//! `sign_tx_output` over arbitrary previous output scripts, previous
//! signature scripts, redeem scripts, input indexes, hash types and
//! transaction shapes must return, never panic and never overflow its
//! stack: dcrd's `SignTxOutput` panics on a pay-to-pubkey script whose key
//! does not parse and on an input index past the inputs under
//! `SigHashAnyOneCanPay`, and recurses until its stack overflows on a merge
//! into a nested pay-to-script-hash signature script, and the port answers
//! each with an error (QK-0034, QK-0035, QK-0036).
//!
//! Input layout: the hash type (1), the treasury flag (1), the input index
//! (1), the input and output counts (1 each, taken modulo 4), the key mode
//! (1: which of the three signature types every key lookup answers with,
//! or a failed lookup), whether script lookups fail (1), the lengths of the
//! previous output script and the previous signature script (2 each, little
//! endian), then those two scripts and, from the rest, the redeem script
//! every script lookup answers with.  A redeem script answered for every
//! address is what lets the fuzzer build nested pay-to-script-hash inputs
//! and pay-to-pubkey redeem scripts out of one byte string.

#![no_main]

use libfuzzer_sys::fuzz_target;

use dcroxide_chaincfg::simnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_txscript::SigHashType;
use dcroxide_txscript::sign::{SignError, SignatureType, sign_tx_output};
use dcroxide_txscript::stdaddr::Address;
use dcroxide_wire::{MsgTx, OutPoint, TxIn, TxOut, TxSerializeType};

/// The bytes ahead of the scripts.
const HEADER: usize = 11;

fn le16(b: &[u8]) -> usize {
    usize::from(u16::from_le_bytes([b[0], b[1]]))
}

/// A fixed valid key in each signature type's serialized form.
fn key(sig_type: SignatureType) -> Vec<u8> {
    let seed = [7u8; 32];
    match sig_type {
        SignatureType::Ed25519 => {
            let public = dcroxide_dcrec::edwards::SecretKey::from_seed(seed)
                .public_key()
                .serialize();
            [seed.as_slice(), public.as_slice()].concat()
        }
        _ => seed.to_vec(),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER {
        return;
    }
    let hash_type = SigHashType(data[0]);
    let treasury = data[1] & 1 == 1;
    let idx = usize::from(data[2]);
    let n_in = usize::from(data[3] % 4);
    let n_out = usize::from(data[4] % 4);
    let key_mode = data[5] % 4;
    let scripts_fail = data[6] & 1 == 1;
    let rest = &data[HEADER..];
    let pk_len = le16(&data[7..9]).min(rest.len());
    let (pk_script, rest) = rest.split_at(pk_len);
    let prev_len = le16(&data[9..11]).min(rest.len());
    let (prev_script, redeem) = rest.split_at(prev_len);

    let tx = MsgTx {
        ser_type: TxSerializeType::Full,
        version: 1,
        tx_in: (0..n_in)
            .map(|i| TxIn {
                previous_out_point: OutPoint {
                    hash: Hash([i as u8; 32]),
                    index: i as u32,
                    tree: 0,
                },
                sequence: u32::MAX,
                value_in: 0,
                block_height: 0,
                block_index: 0,
                signature_script: Vec::new(),
            })
            .collect(),
        tx_out: (0..n_out)
            .map(|i| TxOut {
                value: i as i64,
                version: 0,
                pk_script: vec![0x51],
            })
            .collect(),
        lock_time: 0,
        expiry: 0,
    };

    let mut kdb = |_: &Address| -> Result<(Vec<u8>, SignatureType, bool), SignError> {
        let sig_type = match key_mode {
            0 => SignatureType::EcdsaSecp256k1,
            1 => SignatureType::SchnorrSecp256k1,
            2 => SignatureType::Ed25519,
            _ => return Err(SignError::new("no key")),
        };
        Ok((key(sig_type), sig_type, true))
    };
    let mut sdb = |_: &Address| -> Result<Vec<u8>, SignError> {
        if scripts_fail {
            Err(SignError::other("no script"))
        } else {
            Ok(redeem.to_vec())
        }
    };
    let params = simnet_params();
    let _ = sign_tx_output(
        &params,
        &tx,
        idx,
        pk_script,
        hash_type,
        &mut kdb,
        &mut sdb,
        prev_script,
        treasury,
    );
});
