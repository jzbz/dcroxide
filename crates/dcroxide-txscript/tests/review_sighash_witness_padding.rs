// SPDX-License-Identifier: ISC
//! dcrd sizes the witness buffer of the signature hash with
//! `sigHashWitnessSerializeSize` and hashes all of it
//! (txscript/sighash.go `calcSignatureHash`).  The size assumes the
//! signing script gets written, so when no input sits at the signed index
//! -- a transaction with no inputs, or an index past the last input
//! without SigHashAnyOneCanPay -- dcrd hashes a zero-padded tail.  The port
//! hashed only the bytes it wrote, so `calc_signature_hash_checked` gave a
//! different hash for any such call with a non-empty script.  Consensus
//! cannot reach it (the engine requires a valid input index); the public
//! API can.

// Test-harness arithmetic over bounded indices and lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_chainhash::{Hash, hash_b, hash_h};
use dcroxide_testutil::{hex, oracle_or_skip};
use dcroxide_txscript::{
    SIG_HASH_ALL, SIG_HASH_NONE, SIG_HASH_SERIALIZE_PREFIX, SIG_HASH_SERIALIZE_WITNESS,
    SIG_HASH_SINGLE, SigHashType, calc_signature_hash_checked,
};
use dcroxide_wire::{MsgTx, OutPoint, TxIn, TxOut, TxSerializeType};

fn tx(num_in: usize, num_out: usize) -> MsgTx {
    MsgTx {
        ser_type: TxSerializeType::Full,
        version: 1,
        tx_in: (0..num_in)
            .map(|i| TxIn {
                previous_out_point: OutPoint {
                    hash: Hash([i as u8 + 1; 32]),
                    index: i as u32,
                    tree: 0,
                },
                sequence: 0xffff_fffe,
                value_in: 5,
                block_height: 7,
                block_index: 9,
                signature_script: vec![0x51],
            })
            .collect(),
        tx_out: (0..num_out)
            .map(|i| TxOut {
                value: 1000 + i as i64,
                version: 0,
                pk_script: vec![0x76, 0xa9, i as u8],
            })
            .collect(),
        lock_time: 0x0102_0304,
        expiry: 0x0506_0708,
    }
}

/// The sighash of a transaction with no inputs and no outputs, built by
/// hand from dcrd's serialization: the prefix commits to the version, two
/// zero counts, lock time and expiry; the witness buffer is
/// `4 + varint(0) + (0 - 1) + varint(len) + len` bytes, of which only the
/// version and the zero input count are written.
#[test]
fn zero_input_sighash_hashes_dcrds_padded_witness_buffer() {
    let script = [0x51u8, 0x52, 0x53];
    let tx = tx(0, 0);

    let mut prefix = Vec::new();
    prefix.extend_from_slice(&(1u32 | (SIG_HASH_SERIALIZE_PREFIX << 16)).to_le_bytes());
    prefix.push(0); // no inputs
    prefix.push(0); // no outputs
    prefix.extend_from_slice(&tx.lock_time.to_le_bytes());
    prefix.extend_from_slice(&tx.expiry.to_le_bytes());

    let mut witness = Vec::new();
    witness.extend_from_slice(&(1u32 | (SIG_HASH_SERIALIZE_WITNESS << 16)).to_le_bytes());
    witness.push(0); // no inputs
    // dcrd's size is 4 + 1 + (-1) + 1 + 3 = 8; the last three bytes are
    // never written and stay zero.
    witness.resize(8, 0);

    let mut sig_hash = Vec::new();
    sig_hash.extend_from_slice(&u32::from(SIG_HASH_ALL.0).to_le_bytes());
    sig_hash.extend_from_slice(&hash_h(&prefix).0);
    sig_hash.extend_from_slice(&hash_h(&witness).0);
    let want = hash_b(&sig_hash);

    let got = calc_signature_hash_checked(&script, SIG_HASH_ALL, &tx, 0).expect("parses");
    assert_eq!(hex(&got), hex(&want));
}

/// The cases that leave the signing script unwritten, against dcrd's
/// `CalcSignatureHash` itself.
#[test]
fn unwritten_signing_script_matches_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    // Empty, one byte, a few opcodes, and long enough for a three-byte
    // length varint.
    let long = vec![0x51u8; 300];
    let scripts: [&[u8]; 4] = [&[], &[0x51], &[0x76, 0xa9, 0x88, 0xac, 0x00, 0x51], &long];
    // (inputs, outputs, signed index, hash type): no inputs at all, and
    // indexes past the last input.  SigHashSingle needs an output at the
    // index; SigHashAnyOneCanPay would slice out of range in both.
    let cases: &[(usize, usize, usize, SigHashType)] = &[
        (0, 0, 0, SIG_HASH_ALL),
        (0, 2, 0, SIG_HASH_ALL),
        (0, 2, 1, SIG_HASH_NONE),
        (0, 2, 1, SIG_HASH_SINGLE),
        (0, 1, 5, SigHashType(0x1f)),
        (1, 1, 1, SIG_HASH_ALL),
        (2, 3, 2, SIG_HASH_SINGLE),
        (3, 0, 7, SIG_HASH_NONE),
        (1, 2, 1, SIG_HASH_ALL),
    ];
    for script in scripts {
        for &(num_in, num_out, idx, hash_type) in cases {
            let tx = tx(num_in, num_out);
            let ours = hex(&calc_signature_hash_checked(script, hash_type, &tx, idx)
                .expect("script parses and index has an output"));

            let mut req = Vec::new();
            req.push(hash_type.0);
            req.extend_from_slice(&(idx as u32).to_be_bytes());
            req.extend_from_slice(&(script.len() as u32).to_be_bytes());
            req.extend_from_slice(script);
            req.extend_from_slice(&tx.serialize());
            let resp = oracle.call("calc_sighash", &req);
            assert_eq!(
                resp["result"].as_str(),
                Some(ours.as_str()),
                "script={} inputs={num_in} outputs={num_out} idx={idx} hash_type={:#x}: {resp}",
                hex(script),
                hash_type.0
            );
        }
    }
}
