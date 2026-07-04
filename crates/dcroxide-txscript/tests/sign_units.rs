// SPDX-License-Identifier: ISC
//! Focused, oracle-free unit tests for the sign module covering the paths
//! the differential does not exercise: the error arms of `sign`
//! (NULLDATA and nonstandard scripts), an independent-partial multisig
//! merge assembled from two separately-produced scripts, and a basic
//! sign-then-verify round trip that pins the happy path without relying on
//! the differential harness.

// Test-harness arithmetic over bounded indices.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_chaincfg::mainnet_params;
use dcroxide_txscript::sign::{SignError, SignatureType, sign_tx_output};
use dcroxide_txscript::stdaddr::{self, Address};
use dcroxide_txscript::{Engine, ScriptFlags, SigHashType, stdscript};
use dcroxide_wire::{MsgTx, OutPoint, TxIn, TxOut, TxSerializeType};

fn spending_tx(pk_script: &[u8]) -> MsgTx {
    // A minimal well-formed spending transaction with one input and one
    // zero-value output, mirroring the reference spend shape.
    let coinbase = MsgTx {
        ser_type: TxSerializeType::Full,
        version: 1,
        tx_in: vec![TxIn {
            previous_out_point: OutPoint {
                hash: dcroxide_chainhash::Hash::ZERO,
                index: !0u32,
                tree: 0,
            },
            sequence: !0u32,
            value_in: 0,
            block_height: 0,
            block_index: !0u32,
            signature_script: vec![0x00, 0x00],
        }],
        tx_out: vec![TxOut {
            value: 0,
            version: 0,
            pk_script: pk_script.to_vec(),
        }],
        lock_time: 0,
        expiry: 0,
    };
    MsgTx {
        ser_type: TxSerializeType::Full,
        version: 1,
        tx_in: vec![TxIn {
            previous_out_point: OutPoint {
                hash: coinbase.tx_hash(),
                index: 0,
                tree: 0,
            },
            sequence: !0u32,
            value_in: 0,
            block_height: 0,
            block_index: !0u32,
            signature_script: Vec::new(),
        }],
        tx_out: vec![TxOut {
            value: 0,
            version: 0,
            pk_script: Vec::new(),
        }],
        lock_time: 0,
        expiry: 0,
    }
}

/// A fixed valid secp256k1 key (all-ones scalar is in range).
fn fixed_key(byte: u8) -> [u8; 32] {
    let mut k = [byte; 32];
    // Ensure it is a valid, in-range scalar.
    k[0] = 0x01;
    k
}

fn secp_pub(key: &[u8; 32]) -> [u8; 33] {
    dcroxide_dcrec::secp256k1::PrivateKey::from_bytes(key)
        .expect("valid key")
        .public_key()
        .serialize_compressed()
}

/// A KeyDb backed by a single (address, key) pair.
fn single_key_db(
    addr: String,
    key: Vec<u8>,
    sig_type: SignatureType,
    compressed: bool,
) -> impl FnMut(&Address) -> Result<(Vec<u8>, SignatureType, bool), SignError> {
    move |a: &Address| {
        if a.encode() == addr {
            Ok((key.clone(), sig_type, compressed))
        } else {
            Err(SignError(format!("no key for {}", a.encode())))
        }
    }
}

fn no_script_db() -> impl FnMut(&Address) -> Result<Vec<u8>, SignError> {
    |a: &Address| Err(SignError(format!("no script for {}", a.encode())))
}

/// Signing a NULLDATA script fails with dcrd's exact message.
#[test]
fn sign_nulldata_errors() {
    let params = mainnet_params();
    let pk_script = stdscript::provably_pruneable_script_v0(b"hello").expect("builds");
    let tx = spending_tx(&pk_script);
    let mut kdb = |_: &Address| Err(SignError("unused".into()));
    let mut sdb = no_script_db();
    let err = sign_tx_output(
        &params,
        &tx,
        0,
        &pk_script,
        SigHashType(0x01),
        &mut kdb,
        &mut sdb,
        &[],
        false,
    )
    .expect_err("nulldata cannot be signed");
    assert_eq!(err.0, "can't sign NULLDATA transactions");
}

/// Signing a nonstandard script fails with dcrd's exact message.
#[test]
fn sign_nonstandard_errors() {
    let params = mainnet_params();
    // OP_TRUE alone is nonstandard for signing purposes.
    let pk_script = vec![0x51];
    let tx = spending_tx(&pk_script);
    let mut kdb = |_: &Address| Err(SignError("unused".into()));
    let mut sdb = no_script_db();
    let err = sign_tx_output(
        &params,
        &tx,
        0,
        &pk_script,
        SigHashType(0x01),
        &mut kdb,
        &mut sdb,
        &[],
        false,
    )
    .expect_err("nonstandard cannot be signed");
    assert_eq!(err.0, "can't sign unknown transactions");
}

/// A missing key propagates the KeyDb error rather than signing.
#[test]
fn sign_missing_key_errors() {
    let params = mainnet_params();
    let key = fixed_key(0x11);
    let addr = stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(
        &stdaddr::hash160(&secp_pub(&key)),
        &params,
    )
    .expect("20 bytes");
    let (_, pk_script) = addr.payment_script();
    let tx = spending_tx(&pk_script);
    // KeyDb that never has the key.
    let mut kdb = |a: &Address| Err(SignError(format!("no key for {}", a.encode())));
    let mut sdb = no_script_db();
    let err = sign_tx_output(
        &params,
        &tx,
        0,
        &pk_script,
        SigHashType(0x01),
        &mut kdb,
        &mut sdb,
        &[],
        false,
    )
    .expect_err("missing key errors");
    assert!(err.0.starts_with("no key for"), "got: {}", err.0);
}

/// A basic P2PKH sign-then-verify round trip, independent of the oracle.
#[test]
fn sign_p2pkh_round_trip() {
    let params = mainnet_params();
    let key = fixed_key(0x22);
    let addr = stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(
        &stdaddr::hash160(&secp_pub(&key)),
        &params,
    )
    .expect("20 bytes");
    let (_, pk_script) = addr.payment_script();
    let tx = spending_tx(&pk_script);

    let mut kdb = single_key_db(
        addr.encode(),
        key.to_vec(),
        SignatureType::EcdsaSecp256k1,
        true,
    );
    let mut sdb = no_script_db();
    let sig_script = sign_tx_output(
        &params,
        &tx,
        0,
        &pk_script,
        SigHashType(0x01),
        &mut kdb,
        &mut sdb,
        &[],
        false,
    )
    .expect("signs");

    let mut signed = tx.clone();
    signed.tx_in[0].signature_script = sig_script;
    Engine::new(&pk_script, &signed, 0, ScriptFlags::default(), 0)
        .and_then(|mut vm| vm.execute())
        .expect("signed input verifies");
}

/// Two independently-produced partial multisig scripts merge into a
/// fully-satisfying script. This exercises `mergeMultiSig`'s
/// signature-to-pubkey matching over signatures produced in separate
/// signing passes (as opposed to the sequential fill of a single pass).
#[test]
fn multisig_independent_partials_merge() {
    let params = mainnet_params();
    let keys: Vec<[u8; 32]> = (0..3).map(|i| fixed_key(0x30 + i)).collect();
    let pub_keys: Vec<[u8; 33]> = keys.iter().map(secp_pub).collect();
    let key_refs: Vec<&[u8]> = pub_keys.iter().map(|k| k.as_slice()).collect();
    let pk_script = stdscript::multi_sig_script_v0(2, &key_refs).expect("2-of-3");
    let tx = spending_tx(&pk_script);

    let addr_of = |k: &[u8; 32]| {
        stdaddr::new_address_pub_key_ecdsa_secp256k1_v0(secp_pub(k), &params).encode()
    };

    let sign_with = |which: usize, prev: &[u8]| -> Vec<u8> {
        let addr = addr_of(&keys[which]);
        let key = keys[which].to_vec();
        let mut kdb = single_key_db(addr, key, SignatureType::EcdsaSecp256k1, true);
        let mut sdb = no_script_db();
        sign_tx_output(
            &params,
            &tx,
            0,
            &pk_script,
            SigHashType(0x01),
            &mut kdb,
            &mut sdb,
            prev,
            false,
        )
        .expect("partial signs")
    };

    // Produce two independent single-signature partials, then merge the
    // first into the second by passing it as the previous script.
    let partial0 = sign_with(0, &[]);
    let merged = sign_with(2, &partial0);

    // The merged script must satisfy the 2-of-3 requirement.
    let mut signed = tx.clone();
    signed.tx_in[0].signature_script = merged;
    Engine::new(&pk_script, &signed, 0, ScriptFlags::default(), 0)
        .and_then(|mut vm| vm.execute())
        .expect("merged multisig verifies");
}
