// SPDX-License-Identifier: ISC
//! Transaction signing helpers (dcrd `txscript/v4/sign`): raw input
//! signatures across all three signature suites, standard signature
//! scripts, multisig signing and merging, `SignTxOutput`, and treasury
//! spend signing.
//!
//! Version 0 scripts are the only supported version, matching dcrd.
//!
//! Key formats match dcrd's `PrivKeyFromBytes` exactly: secp256k1 keys
//! (ECDSA and Schnorr) are 32 bytes, and Ed25519 keys are the 64-byte
//! `seed ‖ public key` expanded form — the embedded public key is parsed
//! (rejecting keys whose trailing 32 bytes are not a valid point) and its
//! canonical re-serialization is what participates in the signature
//! commitment, reproducing the 2017-`agl` `ed25519.Sign` behavior dcrd
//! relies on. dcrd's silent mod-N reduction of out-of-range secp256k1 keys
//! is not reproduced (we reject them, as elsewhere — see PARITY.md).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use dcroxide_wire::MsgTx;

use crate::builder::ScriptBuilder;
use crate::opcode_table::{OP_0, OP_TSPEND};
use crate::script::{check_script_parses, final_opcode_data};
use crate::sighash::{SIG_HASH_ALL, SigHashType, calc_signature_hash_checked};
use crate::stdaddr::{Address, AddressParamsV0};
use crate::stdscript::{self, ScriptType};
use crate::tokenizer::ScriptTokenizer;

/// The dcrec signature type identifiers (dcrd `dcrec.SignatureType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)] // Values mirror dcrd's documented constants 1:1.
pub enum SignatureType {
    EcdsaSecp256k1,
    Ed25519,
    SchnorrSecp256k1,
}

/// A signing error; dcrd's sign package uses plain string errors with no
/// kind type, so only the message carries information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignError(pub String);

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::error::Error for SignError {}

fn sign_error(msg: impl Into<String>) -> SignError {
    SignError(msg.into())
}

/// Access to private keys for addresses (dcrd `KeyDB`): returns the
/// serialized private key, its signature type, and whether the associated
/// public key should be serialized compressed.
pub trait KeyDb {
    /// Look up the key material for the address.
    fn get_key(&mut self, addr: &Address) -> Result<(Vec<u8>, SignatureType, bool), SignError>;
}

impl<F> KeyDb for F
where
    F: FnMut(&Address) -> Result<(Vec<u8>, SignatureType, bool), SignError>,
{
    fn get_key(&mut self, addr: &Address) -> Result<(Vec<u8>, SignatureType, bool), SignError> {
        self(addr)
    }
}

/// Access to redeem scripts for pay-to-script-hash addresses (dcrd
/// `ScriptDB`).
pub trait ScriptDb {
    /// Look up the redeem script for the address.
    fn get_script(&mut self, addr: &Address) -> Result<Vec<u8>, SignError>;
}

impl<F> ScriptDb for F
where
    F: FnMut(&Address) -> Result<Vec<u8>, SignError>,
{
    fn get_script(&mut self, addr: &Address) -> Result<Vec<u8>, SignError> {
        self(addr)
    }
}

/// Parse a 32-byte secp256k1 private key with the strictness documented in
/// the module header.
fn secp_priv_key(key: &[u8]) -> Result<dcroxide_dcrec::secp256k1::PrivateKey, SignError> {
    let bytes: [u8; 32] = key.try_into().map_err(|_| sign_error("invalid privkey"))?;
    dcroxide_dcrec::secp256k1::PrivateKey::from_bytes(&bytes)
        .ok_or_else(|| sign_error("invalid privkey"))
}

/// Parse a 64-byte Ed25519 `seed ‖ pubkey` key (dcrd
/// `edwards.PrivKeyFromBytes`), returning the seed-derived secret and the
/// canonical re-serialization of the embedded public key. The trailing 32
/// bytes must decode as a valid curve point or the key is rejected.
fn ed25519_secret(key: &[u8]) -> Result<(dcroxide_dcrec::edwards::SecretKey, [u8; 32]), SignError> {
    let key: [u8; 64] = key.try_into().map_err(|_| sign_error("invalid privkey"))?;
    let seed: [u8; 32] = key[..32].try_into().expect("32 bytes");
    let pub_key = dcroxide_dcrec::edwards::parse_pub_key(&key[32..])
        .map_err(|_| sign_error("invalid privkey"))?;
    Ok((
        dcroxide_dcrec::edwards::SecretKey::from_seed(seed),
        pub_key.serialize(),
    ))
}

/// The serialized signature for input `idx` of the transaction with the
/// hash type appended (dcrd `RawTxInSignature`).
///
/// NOTE: Only valid for version 0 scripts.
pub fn raw_tx_in_signature(
    tx: &MsgTx,
    idx: usize,
    sub_script: &[u8],
    hash_type: SigHashType,
    key: &[u8],
    sig_type: SignatureType,
) -> Result<Vec<u8>, SignError> {
    let hash = calc_signature_hash_checked(sub_script, hash_type, tx, idx)
        .map_err(|e| sign_error(format!("{e}")))?;

    let mut sig_bytes = match sig_type {
        SignatureType::EcdsaSecp256k1 => {
            let priv_key = secp_priv_key(key)?;
            dcroxide_dcrec::secp256k1::ecdsa::sign(&priv_key, &hash).serialize()
        }
        SignatureType::Ed25519 => {
            let (secret, pub_bytes) = ed25519_secret(key)?;
            dcroxide_dcrec::edwards::sign_with_pub_key_bytes(&secret, &pub_bytes, &hash)
                .serialize()
                .to_vec()
        }
        SignatureType::SchnorrSecp256k1 => {
            let priv_key = secp_priv_key(key)?;
            dcroxide_dcrec::secp256k1::schnorr::sign(&priv_key, &hash)
                .map_err(|e| sign_error(format!("cannot sign tx input: {e:?}")))?
                .serialize()
                .to_vec()
        }
    };

    sig_bytes.push(hash_type.0);
    Ok(sig_bytes)
}

/// The public key serialization used in signature scripts for the key and
/// signature type.
fn pk_data(key: &[u8], sig_type: SignatureType, compress: bool) -> Result<Vec<u8>, SignError> {
    Ok(match sig_type {
        SignatureType::EcdsaSecp256k1 => {
            let priv_key = secp_priv_key(key)?;
            if compress {
                priv_key.public_key().serialize_compressed().to_vec()
            } else {
                priv_key.public_key().serialize_uncompressed().to_vec()
            }
        }
        SignatureType::Ed25519 => {
            // dcrd returns the canonical re-serialization of the embedded
            // public key (its `pub.Serialize()`), not one derived from the
            // seed.
            let (_, pub_bytes) = ed25519_secret(key)?;
            pub_bytes.to_vec()
        }
        SignatureType::SchnorrSecp256k1 => {
            let priv_key = secp_priv_key(key)?;
            priv_key.public_key().serialize_compressed().to_vec()
        }
    })
}

/// An input signature script spending a previous output to the owner of
/// the private key: `<sig> <pubkey>` (dcrd `SignatureScript`).
///
/// NOTE: Only valid for version 0 scripts.
pub fn signature_script(
    tx: &MsgTx,
    idx: usize,
    subscript: &[u8],
    hash_type: SigHashType,
    priv_key: &[u8],
    sig_type: SignatureType,
    compress: bool,
) -> Result<Vec<u8>, SignError> {
    let sig = raw_tx_in_signature(tx, idx, subscript, hash_type, priv_key, sig_type)?;
    let pk_data = pk_data(priv_key, sig_type, compress)?;

    ScriptBuilder::new()
        .add_data(&sig)
        .add_data(&pk_data)
        .script()
        .map_err(|e| sign_error(format!("{e}")))
}

/// A pay-to-pubkey signature script: `<sig>` (dcrd `p2pkSignatureScript`).
fn p2pk_signature_script(
    tx: &MsgTx,
    idx: usize,
    sub_script: &[u8],
    hash_type: SigHashType,
    priv_key: &[u8],
    sig_type: SignatureType,
) -> Result<Vec<u8>, SignError> {
    let sig = raw_tx_in_signature(tx, idx, sub_script, hash_type, priv_key, sig_type)?;
    ScriptBuilder::new()
        .add_data(&sig)
        .script()
        .map_err(|e| sign_error(format!("{e}")))
}

/// Sign as many of the outputs in the provided multisig script as possible
/// (dcrd `signMultiSig`); returns the script and whether the contract is
/// fulfilled. Failing to sign any output is not an error.
fn sign_multi_sig(
    tx: &MsgTx,
    idx: usize,
    sub_script: &[u8],
    hash_type: SigHashType,
    addresses: &[Address],
    n_required: u16,
    kdb: &mut dyn KeyDb,
) -> (Vec<u8>, bool) {
    // No need to add a dummy in Decred.
    let mut builder = ScriptBuilder::new();
    let mut signed: u16 = 0;
    for addr in addresses {
        let Ok((key, sig_type, _)) = kdb.get_key(addr) else {
            continue;
        };
        let Ok(sig) = raw_tx_in_signature(tx, idx, sub_script, hash_type, &key, sig_type) else {
            continue;
        };

        builder = builder.add_data(&sig);
        signed += 1;
        if signed == n_required {
            break;
        }
    }

    (builder.unchecked_script(), signed == n_required)
}

/// Convert stake-specific script types to their associated sub type (dcrd
/// `stakeSubScriptType`).
fn stake_sub_script_type(script_type: ScriptType, is_treasury_enabled: bool) -> ScriptType {
    use ScriptType::*;
    match script_type {
        StakeSubmissionPubKeyHash
        | StakeChangePubKeyHash
        | StakeGenPubKeyHash
        | StakeRevocationPubKeyHash => PubKeyHashEcdsaSecp256k1,
        TreasuryGenPubKeyHash if is_treasury_enabled => PubKeyHashEcdsaSecp256k1,

        StakeSubmissionScriptHash
        | StakeChangeScriptHash
        | StakeGenScriptHash
        | StakeRevocationScriptHash => ScriptHash,
        TreasuryGenScriptHash if is_treasury_enabled => ScriptHash,

        other => other,
    }
}

/// The `sign` result: the script, the (untransformed) script type, and the
/// extracted addresses.
type SignResult = (Vec<u8>, ScriptType, Vec<Address>);

/// Sign a stake-tagged output (dcrd `handleStakeOutSign`).
#[allow(clippy::too_many_arguments)] // Mirrors dcrd's signature.
fn handle_stake_out_sign(
    tx: &MsgTx,
    idx: usize,
    sub_script: &[u8],
    hash_type: SigHashType,
    kdb: &mut dyn KeyDb,
    sdb: &mut dyn ScriptDb,
    addresses: Vec<Address>,
    script_type: ScriptType,
    is_treasury_enabled: bool,
) -> Result<SignResult, SignError> {
    let sub_type = stake_sub_script_type(script_type, is_treasury_enabled);
    match sub_type {
        ScriptType::PubKeyHashEcdsaSecp256k1 => {
            let (key, sig_type, compressed) = kdb.get_key(&addresses[0])?;
            let script =
                signature_script(tx, idx, sub_script, hash_type, &key, sig_type, compressed)?;
            Ok((script, script_type, addresses))
        }
        ScriptType::ScriptHash => {
            let script = sdb.get_script(&addresses[0])?;
            Ok((script, script_type, addresses))
        }
        _ => Err(sign_error(
            "unknown sub script type for stake output to sign",
        )),
    }
}

/// The main signing workhorse (dcrd `sign`).
#[allow(clippy::too_many_arguments)] // Mirrors dcrd's signature.
fn sign(
    chain_params: &dyn AddressParamsV0,
    tx: &MsgTx,
    idx: usize,
    sub_script: &[u8],
    hash_type: SigHashType,
    kdb: &mut dyn KeyDb,
    sdb: &mut dyn ScriptDb,
    is_treasury_enabled: bool,
) -> Result<SignResult, SignError> {
    use ScriptType::*;

    let (script_type, addresses) = stdscript::extract_addrs_v0(sub_script, chain_params);
    match script_type {
        PubKeyEcdsaSecp256k1 | PubKeyEd25519 | PubKeySchnorrSecp256k1 => {
            let (key, sig_type, _) = kdb.get_key(&addresses[0])?;
            let script = p2pk_signature_script(tx, idx, sub_script, hash_type, &key, sig_type)?;
            Ok((script, script_type, addresses))
        }

        PubKeyHashEcdsaSecp256k1 | PubKeyHashEd25519 | PubKeyHashSchnorrSecp256k1 => {
            let (key, sig_type, compressed) = kdb.get_key(&addresses[0])?;
            let script =
                signature_script(tx, idx, sub_script, hash_type, &key, sig_type, compressed)?;
            Ok((script, script_type, addresses))
        }

        ScriptHash => {
            let script = sdb.get_script(&addresses[0])?;
            Ok((script, script_type, addresses))
        }

        MultiSig => {
            let details = stdscript::extract_multi_sig_script_details_v0(sub_script, false);
            let threshold = details.required_sigs;
            let (script, _) =
                sign_multi_sig(tx, idx, sub_script, hash_type, &addresses, threshold, kdb);
            Ok((script, script_type, addresses))
        }

        StakeSubmissionPubKeyHash
        | StakeSubmissionScriptHash
        | StakeGenPubKeyHash
        | StakeGenScriptHash
        | StakeRevocationPubKeyHash
        | StakeRevocationScriptHash
        | StakeChangePubKeyHash
        | StakeChangeScriptHash
        | TreasuryGenPubKeyHash
        | TreasuryGenScriptHash => handle_stake_out_sign(
            tx,
            idx,
            sub_script,
            hash_type,
            kdb,
            sdb,
            addresses,
            script_type,
            is_treasury_enabled,
        ),

        NullData => Err(sign_error("can't sign NULLDATA transactions")),

        _ => Err(sign_error("can't sign unknown transactions")),
    }
}

/// Combine two signature scripts that both provide signatures for a
/// multisig output (dcrd `mergeMultiSig`). Behavior is undefined when the
/// arguments are inconsistent with the output, matching dcrd.
///
/// NOTE: Only valid for version 0 scripts.
fn merge_multi_sig(
    tx: &MsgTx,
    idx: usize,
    addresses: &[Address],
    n_required: u16,
    pk_script: &[u8],
    sig_script: &[u8],
    prev_script: &[u8],
) -> Vec<u8> {
    // Nothing to merge when either script is empty.
    if sig_script.is_empty() {
        return prev_script.to_vec();
    }
    if prev_script.is_empty() {
        return sig_script.to_vec();
    }

    // Collect the non-empty pushes from both scripts; a parse failure in
    // one returns the other unchanged.
    fn extract_sigs(script: &[u8], sigs: &mut Vec<Vec<u8>>) -> Result<(), ()> {
        const SCRIPT_VERSION: u16 = 0;
        let mut tokenizer = ScriptTokenizer::new(SCRIPT_VERSION, script);
        while tokenizer.next() {
            let data = tokenizer.data();
            if !data.is_empty() {
                sigs.push(data.to_vec());
            }
        }
        if tokenizer.err().is_some() {
            return Err(());
        }
        Ok(())
    }

    let mut possible_sigs: Vec<Vec<u8>> = Vec::new();
    if extract_sigs(sig_script, &mut possible_sigs).is_err() {
        return prev_script.to_vec();
    }
    if extract_sigs(prev_script, &mut possible_sigs).is_err() {
        return sig_script.to_vec();
    }

    // Match signatures to pubkeys by attempting verification against each
    // address in order; anything that doesn't parse or verify is thrown
    // away.
    let mut addr_to_sig: alloc::collections::BTreeMap<String, Vec<u8>> =
        alloc::collections::BTreeMap::new();
    'sig_loop: for sig in &possible_sigs {
        if sig.is_empty() {
            continue;
        }
        let t_sig = &sig[..sig.len() - 1];
        let hash_type = SigHashType(sig[sig.len() - 1]);

        let Ok(p_sig) = dcroxide_dcrec::secp256k1::ecdsa::parse_der_signature(t_sig) else {
            continue;
        };

        // Hash types may vary between signatures, so compute per
        // signature.
        let Ok(hash) = calc_signature_hash_checked(pk_script, hash_type, tx, idx) else {
            continue;
        };

        for addr in addresses {
            // All multisig addresses are pubkey addresses; it is an error
            // to call this internal function with bad input (dcrd panics
            // on the type assertion the same way).
            let serialized = addr
                .serialized_pub_key()
                .expect("multisig addresses are pubkey addresses");
            let Ok(pub_key) = dcroxide_dcrec::secp256k1::PublicKey::parse(serialized) else {
                continue;
            };

            // Only one signature per public key.
            if p_sig.verify(&hash, &pub_key) {
                let a_str = addr.encode();
                addr_to_sig.entry(a_str).or_insert_with(|| sig.clone());
                continue 'sig_loop;
            }
        }
    }

    let mut builder = ScriptBuilder::new();
    let mut done_sigs: u16 = 0;
    // This assumes that addresses are in the same order as in the script.
    for addr in addresses {
        let Some(sig) = addr_to_sig.get(&addr.encode()) else {
            continue;
        };
        builder = builder.add_data(sig);
        done_sigs += 1;
        if done_sigs == n_required {
            break;
        }
    }

    // Padding for missing ones.
    for _ in done_sigs..n_required {
        builder = builder.add_op(OP_0);
    }

    builder.unchecked_script()
}

/// Merge two partial solutions for a public key script (dcrd
/// `mergeScripts`); undefined behavior when the extracted metadata does
/// not match the script, matching dcrd.
///
/// NOTE: Only valid for version 0 scripts.
#[allow(clippy::too_many_arguments)] // Mirrors dcrd's signature.
fn merge_scripts(
    chain_params: &dyn AddressParamsV0,
    tx: &MsgTx,
    idx: usize,
    pk_script: &[u8],
    script_type: ScriptType,
    addresses: &[Address],
    sig_script: &[u8],
    prev_script: &[u8],
) -> Vec<u8> {
    const SCRIPT_VERSION: u16 = 0;
    match script_type {
        ScriptType::ScriptHash => {
            // Nothing to merge when either script is empty or fails to
            // parse.
            if sig_script.is_empty() || check_script_parses(SCRIPT_VERSION, sig_script).is_err() {
                return prev_script.to_vec();
            }
            if prev_script.is_empty() || check_script_parses(SCRIPT_VERSION, prev_script).is_err() {
                return sig_script.to_vec();
            }

            // Remove the last push in the script and recurse; assume the
            // final script is the correct one since it was just made and
            // is a pay-to-script-hash.
            let script = final_opcode_data(SCRIPT_VERSION, sig_script)
                .unwrap_or_default()
                .to_vec();

            // Determine the redeem script type, extract its addresses,
            // and merge.
            let (script_type, addresses) = stdscript::extract_addrs_v0(&script, chain_params);
            let merged_script = merge_scripts(
                chain_params,
                tx,
                idx,
                &script,
                script_type,
                &addresses,
                sig_script,
                prev_script,
            );

            // Reappend the redeem script and return the result.
            ScriptBuilder::new()
                .add_ops(&merged_script)
                .add_data(&script)
                .unchecked_script()
        }

        ScriptType::MultiSig => {
            let details = stdscript::extract_multi_sig_script_details_v0(pk_script, false);
            merge_multi_sig(
                tx,
                idx,
                addresses,
                details.required_sigs,
                pk_script,
                sig_script,
                prev_script,
            )
        }

        // Merging only makes sense for multisig and scripthash; everything
        // else has zero or one signature, so take the longest as correct
        // like the reference implementation.
        _ => {
            if sig_script.len() > prev_script.len() {
                sig_script.to_vec()
            } else {
                prev_script.to_vec()
            }
        }
    }
}

/// Sign output `idx` of the transaction to resolve the given public key
/// script (dcrd `SignTxOutput`): keys and redeem scripts are looked up via
/// the databases, and any previous partial signature script is merged in a
/// type-dependent manner.
///
/// NOTE: Only valid for version 0 scripts.
///
/// Like dcrd, this assumes `pk_script` is a well-formed transaction output
/// script. A script that classifies as a pubkey/pubkey-hash/script-hash
/// type but yields no extractable address (e.g. a structurally valid
/// pay-to-pubkey script whose key is not a valid curve point) will panic on
/// the internal `addresses[0]` access, matching dcrd's identical
/// unguarded indexing; callers must not pass untrusted scripts.
#[allow(clippy::too_many_arguments)] // Mirrors dcrd's signature.
pub fn sign_tx_output(
    chain_params: &dyn AddressParamsV0,
    tx: &MsgTx,
    idx: usize,
    pk_script: &[u8],
    hash_type: SigHashType,
    kdb: &mut dyn KeyDb,
    sdb: &mut dyn ScriptDb,
    previous_script: &[u8],
    is_treasury_enabled: bool,
) -> Result<Vec<u8>, SignError> {
    let (mut sig_script, script_type, addresses) = sign(
        chain_params,
        tx,
        idx,
        pk_script,
        hash_type,
        kdb,
        sdb,
        is_treasury_enabled,
    )?;

    let script_type = stake_sub_script_type(script_type, is_treasury_enabled);
    if script_type == ScriptType::ScriptHash {
        // The signature script is the redeem script; sign it and append
        // it as the final push.
        let (real_sig_script, _, _) = sign(
            chain_params,
            tx,
            idx,
            &sig_script,
            hash_type,
            kdb,
            sdb,
            is_treasury_enabled,
        )?;

        sig_script = ScriptBuilder::new()
            .add_ops(&real_sig_script)
            .add_data(&sig_script)
            .unchecked_script();
    }

    // Merge with any previous data.
    Ok(merge_scripts(
        chain_params,
        tx,
        idx,
        pk_script,
        script_type,
        &addresses,
        &sig_script,
        previous_script,
    ))
}

/// An input signature script authorizing a treasury spend transaction
/// (dcrd `TSpendSignatureScript`); the key must correspond to a Pi key
/// recognized by consensus.
pub fn tspend_signature_script(msg_tx: &MsgTx, priv_key: &[u8]) -> Result<Vec<u8>, SignError> {
    let hash = calc_signature_hash_checked(&[], SIG_HASH_ALL, msg_tx, 0)
        .map_err(|e| sign_error(format!("{e}")))?;

    let priv_key = secp_priv_key(priv_key)?;
    let sig = dcroxide_dcrec::secp256k1::schnorr::sign(&priv_key, &hash)
        .map_err(|e| sign_error(format!("cannot sign tx input: {e:?}")))?;
    let sig_bytes = sig.serialize();
    let pk_bytes = priv_key.public_key().serialize_compressed();

    ScriptBuilder::new()
        .add_data(&sig_bytes)
        .add_data(&pk_bytes)
        .add_op(OP_TSPEND)
        .script()
        .map_err(|e| sign_error(format!("{e}")))
}
