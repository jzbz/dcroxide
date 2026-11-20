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
//!
//! A lookup's own error comes back from [`sign_tx_output`] unchanged, as
//! dcrd returns a `KeyDB` or `ScriptDB` closure's error ([`SignError`]).
//! Where dcrd panics or recurses without end on what it is given, the
//! functions here return an error instead, at the point dcrd would fail;
//! [`sign_tx_output`] lists those inputs.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use dcroxide_wire::MsgTx;

use crate::builder::ScriptBuilder;
use crate::opcode_table::{OP_0, OP_TSPEND};
use crate::script::{check_script_parses, final_opcode_data};
use crate::sighash::{
    SIG_HASH_ALL, SIG_HASH_ANY_ONE_CAN_PAY, SIG_HASH_MASK, SIG_HASH_SINGLE, SigHashType,
    calc_signature_hash_checked,
};
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

/// The error a caller's [`KeyDb`] or [`ScriptDb`] hands back inside a
/// [`SignError`], unchanged.
///
/// Any `Error + Send + Sync` is accepted, as `std::io::Error` accepts
/// one.  The bound names no `UnwindSafe` or `RefUnwindSafe`, so that an
/// error holding an opaque `dyn Error + Send + Sync` of its own -- a
/// wallet's error usually does -- can be wrapped; the cost is that
/// [`SignError`] is neither `UnwindSafe` nor `RefUnwindSafe`.
pub type LookupError = Box<dyn core::error::Error + Send + Sync + 'static>;

/// A signing error.
///
/// dcrd's sign package returns plain `error` values of two origins, and
/// both survive here.  Its own errors are text with no kind type
/// (`errors.New`, `fmt.Errorf`), and [`SignError::new`] makes one.  An
/// error a `KeyDB` or `ScriptDB` lookup returns, dcrd's `SignTxOutput`
/// returns unchanged (`sign/sign.go:225-228` and the like), so that its
/// caller can still tell its own failures apart with `errors.Is` and
/// `errors.As`.  A lookup here does the same by returning
/// [`SignError::other`] around its own error, which [`sign_tx_output`]
/// passes back as it came and [`SignError::get_ref`] and
/// [`SignError::into_inner`] hand back for downcasting.
///
/// A third origin has no counterpart in dcrd: the error [`sign_tx_output`]
/// returns where dcrd panics or never returns (its documentation lists
/// them).  It is text, like dcrd's own errors, with dcroxide's wording.
///
/// `SignError` is `Send` and `Sync` but, because it can carry any
/// [`LookupError`], neither `Clone`, `PartialEq`, `UnwindSafe` nor
/// `RefUnwindSafe`; compare errors by their text or by downcasting, and
/// wrap a borrow in `AssertUnwindSafe` to move it into `catch_unwind`.
#[derive(Debug)]
pub struct SignError(Repr);

#[derive(Debug)]
enum Repr {
    /// An error of the sign package's own, by its text.
    Message(String),
    /// dcroxide's error where dcrd panics or recurses without end.
    Unsupported(String),
    /// A caller's error, from a lookup.
    Other(LookupError),
}

impl SignError {
    /// A text error, as dcrd's `errors.New` makes one.
    pub fn new(msg: impl Into<String>) -> SignError {
        SignError(Repr::Message(msg.into()))
    }

    /// The caller's own `error`, for a [`KeyDb`] or [`ScriptDb`] lookup to
    /// return: [`sign_tx_output`] passes it back unchanged, as dcrd returns
    /// a lookup closure's error unchanged.  Its text is the error's own,
    /// and [`SignError::get_ref`] and [`SignError::into_inner`] return the
    /// value itself.
    pub fn other<E>(error: E) -> SignError
    where
        E: Into<LookupError>,
    {
        SignError(Repr::Other(error.into()))
    }

    /// The caller's error inside, when this came from
    /// [`SignError::other`]; `None` for an error of the sign package's
    /// own.
    pub fn get_ref(&self) -> Option<&(dyn core::error::Error + Send + Sync + 'static)> {
        match &self.0 {
            Repr::Other(error) => Some(&**error),
            Repr::Message(_) | Repr::Unsupported(_) => None,
        }
    }

    /// The caller's error itself, when this came from
    /// [`SignError::other`]; `None` for an error of the sign package's
    /// own.
    pub fn into_inner(self) -> Option<LookupError> {
        match self.0 {
            Repr::Other(error) => Some(error),
            Repr::Message(_) | Repr::Unsupported(_) => None,
        }
    }

    /// dcroxide's error where dcrd would panic or recurse without end.
    fn unsupported(msg: impl Into<String>) -> SignError {
        SignError(Repr::Unsupported(msg.into()))
    }

    /// Whether dcrd panics or recurses without end where this was
    /// returned: such an error is passed up from the places where dcrd
    /// skips a failure and carries on, because dcrd would not carry on.
    fn is_unsupported(&self) -> bool {
        matches!(self.0, Repr::Unsupported(_))
    }
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Repr::Message(msg) | Repr::Unsupported(msg) => f.write_str(msg),
            Repr::Other(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl core::error::Error for SignError {
    /// The caller's error's own source, when this wraps one: the wrapper
    /// is transparent, its text the caller's error's text, as
    /// `std::io::Error` treats an error it carries.
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match &self.0 {
            Repr::Other(error) => error.source(),
            Repr::Message(_) | Repr::Unsupported(_) => None,
        }
    }
}

fn sign_error(msg: impl Into<String>) -> SignError {
    SignError::new(msg)
}

/// The text [`sign_tx_output`] returns for a pay-to-pubkey script whose
/// public key does not parse, where dcrd indexes the empty address list
/// and panics (QK-0034).
const INVALID_PUBKEY_SCRIPT: &str =
    "cannot sign a pay-to-pubkey script whose public key is not valid";

/// The text [`sign_tx_output`] returns where dcrd's signature-script merge
/// recurses until the stack overflows (QK-0036).
const NESTED_SCRIPT_HASH_MERGE: &str = "cannot merge signature scripts of a \
     pay-to-script-hash input whose redeem script is itself pay-to-script-hash";

/// Access to private keys for addresses (dcrd `KeyDB`): returns the
/// serialized private key, its signature type, and whether the associated
/// public key should be serialized compressed.
///
/// A lookup that fails returns its own error inside [`SignError::other`]
/// to have [`sign_tx_output`] hand it back unchanged, as dcrd's
/// `SignTxOutput` returns a `KeyDB`'s error, so that a caller can tell a
/// key it does not hold from its own failures by downcasting
/// [`SignError::get_ref`].  Where dcrd skips a failed lookup and carries
/// on, a multisig script's keys, the error is dropped here too.
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
///
/// As with [`KeyDb`], a lookup's own error returned inside
/// [`SignError::other`] comes back from [`sign_tx_output`] unchanged.
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

/// The signature hash the sign package signs and merges against (dcrd
/// `txscript.CalcSignatureHash`, `sighash.go:451-458`), with an error
/// where dcrd panics.
///
/// dcrd slices `tx.TxIn[idx : idx+1]` under `SigHashAnyOneCanPay`
/// (`sighash.go:248-252`) with no check of `idx`, after checking only
/// that the script parses and, for `SigHashSingle`, that an output sits at
/// `idx` (`:236-241`).  An index past the inputs then panics, or, for a
/// transaction whose input slice has spare capacity, reads past its end.
/// That is the one place the hash can fail where dcrd has no defined
/// behaviour, so it is answered here, after dcrd's two errors, with an
/// error that callers which skip a failed hash pass up instead.  Without
/// `SigHashAnyOneCanPay` an index past the inputs is defined in dcrd: the
/// hash commits the script nowhere and covers the zero-padded witness
/// buffer, and [`calc_signature_hash_checked`] reproduces that.
fn signature_hash(
    script: &[u8],
    hash_type: SigHashType,
    tx: &MsgTx,
    idx: usize,
) -> Result<[u8; 32], SignError> {
    const SCRIPT_VERSION: u16 = 0;
    let anyone_can_pay = hash_type.0 & SIG_HASH_ANY_ONE_CAN_PAY.0 != 0;
    let single_without_output =
        hash_type.0 & SIG_HASH_MASK == SIG_HASH_SINGLE.0 && idx >= tx.tx_out.len();
    if anyone_can_pay && idx >= tx.tx_in.len() && !single_without_output {
        check_script_parses(SCRIPT_VERSION, script).map_err(|e| sign_error(format!("{e}")))?;
        return Err(SignError::unsupported(format!(
            "cannot sign input {idx} of a transaction with {} inputs: the input index is out \
             of range",
            tx.tx_in.len()
        )));
    }
    calc_signature_hash_checked(script, hash_type, tx, idx).map_err(|e| sign_error(format!("{e}")))
}

/// The serialized signature for input `idx` of the transaction with the
/// hash type appended (dcrd `RawTxInSignature`).
///
/// NOTE: Only valid for version 0 scripts.
///
/// # Errors
///
/// dcrd's errors: the signature hash's (a script that does not parse, or
/// `SigHashSingle` with no output at `idx`) and the key's.  Where dcrd
/// panics, for `idx` past the inputs under `SigHashAnyOneCanPay`, an error
/// of dcroxide's own (QK-0035).
pub fn raw_tx_in_signature(
    tx: &MsgTx,
    idx: usize,
    sub_script: &[u8],
    hash_type: SigHashType,
    key: &[u8],
    sig_type: SignatureType,
) -> Result<Vec<u8>, SignError> {
    let hash = signature_hash(sub_script, hash_type, tx, idx)?;

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
/// fulfilled. Failing to sign any output is not an error, except where
/// dcrd panics rather than fails (see [`signature_hash`]): that error is
/// returned, as dcrd would not go on to the next key.
fn sign_multi_sig(
    tx: &MsgTx,
    idx: usize,
    sub_script: &[u8],
    hash_type: SigHashType,
    addresses: &[Address],
    n_required: u16,
    kdb: &mut dyn KeyDb,
) -> Result<(Vec<u8>, bool), SignError> {
    // No need to add a dummy in Decred.
    let mut builder = ScriptBuilder::new();
    let mut signed: u16 = 0;
    for addr in addresses {
        let Ok((key, sig_type, _)) = kdb.get_key(addr) else {
            continue;
        };
        let sig = match raw_tx_in_signature(tx, idx, sub_script, hash_type, &key, sig_type) {
            Ok(sig) => sig,
            Err(e) if e.is_unsupported() => return Err(e),
            Err(_) => continue,
        };

        builder = builder.add_data(&sig);
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "one increment per address, and a standard multisig script names at most \
                      16 keys (a small-int count), so signed <= 16"
        )]
        {
            signed += 1;
        }
        if signed == n_required {
            break;
        }
    }

    Ok((builder.unchecked_script(), signed == n_required))
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

/// The first address extracted from a script, which dcrd's `sign` and
/// `handleStakeOutSign` index as `addresses[0]` without a check
/// (`sign/sign.go:189`, `:201`, `:225`, `:240`, `:255`, `:270`, `:284`).
///
/// Only a pay-to-pubkey script can yield none: `stdscript` classifies it
/// by its shape and drops a key that does not parse, while every other
/// class indexed holds a hash, which always makes an address.  dcrd then
/// panics with an index out of range; this returns
/// [`INVALID_PUBKEY_SCRIPT`] before any lookup, where the panic falls
/// (QK-0034).  For the other classes the error cannot be reached, and its
/// text says only what happened.
fn first_address(addresses: &[Address], script_type: ScriptType) -> Result<&Address, SignError> {
    use ScriptType::*;
    addresses.first().ok_or_else(|| match script_type {
        PubKeyEcdsaSecp256k1 | PubKeyEd25519 | PubKeySchnorrSecp256k1 => {
            SignError::unsupported(INVALID_PUBKEY_SCRIPT)
        }
        other => SignError::unsupported(format!(
            "cannot sign a {} script that yields no address",
            other.name()
        )),
    })
}

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
            let (key, sig_type, compressed) =
                kdb.get_key(first_address(&addresses, script_type)?)?;
            let script =
                signature_script(tx, idx, sub_script, hash_type, &key, sig_type, compressed)?;
            Ok((script, script_type, addresses))
        }
        ScriptType::ScriptHash => {
            let script = sdb.get_script(first_address(&addresses, script_type)?)?;
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
            let (key, sig_type, _) = kdb.get_key(first_address(&addresses, script_type)?)?;
            let script = p2pk_signature_script(tx, idx, sub_script, hash_type, &key, sig_type)?;
            Ok((script, script_type, addresses))
        }

        PubKeyHashEcdsaSecp256k1 | PubKeyHashEd25519 | PubKeyHashSchnorrSecp256k1 => {
            let (key, sig_type, compressed) =
                kdb.get_key(first_address(&addresses, script_type)?)?;
            let script =
                signature_script(tx, idx, sub_script, hash_type, &key, sig_type, compressed)?;
            Ok((script, script_type, addresses))
        }

        ScriptHash => {
            let script = sdb.get_script(first_address(&addresses, script_type)?)?;
            Ok((script, script_type, addresses))
        }

        MultiSig => {
            let details = stdscript::extract_multi_sig_script_details_v0(sub_script, false);
            let threshold = details.required_sigs;
            let (script, _) =
                sign_multi_sig(tx, idx, sub_script, hash_type, &addresses, threshold, kdb)?;
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
) -> Result<Vec<u8>, SignError> {
    // Nothing to merge when either script is empty.
    if sig_script.is_empty() {
        return Ok(prev_script.to_vec());
    }
    if prev_script.is_empty() {
        return Ok(sig_script.to_vec());
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
        return Ok(prev_script.to_vec());
    }
    if extract_sigs(prev_script, &mut possible_sigs).is_err() {
        return Ok(sig_script.to_vec());
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
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "sig is non-empty (checked above), so sig.len() - 1 >= 0"
        )]
        let t_sig = &sig[..sig.len() - 1];
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "sig is non-empty (checked above), so sig.len() - 1 >= 0"
        )]
        let hash_type = SigHashType(sig[sig.len() - 1]);

        let Ok(p_sig) = dcroxide_dcrec::secp256k1::ecdsa::parse_der_signature(t_sig) else {
            continue;
        };

        // Hash types may vary between signatures, so compute per
        // signature.  dcrd skips a signature whose hash fails, but where
        // it panics instead -- a signature carrying SigHashAnyOneCanPay
        // for an index past the inputs, whatever hash type the caller
        // signs with -- it does not carry on, and neither does this.
        let hash = match signature_hash(pk_script, hash_type, tx, idx) {
            Ok(hash) => hash,
            Err(e) if e.is_unsupported() => return Err(e),
            Err(_) => continue,
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
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "one increment per address, and a standard multisig script names at most \
                      16 keys (a small-int count), so done_sigs <= 16"
        )]
        {
            done_sigs += 1;
        }
        if done_sigs == n_required {
            break;
        }
    }

    // Padding for missing ones.
    for _ in done_sigs..n_required {
        builder = builder.add_op(OP_0);
    }

    Ok(builder.unchecked_script())
}

/// Merge two partial solutions for a public key script (dcrd
/// `mergeScripts`); undefined behavior when the extracted metadata does
/// not match the script, matching dcrd.
///
/// NOTE: Only valid for version 0 scripts.
///
/// dcrd recurses once for a pay-to-script-hash output, on the redeem
/// script it takes from the new signature script's final push, with the
/// same two signature scripts (`sign/sign.go:507-540`).  When that push
/// is itself a plain pay-to-script-hash script, the recursion takes the
/// same push again with the same arguments and never ends, until Go's
/// runtime kills the process with a stack overflow.  The recursion is
/// otherwise one level deep, so this returns [`NESTED_SCRIPT_HASH_MERGE`]
/// exactly where dcrd would recurse a second time (QK-0036); without it
/// the port would overflow its own stack and abort.  The other errors are
/// [`signature_hash`]'s, passed up from [`merge_multi_sig`].
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
) -> Result<Vec<u8>, SignError> {
    const SCRIPT_VERSION: u16 = 0;
    match script_type {
        ScriptType::ScriptHash => {
            // Nothing to merge when either script is empty or fails to
            // parse.
            if sig_script.is_empty() || check_script_parses(SCRIPT_VERSION, sig_script).is_err() {
                return Ok(prev_script.to_vec());
            }
            if prev_script.is_empty() || check_script_parses(SCRIPT_VERSION, prev_script).is_err() {
                return Ok(sig_script.to_vec());
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
            if script_type == ScriptType::ScriptHash {
                // dcrd's next call would be this one again, forever.
                return Err(SignError::unsupported(NESTED_SCRIPT_HASH_MERGE));
            }
            let merged_script = merge_scripts(
                chain_params,
                tx,
                idx,
                &script,
                script_type,
                &addresses,
                sig_script,
                prev_script,
            )?;

            // Reappend the redeem script and return the result.
            Ok(ScriptBuilder::new()
                .add_ops(&merged_script)
                .add_data(&script)
                .unchecked_script())
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
        _ => Ok(if sig_script.len() > prev_script.len() {
            sig_script.to_vec()
        } else {
            prev_script.to_vec()
        }),
    }
}

/// Sign output `idx` of the transaction to resolve the given public key
/// script (dcrd `SignTxOutput`): keys and redeem scripts are looked up via
/// the databases, and any previous partial signature script is merged in a
/// type-dependent manner.
///
/// NOTE: Only valid for version 0 scripts.
///
/// # Errors
///
/// dcrd's errors, with dcrd's texts where dcrd makes them: an error a
/// lookup returns, unchanged ([`SignError::other`]); `can't sign NULLDATA
/// transactions`, `can't sign unknown transactions` and `unknown sub
/// script type for stake output to sign`; and the signing errors of
/// [`raw_tx_in_signature`].
///
/// Where dcrd has no defined behaviour, because it panics or recurses
/// until its stack overflows, an error of dcroxide's own at the point
/// dcrd would fail, so that every lookup dcrd makes before it is made
/// here too and none after (PARITY.md, *SignTxOutput preconditions*):
///
/// * `cannot sign a pay-to-pubkey script whose public key is not valid`
///   for a pay-to-pubkey script, or the redeem script of a
///   pay-to-script-hash output, whose key does not parse, which dcrd
///   classifies by its shape and then indexes its empty address list for
///   (QK-0034);
/// * `cannot sign input <idx> of a transaction with <n> inputs: the input
///   index is out of range` where a signature hash is computed for `idx`
///   past the inputs under `SigHashAnyOneCanPay`, whether in the caller's
///   hash type or in that of a signature found in `previous_script` while
///   merging multisig signatures, which dcrd slices out of range for
///   (QK-0035).  Without `SigHashAnyOneCanPay` such an index is defined
///   in dcrd and signs as dcrd does, over a hash that commits the script
///   to no input;
/// * `cannot merge signature scripts of a pay-to-script-hash input whose
///   redeem script is itself pay-to-script-hash` where the merge with
///   `previous_script` would recurse without end (QK-0036).
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
    merge_scripts(
        chain_params,
        tx,
        idx,
        pk_script,
        script_type,
        &addresses,
        &sig_script,
        previous_script,
    )
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
