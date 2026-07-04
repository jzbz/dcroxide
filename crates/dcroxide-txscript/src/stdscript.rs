// SPDX-License-Identifier: ISC
//! Standard script classification and extraction (dcrd
//! `txscript/v4/stdscript`). Version 0 is the only supported script
//! version; dispatchers return non-standard/false/0 for all others,
//! matching dcrd.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::builder::ScriptBuilder;
use crate::opcode_table::{
    OP_0, OP_16, OP_CHECKMULTISIG, OP_CHECKSIG, OP_CHECKSIGALT, OP_DATA_20, OP_DATA_32, OP_DATA_33,
    OP_DATA_65, OP_DUP, OP_EQUALVERIFY, OP_HASH160, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4,
    OP_RETURN, OP_SSGEN, OP_SSRTX, OP_SSTX, OP_SSTXCHANGE, OP_TADD, OP_TGEN,
};
use crate::script::{as_small_int, extract_script_hash, is_small_int};
use crate::scriptnum::{CLTV_MAX_SCRIPT_NUM_LEN, MATH_OP_CODE_MAX_SCRIPT_NUM_LEN, make_script_num};
use crate::stdaddr::{self, Address, AddressParamsV0};
use crate::tokenizer::ScriptTokenizer;
use crate::{MAX_PUB_KEYS_PER_MULTI_SIG, is_strict_compressed_pub_key_encoding};

/// The maximum number of bytes in pushed data for a standard version 0
/// provably pruneable nulldata script (dcrd `MaxDataCarrierSizeV0`).
pub const MAX_DATA_CARRIER_SIZE_V0: usize = 256;

/// A kind of stdscript error (dcrd stdscript `ErrorKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)] // Kinds mirror dcrd's documented ErrorKind constants 1:1.
pub enum StdScriptErrorKind {
    UnsupportedScriptVersion,
    NegativeRequiredSigs,
    TooManyRequiredSigs,
    PubKeyType,
    TooMuchNullData,
}

impl StdScriptErrorKind {
    /// The dcrd `ErrorKind` constant name.
    pub fn kind_name(self) -> &'static str {
        use StdScriptErrorKind::*;
        match self {
            UnsupportedScriptVersion => "ErrUnsupportedScriptVersion",
            NegativeRequiredSigs => "ErrNegativeRequiredSigs",
            TooManyRequiredSigs => "ErrTooManyRequiredSigs",
            PubKeyType => "ErrPubKeyType",
            TooMuchNullData => "ErrTooMuchNullData",
        }
    }
}

/// A stdscript error (dcrd stdscript `Error`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StdScriptError {
    /// The kind of error.
    pub kind: StdScriptErrorKind,
    /// Human-readable description.
    pub description: String,
}

impl fmt::Display for StdScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.description)
    }
}

impl core::error::Error for StdScriptError {}

fn make_error(kind: StdScriptErrorKind, description: impl Into<String>) -> StdScriptError {
    StdScriptError {
        kind,
        description: description.into(),
    }
}

/// The type of a known standard script (dcrd `ScriptType`); everything
/// else is non-standard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(missing_docs)] // Variants mirror dcrd's documented ST* constants 1:1.
pub enum ScriptType {
    NonStandard = 0,
    PubKeyEcdsaSecp256k1,
    PubKeyEd25519,
    PubKeySchnorrSecp256k1,
    PubKeyHashEcdsaSecp256k1,
    PubKeyHashEd25519,
    PubKeyHashSchnorrSecp256k1,
    ScriptHash,
    MultiSig,
    NullData,
    StakeSubmissionPubKeyHash,
    StakeSubmissionScriptHash,
    StakeGenPubKeyHash,
    StakeGenScriptHash,
    StakeRevocationPubKeyHash,
    StakeRevocationScriptHash,
    StakeChangePubKeyHash,
    StakeChangeScriptHash,
    TreasuryAdd,
    TreasuryGenPubKeyHash,
    TreasuryGenScriptHash,
}

impl ScriptType {
    /// The human-readable name dcrd's `ScriptType.String` produces.
    pub fn name(self) -> &'static str {
        use ScriptType::*;
        match self {
            NonStandard => "nonstandard",
            PubKeyEcdsaSecp256k1 => "pubkey",
            PubKeyEd25519 => "pubkey-ed25519",
            PubKeySchnorrSecp256k1 => "pubkey-schnorr-secp256k1",
            PubKeyHashEcdsaSecp256k1 => "pubkeyhash",
            PubKeyHashEd25519 => "pubkeyhash-ed25519",
            PubKeyHashSchnorrSecp256k1 => "pubkeyhash-schnorr-secp256k1",
            ScriptHash => "scripthash",
            MultiSig => "multisig",
            NullData => "nulldata",
            StakeSubmissionPubKeyHash => "stakesubmission-pubkeyhash",
            StakeSubmissionScriptHash => "stakesubmission-scripthash",
            StakeGenPubKeyHash => "stakegen-pubkeyhash",
            StakeGenScriptHash => "stakegen-scripthash",
            StakeRevocationPubKeyHash => "stakerevoke-pubkeyhash",
            StakeRevocationScriptHash => "stakerevoke-scripthash",
            StakeChangePubKeyHash => "stakechange-pubkeyhash",
            StakeChangeScriptHash => "stakechange-scripthash",
            TreasuryAdd => "treasuryadd",
            TreasuryGenPubKeyHash => "treasurygen-pubkeyhash",
            TreasuryGenScriptHash => "treasurygen-scripthash",
        }
    }
}

impl fmt::Display for ScriptType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Extract a compressed public key from a standard version 0
/// pay-to-compressed-secp256k1-pubkey script (dcrd
/// `ExtractCompressedPubKeyV0`).
pub fn extract_compressed_pub_key_v0(script: &[u8]) -> Option<&[u8]> {
    // OP_DATA_33 <33-byte compressed pubkey> OP_CHECKSIG
    if script.len() == 35
        && script[34] == OP_CHECKSIG
        && script[0] == OP_DATA_33
        && (script[1] == 0x02 || script[1] == 0x03)
    {
        return Some(&script[1..34]);
    }
    None
}

/// Extract an uncompressed public key from a standard version 0
/// pay-to-uncompressed-secp256k1-pubkey script (dcrd
/// `ExtractUncompressedPubKeyV0`).
pub fn extract_uncompressed_pub_key_v0(script: &[u8]) -> Option<&[u8]> {
    // OP_DATA_65 <65-byte uncompressed pubkey> OP_CHECKSIG
    if script.len() == 67
        && script[66] == OP_CHECKSIG
        && script[0] == OP_DATA_65
        && script[1] == 0x04
    {
        return Some(&script[1..66]);
    }
    None
}

/// Extract either form of secp256k1 public key from a standard version 0
/// pay-to-pubkey script (dcrd `ExtractPubKeyV0`).
pub fn extract_pub_key_v0(script: &[u8]) -> Option<&[u8]> {
    extract_compressed_pub_key_v0(script).or_else(|| extract_uncompressed_pub_key_v0(script))
}

/// Whether the script is a standard version 0 pay-to-secp256k1-pubkey
/// script of either form (dcrd `IsPubKeyScriptV0`).
pub fn is_pub_key_script_v0(script: &[u8]) -> bool {
    extract_pub_key_v0(script).is_some()
}

/// Extract the public key and signature type from a standard version 0
/// pay-to-alt-pubkey script (dcrd `ExtractPubKeyAltDetailsV0`); the
/// signature type is 1 for Ed25519 and 2 for Schnorr-secp256k1.
pub fn extract_pub_key_alt_details_v0(script: &[u8]) -> Option<(&[u8], u8)> {
    // PUBKEY SIGTYPE OP_CHECKSIGALT with either:
    //  OP_DATA_32 <32-byte pubkey> <ed25519 sigtype> OP_CHECKSIGALT
    //  OP_DATA_33 <33-byte pubkey> <schnorr+secp sigtype> OP_CHECKSIGALT
    if script.len() < 3 || script[script.len() - 1] != OP_CHECKSIGALT {
        return None;
    }

    if script.len() == 35
        && script[0] == OP_DATA_32
        && is_small_int(script[33])
        && as_small_int(script[33]) == 1
    {
        return Some((&script[1..33], 1));
    }

    if script.len() == 36
        && script[0] == OP_DATA_33
        && is_small_int(script[34])
        && as_small_int(script[34]) == 2
        && is_strict_compressed_pub_key_encoding(&script[1..34])
    {
        return Some((&script[1..34], 2));
    }

    None
}

/// Extract the public key from a standard version 0
/// pay-to-ed25519-pubkey script (dcrd `ExtractPubKeyEd25519V0`).
pub fn extract_pub_key_ed25519_v0(script: &[u8]) -> Option<&[u8]> {
    match extract_pub_key_alt_details_v0(script) {
        Some((pk, 1)) => Some(pk),
        _ => None,
    }
}

/// Whether the script is a standard version 0 pay-to-ed25519-pubkey script
/// (dcrd `IsPubKeyEd25519ScriptV0`).
pub fn is_pub_key_ed25519_script_v0(script: &[u8]) -> bool {
    extract_pub_key_ed25519_v0(script).is_some()
}

/// Extract the public key from a standard version 0
/// pay-to-schnorr-secp256k1-pubkey script (dcrd
/// `ExtractPubKeySchnorrSecp256k1V0`).
pub fn extract_pub_key_schnorr_secp256k1_v0(script: &[u8]) -> Option<&[u8]> {
    match extract_pub_key_alt_details_v0(script) {
        Some((pk, 2)) => Some(pk),
        _ => None,
    }
}

/// Whether the script is a standard version 0
/// pay-to-schnorr-secp256k1-pubkey script (dcrd
/// `IsPubKeySchnorrSecp256k1ScriptV0`).
pub fn is_pub_key_schnorr_secp256k1_script_v0(script: &[u8]) -> bool {
    extract_pub_key_schnorr_secp256k1_v0(script).is_some()
}

/// Extract the public key hash from a standard version 0
/// pay-to-pubkey-hash-ecdsa-secp256k1 script (dcrd `ExtractPubKeyHashV0`).
pub fn extract_pub_key_hash_v0(script: &[u8]) -> Option<&[u8]> {
    // OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
    if script.len() == 25
        && script[0] == OP_DUP
        && script[1] == OP_HASH160
        && script[2] == OP_DATA_20
        && script[23] == OP_EQUALVERIFY
        && script[24] == OP_CHECKSIG
    {
        return Some(&script[3..23]);
    }
    None
}

/// Whether the script is a standard version 0 P2PKH-ecdsa-secp256k1 script
/// (dcrd `IsPubKeyHashScriptV0`).
pub fn is_pub_key_hash_script_v0(script: &[u8]) -> bool {
    extract_pub_key_hash_v0(script).is_some()
}

/// Whether the opcode pushes a standard alt signature type (dcrd
/// `IsStandardAltSignatureTypeV0`).
pub fn is_standard_alt_signature_type_v0(op: u8) -> bool {
    if !is_small_int(op) {
        return false;
    }
    let sig_type = as_small_int(op);
    sig_type == 1 || sig_type == 2
}

/// Extract the public key hash and signature type from a standard version
/// 0 pay-to-alt-pubkey-hash script (dcrd
/// `ExtractPubKeyHashAltDetailsV0`).
pub fn extract_pub_key_hash_alt_details_v0(script: &[u8]) -> Option<(&[u8], u8)> {
    // DUP HASH160 <20-byte hash> EQUALVERIFY SIGTYPE CHECKSIGALT
    if script.len() == 26
        && script[0] == OP_DUP
        && script[1] == OP_HASH160
        && script[2] == OP_DATA_20
        && script[23] == OP_EQUALVERIFY
        && is_standard_alt_signature_type_v0(script[24])
        && script[25] == OP_CHECKSIGALT
    {
        return Some((&script[3..23], as_small_int(script[24]) as u8));
    }
    None
}

/// Extract the public key hash from a standard version 0 P2PKH-ed25519
/// script (dcrd `ExtractPubKeyHashEd25519V0`).
pub fn extract_pub_key_hash_ed25519_v0(script: &[u8]) -> Option<&[u8]> {
    match extract_pub_key_hash_alt_details_v0(script) {
        Some((hash, 1)) => Some(hash),
        _ => None,
    }
}

/// Whether the script is a standard version 0 P2PKH-ed25519 script (dcrd
/// `IsPubKeyHashEd25519ScriptV0`).
pub fn is_pub_key_hash_ed25519_script_v0(script: &[u8]) -> bool {
    extract_pub_key_hash_ed25519_v0(script).is_some()
}

/// Extract the public key hash from a standard version 0
/// P2PKH-schnorr-secp256k1 script (dcrd
/// `ExtractPubKeyHashSchnorrSecp256k1V0`).
pub fn extract_pub_key_hash_schnorr_secp256k1_v0(script: &[u8]) -> Option<&[u8]> {
    match extract_pub_key_hash_alt_details_v0(script) {
        Some((hash, 2)) => Some(hash),
        _ => None,
    }
}

/// Whether the script is a standard version 0 P2PKH-schnorr-secp256k1
/// script (dcrd `IsPubKeyHashSchnorrSecp256k1ScriptV0`).
pub fn is_pub_key_hash_schnorr_secp256k1_script_v0(script: &[u8]) -> bool {
    extract_pub_key_hash_schnorr_secp256k1_v0(script).is_some()
}

/// Extract the script hash from a standard version 0 P2SH script (dcrd
/// `ExtractScriptHashV0`, which defers to consensus code).
pub fn extract_script_hash_v0(script: &[u8]) -> Option<&[u8]> {
    extract_script_hash(script)
}

/// Whether the script is a standard version 0 P2SH script (dcrd
/// `IsScriptHashScriptV0`).
pub fn is_script_hash_script_v0(script: &[u8]) -> bool {
    extract_script_hash_v0(script).is_some()
}

/// Details extracted from a standard version 0 ECDSA multisig script (dcrd
/// `MultiSigDetailsV0`).
#[derive(Debug, Clone, Default)]
pub struct MultiSigDetailsV0 {
    /// The number of required signatures.
    pub required_sigs: u16,
    /// The number of public keys.
    pub num_pub_keys: u16,
    /// The raw public keys when extraction was requested.
    pub pub_keys: Vec<Vec<u8>>,
    /// Whether the script is a valid multisig script.
    pub valid: bool,
}

/// Extract details from a standard version 0 ECDSA multisig script (dcrd
/// `ExtractMultiSigScriptDetailsV0`); `extract_pub_keys` controls whether
/// the pubkeys themselves are collected.
pub fn extract_multi_sig_script_details_v0(
    script: &[u8],
    extract_pub_keys: bool,
) -> MultiSigDetailsV0 {
    // REQ_SIGS PUBKEY PUBKEY PUBKEY ... NUM_PUBKEYS OP_CHECKMULTISIG
    if script.len() < 3 || script[script.len() - 1] != OP_CHECKMULTISIG {
        return MultiSigDetailsV0::default();
    }

    // The first opcode must be a small integer specifying the number of
    // signatures required.
    const SCRIPT_VERSION: u16 = 0;
    let mut tokenizer = ScriptTokenizer::new(SCRIPT_VERSION, script);
    if !tokenizer.next() || !is_small_int(tokenizer.opcode()) {
        return MultiSigDetailsV0::default();
    }
    let required_sigs = as_small_int(tokenizer.opcode());

    // There must be at least one required signature.
    if required_sigs == 0 {
        return MultiSigDetailsV0::default();
    }

    // The next series of opcodes must either push public keys or be a
    // small integer specifying the number of public keys; the maximum is
    // intentionally restricted to what a small integer can represent.
    let mut num_pub_keys = 0usize;
    let mut pub_keys = Vec::with_capacity(if extract_pub_keys {
        MAX_PUB_KEYS_PER_MULTI_SIG
    } else {
        0
    });
    while tokenizer.next() {
        let data = tokenizer.data();
        if !is_strict_compressed_pub_key_encoding(data) {
            break;
        }
        num_pub_keys += 1;
        if extract_pub_keys {
            pub_keys.push(data.to_vec());
        }
    }
    if tokenizer.done() {
        return MultiSigDetailsV0::default();
    }

    // The next opcode must be a small integer specifying the number of
    // public keys required.
    let op = tokenizer.opcode();
    if !is_small_int(op) || as_small_int(op) != num_pub_keys {
        return MultiSigDetailsV0::default();
    }

    // There must be at least as many pubkeys as required signatures.
    if num_pub_keys < required_sigs {
        return MultiSigDetailsV0::default();
    }

    // There must only be a single opcode left unparsed, which will be
    // OP_CHECKMULTISIG per the check above.
    if script.len() - tokenizer.byte_index() != 1 {
        return MultiSigDetailsV0::default();
    }

    MultiSigDetailsV0 {
        required_sigs: required_sigs as u16,
        num_pub_keys: num_pub_keys as u16,
        pub_keys,
        valid: true,
    }
}

/// Whether the script is a standard version 0 ECDSA multisig script (dcrd
/// `IsMultiSigScriptV0`).
pub fn is_multi_sig_script_v0(script: &[u8]) -> bool {
    extract_multi_sig_script_details_v0(script, false).valid
}

/// The data associated with the final opcode, or `None` for parse failures
/// or when the final opcode carries no data (dcrd `finalOpcodeDataV0`,
/// whose nil result covers both).
fn final_opcode_data_v0(script: &[u8]) -> Option<Vec<u8>> {
    if script.is_empty() {
        return None;
    }

    let mut data: Option<Vec<u8>> = None;
    const SCRIPT_VERSION: u16 = 0;
    let mut tokenizer = ScriptTokenizer::new(SCRIPT_VERSION, script);
    while tokenizer.next() {
        // Mirror Go's nil-vs-data distinction: only data-carrying opcodes
        // (OP_DATA_1..OP_PUSHDATA4) produce a non-nil buffer.
        data = if (0x01..=0x4e).contains(&tokenizer.opcode()) {
            Some(tokenizer.data().to_vec())
        } else {
            None
        };
    }
    if tokenizer.err().is_some() {
        return None;
    }
    data
}

/// Whether the script appears to be a signature script consisting of a
/// P2SH multisig redeem script (dcrd `IsMultiSigSigScriptV0`); a fast best
/// effort guess.
pub fn is_multi_sig_sig_script_v0(script: &[u8]) -> bool {
    // Must end with OP_CHECKMULTISIG (inside the pushed redeem script) and
    // have room for at least a push before it.
    if script.len() < 4 || script[script.len() - 1] != OP_CHECKMULTISIG {
        return false;
    }

    let Some(possible_redeem_script) = final_opcode_data_v0(script) else {
        return false;
    };

    is_multi_sig_script_v0(&possible_redeem_script)
}

/// Extract a multisig redeem script from a version 0 P2SH-redeeming input
/// (dcrd `MultiSigRedeemScriptFromScriptSigV0`); results are undefined for
/// other script types.
pub fn multi_sig_redeem_script_from_script_sig_v0(script: &[u8]) -> Option<Vec<u8>> {
    // The redeem script is always the last item on the sig script's stack.
    final_opcode_data_v0(script)
}

/// Whether the version 0 opcode/data pair is a push using the smallest
/// possible instruction (dcrd stdscript `isCanonicalPushV0`; note this
/// differs from the consensus variant by returning false for non-push
/// opcodes).
fn is_canonical_push_v0(opcode: u8, data: &[u8]) -> bool {
    let data_len = data.len();
    if opcode > OP_16 {
        return false;
    }
    if opcode < OP_PUSHDATA1 && opcode > OP_0 && data_len == 1 && data[0] <= 16 {
        return false;
    }
    if opcode == OP_PUSHDATA1 && data_len < usize::from(OP_PUSHDATA1) {
        return false;
    }
    if opcode == OP_PUSHDATA2 && data_len <= 0xff {
        return false;
    }
    if opcode == OP_PUSHDATA4 && data_len <= 0xffff {
        return false;
    }
    true
}

/// Whether the script is a standard version 0 null data script (dcrd
/// `IsNullDataScriptV0`).
pub fn is_null_data_script_v0(script: &[u8]) -> bool {
    // OP_RETURN, optionally followed by one canonical data push of up to
    // MaxDataCarrierSizeV0 bytes.
    if script.is_empty() || script[0] != OP_RETURN {
        return false;
    }
    if script.len() == 1 {
        return true;
    }

    const SCRIPT_VERSION: u16 = 0;
    let mut tokenizer = ScriptTokenizer::new(SCRIPT_VERSION, &script[1..]);
    tokenizer.next()
        && tokenizer.done()
        && tokenizer.err().is_none()
        && tokenizer.data().len() <= MAX_DATA_CARRIER_SIZE_V0
        && is_canonical_push_v0(tokenizer.opcode(), tokenizer.data())
}

/// Extract the pubkey hash from a stake-tagged P2PKH script with the given
/// tag (dcrd `extractStakePubKeyHashV0`).
fn extract_stake_pub_key_hash_v0_tagged(script: &[u8], stake_opcode: u8) -> Option<&[u8]> {
    if script.is_empty() || script[0] != stake_opcode {
        return None;
    }
    extract_pub_key_hash_v0(&script[1..])
}

/// Extract the script hash from a stake-tagged P2SH script with the given
/// tag (dcrd `extractStakeScriptHashV0`).
fn extract_stake_script_hash_v0_tagged(script: &[u8], stake_opcode: u8) -> Option<&[u8]> {
    if script.is_empty() || script[0] != stake_opcode {
        return None;
    }
    extract_script_hash(&script[1..])
}

/// Extract the pubkey hash from a standard version 0 stake submission
/// P2PKH script (dcrd `ExtractStakeSubmissionPubKeyHashV0`).
pub fn extract_stake_submission_pub_key_hash_v0(script: &[u8]) -> Option<&[u8]> {
    extract_stake_pub_key_hash_v0_tagged(script, OP_SSTX)
}

/// Whether the script is a standard version 0 stake submission P2PKH
/// script (dcrd `IsStakeSubmissionPubKeyHashScriptV0`).
pub fn is_stake_submission_pub_key_hash_script_v0(script: &[u8]) -> bool {
    extract_stake_submission_pub_key_hash_v0(script).is_some()
}

/// Extract the script hash from a standard version 0 stake submission P2SH
/// script (dcrd `ExtractStakeSubmissionScriptHashV0`).
pub fn extract_stake_submission_script_hash_v0(script: &[u8]) -> Option<&[u8]> {
    extract_stake_script_hash_v0_tagged(script, OP_SSTX)
}

/// Whether the script is a standard version 0 stake submission P2SH script
/// (dcrd `IsStakeSubmissionScriptHashScriptV0`).
pub fn is_stake_submission_script_hash_script_v0(script: &[u8]) -> bool {
    extract_stake_submission_script_hash_v0(script).is_some()
}

/// Extract the pubkey hash from a standard version 0 stake generation
/// P2PKH script (dcrd `ExtractStakeGenPubKeyHashV0`).
pub fn extract_stake_gen_pub_key_hash_v0(script: &[u8]) -> Option<&[u8]> {
    extract_stake_pub_key_hash_v0_tagged(script, OP_SSGEN)
}

/// Whether the script is a standard version 0 stake generation P2PKH
/// script (dcrd `IsStakeGenPubKeyHashScriptV0`).
pub fn is_stake_gen_pub_key_hash_script_v0(script: &[u8]) -> bool {
    extract_stake_gen_pub_key_hash_v0(script).is_some()
}

/// Extract the script hash from a standard version 0 stake generation P2SH
/// script (dcrd `ExtractStakeGenScriptHashV0`).
pub fn extract_stake_gen_script_hash_v0(script: &[u8]) -> Option<&[u8]> {
    extract_stake_script_hash_v0_tagged(script, OP_SSGEN)
}

/// Whether the script is a standard version 0 stake generation P2SH script
/// (dcrd `IsStakeGenScriptHashScriptV0`).
pub fn is_stake_gen_script_hash_script_v0(script: &[u8]) -> bool {
    extract_stake_gen_script_hash_v0(script).is_some()
}

/// Extract the pubkey hash from a standard version 0 stake revocation
/// P2PKH script (dcrd `ExtractStakeRevocationPubKeyHashV0`).
pub fn extract_stake_revocation_pub_key_hash_v0(script: &[u8]) -> Option<&[u8]> {
    extract_stake_pub_key_hash_v0_tagged(script, OP_SSRTX)
}

/// Whether the script is a standard version 0 stake revocation P2PKH
/// script (dcrd `IsStakeRevocationPubKeyHashScriptV0`).
pub fn is_stake_revocation_pub_key_hash_script_v0(script: &[u8]) -> bool {
    extract_stake_revocation_pub_key_hash_v0(script).is_some()
}

/// Extract the script hash from a standard version 0 stake revocation P2SH
/// script (dcrd `ExtractStakeRevocationScriptHashV0`).
pub fn extract_stake_revocation_script_hash_v0(script: &[u8]) -> Option<&[u8]> {
    extract_stake_script_hash_v0_tagged(script, OP_SSRTX)
}

/// Whether the script is a standard version 0 stake revocation P2SH script
/// (dcrd `IsStakeRevocationScriptHashScriptV0`).
pub fn is_stake_revocation_script_hash_script_v0(script: &[u8]) -> bool {
    extract_stake_revocation_script_hash_v0(script).is_some()
}

/// Extract the pubkey hash from a standard version 0 stake change P2PKH
/// script (dcrd `ExtractStakeChangePubKeyHashV0`).
pub fn extract_stake_change_pub_key_hash_v0(script: &[u8]) -> Option<&[u8]> {
    extract_stake_pub_key_hash_v0_tagged(script, OP_SSTXCHANGE)
}

/// Whether the script is a standard version 0 stake change P2PKH script
/// (dcrd `IsStakeChangePubKeyHashScriptV0`).
pub fn is_stake_change_pub_key_hash_script_v0(script: &[u8]) -> bool {
    extract_stake_change_pub_key_hash_v0(script).is_some()
}

/// Extract the script hash from a standard version 0 stake change P2SH
/// script (dcrd `ExtractStakeChangeScriptHashV0`).
pub fn extract_stake_change_script_hash_v0(script: &[u8]) -> Option<&[u8]> {
    extract_stake_script_hash_v0_tagged(script, OP_SSTXCHANGE)
}

/// Whether the script is a standard version 0 stake change P2SH script
/// (dcrd `IsStakeChangeScriptHashScriptV0`).
pub fn is_stake_change_script_hash_script_v0(script: &[u8]) -> bool {
    extract_stake_change_script_hash_v0(script).is_some()
}

/// Whether the script is a supported version 0 treasury add script (dcrd
/// `IsTreasuryAddScriptV0`).
pub fn is_treasury_add_script_v0(script: &[u8]) -> bool {
    script.len() == 1 && script[0] == OP_TADD
}

/// Extract the pubkey hash from a standard version 0 treasury generation
/// P2PKH script (dcrd `ExtractTreasuryGenPubKeyHashV0`).
pub fn extract_treasury_gen_pub_key_hash_v0(script: &[u8]) -> Option<&[u8]> {
    extract_stake_pub_key_hash_v0_tagged(script, OP_TGEN)
}

/// Whether the script is a standard version 0 treasury generation P2PKH
/// script (dcrd `IsTreasuryGenPubKeyHashScriptV0`).
pub fn is_treasury_gen_pub_key_hash_script_v0(script: &[u8]) -> bool {
    extract_treasury_gen_pub_key_hash_v0(script).is_some()
}

/// Extract the script hash from a standard version 0 treasury generation
/// P2SH script (dcrd `ExtractTreasuryGenScriptHashV0`).
pub fn extract_treasury_gen_script_hash_v0(script: &[u8]) -> Option<&[u8]> {
    extract_stake_script_hash_v0_tagged(script, OP_TGEN)
}

/// Whether the script is a standard version 0 treasury generation P2SH
/// script (dcrd `IsTreasuryGenScriptHashScriptV0`).
pub fn is_treasury_gen_script_hash_script_v0(script: &[u8]) -> bool {
    extract_treasury_gen_script_hash_v0(script).is_some()
}

/// Extract the pubkey hash from any supported version 0 stake-tagged P2PKH
/// script (dcrd `ExtractStakePubKeyHashV0`).
pub fn extract_stake_pub_key_hash_v0(script: &[u8]) -> Option<&[u8]> {
    extract_stake_submission_pub_key_hash_v0(script)
        .or_else(|| extract_stake_gen_pub_key_hash_v0(script))
        .or_else(|| extract_stake_revocation_pub_key_hash_v0(script))
        .or_else(|| extract_stake_change_pub_key_hash_v0(script))
        .or_else(|| extract_treasury_gen_pub_key_hash_v0(script))
}

/// Extract the script hash from any supported version 0 stake-tagged P2SH
/// script (dcrd `ExtractStakeScriptHashV0`).
pub fn extract_stake_script_hash_v0(script: &[u8]) -> Option<&[u8]> {
    extract_stake_submission_script_hash_v0(script)
        .or_else(|| extract_stake_gen_script_hash_v0(script))
        .or_else(|| extract_stake_revocation_script_hash_v0(script))
        .or_else(|| extract_stake_change_script_hash_v0(script))
        .or_else(|| extract_treasury_gen_script_hash_v0(script))
}

/// The type of the passed version 0 script for the known standard types
/// (dcrd `DetermineScriptTypeV0`); non-standard when it does not parse.
pub fn determine_script_type_v0(script: &[u8]) -> ScriptType {
    if is_pub_key_script_v0(script) {
        return ScriptType::PubKeyEcdsaSecp256k1;
    }
    if is_pub_key_ed25519_script_v0(script) {
        return ScriptType::PubKeyEd25519;
    }
    if is_pub_key_schnorr_secp256k1_script_v0(script) {
        return ScriptType::PubKeySchnorrSecp256k1;
    }
    if is_pub_key_hash_script_v0(script) {
        return ScriptType::PubKeyHashEcdsaSecp256k1;
    }
    if is_pub_key_hash_ed25519_script_v0(script) {
        return ScriptType::PubKeyHashEd25519;
    }
    if is_pub_key_hash_schnorr_secp256k1_script_v0(script) {
        return ScriptType::PubKeyHashSchnorrSecp256k1;
    }
    if is_script_hash_script_v0(script) {
        return ScriptType::ScriptHash;
    }
    if is_multi_sig_script_v0(script) {
        return ScriptType::MultiSig;
    }
    if is_null_data_script_v0(script) {
        return ScriptType::NullData;
    }
    if is_stake_submission_pub_key_hash_script_v0(script) {
        return ScriptType::StakeSubmissionPubKeyHash;
    }
    if is_stake_submission_script_hash_script_v0(script) {
        return ScriptType::StakeSubmissionScriptHash;
    }
    if is_stake_gen_pub_key_hash_script_v0(script) {
        return ScriptType::StakeGenPubKeyHash;
    }
    if is_stake_gen_script_hash_script_v0(script) {
        return ScriptType::StakeGenScriptHash;
    }
    if is_stake_revocation_pub_key_hash_script_v0(script) {
        return ScriptType::StakeRevocationPubKeyHash;
    }
    if is_stake_revocation_script_hash_script_v0(script) {
        return ScriptType::StakeRevocationScriptHash;
    }
    if is_stake_change_pub_key_hash_script_v0(script) {
        return ScriptType::StakeChangePubKeyHash;
    }
    if is_stake_change_script_hash_script_v0(script) {
        return ScriptType::StakeChangeScriptHash;
    }
    if is_treasury_add_script_v0(script) {
        return ScriptType::TreasuryAdd;
    }
    if is_treasury_gen_pub_key_hash_script_v0(script) {
        return ScriptType::TreasuryGenPubKeyHash;
    }
    if is_treasury_gen_script_hash_script_v0(script) {
        return ScriptType::TreasuryGenScriptHash;
    }
    ScriptType::NonStandard
}

/// The type of the passed script (dcrd `DetermineScriptType`); always
/// non-standard for unsupported script versions.
pub fn determine_script_type(script_version: u16, script: &[u8]) -> ScriptType {
    match script_version {
        0 => determine_script_type_v0(script),
        _ => ScriptType::NonStandard,
    }
}

/// The number of signatures required by the passed version 0 script for
/// the known standard types (dcrd `DetermineRequiredSigsV0`).
pub fn determine_required_sigs_v0(script: &[u8]) -> u16 {
    use ScriptType::*;
    match determine_script_type_v0(script) {
        PubKeyHashEcdsaSecp256k1
        | ScriptHash
        | PubKeyHashEd25519
        | PubKeyHashSchnorrSecp256k1
        | PubKeyEcdsaSecp256k1
        | PubKeyEd25519
        | PubKeySchnorrSecp256k1
        | StakeSubmissionPubKeyHash
        | StakeSubmissionScriptHash
        | StakeGenPubKeyHash
        | StakeGenScriptHash
        | StakeRevocationPubKeyHash
        | StakeRevocationScriptHash
        | StakeChangePubKeyHash
        | StakeChangeScriptHash
        | TreasuryGenPubKeyHash
        | TreasuryGenScriptHash => 1,

        MultiSig => {
            let details = extract_multi_sig_script_details_v0(script, false);
            if details.valid {
                details.required_sigs
            } else {
                0
            }
        }

        NullData | TreasuryAdd | NonStandard => 0,
    }
}

/// The number of signatures required by the passed script (dcrd
/// `DetermineRequiredSigs`); always 0 for unsupported script versions.
pub fn determine_required_sigs(script_version: u16, script: &[u8]) -> u16 {
    match script_version {
        0 => determine_required_sigs_v0(script),
        _ => 0,
    }
}

/// A valid version 0 multisig redemption script for the given threshold
/// and compressed public keys (dcrd `MultiSigScriptV0`).
pub fn multi_sig_script_v0(threshold: i64, pub_keys: &[&[u8]]) -> Result<Vec<u8>, StdScriptError> {
    if threshold < 0 {
        return Err(make_error(
            StdScriptErrorKind::NegativeRequiredSigs,
            format!("unable to generate multisig script with {threshold} required signatures"),
        ));
    }
    if (pub_keys.len() as i64) < threshold {
        return Err(make_error(
            StdScriptErrorKind::TooManyRequiredSigs,
            format!(
                "unable to generate multisig script with {threshold} required signatures when \
                 there are only {} public keys available",
                pub_keys.len()
            ),
        ));
    }

    let mut builder = ScriptBuilder::new().add_int64(threshold);
    for pub_key in pub_keys {
        if !is_strict_compressed_pub_key_encoding(pub_key) {
            let hex: String = pub_key.iter().map(|b| format!("{b:02x}")).collect();
            return Err(make_error(
                StdScriptErrorKind::PubKeyType,
                format!("unable to generate multisig script with unsupported public key {hex}"),
            ));
        }
        builder = builder.add_data(pub_key);
    }
    let builder = builder
        .add_int64(pub_keys.len() as i64)
        .add_op(OP_CHECKMULTISIG);

    // The builder cannot fail here in practice (sizes are bounded well
    // below the limits), but mirror dcrd by propagating.
    builder
        .script()
        .map_err(|e| make_error(StdScriptErrorKind::UnsupportedScriptVersion, format!("{e}")))
}

/// A valid version 0 provably-pruneable script: OP_RETURN followed by the
/// passed data (dcrd `ProvablyPruneableScriptV0`).
pub fn provably_pruneable_script_v0(data: &[u8]) -> Result<Vec<u8>, StdScriptError> {
    if data.len() > MAX_DATA_CARRIER_SIZE_V0 {
        return Err(make_error(
            StdScriptErrorKind::TooMuchNullData,
            format!(
                "data size {} is larger than max allowed size {MAX_DATA_CARRIER_SIZE_V0}",
                data.len()
            ),
        ));
    }

    ScriptBuilder::new()
        .add_op(OP_RETURN)
        .add_data(data)
        .script()
        .map_err(|e| make_error(StdScriptErrorKind::TooMuchNullData, format!("{e}")))
}

/// The data pushes in a version 0 hash-based atomic swap contract (dcrd
/// `AtomicSwapDataPushesV0`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtomicSwapDataPushesV0 {
    /// The Hash160 of the recipient.
    pub recipient_hash160: [u8; 20],
    /// The Hash160 for the refund path.
    pub refund_hash160: [u8; 20],
    /// The SHA-256 hash of the secret.
    pub secret_hash: [u8; 32],
    /// The size of the secret in bytes.
    pub secret_size: i64,
    /// The locktime for the refund path.
    pub lock_time: i64,
}

/// Extract the data pushes from a version 0 atomic swap contract, or
/// `None` when the script is not one (dcrd
/// `ExtractAtomicSwapDataPushesV0`).
pub fn extract_atomic_swap_data_pushes_v0(redeem_script: &[u8]) -> Option<AtomicSwapDataPushesV0> {
    use crate::opcode_table::{
        OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_ELSE, OP_ENDIF, OP_IF, OP_SHA256, OP_SIZE,
    };

    // The template entries: either an expected opcode or a canonical int
    // with the given maximum encoded length.
    enum Tpl {
        Op(u8),
        Int(usize),
    }
    let template = [
        Tpl::Op(OP_IF),
        Tpl::Op(OP_SIZE),
        Tpl::Int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN),
        Tpl::Op(OP_EQUALVERIFY),
        Tpl::Op(OP_SHA256),
        Tpl::Op(OP_DATA_32),
        Tpl::Op(OP_EQUALVERIFY),
        Tpl::Op(OP_DUP),
        Tpl::Op(OP_HASH160),
        Tpl::Op(OP_DATA_20),
        Tpl::Op(OP_ELSE),
        Tpl::Int(CLTV_MAX_SCRIPT_NUM_LEN),
        Tpl::Op(OP_CHECKLOCKTIMEVERIFY),
        Tpl::Op(OP_DROP),
        Tpl::Op(OP_DUP),
        Tpl::Op(OP_HASH160),
        Tpl::Op(OP_DATA_20),
        Tpl::Op(OP_ENDIF),
        Tpl::Op(OP_EQUALVERIFY),
        Tpl::Op(OP_CHECKSIG),
    ];

    let mut extracted_ints = [0i64; 20];
    let mut extracted_data: [&[u8]; 20] = [&[]; 20];

    const SCRIPT_VERSION: u16 = 0;
    let mut template_offset = 0usize;
    let mut tokenizer = ScriptTokenizer::new(SCRIPT_VERSION, redeem_script);
    while tokenizer.next() {
        // Not an atomic swap script if it has more opcodes than expected.
        if template_offset >= template.len() {
            return None;
        }

        let op = tokenizer.opcode();
        let data = tokenizer.data();
        // Go's nil-vs-data distinction: only data-carrying opcodes count
        // as an attached data buffer for the canonical-int branch.
        let has_data_buffer = (0x01..=0x4e).contains(&op);
        match &template[template_offset] {
            Tpl::Int(max_int_bytes) => {
                if has_data_buffer {
                    let val = make_script_num(data, *max_int_bytes).ok()?;
                    extracted_ints[template_offset] = val.0;
                } else if is_small_int(op) {
                    extracted_ints[template_offset] = as_small_int(op) as i64;
                } else {
                    // Not an atomic swap script if the opcode does not
                    // push an int.
                    return None;
                }
            }
            Tpl::Op(expected) => {
                if op != *expected {
                    return None;
                }
                extracted_data[template_offset] = data;
            }
        }

        template_offset += 1;
    }
    if tokenizer.err().is_some() {
        return None;
    }
    if template_offset != template.len() {
        return None;
    }

    let mut pushes = AtomicSwapDataPushesV0 {
        recipient_hash160: [0u8; 20],
        refund_hash160: [0u8; 20],
        secret_hash: [0u8; 32],
        secret_size: extracted_ints[2],
        lock_time: extracted_ints[11],
    };
    pushes.secret_hash.copy_from_slice(extracted_data[5]);
    pushes.recipient_hash160.copy_from_slice(extracted_data[9]);
    pushes.refund_hash160.copy_from_slice(extracted_data[16]);
    Some(pushes)
}

/// Analyze a version 0 public key script and return its type along with
/// any addresses associated with it when possible (dcrd `ExtractAddrsV0`);
/// data failing to produce a valid address is omitted.
pub fn extract_addrs_v0(
    pk_script: &[u8],
    params: &dyn AddressParamsV0,
) -> (ScriptType, Vec<Address>) {
    fn one(addr: Result<Address, stdaddr::AddrError>) -> Vec<Address> {
        match addr {
            Ok(addr) => alloc::vec![addr],
            Err(_) => Vec::new(),
        }
    }

    if let Some(h) = extract_pub_key_hash_v0(pk_script) {
        let addr = stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(h, params);
        return (ScriptType::PubKeyHashEcdsaSecp256k1, one(addr));
    }
    if let Some(h) = extract_script_hash_v0(pk_script) {
        let addr = stdaddr::new_address_script_hash_v0_from_hash(h, params);
        return (ScriptType::ScriptHash, one(addr));
    }
    if let Some(h) = extract_pub_key_hash_ed25519_v0(pk_script) {
        let addr = stdaddr::new_address_pub_key_hash_ed25519_v0(h, params);
        return (ScriptType::PubKeyHashEd25519, one(addr));
    }
    if let Some(h) = extract_pub_key_hash_schnorr_secp256k1_v0(pk_script) {
        let addr = stdaddr::new_address_pub_key_hash_schnorr_secp256k1_v0(h, params);
        return (ScriptType::PubKeyHashSchnorrSecp256k1, one(addr));
    }
    if let Some(data) = extract_pub_key_v0(pk_script) {
        // The address is intentionally limited to compressed pubkeys even
        // though consensus allows both forms, so the key is parsed and
        // re-serialized compressed (dcrd parses then uses the concrete-key
        // constructor).
        let addrs = match dcroxide_dcrec::secp256k1::PublicKey::parse(data) {
            Ok(pk) => alloc::vec![stdaddr::new_address_pub_key_ecdsa_secp256k1_v0(
                pk.serialize_compressed(),
                params
            )],
            Err(_) => Vec::new(),
        };
        return (ScriptType::PubKeyEcdsaSecp256k1, addrs);
    }
    if let Some(data) = extract_pub_key_ed25519_v0(pk_script) {
        let addr = stdaddr::new_address_pub_key_ed25519_v0_raw(data, params);
        return (ScriptType::PubKeyEd25519, one(addr));
    }
    if let Some(data) = extract_pub_key_schnorr_secp256k1_v0(pk_script) {
        let addr = stdaddr::new_address_pub_key_schnorr_secp256k1_v0_raw(data, params);
        return (ScriptType::PubKeySchnorrSecp256k1, one(addr));
    }

    let details = extract_multi_sig_script_details_v0(pk_script, true);
    if details.valid {
        // Convert the public keys while skipping any that are invalid.
        let mut addrs = Vec::new();
        for pub_key in &details.pub_keys {
            if let Ok(pk) = dcroxide_dcrec::secp256k1::PublicKey::parse(pub_key) {
                addrs.push(stdaddr::new_address_pub_key_ecdsa_secp256k1_v0(
                    pk.serialize_compressed(),
                    params,
                ));
            }
        }
        return (ScriptType::MultiSig, addrs);
    }

    if let Some(h) = extract_stake_submission_pub_key_hash_v0(pk_script) {
        let addr = stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(h, params);
        return (ScriptType::StakeSubmissionPubKeyHash, one(addr));
    }
    if let Some(h) = extract_stake_submission_script_hash_v0(pk_script) {
        let addr = stdaddr::new_address_script_hash_v0_from_hash(h, params);
        return (ScriptType::StakeSubmissionScriptHash, one(addr));
    }
    if let Some(h) = extract_stake_gen_pub_key_hash_v0(pk_script) {
        let addr = stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(h, params);
        return (ScriptType::StakeGenPubKeyHash, one(addr));
    }
    if let Some(h) = extract_stake_gen_script_hash_v0(pk_script) {
        let addr = stdaddr::new_address_script_hash_v0_from_hash(h, params);
        return (ScriptType::StakeGenScriptHash, one(addr));
    }
    if let Some(h) = extract_stake_revocation_pub_key_hash_v0(pk_script) {
        let addr = stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(h, params);
        return (ScriptType::StakeRevocationPubKeyHash, one(addr));
    }
    if let Some(h) = extract_stake_revocation_script_hash_v0(pk_script) {
        let addr = stdaddr::new_address_script_hash_v0_from_hash(h, params);
        return (ScriptType::StakeRevocationScriptHash, one(addr));
    }
    if let Some(h) = extract_stake_change_pub_key_hash_v0(pk_script) {
        let addr = stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(h, params);
        return (ScriptType::StakeChangePubKeyHash, one(addr));
    }
    if let Some(h) = extract_stake_change_script_hash_v0(pk_script) {
        let addr = stdaddr::new_address_script_hash_v0_from_hash(h, params);
        return (ScriptType::StakeChangeScriptHash, one(addr));
    }

    if is_null_data_script_v0(pk_script) {
        // Null data scripts do not have an associated address.
        return (ScriptType::NullData, Vec::new());
    }
    if is_treasury_add_script_v0(pk_script) {
        return (ScriptType::TreasuryAdd, Vec::new());
    }
    if let Some(h) = extract_treasury_gen_pub_key_hash_v0(pk_script) {
        let addr = stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(h, params);
        return (ScriptType::TreasuryGenPubKeyHash, one(addr));
    }
    if let Some(h) = extract_treasury_gen_script_hash_v0(pk_script) {
        let addr = stdaddr::new_address_script_hash_v0_from_hash(h, params);
        return (ScriptType::TreasuryGenScriptHash, one(addr));
    }

    (ScriptType::NonStandard, Vec::new())
}

/// Analyze a public key script for any script version (dcrd
/// `ExtractAddrs`); non-standard with no addresses for unsupported
/// versions.
pub fn extract_addrs(
    script_version: u16,
    pk_script: &[u8],
    params: &dyn AddressParamsV0,
) -> (ScriptType, Vec<Address>) {
    match script_version {
        0 => extract_addrs_v0(pk_script, params),
        _ => (ScriptType::NonStandard, Vec::new()),
    }
}
