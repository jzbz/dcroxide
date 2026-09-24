// SPDX-License-Identifier: ISC
//! Human-readable Decred payment addresses (dcrd `txscript/v4/stdaddr`).
//!
//! Version 0 is the only supported script version, matching dcrd. dcrd
//! models the address kinds as distinct types behind `Address`/
//! `StakeAddress` interfaces; here they are one [`Address`] enum whose
//! stake-specific methods return `None` for kinds that do not implement
//! dcrd's `StakeAddress` (only P2PKH-ECDSA and P2SH do). Everything
//! observable — string encodings, scripts, and error kinds — matches dcrd
//! exactly.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::opcode_table::{
    OP_1, OP_2, OP_CHECKSIG, OP_CHECKSIGALT, OP_DATA_20, OP_DATA_30, OP_DATA_32, OP_DATA_33,
    OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_RETURN, OP_SSGEN, OP_SSRTX, OP_SSTX,
    OP_SSTXCHANGE, OP_TGEN,
};

/// The dcrec.STEd25519 signature type as its small-integer push opcode.
const OP_PUSH_ST_ED25519: u8 = OP_1;
/// The dcrec.STSchnorrSecp256k1 signature type as its small-integer push
/// opcode.
const OP_PUSH_ST_SCHNORR_SECP256K1: u8 = OP_2;

/// The bitmask applied to the pubkey address signature type byte to
/// specify the omitted y coordinate is odd (dcrd
/// `sigTypeSecp256k1PubKeyCompOddFlag`).
const SIG_TYPE_SECP256K1_PUB_KEY_COMP_ODD_FLAG: u8 = 1 << 7;

/// The bitmask applied to a ticket commitment amount to mark it as a
/// pay-to-script-hash commitment (dcrd `commitP2SHFlag`).
const COMMIT_P2SH_FLAG: u64 = 1 << 63;

/// Length of a standard version 0 P2PKH-ecdsa-secp256k1 payment script.
const P2PKH_PAYMENT_SCRIPT_LEN: usize = 25;

/// Length of a standard version 0 P2SH payment script.
const P2SH_PAYMENT_SCRIPT_LEN: usize = 23;

/// The RIPEMD-160 hash size used by hash-based addresses.
pub const HASH160_SIZE: usize = 20;

/// A kind of address error (dcrd stdaddr `ErrorKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)] // Kinds mirror dcrd's documented ErrorKind constants 1:1.
pub enum AddrErrorKind {
    UnsupportedAddress,
    UnsupportedScriptVersion,
    MalformedAddress,
    MalformedAddressData,
    BadAddressChecksum,
    InvalidPubKey,
    InvalidPubKeyFormat,
    InvalidHashLen,
}

impl AddrErrorKind {
    /// The dcrd `ErrorKind` constant name (e.g. `"ErrMalformedAddress"`).
    pub fn kind_name(self) -> &'static str {
        use AddrErrorKind::*;
        match self {
            UnsupportedAddress => "ErrUnsupportedAddress",
            UnsupportedScriptVersion => "ErrUnsupportedScriptVersion",
            MalformedAddress => "ErrMalformedAddress",
            MalformedAddressData => "ErrMalformedAddressData",
            BadAddressChecksum => "ErrBadAddressChecksum",
            InvalidPubKey => "ErrInvalidPubKey",
            InvalidPubKeyFormat => "ErrInvalidPubKeyFormat",
            InvalidHashLen => "ErrInvalidHashLen",
        }
    }
}

/// An address-related error (dcrd stdaddr `Error`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrError {
    /// The kind of error.
    pub kind: AddrErrorKind,
    /// Human-readable description.
    pub description: String,
}

impl fmt::Display for AddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.description)
    }
}

impl core::error::Error for AddrError {}

fn make_error(kind: AddrErrorKind, description: impl Into<String>) -> AddrError {
    AddrError {
        kind,
        description: description.into(),
    }
}

/// The parameters required for encoding and decoding version 0 addresses
/// (dcrd `AddressParamsV0`), typically unique per network.
pub trait AddressParamsV0 {
    /// The magic prefix bytes for version 0 pay-to-pubkey addresses.
    fn addr_id_pub_key_v0(&self) -> [u8; 2];
    /// The magic prefix bytes for version 0 P2PKH-ecdsa-secp256k1
    /// addresses.
    fn addr_id_pub_key_hash_ecdsa_v0(&self) -> [u8; 2];
    /// The magic prefix bytes for version 0 P2PKH-ed25519 addresses.
    fn addr_id_pub_key_hash_ed25519_v0(&self) -> [u8; 2];
    /// The magic prefix bytes for version 0 P2PKH-schnorr-secp256k1
    /// addresses.
    fn addr_id_pub_key_hash_schnorr_v0(&self) -> [u8; 2];
    /// The magic prefix bytes for version 0 pay-to-script-hash addresses.
    fn addr_id_script_hash_v0(&self) -> [u8; 2];
}

impl AddressParamsV0 for dcroxide_chaincfg::Params {
    fn addr_id_pub_key_v0(&self) -> [u8; 2] {
        self.pub_key_addr_id
    }
    fn addr_id_pub_key_hash_ecdsa_v0(&self) -> [u8; 2] {
        self.pub_key_hash_addr_id
    }
    fn addr_id_pub_key_hash_ed25519_v0(&self) -> [u8; 2] {
        self.pkh_edwards_addr_id
    }
    fn addr_id_pub_key_hash_schnorr_v0(&self) -> [u8; 2] {
        self.pkh_schnorr_addr_id
    }
    fn addr_id_script_hash_v0(&self) -> [u8; 2] {
        self.script_hash_addr_id
    }
}

/// The base58 check encoding used by version 0 addresses (dcrd
/// `encodeAddressV0`).
fn encode_address_v0(data: &[u8], net_id: [u8; 2]) -> String {
    dcroxide_base58::check_encode(data, net_id)
}

/// ripemd160(blake256(b)) (dcrd stdaddr `Hash160`).
pub fn hash160(buf: &[u8]) -> [u8; HASH160_SIZE] {
    let b256 = dcroxide_crypto::blake256::sum256(buf);
    dcroxide_crypto::ripemd160::sum160(&b256)
}

/// A destination a transaction output may spend to (all supported version
/// 0 address kinds; see the module docs for how this maps onto dcrd's
/// interface-based design).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// Pay-to-pubkey-ecdsa-secp256k1 (dcrd
    /// `AddressPubKeyEcdsaSecp256k1V0`).
    PubKeyEcdsaSecp256k1V0 {
        /// The pay-to-pubkey address prefix.
        pub_key_id: [u8; 2],
        /// The P2PKH-ECDSA prefix used by [`Address::address_pub_key_hash`].
        pub_key_hash_id: [u8; 2],
        /// The compressed serialized public key.
        serialized_pub_key: Vec<u8>,
    },
    /// Pay-to-pubkey-ed25519 (dcrd `AddressPubKeyEd25519V0`).
    PubKeyEd25519V0 {
        /// The pay-to-pubkey address prefix.
        pub_key_id: [u8; 2],
        /// The P2PKH-Ed25519 prefix used by
        /// [`Address::address_pub_key_hash`].
        pub_key_hash_id: [u8; 2],
        /// The serialized public key.
        serialized_pub_key: Vec<u8>,
    },
    /// Pay-to-pubkey-schnorr-secp256k1 (dcrd
    /// `AddressPubKeySchnorrSecp256k1V0`).
    PubKeySchnorrSecp256k1V0 {
        /// The pay-to-pubkey address prefix.
        pub_key_id: [u8; 2],
        /// The P2PKH-Schnorr prefix used by
        /// [`Address::address_pub_key_hash`].
        pub_key_hash_id: [u8; 2],
        /// The compressed serialized public key.
        serialized_pub_key: Vec<u8>,
    },
    /// Pay-to-pubkey-hash-ecdsa-secp256k1 (dcrd
    /// `AddressPubKeyHashEcdsaSecp256k1V0`).
    PubKeyHashEcdsaSecp256k1V0 {
        /// The network prefix.
        net_id: [u8; 2],
        /// The Hash160 of the compressed public key.
        hash: [u8; HASH160_SIZE],
    },
    /// Pay-to-pubkey-hash-ed25519 (dcrd `AddressPubKeyHashEd25519V0`).
    PubKeyHashEd25519V0 {
        /// The network prefix.
        net_id: [u8; 2],
        /// The Hash160 of the public key.
        hash: [u8; HASH160_SIZE],
    },
    /// Pay-to-pubkey-hash-schnorr-secp256k1 (dcrd
    /// `AddressPubKeyHashSchnorrSecp256k1V0`).
    PubKeyHashSchnorrSecp256k1V0 {
        /// The network prefix.
        net_id: [u8; 2],
        /// The Hash160 of the compressed public key.
        hash: [u8; HASH160_SIZE],
    },
    /// Pay-to-script-hash (dcrd `AddressScriptHashV0`).
    ScriptHashV0 {
        /// The network prefix.
        net_id: [u8; 2],
        /// The Hash160 of the redeem script.
        hash: [u8; HASH160_SIZE],
    },
}

/// Construct a P2PK-ecdsa-secp256k1 address from a serialized compressed
/// public key, validating it parses and is in the compressed format (dcrd
/// `NewAddressPubKeyEcdsaSecp256k1V0Raw`).
pub fn new_address_pub_key_ecdsa_secp256k1_v0_raw(
    serialized_pub_key: &[u8],
    params: &dyn AddressParamsV0,
) -> Result<Address, AddrError> {
    if let Err(err) = dcroxide_dcrec::secp256k1::PublicKey::parse(serialized_pub_key) {
        return Err(make_error(
            AddrErrorKind::InvalidPubKey,
            format!("failed to parse public key: {err}"),
        ));
    }

    // Only the compressed format is supported; uncompressed and hybrid are
    // intentionally not.
    match serialized_pub_key[0] {
        0x02 | 0x03 => {}
        _ => {
            let hex: String = serialized_pub_key
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            return Err(make_error(
                AddrErrorKind::InvalidPubKeyFormat,
                format!("serialized public key {hex} is not a valid format"),
            ));
        }
    }

    Ok(Address::PubKeyEcdsaSecp256k1V0 {
        pub_key_id: params.addr_id_pub_key_v0(),
        pub_key_hash_id: params.addr_id_pub_key_hash_ecdsa_v0(),
        serialized_pub_key: serialized_pub_key.to_vec(),
    })
}

/// Construct a P2PK-ecdsa-secp256k1 address from an already-validated
/// compressed serialization (dcrd `NewAddressPubKeyEcdsaSecp256k1V0`,
/// which takes a parsed key and serializes it compressed).
pub fn new_address_pub_key_ecdsa_secp256k1_v0(
    compressed_pub_key: [u8; 33],
    params: &dyn AddressParamsV0,
) -> Address {
    Address::PubKeyEcdsaSecp256k1V0 {
        pub_key_id: params.addr_id_pub_key_v0(),
        pub_key_hash_id: params.addr_id_pub_key_hash_ecdsa_v0(),
        serialized_pub_key: compressed_pub_key.to_vec(),
    }
}

/// Construct a P2PK-ed25519 address from a serialized public key,
/// validating it parses (dcrd `NewAddressPubKeyEd25519V0Raw`).
pub fn new_address_pub_key_ed25519_v0_raw(
    serialized_pub_key: &[u8],
    params: &dyn AddressParamsV0,
) -> Result<Address, AddrError> {
    if let Err(err) = dcroxide_dcrec::edwards::parse_pub_key(serialized_pub_key) {
        return Err(make_error(
            AddrErrorKind::InvalidPubKey,
            format!("failed to parse public key: {err}"),
        ));
    }

    Ok(Address::PubKeyEd25519V0 {
        pub_key_id: params.addr_id_pub_key_v0(),
        pub_key_hash_id: params.addr_id_pub_key_hash_ed25519_v0(),
        serialized_pub_key: serialized_pub_key.to_vec(),
    })
}

/// Construct a P2PK-schnorr-secp256k1 address from a serialized compressed
/// public key, validating it parses and is in the compressed format (dcrd
/// `NewAddressPubKeySchnorrSecp256k1V0Raw`).
pub fn new_address_pub_key_schnorr_secp256k1_v0_raw(
    serialized_pub_key: &[u8],
    params: &dyn AddressParamsV0,
) -> Result<Address, AddrError> {
    if let Err(err) = dcroxide_dcrec::secp256k1::PublicKey::parse(serialized_pub_key) {
        return Err(make_error(
            AddrErrorKind::InvalidPubKey,
            format!("failed to parse public key: {err}"),
        ));
    }

    match serialized_pub_key[0] {
        0x02 | 0x03 => {}
        _ => {
            let hex: String = serialized_pub_key
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            return Err(make_error(
                AddrErrorKind::InvalidPubKeyFormat,
                format!("serialized public key {hex} is not a valid format"),
            ));
        }
    }

    Ok(Address::PubKeySchnorrSecp256k1V0 {
        pub_key_id: params.addr_id_pub_key_v0(),
        pub_key_hash_id: params.addr_id_pub_key_hash_schnorr_v0(),
        serialized_pub_key: serialized_pub_key.to_vec(),
    })
}

/// The common 20-byte-hash length check (dcrd's per-constructor check).
fn check_hash160_len(hash: &[u8], what: &str) -> Result<[u8; HASH160_SIZE], AddrError> {
    if hash.len() != HASH160_SIZE {
        return Err(make_error(
            AddrErrorKind::InvalidHashLen,
            format!(
                "{what} is {} bytes vs required {HASH160_SIZE} bytes",
                hash.len()
            ),
        ));
    }
    let mut out = [0u8; HASH160_SIZE];
    out.copy_from_slice(hash);
    Ok(out)
}

/// Construct a P2PKH-ecdsa-secp256k1 address (dcrd
/// `NewAddressPubKeyHashEcdsaSecp256k1V0`).
pub fn new_address_pub_key_hash_ecdsa_secp256k1_v0(
    pk_hash: &[u8],
    params: &dyn AddressParamsV0,
) -> Result<Address, AddrError> {
    Ok(Address::PubKeyHashEcdsaSecp256k1V0 {
        net_id: params.addr_id_pub_key_hash_ecdsa_v0(),
        hash: check_hash160_len(pk_hash, "public key hash")?,
    })
}

/// Construct a P2PKH-ed25519 address (dcrd
/// `NewAddressPubKeyHashEd25519V0`).
pub fn new_address_pub_key_hash_ed25519_v0(
    pk_hash: &[u8],
    params: &dyn AddressParamsV0,
) -> Result<Address, AddrError> {
    Ok(Address::PubKeyHashEd25519V0 {
        net_id: params.addr_id_pub_key_hash_ed25519_v0(),
        hash: check_hash160_len(pk_hash, "public key hash")?,
    })
}

/// Construct a P2PKH-schnorr-secp256k1 address (dcrd
/// `NewAddressPubKeyHashSchnorrSecp256k1V0`).
pub fn new_address_pub_key_hash_schnorr_secp256k1_v0(
    pk_hash: &[u8],
    params: &dyn AddressParamsV0,
) -> Result<Address, AddrError> {
    Ok(Address::PubKeyHashSchnorrSecp256k1V0 {
        net_id: params.addr_id_pub_key_hash_schnorr_v0(),
        hash: check_hash160_len(pk_hash, "public key hash")?,
    })
}

/// Construct a P2SH address from the script hash (dcrd
/// `NewAddressScriptHashV0FromHash`).
pub fn new_address_script_hash_v0_from_hash(
    script_hash: &[u8],
    params: &dyn AddressParamsV0,
) -> Result<Address, AddrError> {
    Ok(Address::ScriptHashV0 {
        net_id: params.addr_id_script_hash_v0(),
        hash: check_hash160_len(script_hash, "script hash")?,
    })
}

/// Construct a P2SH address from the redeem script (dcrd
/// `NewAddressScriptHashV0`).
pub fn new_address_script_hash_v0(
    redeem_script: &[u8],
    params: &dyn AddressParamsV0,
) -> Result<Address, AddrError> {
    let script_hash = hash160(redeem_script);
    new_address_script_hash_v0_from_hash(&script_hash, params)
}

/// The encoded limits for vote/revocation fees in a ticket reward
/// commitment (dcrd `calcRewardCommitScriptLimits`).
fn calc_reward_commit_script_limits(vote_fee_limit: i64, revocation_fee_limit: i64) -> u16 {
    // The limits are the closest base 2 exponent with a marker bit; vote
    // in the low byte, revocation in the high byte.
    let mut limits: u16 = 0;
    if vote_fee_limit != 0 {
        let exp = (vote_fee_limit as f64).log2().ceil() as u16;
        limits |= exp | 0x40;
    }
    if revocation_fee_limit != 0 {
        let exp = (revocation_fee_limit as f64).log2().ceil() as u16;
        limits |= (exp | 0x40) << 8;
    }
    limits
}

/// Build the shared `RETURN <hash || amount || limits>` ticket commitment
/// script (dcrd's per-type `RewardCommitmentScript` bodies).
fn reward_commitment_script(
    hash: &[u8; HASH160_SIZE],
    amount_with_flag: u64,
    vote_fee_limit: i64,
    revocation_fee_limit: i64,
) -> Vec<u8> {
    let limits = calc_reward_commit_script_limits(vote_fee_limit, revocation_fee_limit);
    let mut script = Vec::with_capacity(32);
    script.push(OP_RETURN);
    script.push(OP_DATA_30);
    script.extend_from_slice(hash);
    script.extend_from_slice(&amount_with_flag.to_le_bytes());
    script.extend_from_slice(&limits.to_le_bytes());
    script
}

impl Address {
    /// The string encoding of the payment address (dcrd `Address.String`).
    pub fn encode(&self) -> String {
        match self {
            Address::PubKeyEcdsaSecp256k1V0 {
                pub_key_id,
                serialized_pub_key,
                ..
            } => {
                // identifier byte (sig type + oddness in the high bit)
                // followed by the 32-byte X coordinate.
                let mut data = [0u8; 33];
                data[0] = 0; // STEcdsaSecp256k1
                if serialized_pub_key[0] == 0x03 {
                    data[0] |= SIG_TYPE_SECP256K1_PUB_KEY_COMP_ODD_FLAG;
                }
                data[1..].copy_from_slice(&serialized_pub_key[1..]);
                encode_address_v0(&data, *pub_key_id)
            }
            Address::PubKeyEd25519V0 {
                pub_key_id,
                serialized_pub_key,
                ..
            } => {
                let mut data = [0u8; 33];
                data[0] = 1; // STEd25519 (no oddness bit)
                data[1..].copy_from_slice(serialized_pub_key);
                encode_address_v0(&data, *pub_key_id)
            }
            Address::PubKeySchnorrSecp256k1V0 {
                pub_key_id,
                serialized_pub_key,
                ..
            } => {
                let mut data = [0u8; 33];
                data[0] = 2; // STSchnorrSecp256k1
                if serialized_pub_key[0] == 0x03 {
                    data[0] |= SIG_TYPE_SECP256K1_PUB_KEY_COMP_ODD_FLAG;
                }
                data[1..].copy_from_slice(&serialized_pub_key[1..]);
                encode_address_v0(&data, *pub_key_id)
            }
            Address::PubKeyHashEcdsaSecp256k1V0 { net_id, hash }
            | Address::PubKeyHashEd25519V0 { net_id, hash }
            | Address::PubKeyHashSchnorrSecp256k1V0 { net_id, hash }
            | Address::ScriptHashV0 { net_id, hash } => encode_address_v0(hash, *net_id),
        }
    }

    /// The script version and payment script (dcrd
    /// `Address.PaymentScript`).
    pub fn payment_script(&self) -> (u16, Vec<u8>) {
        match self {
            Address::PubKeyEcdsaSecp256k1V0 {
                serialized_pub_key, ..
            } => {
                // <33-byte compressed pubkey> CHECKSIG
                let mut script = Vec::with_capacity(35);
                script.push(OP_DATA_33);
                script.extend_from_slice(serialized_pub_key);
                script.push(OP_CHECKSIG);
                (0, script)
            }
            Address::PubKeyEd25519V0 {
                serialized_pub_key, ..
            } => {
                // <32-byte pubkey> <1-byte sigtype> CHECKSIGALT
                let mut script = Vec::with_capacity(35);
                script.push(OP_DATA_32);
                script.extend_from_slice(serialized_pub_key);
                script.push(OP_PUSH_ST_ED25519);
                script.push(OP_CHECKSIGALT);
                (0, script)
            }
            Address::PubKeySchnorrSecp256k1V0 {
                serialized_pub_key, ..
            } => {
                // <33-byte compressed pubkey> <1-byte sigtype> CHECKSIGALT
                let mut script = Vec::with_capacity(36);
                script.push(OP_DATA_33);
                script.extend_from_slice(serialized_pub_key);
                script.push(OP_PUSH_ST_SCHNORR_SECP256K1);
                script.push(OP_CHECKSIGALT);
                (0, script)
            }
            Address::PubKeyHashEcdsaSecp256k1V0 { hash, .. } => {
                (0, p2pkh_payment_script(hash).to_vec())
            }
            Address::PubKeyHashEd25519V0 { hash, .. } => (
                0,
                p2pkh_alt_payment_script(hash, OP_PUSH_ST_ED25519).to_vec(),
            ),
            Address::PubKeyHashSchnorrSecp256k1V0 { hash, .. } => (
                0,
                p2pkh_alt_payment_script(hash, OP_PUSH_ST_SCHNORR_SECP256K1).to_vec(),
            ),
            Address::ScriptHashV0 { hash, .. } => (0, p2sh_payment_script(hash).to_vec()),
        }
    }

    /// The stake payment script tagged with the given opcode, or `None`
    /// when the address kind does not implement dcrd's `StakeAddress`
    /// interface (only P2PKH-ECDSA and P2SH do).
    fn stake_tagged_script(&self, tag: u8) -> Option<(u16, Vec<u8>)> {
        match self {
            Address::PubKeyHashEcdsaSecp256k1V0 { hash, .. } => {
                let mut script = Vec::with_capacity(P2PKH_PAYMENT_SCRIPT_LEN + 1);
                script.push(tag);
                script.extend_from_slice(&p2pkh_payment_script(hash));
                Some((0, script))
            }
            Address::ScriptHashV0 { hash, .. } => {
                let mut script = Vec::with_capacity(P2SH_PAYMENT_SCRIPT_LEN + 1);
                script.push(tag);
                script.extend_from_slice(&p2sh_payment_script(hash));
                Some((0, script))
            }
            _ => None,
        }
    }

    /// A script giving voting rights to the address, for ticket purchases
    /// (dcrd `StakeAddress.VotingRightsScript`).
    pub fn voting_rights_script(&self) -> Option<(u16, Vec<u8>)> {
        self.stake_tagged_script(OP_SSTX)
    }

    /// The ticket reward commitment script (dcrd
    /// `StakeAddress.RewardCommitmentScript`); fee limits are rounded up
    /// to the next power of 2.
    pub fn reward_commitment_script(
        &self,
        amount: i64,
        vote_fee_limit: i64,
        revocation_fee_limit: i64,
    ) -> Option<(u16, Vec<u8>)> {
        match self {
            Address::PubKeyHashEcdsaSecp256k1V0 { hash, .. } => {
                // The high bit of the amount is NOT set for a pubkey hash.
                let amount = (amount as u64) & !COMMIT_P2SH_FLAG;
                Some((
                    0,
                    reward_commitment_script(hash, amount, vote_fee_limit, revocation_fee_limit),
                ))
            }
            Address::ScriptHashV0 { hash, .. } => {
                // The high bit of the amount IS set for a script hash.
                let amount = (amount as u64) | COMMIT_P2SH_FLAG;
                Some((
                    0,
                    reward_commitment_script(hash, amount, vote_fee_limit, revocation_fee_limit),
                ))
            }
            _ => None,
        }
    }

    /// A stake change script, for ticket purchases and treasury adds (dcrd
    /// `StakeAddress.StakeChangeScript`).
    pub fn stake_change_script(&self) -> Option<(u16, Vec<u8>)> {
        self.stake_tagged_script(OP_SSTXCHANGE)
    }

    /// A script paying a ticket commitment as part of a vote (dcrd
    /// `StakeAddress.PayVoteCommitmentScript`).
    pub fn pay_vote_commitment_script(&self) -> Option<(u16, Vec<u8>)> {
        self.stake_tagged_script(OP_SSGEN)
    }

    /// A script paying a ticket commitment as part of a revocation (dcrd
    /// `StakeAddress.PayRevokeCommitmentScript`).
    pub fn pay_revoke_commitment_script(&self) -> Option<(u16, Vec<u8>)> {
        self.stake_tagged_script(OP_SSRTX)
    }

    /// A script paying from the treasury as part of a treasury spend (dcrd
    /// `StakeAddress.PayFromTreasuryScript`).
    pub fn pay_from_treasury_script(&self) -> Option<(u16, Vec<u8>)> {
        self.stake_tagged_script(OP_TGEN)
    }

    /// The serialized public key for pubkey address kinds (dcrd
    /// `SerializedPubKeyer`).
    pub fn serialized_pub_key(&self) -> Option<&[u8]> {
        match self {
            Address::PubKeyEcdsaSecp256k1V0 {
                serialized_pub_key, ..
            }
            | Address::PubKeyEd25519V0 {
                serialized_pub_key, ..
            }
            | Address::PubKeySchnorrSecp256k1V0 {
                serialized_pub_key, ..
            } => Some(serialized_pub_key),
            _ => None,
        }
    }

    /// The pay-to-pubkey-hash variant of a pubkey address (dcrd
    /// `AddressPubKeyHasher`).
    pub fn address_pub_key_hash(&self) -> Option<Address> {
        match self {
            Address::PubKeyEcdsaSecp256k1V0 {
                pub_key_hash_id,
                serialized_pub_key,
                ..
            } => Some(Address::PubKeyHashEcdsaSecp256k1V0 {
                net_id: *pub_key_hash_id,
                hash: hash160(serialized_pub_key),
            }),
            Address::PubKeyEd25519V0 {
                pub_key_hash_id,
                serialized_pub_key,
                ..
            } => Some(Address::PubKeyHashEd25519V0 {
                net_id: *pub_key_hash_id,
                hash: hash160(serialized_pub_key),
            }),
            Address::PubKeySchnorrSecp256k1V0 {
                pub_key_hash_id,
                serialized_pub_key,
                ..
            } => Some(Address::PubKeyHashSchnorrSecp256k1V0 {
                net_id: *pub_key_hash_id,
                hash: hash160(serialized_pub_key),
            }),
            _ => None,
        }
    }

    /// The underlying RIPEMD-160 hash for hash-based address kinds (dcrd
    /// `Hash160er`).
    pub fn hash160(&self) -> Option<&[u8; HASH160_SIZE]> {
        match self {
            Address::PubKeyHashEcdsaSecp256k1V0 { hash, .. }
            | Address::PubKeyHashEd25519V0 { hash, .. }
            | Address::PubKeyHashSchnorrSecp256k1V0 { hash, .. }
            | Address::ScriptHashV0 { hash, .. } => Some(hash),
            _ => None,
        }
    }

    /// The dcrd concrete type name for this address kind, used to assert
    /// type parity in differential tests.
    pub fn go_type_name(&self) -> &'static str {
        match self {
            Address::PubKeyEcdsaSecp256k1V0 { .. } => "*stdaddr.AddressPubKeyEcdsaSecp256k1V0",
            Address::PubKeyEd25519V0 { .. } => "*stdaddr.AddressPubKeyEd25519V0",
            Address::PubKeySchnorrSecp256k1V0 { .. } => "*stdaddr.AddressPubKeySchnorrSecp256k1V0",
            Address::PubKeyHashEcdsaSecp256k1V0 { .. } => {
                "*stdaddr.AddressPubKeyHashEcdsaSecp256k1V0"
            }
            Address::PubKeyHashEd25519V0 { .. } => "*stdaddr.AddressPubKeyHashEd25519V0",
            Address::PubKeyHashSchnorrSecp256k1V0 { .. } => {
                "*stdaddr.AddressPubKeyHashSchnorrSecp256k1V0"
            }
            Address::ScriptHashV0 { .. } => "*stdaddr.AddressScriptHashV0",
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode())
    }
}

/// The standard P2PKH-ecdsa-secp256k1 payment script (dcrd
/// `putPaymentScript` on the P2PKH type).
fn p2pkh_payment_script(hash: &[u8; HASH160_SIZE]) -> [u8; P2PKH_PAYMENT_SCRIPT_LEN] {
    let mut script = [0u8; P2PKH_PAYMENT_SCRIPT_LEN];
    script[0] = OP_DUP;
    script[1] = OP_HASH160;
    script[2] = OP_DATA_20;
    script[3..23].copy_from_slice(hash);
    script[23] = OP_EQUALVERIFY;
    script[24] = OP_CHECKSIG;
    script
}

/// The alt-signature P2PKH payment script:
/// `DUP HASH160 <hash> EQUALVERIFY <sigtype> CHECKSIGALT`.
fn p2pkh_alt_payment_script(hash: &[u8; HASH160_SIZE], sig_type_op: u8) -> [u8; 26] {
    let mut script = [0u8; 26];
    script[0] = OP_DUP;
    script[1] = OP_HASH160;
    script[2] = OP_DATA_20;
    script[3..23].copy_from_slice(hash);
    script[23] = OP_EQUALVERIFY;
    script[24] = sig_type_op;
    script[25] = OP_CHECKSIGALT;
    script
}

/// The standard P2SH payment script (dcrd `putPaymentScript` on the P2SH
/// type).
fn p2sh_payment_script(hash: &[u8; HASH160_SIZE]) -> [u8; P2SH_PAYMENT_SCRIPT_LEN] {
    let mut script = [0u8; P2SH_PAYMENT_SCRIPT_LEN];
    script[0] = OP_HASH160;
    script[1] = OP_DATA_20;
    script[2..22].copy_from_slice(hash);
    script[22] = OP_EQUAL;
    script
}

/// Whether the string looks like a version 0 base58 address by length and
/// alphabet (dcrd `probablyV0Base58Addr`).
fn probably_v0_base58_addr(s: &str) -> bool {
    // The possible lengths for supported version 0 addresses.
    if s.len() != 35 && s.len() != 53 {
        return false;
    }

    for r in s.chars() {
        if !('1'..='z').contains(&r)
            || r == 'I'
            || r == 'O'
            || r == 'l'
            || (r > '9' && r < 'A')
            || (r > 'Z' && r < 'a')
        {
            return false;
        }
    }

    true
}

/// Decode the string encoding of an address for the provided network (dcrd
/// `DecodeAddress`).
pub fn decode_address(addr: &str, params: &dyn AddressParamsV0) -> Result<Address, AddrError> {
    if probably_v0_base58_addr(addr) {
        return decode_address_v0(addr, params);
    }

    Err(make_error(
        AddrErrorKind::UnsupportedAddress,
        format!(
            "address {} is not a supported type",
            goquote::go_quote(addr.as_bytes())
        ),
    ))
}

/// Decode the string encoding of a version 0 address for the provided
/// network (dcrd `DecodeAddressV0`), with dcrd's exact error kinds.
pub fn decode_address_v0(addr: &str, params: &dyn AddressParamsV0) -> Result<Address, AddrError> {
    // The largest supported decoded data is 33 bytes for the public key
    // plus 2 network bytes and 4 checksum bytes; base58 expands by
    // log_58(256) ~= 1.37.
    const MAX_V0_ADDR_LEN: usize = 54;
    if addr.len() > MAX_V0_ADDR_LEN {
        // dcrd slices the first bytes, `addr[:maxV0AddrLen]`, which can
        // split a multibyte rune; `%q` then spells the stray bytes `\xNN`.
        let prefix = &addr.as_bytes()[..MAX_V0_ADDR_LEN];
        return Err(make_error(
            AddrErrorKind::MalformedAddress,
            format!(
                "failed to decode address {}...: len {} exceeds max allowed {MAX_V0_ADDR_LEN}",
                goquote::go_quote(prefix),
                addr.len()
            ),
        ));
    }

    let (mut decoded, addr_id) = match dcroxide_base58::check_decode(addr) {
        Ok(result) => result,
        Err(err) => {
            let kind = match err {
                dcroxide_base58::CheckError::Checksum => AddrErrorKind::BadAddressChecksum,
                dcroxide_base58::CheckError::InvalidFormat => AddrErrorKind::MalformedAddress,
            };
            return Err(make_error(
                kind,
                format!(
                    "failed to decode address {}: {err}",
                    goquote::go_quote(addr.as_bytes())
                ),
            ));
        }
    };

    if addr_id == params.addr_id_script_hash_v0() {
        return new_address_script_hash_v0_from_hash(&decoded, params);
    }
    if addr_id == params.addr_id_pub_key_hash_ecdsa_v0() {
        return new_address_pub_key_hash_ecdsa_secp256k1_v0(&decoded, params);
    }
    if addr_id == params.addr_id_pub_key_hash_schnorr_v0() {
        return new_address_pub_key_hash_schnorr_secp256k1_v0(&decoded, params);
    }
    if addr_id == params.addr_id_pub_key_hash_ed25519_v0() {
        return new_address_pub_key_hash_ed25519_v0(&decoded, params);
    }
    if addr_id == params.addr_id_pub_key_v0() {
        // The decoded data must have the signature type identifier byte.
        if decoded.is_empty() {
            return Err(make_error(
                AddrErrorKind::MalformedAddressData,
                format!(
                    "address {} decoded data is empty",
                    goquote::go_quote(addr.as_bytes())
                ),
            ));
        }

        let sig_type = decoded[0] & !SIG_TYPE_SECP256K1_PUB_KEY_COMP_ODD_FLAG;
        match sig_type {
            0 | 2 => {
                // secp256k1 (ECDSA or Schnorr): a 32-byte X coordinate with
                // the Y oddness in the high bit of the first byte;
                // reconstruct the compressed serialization.
                const REQ_PUB_KEY_LEN: usize = 33;
                if decoded.len() != REQ_PUB_KEY_LEN {
                    return Err(make_error(
                        AddrErrorKind::MalformedAddressData,
                        format!(
                            "public key is {} bytes vs required {REQ_PUB_KEY_LEN} bytes",
                            decoded.len()
                        ),
                    ));
                }
                let is_odd_y = decoded[0] & SIG_TYPE_SECP256K1_PUB_KEY_COMP_ODD_FLAG != 0;
                decoded[0] = if is_odd_y { 0x03 } else { 0x02 };
                if sig_type == 0 {
                    return new_address_pub_key_ecdsa_secp256k1_v0_raw(&decoded, params);
                }
                return new_address_pub_key_schnorr_secp256k1_v0_raw(&decoded, params);
            }
            1 => {
                // Ed25519: the encoded data is the public key itself.
                const REQ_PUB_KEY_LEN: usize = 32;
                let pub_key = &decoded[1..];
                if pub_key.len() != REQ_PUB_KEY_LEN {
                    return Err(make_error(
                        AddrErrorKind::MalformedAddressData,
                        format!(
                            "public key is {} bytes vs required {REQ_PUB_KEY_LEN} bytes",
                            pub_key.len()
                        ),
                    ));
                }
                return new_address_pub_key_ed25519_v0_raw(pub_key, params);
            }
            _ => {}
        }
    }

    Err(make_error(
        AddrErrorKind::UnsupportedAddress,
        format!(
            "address {} is not a supported type",
            goquote::go_quote(addr.as_bytes())
        ),
    ))
}

/// Go's `strconv.Quote` (the `%q` verb dcrd formats addresses with), so an
/// address that fails to decode is echoed in dcrd's spelling: Rust's
/// `{:?}` writes `\u{1}` where Go writes `\x01`.  A copy of
/// `dcroxide_dcrjson::gojson::go_quote` and its `strconv.IsPrint` tables
/// (Go 1.26.5), which this `no_std` crate cannot depend on; keep the two
/// in step when the parity toolchain moves.
mod goquote {
    use alloc::format;
    use alloc::string::String;

    /// Quote bytes exactly like Go's `strconv.Quote` of `string(s)`:
    /// `appendQuotedWith` over `appendEscapedRune` (`strconv/quote.go`).
    ///
    /// A double quote and a backslash are backslashed, and every rune
    /// `strconv.IsPrint` accepts is kept.  Otherwise the seven C escapes
    /// are named (`\a \b \f \n \r \t \v`), the other ASCII controls
    /// and DEL are `\xNN`, and every other rune is `\uNNNN` or
    /// `\UNNNNNNNN`.  A byte that begins no valid UTF-8 encoding is
    /// `\xNN` too: Go decodes it as a width-one `RuneError`, and each
    /// byte of an invalid sequence does the same in turn.
    pub(super) fn go_quote(s: &[u8]) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        for chunk in s.utf8_chunks() {
            for c in chunk.valid().chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    c if is_print(c) => out.push(c),
                    '\u{07}' => out.push_str("\\a"),
                    '\u{08}' => out.push_str("\\b"),
                    '\u{0c}' => out.push_str("\\f"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    '\u{0b}' => out.push_str("\\v"),
                    c if c < ' ' || c == '\u{7f}' => {
                        out.push_str(&format!("\\x{:02x}", u32::from(c)));
                    }
                    c if u32::from(c) < 0x1_0000 => {
                        out.push_str(&format!("\\u{:04x}", u32::from(c)));
                    }
                    c => out.push_str(&format!("\\U{:08x}", u32::from(c))),
                }
            }
            for b in chunk.invalid() {
                out.push_str(&format!("\\x{b:02x}"));
            }
        }
        out.push('"');
        out
    }

    /// Byte strings that are not valid UTF-8, quoted as Go quotes them
    /// (expected values from running Go): each byte of an invalid
    /// sequence, a lone continuation byte, a surrogate encoding and a
    /// truncated rune is `\xNN`, while valid runes around them are kept.
    #[cfg(test)]
    #[test]
    fn invalid_utf8_is_quoted_byte_by_byte_like_go() {
        assert_eq!(
            go_quote(b"a\xe2\x82b\xff\xed\xa0\x80"),
            "\"a\\xe2\\x82b\\xff\\xed\\xa0\\x80\""
        );
        assert_eq!(go_quote("\u{e9}".as_bytes()), "\"\u{e9}\"");
        assert_eq!(go_quote(&"\u{e9}".as_bytes()[..1]), "\"\\xc3\"");
    }

    /// Go `strconv.IsPrint`.
    fn is_print(r: char) -> bool {
        let r = u32::from(r);
        // Fast check for Latin-1.
        if r <= 0xff {
            if (0x20..=0x7e).contains(&r) {
                // All the ASCII is printable from space through DEL-1.
                return true;
            }
            if (0xa1..=0xff).contains(&r) {
                // Similarly for U+00A1 through U+00FF, except for the
                // soft hyphen.
                return r != 0xad;
            }
            return false;
        }

        // Find the first i such that IS_PRINT[i] >= r: the start (even i)
        // or the end (odd i) of a pair that might span r.  In a range, r
        // is printable unless it is in the not-printable list.
        if let Ok(rr) = u16::try_from(r) {
            let i = IS_PRINT16.partition_point(|&v| v < rr);
            if i >= IS_PRINT16.len() || rr < IS_PRINT16[i & !1] || IS_PRINT16[i | 1] < rr {
                return false;
            }
            return IS_NOT_PRINT16.binary_search(&rr).is_err();
        }

        let i = IS_PRINT32.partition_point(|&v| v < r);
        if i >= IS_PRINT32.len() || r < IS_PRINT32[i & !1] || IS_PRINT32[i | 1] < r {
            return false;
        }
        if r >= 0x20000 {
            return true;
        }
        // The 32-bit exception list stores each rune less 0x10000, which
        // fits 16 bits below 0x20000 (Go's `uint16(r)`).
        let rr = (r - 0x10000) as u16;
        IS_NOT_PRINT32.binary_search(&rr).is_err()
    }

    /// Go `isPrint16`: inclusive ranges of printable BMP runes, as pairs.
    #[rustfmt::skip]
    static IS_PRINT16: [u16; 424] = [
        0x0020, 0x007e, 0x00a1, 0x0377, 0x037a, 0x037f, 0x0384, 0x0556,
        0x0559, 0x058a, 0x058d, 0x05c7, 0x05d0, 0x05ea, 0x05ef, 0x05f4,
        0x0606, 0x070d, 0x0710, 0x074a, 0x074d, 0x07b1, 0x07c0, 0x07fa,
        0x07fd, 0x082d, 0x0830, 0x085b, 0x085e, 0x086a, 0x0870, 0x088e,
        0x0898, 0x098c, 0x098f, 0x0990, 0x0993, 0x09b2, 0x09b6, 0x09b9,
        0x09bc, 0x09c4, 0x09c7, 0x09c8, 0x09cb, 0x09ce, 0x09d7, 0x09d7,
        0x09dc, 0x09e3, 0x09e6, 0x09fe, 0x0a01, 0x0a0a, 0x0a0f, 0x0a10,
        0x0a13, 0x0a39, 0x0a3c, 0x0a42, 0x0a47, 0x0a48, 0x0a4b, 0x0a4d,
        0x0a51, 0x0a51, 0x0a59, 0x0a5e, 0x0a66, 0x0a76, 0x0a81, 0x0ab9,
        0x0abc, 0x0acd, 0x0ad0, 0x0ad0, 0x0ae0, 0x0ae3, 0x0ae6, 0x0af1,
        0x0af9, 0x0b0c, 0x0b0f, 0x0b10, 0x0b13, 0x0b39, 0x0b3c, 0x0b44,
        0x0b47, 0x0b48, 0x0b4b, 0x0b4d, 0x0b55, 0x0b57, 0x0b5c, 0x0b63,
        0x0b66, 0x0b77, 0x0b82, 0x0b8a, 0x0b8e, 0x0b95, 0x0b99, 0x0b9f,
        0x0ba3, 0x0ba4, 0x0ba8, 0x0baa, 0x0bae, 0x0bb9, 0x0bbe, 0x0bc2,
        0x0bc6, 0x0bcd, 0x0bd0, 0x0bd0, 0x0bd7, 0x0bd7, 0x0be6, 0x0bfa,
        0x0c00, 0x0c39, 0x0c3c, 0x0c4d, 0x0c55, 0x0c5a, 0x0c5d, 0x0c5d,
        0x0c60, 0x0c63, 0x0c66, 0x0c6f, 0x0c77, 0x0cb9, 0x0cbc, 0x0ccd,
        0x0cd5, 0x0cd6, 0x0cdd, 0x0ce3, 0x0ce6, 0x0cf3, 0x0d00, 0x0d4f,
        0x0d54, 0x0d63, 0x0d66, 0x0d96, 0x0d9a, 0x0dbd, 0x0dc0, 0x0dc6,
        0x0dca, 0x0dca, 0x0dcf, 0x0ddf, 0x0de6, 0x0def, 0x0df2, 0x0df4,
        0x0e01, 0x0e3a, 0x0e3f, 0x0e5b, 0x0e81, 0x0ebd, 0x0ec0, 0x0ed9,
        0x0edc, 0x0edf, 0x0f00, 0x0f6c, 0x0f71, 0x0fda, 0x1000, 0x10c7,
        0x10cd, 0x10cd, 0x10d0, 0x124d, 0x1250, 0x125d, 0x1260, 0x128d,
        0x1290, 0x12b5, 0x12b8, 0x12c5, 0x12c8, 0x1315, 0x1318, 0x135a,
        0x135d, 0x137c, 0x1380, 0x1399, 0x13a0, 0x13f5, 0x13f8, 0x13fd,
        0x1400, 0x169c, 0x16a0, 0x16f8, 0x1700, 0x1715, 0x171f, 0x1736,
        0x1740, 0x1753, 0x1760, 0x1773, 0x1780, 0x17dd, 0x17e0, 0x17e9,
        0x17f0, 0x17f9, 0x1800, 0x1819, 0x1820, 0x1878, 0x1880, 0x18aa,
        0x18b0, 0x18f5, 0x1900, 0x192b, 0x1930, 0x193b, 0x1940, 0x1940,
        0x1944, 0x196d, 0x1970, 0x1974, 0x1980, 0x19ab, 0x19b0, 0x19c9,
        0x19d0, 0x19da, 0x19de, 0x1a1b, 0x1a1e, 0x1a7c, 0x1a7f, 0x1a89,
        0x1a90, 0x1a99, 0x1aa0, 0x1aad, 0x1ab0, 0x1ace, 0x1b00, 0x1b4c,
        0x1b50, 0x1bf3, 0x1bfc, 0x1c37, 0x1c3b, 0x1c49, 0x1c4d, 0x1c88,
        0x1c90, 0x1cba, 0x1cbd, 0x1cc7, 0x1cd0, 0x1cfa, 0x1d00, 0x1f15,
        0x1f18, 0x1f1d, 0x1f20, 0x1f45, 0x1f48, 0x1f4d, 0x1f50, 0x1f7d,
        0x1f80, 0x1fd3, 0x1fd6, 0x1fef, 0x1ff2, 0x1ffe, 0x2010, 0x2027,
        0x2030, 0x205e, 0x2070, 0x2071, 0x2074, 0x209c, 0x20a0, 0x20c0,
        0x20d0, 0x20f0, 0x2100, 0x218b, 0x2190, 0x2426, 0x2440, 0x244a,
        0x2460, 0x2b73, 0x2b76, 0x2cf3, 0x2cf9, 0x2d27, 0x2d2d, 0x2d2d,
        0x2d30, 0x2d67, 0x2d6f, 0x2d70, 0x2d7f, 0x2d96, 0x2da0, 0x2e5d,
        0x2e80, 0x2ef3, 0x2f00, 0x2fd5, 0x2ff0, 0x2ffb, 0x3001, 0x3096,
        0x3099, 0x30ff, 0x3105, 0x31e3, 0x31f0, 0xa48c, 0xa490, 0xa4c6,
        0xa4d0, 0xa62b, 0xa640, 0xa6f7, 0xa700, 0xa7ca, 0xa7d0, 0xa7d9,
        0xa7f2, 0xa82c, 0xa830, 0xa839, 0xa840, 0xa877, 0xa880, 0xa8c5,
        0xa8ce, 0xa8d9, 0xa8e0, 0xa953, 0xa95f, 0xa97c, 0xa980, 0xa9d9,
        0xa9de, 0xaa36, 0xaa40, 0xaa4d, 0xaa50, 0xaa59, 0xaa5c, 0xaac2,
        0xaadb, 0xaaf6, 0xab01, 0xab06, 0xab09, 0xab0e, 0xab11, 0xab16,
        0xab20, 0xab6b, 0xab70, 0xabed, 0xabf0, 0xabf9, 0xac00, 0xd7a3,
        0xd7b0, 0xd7c6, 0xd7cb, 0xd7fb, 0xf900, 0xfa6d, 0xfa70, 0xfad9,
        0xfb00, 0xfb06, 0xfb13, 0xfb17, 0xfb1d, 0xfbc2, 0xfbd3, 0xfd8f,
        0xfd92, 0xfdc7, 0xfdcf, 0xfdcf, 0xfdf0, 0xfe19, 0xfe20, 0xfe6b,
        0xfe70, 0xfefc, 0xff01, 0xffbe, 0xffc2, 0xffc7, 0xffca, 0xffcf,
        0xffd2, 0xffd7, 0xffda, 0xffdc, 0xffe0, 0xffee, 0xfffc, 0xfffd,
    ];

    /// Go `isNotPrint16`: the BMP runes inside those ranges that are not
    /// printable.
    #[rustfmt::skip]
    static IS_NOT_PRINT16: [u16; 133] = [
        0x00ad, 0x038b, 0x038d, 0x03a2, 0x0530, 0x0590, 0x061c, 0x06dd,
        0x083f, 0x085f, 0x08e2, 0x0984, 0x09a9, 0x09b1, 0x09de, 0x0a04,
        0x0a29, 0x0a31, 0x0a34, 0x0a37, 0x0a3d, 0x0a5d, 0x0a84, 0x0a8e,
        0x0a92, 0x0aa9, 0x0ab1, 0x0ab4, 0x0ac6, 0x0aca, 0x0b00, 0x0b04,
        0x0b29, 0x0b31, 0x0b34, 0x0b5e, 0x0b84, 0x0b91, 0x0b9b, 0x0b9d,
        0x0bc9, 0x0c0d, 0x0c11, 0x0c29, 0x0c45, 0x0c49, 0x0c57, 0x0c8d,
        0x0c91, 0x0ca9, 0x0cb4, 0x0cc5, 0x0cc9, 0x0cdf, 0x0cf0, 0x0d0d,
        0x0d11, 0x0d45, 0x0d49, 0x0d80, 0x0d84, 0x0db2, 0x0dbc, 0x0dd5,
        0x0dd7, 0x0e83, 0x0e85, 0x0e8b, 0x0ea4, 0x0ea6, 0x0ec5, 0x0ec7,
        0x0ecf, 0x0f48, 0x0f98, 0x0fbd, 0x0fcd, 0x10c6, 0x1249, 0x1257,
        0x1259, 0x1289, 0x12b1, 0x12bf, 0x12c1, 0x12d7, 0x1311, 0x1680,
        0x176d, 0x1771, 0x180e, 0x191f, 0x1a5f, 0x1b7f, 0x1f58, 0x1f5a,
        0x1f5c, 0x1f5e, 0x1fb5, 0x1fc5, 0x1fdc, 0x1ff5, 0x208f, 0x2b96,
        0x2d26, 0x2da7, 0x2daf, 0x2db7, 0x2dbf, 0x2dc7, 0x2dcf, 0x2dd7,
        0x2ddf, 0x2e9a, 0x3040, 0x3130, 0x318f, 0x321f, 0xa7d2, 0xa7d4,
        0xa9ce, 0xa9ff, 0xab27, 0xab2f, 0xfb37, 0xfb3d, 0xfb3f, 0xfb42,
        0xfb45, 0xfe53, 0xfe67, 0xfe75, 0xffe7,
    ];

    /// Go `isPrint32`: inclusive ranges of printable supplementary-plane
    /// runes, as pairs.
    #[rustfmt::skip]
    static IS_PRINT32: [u32; 508] = [
        0x010000, 0x01004d, 0x010050, 0x01005d, 0x010080, 0x0100fa,
        0x010100, 0x010102, 0x010107, 0x010133, 0x010137, 0x01019c,
        0x0101a0, 0x0101a0, 0x0101d0, 0x0101fd, 0x010280, 0x01029c,
        0x0102a0, 0x0102d0, 0x0102e0, 0x0102fb, 0x010300, 0x010323,
        0x01032d, 0x01034a, 0x010350, 0x01037a, 0x010380, 0x0103c3,
        0x0103c8, 0x0103d5, 0x010400, 0x01049d, 0x0104a0, 0x0104a9,
        0x0104b0, 0x0104d3, 0x0104d8, 0x0104fb, 0x010500, 0x010527,
        0x010530, 0x010563, 0x01056f, 0x0105bc, 0x010600, 0x010736,
        0x010740, 0x010755, 0x010760, 0x010767, 0x010780, 0x0107ba,
        0x010800, 0x010805, 0x010808, 0x010838, 0x01083c, 0x01083c,
        0x01083f, 0x01089e, 0x0108a7, 0x0108af, 0x0108e0, 0x0108f5,
        0x0108fb, 0x01091b, 0x01091f, 0x010939, 0x01093f, 0x01093f,
        0x010980, 0x0109b7, 0x0109bc, 0x0109cf, 0x0109d2, 0x010a06,
        0x010a0c, 0x010a35, 0x010a38, 0x010a3a, 0x010a3f, 0x010a48,
        0x010a50, 0x010a58, 0x010a60, 0x010a9f, 0x010ac0, 0x010ae6,
        0x010aeb, 0x010af6, 0x010b00, 0x010b35, 0x010b39, 0x010b55,
        0x010b58, 0x010b72, 0x010b78, 0x010b91, 0x010b99, 0x010b9c,
        0x010ba9, 0x010baf, 0x010c00, 0x010c48, 0x010c80, 0x010cb2,
        0x010cc0, 0x010cf2, 0x010cfa, 0x010d27, 0x010d30, 0x010d39,
        0x010e60, 0x010ead, 0x010eb0, 0x010eb1, 0x010efd, 0x010f27,
        0x010f30, 0x010f59, 0x010f70, 0x010f89, 0x010fb0, 0x010fcb,
        0x010fe0, 0x010ff6, 0x011000, 0x01104d, 0x011052, 0x011075,
        0x01107f, 0x0110c2, 0x0110d0, 0x0110e8, 0x0110f0, 0x0110f9,
        0x011100, 0x011147, 0x011150, 0x011176, 0x011180, 0x0111f4,
        0x011200, 0x011241, 0x011280, 0x0112a9, 0x0112b0, 0x0112ea,
        0x0112f0, 0x0112f9, 0x011300, 0x01130c, 0x01130f, 0x011310,
        0x011313, 0x011344, 0x011347, 0x011348, 0x01134b, 0x01134d,
        0x011350, 0x011350, 0x011357, 0x011357, 0x01135d, 0x011363,
        0x011366, 0x01136c, 0x011370, 0x011374, 0x011400, 0x011461,
        0x011480, 0x0114c7, 0x0114d0, 0x0114d9, 0x011580, 0x0115b5,
        0x0115b8, 0x0115dd, 0x011600, 0x011644, 0x011650, 0x011659,
        0x011660, 0x01166c, 0x011680, 0x0116b9, 0x0116c0, 0x0116c9,
        0x011700, 0x01171a, 0x01171d, 0x01172b, 0x011730, 0x011746,
        0x011800, 0x01183b, 0x0118a0, 0x0118f2, 0x0118ff, 0x011906,
        0x011909, 0x011909, 0x01190c, 0x011938, 0x01193b, 0x011946,
        0x011950, 0x011959, 0x0119a0, 0x0119a7, 0x0119aa, 0x0119d7,
        0x0119da, 0x0119e4, 0x011a00, 0x011a47, 0x011a50, 0x011aa2,
        0x011ab0, 0x011af8, 0x011b00, 0x011b09, 0x011c00, 0x011c45,
        0x011c50, 0x011c6c, 0x011c70, 0x011c8f, 0x011c92, 0x011cb6,
        0x011d00, 0x011d36, 0x011d3a, 0x011d47, 0x011d50, 0x011d59,
        0x011d60, 0x011d98, 0x011da0, 0x011da9, 0x011ee0, 0x011ef8,
        0x011f00, 0x011f3a, 0x011f3e, 0x011f59, 0x011fb0, 0x011fb0,
        0x011fc0, 0x011ff1, 0x011fff, 0x012399, 0x012400, 0x012474,
        0x012480, 0x012543, 0x012f90, 0x012ff2, 0x013000, 0x01342f,
        0x013440, 0x013455, 0x014400, 0x014646, 0x016800, 0x016a38,
        0x016a40, 0x016a69, 0x016a6e, 0x016ac9, 0x016ad0, 0x016aed,
        0x016af0, 0x016af5, 0x016b00, 0x016b45, 0x016b50, 0x016b77,
        0x016b7d, 0x016b8f, 0x016e40, 0x016e9a, 0x016f00, 0x016f4a,
        0x016f4f, 0x016f87, 0x016f8f, 0x016f9f, 0x016fe0, 0x016fe4,
        0x016ff0, 0x016ff1, 0x017000, 0x0187f7, 0x018800, 0x018cd5,
        0x018d00, 0x018d08, 0x01aff0, 0x01b122, 0x01b132, 0x01b132,
        0x01b150, 0x01b152, 0x01b155, 0x01b155, 0x01b164, 0x01b167,
        0x01b170, 0x01b2fb, 0x01bc00, 0x01bc6a, 0x01bc70, 0x01bc7c,
        0x01bc80, 0x01bc88, 0x01bc90, 0x01bc99, 0x01bc9c, 0x01bc9f,
        0x01cf00, 0x01cf2d, 0x01cf30, 0x01cf46, 0x01cf50, 0x01cfc3,
        0x01d000, 0x01d0f5, 0x01d100, 0x01d126, 0x01d129, 0x01d172,
        0x01d17b, 0x01d1ea, 0x01d200, 0x01d245, 0x01d2c0, 0x01d2d3,
        0x01d2e0, 0x01d2f3, 0x01d300, 0x01d356, 0x01d360, 0x01d378,
        0x01d400, 0x01d49f, 0x01d4a2, 0x01d4a2, 0x01d4a5, 0x01d4a6,
        0x01d4a9, 0x01d50a, 0x01d50d, 0x01d546, 0x01d54a, 0x01d6a5,
        0x01d6a8, 0x01d7cb, 0x01d7ce, 0x01da8b, 0x01da9b, 0x01daaf,
        0x01df00, 0x01df1e, 0x01df25, 0x01df2a, 0x01e000, 0x01e018,
        0x01e01b, 0x01e02a, 0x01e030, 0x01e06d, 0x01e08f, 0x01e08f,
        0x01e100, 0x01e12c, 0x01e130, 0x01e13d, 0x01e140, 0x01e149,
        0x01e14e, 0x01e14f, 0x01e290, 0x01e2ae, 0x01e2c0, 0x01e2f9,
        0x01e2ff, 0x01e2ff, 0x01e4d0, 0x01e4f9, 0x01e7e0, 0x01e8c4,
        0x01e8c7, 0x01e8d6, 0x01e900, 0x01e94b, 0x01e950, 0x01e959,
        0x01e95e, 0x01e95f, 0x01ec71, 0x01ecb4, 0x01ed01, 0x01ed3d,
        0x01ee00, 0x01ee24, 0x01ee27, 0x01ee3b, 0x01ee42, 0x01ee42,
        0x01ee47, 0x01ee54, 0x01ee57, 0x01ee64, 0x01ee67, 0x01ee9b,
        0x01eea1, 0x01eebb, 0x01eef0, 0x01eef1, 0x01f000, 0x01f02b,
        0x01f030, 0x01f093, 0x01f0a0, 0x01f0ae, 0x01f0b1, 0x01f0f5,
        0x01f100, 0x01f1ad, 0x01f1e6, 0x01f202, 0x01f210, 0x01f23b,
        0x01f240, 0x01f248, 0x01f250, 0x01f251, 0x01f260, 0x01f265,
        0x01f300, 0x01f6d7, 0x01f6dc, 0x01f6ec, 0x01f6f0, 0x01f6fc,
        0x01f700, 0x01f776, 0x01f77b, 0x01f7d9, 0x01f7e0, 0x01f7eb,
        0x01f7f0, 0x01f7f0, 0x01f800, 0x01f80b, 0x01f810, 0x01f847,
        0x01f850, 0x01f859, 0x01f860, 0x01f887, 0x01f890, 0x01f8ad,
        0x01f8b0, 0x01f8b1, 0x01f900, 0x01fa53, 0x01fa60, 0x01fa6d,
        0x01fa70, 0x01fa7c, 0x01fa80, 0x01fa88, 0x01fa90, 0x01fac5,
        0x01face, 0x01fadb, 0x01fae0, 0x01fae8, 0x01faf0, 0x01faf8,
        0x01fb00, 0x01fbca, 0x01fbf0, 0x01fbf9, 0x020000, 0x02a6df,
        0x02a700, 0x02b739, 0x02b740, 0x02b81d, 0x02b820, 0x02cea1,
        0x02ceb0, 0x02ebe0, 0x02f800, 0x02fa1d, 0x030000, 0x03134a,
        0x031350, 0x0323af, 0x0e0100, 0x0e01ef,
    ];

    /// Go `isNotPrint32`: the supplementary-plane runes inside those ranges
    /// that are not printable, each stored less 0x10000.
    #[rustfmt::skip]
    static IS_NOT_PRINT32: [u16; 112] = [
        0x000c, 0x0027, 0x003b, 0x003e, 0x018f, 0x039e, 0x057b, 0x058b,
        0x0593, 0x0596, 0x05a2, 0x05b2, 0x05ba, 0x0786, 0x07b1, 0x0809,
        0x0836, 0x0856, 0x08f3, 0x0a04, 0x0a14, 0x0a18, 0x0e7f, 0x0eaa,
        0x10bd, 0x1135, 0x11e0, 0x1212, 0x1287, 0x1289, 0x128e, 0x129e,
        0x1304, 0x1329, 0x1331, 0x1334, 0x133a, 0x145c, 0x1914, 0x1917,
        0x1936, 0x1c09, 0x1c37, 0x1ca8, 0x1d07, 0x1d0a, 0x1d3b, 0x1d3e,
        0x1d66, 0x1d69, 0x1d8f, 0x1d92, 0x1f11, 0x246f, 0x6a5f, 0x6abf,
        0x6b5a, 0x6b62, 0xaff4, 0xaffc, 0xafff, 0xd455, 0xd49d, 0xd4ad,
        0xd4ba, 0xd4bc, 0xd4c4, 0xd506, 0xd515, 0xd51d, 0xd53a, 0xd53f,
        0xd545, 0xd551, 0xdaa0, 0xe007, 0xe022, 0xe025, 0xe7e7, 0xe7ec,
        0xe7ef, 0xe7ff, 0xee04, 0xee20, 0xee23, 0xee28, 0xee33, 0xee38,
        0xee3a, 0xee48, 0xee4a, 0xee4c, 0xee50, 0xee53, 0xee58, 0xee5a,
        0xee5c, 0xee5e, 0xee60, 0xee63, 0xee6b, 0xee73, 0xee78, 0xee7d,
        0xee7f, 0xee8a, 0xeea4, 0xeeaa, 0xf0c0, 0xf0d0, 0xfabe, 0xfb93,
    ];
}
