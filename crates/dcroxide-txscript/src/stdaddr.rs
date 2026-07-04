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
            format!("failed to parse public key: {err:?}"),
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
            format!("failed to parse public key: {err:?}"),
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
            format!("failed to parse public key: {err:?}"),
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
        format!("address {addr:?} is not a supported type"),
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
        let prefix: String = addr.chars().take(MAX_V0_ADDR_LEN).collect();
        return Err(make_error(
            AddrErrorKind::MalformedAddress,
            format!(
                "failed to decode address {prefix:?}...: len {} exceeds max allowed {MAX_V0_ADDR_LEN}",
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
                format!("failed to decode address {addr:?}: {err}"),
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
                format!("address {addr:?} decoded data is empty"),
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
        format!("address {addr:?} is not a supported type"),
    ))
}
