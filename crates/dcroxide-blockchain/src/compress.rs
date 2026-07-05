// SPDX-License-Identifier: ISC
//! Domain-specific compression for stored scripts and amounts (dcrd
//! internal/blockchain `compress.go`).
//!
//! The variable-length quantity (VLQ) is an MSB base-128 encoding with
//! an offset subtracted per 7-bit group so every integer has exactly
//! one representation.  Script compression recognizes the standard
//! pay-to-pubkey-hash, pay-to-script-hash, and pay-to-pubkey forms and
//! stores them in 21 or 33 bytes; everything else is stored raw behind
//! a VLQ of `length + 64`.  Amounts use a base-10 exponent scheme
//! lifted from Bitcoin Core.

use alloc::vec;
use alloc::vec::Vec;

use dcroxide_dcrec::secp256k1::PublicKey;
use dcroxide_stake::TxType;

use crate::error::{Error, deserialize_error};

/// The current UTXO compression version (dcrd
/// `currentCompressionVersion`).
pub const CURRENT_COMPRESSION_VERSION: u32 = 1;

// -----------------------------------------------------------------------
// Variable length quantities.
// -----------------------------------------------------------------------

/// The number of bytes serializing `n` as a VLQ takes (dcrd
/// `serializeSizeVLQ`).
pub fn serialize_size_vlq(mut n: u64) -> usize {
    let mut size = 1;
    while n > 0x7f {
        size += 1;
        n = (n >> 7) - 1;
    }
    size
}

/// Serialize `n` as a VLQ into the target, which must be large enough
/// per [`serialize_size_vlq`]; returns the bytes written (dcrd
/// `putVLQ`).
pub fn put_vlq(target: &mut [u8], mut n: u64) -> usize {
    let mut offset = 0;
    loop {
        // The high bit is set when another byte follows.
        let high_bit_mask: u8 = if offset == 0 { 0x00 } else { 0x80 };
        target[offset] = (n & 0x7f) as u8 | high_bit_mask;
        if n <= 0x7f {
            break;
        }
        n = (n >> 7) - 1;
        offset += 1;
    }

    // Reverse the bytes so it is MSB-encoded.
    target[..=offset].reverse();
    offset + 1
}

/// Deserialize a VLQ, returning the value and the number of bytes read
/// (zero when the input is empty) (dcrd `deserializeVLQ`).
pub fn deserialize_vlq(serialized: &[u8]) -> (u64, usize) {
    let mut n: u64 = 0;
    let mut size = 0;
    for &val in serialized {
        size += 1;
        n = (n << 7) | u64::from(val & 0x7f);
        if val & 0x80 != 0x80 {
            break;
        }
        n += 1;
    }
    (n, size)
}

// -----------------------------------------------------------------------
// Script compression.
// -----------------------------------------------------------------------

/// Compressed script type: pay-to-pubkey-hash (dcrd
/// `cstPayToPubKeyHash`).
const CST_PAY_TO_PUB_KEY_HASH: u64 = 0;
/// Compressed script type: pay-to-script-hash.
const CST_PAY_TO_SCRIPT_HASH: u64 = 1;
/// Compressed script type: pay-to-pubkey, compressed key, even y.
const CST_PAY_TO_PUB_KEY_COMP_EVEN: u64 = 2;
/// Compressed script type: pay-to-pubkey, compressed key, odd y.
const CST_PAY_TO_PUB_KEY_COMP_ODD: u64 = 3;
/// Compressed script type: pay-to-pubkey, uncompressed key, even y.
const CST_PAY_TO_PUB_KEY_UNCOMP_EVEN: u64 = 4;
/// Compressed script type: pay-to-pubkey, uncompressed key, odd y.
const CST_PAY_TO_PUB_KEY_UNCOMP_ODD: u64 = 5;
/// The number of special script types reserved by the encoding (dcrd
/// `numSpecialScripts`).
const NUM_SPECIAL_SCRIPTS: u64 = 64;

// Opcode values used by the raw byte-pattern matching below; defined
// here like dcrd does (via txscript there) to keep the matching
// byte-exact and independent of higher-level script analysis.
const OP_DUP: u8 = 0x76;
const OP_HASH160: u8 = 0xa9;
const OP_DATA_20: u8 = 0x14;
const OP_DATA_33: u8 = 0x21;
const OP_DATA_65: u8 = 0x41;
const OP_EQUAL: u8 = 0x87;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_CHECKSIG: u8 = 0xac;

/// The pubkey hash when the script is a standard P2PKH (dcrd
/// `extractPubKeyHash`).
pub(crate) fn extract_pub_key_hash(script: &[u8]) -> Option<&[u8]> {
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

/// The script hash when the script is a standard P2SH (dcrd
/// `extractScriptHash`).
pub(crate) fn extract_script_hash(script: &[u8]) -> Option<&[u8]> {
    if script.len() == 23
        && script[0] == OP_HASH160
        && script[1] == OP_DATA_20
        && script[22] == OP_EQUAL
    {
        return Some(&script[2..22]);
    }
    None
}

/// The serialized pubkey when the script is a standard P2PK paying to a
/// valid secp256k1 key (dcrd `isPubKey`).
fn is_pub_key(script: &[u8]) -> Option<&[u8]> {
    // Pay-to-compressed-pubkey.
    if script.len() == 35
        && script[0] == OP_DATA_33
        && script[34] == OP_CHECKSIG
        && (script[1] == 0x02 || script[1] == 0x03)
    {
        let serialized = &script[1..34];
        if PublicKey::parse(serialized).is_ok() {
            return Some(serialized);
        }
    }

    // Pay-to-uncompressed-pubkey.
    if script.len() == 67
        && script[0] == OP_DATA_65
        && script[66] == OP_CHECKSIG
        && script[1] == 0x04
    {
        let serialized = &script[1..66];
        if PublicKey::parse(serialized).is_ok() {
            return Some(serialized);
        }
    }

    None
}

/// The number of bytes the script would take when compressed (dcrd
/// `compressedScriptSize`).
pub fn compressed_script_size(_script_version: u16, pk_script: &[u8]) -> usize {
    if extract_pub_key_hash(pk_script).is_some() || extract_script_hash(pk_script).is_some() {
        return 21;
    }
    if is_pub_key(pk_script).is_some() {
        return 33;
    }

    // When none of the special cases apply, encode the script as-is
    // preceded by its size shifted past the special encodings.
    serialize_size_vlq(pk_script.len() as u64 + NUM_SPECIAL_SCRIPTS) + pk_script.len()
}

/// The number of bytes the compressed script starting at the front of
/// the serialized data occupies (dcrd `decodeCompressedScriptSize`).
pub fn decode_compressed_script_size(serialized: &[u8]) -> usize {
    let (script_size, bytes_read) = deserialize_vlq(serialized);
    if bytes_read == 0 {
        return 0;
    }

    match script_size {
        CST_PAY_TO_PUB_KEY_HASH | CST_PAY_TO_SCRIPT_HASH => 21,
        CST_PAY_TO_PUB_KEY_COMP_EVEN
        | CST_PAY_TO_PUB_KEY_COMP_ODD
        | CST_PAY_TO_PUB_KEY_UNCOMP_EVEN
        | CST_PAY_TO_PUB_KEY_UNCOMP_ODD => 33,
        _ => (script_size - NUM_SPECIAL_SCRIPTS) as usize + bytes_read,
    }
}

/// Compress the script into the target, which must be large enough per
/// [`compressed_script_size`]; returns the bytes written (dcrd
/// `putCompressedScript`).
///
/// Note: dcrd's implementation begins with a dead `len(target) == 0`
/// branch that would panic if it were ever reached (it indexes the
/// empty slice); callers always size the target from
/// `compressedScriptSize`, which is at least one byte, so the branch is
/// unreachable and deliberately not reproduced.
pub fn put_compressed_script(target: &mut [u8], _script_version: u16, pk_script: &[u8]) -> usize {
    // Pay-to-pubkey-hash script.
    if let Some(hash) = extract_pub_key_hash(pk_script) {
        target[0] = CST_PAY_TO_PUB_KEY_HASH as u8;
        target[1..21].copy_from_slice(hash);
        return 21;
    }

    // Pay-to-script-hash script.
    if let Some(hash) = extract_script_hash(pk_script) {
        target[0] = CST_PAY_TO_SCRIPT_HASH as u8;
        target[1..21].copy_from_slice(hash);
        return 21;
    }

    // Pay-to-pubkey (compressed or uncompressed) script.
    if let Some(serialized_pub_key) = is_pub_key(pk_script) {
        match serialized_pub_key[0] {
            0x02 | 0x03 => {
                target[0] = if serialized_pub_key[0] == 0x02 {
                    CST_PAY_TO_PUB_KEY_COMP_EVEN as u8
                } else {
                    CST_PAY_TO_PUB_KEY_COMP_ODD as u8
                };
                target[1..33].copy_from_slice(&serialized_pub_key[1..33]);
                return 33;
            }
            0x04 => {
                target[0] = if serialized_pub_key[64] & 0x01 == 0x01 {
                    CST_PAY_TO_PUB_KEY_UNCOMP_ODD as u8
                } else {
                    CST_PAY_TO_PUB_KEY_UNCOMP_EVEN as u8
                };
                target[1..33].copy_from_slice(&serialized_pub_key[1..33]);
                return 33;
            }
            _ => {}
        }
    }

    // When none of the special cases apply, encode the unmodified
    // script preceded by its size shifted past the special encodings.
    let encoded_size = pk_script.len() as u64 + NUM_SPECIAL_SCRIPTS;
    let vlq_size_len = put_vlq(target, encoded_size);
    target[vlq_size_len..vlq_size_len + pk_script.len()].copy_from_slice(pk_script);
    vlq_size_len + pk_script.len()
}

/// Decompress the passed compressed script back into its original form
/// (dcrd `decompressScript`); an empty input or an uncompressed-pubkey
/// form whose key fails to parse yields an empty script (dcrd returns
/// nil for both).
pub fn decompress_script(compressed_pk_script: &[u8]) -> Vec<u8> {
    // Empty scripts, specified by 0x00, are considered nil.
    if compressed_pk_script.is_empty() {
        return Vec::new();
    }

    let (encoded_script_size, bytes_read) = deserialize_vlq(compressed_pk_script);
    match encoded_script_size {
        // Pay-to-pubkey-hash script.
        CST_PAY_TO_PUB_KEY_HASH => {
            let mut pk_script = vec![0u8; 25];
            pk_script[0] = OP_DUP;
            pk_script[1] = OP_HASH160;
            pk_script[2] = OP_DATA_20;
            pk_script[3..23].copy_from_slice(&compressed_pk_script[bytes_read..bytes_read + 20]);
            pk_script[23] = OP_EQUALVERIFY;
            pk_script[24] = OP_CHECKSIG;
            pk_script
        }

        // Pay-to-script-hash script.
        CST_PAY_TO_SCRIPT_HASH => {
            let mut pk_script = vec![0u8; 23];
            pk_script[0] = OP_HASH160;
            pk_script[1] = OP_DATA_20;
            pk_script[2..22].copy_from_slice(&compressed_pk_script[bytes_read..bytes_read + 20]);
            pk_script[22] = OP_EQUAL;
            pk_script
        }

        // Pay-to-compressed-pubkey script.
        CST_PAY_TO_PUB_KEY_COMP_EVEN | CST_PAY_TO_PUB_KEY_COMP_ODD => {
            let mut pk_script = vec![0u8; 35];
            pk_script[0] = OP_DATA_33;
            pk_script[1] = if encoded_script_size == CST_PAY_TO_PUB_KEY_COMP_ODD {
                0x03
            } else {
                0x02
            };
            pk_script[2..34].copy_from_slice(&compressed_pk_script[bytes_read..bytes_read + 32]);
            pk_script[34] = OP_CHECKSIG;
            pk_script
        }

        // Pay-to-uncompressed-pubkey script.
        CST_PAY_TO_PUB_KEY_UNCOMP_EVEN | CST_PAY_TO_PUB_KEY_UNCOMP_ODD => {
            // Change the leading byte to the appropriate compressed
            // pubkey identifier so it can be decoded as a compressed
            // pubkey, then decompress the point to recover the full
            // uncompressed form.
            let mut compressed_key = [0u8; 33];
            compressed_key[0] = if encoded_script_size == CST_PAY_TO_PUB_KEY_UNCOMP_ODD {
                0x03
            } else {
                0x02
            };
            compressed_key[1..].copy_from_slice(&compressed_pk_script[1..33]);
            let Ok(key) = PublicKey::parse(&compressed_key) else {
                return Vec::new();
            };

            let mut pk_script = vec![0u8; 67];
            pk_script[0] = OP_DATA_65;
            pk_script[1..66].copy_from_slice(&key.serialize_uncompressed());
            pk_script[66] = OP_CHECKSIG;
            pk_script
        }

        // When none of the special cases apply, the script was encoded
        // using the general format: return the unmodified script.
        _ => {
            let script_size = (encoded_script_size - NUM_SPECIAL_SCRIPTS) as usize;
            compressed_pk_script[bytes_read..bytes_read + script_size].to_vec()
        }
    }
}

// -----------------------------------------------------------------------
// Amount compression.
// -----------------------------------------------------------------------

/// Compress a transaction output amount (dcrd `compressTxOutAmount`).
pub fn compress_tx_out_amount(mut amount: u64) -> u64 {
    // No need to do any work if it's zero.
    if amount == 0 {
        return 0;
    }

    // Find the largest power of 10 (max of 9) that evenly divides the
    // value.
    let mut exponent: u64 = 0;
    while amount % 10 == 0 && exponent < 9 {
        amount /= 10;
        exponent += 1;
    }

    // The compressed result for exponents less than 9 is:
    // 1 + 10*(9*n + d-1) + e
    if exponent < 9 {
        let last_digit = amount % 10;
        amount /= 10;
        return 1 + 10 * (9 * amount + last_digit - 1) + exponent;
    }

    // The compressed result for an exponent of 9 is: 10 + 10*(n-1)
    10 + 10 * (amount - 1)
}

/// Decompress a compressed transaction output amount (dcrd
/// `decompressTxOutAmount`).
pub fn decompress_tx_out_amount(mut amount: u64) -> u64 {
    // No need to do any work if it's zero.
    if amount == 0 {
        return 0;
    }

    // The decompressed amount is either of the following two equations:
    // x = 1 + 10*(9*n + d - 1) + e
    // x = 1 + 10*(n - 1)       + 9
    amount -= 1;

    // The decompressed amount is now one of the following two equations:
    // x = 10*(9*n + d - 1) + e
    // x = 10*(n - 1)       + 9
    let exponent = amount % 10;
    amount /= 10;

    let mut n: u64;
    if exponent < 9 {
        let last_digit = amount % 9 + 1;
        amount /= 9;
        n = amount * 10 + last_digit;
    } else {
        n = amount + 1;
    }

    // Apply the exponent.
    for _ in 0..exponent {
        n *= 10;
    }

    n
}

// -----------------------------------------------------------------------
// Compressed transaction outputs.
// -----------------------------------------------------------------------

/// The number of bytes the passed transaction output fields would take
/// when compressed (dcrd `compressedTxOutSize`).
pub fn compressed_tx_out_size(
    amount: u64,
    script_version: u16,
    pk_script: &[u8],
    has_amount: bool,
) -> usize {
    let script_version_size = serialize_size_vlq(u64::from(script_version));
    if !has_amount {
        return script_version_size + compressed_script_size(script_version, pk_script);
    }

    script_version_size
        + serialize_size_vlq(compress_tx_out_amount(amount))
        + compressed_script_size(script_version, pk_script)
}

/// Compress the transaction output fields into the target, which must
/// be large enough per [`compressed_tx_out_size`]; returns the bytes
/// written (dcrd `putCompressedTxOut`).
pub fn put_compressed_tx_out(
    target: &mut [u8],
    amount: u64,
    script_version: u16,
    pk_script: &[u8],
    has_amount: bool,
) -> usize {
    if !has_amount {
        let mut offset = put_vlq(target, u64::from(script_version));
        offset += put_compressed_script(&mut target[offset..], script_version, pk_script);
        return offset;
    }

    let mut offset = put_vlq(target, compress_tx_out_amount(amount));
    offset += put_vlq(&mut target[offset..], u64::from(script_version));
    offset += put_compressed_script(&mut target[offset..], script_version, pk_script);
    offset
}

/// Decode a compressed transaction output from the front of the
/// serialized bytes, returning the amount, script version, script, and
/// the number of bytes consumed (dcrd `decodeCompressedTxOut`).
pub fn decode_compressed_tx_out(
    serialized: &[u8],
    has_amount: bool,
) -> Result<(i64, u16, Vec<u8>, usize), Error> {
    let mut amount: i64 = 0;
    let mut offset = 0;

    // Deserialize the compressed amount when expected and decompress
    // it.
    if has_amount {
        let (compressed_amount, bytes_read) = deserialize_vlq(serialized);
        if bytes_read == 0 {
            return Err(deserialize_error(
                "unexpected end of data during decoding (compressed amount)",
            ));
        }
        amount = decompress_tx_out_amount(compressed_amount) as i64;
        offset += bytes_read;
    }

    // Deserialize the script version.
    let (script_version, bytes_read) = deserialize_vlq(&serialized[offset..]);
    if bytes_read == 0 {
        return Err(deserialize_error(
            "unexpected end of data during decoding (script version)",
        ));
    }
    offset += bytes_read;

    // Decode the compressed script size and ensure there are enough
    // bytes left in the slice for it.
    let script_size = decode_compressed_script_size(&serialized[offset..]);
    if serialized[offset..].len() < script_size {
        return Err(deserialize_error(alloc::format!(
            "unexpected end of data after script size (got {}, need {})",
            serialized[offset..].len(),
            script_size,
        )));
    }

    // Decompress the script.
    let script = decompress_script(&serialized[offset..offset + script_size]);
    Ok((amount, script_version as u16, script, offset + script_size))
}

// -----------------------------------------------------------------------
// Transaction output flags.
// -----------------------------------------------------------------------

/// Bit 0 of the serialized txout flags: output is from a coinbase (dcrd
/// `txOutFlagCoinBase`).
const TX_OUT_FLAG_COIN_BASE: u8 = 1 << 0;
/// Bit 1: the containing transaction has an expiry.
const TX_OUT_FLAG_HAS_EXPIRY: u8 = 1 << 1;
/// Bits 2-5: the stake transaction type of the containing transaction.
const TX_OUT_FLAG_TX_TYPE_BITMASK: u8 = 0x3c;
const TX_OUT_FLAG_TX_TYPE_SHIFT: u8 = 2;

/// Encode the serialized txout flags byte (dcrd `encodeFlags`).
pub fn encode_flags(is_coin_base: bool, has_expiry: bool, tx_type: TxType) -> u8 {
    let mut b = (tx_type as u8) << TX_OUT_FLAG_TX_TYPE_SHIFT;
    if is_coin_base {
        b |= TX_OUT_FLAG_COIN_BASE;
    }
    if has_expiry {
        b |= TX_OUT_FLAG_HAS_EXPIRY;
    }
    b
}

/// Decode the serialized txout flags byte into (is coinbase, has
/// expiry, raw stake transaction type value) (dcrd `decodeFlags`).
/// The type is returned as a raw value because, like dcrd's
/// `stake.TxType` cast, values beyond the defined ones survive the
/// round trip.
pub fn decode_flags(flags: u8) -> (bool, bool, u8) {
    let is_coin_base = flags & TX_OUT_FLAG_COIN_BASE == TX_OUT_FLAG_COIN_BASE;
    let has_expiry = flags & TX_OUT_FLAG_HAS_EXPIRY == TX_OUT_FLAG_HAS_EXPIRY;
    let tx_type = (flags & TX_OUT_FLAG_TX_TYPE_BITMASK) >> TX_OUT_FLAG_TX_TYPE_SHIFT;
    (is_coin_base, has_expiry, tx_type)
}
