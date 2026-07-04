// SPDX-License-Identifier: ISC
//! Strict-encoding checks and locktime constants (dcrd `consensus.go`),
//! including the exact DER signature validation order and error kinds.

use alloc::format;

use crate::error::{ErrorKind, ScriptError, script_error};
use crate::sighash::{SIG_HASH_ALL, SIG_HASH_ANY_ONE_CAN_PAY, SIG_HASH_SINGLE, SigHashType};

/// The number below which a lock time is interpreted to be a block number
/// (dcrd `LockTimeThreshold`).
pub const LOCK_TIME_THRESHOLD: i64 = 500_000_000; // Tue Nov 5 00:53:20 1985 UTC

/// The secp256k1 group half order, big-endian (for the low-S check).
const HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// The secp256k1 group order, big-endian.
const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Compare a stripped big-endian byte string against a 32-byte big-endian
/// constant; returns core::cmp::Ordering of value vs constant.
fn cmp_be(bytes: &[u8], constant: &[u8; 32]) -> core::cmp::Ordering {
    debug_assert!(bytes.len() <= 32);
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(bytes);
    padded.cmp(constant)
}

/// Returns an error unless the passed signature adheres to the strict DER
/// encoding requirements (dcrd `CheckSignatureEncoding`), with dcrd's exact
/// check order and error kinds.
pub fn check_signature_encoding(sig: &[u8]) -> Result<(), ScriptError> {
    const ASN1_SEQUENCE_ID: u8 = 0x30;
    const ASN1_INTEGER_ID: u8 = 0x02;
    // Minimum length: both R and S are 1 byte each.
    const MIN_SIG_LEN: usize = 8;
    // Maximum length: both R and S are 33 bytes each.
    const MAX_SIG_LEN: usize = 72;
    const SEQUENCE_OFFSET: usize = 0;
    const DATA_LEN_OFFSET: usize = 1;
    const R_TYPE_OFFSET: usize = 2;
    const R_LEN_OFFSET: usize = 3;
    const R_OFFSET: usize = 4;

    let sig_len = sig.len();
    if sig_len < MIN_SIG_LEN {
        return Err(script_error(
            ErrorKind::SigTooShort,
            format!("malformed signature: too short: {sig_len} < {MIN_SIG_LEN}"),
        ));
    }
    if sig_len > MAX_SIG_LEN {
        return Err(script_error(
            ErrorKind::SigTooLong,
            format!("malformed signature: too long: {sig_len} > {MAX_SIG_LEN}"),
        ));
    }

    if sig[SEQUENCE_OFFSET] != ASN1_SEQUENCE_ID {
        return Err(script_error(
            ErrorKind::SigInvalidSeqID,
            format!(
                "malformed signature: format has wrong type: {:#x}",
                sig[SEQUENCE_OFFSET]
            ),
        ));
    }

    if usize::from(sig[DATA_LEN_OFFSET]) != sig_len - 2 {
        return Err(script_error(
            ErrorKind::SigInvalidDataLen,
            format!(
                "malformed signature: bad length: {} != {}",
                sig[DATA_LEN_OFFSET],
                sig_len - 2
            ),
        ));
    }

    // Calculate the offsets of the elements related to S and ensure S is
    // inside the signature.
    let r_len = usize::from(sig[R_LEN_OFFSET]);
    let s_type_offset = R_OFFSET + r_len;
    let s_len_offset = s_type_offset + 1;
    if s_type_offset >= sig_len {
        return Err(script_error(
            ErrorKind::SigMissingSTypeID,
            "malformed signature: S type indicator missing",
        ));
    }
    if s_len_offset >= sig_len {
        return Err(script_error(
            ErrorKind::SigMissingSLen,
            "malformed signature: S length missing",
        ));
    }

    // The lengths of R and S must match the overall length of the
    // signature.
    let s_offset = s_len_offset + 1;
    let s_len = usize::from(sig[s_len_offset]);
    if s_offset + s_len != sig_len {
        return Err(script_error(
            ErrorKind::SigInvalidSLen,
            "malformed signature: invalid S length",
        ));
    }

    // R elements must be ASN.1 integers.
    if sig[R_TYPE_OFFSET] != ASN1_INTEGER_ID {
        return Err(script_error(
            ErrorKind::SigInvalidRIntID,
            format!(
                "malformed signature: R integer marker: {:#x} != {:#x}",
                sig[R_TYPE_OFFSET], ASN1_INTEGER_ID
            ),
        ));
    }

    // Zero-length integers are not allowed for R.
    if r_len == 0 {
        return Err(script_error(
            ErrorKind::SigZeroRLen,
            "malformed signature: R length is zero",
        ));
    }

    // R must not be negative.
    if sig[R_OFFSET] & 0x80 != 0 {
        return Err(script_error(
            ErrorKind::SigNegativeR,
            "malformed signature: R is negative",
        ));
    }

    // Null bytes at the start of R are not allowed, unless R would
    // otherwise be interpreted as a negative number.
    if r_len > 1 && sig[R_OFFSET] == 0x00 && sig[R_OFFSET + 1] & 0x80 == 0 {
        return Err(script_error(
            ErrorKind::SigTooMuchRPadding,
            "malformed signature: R value has too much padding",
        ));
    }

    // S elements must be ASN.1 integers.
    if sig[s_type_offset] != ASN1_INTEGER_ID {
        return Err(script_error(
            ErrorKind::SigInvalidSIntID,
            format!(
                "malformed signature: S integer marker: {:#x} != {:#x}",
                sig[s_type_offset], ASN1_INTEGER_ID
            ),
        ));
    }

    // Zero-length integers are not allowed for S.
    if s_len == 0 {
        return Err(script_error(
            ErrorKind::SigZeroSLen,
            "malformed signature: S length is zero",
        ));
    }

    // S must not be negative.
    if sig[s_offset] & 0x80 != 0 {
        return Err(script_error(
            ErrorKind::SigNegativeS,
            "malformed signature: S is negative",
        ));
    }

    // Null bytes at the start of S are not allowed, unless S would
    // otherwise be interpreted as a negative number.
    if s_len > 1 && sig[s_offset] == 0x00 && sig[s_offset + 1] & 0x80 == 0 {
        return Err(script_error(
            ErrorKind::SigTooMuchSPadding,
            "malformed signature: S value has too much padding",
        ));
    }

    // Strip leading zeroes from S.
    let mut s_bytes = &sig[s_offset..s_offset + s_len];
    while !s_bytes.is_empty() && s_bytes[0] == 0x00 {
        s_bytes = &s_bytes[1..];
    }

    // Verify the S value is <= half the order of the curve.
    if s_bytes.len() > 32 {
        return Err(script_error(
            ErrorKind::SigHighS,
            "non-canonical signature: S is larger than 256 bits",
        ));
    }
    if cmp_be(s_bytes, &ORDER) != core::cmp::Ordering::Less {
        return Err(script_error(
            ErrorKind::SigHighS,
            "non-canonical signature: S >= group order",
        ));
    }
    if cmp_be(s_bytes, &HALF_ORDER) == core::cmp::Ordering::Greater {
        return Err(script_error(
            ErrorKind::SigHighS,
            "non-canonical signature: S > group half order",
        ));
    }

    Ok(())
}

/// Whether the passed signature adheres to the strict encoding requirements
/// (dcrd `IsStrictSignatureEncoding`).
pub fn is_strict_signature_encoding(signature: &[u8]) -> bool {
    check_signature_encoding(signature).is_ok()
}

/// Whether the passed public key adheres to the strict encoding
/// requirements (dcrd `isStrictPubKeyEncoding`).
pub(crate) fn is_strict_pub_key_encoding(pub_key: &[u8]) -> bool {
    if pub_key.len() == 33 && (pub_key[0] == 0x02 || pub_key[0] == 0x03) {
        // Compressed
        return true;
    }
    if pub_key.len() == 65 && pub_key[0] == 0x04 {
        // Uncompressed
        return true;
    }
    false
}

/// Returns an error if the passed public key does not adhere to the strict
/// encoding requirements (dcrd `CheckPubKeyEncoding`).
pub fn check_pub_key_encoding(pub_key: &[u8]) -> Result<(), ScriptError> {
    if !is_strict_pub_key_encoding(pub_key) {
        return Err(script_error(
            ErrorKind::PubKeyType,
            "unsupported public key type",
        ));
    }
    Ok(())
}

/// Returns an error unless the passed hash type adheres to the strict
/// encoding requirements (dcrd `CheckHashTypeEncoding`).
pub fn check_hash_type_encoding(hash_type: SigHashType) -> Result<(), ScriptError> {
    let sig_hash_type = hash_type.0 & !SIG_HASH_ANY_ONE_CAN_PAY.0;
    if !(SIG_HASH_ALL.0..=SIG_HASH_SINGLE.0).contains(&sig_hash_type) {
        return Err(script_error(
            ErrorKind::InvalidSigHashType,
            format!("invalid hash type 0x{:x}", hash_type.0),
        ));
    }
    Ok(())
}

/// Whether the passed public key adheres to the strict compressed encoding
/// requirements (dcrd `IsStrictCompressedPubKeyEncoding`).
pub fn is_strict_compressed_pub_key_encoding(pub_key: &[u8]) -> bool {
    pub_key.len() == 33 && (pub_key[0] == 0x02 || pub_key[0] == 0x03)
}

/// Whether the script is an OP_RETURN followed by a data push of exactly
/// the required length (dcrd `IsStrictNullData`); always false for required
/// lengths > 75.
pub fn is_strict_null_data(script_version: u16, script: &[u8], required_len: u32) -> bool {
    use crate::opcode_table::{OP_DATA_75, OP_RETURN};
    use crate::script::{is_canonical_push, is_small_int};
    use crate::tokenizer::ScriptTokenizer;

    // The only currently supported script version is 0.
    if script_version != 0 {
        return false;
    }

    // The script can't possibly be a null data script if it doesn't start
    // with OP_RETURN.
    if script.is_empty() || script[0] != OP_RETURN {
        return false;
    }

    // Allow bare OP_RETURN when the required length is 0.
    if script.len() == 1 && required_len == 0 {
        return true;
    }

    // OP_RETURN followed by a data push of the required size.
    let mut tokenizer = ScriptTokenizer::new(script_version, &script[1..]);
    tokenizer.next()
        && tokenizer.done()
        && tokenizer.err().is_none()
        && is_canonical_push(tokenizer.opcode(), tokenizer.data())
        && ((is_small_int(tokenizer.opcode()) && required_len == 1)
            || (tokenizer.opcode() <= OP_DATA_75 && tokenizer.data().len() as u32 == required_len))
}
