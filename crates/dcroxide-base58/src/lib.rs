// SPDX-License-Identifier: ISC
//! Modified base58 and Decred base58check, mirroring `decred/base58` at
//! v1.0.6 (dcrd's pin at release-v2.1.5).
//!
//! Behavioral quirks preserved deliberately: [`decode`] returns an *empty
//! vector* — not an error — for both empty input and input containing any
//! invalid base58 character, exactly like the Go `Decode`; leading `'1'`
//! characters map to leading zero bytes and vice versa.

#![cfg_attr(not(test), no_std)]
// Big-integer base conversion ported from decred/base58; all index
// arithmetic is bounded by the computed output sizes exactly as upstream.
#![allow(clippy::arithmetic_side_effects)]

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

/// The modified base58 alphabet used by Bitcoin and Decred.
pub const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The alphabet character representing zero (`'1'`).
const ALPHABET_IDX0: u8 = b'1';

/// The reverse-lookup table from ASCII byte to base58 digit; 255 marks an
/// invalid character (decred/base58 `b58`).
fn b58_digit(c: u8) -> u8 {
    // Equivalent to the generated table in decred/base58 alphabet.go.
    match ALPHABET.iter().position(|&a| a == c) {
        Some(idx) => idx as u8,
        None => 255,
    }
}

/// Decode a modified base58 string to a byte vector (decred/base58
/// `Decode`). Returns an empty vector for empty input or any invalid
/// base58 character, exactly like the Go implementation.
pub fn decode(input: &str) -> Vec<u8> {
    let input = input.as_bytes();
    if input.is_empty() {
        return Vec::new();
    }

    // Count leading zeros ('1' characters).
    let mut nlz = 0usize;
    while nlz < input.len() && input[nlz] == ALPHABET_IDX0 {
        nlz += 1;
    }

    // Max output size: nlz + ceil(rest * log_256(58)) with the same 47/64
    // approximation upstream uses, rounded up to a multiple of 4.
    let max_output_size_no_lz = (input.len() - nlz) * 47 / 64 + 1;
    let max_out32_size = max_output_size_no_lz.div_ceil(4);
    let mut out32 = vec![0u32; max_out32_size];

    // Decode to base256 in reverse order.
    let mut out32_idx = 0usize;
    for &r in &input[nlz..] {
        let digit = b58_digit(r);
        if digit == 255 {
            // Invalid base58 character.
            return Vec::new();
        }

        let mut val = u64::from(digit);
        for ui32 in out32[..out32_idx].iter_mut() {
            val += u64::from(*ui32) * 58;
            *ui32 = val as u32;
            val >>= 32;
        }
        if val > 0 {
            out32[out32_idx] = val as u32;
            out32_idx += 1;
        }
    }

    // Convert u32 words to little-endian bytes.
    let mut output = Vec::with_capacity(out32_idx * 4 + nlz);
    for &ui32 in &out32[..out32_idx] {
        output.extend_from_slice(&ui32.to_le_bytes());
    }

    // Trim to the most significant byte and account for leading zeros
    // (they come last since decoding happened in reverse order).
    let mut index = output.len();
    if out32_idx > 0 {
        index -= (out32[out32_idx - 1].leading_zeros() / 8) as usize;
    }
    output.truncate(index);
    output.extend(core::iter::repeat_n(0u8, nlz));

    // Reverse into big-endian order.
    output.reverse();
    output
}

/// Encode a byte slice to a modified base58 string (decred/base58
/// `Encode`).
pub fn encode(input: &[u8]) -> String {
    let mut output = vec![0u8; input.len() * 137 / 100 + 1];

    // Encode to base58 in reverse order.
    let mut index = 0usize;
    for &r in input {
        let mut val = u32::from(r);
        for b in output[..index].iter_mut() {
            val += u32::from(*b) << 8;
            *b = (val % 58) as u8;
            val /= 58;
        }
        while val > 0 {
            output[index] = (val % 58) as u8;
            index += 1;
            val /= 58;
        }
    }

    // Replace remainders with their base58 digits.
    for b in output[..index].iter_mut() {
        *b = ALPHABET[usize::from(*b)];
    }

    // Account for leading zero bytes in the input.
    for &r in input {
        if r != 0 {
            break;
        }
        output[index] = ALPHABET_IDX0;
        index += 1;
    }

    output.truncate(index);
    output.reverse();
    String::from_utf8(output).expect("base58 alphabet is ASCII")
}

/// Errors from [`check_decode`] (decred/base58 `ErrChecksum` /
/// `ErrInvalidFormat`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckError {
    /// The checksum does not verify (decred/base58 `ErrChecksum`).
    Checksum,
    /// Version and/or checksum bytes are missing (decred/base58
    /// `ErrInvalidFormat`).
    InvalidFormat,
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheckError::Checksum => f.write_str("checksum error"),
            CheckError::InvalidFormat => {
                f.write_str("invalid format: version and/or checksum bytes missing")
            }
        }
    }
}

impl core::error::Error for CheckError {}

/// The first four bytes of BLAKE256(BLAKE256(input)) (decred/base58
/// `checksum`).
fn checksum(input: &[u8]) -> [u8; 4] {
    let final_hash = dcroxide_crypto::blake256::sum256d(input);
    [final_hash[0], final_hash[1], final_hash[2], final_hash[3]]
}

/// Prepend two version bytes and append a four byte checksum, then base58
/// encode (decred/base58 `CheckEncode`).
pub fn check_encode(input: &[u8], version: [u8; 2]) -> String {
    let mut b = Vec::with_capacity(2 + input.len() + 4);
    b.extend_from_slice(&version);
    b.extend_from_slice(input);
    let calculated = checksum(&b);
    b.extend_from_slice(&calculated);
    encode(&b)
}

/// Decode a [`check_encode`]d string and verify the checksum, returning
/// the payload and version (decred/base58 `CheckDecode`).
pub fn check_decode(input: &str) -> Result<(Vec<u8>, [u8; 2]), CheckError> {
    let decoded = decode(input);
    if decoded.len() < 6 {
        return Err(CheckError::InvalidFormat);
    }
    let version = [decoded[0], decoded[1]];
    let data_len = decoded.len() - 4;
    let decoded_checksum = &decoded[data_len..];
    let calculated = checksum(&decoded[..data_len]);
    if decoded_checksum != calculated {
        return Err(CheckError::Checksum);
    }
    Ok((decoded[2..data_len].to_vec(), version))
}
