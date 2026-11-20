// SPDX-License-Identifier: ISC
//! The per-digit algorithm, as `src/lib.rs` implemented it before the
//! limb-based conversion: a line-for-line port of decred/base58 v1.0.6's
//! `Decode` (32-bit words multiplied by 58 once per character) and
//! `Encode` (base58 digits multiplied by 256 once per byte), with
//! `CheckDecode` and `CheckEncode` over them.  Kept unchanged as the
//! reference that the crate's property tests (`tests/reference.rs`) and
//! the `base58_reference` fuzz target hold the library to.  Its character
//! lookup is a linear search of the alphabet, the same function as Go's
//! table.  Never used outside tests and the fuzz target.

// Test-only code, kept as it was in the library.
#![allow(dead_code)]

use dcroxide_base58::{ALPHABET, CheckError};

/// The alphabet character representing zero (`'1'`).
const ALPHABET_IDX0: u8 = b'1';

/// The reverse lookup from byte to base58 digit; 255 marks an invalid
/// character (decred/base58 `b58`).
fn b58_digit(c: u8) -> u8 {
    match ALPHABET.iter().position(|&a| a == c) {
        Some(idx) => idx as u8,
        None => 255,
    }
}

/// decred/base58 `Decode`, one character at a time.
pub fn decode(input: &str) -> Vec<u8> {
    let input = input.as_bytes();
    if input.is_empty() {
        return Vec::new();
    }

    // Count leading zeros ('1' characters).
    let mut nlz = 0usize;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "nlz < input.len() is the loop condition, so nlz + 1 <= input.len()"
    )]
    while nlz < input.len() && input[nlz] == ALPHABET_IDX0 {
        nlz += 1;
    }

    // Max output size: nlz + ceil(rest * log_256(58)) with the same 47/64
    // approximation upstream uses, rounded up to a multiple of 4.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "nlz <= input.len(); test inputs are far below usize::MAX / 47"
    )]
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
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "val < 2^32 on entry and *ui32 * 58 <= 58 * (2^32 - 1), so the sum stays \
                      below 59 * 2^32"
        )]
        for ui32 in out32[..out32_idx].iter_mut() {
            val += u64::from(*ui32) * 58;
            *ui32 = val as u32;
            val >>= 32;
        }
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "the store to out32[out32_idx] is bounds-checked, so out32_idx < out32.len()"
        )]
        if val > 0 {
            out32[out32_idx] = val as u32;
            out32_idx += 1;
        }
    }

    // Convert u32 words to little-endian bytes.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "out32_idx <= out32.len(), so the capacity is at most input.len() + 4"
    )]
    let mut output = Vec::with_capacity(out32_idx * 4 + nlz);
    for &ui32 in &out32[..out32_idx] {
        output.extend_from_slice(&ui32.to_le_bytes());
    }

    // Trim to the most significant byte and account for leading zeros
    // (they come last since decoding happened in reverse order).
    let mut index = output.len();
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "out32_idx > 0 is checked; index = out32_idx * 4 >= 4 and leading_zeros() / 8 \
                  <= 4"
    )]
    if out32_idx > 0 {
        index -= (out32[out32_idx - 1].leading_zeros() / 8) as usize;
    }
    output.truncate(index);
    output.extend(core::iter::repeat_n(0u8, nlz));

    // Reverse into big-endian order.
    output.reverse();
    output
}

/// decred/base58 `Encode`, one byte at a time.
pub fn encode(input: &[u8]) -> String {
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "test inputs are far below usize::MAX / 137"
    )]
    let mut output = vec![0u8; input.len() * 137 / 100 + 1];

    // Encode to base58 in reverse order.
    let mut index = 0usize;
    for &r in input {
        let mut val = u32::from(r);
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "*b < 58 and val <= 255 on entry, so the sum is at most 255 + 57 * 256"
        )]
        for b in output[..index].iter_mut() {
            val += u32::from(*b) << 8;
            *b = (val % 58) as u8;
            val /= 58;
        }
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "the store to output[index] is bounds-checked, so index < output.len()"
        )]
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
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the store to output[index] is bounds-checked, so index < output.len()"
    )]
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

/// The first four bytes of BLAKE256(BLAKE256(input)).
fn checksum(input: &[u8]) -> [u8; 4] {
    let final_hash = dcroxide_crypto::blake256::sum256d(input);
    [final_hash[0], final_hash[1], final_hash[2], final_hash[3]]
}

/// decred/base58 `CheckEncode` over [`encode`].
pub fn check_encode(input: &[u8], version: [u8; 2]) -> String {
    let mut b = Vec::with_capacity(input.len().saturating_add(6));
    b.extend_from_slice(&version);
    b.extend_from_slice(input);
    let calculated = checksum(&b);
    b.extend_from_slice(&calculated);
    encode(&b)
}

/// decred/base58 `CheckDecode` over [`decode`].
pub fn check_decode(input: &str) -> Result<(Vec<u8>, [u8; 2]), CheckError> {
    let decoded = decode(input);
    if decoded.len() < 6 {
        return Err(CheckError::InvalidFormat);
    }
    let version = [decoded[0], decoded[1]];
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "decoded.len() >= 6 is checked above"
    )]
    let data_len = decoded.len() - 4;
    let decoded_checksum = &decoded[data_len..];
    let calculated = checksum(&decoded[..data_len]);
    if decoded_checksum != calculated {
        return Err(CheckError::Checksum);
    }
    Ok((decoded[2..data_len].to_vec(), version))
}
