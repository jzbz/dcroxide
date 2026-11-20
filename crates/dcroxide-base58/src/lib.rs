// SPDX-License-Identifier: ISC
//! Modified base58 and Decred base58check, mirroring `decred/base58` at
//! v1.0.6.
//!
//! Behavioral quirks preserved deliberately: [`decode`] returns an *empty
//! vector* — not an error — for both empty input and input containing any
//! invalid base58 character, exactly like the Go `Decode`; leading `'1'`
//! characters map to leading zero bytes and vice versa.
//!
//! **The conversion.** The Go package converts one digit at a time: each
//! base58 character multiplies a little-endian array of 32-bit words by 58
//! (decoding), and each byte multiplies an array of base58 digits by 256
//! (encoding), which costs work proportional to the square of the length
//! with a word or a digit per step.  This crate computes the same numbers
//! in larger steps.  [`decode`] folds up to ten digits into one machine
//! word (58^10 < 2^64) and multiplies a little-endian array of 64-bit limbs
//! by 58^10 once per group, through a 128-bit product; [`encode`] takes the
//! input four bytes at a time and multiplies an array of limbs in base
//! 58^5 (each limb five base58 digits, 58^5 < 2^32) by 2^32, through a
//! 64-bit product.  Both are the same quadratic algorithm with about a
//! tenth of the inner steps.  The value converted is the same, and the
//! leading `'1'`s and zero bytes are counted apart from it exactly as Go
//! counts them, so every output is Go's byte for byte; the crate's tests
//! hold both functions to the per-digit algorithm (kept as a test-only
//! reference) and to Go through the oracle.
//!
//! **Allocation.** [`decode`] checks every character before it allocates
//! anything, so an invalid string of any length allocates nothing (Go's
//! `Decode` allocates its output first).  A valid string allocates its
//! output, of exactly the decoded length, and, only when more than 261
//! digits follow its leading `'1'`s, a scratch array of
//! `ceil((floor(n * 47 / 64) + 1) / 8)` 64-bit limbs for `n` such digits.
//! That is the size of Go's `out32` array (`ceil(ceil(n * 47 / 64) / 4)`
//! 32-bit words) rounded up to eight bytes, except when `n` is a multiple
//! of 512, where it is one limb (eight bytes) more; shorter strings use a
//! fixed array on the stack.  [`encode`] allocates its output, of exactly
//! the encoded length, and, only above 233 bytes after the leading zero
//! bytes, a scratch array of `ceil((floor(n * 137 / 100) + 1) / 5)` 32-bit
//! limbs for `n` such bytes.  That is at most 1.113 bytes of scratch per
//! input byte (the most is 268 bytes for 241, 1.112 a byte), under 1.1
//! from 1,001 bytes on, and it falls toward 1.096, where Go's output
//! buffer is about 1.37 bytes per input byte.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

/// The modified base58 alphabet used by Bitcoin and Decred.
pub const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The alphabet character representing zero (`'1'`).
const ALPHABET_IDX0: u8 = b'1';

/// The reverse-lookup table from byte to base58 digit; 255 marks an
/// invalid character (decred/base58 `b58`, which its genalphabet.go
/// generates the same way from the alphabet).
const B58: [u8; 256] = {
    let mut table = [255u8; 256];
    let mut i = 0;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "i < 58 is the loop condition, so i + 1 <= 58"
    )]
    while i < ALPHABET.len() {
        table[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
};

/// The base58 digits [`decode`] folds into one word before multiplying
/// the big number by it: 58^10 < 2^64 <= 58^11.
const DECODE_GROUP: usize = 10;

/// `POW58[k]` is 58^k, for a group of `k` digits.
const POW58: [u64; DECODE_GROUP + 1] = {
    let mut pow = [1u64; DECODE_GROUP + 1];
    let mut k = 1;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "k runs from 1 to 10, and 58^10 < 2^64"
    )]
    while k <= DECODE_GROUP {
        pow[k] = pow[k - 1] * 58;
        k += 1;
    }
    pow
};

/// The 64-bit limbs [`decode`] keeps on the stack: enough for 261 digits
/// after the leading ones (261 * 47 / 64 + 1 = 192 bytes, 24 limbs).
const DECODE_STACK_LIMBS: usize = 24;

/// The 64-bit limbs that hold any value of `digits` base58 digits.
///
/// Go sizes its output as `ceil(digits * 47 / 64)` bytes, since
/// log_256(58) ~= 0.7322 < 47/64; this takes `floor(digits * 47 / 64) + 1`
/// bytes, never fewer and one more when `digits * 47 / 64` is a whole
/// number (`digits` a multiple of 64), in limbs.  A value of `digits` digits is below
/// 58^digits, which needs `ceil(digits * log2(58))` bits, and 8 times the
/// byte count is an integer above `digits * log2(58)`.  The product is
/// split so it cannot overflow for any length.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "digits / 64 * 47 <= digits and (digits % 64) * 47 / 64 < 47, so the sum is at \
              most digits + 47, which is below usize::MAX for the length of any str"
)]
const fn decode_limbs(digits: usize) -> usize {
    let bytes = digits / 64 * 47 + digits % 64 * 47 / 64 + 1;
    bytes.div_ceil(8)
}

/// The value of up to ten base58 digits, each known to be valid.
#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "after j digits acc < 58^j, so acc * 58 + digit < 58^(j + 1) <= 58^10 < 2^64"
)]
fn fold_digits(group: &[u8]) -> u64 {
    group
        .iter()
        .fold(0u64, |acc, &c| acc * 58 + u64::from(B58[usize::from(c)]))
}

/// `limbs[..used] = limbs[..used] * mul + add`, growing by a limb when the
/// carry out is nonzero; returns the new count of limbs in use.
#[inline]
fn decode_mul_add(limbs: &mut [u64], mut used: usize, mul: u64, add: u64) -> usize {
    let mut carry = add;
    for limb in &mut limbs[..used] {
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "each factor and the carry are below 2^64, so the sum is at most \
                      (2^64 - 1)^2 + 2^64 - 1 = 2^128 - 2^64 < 2^128"
        )]
        let t = u128::from(*limb) * u128::from(mul) + u128::from(carry);
        *limb = t as u64;
        carry = (t >> 64) as u64;
    }
    if carry == 0 {
        return used;
    }
    // In bounds: limbs has room for the whole value (`decode_limbs`), and a
    // limb is added only when the value is at least 2^(64 * used).
    limbs[used] = carry;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the store to limbs[used] is bounds-checked, so used < limbs.len()"
    )]
    {
        used += 1;
    }
    used
}

/// The value of `digits`, every one valid, into `limbs` (little-endian,
/// least significant limb first); returns the count of limbs in use.  The
/// first group takes `digits.len() % 10` digits and every later one ten.
fn decode_digits(digits: &[u8], limbs: &mut [u64]) -> usize {
    let (head, rest) = digits.split_at(digits.len() % DECODE_GROUP);
    let (groups, tail) = rest.as_chunks::<DECODE_GROUP>();
    debug_assert!(tail.is_empty());
    let mut used = 0;
    if !head.is_empty() {
        used = decode_mul_add(limbs, used, POW58[head.len()], fold_digits(head));
    }
    for group in groups {
        used = decode_mul_add(limbs, used, POW58[DECODE_GROUP], fold_digits(group));
    }
    used
}

/// `nlz` zero bytes, then the big-endian bytes of the value in `limbs`
/// from its most significant nonzero byte.
fn limbs_to_bytes(nlz: usize, limbs: &[u64]) -> Vec<u8> {
    let Some((&top, rest)) = limbs.split_last() else {
        return vec![0u8; nlz];
    };
    let top_bytes = top.to_be_bytes();
    let top_bytes = &top_bytes[(top.leading_zeros() / 8) as usize..];
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "rest.len() * 8 + 8 is at most the limb bytes, about 0.73 per digit plus 8, so \
                  the sum is below the input's length plus 16, far from usize::MAX"
    )]
    let len = nlz + top_bytes.len() + rest.len() * 8;
    let mut output = Vec::with_capacity(len);
    output.resize(nlz, 0);
    output.extend_from_slice(top_bytes);
    for limb in rest.iter().rev() {
        output.extend_from_slice(&limb.to_be_bytes());
    }
    output
}

/// Decode a modified base58 string to a byte vector (decred/base58
/// `Decode`). Returns an empty vector for empty input or any invalid
/// base58 character, exactly like the Go implementation.
pub fn decode(input: &str) -> Vec<u8> {
    let input = input.as_bytes();
    if input.is_empty() {
        return Vec::new();
    }

    // Leading '1's are leading zero bytes, counted apart from the value.
    let nlz = input.iter().take_while(|&&c| c == ALPHABET_IDX0).count();
    let digits = &input[nlz..];

    // Every character is checked before anything is allocated.
    if digits.iter().any(|&c| B58[usize::from(c)] == 255) {
        return Vec::new();
    }

    let needed = decode_limbs(digits.len());
    let mut stack = [0u64; DECODE_STACK_LIMBS];
    let mut heap;
    let limbs: &mut [u64] = if needed <= DECODE_STACK_LIMBS {
        &mut stack[..needed]
    } else {
        heap = vec![0u64; needed];
        &mut heap
    };
    let used = decode_digits(digits, limbs);
    limbs_to_bytes(nlz, &limbs[..used])
}

/// The base of [`encode`]'s limbs, 58^5: five base58 digits a limb, and
/// below 2^32, so a limb times 2^32 plus a carry below 2^32 fits a u64.
const ENCODE_BASE: u64 = 656_356_768;

/// The base58 digits in one of [`encode`]'s limbs.
const ENCODE_LIMB_DIGITS: usize = 5;

/// The 32-bit limbs [`encode`] keeps on the stack: enough for 233 bytes
/// after the leading zeros (233 * 137 / 100 + 1 = 320 digits, 64 limbs).
const ENCODE_STACK_LIMBS: usize = 64;

/// The limbs in base 58^5 that hold any value of `bytes` bytes.
///
/// Go sizes its output as `bytes * 137 / 100 + 1` digits, since
/// log_58(256) ~= 1.3657 < 1.37; this takes the same count in limbs of
/// five digits, rounded up.  A limb is added only when the value reaches
/// 58^(5 * limbs), and a value below 256^bytes has at most that many
/// digits.  The product is split so it cannot overflow for any length.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "bytes / 100 * 137 <= 1.37 * bytes and (bytes % 100) * 137 / 100 < 137, so the \
              sum is below 1.37 * bytes + 138; for bytes <= isize::MAX, the length of any \
              slice, that is below 1.27e19 on 64-bit and 2.95e9 on 32-bit, under usize::MAX"
)]
const fn encode_limbs(bytes: usize) -> usize {
    let digits = bytes / 100 * 137 + bytes % 100 * 137 / 100 + 1;
    digits.div_ceil(ENCODE_LIMB_DIGITS)
}

/// `limbs[..used] = limbs[..used] * 2^shift + add` in base 58^5, growing
/// by a limb or two when the carry out is nonzero; returns the new count
/// of limbs in use.  `shift` is at most 32 and `add` below 2^shift.
#[inline]
fn encode_shift_add(limbs: &mut [u32], mut used: usize, shift: u32, add: u32) -> usize {
    let mut carry = u64::from(add);
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "a limb is below 58^5 < 2^30 and shift <= 32, so the shift is below 2^62; the \
                  carry stays at most 2^32 - 1, since t <= (58^5 - 1) * 2^32 + 2^32 - 1 = \
                  58^5 * 2^32 - 1 gives t / 58^5 < 2^32; so t < 2^63, and the divisor is a \
                  nonzero constant"
    )]
    for limb in &mut limbs[..used] {
        let t = (u64::from(*limb) << shift) + carry;
        *limb = (t % ENCODE_BASE) as u32;
        carry = t / ENCODE_BASE;
    }
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the store to limbs[used] is bounds-checked, so used < limbs.len(); the divisor \
                  is a nonzero constant"
    )]
    while carry != 0 {
        // In bounds: limbs has room for the whole value (`encode_limbs`).
        limbs[used] = (carry % ENCODE_BASE) as u32;
        carry /= ENCODE_BASE;
        used += 1;
    }
    used
}

/// The value of `bytes` (big-endian) into `limbs` in base 58^5, least
/// significant limb first; returns the count of limbs in use.  The first
/// step takes `bytes.len() % 4` bytes and every later one four.
fn encode_bytes(bytes: &[u8], limbs: &mut [u32]) -> usize {
    let (head, rest) = bytes.split_at(bytes.len() % 4);
    let (words, tail) = rest.as_chunks::<4>();
    debug_assert!(tail.is_empty());
    let mut used = 0;
    if !head.is_empty() {
        let value = head.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b));
        // No limb is in use yet, so the shift multiplies nothing.
        used = encode_shift_add(limbs, used, 0, value);
    }
    for word in words {
        used = encode_shift_add(limbs, used, 32, u32::from_be_bytes(*word));
    }
    used
}

/// The five base58 characters of a limb, most significant first.
#[inline]
fn limb_chars(mut limb: u32) -> [u8; ENCODE_LIMB_DIGITS] {
    let mut chars = [0u8; ENCODE_LIMB_DIGITS];
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the divisor is a nonzero constant"
    )]
    for c in chars.iter_mut().rev() {
        *c = ALPHABET[(limb % 58) as usize];
        limb /= 58;
    }
    chars
}

/// `nz` `'1'`s, then the base58 characters of the value in `limbs` from
/// its most significant nonzero digit.
fn limbs_to_string(nz: usize, limbs: &[u32]) -> String {
    let (top_chars, rest) = match limbs.split_last() {
        Some((&top, rest)) => (limb_chars(top), rest),
        None => ([ALPHABET_IDX0; ENCODE_LIMB_DIGITS], limbs),
    };
    let skip = top_chars
        .iter()
        .take_while(|&&c| c == ALPHABET_IDX0)
        .count();
    let top_chars = &top_chars[skip..];
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "rest.len() * 5 + 5 is at most the digits of the value, about 1.37 per byte, \
                  so the sum is below 1.37 times the input's length plus 5, which is below \
                  usize::MAX for the length of any slice (at most isize::MAX)"
    )]
    let len = nz + top_chars.len() + rest.len() * ENCODE_LIMB_DIGITS;
    let mut output = Vec::with_capacity(len);
    output.resize(nz, ALPHABET_IDX0);
    output.extend_from_slice(top_chars);
    for &limb in rest.iter().rev() {
        output.extend_from_slice(&limb_chars(limb));
    }
    String::from_utf8(output).expect("base58 alphabet is ASCII")
}

/// Encode a byte slice to a modified base58 string (decred/base58
/// `Encode`).
pub fn encode(input: &[u8]) -> String {
    // Leading zero bytes are leading '1's, counted apart from the value.
    let nz = input.iter().take_while(|&&b| b == 0).count();
    let bytes = &input[nz..];

    let needed = encode_limbs(bytes.len());
    let mut stack = [0u32; ENCODE_STACK_LIMBS];
    let mut heap;
    let limbs: &mut [u32] = if needed <= ENCODE_STACK_LIMBS {
        &mut stack[..needed]
    } else {
        heap = vec![0u32; needed];
        &mut heap
    };
    let used = encode_bytes(bytes, limbs);
    limbs_to_string(nz, &limbs[..used])
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
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "input.len() <= isize::MAX for a slice, so 2 + input.len() + 4 fits usize"
    )]
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
    let mut decoded = decode(input);
    if decoded.len() < 6 {
        return Err(CheckError::InvalidFormat);
    }
    let version = [decoded[0], decoded[1]];
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "decoded.len() >= 6 is checked above"
    )]
    let data_len = decoded.len() - 4;
    let calculated = checksum(&decoded[..data_len]);
    if decoded[data_len..] != calculated {
        return Err(CheckError::Checksum);
    }
    // The payload moves to the front of the decoded vector in place, where
    // Go returns a subslice of it; no second allocation.
    decoded.copy_within(2..data_len, 0);
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "data_len >= 2 since decoded.len() >= 6"
    )]
    decoded.truncate(data_len - 2);
    Ok((decoded, version))
}

#[cfg(test)]
mod tests {
    // Test arithmetic over bounded lengths.
    #![allow(clippy::arithmetic_side_effects)]

    use super::*;

    /// The bytes of Go's `out32` array for `digits` digits after the
    /// leading '1's (decred/base58 v1.0.6 `Decode`: `maxOutputSizeNoLZ :=
    /// (n*47 + 63) / 64`, `maxOut32Size := (maxOutputSizeNoLZ + 3) / 4`).
    fn go_out32_bytes(digits: usize) -> usize {
        (digits * 47).div_ceil(64).div_ceil(4) * 4
    }

    /// The module doc's statement of `decode`'s scratch: Go's `out32`
    /// rounded up to eight bytes, one limb more at every multiple of 512
    /// digits; and enough limbs for the largest value, 58^digits - 1.
    #[test]
    fn decode_scratch_is_as_documented() {
        for digits in 0..=200_000usize {
            let ours = decode_limbs(digits) * 8;
            let go = go_out32_bytes(digits).div_ceil(8) * 8;
            if digits % 512 == 0 {
                assert_eq!(ours, go + 8, "{digits} digits");
            } else {
                assert_eq!(ours, go, "{digits} digits");
            }
            // 58^digits needs digits * log2(58) bits; the gap to the
            // limbs' bits is at least 0.017 bits a digit, far above the
            // float's error.
            assert!(
                digits as f64 * 58f64.log2() <= (decode_limbs(digits) * 64) as f64,
                "{digits} digits"
            );
        }
        assert_eq!(decode_limbs(261), DECODE_STACK_LIMBS);
        assert!(decode_limbs(262) > DECODE_STACK_LIMBS);
    }

    /// The module doc's statement of `encode`'s scratch: none to 233 bytes,
    /// then at most 1.113 bytes per input byte, the most 268 bytes for
    /// 241, and under 1.1 from 1,001 bytes on.
    #[test]
    fn encode_scratch_is_as_documented() {
        assert_eq!(encode_limbs(233), ENCODE_STACK_LIMBS);
        assert!(encode_limbs(234) > ENCODE_STACK_LIMBS);
        let mut worst = (1usize, 0usize);
        for bytes in 234..=1_000_000usize {
            let scratch = encode_limbs(bytes) * 4;
            assert!(scratch * 1000 <= bytes * 1113, "{bytes} bytes");
            if bytes > 1000 {
                assert!(scratch * 10 < bytes * 11, "{bytes} bytes");
            }
            if scratch * worst.0 > worst.1 * bytes {
                worst = (bytes, scratch);
            }
        }
        assert_eq!(worst, (241, 268));
        // Enough limbs for the largest value, 256^bytes - 1, whose base58
        // digits number ceil(bytes * log58(256)) at most, so a whole count
        // of digits at least bytes * log58(256) holds it.
        for bytes in 0..=200_000usize {
            assert!(
                bytes as f64 * 256f64.ln() / 58f64.ln()
                    <= (encode_limbs(bytes) * ENCODE_LIMB_DIGITS) as f64,
                "{bytes} bytes"
            );
        }
    }
}
