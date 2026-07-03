// SPDX-License-Identifier: ISC
//! The Decred chain hash type, mirroring dcrd's `chaincfg/chainhash` package
//! (module version v1.0.5, as pinned by dcrd release-v2.1.5).
//!
//! A [`Hash`] is 32 bytes stored in "natural" (internal) byte order and
//! displayed/parsed as the hexadecimal string of the *byte-reversed* value,
//! exactly like dcrd (and Bitcoin) block/transaction hashes.
//!
//! Parsing reproduces dcrd's `NewHashFromStr` behavior bug-for-bug, including
//! its quirk: strings shorter than 64 characters are accepted, and the
//! missing characters are treated as leading zeros of the displayed form
//! (which become trailing zero bytes of the stored hash).

#![cfg_attr(not(test), no_std)]
// All arithmetic here is hex-digit math and cursor positions bounded by the
// fixed 32-byte/64-char sizes. The workspace lint stays on for consensus-math
// crates (amounts, difficulty, subsidies).
#![allow(clippy::arithmetic_side_effects)]

use core::fmt;
use core::str::FromStr;

/// The size of a [`Hash`] in bytes.
pub const HASH_SIZE: usize = 32;

/// The maximum length of a hash string (`HASH_SIZE * 2`).
pub const MAX_HASH_STRING_SIZE: usize = HASH_SIZE * 2;

/// The block size in bytes of the hash algorithm (BLAKE-256).
pub const HASH_BLOCK_SIZE: usize = 64;

/// Error returned when parsing a hash string fails.
///
/// Mirrors the two failure modes of dcrd's `chainhash.Decode`:
/// `ErrHashStrSize` and Go's `hex.InvalidByteError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashError {
    /// The string exceeds [`MAX_HASH_STRING_SIZE`] characters.
    StrSize,
    /// The string contains a byte that is not a hexadecimal digit.
    /// Carries the first offending byte, like Go's `hex.InvalidByteError`.
    InvalidHexByte(u8),
}

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashError::StrSize => {
                write!(f, "max hash string length is {MAX_HASH_STRING_SIZE} bytes")
            }
            HashError::InvalidHexByte(b) => {
                write!(f, "invalid byte: {:#04x} {:?}", b, *b as char)
            }
        }
    }
}

impl core::error::Error for HashError {}

/// A 32-byte hash in natural byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct Hash(pub [u8; HASH_SIZE]);

impl Hash {
    /// The all-zero hash.
    pub const ZERO: Hash = Hash([0u8; HASH_SIZE]);

    /// Construct from a byte slice; errors unless it is exactly 32 bytes
    /// (dcrd `NewHash`/`SetBytes` semantics, minus the pointer plumbing).
    pub fn new(bytes: &[u8]) -> Result<Hash, InvalidHashLen> {
        if bytes.len() != HASH_SIZE {
            return Err(InvalidHashLen(bytes.len()));
        }
        let mut h = [0u8; HASH_SIZE];
        h.copy_from_slice(bytes);
        Ok(Hash(h))
    }

    /// The bytes in natural order.
    pub fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }
}

/// Error for byte-slice constructors of the wrong length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidHashLen(pub usize);

impl fmt::Display for InvalidHashLen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid hash length of {}, want {}", self.0, HASH_SIZE)
    }
}

impl core::error::Error for InvalidHashLen {}

impl From<[u8; HASH_SIZE]> for Hash {
    fn from(b: [u8; HASH_SIZE]) -> Hash {
        Hash(b)
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Hash {
    /// The hexadecimal string of the byte-reversed hash, like dcrd's
    /// `Hash.String`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0.iter().rev() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Value of a hex digit, or an error carrying the offending byte.
fn hex_digit(b: u8) -> Result<u8, HashError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(HashError::InvalidHexByte(b)),
    }
}

impl FromStr for Hash {
    type Err = HashError;

    /// Parse the hexadecimal string of a byte-reversed hash, reproducing
    /// dcrd's `chainhash.Decode` exactly:
    ///
    /// - more than 64 characters is an error;
    /// - an odd-length string is treated as having a leading `'0'`;
    /// - shorter strings decode as if left-padded with zeros (so the missing
    ///   bytes become trailing zeros of the stored hash);
    /// - the first non-hex byte (scanning left to right through the padded
    ///   string) is reported, matching Go's `hex.InvalidByteError`.
    fn from_str(s: &str) -> Result<Hash, HashError> {
        if s.len() > MAX_HASH_STRING_SIZE {
            return Err(HashError::StrSize);
        }

        // Decode into the tail of a zeroed buffer holding the displayed
        // (reversed) byte order, implicitly left-padding short strings.
        let src = s.as_bytes();
        let mut reversed = [0u8; HASH_SIZE];
        let padded_len = src.len() + (src.len() % 2);
        let mut out = HASH_SIZE - padded_len / 2;

        let mut iter = src.iter().copied();
        if src.len() % 2 != 0 {
            // Odd length: dcrd prepends '0', so the first digit is a full
            // byte's low nibble. Go's hex.Decode checks the high nibble ('0',
            // always valid) before the low one, so error order is preserved.
            let lo = hex_digit(iter.next().expect("non-empty odd-length string"))?;
            reversed[out] = lo;
            out += 1;
        }
        while let Some(hi) = iter.next() {
            let hi = hex_digit(hi)?;
            let lo = hex_digit(iter.next().expect("even remainder"))?;
            reversed[out] = (hi << 4) | lo;
            out += 1;
        }

        // Reverse into natural byte order.
        let mut hash = [0u8; HASH_SIZE];
        for (i, b) in reversed.iter().rev().enumerate() {
            hash[i] = *b;
        }
        Ok(Hash(hash))
    }
}

/// BLAKE-256 of `b` as a byte array (dcrd `chainhash.HashB`/`HashFunc`).
pub fn hash_b(b: &[u8]) -> [u8; HASH_SIZE] {
    dcroxide_crypto::blake256::sum256(b)
}

/// BLAKE-256 of `b` as a [`Hash`] (dcrd `chainhash.HashH`).
pub fn hash_h(b: &[u8]) -> Hash {
    Hash(dcroxide_crypto::blake256::sum256(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test data ported from dcrd chaincfg/chainhash hash_test.go (which, per
    // its own note, intentionally uses Bitcoin-chain values shared with btcd).

    /// Bitcoin mainnet genesis hash (natural byte order).
    const MAINNET_GENESIS: Hash = Hash([
        0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7,
        0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ]);

    #[test]
    fn hash_api() {
        // Hash of block 234439 (string form, short — exercises the quirk).
        let block_hash: Hash = "14a0810ac680a3eb3f82edc878cea25ec41d6b790744e5daeef"
            .parse()
            .expect("parse short hash");

        // Hash of block 234440 as bytes.
        let buf = [
            0x79u8, 0xa6, 0x1a, 0xdb, 0xc6, 0xe5, 0xa2, 0xe1, 0x39, 0xd2, 0x71, 0x3a, 0x54, 0x6e,
            0xc7, 0xc8, 0x75, 0x63, 0x2e, 0x75, 0xf1, 0xdf, 0x9c, 0x3f, 0xa6, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let hash = Hash::new(&buf).expect("32 bytes");
        assert_eq!(hash.as_bytes(), &buf);
        assert_ne!(hash, block_hash);

        // Wrong-size constructors error.
        assert_eq!(Hash::new(&[0u8; 1]), Err(InvalidHashLen(1)));
        assert_eq!(Hash::new(&[0u8; 33]), Err(InvalidHashLen(33)));
    }

    #[test]
    fn hash_string() {
        // Block 100000 hash.
        let want = "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506";
        let hash = Hash([
            0x06, 0xe5, 0x33, 0xfd, 0x1a, 0xda, 0x86, 0x39, 0x1f, 0x3f, 0x6c, 0x34, 0x32, 0x04,
            0xb0, 0xd2, 0x78, 0xd4, 0xaa, 0xec, 0x1c, 0x0b, 0x20, 0xaa, 0x27, 0xba, 0x03, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]);
        assert_eq!(hash.to_string(), want);
    }

    #[test]
    fn new_hash_from_str() {
        // (input, expected) pairs from dcrd's TestNewHashFromStr.
        let cases: &[(&str, Result<Hash, HashError>)] = &[
            // Genesis hash.
            (
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
                Ok(MAINNET_GENESIS),
            ),
            // Genesis hash with stripped leading zeros.
            (
                "19d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
                Ok(MAINNET_GENESIS),
            ),
            // Empty string.
            ("", Ok(Hash::ZERO)),
            // Single digit hash.
            ("1", {
                let mut h = [0u8; HASH_SIZE];
                h[0] = 0x01;
                Ok(Hash(h))
            }),
            // Block 203707 with stripped leading zeros.
            (
                "3264bc2ac36a60840790ba1d475d01367e7c723da941069e9dc",
                Ok(Hash([
                    0xdc, 0xe9, 0x69, 0x10, 0x94, 0xda, 0x23, 0xc7, 0xe7, 0x67, 0x13, 0xd0, 0x75,
                    0xd4, 0xa1, 0x0b, 0x79, 0x40, 0x08, 0xa6, 0x36, 0xac, 0xc2, 0x4b, 0x26, 0x03,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ])),
            ),
            // Hash string that is too long.
            (
                "01234567890123456789012345678901234567890123456789012345678912345",
                Err(HashError::StrSize),
            ),
            // Hash strings with non-hex chars; the first invalid byte in
            // left-to-right scan order is reported, matching Go hex.Decode.
            ("abcdefg", Err(HashError::InvalidHexByte(b'g'))),
            ("banana", Err(HashError::InvalidHexByte(b'n'))),
        ];

        for (i, (input, want)) in cases.iter().enumerate() {
            assert_eq!(&input.parse::<Hash>(), want, "case {i}: {input:?}");
        }
    }

    #[test]
    fn display_parse_round_trip() {
        let h = hash_h(b"round trip");
        let parsed: Hash = h.to_string().parse().expect("parse own display");
        assert_eq!(parsed, h);
    }

    #[test]
    fn hash_funcs_are_blake256() {
        // Canonical BLAKE-256 empty-string digest, natural byte order.
        let want = "716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a";
        let got = hash_b(b"");
        let got_hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got_hex, want);
        assert_eq!(hash_h(b"").0, got);
    }
}
