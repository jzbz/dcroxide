// SPDX-License-Identifier: ISC
//! Wire decoding errors, mirroring dcrd's `wire.ErrorCode` kinds.

use core::fmt;

/// An error from decoding wire data.
///
/// Variants correspond 1:1 to the dcrd `wire` error codes reachable from the
/// codecs implemented so far (per-variant notes name the dcrd code). Message
/// texts approximate dcrd's; exact-text parity is only chased where it leaks
/// into observable behavior (tracked in `PARITY.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// Ran out of bytes mid-value. dcrd surfaces Go's `io.EOF` /
    /// `io.ErrUnexpectedEOF` here; both collapse to this variant.
    UnexpectedEof,
    /// A variable-length integer used more bytes than necessary
    /// (`ErrNonCanonicalVarInt`).
    NonCanonicalVarInt {
        /// The decoded value.
        value: u64,
        /// The smallest value that would justify the encoding used.
        min: u64,
    },
    /// A variable-length byte array exceeded its size limit
    /// (`ErrVarBytesTooLong`).
    VarBytesTooLong {
        /// The declared length.
        count: u64,
        /// The maximum allowed.
        max: u64,
    },
    /// A transaction input or output count exceeded what could fit in a
    /// message (`ErrTooManyTxs`).
    TooManyTxs {
        /// The declared count.
        count: u64,
        /// The maximum allowed.
        max: u64,
    },
    /// A full transaction's witness input count did not match its prefix
    /// input count (`ErrMismatchedWitnessCount`).
    MismatchedWitnessCount {
        /// The witness input count.
        witness: u64,
        /// The prefix input count.
        prefix: u64,
    },
    /// The transaction serialization type is unknown (`ErrUnknownTxType`).
    UnknownTxType(u16),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::UnexpectedEof => write!(f, "unexpected end of data"),
            WireError::NonCanonicalVarInt { value, min } => write!(
                f,
                "non-canonical varint {value:x} - must encode a value greater than {min:x}"
            ),
            WireError::VarBytesTooLong { count, max } => write!(
                f,
                "byte array is larger than the max allowed size [count {count}, max {max}]"
            ),
            WireError::TooManyTxs { count, max } => write!(
                f,
                "too many transactions to fit into max message size [count {count}, max {max}]"
            ),
            WireError::MismatchedWitnessCount { witness, prefix } => write!(
                f,
                "non equal witness and prefix txin quantities (witness {witness}, prefix {prefix})"
            ),
            WireError::UnknownTxType(t) => {
                write!(f, "unsupported transaction type {t}")
            }
        }
    }
}

impl core::error::Error for WireError {}
