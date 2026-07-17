// SPDX-License-Identifier: ISC
//! Wire decoding errors, mirroring dcrd's `wire.ErrorCode` kinds.

use core::fmt;

/// An error from encoding or decoding wire data.
///
/// Variants correspond 1:1 to the dcrd `wire` error codes reachable from the
/// implemented codecs ([`Self::kind_name`] gives the dcrd name for
/// differential comparison). Message texts approximate dcrd's; exact-text
/// parity is only chased where it leaks into observable behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)] // Limit-variant `count`/`max`-style fields are self-describing.
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
    /// A variable-length string exceeded its size limit
    /// (`ErrVarStringTooLong`).
    VarStringTooLong {
        /// The declared length.
        count: u64,
        /// The maximum allowed.
        max: u64,
    },
    /// A variable-length byte array exceeded its size limit
    /// (`ErrVarBytesTooLong`).
    VarBytesTooLong {
        /// The declared length.
        count: u64,
        /// The maximum allowed.
        max: u64,
    },
    /// A command string exceeded the 12-byte header field
    /// (`ErrCmdTooLong`).
    CmdTooLong,
    /// A message payload exceeded the global or per-type maximum
    /// (`ErrPayloadTooLarge`).
    PayloadTooLarge {
        /// The payload length.
        len: u64,
        /// The maximum allowed.
        max: u64,
    },
    /// A message header carried the magic of a different network
    /// (`ErrWrongNetwork`).
    WrongNetwork(u32),
    /// A message header command was not strict ASCII (`ErrMalformedCmd`).
    MalformedCmd,
    /// A message header command is not recognized (`ErrUnknownCmd`).
    UnknownCmd,
    /// The payload checksum did not match the header (`ErrPayloadChecksum`).
    PayloadChecksum,
    /// A message payload had unconsumed trailing bytes (`ErrTrailingBytes`).
    TrailingBytes,
    /// An address list exceeded its maximum (`ErrTooManyAddrs`).
    TooManyAddrs { count: u64, max: u64 },
    /// An address list had no entries where at least one is required
    /// (`ErrTooFewAddrs`).
    TooFewAddrs,
    /// A version 2 network address carried an unknown address type
    /// discriminator (`ErrUnknownNetAddrType`).
    UnknownNetAddrType { addr_type: u8 },
    /// A transaction count exceeded what could fit (`ErrTooManyTxs`).
    TooManyTxs { count: u64, max: u64 },
    /// The message is not valid for the negotiated protocol version
    /// (`ErrMsgInvalidForPVer`).
    MsgInvalidForPVer,
    /// A committed filter exceeded the maximum size (`ErrFilterTooLarge`).
    FilterTooLarge { size: u64, max: u64 },
    /// Too many header-commitment proof hashes (`ErrTooManyProofs`).
    TooManyProofs { count: u64, max: u64 },
    /// Too many filter types (`ErrTooManyFilterTypes`).
    TooManyFilterTypes { count: u64, max: u64 },
    /// Too many block locator hashes (`ErrTooManyLocators`).
    TooManyLocators { count: u64, max: u64 },
    /// Too many inventory vectors (`ErrTooManyVectors`).
    TooManyVectors { count: u64, max: u64 },
    /// Too many block headers or header-hashes (`ErrTooManyHeaders`).
    TooManyHeaders { count: u64, max: u64 },
    /// A headers-message header claimed to contain transactions
    /// (`ErrHeaderContainsTxs`).
    HeaderContainsTxs { count: u64 },
    /// Too many vote hashes (`ErrTooManyVotes`).
    TooManyVotes { count: u64, max: u64 },
    /// Too many block hashes (`ErrTooManyBlocks`).
    TooManyBlocks { count: u64, max: u64 },
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
    /// The version message structure was invalid (`ErrInvalidMsg`).
    InvalidMsg,
    /// The user agent exceeded its maximum length (`ErrUserAgentTooLong`).
    UserAgentTooLong { len: u64, max: u64 },
    /// Too many committed filter headers (`ErrTooManyFilterHeaders`).
    TooManyFilterHeaders { count: u64, max: u64 },
    /// A strict-ASCII string contained other bytes
    /// (`ErrMalformedStrictString`).
    MalformedStrictString,
    /// Too many initial state types (`ErrTooManyInitStateTypes`).
    TooManyInitStateTypes { count: u64, max: u64 },
    /// An initial state type string was too long
    /// (`ErrInitStateTypeTooLong`).
    InitStateTypeTooLong { len: u64, max: u64 },
    /// Too many treasury spend hashes (`ErrTooManyTSpends`).
    TooManyTSpends { count: u64, max: u64 },
    /// A mixing script class exceeded its maximum length
    /// (`ErrMixPairReqScriptClassTooLong`).
    MixPairReqScriptClassTooLong { len: u64, max: u64 },
    /// Too many UTXOs in a mix pair request (`ErrTooManyMixPairReqUTXOs`).
    TooManyMixPairReqUTXOs { count: u64, max: u64 },
    /// Too many referenced previous mixing messages
    /// (`ErrTooManyPrevMixMsgs`).
    TooManyPrevMixMsgs { count: u64, max: u64 },
    /// Too many batched committed filters (`ErrTooManyCFilters`).
    TooManyCFilters { count: u64, max: u64 },
    /// A timestamp exceeded the maximum representable value
    /// (`ErrInvalidTimestamp`).
    InvalidTimestamp,
}

impl WireError {
    /// The dcrd `wire.ErrorCode` name, used for differential comparison.
    /// [`WireError::UnexpectedEof`] has no dcrd kind (it maps to Go io
    /// errors) and returns an empty string.
    pub fn kind_name(&self) -> &'static str {
        match self {
            WireError::UnexpectedEof => "",
            WireError::NonCanonicalVarInt { .. } => "ErrNonCanonicalVarInt",
            WireError::VarStringTooLong { .. } => "ErrVarStringTooLong",
            WireError::VarBytesTooLong { .. } => "ErrVarBytesTooLong",
            WireError::CmdTooLong => "ErrCmdTooLong",
            WireError::PayloadTooLarge { .. } => "ErrPayloadTooLarge",
            WireError::WrongNetwork(_) => "ErrWrongNetwork",
            WireError::MalformedCmd => "ErrMalformedCmd",
            WireError::UnknownCmd => "ErrUnknownCmd",
            WireError::PayloadChecksum => "ErrPayloadChecksum",
            WireError::TrailingBytes => "ErrTrailingBytes",
            WireError::TooManyAddrs { .. } => "ErrTooManyAddrs",
            WireError::TooManyTxs { .. } => "ErrTooManyTxs",
            WireError::MsgInvalidForPVer => "ErrMsgInvalidForPVer",
            WireError::FilterTooLarge { .. } => "ErrFilterTooLarge",
            WireError::TooManyProofs { .. } => "ErrTooManyProofs",
            WireError::TooManyFilterTypes { .. } => "ErrTooManyFilterTypes",
            WireError::TooManyLocators { .. } => "ErrTooManyLocators",
            WireError::TooManyVectors { .. } => "ErrTooManyVectors",
            WireError::TooManyHeaders { .. } => "ErrTooManyHeaders",
            WireError::HeaderContainsTxs { .. } => "ErrHeaderContainsTxs",
            WireError::TooManyVotes { .. } => "ErrTooManyVotes",
            WireError::TooManyBlocks { .. } => "ErrTooManyBlocks",
            WireError::MismatchedWitnessCount { .. } => "ErrMismatchedWitnessCount",
            WireError::UnknownTxType(_) => "ErrUnknownTxType",
            WireError::InvalidMsg => "ErrInvalidMsg",
            WireError::TooFewAddrs => "ErrTooFewAddrs",
            WireError::UnknownNetAddrType { .. } => "ErrUnknownNetAddrType",
            WireError::UserAgentTooLong { .. } => "ErrUserAgentTooLong",
            WireError::TooManyFilterHeaders { .. } => "ErrTooManyFilterHeaders",
            WireError::MalformedStrictString => "ErrMalformedStrictString",
            WireError::TooManyInitStateTypes { .. } => "ErrTooManyInitStateTypes",
            WireError::InitStateTypeTooLong { .. } => "ErrInitStateTypeTooLong",
            WireError::TooManyTSpends { .. } => "ErrTooManyTSpends",
            WireError::MixPairReqScriptClassTooLong { .. } => "ErrMixPairReqScriptClassTooLong",
            WireError::TooManyMixPairReqUTXOs { .. } => "ErrTooManyMixPairReqUTXOs",
            WireError::TooManyPrevMixMsgs { .. } => "ErrTooManyPrevMixMsgs",
            WireError::TooManyCFilters { .. } => "ErrTooManyCFilters",
            WireError::InvalidTimestamp => "ErrInvalidTimestamp",
        }
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::UnexpectedEof => write!(f, "unexpected end of data"),
            WireError::NonCanonicalVarInt { value, min } => write!(
                f,
                "non-canonical varint {value:x} - must encode a value greater than {min:x}"
            ),
            WireError::WrongNetwork(magic) => {
                write!(f, "message from other network [{magic:#x}]")
            }
            WireError::MismatchedWitnessCount { witness, prefix } => write!(
                f,
                "non equal witness and prefix txin quantities (witness {witness}, prefix {prefix})"
            ),
            WireError::UnknownTxType(t) => {
                write!(f, "unsupported transaction type {t}")
            }
            other => f.write_str(other.kind_name()),
        }
    }
}

impl core::error::Error for WireError {}
