// SPDX-License-Identifier: ISC
//! Wire decoding errors, mirroring dcrd's `wire.ErrorCode` kinds.

use core::fmt;

/// The `Func` and `Description` of a dcrd `MessageError`, for the error
/// kinds whose description differs from one check to the next.
///
/// [`Self::desc`] is dcrd's format string verbatim, so a construction
/// site reads like the `messageError(op, code, fmt.Sprintf(...))` call it
/// ports: rendering fills the format's `%s` verb with [`Self::field`]
/// and its `%d` and `%v` verbs with [`Self::args`] in order, which is
/// what `fmt.Sprintf` prints for the field names and unsigned counts
/// dcrd passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageText {
    /// The dcrd function that raised the error (`MessageError.Func`).
    pub op: &'static str,
    /// dcrd's description format string.
    pub desc: &'static str,
    /// The value of the description's `%s` verb.
    pub field: &'static str,
    /// The values of its `%d` and `%v` verbs, in order.
    pub args: [u64; 2],
}

impl MessageText {
    /// A check the port makes and dcrd does not, so there is no dcrd
    /// text to render: the error prints its kind name.
    pub const NONE: MessageText = MessageText::new("", "");

    /// The text for a description without values.
    pub const fn new(op: &'static str, desc: &'static str) -> MessageText {
        MessageText {
            op,
            desc,
            field: "",
            args: [0, 0],
        }
    }

    /// The same text with the value of the description's one numeric
    /// verb.
    pub const fn with_arg(self, arg: u64) -> MessageText {
        self.with_args(arg, 0)
    }

    /// The same text with the values of the description's two numeric
    /// verbs.
    pub const fn with_args(self, first: u64, second: u64) -> MessageText {
        MessageText {
            args: [first, second],
            ..self
        }
    }

    /// The same text with the value of the description's `%s` verb.
    pub const fn with_field(self, field: &'static str) -> MessageText {
        MessageText { field, ..self }
    }
}

impl fmt::Display for MessageText {
    /// dcrd's `MessageError.Error()` (`wire/error.go:266-270`): `Func:
    /// Description`, or the description alone when there is no `Func`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.op.is_empty() {
            write!(f, "{}: ", self.op)?;
        }
        let mut args = self.args.iter();
        let mut rest = self.desc;
        while let Some((literal, tail)) = rest.split_once('%') {
            f.write_str(literal)?;
            let mut verb = tail.chars();
            match verb.next() {
                Some('s') => f.write_str(self.field)?,
                Some('d' | 'v') => write!(f, "{}", args.next().copied().unwrap_or_default())?,
                _ => {
                    f.write_str("%")?;
                    rest = tail;
                    continue;
                }
            }
            rest = verb.as_str();
        }
        f.write_str(rest)
    }
}

/// An error from encoding or decoding wire data.
///
/// Variants correspond 1:1 to the dcrd `wire` error codes reachable from the
/// implemented codecs ([`Self::kind_name`] gives the dcrd name for
/// differential comparison), plus the two Go io errors a short read
/// returns.  Message texts approximate dcrd's, except where they leak
/// into observable behavior: the `decoderawtransaction`,
/// `sendrawtransaction`, `getrawtransaction`, `submitblock` and
/// `sendrawmixmessage` RPCs return the text of a transaction, block or
/// mixing message decode error, so every error those decoders can
/// produce renders dcrd's `MessageError` text (`Func: Description`) or
/// Go's io error text exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)] // Limit-variant `count`/`max`-style fields are self-describing.
pub enum WireError {
    /// A read found no bytes left at all: Go's `io.EOF`, which dcrd's
    /// short reads return when nothing could be read (`shortRead`'s
    /// `n == 0` case, `io.ReadFull` reading zero bytes).
    Eof,
    /// A read found some of the bytes it needed but not all of them:
    /// Go's `io.ErrUnexpectedEOF`.
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
    VarStringTooLong(MessageText),
    /// A variable-length byte array, a script among them, exceeded its
    /// size limit (`ErrVarBytesTooLong`).
    VarBytesTooLong(MessageText),
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
    TooManyTxs {
        count: u64,
        max: u64,
        /// The dcrd function that checked the count (`MessageError.Func`).
        op: &'static str,
        /// What was counted, as dcrd's description words it.
        what: &'static str,
    },
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
    /// The message structure was invalid (`ErrInvalidMsg`).
    InvalidMsg(MessageText),
    /// The user agent exceeded its maximum length (`ErrUserAgentTooLong`).
    UserAgentTooLong { len: u64, max: u64 },
    /// Too many committed filter headers (`ErrTooManyFilterHeaders`).
    TooManyFilterHeaders { count: u64, max: u64 },
    /// A strict-ASCII string contained other bytes
    /// (`ErrMalformedStrictString`).
    MalformedStrictString(MessageText),
    /// Too many initial state types (`ErrTooManyInitStateTypes`).
    TooManyInitStateTypes { count: u64, max: u64 },
    /// An initial state type string was too long
    /// (`ErrInitStateTypeTooLong`).
    InitStateTypeTooLong { len: u64, max: u64 },
    /// Too many treasury spend hashes (`ErrTooManyTSpends`).
    TooManyTSpends { count: u64, max: u64 },
    /// A mixing script class exceeded its maximum length
    /// (`ErrMixPairReqScriptClassTooLong`).
    MixPairReqScriptClassTooLong(MessageText),
    /// Too many UTXOs in a mix pair request (`ErrTooManyMixPairReqUTXOs`).
    TooManyMixPairReqUTXOs(MessageText),
    /// Too many referenced previous mixing messages
    /// (`ErrTooManyPrevMixMsgs`).
    TooManyPrevMixMsgs(MessageText),
    /// Too many batched committed filters (`ErrTooManyCFilters`).
    TooManyCFilters { count: u64, max: u64 },
    /// A timestamp exceeded the maximum representable value
    /// (`ErrInvalidTimestamp`).
    InvalidTimestamp,
}

impl WireError {
    /// The dcrd `wire.ErrorCode` name, used for differential comparison.
    /// [`WireError::Eof`] and [`WireError::UnexpectedEof`] have no dcrd
    /// kind (they are Go io errors) and return an empty string.
    pub fn kind_name(&self) -> &'static str {
        match self {
            WireError::Eof | WireError::UnexpectedEof => "",
            WireError::NonCanonicalVarInt { .. } => "ErrNonCanonicalVarInt",
            WireError::VarStringTooLong(_) => "ErrVarStringTooLong",
            WireError::VarBytesTooLong(_) => "ErrVarBytesTooLong",
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
            WireError::InvalidMsg(_) => "ErrInvalidMsg",
            WireError::TooFewAddrs => "ErrTooFewAddrs",
            WireError::UnknownNetAddrType { .. } => "ErrUnknownNetAddrType",
            WireError::UserAgentTooLong { .. } => "ErrUserAgentTooLong",
            WireError::TooManyFilterHeaders { .. } => "ErrTooManyFilterHeaders",
            WireError::MalformedStrictString(_) => "ErrMalformedStrictString",
            WireError::TooManyInitStateTypes { .. } => "ErrTooManyInitStateTypes",
            WireError::InitStateTypeTooLong { .. } => "ErrInitStateTypeTooLong",
            WireError::TooManyTSpends { .. } => "ErrTooManyTSpends",
            WireError::MixPairReqScriptClassTooLong(_) => "ErrMixPairReqScriptClassTooLong",
            WireError::TooManyMixPairReqUTXOs(_) => "ErrTooManyMixPairReqUTXOs",
            WireError::TooManyPrevMixMsgs(_) => "ErrTooManyPrevMixMsgs",
            WireError::TooManyCFilters { .. } => "ErrTooManyCFilters",
            WireError::InvalidTimestamp => "ErrInvalidTimestamp",
        }
    }

    /// The dcrd `MessageError` text the error carries, for the kinds
    /// whose description differs from one check to the next.
    pub fn message_text(&self) -> Option<&MessageText> {
        match self {
            WireError::VarStringTooLong(text)
            | WireError::VarBytesTooLong(text)
            | WireError::InvalidMsg(text)
            | WireError::MalformedStrictString(text)
            | WireError::MixPairReqScriptClassTooLong(text)
            | WireError::TooManyMixPairReqUTXOs(text)
            | WireError::TooManyPrevMixMsgs(text) => Some(text),
            _ => None,
        }
    }
}

impl fmt::Display for WireError {
    /// Go's io error texts for the short reads, and dcrd's
    /// `MessageError.Error()` text, `Func: Description`
    /// (`wire/error.go:266-270`), for every error the transaction,
    /// block and mixing message decoders return.  The remaining kinds,
    /// which only the other P2P codecs produce, print their kind name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(text) = self.message_text() {
            if text.desc.is_empty() {
                return f.write_str(self.kind_name());
            }
            return text.fmt(f);
        }
        match self {
            WireError::Eof => f.write_str("EOF"),
            WireError::UnexpectedEof => f.write_str("unexpected EOF"),
            // dcrd `ReadVarInt` (`nonCanonicalVarIntFormat`); each
            // minimum belongs to one discriminant.
            WireError::NonCanonicalVarInt { value, min } => {
                let discriminant: u8 = match min {
                    0x1_0000_0000 => 0xff,
                    0x1_0000 => 0xfe,
                    _ => 0xfd,
                };
                write!(
                    f,
                    "ReadVarInt: non-canonical varint {value:x} - discriminant \
                     {discriminant:x} must encode a value greater than {min:x}"
                )
            }
            WireError::TooManyTxs {
                count,
                max,
                op,
                what,
            } => write!(f, "{op}: too many {what} [count {count}, max {max}]"),
            WireError::WrongNetwork(magic) => {
                write!(f, "message from other network [{magic:#x}]")
            }
            WireError::MismatchedWitnessCount { witness, prefix } => write!(
                f,
                "MsgTx.decodeWitness: non equal witness and prefix txin \
                 quantities (witness {witness}, prefix {prefix})"
            ),
            // dcrd's description does not name the type.
            WireError::UnknownTxType(_) => {
                f.write_str("MsgTx.BtcDecode: unsupported transaction type")
            }
            other => f.write_str(other.kind_name()),
        }
    }
}

impl core::error::Error for WireError {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    /// The verbs fill in order, as `fmt.Sprintf` does, a `Func`-less
    /// error prints its description alone, and a port-only check prints
    /// its kind name.
    #[test]
    fn message_text_renders_as_dcrd_formats_it() {
        let text = MessageText::new(
            "ReadVarBytes",
            "%s is larger than the max allowed size [count %d, max %d]",
        )
        .with_field("MixFactoredPoly.Roots")
        .with_args(33, 32);
        assert_eq!(
            WireError::VarBytesTooLong(text).to_string(),
            "ReadVarBytes: MixFactoredPoly.Roots is larger than the max allowed size \
             [count 33, max 32]"
        );
        let text = MessageText::new("", "too few mixed messages [%v]").with_arg(0);
        assert_eq!(text.to_string(), "too few mixed messages [0]");
        let text = MessageText::new("op", "100% of %v").with_arg(7);
        assert_eq!(text.to_string(), "op: 100% of 7");
        assert_eq!(
            WireError::InvalidMsg(MessageText::NONE).to_string(),
            "ErrInvalidMsg"
        );
    }
}
