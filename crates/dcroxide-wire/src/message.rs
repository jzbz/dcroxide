// SPDX-License-Identifier: ISC
//! Message framing: the 24-byte header (network magic, null-padded command,
//! payload length, BLAKE-256 checksum) and the dispatch across all message
//! types (dcrd `message.go`).
//!
//! Quirk QK-0001: `reject` is *write-only* in dcrd at the pinned tag — its
//! `makeEmptyMessage` has no case for it, so received reject frames fail
//! with `ErrUnknownCmd` at every protocol version even though the encoder
//! still emits them below `REMOVE_REJECT_VERSION`. Reproduced here: it is
//! absent from the read-path dispatch but encodable via
//! [`write_message`].

use alloc::string::String;
use alloc::vec::Vec;

use crate::MAX_MESSAGE_PAYLOAD;
use crate::cursor::Cursor;
use crate::error::WireError;
use crate::msg_cf::*;
use crate::msg_control::*;
use crate::msg_data::*;
use crate::msg_mix::*;
use crate::msgtx::MsgTx;
use crate::protocol::{CurrencyNet, SEND_HEADERS_VERSION, is_strict_ascii};

/// The number of bytes in a message header (dcrd `MessageHeaderSize`).
pub const MESSAGE_HEADER_SIZE: usize = 24;

/// The fixed size of the command field (dcrd `CommandSize`).
pub const COMMAND_SIZE: usize = 12;

/// A Decred P2P message (dcrd's `Message` interface, as a closed enum).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)] // Variant payloads are documented on their types.
pub enum Message {
    Version(MsgVersion),
    VerAck,
    GetAddr,
    Addr(MsgAddr),
    GetBlocks(MsgGetBlocks),
    Inv(MsgInv),
    GetData(MsgGetData),
    NotFound(MsgNotFound),
    Block(MsgBlock),
    Tx(MsgTx),
    GetHeaders(MsgGetHeaders),
    Headers(MsgHeaders),
    Ping(MsgPing),
    Pong(MsgPong),
    MemPool,
    MiningState(MsgMiningState),
    GetMiningState,
    Reject(MsgReject),
    SendHeaders,
    FeeFilter(MsgFeeFilter),
    GetCFilter(MsgGetCFilter),
    GetCFHeaders(MsgGetCFHeaders),
    GetCFTypes,
    CFilter(MsgCFilter),
    CFHeaders(MsgCFHeaders),
    CFTypes(MsgCFTypes),
    GetCFilterV2(MsgGetCFilterV2),
    CFilterV2(MsgCFilterV2),
    GetInitState(MsgGetInitState),
    InitState(MsgInitState),
    GetCFsV2(MsgGetCFsV2),
    CFiltersV2(MsgCFiltersV2),
    MixPairReq(MsgMixPairReq),
    // Boxed: the post-quantum public key array makes this variant ~1.4 KiB.
    MixKeyExchange(alloc::boxed::Box<MsgMixKeyExchange>),
    MixCiphertexts(MsgMixCiphertexts),
    MixSlotReserve(MsgMixSlotReserve),
    MixFactoredPoly(MsgMixFactoredPoly),
    MixDCNet(MsgMixDCNet),
    MixConfirm(MsgMixConfirm),
    MixSecrets(MsgMixSecrets),
}

impl Message {
    /// The protocol command string (dcrd `Command()`).
    pub fn command(&self) -> &'static str {
        match self {
            Message::Version(_) => "version",
            Message::VerAck => "verack",
            Message::GetAddr => "getaddr",
            Message::Addr(_) => "addr",
            Message::GetBlocks(_) => "getblocks",
            Message::Inv(_) => "inv",
            Message::GetData(_) => "getdata",
            Message::NotFound(_) => "notfound",
            Message::Block(_) => "block",
            Message::Tx(_) => "tx",
            Message::GetHeaders(_) => "getheaders",
            Message::Headers(_) => "headers",
            Message::Ping(_) => "ping",
            Message::Pong(_) => "pong",
            Message::MemPool => "mempool",
            Message::MiningState(_) => "miningstate",
            Message::GetMiningState => "getminings",
            Message::Reject(_) => "reject",
            Message::SendHeaders => "sendheaders",
            Message::FeeFilter(_) => "feefilter",
            Message::GetCFilter(_) => "getcfilter",
            Message::GetCFHeaders(_) => "getcfheaders",
            Message::GetCFTypes => "getcftypes",
            Message::CFilter(_) => "cfilter",
            Message::CFHeaders(_) => "cfheaders",
            Message::CFTypes(_) => "cftypes",
            Message::GetCFilterV2(_) => "getcfilterv2",
            Message::CFilterV2(_) => "cfilterv2",
            Message::GetInitState(_) => "getinitstate",
            Message::InitState(_) => "initstate",
            Message::GetCFsV2(_) => "getcfsv2",
            Message::CFiltersV2(_) => "cfiltersv2",
            Message::MixPairReq(_) => "mixpairreq",
            Message::MixKeyExchange(_) => "mixkeyxchg",
            Message::MixCiphertexts(_) => "mixcphrtxt",
            Message::MixSlotReserve(_) => "mixslotres",
            Message::MixFactoredPoly(_) => "mixfactpoly",
            Message::MixDCNet(_) => "mixdcnet",
            Message::MixConfirm(_) => "mixconfirm",
            Message::MixSecrets(_) => "mixsecrets",
        }
    }

    /// The maximum payload length for this message type at the given
    /// protocol version (dcrd `MaxPayloadLength`).
    pub fn max_payload_length(&self, pver: u32) -> u32 {
        match self {
            // Reject is write-only in dcrd (see the read-path note below),
            // so its limit lives here rather than in the command table.
            Message::Reject(_) => MsgReject::max_payload_length(pver),
            _ => max_payload_for_command(self.command(), pver).expect("known command"),
        }
    }

    /// Encode the payload (dcrd `BtcEncode`).
    pub fn encode_payload(&self, pver: u32) -> Result<Vec<u8>, WireError> {
        let mut w = Vec::new();
        match self {
            Message::Version(m) => m.encode(&mut w)?,
            Message::VerAck | Message::GetAddr | Message::MemPool | Message::GetMiningState => {}
            Message::GetCFTypes => {
                if pver < crate::protocol::NODE_CF_VERSION {
                    return Err(WireError::MsgInvalidForPVer);
                }
            }
            Message::SendHeaders => {
                if pver < SEND_HEADERS_VERSION {
                    return Err(WireError::MsgInvalidForPVer);
                }
            }
            Message::Addr(m) => m.encode(&mut w)?,
            Message::GetBlocks(m) => m.encode(&mut w)?,
            Message::Inv(m) => encode_inv_message(&mut w, &m.inv_list)?,
            Message::GetData(m) => encode_inv_message(&mut w, &m.inv_list)?,
            Message::NotFound(m) => encode_inv_message(&mut w, &m.inv_list)?,
            Message::Block(m) => m.encode(&mut w),
            Message::Tx(m) => m.encode_into(&mut w),
            Message::GetHeaders(m) => m.encode(&mut w)?,
            Message::Headers(m) => m.encode(&mut w)?,
            Message::Ping(m) => w.extend_from_slice(&m.nonce.to_le_bytes()),
            Message::Pong(m) => w.extend_from_slice(&m.nonce.to_le_bytes()),
            Message::MiningState(m) => m.encode(&mut w)?,
            Message::Reject(m) => m.encode(&mut w, pver)?,
            Message::FeeFilter(m) => m.encode(&mut w, pver)?,
            Message::GetCFilter(m) => m.encode(&mut w, pver)?,
            Message::GetCFHeaders(m) => m.encode(&mut w, pver)?,
            Message::CFilter(m) => m.encode(&mut w, pver)?,
            Message::CFHeaders(m) => m.encode(&mut w, pver)?,
            Message::CFTypes(m) => m.encode(&mut w, pver)?,
            Message::GetCFilterV2(m) => m.encode(&mut w, pver)?,
            Message::CFilterV2(m) => m.encode(&mut w, pver)?,
            Message::GetInitState(m) => m.encode(&mut w, pver)?,
            Message::InitState(m) => m.encode(&mut w, pver)?,
            Message::GetCFsV2(m) => m.encode(&mut w, pver)?,
            Message::CFiltersV2(m) => m.encode(&mut w, pver)?,
            Message::MixPairReq(m) => m.encode(&mut w, pver)?,
            Message::MixKeyExchange(m) => m.encode(&mut w, pver)?,
            Message::MixCiphertexts(m) => m.encode(&mut w, pver)?,
            Message::MixSlotReserve(m) => m.encode(&mut w, pver)?,
            Message::MixFactoredPoly(m) => m.encode(&mut w, pver)?,
            Message::MixDCNet(m) => m.encode(&mut w, pver)?,
            Message::MixConfirm(m) => m.encode(&mut w, pver)?,
            Message::MixSecrets(m) => m.encode(&mut w, pver)?,
        }
        Ok(w)
    }
}

/// The per-type maximum payload for a command, or `None` for unknown
/// commands (mirrors `makeEmptyMessage` + `MaxPayloadLength`).
fn max_payload_for_command(command: &str, pver: u32) -> Option<u32> {
    Some(match command {
        "version" => MsgVersion::max_payload_length(pver),
        "verack" | "getaddr" | "mempool" | "getminings" | "sendheaders" | "getcftypes" => 0,
        "addr" => MsgAddr::max_payload_length(pver),
        "getblocks" | "getheaders" => BlockLocator::max_payload_length(pver),
        "inv" | "getdata" | "notfound" => inv_message_max_payload(pver),
        "block" => MsgBlock::max_payload_length(pver),
        "tx" => MsgBlock::max_payload_length(pver),
        "headers" => MsgHeaders::max_payload_length(pver),
        "ping" | "pong" => 8,
        "miningstate" => MsgMiningState::max_payload_length(pver),
        "feefilter" => 8,
        "getcfilter" => dcroxide_chainhash::HASH_SIZE as u32 + 1,
        "getcfheaders" => MsgGetCFHeaders::max_payload_length(pver),
        "cfilter" => MsgCFilter::max_payload_length(pver),
        "cfheaders" => MsgCFHeaders::max_payload_length(pver),
        "cftypes" => MsgCFTypes::max_payload_length(pver),
        "getcfilterv2" => dcroxide_chainhash::HASH_SIZE as u32,
        "cfilterv2" => MsgCFilterV2::max_payload_length(pver),
        "getinitstate" => MsgGetInitState::max_payload_length(pver),
        "initstate" => MsgInitState::max_payload_length(pver),
        "getcfsv2" => dcroxide_chainhash::HASH_SIZE as u32 * 2,
        "cfiltersv2" => MsgCFiltersV2::max_payload_length(pver),
        "mixpairreq" => MsgMixPairReq::max_payload_length(pver),
        "mixkeyxchg" => MsgMixKeyExchange::max_payload_length(pver),
        "mixcphrtxt" => MsgMixCiphertexts::max_payload_length(pver),
        "mixslotres" => MsgMixSlotReserve::max_payload_length(pver),
        "mixfactpoly" => MsgMixFactoredPoly::max_payload_length(pver),
        "mixdcnet" => MsgMixDCNet::max_payload_length(pver),
        "mixconfirm" => MsgMixConfirm::max_payload_length(pver),
        "mixsecrets" => MsgMixSecrets::max_payload_length(pver),
        _ => return None,
    })
}

/// Decode a standalone payload for a known command at the given
/// protocol version, requiring the payload to be fully consumed; for
/// callers holding unframed message bytes such as the mixing tests.
pub fn decode_message_payload(
    command: &str,
    payload: &[u8],
    pver: u32,
) -> Result<Message, WireError> {
    let mut r = Cursor::new(payload);
    let msg = decode_payload(command, &mut r, pver).ok_or(WireError::InvalidMsg)??;
    if r.remaining() != 0 {
        return Err(WireError::InvalidMsg);
    }
    Ok(msg)
}

/// Decode a payload for a known command (mirrors `makeEmptyMessage` +
/// `BtcDecode` dispatch), or `None` for unknown commands.
fn decode_payload(
    command: &str,
    r: &mut Cursor<'_>,
    pver: u32,
) -> Option<Result<Message, WireError>> {
    Some(match command {
        "version" => MsgVersion::decode(r).map(Message::Version),
        "verack" => Ok(Message::VerAck),
        "getaddr" => Ok(Message::GetAddr),
        "mempool" => Ok(Message::MemPool),
        "getminings" => Ok(Message::GetMiningState),
        "sendheaders" => {
            if pver < SEND_HEADERS_VERSION {
                Err(WireError::MsgInvalidForPVer)
            } else {
                Ok(Message::SendHeaders)
            }
        }
        "getcftypes" => {
            if pver < crate::protocol::NODE_CF_VERSION {
                Err(WireError::MsgInvalidForPVer)
            } else {
                Ok(Message::GetCFTypes)
            }
        }
        "addr" => MsgAddr::decode(r).map(Message::Addr),
        "getblocks" => MsgGetBlocks::decode(r).map(Message::GetBlocks),
        "getheaders" => MsgGetHeaders::decode(r).map(Message::GetHeaders),
        "inv" => decode_inv_message(r).map(|inv_list| Message::Inv(MsgInv { inv_list })),
        "getdata" => {
            decode_inv_message(r).map(|inv_list| Message::GetData(MsgGetData { inv_list }))
        }
        "notfound" => {
            decode_inv_message(r).map(|inv_list| Message::NotFound(MsgNotFound { inv_list }))
        }
        "block" => MsgBlock::decode(r, pver).map(Message::Block),
        "tx" => MsgTx::decode(r).map(Message::Tx),
        "headers" => MsgHeaders::decode(r).map(Message::Headers),
        "ping" => r.read_u64().map(|nonce| Message::Ping(MsgPing { nonce })),
        "pong" => r.read_u64().map(|nonce| Message::Pong(MsgPong { nonce })),
        "miningstate" => MsgMiningState::decode(r).map(Message::MiningState),
        "feefilter" => MsgFeeFilter::decode(r, pver).map(Message::FeeFilter),
        "getcfilter" => MsgGetCFilter::decode(r, pver).map(Message::GetCFilter),
        "getcfheaders" => MsgGetCFHeaders::decode(r, pver).map(Message::GetCFHeaders),
        "cfilter" => MsgCFilter::decode(r, pver).map(Message::CFilter),
        "cfheaders" => MsgCFHeaders::decode(r, pver).map(Message::CFHeaders),
        "cftypes" => MsgCFTypes::decode(r, pver).map(Message::CFTypes),
        "getcfilterv2" => MsgGetCFilterV2::decode(r, pver).map(Message::GetCFilterV2),
        "cfilterv2" => MsgCFilterV2::decode(r, pver).map(Message::CFilterV2),
        "getinitstate" => MsgGetInitState::decode(r, pver).map(Message::GetInitState),
        "initstate" => MsgInitState::decode(r, pver).map(Message::InitState),
        "getcfsv2" => MsgGetCFsV2::decode(r, pver).map(Message::GetCFsV2),
        "cfiltersv2" => MsgCFiltersV2::decode(r, pver).map(Message::CFiltersV2),
        "mixpairreq" => MsgMixPairReq::decode(r, pver).map(Message::MixPairReq),
        "mixkeyxchg" => MsgMixKeyExchange::decode(r, pver)
            .map(|m| Message::MixKeyExchange(alloc::boxed::Box::new(m))),
        "mixcphrtxt" => MsgMixCiphertexts::decode(r, pver).map(Message::MixCiphertexts),
        "mixslotres" => MsgMixSlotReserve::decode(r, pver).map(Message::MixSlotReserve),
        "mixfactpoly" => MsgMixFactoredPoly::decode(r, pver).map(Message::MixFactoredPoly),
        "mixdcnet" => MsgMixDCNet::decode(r, pver).map(Message::MixDCNet),
        "mixconfirm" => MsgMixConfirm::decode(r, pver).map(Message::MixConfirm),
        "mixsecrets" => MsgMixSecrets::decode(r, pver).map(Message::MixSecrets),
        _ => return None,
    })
}

/// Frame and encode a message for the given protocol version and network
/// (dcrd `WriteMessage`).
pub fn write_message(msg: &Message, pver: u32, net: CurrencyNet) -> Result<Vec<u8>, WireError> {
    let command = msg.command();
    // Commands are static strings that always fit, but keep the dcrd check.
    if command.len() > COMMAND_SIZE {
        return Err(WireError::CmdTooLong);
    }

    let payload = msg.encode_payload(pver)?;
    if payload.len() as u64 > MAX_MESSAGE_PAYLOAD {
        return Err(WireError::PayloadTooLarge {
            len: payload.len() as u64,
            max: MAX_MESSAGE_PAYLOAD,
        });
    }
    let mpl = msg.max_payload_length(pver);
    if payload.len() as u64 > u64::from(mpl) {
        return Err(WireError::PayloadTooLarge {
            len: payload.len() as u64,
            max: u64::from(mpl),
        });
    }

    let checksum = dcroxide_chainhash::hash_b(&payload);
    let mut out = Vec::with_capacity(MESSAGE_HEADER_SIZE + payload.len());
    out.extend_from_slice(&net.0.to_le_bytes());
    let mut cmd_field = [0u8; COMMAND_SIZE];
    cmd_field[..command.len()].copy_from_slice(command.as_bytes());
    out.extend_from_slice(&cmd_field);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&checksum[..4]);
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Read, validate, and decode the next message from `buf` (dcrd
/// `ReadMessage`), returning the message and the number of bytes consumed.
/// The validation order matches dcrd exactly: global payload limit, network
/// magic, command form, known command, per-type payload limit, checksum,
/// payload decode, trailing bytes.
pub fn read_message(
    buf: &[u8],
    pver: u32,
    net: CurrencyNet,
) -> Result<(Message, usize), WireError> {
    let mut r = Cursor::new(buf);
    let magic = r.read_u32()?;
    let command_field: [u8; COMMAND_SIZE] = r.take_array()?;
    let payload_len = r.read_u32()?;
    let checksum: [u8; 4] = r.take_array()?;

    if u64::from(payload_len) > MAX_MESSAGE_PAYLOAD {
        return Err(WireError::PayloadTooLarge {
            len: u64::from(payload_len),
            max: MAX_MESSAGE_PAYLOAD,
        });
    }
    if magic != net.0 {
        return Err(WireError::WrongNetwork(magic));
    }

    // Trim trailing NULs, then require strict ASCII.
    let trimmed_len = command_field
        .iter()
        .rposition(|&b| b != 0)
        .map_or(0, |p| p + 1);
    let trimmed = &command_field[..trimmed_len];
    if !is_strict_ascii(trimmed) {
        return Err(WireError::MalformedCmd);
    }
    let command = String::from_utf8(trimmed.to_vec()).expect("strict ASCII is UTF-8");

    let Some(mpl) = max_payload_for_command(&command, pver) else {
        return Err(WireError::UnknownCmd);
    };
    if u64::from(payload_len) > u64::from(mpl) {
        return Err(WireError::PayloadTooLarge {
            len: u64::from(payload_len),
            max: u64::from(mpl),
        });
    }

    let payload = r.take(payload_len as usize)?;
    let payload_hash = dcroxide_chainhash::hash_b(payload);
    if payload_hash[..4] != checksum {
        return Err(WireError::PayloadChecksum);
    }

    let mut pr = Cursor::new(payload);
    let msg = decode_payload(&command, &mut pr, pver).expect("command known per max payload")?;
    if pr.remaining() > 0 {
        return Err(WireError::TrailingBytes);
    }

    Ok((msg, r.position()))
}
