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

use dcroxide_chainhash::{HASH_SIZE, Hash};

use crate::MAX_MESSAGE_PAYLOAD;
use crate::blockheader::MAX_BLOCK_HEADER_PAYLOAD;
use crate::cursor::Cursor;
use crate::error::{MessageText, WireError};
use crate::invvect::INV_VECT_PAYLOAD;
use crate::msg_cf::*;
use crate::msg_control::*;
use crate::msg_data::*;
use crate::msg_mix::*;
use crate::msgtx::{MsgTx, TxOut};
use crate::netaddress::MAX_NET_ADDRESS_PAYLOAD;
use crate::protocol::{CurrencyNet, SEND_HEADERS_VERSION, is_strict_ascii};
use crate::varint::var_int_serialize_size;

/// The number of bytes in a message header (dcrd `MessageHeaderSize`).
pub const MESSAGE_HEADER_SIZE: usize = 24;

/// The fixed size of the command field (dcrd `CommandSize`).
pub const COMMAND_SIZE: usize = 12;

/// A message hashed as it is read (dcrd's `hashable` interface in
/// `peer/peer.go`): the eight mixing messages, through their `mix_hash`.
trait MixHashable {
    /// The message's mixing identity hash.
    fn identity_hash(&self) -> Result<Hash, WireError>;
}

macro_rules! mix_hashable {
    ($($msg:ty),* $(,)?) => {
        $(impl MixHashable for $msg {
            fn identity_hash(&self) -> Result<Hash, WireError> {
                self.mix_hash()
            }
        })*
    };
}

mix_hashable!(
    MsgMixPairReq,
    MsgMixKeyExchange,
    MsgMixCiphertexts,
    MsgMixSlotReserve,
    MsgMixFactoredPoly,
    MsgMixDCNet,
    MsgMixConfirm,
    MsgMixSecrets,
);

/// A Decred P2P message (dcrd's `Message` interface, as a closed enum).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)] // Variant payloads are documented on their types.
pub enum Message {
    Version(MsgVersion),
    VerAck,
    GetAddr,
    Addr(MsgAddr),
    /// An `addrv2` message.
    AddrV2(MsgAddrV2),
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
            Message::AddrV2(_) => "addrv2",
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

    /// The mixing-message identity hash of one of the eight mixing
    /// messages, and `None` for every other message: dcrd's `hashable`
    /// type assertion (`peer/peer.go:956-959`), by which `readMessage`
    /// hashes a mixing message as it is read (`:975-977`) and
    /// `maybeRemoveDeadline` settles the request it answers
    /// (`:1156-1160`).  The inner error is the message's own `mix_hash`
    /// failure (see [`MsgMixPairReq::mix_hash`]).
    pub fn mix_hash(&self) -> Option<Result<Hash, WireError>> {
        self.as_mix().map(MixHashable::identity_hash)
    }

    /// Whether this is one of the eight mixing messages, the ones
    /// [`Message::mix_hash`] hashes, without hashing it.
    pub fn is_mix(&self) -> bool {
        self.as_mix().is_some()
    }

    /// The one list of mixing messages behind [`Message::mix_hash`] and
    /// [`Message::is_mix`], so the reader that hashes a mixing message
    /// and the deadline table that settles it by that hash cannot
    /// disagree about which messages those are.  It names every variant
    /// rather than ending in a wildcard, so a message type added later
    /// does not compile until it says whether it is one.
    fn as_mix(&self) -> Option<&dyn MixHashable> {
        match self {
            Message::MixPairReq(m) => Some(m),
            Message::MixKeyExchange(m) => Some(&**m),
            Message::MixCiphertexts(m) => Some(m),
            Message::MixSlotReserve(m) => Some(m),
            Message::MixFactoredPoly(m) => Some(m),
            Message::MixDCNet(m) => Some(m),
            Message::MixConfirm(m) => Some(m),
            Message::MixSecrets(m) => Some(m),
            Message::Version(_)
            | Message::VerAck
            | Message::GetAddr
            | Message::Addr(_)
            | Message::AddrV2(_)
            | Message::GetBlocks(_)
            | Message::Inv(_)
            | Message::GetData(_)
            | Message::NotFound(_)
            | Message::Block(_)
            | Message::Tx(_)
            | Message::GetHeaders(_)
            | Message::Headers(_)
            | Message::Ping(_)
            | Message::Pong(_)
            | Message::MemPool
            | Message::MiningState(_)
            | Message::GetMiningState
            | Message::Reject(_)
            | Message::SendHeaders
            | Message::FeeFilter(_)
            | Message::GetCFilter(_)
            | Message::GetCFHeaders(_)
            | Message::GetCFTypes
            | Message::CFilter(_)
            | Message::CFHeaders(_)
            | Message::CFTypes(_)
            | Message::GetCFilterV2(_)
            | Message::CFilterV2(_)
            | Message::GetInitState(_)
            | Message::InitState(_)
            | Message::GetCFsV2(_)
            | Message::CFiltersV2(_) => None,
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

    /// The number of bytes the payload encodes to (dcrd `SerializeSize`,
    /// which every message has carried since `e51406d1`), computed from
    /// the fields without encoding anything.
    ///
    /// Each arm is the formula of that message's dcrd `SerializeSize`.
    /// Like dcrd's, it takes no protocol version: a message's encoding
    /// has one size at every version where it encodes at all, and a
    /// message the encoder refuses still reports the size of its fields.
    /// For every message that encodes, it equals the encoded length.
    pub fn serialize_size(&self) -> usize {
        // Signature 64 + identity 33 + session id 32 + run 4, the prefix
        // every mix message after the pair request carries.
        const MIX_FIXED: usize = 64 + 33 + 32 + 4;
        match self {
            // dcrd `MsgVersion.SerializeSize`: the two addresses go out
            // without their timestamps.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "constants 4 + 8 + 8 + 2 * 26 + 8 + 4 + 1 = 85 plus var_bytes_size of the in-memory user agent, at most 9 + its length"
            )]
            Message::Version(m) => {
                4 + 8
                    + 8
                    + 2 * net_address_size(false)
                    + 8
                    + var_bytes_size(m.user_agent.len())
                    + 4
                    + 1
            }
            Message::VerAck
            | Message::GetAddr
            | Message::MemPool
            | Message::GetMiningState
            | Message::SendHeaders
            | Message::GetCFTypes => 0,
            // dcrd `MsgAddr.SerializeSize`.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "var_int_size <= 9 plus addr_list.len() * 30, and a NetAddress is 32 bytes in memory, so the product is below the list's allocation"
            )]
            Message::Addr(m) => {
                var_int_size(m.addr_list.len()) + m.addr_list.len() * net_address_size(true)
            }
            // dcrd `MsgAddrV2.SerializeSize` over `NetAddressV2.SerializeSize`:
            // timestamp 8 + services 8 + type 1 + address + port 2.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "var_int_size <= 9 plus 19 + encoded_addr.len() per address, and a NetAddressV2 is 48 bytes in memory plus its encoded_addr bytes, so the sum is below the list's allocations"
            )]
            Message::AddrV2(m) => {
                var_int_size(m.addr_list.len())
                    + m.addr_list
                        .iter()
                        .map(|na| 8 + 8 + 1 + na.encoded_addr.len() + 2)
                        .sum::<usize>()
            }
            // dcrd `MsgGetBlocks`/`MsgGetHeaders.SerializeSize`.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "constants 4 + 32 plus hash_list_size of an in-memory Vec<Hash>, at most 9 + its byte size"
            )]
            Message::GetBlocks(MsgGetBlocks(l)) | Message::GetHeaders(MsgGetHeaders(l)) => {
                4 + hash_list_size(l.block_locator_hashes.len()) + HASH_SIZE
            }
            // dcrd `MsgInv`/`MsgGetData`/`MsgNotFound.SerializeSize`.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "var_int_size <= 9 plus inv_list.len() * 36, and an InvVect is 36 bytes in memory, so the product is the list's allocation"
            )]
            Message::Inv(MsgInv { inv_list })
            | Message::GetData(MsgGetData { inv_list })
            | Message::NotFound(MsgNotFound { inv_list }) => {
                var_int_size(inv_list.len()) + inv_list.len() * INV_VECT_PAYLOAD as usize
            }
            Message::Block(m) => m.serialize_size(),
            Message::Tx(m) => m.serialize_size(),
            // dcrd `MsgHeaders.SerializeSize`: each header is followed by
            // a one-byte zero transaction count.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "var_int_size <= 9 plus headers.len() * 181, and a BlockHeader is 184 bytes in memory, so the product is below the list's allocation"
            )]
            Message::Headers(m) => {
                var_int_size(m.headers.len()) + m.headers.len() * (MAX_BLOCK_HEADER_PAYLOAD + 1)
            }
            Message::Ping(_) | Message::Pong(_) | Message::FeeFilter(_) => 8,
            // dcrd `MsgMiningState.SerializeSize`.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "constants 4 + 4 plus two hash_list_size terms, each at most 9 + the byte size of an in-memory Vec<Hash>"
            )]
            Message::MiningState(m) => {
                4 + 4 + hash_list_size(m.block_hashes.len()) + hash_list_size(m.vote_hashes.len())
            }
            // dcrd `MsgReject.SerializeSize`: block and tx rejects carry
            // the hash of what was rejected.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "at most (9 + cmd.len()) + 1 + (9 + reason.len()) + 32, over the lengths of two in-memory Strings"
            )]
            Message::Reject(m) => {
                let hash = if m.cmd == "block" || m.cmd == "tx" {
                    HASH_SIZE
                } else {
                    0
                };
                var_bytes_size(m.cmd.len()) + 1 + var_bytes_size(m.reason.len()) + hash
            }
            Message::GetCFilter(_) => HASH_SIZE + 1,
            // dcrd `MsgGetCFHeaders.SerializeSize`.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "hash_list_size of an in-memory Vec<Hash>, at most 9 + its byte size, plus constants 32 + 1"
            )]
            Message::GetCFHeaders(m) => {
                hash_list_size(m.block_locator_hashes.len()) + HASH_SIZE + 1
            }
            // dcrd `MsgCFilter.SerializeSize`.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "constants 32 + 1 plus var_bytes_size of an in-memory Vec<u8>, at most 9 + its length"
            )]
            Message::CFilter(m) => HASH_SIZE + 1 + var_bytes_size(m.data.len()),
            // dcrd `MsgCFHeaders.SerializeSize`.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "constants 32 + 1 plus hash_list_size of an in-memory Vec<Hash>, at most 9 + its byte size"
            )]
            Message::CFHeaders(m) => HASH_SIZE + 1 + hash_list_size(m.header_hashes.len()),
            // dcrd `MsgCFTypes.SerializeSize`: one byte per filter type.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "var_int_size <= 9 plus supported_filters.len(), the length of an in-memory Vec<u8>"
            )]
            Message::CFTypes(m) => {
                var_int_size(m.supported_filters.len()) + m.supported_filters.len()
            }
            Message::GetCFilterV2(_) => HASH_SIZE,
            Message::CFilterV2(m) => cfilter_v2_size(m),
            // dcrd `MsgGetInitState.SerializeSize`.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "var_int_size <= 9 plus 9 + t.len() per type, and a String is 24 bytes in memory plus its bytes, so the sum is below the list's allocations"
            )]
            Message::GetInitState(m) => {
                var_int_size(m.types.len())
                    + m.types
                        .iter()
                        .map(|t| var_bytes_size(t.len()))
                        .sum::<usize>()
            }
            // dcrd `MsgInitState.SerializeSize`.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "three hash_list_size terms, each at most 9 + the byte size of an in-memory Vec<Hash>"
            )]
            Message::InitState(m) => {
                hash_list_size(m.block_hashes.len())
                    + hash_list_size(m.vote_hashes.len())
                    + hash_list_size(m.tspend_hashes.len())
            }
            Message::GetCFsV2(_) => HASH_SIZE * 2,
            // dcrd `MsgCFiltersV2.SerializeSize`.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "var_int_size <= 9 plus cfilter_v2_size per filter, at most 54 + its data and proof-hash bytes, and a MsgCFilterV2 is 88 bytes in memory plus those bytes"
            )]
            Message::CFiltersV2(m) => {
                var_int_size(m.cfilters.len())
                    + m.cfilters.iter().map(cfilter_v2_size).sum::<usize>()
            }
            // dcrd `MsgMixPairReq.SerializeSize`.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "constants 64 + 33 + 4 + 8 + 2 + 4 + 4 + 8 + 1 + 2 = 130, varint sizes <= 9, at most 65 + three byte lengths per UTXO while a MixPairReqUTXO is 120 bytes in memory plus those bytes, and the change TxOut's own serialize_size"
            )]
            Message::MixPairReq(m) => {
                // Signature 64 + identity 33 + expiry 4 + mix amount 8,
                // then the script class, then tx version 2 + lock time 4
                // + message count 4 + input value 8.
                64 + 33
                    + 4
                    + 8
                    + var_bytes_size(m.script_class.len())
                    + 2
                    + 4
                    + 4
                    + 8
                    + var_int_size(m.utxos.len())
                    + m.utxos
                        .iter()
                        .map(|u| {
                            // Outpoint 37, three var-byte fields, opcode 1.
                            37 + var_bytes_size(u.script.len())
                                + var_bytes_size(u.pub_key.len())
                                + var_bytes_size(u.signature.len())
                                + 1
                        })
                        .sum::<usize>()
                    // The has-change flag, then the change output.
                    + 1
                    + m.change.as_ref().map_or(0, TxOut::serialize_size)
                    // Flags 1 + pairing flags 1.
                    + 2
            }
            // dcrd `MsgMixKeyExchange.SerializeSize`: epoch 8, run 4, pos
            // 4, ECDH key 33, PQ key 1218 and commitment 32 on top of the
            // signature, identity and session id.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "constants 64 + 33 + 32 + 8 + 4 + 4 + 33 + 1218 + 32 = 1428 plus hash_list_size of an in-memory Vec<Hash>, at most 9 + its byte size"
            )]
            Message::MixKeyExchange(m) => {
                64 + 33 + 32 + 8 + 4 + 4 + 33 + 1218 + 32 + hash_list_size(m.seen_prs.len())
            }
            // dcrd `MsgMixCiphertexts.SerializeSize`: one count covers the
            // ciphertexts and the seen key exchanges.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "MIX_FIXED 133 and var_int_size <= 9 plus ciphertexts.len() * 1047 and seen_key_exchanges.len() * 32, the byte sizes of an in-memory Vec<[u8; 1047]> and Vec<Hash>"
            )]
            Message::MixCiphertexts(m) => {
                MIX_FIXED
                    + var_int_size(m.ciphertexts.len())
                    + m.ciphertexts.len() * 1047
                    + m.seen_key_exchanges.len() * HASH_SIZE
            }
            // dcrd `MsgMixSlotReserve.SerializeSize`.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "MIX_FIXED 133, two varint sizes <= 9, 9 + v.len() per inner Vec<u8> (24 bytes in memory plus its bytes) and hash_list_size of an in-memory Vec<Hash>"
            )]
            Message::MixSlotReserve(m) => {
                let kpcount = m.dc_mix.first().map_or(0, Vec::len);
                MIX_FIXED
                    + var_int_size(m.dc_mix.len())
                    + var_int_size(kpcount)
                    + m.dc_mix
                        .iter()
                        .flatten()
                        .map(|v| var_bytes_size(v.len()))
                        .sum::<usize>()
                    + hash_list_size(m.seen_ciphertexts.len())
            }
            // dcrd `MsgMixFactoredPoly.SerializeSize`.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "MIX_FIXED 133, var_int_size <= 9, 9 + r.len() per root Vec<u8> (24 bytes in memory plus its bytes) and hash_list_size of an in-memory Vec<Hash>"
            )]
            Message::MixFactoredPoly(m) => {
                MIX_FIXED
                    + var_int_size(m.roots.len())
                    + m.roots
                        .iter()
                        .map(|r| var_bytes_size(r.len()))
                        .sum::<usize>()
                    + hash_list_size(m.seen_slot_reserves.len())
            }
            // dcrd `MsgMixDCNet.SerializeSize`: the vector count, and when
            // there are vectors, their length and the message size.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "MIX_FIXED 133, varint sizes <= 9, v.len() * 20 per MixVect (the byte size of its in-memory [u8; 20] elements) and hash_list_size of an in-memory Vec<Hash>"
            )]
            Message::MixDCNet(m) => {
                let vects = match m.dc_net.first() {
                    None => 0,
                    Some(first) => {
                        var_int_size(first.len())
                            + var_int_size(MIX_MSG_SIZE)
                            + m.dc_net
                                .iter()
                                .map(|v| v.len() * MIX_MSG_SIZE)
                                .sum::<usize>()
                    }
                };
                MIX_FIXED
                    + var_int_size(m.dc_net.len())
                    + vects
                    + hash_list_size(m.seen_slot_reserves.len())
            }
            // dcrd `MsgMixConfirm.SerializeSize`.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "MIX_FIXED 133 plus the mix MsgTx's own serialize_size and hash_list_size of an in-memory Vec<Hash>"
            )]
            Message::MixConfirm(m) => {
                MIX_FIXED + m.mix.serialize_size() + hash_list_size(m.seen_dc_nets.len())
            }
            // dcrd `MsgMixSecrets.SerializeSize`: the seed 32 after the
            // fixed prefix, and the message size only when there are
            // DC-net messages.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "MIX_FIXED 133 + seed 32, varint sizes <= 9, 9 + sr.len() per Vec<u8> (24 bytes in memory plus its bytes), dc_net_msgs.len() * 20 (the byte size of its in-memory [u8; 20] elements) and hash_list_size of an in-memory Vec<Hash>"
            )]
            Message::MixSecrets(m) => {
                let dc_net = if m.dc_net_msgs.is_empty() {
                    0
                } else {
                    var_int_size(MIX_MSG_SIZE) + m.dc_net_msgs.len() * MIX_MSG_SIZE
                };
                MIX_FIXED
                    + 32
                    + var_int_size(m.slot_reserve_msgs.len())
                    + m.slot_reserve_msgs
                        .iter()
                        .map(|sr| var_bytes_size(sr.len()))
                        .sum::<usize>()
                    + var_int_size(m.dc_net_msgs.len())
                    + dc_net
                    + hash_list_size(m.seen_secrets.len())
            }
        }
    }

    /// Encode the payload (dcrd `BtcEncode`).
    pub fn encode_payload(&self, pver: u32) -> Result<Vec<u8>, WireError> {
        let mut w = Vec::with_capacity(self.serialize_size());
        self.encode_payload_into(&mut w, pver)?;
        Ok(w)
    }

    /// Append the payload encoding to `w` (dcrd `BtcEncode` into the
    /// caller's buffer).  On error, `w` may hold a partial encoding.
    fn encode_payload_into(&self, w: &mut Vec<u8>, pver: u32) -> Result<(), WireError> {
        match self {
            Message::Version(m) => m.encode(w)?,
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
            Message::Addr(m) => m.encode(w, pver)?,
            Message::AddrV2(m) => m.encode(w, pver)?,
            Message::GetBlocks(m) => m.encode(w)?,
            Message::Inv(m) => encode_inv_message(w, &m.inv_list)?,
            Message::GetData(m) => encode_inv_message(w, &m.inv_list)?,
            Message::NotFound(m) => encode_inv_message(w, &m.inv_list)?,
            Message::Block(m) => m.encode(w),
            Message::Tx(m) => m.encode_into(w),
            Message::GetHeaders(m) => m.encode(w)?,
            Message::Headers(m) => m.encode(w)?,
            Message::Ping(m) => w.extend_from_slice(&m.nonce.to_le_bytes()),
            Message::Pong(m) => w.extend_from_slice(&m.nonce.to_le_bytes()),
            Message::MiningState(m) => m.encode(w)?,
            Message::Reject(m) => m.encode(w, pver)?,
            Message::FeeFilter(m) => m.encode(w, pver)?,
            Message::GetCFilter(m) => m.encode(w, pver)?,
            Message::GetCFHeaders(m) => m.encode(w, pver)?,
            Message::CFilter(m) => m.encode(w, pver)?,
            Message::CFHeaders(m) => m.encode(w, pver)?,
            Message::CFTypes(m) => m.encode(w, pver)?,
            Message::GetCFilterV2(m) => m.encode(w, pver)?,
            Message::CFilterV2(m) => m.encode(w, pver)?,
            Message::GetInitState(m) => m.encode(w, pver)?,
            Message::InitState(m) => m.encode(w, pver)?,
            Message::GetCFsV2(m) => m.encode(w, pver)?,
            Message::CFiltersV2(m) => m.encode(w, pver)?,
            Message::MixPairReq(m) => m.encode(w, pver)?,
            Message::MixKeyExchange(m) => m.encode(w, pver)?,
            Message::MixCiphertexts(m) => m.encode(w, pver)?,
            Message::MixSlotReserve(m) => m.encode(w, pver)?,
            Message::MixFactoredPoly(m) => m.encode(w, pver)?,
            Message::MixDCNet(m) => m.encode(w, pver)?,
            Message::MixConfirm(m) => m.encode(w, pver)?,
            Message::MixSecrets(m) => m.encode(w, pver)?,
        }
        Ok(())
    }
}

/// The size of a count's varint (dcrd `VarIntSerializeSize`).
fn var_int_size(n: usize) -> usize {
    var_int_serialize_size(n as u64)
}

/// The size of a varint-prefixed byte string of `len` bytes.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "len is an in-memory byte length (<= isize::MAX) and a varint size is at most 9"
)]
fn var_bytes_size(len: usize) -> usize {
    var_int_size(len) + len
}

/// The size of a varint-counted list of `n` hashes.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "n is the length of an in-memory Vec<Hash>, so n * 32 <= isize::MAX, and a varint size is at most 9"
)]
fn hash_list_size(n: usize) -> usize {
    var_int_size(n) + n * HASH_SIZE
}

/// dcrd `NetAddress.SerializeSize`: services 8 + IP 16 + port 2, plus
/// the 4-byte timestamp where the context carries one.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "full is MAX_NET_ADDRESS_PAYLOAD = 30"
)]
fn net_address_size(with_timestamp: bool) -> usize {
    let full = MAX_NET_ADDRESS_PAYLOAD as usize;
    if with_timestamp { full } else { full - 4 }
}

/// dcrd `MsgCFilterV2.SerializeSize`: block hash, filter data, proof
/// index 4 and the proof hashes.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "constants 32 + 4 plus the sizes of the filter's in-memory data and proof-hash list, bounded by its allocation"
)]
fn cfilter_v2_size(m: &MsgCFilterV2) -> usize {
    HASH_SIZE + var_bytes_size(m.data.len()) + 4 + hash_list_size(m.proof_hashes.len())
}

/// The per-type maximum payload for a command, or `None` for unknown
/// commands (mirrors `makeEmptyMessage` + `MaxPayloadLength`).
fn max_payload_for_command(command: &str, pver: u32) -> Option<u32> {
    Some(match command {
        "version" => MsgVersion::max_payload_length(pver),
        "verack" | "getaddr" | "mempool" | "getminings" | "sendheaders" | "getcftypes" => 0,
        "addr" => MsgAddr::max_payload_length(pver),
        "addrv2" => MsgAddrV2::max_payload_length(pver),
        "getblocks" | "getheaders" => BlockLocator::max_payload_length(pver),
        "inv" | "getdata" | "notfound" => inv_message_max_payload(pver),
        "block" => MsgBlock::max_payload_length(pver),
        "tx" => MsgBlock::max_payload_length(pver),
        "headers" => MsgHeaders::max_payload_length(pver),
        "ping" | "pong" => 8,
        "miningstate" => MsgMiningState::max_payload_length(pver),
        "feefilter" => 8,
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "constant: HASH_SIZE + 1 = 33"
        )]
        "getcfilter" => dcroxide_chainhash::HASH_SIZE as u32 + 1,
        "getcfheaders" => MsgGetCFHeaders::max_payload_length(pver),
        "cfilter" => MsgCFilter::max_payload_length(pver),
        "cfheaders" => MsgCFHeaders::max_payload_length(pver),
        "cftypes" => MsgCFTypes::max_payload_length(pver),
        "getcfilterv2" => dcroxide_chainhash::HASH_SIZE as u32,
        "cfilterv2" => MsgCFilterV2::max_payload_length(pver),
        "getinitstate" => MsgGetInitState::max_payload_length(pver),
        "initstate" => MsgInitState::max_payload_length(pver),
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "constant: HASH_SIZE * 2 = 64"
        )]
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
    let msg =
        decode_payload(command, &mut r, pver).ok_or(WireError::InvalidMsg(MessageText::NONE))??;
    if r.remaining() != 0 {
        return Err(WireError::InvalidMsg(MessageText::NONE));
    }
    Ok(msg)
}

/// Decode a standalone payload for a known command at the given
/// protocol version without requiring the payload to be fully
/// consumed; for callers mirroring dcrd handlers that stream from a
/// lazy reader and never read past the end of the message.
pub fn decode_message_payload_prefix(
    command: &str,
    payload: &[u8],
    pver: u32,
) -> Result<Message, WireError> {
    let mut r = Cursor::new(payload);
    decode_payload(command, &mut r, pver).ok_or(WireError::InvalidMsg(MessageText::NONE))?
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
        "addr" => MsgAddr::decode(r, pver).map(Message::Addr),
        "addrv2" => MsgAddrV2::decode(r, pver).map(Message::AddrV2),
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
///
/// Like dcrd's `WriteMessageN`, the frame is one buffer sized by
/// [`Message::serialize_size`]: a zeroed header, the payload encoded
/// straight after it, and the header filled in once the payload's
/// length and checksum are known.
pub fn write_message(msg: &Message, pver: u32, net: CurrencyNet) -> Result<Vec<u8>, WireError> {
    let command = msg.command();
    // Commands are static strings that always fit, but keep the dcrd check.
    if command.len() > COMMAND_SIZE {
        return Err(WireError::CmdTooLong);
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "serialize_size is bounded by the message's in-memory size, far below usize::MAX - 24"
    )]
    let mut out = Vec::with_capacity(MESSAGE_HEADER_SIZE + msg.serialize_size());
    out.resize(MESSAGE_HEADER_SIZE, 0);
    msg.encode_payload_into(&mut out, pver)?;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "out.len() >= MESSAGE_HEADER_SIZE: out was resized to it and encoding only appends"
    )]
    let payload_len = out.len() - MESSAGE_HEADER_SIZE;
    if payload_len as u64 > MAX_MESSAGE_PAYLOAD {
        return Err(WireError::PayloadTooLarge {
            len: payload_len as u64,
            max: MAX_MESSAGE_PAYLOAD,
        });
    }
    let mpl = msg.max_payload_length(pver);
    if payload_len as u64 > u64::from(mpl) {
        return Err(WireError::PayloadTooLarge {
            len: payload_len as u64,
            max: u64::from(mpl),
        });
    }

    let checksum = dcroxide_chainhash::hash_b(&out[MESSAGE_HEADER_SIZE..]);
    let (header, _) = out.split_at_mut(MESSAGE_HEADER_SIZE);
    header[..4].copy_from_slice(&net.0.to_le_bytes());
    // The command field is already zeroed, which is its NUL padding.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "command.len() <= COMMAND_SIZE (12), checked above"
    )]
    header[4..4 + command.len()].copy_from_slice(command.as_bytes());
    header[4 + COMMAND_SIZE..8 + COMMAND_SIZE].copy_from_slice(&(payload_len as u32).to_le_bytes());
    header[8 + COMMAND_SIZE..].copy_from_slice(&checksum[..4]);
    Ok(out)
}

/// A validated fixed-size message header (dcrd `messageHeader` once
/// `readMessageN` has run its pre-payload checks).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageHeader {
    /// The command, with the trailing NUL padding removed.
    pub command: String,
    /// The declared payload length, already checked against both the
    /// global cap and the per-type maximum for `command`.
    pub payload_len: u32,
    /// The first four bytes of the BLAKE-256 of the payload.
    pub checksum: [u8; 4],
}

/// Validate the fixed-size header at the front of `buf` without
/// touching the payload (dcrd's `readMessageN` checks up to, but not
/// including, `payload := make([]byte, hdr.length)`).
///
/// This exists so a reader can bound the payload allocation by the
/// per-command maximum before reserving anything: the declared length
/// arrives in 24 attacker-controlled bytes, and validating only after
/// the payload has been buffered would let a peer reserve the global
/// 32 MiB cap per connection and then never send the bytes.
///
/// The checks run in dcrd's order — global payload limit, network
/// magic, command form, known command, per-type payload limit — so the
/// error a peer sees does not depend on how the caller framed the read.
pub fn read_message_header(
    buf: &[u8],
    pver: u32,
    net: CurrencyNet,
) -> Result<MessageHeader, WireError> {
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
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "p < COMMAND_SIZE (12): it is an index into command_field"
    )]
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

    Ok(MessageHeader {
        command,
        payload_len,
        checksum,
    })
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
    let MessageHeader {
        command,
        payload_len,
        checksum,
    } = read_message_header(buf, pver, net)?;

    let mut r = Cursor::new(buf);
    r.take(MESSAGE_HEADER_SIZE)?;
    let payload = r.take(payload_len as usize)?;
    let payload_hash = dcroxide_chainhash::hash_b(payload);
    if payload_hash[..4] != checksum {
        return Err(WireError::PayloadChecksum);
    }

    // `read_message_header` accepted the command from the payload-limit
    // table, and the decode table is a separate match.  Were the two
    // ever to disagree, the frame fails as dcrd's unknown command would
    // rather than panicking on a peer's bytes.
    let mut pr = Cursor::new(payload);
    let msg = decode_payload(&command, &mut pr, pver).ok_or(WireError::UnknownCmd)??;
    if pr.remaining() > 0 {
        return Err(WireError::TrailingBytes);
    }

    Ok((msg, r.position()))
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic over small fixed values"
)]
mod tests {
    use alloc::boxed::Box;
    use alloc::collections::BTreeSet;
    use alloc::vec;

    use dcroxide_chainhash::Hash;

    use super::*;
    use crate::blockheader::BlockHeader;
    use crate::invvect::{InvType, InvVect};
    use crate::msgtx::{OutPoint, TxIn, TxSerializeType};
    use crate::netaddress::{NetAddress, NetAddressType, NetAddressV2};
    use crate::protocol::{ADDR_V2_VERSION, PROTOCOL_VERSION, REMOVE_REJECT_VERSION};

    /// The number of `Message` variants, one per dcrd command.
    const VARIANTS: usize = 41;

    /// A dense index per variant.  The match is exhaustive on purpose: a
    /// new variant does not compile until it is numbered here, and then
    /// [`samples`] fails the coverage check until it has a sample.
    fn variant(m: &Message) -> usize {
        match m {
            Message::Version(_) => 0,
            Message::VerAck => 1,
            Message::GetAddr => 2,
            Message::Addr(_) => 3,
            Message::AddrV2(_) => 4,
            Message::GetBlocks(_) => 5,
            Message::Inv(_) => 6,
            Message::GetData(_) => 7,
            Message::NotFound(_) => 8,
            Message::Block(_) => 9,
            Message::Tx(_) => 10,
            Message::GetHeaders(_) => 11,
            Message::Headers(_) => 12,
            Message::Ping(_) => 13,
            Message::Pong(_) => 14,
            Message::MemPool => 15,
            Message::MiningState(_) => 16,
            Message::GetMiningState => 17,
            Message::Reject(_) => 18,
            Message::SendHeaders => 19,
            Message::FeeFilter(_) => 20,
            Message::GetCFilter(_) => 21,
            Message::GetCFHeaders(_) => 22,
            Message::GetCFTypes => 23,
            Message::CFilter(_) => 24,
            Message::CFHeaders(_) => 25,
            Message::CFTypes(_) => 26,
            Message::GetCFilterV2(_) => 27,
            Message::CFilterV2(_) => 28,
            Message::GetInitState(_) => 29,
            Message::InitState(_) => 30,
            Message::GetCFsV2(_) => 31,
            Message::CFiltersV2(_) => 32,
            Message::MixPairReq(_) => 33,
            Message::MixKeyExchange(_) => 34,
            Message::MixCiphertexts(_) => 35,
            Message::MixSlotReserve(_) => 36,
            Message::MixFactoredPoly(_) => 37,
            Message::MixDCNet(_) => 38,
            Message::MixConfirm(_) => 39,
            Message::MixSecrets(_) => 40,
        }
    }

    /// The protocol version a sample encodes at: the legacy `addr` and
    /// `reject` stop encoding at `addrv2` and at reject removal.
    fn encode_pver(m: &Message) -> u32 {
        match m {
            Message::Addr(_) => ADDR_V2_VERSION - 1,
            Message::Reject(_) => REMOVE_REJECT_VERSION - 1,
            _ => PROTOCOL_VERSION,
        }
    }

    fn hashes(n: usize) -> Vec<Hash> {
        (0..n).map(|i| Hash([i as u8; 32])).collect()
    }

    fn header() -> BlockHeader {
        BlockHeader::decode(&mut Cursor::new(&[7u8; MAX_BLOCK_HEADER_PAYLOAD])).expect("header")
    }

    fn tx(ins: usize, outs: usize) -> MsgTx {
        MsgTx {
            ser_type: TxSerializeType::Full,
            version: 3,
            tx_in: (0..ins)
                .map(|i| TxIn {
                    previous_out_point: OutPoint {
                        hash: Hash([i as u8; 32]),
                        index: i as u32,
                        tree: 1,
                    },
                    sequence: 9,
                    value_in: 10,
                    block_height: 11,
                    block_index: 12,
                    signature_script: vec![0x51; 3 + i],
                })
                .collect(),
            tx_out: (0..outs)
                .map(|i| TxOut {
                    value: 5,
                    version: 0,
                    pk_script: vec![0x6a; 25 + i],
                })
                .collect(),
            lock_time: 13,
            expiry: 14,
        }
    }

    fn cfilter_v2(data: usize, proofs: usize) -> MsgCFilterV2 {
        MsgCFilterV2 {
            block_hash: Hash([1; 32]),
            data: vec![0xab; data],
            proof_index: 3,
            proof_hashes: hashes(proofs),
        }
    }

    fn inv(n: usize) -> Vec<InvVect> {
        (0..n)
            .map(|i| InvVect {
                inv_type: InvType::TX,
                hash: Hash([i as u8; 32]),
            })
            .collect()
    }

    /// At least one sample of every variant, with the variable-length
    /// parts at 0, 1 and a few entries, and at 253 where a varint then
    /// takes three bytes.
    fn samples() -> Vec<Message> {
        let mut out = vec![
            Message::Version(MsgVersion {
                protocol_version: 12,
                user_agent: "/dcroxide:0.1.0/".into(),
                ..MsgVersion::default()
            }),
            Message::Version(MsgVersion {
                user_agent: "a".repeat(253),
                ..MsgVersion::default()
            }),
            Message::VerAck,
            Message::GetAddr,
            Message::Addr(MsgAddr {
                addr_list: vec![NetAddress::default(); 3],
            }),
            Message::Addr(MsgAddr {
                addr_list: vec![NetAddress::default(); 253],
            }),
            Message::AddrV2(MsgAddrV2 {
                addr_list: vec![
                    NetAddressV2 {
                        addr_type: NetAddressType::IPV4,
                        encoded_addr: vec![127, 0, 0, 1],
                        port: 9108,
                        ..NetAddressV2::default()
                    },
                    NetAddressV2 {
                        addr_type: NetAddressType::IPV6,
                        encoded_addr: vec![0xfd; 16],
                        port: 9108,
                        ..NetAddressV2::default()
                    },
                ],
            }),
            Message::GetBlocks(MsgGetBlocks(BlockLocator {
                protocol_version: 12,
                block_locator_hashes: hashes(3),
                hash_stop: Hash([9; 32]),
            })),
            Message::GetHeaders(MsgGetHeaders(BlockLocator {
                protocol_version: 12,
                block_locator_hashes: hashes(253),
                hash_stop: Hash::ZERO,
            })),
            Message::Inv(MsgInv { inv_list: inv(0) }),
            Message::Inv(MsgInv { inv_list: inv(253) }),
            Message::GetData(MsgGetData { inv_list: inv(2) }),
            Message::NotFound(MsgNotFound { inv_list: inv(1) }),
            Message::Block(MsgBlock {
                header: header(),
                transactions: vec![tx(1, 2), tx(2, 1)],
                stransactions: vec![tx(0, 0)],
            }),
            Message::Tx(tx(2, 3)),
            Message::Tx(MsgTx {
                ser_type: TxSerializeType::NoWitness,
                ..tx(1, 253)
            }),
            Message::Tx(MsgTx {
                ser_type: TxSerializeType::OnlyWitness,
                tx_out: Vec::new(),
                ..tx(253, 0)
            }),
            Message::Headers(MsgHeaders {
                headers: vec![header(); 2],
            }),
            Message::Headers(MsgHeaders {
                headers: vec![header(); 253],
            }),
            Message::Ping(MsgPing { nonce: 1 }),
            Message::Pong(MsgPong { nonce: 2 }),
            Message::MemPool,
            Message::MiningState(MsgMiningState {
                version: 1,
                height: 2,
                block_hashes: hashes(2),
                vote_hashes: hashes(5),
            }),
            Message::GetMiningState,
            Message::Reject(MsgReject {
                cmd: "block".into(),
                code: 0x10,
                reason: "bad".into(),
                hash: Hash([4; 32]),
            }),
            Message::Reject(MsgReject {
                cmd: "tx".into(),
                code: 0x10,
                reason: String::new(),
                hash: Hash([4; 32]),
            }),
            Message::Reject(MsgReject {
                cmd: "ping".into(),
                code: 0x01,
                reason: "r".repeat(253),
                hash: Hash::ZERO,
            }),
            Message::SendHeaders,
            Message::FeeFilter(MsgFeeFilter { min_fee: 10_000 }),
            Message::GetCFilter(MsgGetCFilter {
                block_hash: Hash([2; 32]),
                filter_type: 1,
            }),
            Message::GetCFHeaders(MsgGetCFHeaders {
                block_locator_hashes: hashes(4),
                hash_stop: Hash([3; 32]),
                filter_type: 0,
            }),
            Message::GetCFTypes,
            Message::CFilter(MsgCFilter {
                block_hash: Hash([5; 32]),
                filter_type: 0,
                data: vec![0xcd; 253],
            }),
            Message::CFHeaders(MsgCFHeaders {
                stop_hash: Hash([6; 32]),
                filter_type: 1,
                header_hashes: hashes(253),
            }),
            Message::CFTypes(MsgCFTypes {
                supported_filters: vec![0, 1],
            }),
            Message::CFTypes(MsgCFTypes {
                supported_filters: vec![0; 253],
            }),
            Message::GetCFilterV2(MsgGetCFilterV2 {
                block_hash: Hash([7; 32]),
            }),
            Message::CFilterV2(cfilter_v2(0, 0)),
            Message::CFilterV2(cfilter_v2(300, 5)),
            Message::GetInitState(MsgGetInitState {
                types: vec!["headblocks".into(), "headblockvotes".into(), String::new()],
            }),
            Message::InitState(MsgInitState {
                block_hashes: hashes(1),
                vote_hashes: hashes(5),
                tspend_hashes: hashes(0),
            }),
            Message::GetCFsV2(MsgGetCFsV2 {
                start_hash: Hash([8; 32]),
                end_hash: Hash([9; 32]),
            }),
            Message::CFiltersV2(MsgCFiltersV2 {
                cfilters: vec![cfilter_v2(10, 1), cfilter_v2(253, 0), cfilter_v2(0, 32)],
            }),
        ];

        let pair_req = |change: Option<TxOut>, utxos: Vec<MixPairReqUTXO>| MsgMixPairReq {
            signature: [1; 64],
            identity: [2; 33],
            expiry: 100,
            mix_amount: 1_000,
            script_class: "P2PKH-secp256k1-v0".into(),
            tx_version: 1,
            lock_time: 0,
            message_count: 2,
            input_value: 5_000,
            utxos,
            change,
            flags: 1,
            pairing_flags: 0,
        };
        out.push(Message::MixPairReq(pair_req(None, Vec::new())));
        out.push(Message::MixPairReq(pair_req(
            Some(TxOut {
                value: 7,
                version: 0,
                pk_script: vec![0x76; 25],
            }),
            vec![
                MixPairReqUTXO {
                    script: vec![0x51; 253],
                    pub_key: vec![0x02; 33],
                    signature: vec![0x30; 64],
                    opcode: 0xac,
                    ..MixPairReqUTXO::default()
                },
                MixPairReqUTXO::default(),
            ],
        )));
        out.push(Message::MixKeyExchange(Box::new(MsgMixKeyExchange {
            signature: [1; 64],
            identity: [2; 33],
            session_id: [3; 32],
            epoch: 4,
            run: 5,
            pos: 6,
            ecdh: [7; 33],
            pqpk: [8; 1218],
            commitment: [9; 32],
            seen_prs: hashes(3),
        })));
        out.push(Message::MixCiphertexts(MsgMixCiphertexts {
            signature: [1; 64],
            identity: [2; 33],
            session_id: [3; 32],
            run: 0,
            ciphertexts: vec![[0xee; 1047]; 2],
            seen_key_exchanges: hashes(2),
        }));
        out.push(Message::MixSlotReserve(MsgMixSlotReserve {
            signature: [1; 64],
            identity: [2; 33],
            session_id: [3; 32],
            run: 0,
            dc_mix: vec![vec![vec![0x11; 32], vec![0x22; 20], Vec::new()]; 2],
            seen_ciphertexts: hashes(3),
        }));
        out.push(Message::MixFactoredPoly(MsgMixFactoredPoly {
            signature: [1; 64],
            identity: [2; 33],
            session_id: [3; 32],
            run: 0,
            roots: vec![vec![0x33; 32], vec![0x44; 1]],
            seen_slot_reserves: hashes(2),
        }));
        out.push(Message::MixDCNet(MsgMixDCNet {
            signature: [1; 64],
            identity: [2; 33],
            session_id: [3; 32],
            run: 0,
            dc_net: vec![vec![[0x55; MIX_MSG_SIZE]; 3]; 2],
            seen_slot_reserves: hashes(2),
        }));
        out.push(Message::MixConfirm(MsgMixConfirm {
            signature: [1; 64],
            identity: [2; 33],
            session_id: [3; 32],
            run: 0,
            mix: tx(3, 4),
            seen_dc_nets: hashes(3),
        }));
        for dc_net_msgs in [Vec::new(), vec![[0x66; MIX_MSG_SIZE]; 253]] {
            out.push(Message::MixSecrets(MsgMixSecrets {
                signature: [1; 64],
                identity: [2; 33],
                session_id: [3; 32],
                run: 0,
                seed: [4; 32],
                slot_reserve_msgs: vec![vec![0x77; 32], Vec::new()],
                dc_net_msgs,
                seen_secrets: hashes(2),
            }));
        }
        out
    }

    #[test]
    fn samples_cover_every_variant() {
        let covered: BTreeSet<usize> = samples().iter().map(variant).collect();
        assert_eq!(covered, (0..VARIANTS).collect::<BTreeSet<_>>());
    }

    /// `mix_hash` hashes exactly dcrd's `hashable` messages, the eight
    /// mixing commands, each with its own type's hash, and `is_mix`
    /// agrees with it on every message.
    #[test]
    fn mix_hash_covers_exactly_the_mixing_messages() {
        let mut hashed = BTreeSet::new();
        for msg in samples() {
            let got = msg.mix_hash();
            assert_eq!(msg.is_mix(), got.is_some(), "{}", msg.command());
            let want = match &msg {
                Message::MixPairReq(m) => Some(m.mix_hash()),
                Message::MixKeyExchange(m) => Some(m.mix_hash()),
                Message::MixCiphertexts(m) => Some(m.mix_hash()),
                Message::MixSlotReserve(m) => Some(m.mix_hash()),
                Message::MixFactoredPoly(m) => Some(m.mix_hash()),
                Message::MixDCNet(m) => Some(m.mix_hash()),
                Message::MixConfirm(m) => Some(m.mix_hash()),
                Message::MixSecrets(m) => Some(m.mix_hash()),
                _ => None,
            };
            assert_eq!(got, want, "{}", msg.command());
            if got.is_some() {
                hashed.insert(msg.command());
            }
        }
        let mixing: BTreeSet<&str> = [
            "mixpairreq",
            "mixkeyxchg",
            "mixcphrtxt",
            "mixslotres",
            "mixfactpoly",
            "mixdcnet",
            "mixconfirm",
            "mixsecrets",
        ]
        .into_iter()
        .collect();
        assert_eq!(hashed, mixing);
    }

    /// `serialize_size` is the exact encoded length for every message,
    /// and `write_message` frames it in one allocation of exactly that
    /// size plus the header: a size off in either direction would leave
    /// the frame's capacity larger than its length.
    #[test]
    fn serialize_size_is_the_encoded_length() {
        for msg in samples() {
            let pver = encode_pver(&msg);
            let payload = msg.encode_payload(pver).unwrap_or_else(|e| {
                panic!("{} encodes at {pver}: {e}", msg.command());
            });
            assert_eq!(msg.serialize_size(), payload.len(), "{}", msg.command());

            let frame = write_message(&msg, pver, CurrencyNet::MAIN_NET).expect("frames");
            assert_eq!(frame.len(), MESSAGE_HEADER_SIZE + payload.len());
            assert_eq!(frame.capacity(), frame.len(), "{} regrew", msg.command());
            assert_eq!(frame[MESSAGE_HEADER_SIZE..], payload[..]);
        }
    }

    /// The in-place framing writes the header dcrd's `WriteMessageN`
    /// does: magic, NUL-padded command, payload length, checksum.
    #[test]
    fn write_message_header_fields() {
        let msg = Message::Ping(MsgPing {
            nonce: 0x0102_0304_0506_0708,
        });
        let frame = write_message(&msg, PROTOCOL_VERSION, CurrencyNet::TEST_NET3).expect("frames");
        let payload = 0x0102_0304_0506_0708u64.to_le_bytes();
        let mut want = Vec::new();
        want.extend_from_slice(&CurrencyNet::TEST_NET3.0.to_le_bytes());
        want.extend_from_slice(b"ping\0\0\0\0\0\0\0\0");
        want.extend_from_slice(&8u32.to_le_bytes());
        want.extend_from_slice(&dcroxide_chainhash::hash_b(&payload)[..4]);
        want.extend_from_slice(&payload);
        assert_eq!(frame, want);
        let (back, used) =
            read_message(&frame, PROTOCOL_VERSION, CurrencyNet::TEST_NET3).expect("reads");
        assert_eq!((back, used), (msg, frame.len()));
    }

    /// A refused encode still fails the frame, with the encoder's error.
    #[test]
    fn write_message_surfaces_encode_errors() {
        let addr = Message::Addr(MsgAddr::default());
        assert_eq!(
            write_message(&addr, ADDR_V2_VERSION, CurrencyNet::MAIN_NET),
            Err(WireError::MsgInvalidForPVer)
        );
    }

    /// The header check (`max_payload_for_command`) and the decoder
    /// (`decode_payload`) are separate matches, so nothing but this test
    /// holds them together: every command the header accepts must have
    /// a decoder, at every protocol version, and `reject` (QK-0001) and
    /// unknown commands must be in neither.
    #[test]
    fn payload_limit_and_decode_tables_agree() {
        let empty: &[u8] = &[];
        let mut commands: BTreeSet<&str> = samples().iter().map(Message::command).collect();
        assert!(commands.remove("reject"));
        for pver in 0..=PROTOCOL_VERSION + 1 {
            for &cmd in &commands {
                assert!(
                    max_payload_for_command(cmd, pver).is_some(),
                    "{cmd} has no payload limit at {pver}"
                );
                assert!(
                    decode_payload(cmd, &mut Cursor::new(empty), pver).is_some(),
                    "{cmd} has no decoder at {pver}"
                );
            }
            for cmd in ["reject", "", "unknown", "Version"] {
                assert!(max_payload_for_command(cmd, pver).is_none(), "{cmd}");
                assert!(decode_payload(cmd, &mut Cursor::new(empty), pver).is_none());
            }
        }
        assert_eq!(commands.len(), VARIANTS - 1);
        assert!(commands.iter().all(|c| c.len() <= COMMAND_SIZE));
    }
}
