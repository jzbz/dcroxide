// SPDX-License-Identifier: ISC
//! Decred P2P wire protocol types and codecs, mirroring dcrd's `wire`
//! package (module version v1.7.5, as pinned by dcrd release-v2.1.5).
//!
//! Currently implemented: variable-length integers, transactions ([`MsgTx`])
//! with all three serialization types and their BLAKE-256 hashes, and the
//! 180-byte [`BlockHeader`]. The remaining message types land with Phase 2 of
//! the project plan.
//!
//! # Decoding model
//!
//! dcrd decodes from `io.Reader`s; this crate decodes from byte slices via
//! [`Cursor`], which is equivalent for length-prefixed P2P messages and for
//! stored data. Like dcrd's `Deserialize`/`FromBytes`, decoding does **not**
//! reject trailing bytes; `from_bytes` constructors return the number of
//! bytes consumed so callers can enforce their own framing.
//!
//! Encoding of every implemented type is canonical (dcrd rejects
//! non-canonical varints), so `encode(decode(bytes)) == bytes` holds for the
//! consumed prefix — a property exercised by the fuzz targets and
//! differential tests.

#![cfg_attr(not(test), no_std)]
// Wire arithmetic is cursor positions and serialize-size sums, all bounded by
// slice lengths / in-memory object sizes (dcrd likewise uses plain int math
// here). The workspace lint stays on for the consensus-math crates.
#![allow(clippy::arithmetic_side_effects)]

extern crate alloc;

mod blockheader;
mod cursor;
mod error;
mod invvect;
mod message;
mod msg_cf;
mod msg_control;
mod msg_data;
mod msg_mix;
mod msgtx;
mod netaddress;
mod protocol;
mod varint;

pub use blockheader::{BlockHeader, MAX_BLOCK_HEADER_PAYLOAD};
pub use cursor::Cursor;
pub use error::WireError;
pub use invvect::{InvType, InvVect, MAX_INV_PER_MSG};
pub use message::{
    COMMAND_SIZE, MESSAGE_HEADER_SIZE, Message, decode_message_payload,
    decode_message_payload_prefix, read_message, write_message,
};
pub use msg_cf::{
    FilterType, MAX_CFHEADERS_PER_MSG, MAX_CFILTER_DATA_SIZE, MAX_CFILTERS_V2_PER_BATCH,
    MAX_FILTER_TYPES_PER_MSG, MAX_HEADER_PROOF_HASHES, MsgCFHeaders, MsgCFTypes, MsgCFilter,
    MsgCFilterV2, MsgCFiltersV2, MsgGetCFHeaders, MsgGetCFilter, MsgGetCFilterV2, MsgGetCFsV2,
};
pub use msg_control::{
    MAX_ADDR_PER_MSG, MAX_ADDR_PER_V2_MSG, MAX_USER_AGENT_LEN, MsgAddr, MsgAddrV2, MsgFeeFilter,
    MsgPing, MsgPong, MsgReject, MsgVersion, RejectCode,
};
pub use msg_data::{
    BlockLocator, INIT_STATE_HEAD_BLOCK_VOTES, INIT_STATE_HEAD_BLOCKS, INIT_STATE_TSPENDS,
    MAX_BLOCK_HEADERS_PER_MSG, MAX_BLOCK_LOCATORS_PER_MSG, MAX_BLOCK_PAYLOAD, MAX_BLOCK_PAYLOAD_V3,
    MAX_INIT_STATE_TYPE_LEN, MAX_INIT_STATE_TYPES, MAX_IS_BLOCKS_AT_HEAD_PER_MSG,
    MAX_IS_TSPENDS_AT_HEAD_PER_MSG, MAX_IS_VOTES_AT_HEAD_PER_MSG, MAX_MS_BLOCKS_AT_HEAD_PER_MSG,
    MAX_MS_VOTES_AT_HEAD_PER_MSG, MsgBlock, MsgGetBlocks, MsgGetData, MsgGetHeaders,
    MsgGetInitState, MsgHeaders, MsgInitState, MsgInv, MsgMiningState, MsgNotFound,
    max_tx_per_tx_tree,
};
pub use msg_mix::{
    MAX_MIX_FIELD_VAL_LEN, MAX_MIX_MCOUNT, MAX_MIX_PAIR_REQ_SCRIPT_CLASS_LEN,
    MAX_MIX_PAIR_REQ_UTXO_PUB_KEY_LEN, MAX_MIX_PAIR_REQ_UTXO_SCRIPT_LEN,
    MAX_MIX_PAIR_REQ_UTXO_SIGNATURE_LEN, MAX_MIX_PAIR_REQ_UTXOS, MAX_MIX_PEERS, MIX_MSG_SIZE,
    MixPairReqUTXO, MixVect, MsgMixCiphertexts, MsgMixConfirm, MsgMixDCNet, MsgMixFactoredPoly,
    MsgMixKeyExchange, MsgMixPairReq, MsgMixSecrets, MsgMixSlotReserve,
};
pub use msgtx::{
    DEFAULT_PK_SCRIPT_VERSION, MAX_PREV_OUT_INDEX, MAX_TX_IN_PER_MESSAGE, MAX_TX_IN_SEQUENCE_NUM,
    MAX_TX_OUT_PER_MESSAGE, MsgTx, NO_EXPIRY_VALUE, NULL_BLOCK_HEIGHT, NULL_BLOCK_INDEX,
    NULL_VALUE_IN, OutPoint, SEQUENCE_LOCK_TIME_DISABLED, SEQUENCE_LOCK_TIME_GRANULARITY,
    SEQUENCE_LOCK_TIME_IS_SECONDS, SEQUENCE_LOCK_TIME_MASK, TX_TREE_REGULAR, TX_TREE_STAKE,
    TX_TREE_UNKNOWN, TX_VERSION, TxIn, TxOut, TxSerializeType,
};
pub use netaddress::{
    MAX_NET_ADDRESS_PAYLOAD, MAX_NET_ADDRESS_PAYLOAD_V2, NetAddress, NetAddressType, NetAddressV2,
};
pub use protocol::{
    ADDR_V2_VERSION, BATCHED_CFILTERS_V2_VERSION, CFILTER_V2_VERSION, CurrencyNet,
    FEE_FILTER_VERSION, INIT_STATE_VERSION, INITIAL_PROTOCOL_VERSION, MAX_BLOCK_SIZE_VERSION,
    MIX_VERSION, NODE_BLOOM_VERSION, NODE_CF_VERSION, PROTOCOL_VERSION, REMOVE_REJECT_VERSION,
    SEND_HEADERS_VERSION, ServiceFlag,
};
pub use varint::{read_var_int, var_int_serialize_size, write_var_int};

/// The maximum bytes a message can be regardless of other individual limits
/// imposed by messages themselves (32 MiB), matching dcrd
/// `wire.MaxMessagePayload`.
pub const MAX_MESSAGE_PAYLOAD: u64 = 1024 * 1024 * 32;
