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
mod msgtx;
mod varint;

pub use blockheader::{BlockHeader, MAX_BLOCK_HEADER_PAYLOAD};
pub use cursor::Cursor;
pub use error::WireError;
pub use msgtx::{
    DEFAULT_PK_SCRIPT_VERSION, MAX_PREV_OUT_INDEX, MAX_TX_IN_PER_MESSAGE, MAX_TX_IN_SEQUENCE_NUM,
    MAX_TX_OUT_PER_MESSAGE, MsgTx, NO_EXPIRY_VALUE, NULL_BLOCK_HEIGHT, NULL_BLOCK_INDEX,
    NULL_VALUE_IN, OutPoint, TX_TREE_REGULAR, TX_TREE_STAKE, TX_TREE_UNKNOWN, TX_VERSION, TxIn,
    TxOut, TxSerializeType,
};
pub use varint::{read_var_int, var_int_serialize_size, write_var_int};

/// The maximum bytes a message can be regardless of other individual limits
/// imposed by messages themselves (32 MiB), matching dcrd
/// `wire.MaxMessagePayload`.
pub const MAX_MESSAGE_PAYLOAD: u64 = 1024 * 1024 * 32;
