// SPDX-License-Identifier: ISC
//! Decred chain-engine components ported from dcrd's
//! `internal/blockchain` at master `452c1a6c` (the dcrd 2.2 campaign
//! parity target).  This crate currently
//! contains the UTXO serialization layer — variable-length quantities,
//! the domain-specific script and amount compression, UTXO entries and
//! their storage format, outpoint keys, and the UTXO set state — and
//! grows into the full chain engine in the blockchain phase.
//!
//! dcrd keeps these in an internal package the test oracle cannot
//! import, so parity is pinned by dcrd's own table-driven test vectors
//! extracted mechanically from the Go test sources, plus round-trip
//! property tests.

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
// The consensus serialization formats ported here rely on Go's
// fixed-width integer semantics over bounded inputs.
#![allow(clippy::arithmetic_side_effects)]

extern crate alloc;

pub mod agendas;
pub mod blockindex;
pub mod chaindb;
pub mod chainio;
pub mod chainview_nodes;
mod checkedmath;
pub mod compress;
pub mod difficulty;
mod error;
pub mod notifications;
pub mod process;
mod ruleerror;
pub mod sequencelock;
pub mod stakever;
pub mod thresholdstate;
pub mod treasurydb;
mod utxoentry;
mod utxoio;
pub mod utxoview;
pub mod validate;

pub use compress::CURRENT_COMPRESSION_VERSION;
pub use error::Error;
pub use ruleerror::{RuleError, RuleErrorKind, render_multi_error};
pub use utxoentry::{
    UTXO_STATE_FRESH, UTXO_STATE_MODIFIED, UTXO_STATE_SPENT, UtxoEntry, encode_utxo_flags,
    is_ticket_submission_output,
};
pub use utxoio::{
    UTXO_PREFIX_DB_INFO, UTXO_PREFIX_UTXO_SET, UTXO_PREFIX_UTXO_STATE, UtxoSetState,
    decode_outpoint_key, deserialize_utxo_entry, deserialize_utxo_set_state, outpoint_key,
    read_deserialize_size_of_minimal_outputs, serialize_utxo_entry, serialize_utxo_set_state,
};
