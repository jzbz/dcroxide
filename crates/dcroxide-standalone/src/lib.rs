// SPDX-License-Identifier: ISC
//! Standalone Decred consensus functions, ported from dcrd's
//! `blockchain/standalone/v2` package at the parity pin, master
//! `b9634e01` (the package's one change since the 2.2 campaign target
//! `452c1a6c`, `ae4c5818`, is not observable through the port's
//! subsidy cache; see PARITY.md): merkle root calculations (regular, stake,
//! and DCP0005 combined), merkle tree
//! inclusion proofs, proof-of-work checks and compact-bits conversions,
//! the DCP0011 ASERT difficulty algorithm, the full subsidy schedule
//! across all three split regimes (60/30/10, DCP0010 10/80/10, and
//! DCP0012 1/89/10), treasury spend voting window math, and context-free
//! transaction identification and sanity checks.
//!
//! Like dcrd, the proof-of-work functions operate on arbitrary-precision
//! signed integers because the compact representation can encode
//! negative values and values well beyond 256 bits; this port uses
//! `num-bigint` for those semantics.
//!
//! dcrd's legacy EMA difficulty retarget lives in `internal/blockchain`,
//! not in this package; its port is `calc_next_blake256_diff` in the
//! `dcroxide-blockchain` crate.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
// This crate holds no hashed containers: every map and set in it is
// ordered.  That is a property worth keeping rather than rediscovering
// -- iteration order over a consensus structure must not depend on a
// per-process hash seed.  Denied here rather than workspace-wide
// because the P2P, RPC and mixing crates legitimately hash (see
// ADR-0008); note the lint fires only on `for` loops.
#![deny(clippy::iter_over_hash_type)]

extern crate alloc;

mod error;
mod inclusionproof;
mod merkle;
mod pow;
mod subsidy;
mod treasury;
mod tx;

pub use error::{ErrorKind, RuleError};
pub use inclusionproof::{generate_inclusion_proof, verify_inclusion_proof};
pub use merkle::{
    calc_combined_tx_tree_merkle_root, calc_merkle_root, calc_merkle_root_in_place,
    calc_tx_tree_merkle_root,
};
pub use pow::{
    big_to_compact, big_to_string, calc_asert_diff, calc_work, check_proof_of_work,
    check_proof_of_work_hash, check_proof_of_work_range, compact_to_big, hash_to_big,
};
pub use subsidy::{SubsidyCache, SubsidyParams, SubsidySplitVariant};
pub use treasury::{
    calc_tspend_expiry, calc_tspend_window, inside_tspend_window, is_treasury_vote_interval,
};
pub use tx::{check_transaction_sanity, is_coin_base_tx, is_treasury_base};

// Re-export the big integer types used by the proof-of-work API so
// consumers do not need a direct num-bigint dependency.
pub use num_bigint::{BigInt, Sign};
