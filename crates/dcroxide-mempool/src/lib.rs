// SPDX-License-Identifier: ISC
//! The transaction memory pool, ported from dcrd's `internal/mempool`
//! package at release-v2.1.5: the mempool error kinds and the relay
//! policy layer (`policy.go`) — minimum relay fees, dust outputs, and
//! the transaction, output script, and input standardness checks.
//! The pool itself (`TxPool`) arrives with the following pieces.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
// The policy arithmetic mirrors Go's fixed-width semantics over sizes
// bounded by the wire message limits.
#![allow(clippy::arithmetic_side_effects)]

extern crate alloc;

mod error;
mod policy;
mod pool;

pub use error::{ErrorKind, PoolError, RuleError, RuleErrorSource, chain_rule_error};
pub use policy::{
    BASE_STANDARD_VERIFY_FLAGS, DEFAULT_MIN_RELAY_TX_FEE, MAX_STANDARD_TX_SIZE,
    calc_min_required_tx_relay_fee, check_inputs_standard, check_pk_script_standard,
    check_transaction_standard, is_dust,
};
pub use pool::{
    MEMPOOL_MAX_CONCURRENT_TSPENDS, Policy, PoolChain, Tag, TxDesc, TxPool, UNMINED_HEIGHT,
    VoteDesc,
};
