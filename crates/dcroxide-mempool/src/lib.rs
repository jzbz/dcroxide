// SPDX-License-Identifier: ISC
//! The transaction memory pool, ported from dcrd's `internal/mempool`
//! package at the parity pin, master `382ff4dd`, whose changes since the
//! previous pin `6f6cf21b` are carried: the refusal of spends of outputs
//! controlled by a misbehaving mixing peer (`3c8a1734`), vote metadata
//! kept in a tracker and pruned ten blocks past the block voted on
//! (`6444f057`, `d54099ad`), and the checks of a vote's claimed height,
//! voted block and ticket before it is accepted (`a9b79d1b`, `6816d9de`,
//! `023c42ff`).  It holds the mempool error kinds, the relay policy layer
//! (`policy.go`) — minimum relay fees, dust outputs, and the
//! transaction, output script, and input standardness checks — the
//! pool itself (`TxPool`, `mempool.go`), and its package logger (`log`).

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
pub mod log;
mod policy;
mod pool;

pub use error::{ErrorKind, PoolError, RuleError, RuleErrorSource, chain_rule_error};
pub use policy::{
    BASE_STANDARD_VERIFY_FLAGS, DEFAULT_MIN_RELAY_TX_FEE, MAX_STANDARD_TX_SIZE,
    calc_min_required_tx_relay_fee, check_inputs_standard, check_pk_script_standard,
    check_transaction_standard, is_dust,
};
pub use pool::{
    FeeEstimatorSink, MEMPOOL_MAX_CONCURRENT_TSPENDS, MixpoolProbe, Policy, PoolChain,
    TSpendReceiver, Tag, TxDesc, TxPool, UNMINED_HEIGHT, UnconfirmedAddrIndexer, VoteDesc,
    VoteReceiver,
};
