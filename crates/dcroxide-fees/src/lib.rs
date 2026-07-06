// SPDX-License-Identifier: ISC
//! Smart fee estimation, ported from dcrd's `internal/fees` package
//! at release-v2.1.5: the exponentially-bucketed confirmation
//! tracking estimator behind the `estimatesmartfee` RPC, including
//! its exact floating point accounting and the database row codec.
//! The leveldb-backed persistence plumbing arrives with the daemon
//! wiring; the row serialization format is pinned here.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
// The estimator mirrors Go's float and fixed-width arithmetic over
// bucket counts bounded by the configuration limits.
#![allow(clippy::arithmetic_side_effects)]

extern crate alloc;

mod estimator;

pub use estimator::{
    DEFAULT_FEE_RATE_STEP, DEFAULT_MAX_BUCKET_FEE_MULTIPLIER, DEFAULT_MAX_CONFIRMATIONS,
    EstimateFeeError, Estimator, EstimatorConfig, TxConfirmStatBucket, deserialize_bucket,
    serialize_bucket,
};
