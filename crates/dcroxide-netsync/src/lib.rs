// SPDX-License-Identifier: ISC
//! The network chain synchronization manager from dcrd's
//! `internal/netsync` package: the decision core that tracks peers,
//! drives the initial header sync, the initial chain sync, and the
//! steady state download of announced blocks, transactions, and
//! mixing messages.
//!
//! The port follows the project's synchronous-port doctrine: the
//! manager is a plain state machine whose handler methods mirror
//! dcrd's `On*` callbacks and return the messages to queue and the
//! peers to disconnect as [`manager::Action`] values instead of
//! calling into a peer object, and the header sync stall timer is
//! surfaced as arm/stop actions plus an
//! [`manager::SyncManager::on_header_sync_stall_timeout`] entry point
//! for the daemon to invoke when its timer fires.  The chain, the
//! transaction pool, and the mixing pool sit behind the
//! [`manager::SyncChain`], [`manager::SyncTxPool`], and
//! [`manager::SyncMixPool`] traits standing in for dcrd's concrete
//! config fields.

pub mod manager;

pub use manager::{
    Action, BestSnapshot, Config, Peer, ProcessBlockFailure, SyncChain, SyncManager, SyncMixPool,
    SyncTxPool,
};
