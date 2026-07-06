// SPDX-License-Identifier: ISC
//! Block template mining support, ported from dcrd's
//! `internal/mining` package at release-v2.1.5: the transaction
//! descriptor types, the dependency graph and mining view with
//! ancestor statistics tracking, the transaction priority queue with
//! Go's exact heap semantics, and the priority calculation.  The
//! block template generation (`NewBlockTemplate`) and the background
//! template generator arrive with the following pieces.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
// The bookkeeping arithmetic mirrors Go's fixed-width semantics over
// counts bounded by the tracking limits.
#![allow(clippy::arithmetic_side_effects)]

extern crate alloc;

mod graph;
mod policy;
mod pq;
mod types;
mod view;

pub use graph::{ForEachRedeemer, TxDescFind};
pub use policy::{calc_input_value_age, calc_priority};
pub use pq::{
    StakePriority, TxPrioItem, TxPriorityQueue, compare_stake_priority, tx_pq_by_stake_and_fee,
    tx_stake_priority,
};
pub use types::{TxAncestorStats, TxDesc, UNMINED_HEIGHT, VoteDesc};
pub use view::{ANCESTOR_TRACKING_LIMIT, TxMiningView};
