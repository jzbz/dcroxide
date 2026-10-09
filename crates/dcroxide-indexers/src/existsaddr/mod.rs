// SPDX-License-Identifier: ISC
//! Layout 3 of the exists-address index: a partitioned memtable, a
//! per-flush journal and packed two-level sorted runs, all written by a
//! flush participant inside the metadata flush ([ADR-0011]).
//!
//! dcrd stores one row per address ever seen (layout 2 here).  In redb,
//! a copy-on-write B-tree, every new address then dirties its own leaf,
//! scattered over a 66-million-row bucket.  Layout 3 keeps the same set
//! and the same answers, but writes it in large sorted batches:
//!
//! - **The memtable** ([`memtable`]) holds every key of an indexed block
//!   not yet in a run.  A connect's `on_commit` hook inserts its keys
//!   after the commit's own flush and before its tip row is published.
//! - **The journal** ([`journal`]) records, in each flush, the memtable
//!   keys not yet journaled, so a restart can rebuild the memtable.
//! - **The runs** ([`runs`]) hold each partition's keys as a delta run and
//!   a base run of 4 KiB chunks.  A flush merges the largest partitions
//!   into them, within a page budget ([`policy`]).
//! - **The meta row** ([`meta`]) ties them together.
//!
//! Every row lives under the `existsaddridx` bucket's id and is written by
//! the participant ([`store`]), never through the overlay, in the same
//! durable commit as the chain's rows and the index's tip row.
//!
//! [ADR-0011]: ../../../../docs/adr/0011-exists-address-layout-3-and-the-flush-participant.md

pub(crate) mod journal;
pub(crate) mod memtable;
pub(crate) mod meta;
pub(crate) mod policy;
pub(crate) mod runs;
pub(crate) mod store;

#[cfg(test)]
mod tests;

use dcroxide_database::{Error, ErrorKind};

pub(crate) use crate::existsaddrindex::ADDR_KEY_SIZE;

/// An address key, dcrd's `addrToKey` form: type byte plus hash160.
pub(crate) type Key = [u8; ADDR_KEY_SIZE];

/// The remedy every corruption error names: the index cannot repair
/// itself, and must not open silently empty.
pub(crate) const REMEDY: &str = "run once with --noexistsaddrindex --dropexistsaddrindex, then \
                                 restart to rebuild the index from genesis";

/// A corruption error naming the index and the remedy.
pub(crate) fn corrupt(detail: impl core::fmt::Display) -> Error {
    Error {
        kind: ErrorKind::Corruption,
        description: format!("exists address index: {detail}; {REMEDY}"),
    }
}
