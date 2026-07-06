// SPDX-License-Identifier: ISC
//! Container data structures mirroring dcrd's `container` packages at
//! `release-v2.1.5`: the age-partitioned bloom filter used for P2P
//! relay deduplication and the generic LRU map and set with optional
//! time-based expiration.
//!
//! dcrd guards both containers with mutexes for concurrent use; the
//! daemon phase owns concurrency in this project, so these ports are
//! single-threaded with otherwise identical semantics.

pub mod apbf;
pub mod lru;
