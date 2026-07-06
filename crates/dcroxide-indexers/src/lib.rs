// SPDX-License-Identifier: ISC
//! Optional block chain indexes mirroring dcrd's
//! `internal/blockchain/indexers` package at `release-v2.1.5`: the
//! shared indexer machinery (the index tips bucket with its version
//! and drop-marker keys, creation, upgrade, recovery, and the
//! incremental drop paths), the index update subscriber with
//! prerequisite/dependent relay and catch-up, the version 2
//! transaction index, the version 2 exists address index, and the
//! legacy index drop helpers.
//!
//! dcrd delivers index notifications over a buffered channel
//! serviced by goroutines and checks sync subscribers on a periodic
//! ticker; this port delivers synchronously with identical state
//! transitions, leaving that concurrency to the daemon phase.

mod common;
mod error;
mod existsaddrindex;
mod legacydrops;
mod subscriber;
mod txindex;

pub use common::{ChainQueryer, Indexer, Interrupt, SyncWaiter};
pub use error::{ErrorKind, IdxError, IndexerError};
pub use existsaddrindex::{
    ADDR_KEY_SIZE, EXISTS_ADDR_INDEX_KEY, EXISTS_ADDRESS_INDEX_NAME, ExistsAddrIndex, addr_to_key,
    drop_exists_addr_index,
};
pub use legacydrops::{ADDR_INDEX_KEY, CF_INDEX_PARENT_BUCKET_KEY, drop_addr_index, drop_cf_index};
pub use subscriber::{
    CONNECT_NTFN, DISCONNECT_NTFN, IndexNtfn, IndexNtfnType, IndexSubscriber, IndexerHandle,
    NO_PREREQS,
};
pub use txindex::{
    HASH_BY_ID_INDEX_BUCKET_NAME, ID_BY_HASH_INDEX_BUCKET_NAME, TX_INDEX_KEY, TX_INDEX_NAME,
    TxIndex, TxIndexEntry, drop_tx_index,
};
