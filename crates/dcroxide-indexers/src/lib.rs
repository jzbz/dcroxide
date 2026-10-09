// SPDX-License-Identifier: ISC
//! Optional block chain indexes mirroring dcrd's
//! `internal/blockchain/indexers` package: the
//! shared indexer machinery (the index tips bucket with its version
//! and drop-marker keys, creation, upgrade, recovery, and the
//! incremental drop paths), the index update subscriber with
//! prerequisite/dependent relay and catch-up, the version 2
//! transaction index, the exists address index (version 3: dcrd's
//! address set in this port's layout 3, written inside the metadata
//! flush), and the legacy index drop helpers.
//!
//! The package's log lines -- the catch-up and recovery with their
//! periodic progress lines, and every drop -- go to the [`LogSink`] the
//! caller passes in, where dcrd writes them to the package logger its
//! callers bind to the `INDX` subsystem.
//!
//! dcrd delivers index notifications over a buffered channel
//! serviced by goroutines and checks sync subscribers on a periodic
//! ticker; this port delivers synchronously with identical state
//! transitions, and the daemon calls it on the block-processing
//! thread.  Moving the updates to a dedicated thread is an open,
//! unmeasured decision (the `internal/blockchain/indexers` row of
//! PARITY.md).

mod common;
mod error;
mod existsaddr;
mod existsaddrindex;
mod legacydrops;
mod log;
mod progresslog;
mod subscriber;
mod txindex;

pub use common::{ChainQueryer, Indexer, Interrupt, SyncWaiter};
pub use error::{ErrorKind, IdxError, IndexerError};
pub use existsaddr::policy::Policy as ExistsAddrPolicy;
#[doc(hidden)]
pub use existsaddr::policy::partition_of as exists_addr_partition_of;
#[doc(hidden)]
pub use existsaddr::store::{LayoutCheck, check_layout, stored_keys};
pub use existsaddrindex::{
    ADDR_KEY_SIZE, EXISTS_ADDR_INDEX_KEY, EXISTS_ADDR_INDEX_VERSION, EXISTS_ADDRESS_INDEX_NAME,
    ExistsAddrIndex, ExistsAddrQuery, ExistsAddrUnconfirmed, addr_to_key, drop_exists_addr_index,
};
pub use legacydrops::{ADDR_INDEX_KEY, CF_INDEX_PARENT_BUCKET_KEY, drop_addr_index, drop_cf_index};
pub use log::{LogLevel, LogSink};
pub use subscriber::{
    CONNECT_NTFN, DISCONNECT_NTFN, IndexNtfn, IndexNtfnType, IndexSubscriber, IndexerHandle,
    NO_PREREQS,
};
pub use txindex::{
    HASH_BY_ID_INDEX_BUCKET_NAME, ID_BY_HASH_INDEX_BUCKET_NAME, TX_INDEX_KEY, TX_INDEX_NAME,
    TxIndex, TxIndexEntry, TxIndexQuery, drop_tx_index,
};
