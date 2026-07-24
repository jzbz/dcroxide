// SPDX-License-Identifier: ISC
//! Block and metadata storage mirroring the observable semantics of
//! dcrd's `database/v3 v3.0.3` interface and its ffldb driver: atomic
//! bucketed metadata behind transactions, plus flat-file block storage
//! with dcrd's exact record format.
//!
//! Per [ADR-0004], the metadata store is backed by `redb` (pure Rust,
//! crash-safe) rather than goleveldb, with a fresh-sync default and no
//! in-place dcrd datadir compatibility; the flat `*.fdb` block files do
//! use dcrd's byte format.  The key layout inside the metadata store is
//! ffldb's exactly (see the `transaction` module docs), so bucket and
//! cursor semantics — iteration order, nested-bucket handling, error
//! kinds, and quirks like `Delete` on an empty key silently succeeding
//! — match dcrd behavior for behavior, which is pinned by the ported
//! ffldb interface test battery.
//!
//! Deliberate divergences from ffldb, all within the interface
//! contract: no goleveldb-style treap write cache (redb transactions
//! natively provide read-your-writes and snapshot isolation), no LRU
//! block-file handle cache, cursors materialize their view at creation
//! (the interface contract already declares cursors invalidated by any
//! bucket modification other than `Cursor::delete`), and
//! `Cursor::delete` on a read-only transaction returns the
//! `ErrTxNotWritable` the contract documents, where ffldb silently
//! accepts the delete into pending state that the read-only commit
//! then discards.
//!
//! [ADR-0004]: ../../../docs/adr/0004-storage-backend.md

#![forbid(unsafe_code)]
// Bounded arithmetic on file offsets and key lengths.
#![allow(clippy::arithmetic_side_effects)]

mod blockfile;
pub mod bootstrap;
pub(crate) mod dbcache;
mod error;
mod transaction;

use std::path::PathBuf;
use std::sync::Condvar;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use blockfile::{BlockStore, deserialize_write_row, serialize_write_row};
pub use bootstrap::ImportStats;
pub use error::{Error, ErrorKind};
use transaction::{
    BLOCK_IDX_BUCKET_ID, BLOCK_IDX_BUCKET_NAME, BUCKET_INDEX_PREFIX, CUR_BUCKET_ID_KEY, KvTxSeed,
    METADATA_BUCKET_ID, WRITE_LOC_KEY,
};
pub use transaction::{BlockRegion, Bucket, Cursor, Transaction};

use crate::error::db_error;

/// The single redb table holding the entire ffldb-layout keyspace.
pub(crate) const METADATA_TABLE: redb::TableDefinition<'static, &'static [u8], &'static [u8]> =
    redb::TableDefinition::new("metadata");

/// The name of the metadata store file within the database directory.
const METADATA_FILE: &str = "metadata.redb";

/// The database driver type identifier (dcrd `DB.Type`).
pub const DB_TYPE: &str = "redb";

/// Releases the writer semaphore on drop.
struct WriterGuard<'a> {
    db: &'a DbInner,
}

impl Drop for WriterGuard<'_> {
    fn drop(&mut self) {
        let mut busy = self.db.writer_busy.lock().expect("writer flag poisoned");
        *busy = false;
        self.db.writer_cv.notify_one();
    }
}

pub(crate) struct DbInner {
    kv: redb::Database,
    pub(crate) block_store: Mutex<BlockStore>,
    closed: AtomicBool,
    /// The metadata write cache (dcrd ffldb's `dbCache`).
    pub(crate) cache: Mutex<crate::dbcache::DbCache>,
    /// Serializes writable transactions for their whole lifetime
    /// (dcrd's `writeLock`); redb no longer provides this because
    /// writes only reach it at flush time.
    pub(crate) writer_cv: Condvar,
    pub(crate) writer_busy: Mutex<bool>,
}

/// Options controlling database creation and opening.
pub struct Options {
    /// The database directory.
    pub path: PathBuf,
    /// The network the block data is for, stored in every block record
    /// (`wire::CurrencyNet` magic).
    pub network: u32,
    /// Maximum size of an individual flat block file; dcrd's 512 MiB
    /// unless overridden (small values are useful in tests to exercise
    /// file rollover).
    pub max_block_file_size: u32,
}

impl Options {
    /// Options with dcrd's defaults for the given directory and
    /// network.
    pub fn new(path: impl Into<PathBuf>, network: u32) -> Options {
        Options {
            path: path.into(),
            network,
            max_block_file_size: blockfile::DEFAULT_MAX_BLOCK_FILE_SIZE,
        }
    }
}

/// A handle to an open block/metadata database (dcrd `database.DB`).
/// Cloning shares the underlying database exactly as copies of dcrd's
/// `database.DB` interface value do: the daemon hands the same open
/// database to the chain and the indexes.
#[derive(Clone)]
pub struct Database {
    inner: Arc<DbInner>,
}

impl Database {
    /// Create a new database at the directory in the options; errors
    /// with `ErrDbExists` when one is already there (dcrd
    /// `database.Create`).
    pub fn create(opts: &Options) -> Result<Database, Error> {
        let meta_path = opts.path.join(METADATA_FILE);
        if meta_path.exists() {
            return Err(db_error(
                ErrorKind::DbExists,
                "database already exists at the provided path",
            ));
        }
        std::fs::create_dir_all(&opts.path)
            .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;

        let kv = redb::Database::create(&meta_path)
            .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;

        // Initialize the ffldb-layout bookkeeping rows: the bucket
        // index entry and fixed ID for the internal block index, the
        // bucket ID counter, and the initial block-file write cursor.
        {
            let wtx = kv
                .begin_write()
                .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
            {
                let mut table = wtx
                    .open_table(METADATA_TABLE)
                    .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
                let mut bidx_key =
                    Vec::with_capacity(BUCKET_INDEX_PREFIX.len() + 4 + BLOCK_IDX_BUCKET_NAME.len());
                bidx_key.extend_from_slice(BUCKET_INDEX_PREFIX);
                bidx_key.extend_from_slice(&METADATA_BUCKET_ID);
                bidx_key.extend_from_slice(BLOCK_IDX_BUCKET_NAME);
                let ops: [(&[u8], &[u8]); 3] = [
                    (&bidx_key, &BLOCK_IDX_BUCKET_ID),
                    (CUR_BUCKET_ID_KEY, &BLOCK_IDX_BUCKET_ID),
                    (
                        &{
                            let mut k = METADATA_BUCKET_ID.to_vec();
                            k.extend_from_slice(WRITE_LOC_KEY);
                            k
                        },
                        &serialize_write_row(0, 0),
                    ),
                ];
                for (k, v) in ops {
                    table
                        .insert(k, v)
                        .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
                }
            }
            wtx.commit()
                .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
        }

        let block_store = BlockStore::open(&opts.path, opts.network, opts.max_block_file_size)?;
        Ok(Database {
            inner: Arc::new(DbInner {
                kv,
                block_store: Mutex::new(block_store),
                closed: AtomicBool::new(false),
                cache: Mutex::new(crate::dbcache::DbCache::new()),
                writer_cv: Condvar::new(),
                writer_busy: Mutex::new(false),
            }),
        })
    }

    /// Open an existing database; errors with `ErrDbDoesNotExist` when
    /// there is none (dcrd `database.Open`).  Reconciles the metadata
    /// against the flat block files, rolling back any block file data
    /// beyond what the metadata records (an unclean shutdown between
    /// the file writes and the metadata commit), and erroring with
    /// `ErrCorruption` when the metadata claims more data than the
    /// files actually hold (dcrd `reconcileDB`).
    pub fn open(opts: &Options) -> Result<Database, Error> {
        let meta_path = opts.path.join(METADATA_FILE);
        if !meta_path.exists() {
            return Err(db_error(
                ErrorKind::DbDoesNotExist,
                "database does not exist at the provided path",
            ));
        }

        let kv = redb::Database::open(&meta_path)
            .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
        let mut block_store = BlockStore::open(&opts.path, opts.network, opts.max_block_file_size)?;

        // Fetch the stored write cursor position.
        let (stored_file, stored_offset) = {
            let rtx = kv
                .begin_read()
                .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
            let table = rtx
                .open_table(METADATA_TABLE)
                .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
            let mut key = METADATA_BUCKET_ID.to_vec();
            key.extend_from_slice(WRITE_LOC_KEY);
            let row = table
                .get(key.as_slice())
                .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?
                .ok_or_else(|| {
                    db_error(ErrorKind::Corruption, "missing block-file write cursor row")
                })?;
            deserialize_write_row(row.value())?
        };

        let scanned = (block_store.write_file_num, block_store.write_offset);
        let stored = (stored_file, stored_offset);
        if stored > scanned {
            return Err(db_error(
                ErrorKind::Corruption,
                format!(
                    "metadata claims file {stored_file}, offset {stored_offset}, but block \
                     data is only at file {}, offset {}",
                    scanned.0, scanned.1
                ),
            ));
        }
        if stored < scanned {
            // Unclean shutdown after block file writes but before the
            // metadata commit: roll the files back.
            block_store.rollback_to(stored_file, stored_offset)?;
        }

        Ok(Database {
            inner: Arc::new(DbInner {
                kv,
                block_store: Mutex::new(block_store),
                closed: AtomicBool::new(false),
                cache: Mutex::new(crate::dbcache::DbCache::new()),
                writer_cv: Condvar::new(),
                writer_busy: Mutex::new(false),
            }),
        })
    }

    /// The database driver type (dcrd `Type`).
    pub fn db_type(&self) -> &'static str {
        DB_TYPE
    }

    fn check_open(&self) -> Result<(), Error> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(db_error(ErrorKind::DbNotOpen, "database is not open"));
        }
        Ok(())
    }

    /// Start a transaction, read-only or read-write per the flag (dcrd
    /// `Begin`).  Multiple read-only transactions may run concurrently;
    /// starting a read-write transaction blocks until any current one
    /// finishes.  The transaction must be finalized with
    /// [`Transaction::commit`] or [`Transaction::rollback`].
    /// Acquire everything a new transaction needs, in the safe order:
    /// the writer semaphore (writable only, dcrd's `writeLock`), the
    /// cache overlay snapshot, and only then the redb read snapshot.
    /// A flush between the two snapshots is then seen twice (the
    /// overlay wins with identical values) instead of not at all.
    fn begin_seed(
        &self,
        writable: bool,
    ) -> Result<(KvTxSeed, std::sync::Arc<crate::dbcache::CacheMap>), Error> {
        let release = |inner: &DbInner| {
            let mut busy = inner.writer_busy.lock().expect("writer flag poisoned");
            *busy = false;
            inner.writer_cv.notify_one();
        };
        if writable {
            let mut busy = self.inner.writer_busy.lock().expect("writer flag poisoned");
            while *busy {
                busy = self
                    .inner
                    .writer_cv
                    .wait(busy)
                    .expect("writer flag poisoned");
            }
            *busy = true;
            drop(busy);
            // The database may have closed while this writer waited
            // (dcrd re-checks `closed` after taking its write lock).
            if self.inner.closed.load(Ordering::SeqCst) {
                release(&self.inner);
                return Err(db_error(ErrorKind::DbNotOpen, "database is not open"));
            }
        }
        let cache_snap =
            std::sync::Arc::clone(&self.inner.cache.lock().expect("cache lock poisoned").cached);
        let kv = match self.inner.kv.begin_read() {
            Ok(t) => t,
            Err(e) => {
                if writable {
                    release(&self.inner);
                }
                return Err(db_error(ErrorKind::DriverSpecific, e.to_string()));
            }
        };
        let seed = if writable {
            KvTxSeed::Write(kv)
        } else {
            KvTxSeed::Read(kv)
        };
        Ok((seed, cache_snap))
    }

    /// Hold the writer semaphore for the guard's lifetime, waiting out
    /// any committing transaction (dcrd holds its close/write locks in
    /// `Flush` and `Close`).
    fn exclusive_writer(&self) -> WriterGuard<'_> {
        let mut busy = self.inner.writer_busy.lock().expect("writer flag poisoned");
        while *busy {
            busy = self
                .inner
                .writer_cv
                .wait(busy)
                .expect("writer flag poisoned");
        }
        *busy = true;
        WriterGuard { db: &self.inner }
    }

    /// Start a transaction (dcrd `Begin`): multiple read-only
    /// transactions may run concurrently; writable transactions
    /// serialize on the writer semaphore.
    pub fn begin(&self, writable: bool) -> Result<Transaction, Error> {
        self.check_open()?;
        let (seed, cache_snap) = self.begin_seed(writable)?;
        Ok(Transaction::new(
            Arc::clone(&self.inner),
            seed,
            cache_snap,
            false,
        ))
    }

    fn begin_managed(&self, writable: bool) -> Result<Transaction, Error> {
        self.check_open()?;
        let (seed, cache_snap) = self.begin_seed(writable)?;
        Ok(Transaction::new(
            Arc::clone(&self.inner),
            seed,
            cache_snap,
            true,
        ))
    }

    /// Invoke the function in a managed read-only transaction (dcrd
    /// `View`); calling commit or rollback on the passed transaction
    /// panics.
    pub fn view(&self, fn_: impl FnOnce(&Transaction) -> Result<(), Error>) -> Result<(), Error> {
        let tx = self.begin_managed(false)?;
        let result = fn_(&tx);
        tx.rollback_internal()?;
        result
    }

    /// Invoke the function in a managed read-write transaction (dcrd
    /// `Update`): committed when it returns `Ok`, rolled back on `Err`;
    /// calling commit or rollback on the passed transaction panics.
    pub fn update(&self, fn_: impl FnOnce(&Transaction) -> Result<(), Error>) -> Result<(), Error> {
        let tx = self.begin_managed(true)?;
        match fn_(&tx) {
            Ok(()) => tx.commit_internal(),
            Err(e) => {
                tx.rollback_internal()?;
                Err(e)
            }
        }
    }

    /// Cleanly shut down the database (dcrd `Close`); later operations
    /// error with `ErrDbNotOpen`.
    pub fn close(&self) -> Result<(), Error> {
        if self.inner.closed.swap(true, Ordering::SeqCst) {
            return Err(db_error(ErrorKind::DbNotOpen, "database is not open"));
        }
        // Flush the metadata write cache so a clean shutdown persists
        // everything (dcrd `Close` flushes the cache), waiting out any
        // committing transaction first (dcrd's close/write locks).
        let _writer = self.exclusive_writer();
        self.inner
            .cache
            .lock()
            .expect("cache lock poisoned")
            .flush(&self.inner.kv, &self.inner.block_store)?;
        Ok(())
    }

    /// Write all outstanding cached entries to disk (dcrd `Flush`):
    /// sync the flat block files, then durably commit the metadata
    /// write cache.
    pub fn flush(&self) -> Result<(), Error> {
        self.check_open()?;
        let _writer = self.exclusive_writer();
        self.inner
            .cache
            .lock()
            .expect("cache lock poisoned")
            .flush(&self.inner.kv, &self.inner.block_store)?;
        Ok(())
    }
}
