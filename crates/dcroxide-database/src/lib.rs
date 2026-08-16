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

use std::path::{Path, PathBuf};
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

// redb 4 moved `begin_read` onto a trait; importing it keeps the call
// sites unchanged. See the ADR-0004 upgrade note for why we are on 4.x.
use redb::ReadableDatabase as _;

/// The single redb table holding the entire ffldb-layout keyspace.
pub(crate) const METADATA_TABLE: redb::TableDefinition<'static, &'static [u8], &'static [u8]> =
    redb::TableDefinition::new("metadata");

/// The name of the metadata store file within the database directory.
const METADATA_FILE: &str = "metadata.redb";

/// The database driver type identifier (dcrd `DB.Type`).
pub const DB_TYPE: &str = "redb";

/// Create `path` and any missing parents, reachable only by the user
/// running the node.
///
/// dcrd creates every database directory owner-only:
/// `os.MkdirAll(dbPath, 0700)` in `database/ffldb/db.go` 2088,
/// `os.MkdirAll(cfg.DataDir, 0700)` in `blockdb.go` 131 and
/// `cmd/addblock/addblock.go` 48, and `os.MkdirAll(dataDir, 0700)` in
/// `internal/blockchain/utxobackend.go` 357.  `std::fs::create_dir_all`
/// takes no mode, so it would create `0777` masked by the umask —
/// `0755` under the common `022`, which lets any local user walk and
/// list a `--datadir` placed on a shared path.  The block and UTXO data
/// are public, so this is traversal parity with dcrd rather than
/// secrecy: nothing here is a credential.
///
/// Directories that already exist keep their current mode, exactly as
/// `MkdirAll` does, so an operator who deliberately widened the data
/// directory is not overridden and a read-only parent is not disturbed.
/// This crate cannot depend on `dcroxide-node`, so this duplicates the
/// daemon's `secretfile::create_dir_all_owner_only`.
#[cfg(unix)]
pub fn create_dir_all_owner_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(path)
}

/// Create `path` and any missing parents.  Off Unix there is no mode to
/// apply, so this is plain `create_dir_all`.
#[cfg(not(unix))]
pub fn create_dir_all_owner_only(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)
}

/// Begin a write transaction with durability set **explicitly**.
///
/// This is the only place in the crate that may call
/// `redb::Database::begin_write`, and `durability_policy.rs` fails the
/// build's test suite if that stops being true.
///
/// **Why not just rely on the engine's default.** redb happens to default
/// to `Durability::Immediate`, so today this call changes nothing. That is
/// the point: durability is a property this node must *assert*, not one it
/// inherits and hopes stays put. The engine dcroxide measured as a
/// replacement (fjall) defaults the other way — its `Database::batch()`
/// hands back `PersistMode::Buffer`, whose `commit()` returns `Ok` having
/// fsynced nothing — so a port that had been relying on an inherited
/// default would have become silently non-durable on the day it switched,
/// with no diff to point at. ADR-0009 records that as one of the
/// conditions on any engine change; this is the seam that satisfies it.
///
/// A commit reaching disk is what the chain's paired write depends on:
/// `Chain::flush` puts block index rows, UTXO entries and both state
/// markers in one transaction so a crash cannot leave them disagreeing,
/// and that guarantee is worth nothing if the commit was never durable.
fn begin_durable_write(kv: &redb::Database) -> Result<redb::WriteTransaction, Error> {
    let mut tx = kv
        .begin_write()
        .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
    tx.set_durability(redb::Durability::Immediate)
        .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
    Ok(tx)
}

/// Releases the writer semaphore on drop.
struct WriterGuard<'a> {
    db: &'a DbInner,
}

impl DbInner {
    /// Latch the store fatal and return the error that caused it.
    ///
    /// Every path that hands a durable commit to the engine routes its
    /// failure through here, so no call site can forget to latch.
    ///
    /// **Why a latch and not a retry.** A failed flush leaves the write
    /// cache holding its dirty set, so the next flush would retry it and
    /// could return `Ok`. That is the sequence one class of storage bug
    /// needs in order to lose data silently: the engine reports a commit
    /// as durable when the write that preceded it left the log in a state
    /// recovery will truncate, and the node believes state it will not
    /// have after a restart. dcroxide's chain writes block index rows,
    /// UTXO entries and both state markers in one transaction precisely
    /// so a crash cannot leave them disagreeing
    /// (`process.rs`, `Chain::flush`); a commit that reports success and
    /// then evaporates defeats that.
    ///
    /// The trade is availability for integrity: a transient `ENOSPC` that
    /// today would be retried now stops the handle until the process
    /// restarts. That is the right way round for a consensus daemon,
    /// which already runs under a supervisor because release builds abort
    /// on panic (see `docs/operating.md`).
    pub(crate) fn mark_fatal(&self, e: Error) -> Error {
        self.fatal.store(true, Ordering::SeqCst);
        e
    }
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
    /// Set when a durable write has failed. Every later write on this
    /// handle is then refused. See [`DbInner::mark_fatal`].
    fatal: AtomicBool,
    /// The metadata write cache (dcrd ffldb's `dbCache`).
    pub(crate) cache: Mutex<crate::dbcache::DbCache>,
    /// Serializes writable transactions for their whole lifetime
    /// (dcrd's `writeLock`); redb no longer provides this because
    /// writes only reach it at flush time.
    pub(crate) writer_cv: Condvar,
    pub(crate) writer_busy: Mutex<bool>,
}

/// What one metadata flush did, handed to an [`Options::flush_observer`].
///
/// The point of collecting these is that the *shape* of the free-page curve
/// over a run distinguishes mechanisms a single end-state measurement
/// cannot tell apart: a monotone stair rising by roughly one flush's freed
/// set is redb's one-generation reclaim lag, a single ratchet that never
/// recovers is a high-water mark no layer above the engine can reclaim,
/// growth that tracks reader overlap is a transaction held across a flush,
/// and growth that tracks row size points at the buddy allocator's
/// power-of-two rounding.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FlushObservation {
    /// Flush count since the database was opened, starting at 1.
    pub sequence: u64,
    /// Entries written or removed by this flush.
    pub dirty_entries: usize,
    /// Bytes the overlay was holding when the flush began.
    pub dirty_bytes: u64,
    /// Wall time for the whole flush, including the redb commit **and**
    /// any stats walk this flush was sampled with.
    ///
    /// Subtract [`Self::stats_elapsed`] to get the cost of the flush
    /// itself. The distinction is not cosmetic: the walk is proportional
    /// to the tree, so on a chain-sized store it is minutes and would
    /// otherwise be indistinguishable from the commit cost being measured.
    pub elapsed: std::time::Duration,
    /// Of `elapsed`, the part spent walking the tree for
    /// [`Self::stats`]. Zero on unsampled flushes.
    pub stats_elapsed: std::time::Duration,
    /// Footprint after this flush's writes and before its commit, present
    /// only on sampled flushes.
    ///
    /// Sampled rather than always taken because redb's `stats()` walks
    /// every branch and leaf page, which is seconds on a chain-sized
    /// tree — collecting it per flush would dominate the very timings the
    /// observer exists to measure.
    pub stats: Option<RawStats>,
}

/// A callback invoked after each metadata flush.
///
/// Called on the flushing thread with the cache lock held, so it must not
/// block or re-enter the database; append to a buffer and analyse later.
pub type FlushObserver = Arc<dyn Fn(&FlushObservation) + Send + Sync>;

/// A callback invoked once per key/value the engine is handed, in the
/// order it is handed them, with `None` for a delete.
///
/// Called inside the flush transaction with the cache lock held, so it
/// must not block or re-enter the database. It exists to capture the
/// engine-level write sequence for ADR-0009's candidate engine benchmark:
/// the order the storage engine actually sees is neither block order nor
/// the sorted contents of the finished store, and picking either would
/// decide that benchmark by itself.
pub type WriteLogSink = Arc<dyn Fn(&[u8], Option<&[u8]>) + Send + Sync>;

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
    /// Bytes redb may use to cache database pages.
    ///
    /// This has no dcrd counterpart — goleveldb's block cache is sized
    /// by ffldb's own write cache, whereas redb caches pages of the
    /// single metadata file. It is a ceiling filled on demand, not an
    /// allocation: the LRU stripes start empty
    /// (redb-4.1.0 `cached_file.rs:247-249`) and a miss that would carry
    /// the total past the limit evicts a page's worth before returning
    /// (`:467-488`), so a small database never pays for a large setting
    /// and the resident cost is bounded by the file size.
    ///
    /// redb 4.1.0 keeps one cache figure and partitions it dynamically
    /// (`db.rs:1161-1164`, `cached_file.rs:203-214`): the write buffer
    /// never exceeds 50% of it, flushing the excess straight to disk
    /// (`:557-583`), and the read cache may grow to 100% when no write
    /// is in flight. Once a commit's dirty set exceeds the write buffer,
    /// redb writes the spilled pages, re-reads them to finalize
    /// checksums, then writes the buffer again — measured against the
    /// mainnet metadata store on redb 2.6.3, whose `set_cache_size` cut
    /// the figure 90/10 into read cache and write buffer with no
    /// separate setter (redb-2.6.3 `db.rs:1186-1187`): at its 1 GiB
    /// default, 62,323 dirty pages cost 124,430 pwrites and 98,221
    /// preads, against 62,323 and 4 with the buffer large enough to hold
    /// them. The mechanism survives the upgrade; the counts were taken
    /// at a write buffer five times smaller than 4.1.0 permits.
    pub db_cache_bytes: usize,
    /// Called after every metadata flush, when set.
    ///
    /// `None` by default, which is exactly the behaviour the daemon had
    /// before this existed: no observation, no cost, no branch beyond a
    /// null check. This is measurement scaffolding for the storage work
    /// tracked in ADR-0004, not a production feature.
    pub flush_observer: Option<FlushObserver>,
    /// Take a full [`RawStats`] on every Nth flush; 0 disables sampling.
    ///
    /// See [`FlushObservation::stats`] for why this is sampled at all.
    pub flush_stats_every: u64,
    /// Called once per key/value handed to the engine, when set.
    ///
    /// `None` by default, and the same "no observation, no cost" contract
    /// as [`Self::flush_observer`]. See [`WriteLogSink`].
    pub write_log: Option<WriteLogSink>,
    /// Bytes the metadata overlay may hold before a commit flushes it.
    ///
    /// Was hardcoded until the ADR-0004 measurement work needed it: with a
    /// fixed 100 MiB ceiling, a probe small enough to run in minutes never
    /// reaches a flush, so the thing being measured never happens. It is
    /// also half of that ADR's "decouple flush cadence from block
    /// connection" lever, which could not be evaluated without a way to
    /// set it.
    pub cache_max_size: u64,
    /// Seconds after which a commit flushes the overlay regardless of size.
    pub cache_flush_interval_secs: u64,
    /// Storage to hand redb instead of letting it open `metadata.redb`
    /// itself.  `None` — the default and the only value the daemon uses
    /// — opens the file directly, exactly as before.
    ///
    /// Exists so a test can model **power loss**, which the crash suite
    /// otherwise cannot reach. Its other primitive is an in-process
    /// `drop`, and killing the process outright would be no better: both
    /// leave the page cache intact, so every byte written but never
    /// `fsync`ed is still readable after the reopen and a store that
    /// skipped its durability step passes anyway. Only storage that
    /// *discards what was never synced* distinguishes them — which is
    /// precisely the property any deferred-fsync work would put at risk,
    /// and the reason this hook exists before that work rather than
    /// after it.
    pub backend: Option<SharedBackend>,
}

/// Storage shared between the caller and redb, so a test can keep a
/// handle on the backend it installed (to fail it, or to drop its
/// unsynced writes) while redb owns its own.
pub type SharedBackend = Arc<dyn redb::StorageBackend>;

/// Adapts a [`SharedBackend`] to the by-value `impl StorageBackend` that
/// `redb::Builder::create_with_backend` takes.  Every method on the
/// trait takes `&self`, so sharing costs one pointer hop and no
/// synchronisation of its own.
#[derive(Debug)]
struct SharedBackendHandle(SharedBackend);

impl redb::StorageBackend for SharedBackendHandle {
    fn len(&self) -> Result<u64, std::io::Error> {
        self.0.len()
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), std::io::Error> {
        self.0.read(offset, out)
    }

    fn set_len(&self, len: u64) -> Result<(), std::io::Error> {
        self.0.set_len(len)
    }

    fn sync_data(&self) -> Result<(), std::io::Error> {
        self.0.sync_data()
    }

    fn write(&self, offset: u64, data: &[u8]) -> Result<(), std::io::Error> {
        self.0.write(offset, data)
    }
}

/// redb's own default cache size, which is what the port used before
/// this became configurable.
///
/// Kept as the default so raising it is an operator's decision rather
/// than a silent change in resident memory — and the decision is to
/// leave it where it is. Over full mainnet replays an 8192 MiB cache
/// measured 50% slower (5125-6294 s against a 3866-3888 s baseline,
/// disjoint), while 256 and 512 MiB both overlap the baseline, so this
/// value is correctly sized in both directions (the 2026-08-10 and
/// 2026-08-11 sweeps in `docs/bench-ledger.md`).
///
/// The table below is the superseded microbenchmark those replays
/// reversed: 2,000,000 scattered writes against the mainnet metadata
/// store (14.48 GiB).
///
/// | cache | 250k per commit | 2M per commit |
/// |---|---|---|
/// | 1 GiB | 78.6 s | 43.0 s |
/// | 4 GiB | 51.4 s | 19.6 s |
/// | 8 GiB | 48.7 s | 16.1 s |
///
/// Its multiplicative reading — 1.8x from batching alone, 2.7x from
/// cache alone, 4.9x together — is withdrawn. Only the flush-cadence
/// half survived the full chain, at 11-12%, and that half is reachable
/// through dcrd's own `--utxocachemaxsize`.
pub const DEFAULT_DB_CACHE_BYTES: usize = 1024 * 1024 * 1024;

impl Options {
    /// Options with dcrd's defaults for the given directory and
    /// network.
    pub fn new(path: impl Into<PathBuf>, network: u32) -> Options {
        Options {
            path: path.into(),
            network,
            max_block_file_size: blockfile::DEFAULT_MAX_BLOCK_FILE_SIZE,
            db_cache_bytes: DEFAULT_DB_CACHE_BYTES,
            flush_observer: None,
            flush_stats_every: 0,
            write_log: None,
            cache_max_size: crate::dbcache::DEFAULT_CACHE_SIZE,
            cache_flush_interval_secs: crate::dbcache::DEFAULT_FLUSH_SECS,
            backend: None,
        }
    }
}

/// Open the metadata store, through `opts.backend` when one is
/// installed and directly otherwise.
///
/// `create_with_backend` is redb's only backend entry point and carries
/// its create-or-open semantics, so both call sites route through here
/// rather than one of them quietly ignoring the hook.
fn open_metadata(opts: &Options, meta_path: &Path) -> Result<redb::Database, redb::DatabaseError> {
    match &opts.backend {
        Some(shared) => {
            redb_builder(opts).create_with_backend(SharedBackendHandle(Arc::clone(shared)))
        }
        None => redb_builder(opts).create(meta_path),
    }
}

/// The redb builder both open paths use, so the cache setting cannot be
/// applied on one and forgotten on the other.
fn redb_builder(opts: &Options) -> redb::Builder {
    let mut builder = redb::Builder::new();
    builder.set_cache_size(opts.db_cache_bytes);
    builder
}

/// A handle to an open block/metadata database (dcrd `database.DB`).
/// Cloning shares the underlying database exactly as copies of dcrd's
/// `database.DB` interface value do: the daemon hands the same open
/// database to the chain and the indexes.
#[derive(Clone)]
pub struct Database {
    inner: Arc<DbInner>,
}

/// One bucket's payload and row-size distribution, from
/// [`Database::bucket_stats`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketStats {
    /// The four-byte bucket id that prefixes every key in it.
    pub id: [u8; 4],
    /// The bucket's name, or a rendering of its id when the index row
    /// naming it was not found.
    pub name: String,
    /// Rows in the bucket.
    pub rows: u64,
    /// Key plus value bytes actually stored.
    pub payload_bytes: u64,
    /// The largest single row, key plus value.
    pub largest_row_bytes: u64,
    /// Row sizes bucketed by `floor(log2(bytes))`, so index `i` counts
    /// rows of `2^i .. 2^(i+1)` bytes.
    ///
    /// A mean is not enough to reason about packing, and assuming it was
    /// cost this project a retraction: `spendjournalv3` has a mean row of
    /// 2402 bytes but a *median* of 1248, a p99 of 13748 and a largest row
    /// of 66699. The mean is set by a long tail and describes almost no
    /// actual row, which made a bucket that mostly packs several rows per
    /// leaf look like one that packs none.
    pub size_log2: [u64; 40],
}

impl BucketStats {
    /// Mean stored bytes per row.
    pub fn mean_row_bytes(&self) -> f64 {
        if self.rows == 0 {
            return 0.0;
        }
        self.payload_bytes as f64 / self.rows as f64
    }

    /// The row size at percentile `p` (0.0 to 1.0), as the lower bound of
    /// the `log2` band it falls in.
    ///
    /// Approximate by construction — a band spans a factor of two — but a
    /// measured approximation, which is the distinction that matters here.
    /// This replaced a `rows_per_page` / `predicted_slack_bytes` model that
    /// divided the page size by the *mean* row. That model put
    /// `spendjournalv3` at one row per page and 1.74 GiB of recoverable
    /// slack; the bucket measures 1.55 rows per leaf node and 1.536 GiB of
    /// slack, none of which any re-keying reaches (2026-08-12 addendum to
    /// ADR-0004). It was close enough to look confirmed and wrong about the
    /// mechanism, which is the worst combination a model can have.
    pub fn size_percentile(&self, p: f64) -> u64 {
        let target = (self.rows as f64 * p.clamp(0.0, 1.0)) as u64;
        let mut seen = 0u64;
        for (i, &count) in self.size_log2.iter().enumerate() {
            seen = seen.saturating_add(count);
            if seen >= target && count > 0 {
                return 1u64 << i;
            }
        }
        self.largest_row_bytes
    }
}

/// The metadata store's footprint, split into the parts that behave
/// differently (see [`Database::raw_stats`]).
///
/// The split exists because redb's headline figure cannot be read as a
/// packing ratio. `DatabaseStats::fragmented_bytes` sums the trees'
/// intra-page slack **and** `count_free_pages() * page_size`
/// (redb-2.6.3 `transactions.rs:2298-2301`), so it conflates space wasted
/// *inside* live pages with space the allocator holds and has not returned.
/// Those have different causes and different remedies: slack is a packing
/// property of the B-tree, while free pages are an allocator property that
/// no amount of repacking touches. Only [`Self::table_fragmented_bytes`] is
/// slack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawStats {
    /// redb's page size, the unit every page count below is in.
    pub page_size: u64,
    /// Pages the allocator holds, live or free.
    pub allocated_pages: u64,
    /// Traversal depth to the deepest pair.
    pub tree_height: u32,
    /// Database-wide: intra-page slack across all trees **plus** free
    /// pages. Not a packing figure; see the type docs.
    pub database_fragmented_bytes: u64,
    /// Leaf pages of the metadata table.
    pub leaf_pages: u64,
    /// Branch pages of the metadata table.
    pub branch_pages: u64,
    /// Key and value bytes actually stored in the metadata table.
    pub stored_leaf_bytes: u64,
    /// redb's per-pair overhead and branch-page bytes for the table.
    pub metadata_bytes: u64,
    /// Intra-page slack for the metadata table alone — the real packing
    /// figure.
    pub table_fragmented_bytes: u64,
}

impl RawStats {
    /// Bytes in pages the allocator holds but the tree does not use.
    ///
    /// Derived by subtracting the metadata table's intra-page slack from
    /// the database-wide fragmented figure. The remainder is free pages
    /// plus the slack of redb's own system and freed trees, which are
    /// small next to a chain-sized table; treat it as free pages with that
    /// caveat rather than as an exact count, which redb does not expose.
    pub fn free_page_bytes(&self) -> u64 {
        self.database_fragmented_bytes
            .saturating_sub(self.table_fragmented_bytes)
    }

    /// Bytes the metadata table's live pages occupy: payload, redb's
    /// per-pair and branch overhead, and the slack between them.
    ///
    /// Deliberately *not* `(leaf_pages + branch_pages) * page_size`, which
    /// on the mainnet store reports 8.46 GiB where the tree really occupies
    /// 9.79 — a 1.42 GiB shortfall. The reason is that `leaf_pages` counts
    /// leaf *nodes*, one per node, while a node's allocation is rounded to
    /// a power-of-two run of pages (`required_order = ceil_log2`), so a
    /// single row too large to share a leaf can occupy 2, 4 or 32 pages and
    /// still be counted once. (An earlier version of this comment blamed
    /// "overflow pages"; redb 2.6.3 has no such mechanism, and the real one
    /// is the allocator rounding — which is also where 14% of this store's
    /// slack comes from.) Summing the three measured components is the
    /// honest figure.
    pub fn live_tree_bytes(&self) -> u64 {
        self.stored_leaf_bytes
            .saturating_add(self.metadata_bytes)
            .saturating_add(self.table_fragmented_bytes)
    }

    /// Fraction of the live tree holding payload or overhead rather than
    /// slack, in `0.0..=1.0`.
    ///
    /// This is the packing figure. redb's own `fragmented_bytes` cannot be
    /// used for it — see the type docs.
    pub fn fill_ratio(&self) -> f64 {
        let live = self.live_tree_bytes();
        if live == 0 {
            return 0.0;
        }
        let used = self.stored_leaf_bytes.saturating_add(self.metadata_bytes);
        used as f64 / live as f64
    }

    /// Bytes this decomposition accounts for: live pages plus free ones.
    ///
    /// Should land within a couple of megabytes of the `metadata.redb`
    /// file size — redb's header and region metadata are the remainder.
    /// A larger gap means the decomposition has stopped describing the
    /// file and the figures below it should not be trusted.
    pub fn accounted_bytes(&self) -> u64 {
        self.allocated_bytes()
            .saturating_add(self.free_page_bytes())
    }

    /// Total bytes the allocator holds.
    pub fn allocated_bytes(&self) -> u64 {
        self.allocated_pages.saturating_mul(self.page_size)
    }

    /// Render as one JSON object, so a run is a diffable ledger row.
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\"page_size\":{},\"allocated_pages\":{},\"allocated_bytes\":{},",
                "\"tree_height\":{},\"leaf_pages\":{},\"branch_pages\":{},",
                "\"stored_leaf_bytes\":{},\"metadata_bytes\":{},",
                "\"table_fragmented_bytes\":{},\"database_fragmented_bytes\":{},",
                "\"free_page_bytes\":{},\"live_tree_bytes\":{},\"accounted_bytes\":{},",
                "\"fill_ratio\":{:.6}}}"
            ),
            self.page_size,
            self.allocated_pages,
            self.allocated_bytes(),
            self.tree_height,
            self.leaf_pages,
            self.branch_pages,
            self.stored_leaf_bytes,
            self.metadata_bytes,
            self.table_fragmented_bytes,
            self.database_fragmented_bytes,
            self.free_page_bytes(),
            self.live_tree_bytes(),
            self.accounted_bytes(),
            self.fill_ratio(),
        )
    }
}

/// Classify a redb open failure.
///
/// redb takes an exclusive `flock` on the metadata file and reports
/// `DatabaseAlreadyOpen` when another process already holds it, which is
/// what stops two daemons from sharing one data directory.  That has to
/// surface as [`ErrorKind::DbAlreadyOpen`] — dcrd's `ErrDbAlreadyOpen` —
/// rather than a generic driver error, both because the operator needs an
/// actionable message and because the lock is acquired before the flat
/// block files are touched, making this the check that protects them.
fn open_error(e: redb::DatabaseError) -> Error {
    match e {
        redb::DatabaseError::DatabaseAlreadyOpen => db_error(
            ErrorKind::DbAlreadyOpen,
            "the database is already open by another process -- only one \
             instance may use a data directory at a time",
        ),
        // A data directory written by a dcroxide built against redb 2.x.
        // redb 4 reads only file format 3 and reports this rather than
        // guessing, which is the behaviour that makes the upgrade safe:
        // an old directory is refused, not misread. There is no in-place
        // migration and ADR-0004's fresh-sync stance means there does not
        // need to be, but the operator has to be told which of the two
        // things happened, because "delete the data directory and re-sync"
        // and "your disk is damaged" call for very different reactions.
        redb::DatabaseError::UpgradeRequired(version) => db_error(
            ErrorKind::Invalid,
            format!(
                "the metadata store is redb file format {version}, which this build \
                 cannot read -- it was written by a dcroxide built against redb 2.x. \
                 There is no in-place upgrade: remove the data directory and sync \
                 again (see docs/operating.md). The chain is not damaged."
            ),
        ),
        other => db_error(ErrorKind::DriverSpecific, other.to_string()),
    }
}

#[cfg(test)]
impl Database {
    /// How many layers the metadata overlay currently holds.
    ///
    /// The layer count is an implementation detail everywhere except in
    /// the overlay's own tests, which have to prove they are exercising a
    /// real stack rather than the collapsed single-layer case.
    pub(crate) fn overlay_layer_count(&self) -> usize {
        self.inner
            .cache
            .lock()
            .expect("cache lock poisoned")
            .cached
            .layer_count()
    }
}

impl Database {
    /// Create a new database at the directory in the options; errors
    /// with `ErrDbExists` when one is already there (dcrd
    /// `database.Create`).
    pub fn create(opts: &Options) -> Result<Database, Error> {
        let meta_path = opts.path.join(METADATA_FILE);
        // The guard protects against clobbering a store that lives at
        // this path. A caller-supplied backend IS the store, so the path
        // says nothing about whether one exists and the check would only
        // reject storage the caller already opened. The daemon never
        // sets a backend, so its behaviour is unchanged.
        if opts.backend.is_none() && meta_path.exists() {
            return Err(db_error(
                ErrorKind::DbExists,
                "database already exists at the provided path",
            ));
        }
        // dcrd's ffldb only creates the tree when the database does not
        // exist (the guard above), and creates it 0700.
        create_dir_all_owner_only(&opts.path)
            .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;

        let kv = open_metadata(opts, &meta_path).map_err(open_error)?;

        // Initialize the ffldb-layout bookkeeping rows: the bucket
        // index entry and fixed ID for the internal block index, the
        // bucket ID counter, and the initial block-file write cursor.
        {
            let wtx = begin_durable_write(&kv)?;
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
                fatal: AtomicBool::new(false),
                cache: Mutex::new({
                    let mut cache = crate::dbcache::DbCache::new();
                    cache.set_observer(opts.flush_observer.clone(), opts.flush_stats_every);
                    cache.set_write_log(opts.write_log.clone());
                    cache.set_limits(opts.cache_max_size, opts.cache_flush_interval_secs);
                    cache
                }),
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

        // Both paths check `meta_path.exists()` above, so redb's own
        // create-or-open distinction is not what enforces "must already
        // exist" here and routing through the backend hook cannot
        // weaken it.
        let kv = open_metadata(opts, &meta_path).map_err(open_error)?;
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
                fatal: AtomicBool::new(false),
                cache: Mutex::new({
                    let mut cache = crate::dbcache::DbCache::new();
                    cache.set_observer(opts.flush_observer.clone(), opts.flush_stats_every);
                    cache.set_write_log(opts.write_log.clone());
                    cache.set_limits(opts.cache_max_size, opts.cache_flush_interval_secs);
                    cache
                }),
                writer_cv: Condvar::new(),
                writer_busy: Mutex::new(false),
            }),
        })
    }

    /// The database driver type (dcrd `Type`).
    pub fn db_type(&self) -> &'static str {
        DB_TYPE
    }

    /// Per-bucket payload and row-size distribution.
    ///
    /// This is what scores ADR-0004's lever (d). redb splits a leaf when
    /// its serialized form exceeds one page **unless the leaf holds a
    /// single pair**, which is then given a power-of-two run of pages
    /// (`btree_base.rs` `should_split`). So the threshold that matters is
    /// per row, not per mean: with a 36-byte key a value over about 4048
    /// bytes can never share a leaf, and two rows share only when each is
    /// under about 2002.
    ///
    /// Read the distribution, not the mean. An earlier comment here said a
    /// bucket whose *mean* row exceeds half a page "cannot fit two rows in
    /// one"; that is false, and believing it put a 1.74 GiB recoverable-slack
    /// figure into two ADRs. `spendjournalv3` has a 2402-byte mean and a
    /// 1248-byte median, packs 1.55 rows per leaf node, and its 1.536 GiB of
    /// slack survives every re-keying measured — see ADR-0004's 2026-08-12
    /// addendum.
    ///
    /// Read-only: this iterates rather than opening a write transaction,
    /// so unlike [`Self::raw_stats`] it does not perturb what it measures.
    pub fn bucket_stats(&self) -> Result<Vec<BucketStats>, Error> {
        self.check_open()?;
        let tx = self
            .inner
            .kv
            .begin_read()
            .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
        let table = tx
            .open_table(METADATA_TABLE)
            .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;

        // Bucket id -> name, from the `bidx<parent><name>` index rows.
        let mut names: std::collections::BTreeMap<[u8; 4], String> =
            std::collections::BTreeMap::new();
        // Bucket id -> (rows, payload bytes, largest row).
        // (rows, payload, largest, log2 size bands)
        #[allow(clippy::type_complexity)]
        let mut agg: std::collections::BTreeMap<[u8; 4], (u64, u64, u64, [u64; 40])> =
            std::collections::BTreeMap::new();

        let iter = redb::ReadableTable::range::<&[u8]>(&table, ..)
            .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
        for entry in iter {
            let (k, v) = entry.map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
            let key = k.value();
            let val = v.value();
            if key.starts_with(BUCKET_INDEX_PREFIX) {
                // `bidx-cbid` shares the `bidx` prefix but is the bucket-id
                // counter, not an index row, and it parses as one: nine bytes
                // long with a four-byte value, so the naive split reads `-cbi`
                // as the parent and `d` as the name, then binds that name to
                // whatever id the counter currently holds -- the most recently
                // allocated bucket. It sorts after the real row (`-` is 0x2d
                // against the root parent's 0x00), so it silently renamed the
                // highest-id bucket to `d`. That is how `existsaddridx` came
                // to be reported as `d` on both sides of the 2026-08-11 dcrd
                // comparison.
                if key == CUR_BUCKET_ID_KEY {
                    continue;
                }
                // `bidx` + parent id (4) + name; the value is the child id.
                if val.len() == 4 && key.len() > BUCKET_INDEX_PREFIX.len() + 4 {
                    let mut id = [0u8; 4];
                    id.copy_from_slice(val);
                    let name = String::from_utf8_lossy(
                        &key[BUCKET_INDEX_PREFIX.len().saturating_add(4)..],
                    )
                    .into_owned();
                    names.insert(id, name);
                }
                continue;
            }
            if key.len() < 4 {
                continue;
            }
            let mut id = [0u8; 4];
            id.copy_from_slice(&key[..4]);
            let bytes = (key.len() as u64).saturating_add(val.len() as u64);
            let slot = agg
                .entry(id)
                .or_insert_with(|| (0u64, 0u64, 0u64, [0u64; 40]));
            slot.0 = slot.0.saturating_add(1);
            slot.1 = slot.1.saturating_add(bytes);
            slot.2 = slot.2.max(bytes);
            // floor(log2(bytes)), so the band is [2^i, 2^(i+1)).
            let band = (u64::BITS - 1).saturating_sub(bytes.max(1).leading_zeros()) as usize;
            slot.3[band.min(39)] = slot.3[band.min(39)].saturating_add(1);
        }

        let mut out: Vec<BucketStats> = agg
            .into_iter()
            .map(|(id, (rows, payload, largest, size_log2))| BucketStats {
                id,
                name: names.get(&id).cloned().unwrap_or_else(|| {
                    format!("<id {:02x}{:02x}{:02x}{:02x}>", id[0], id[1], id[2], id[3])
                }),
                rows,
                payload_bytes: payload,
                largest_row_bytes: largest,
                size_log2,
            })
            .collect();
        out.sort_by_key(|b| core::cmp::Reverse(b.payload_bytes));
        Ok(out)
    }

    /// Decompose the metadata store's on-disk footprint.
    ///
    /// **This opens a write transaction.** redb exposes `stats()` only on
    /// `WriteTransaction`, so measuring necessarily takes the writer, and a
    /// database that has to be repaired on open is repaired before anything
    /// is read. Measure a copy, never an artifact whose figures matter: on
    /// btrfs `cp -a --reflink=always` clones a datadir in seconds at no
    /// space cost. The transaction is aborted rather than committed, so no
    /// data changes, but the file is still opened for writing.
    ///
    /// The walk is proportional to the tree: redb's `stats()` recurses
    /// through every branch and leaf page. On a mainnet-sized metadata
    /// store that is seconds, which is why the per-flush observer samples
    /// rather than calling this on every commit.
    pub fn raw_stats(&self) -> Result<RawStats, Error> {
        self.check_open()?;
        let tx = begin_durable_write(&self.inner.kv)?;
        let stats = {
            let db_stats = tx
                .stats()
                .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
            let table = tx
                .open_table(METADATA_TABLE)
                .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
            let table_stats = redb::ReadableTableMetadata::stats(&table)
                .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
            RawStats {
                page_size: db_stats.page_size() as u64,
                allocated_pages: db_stats.allocated_pages(),
                tree_height: db_stats.tree_height(),
                database_fragmented_bytes: db_stats.fragmented_bytes(),
                leaf_pages: table_stats.leaf_pages(),
                branch_pages: table_stats.branch_pages(),
                stored_leaf_bytes: table_stats.stored_bytes(),
                metadata_bytes: table_stats.metadata_bytes(),
                table_fragmented_bytes: table_stats.fragmented_bytes(),
            }
        };
        // Abort explicitly: committing would rewrite the root for a
        // read-only question.
        tx.abort()
            .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
        Ok(stats)
    }

    fn check_open(&self) -> Result<(), Error> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(db_error(ErrorKind::DbNotOpen, "database is not open"));
        }
        Ok(())
    }

    /// Whether a durable write has failed on this store.
    ///
    /// Exposed so callers above the storage layer can tell a *storage*
    /// failure from a consensus one. They look identical otherwise:
    /// `Chain::process_block` renders a persistence failure as a
    /// `RuleError` so it can flow through the existing error paths, and a
    /// caller that took that at face value would blame the peer that sent
    /// a perfectly good block.
    pub fn is_fatal(&self) -> bool {
        self.inner.fatal.load(Ordering::SeqCst)
    }

    /// Refuse a write once a durable write has failed.
    ///
    /// Deliberately **not** applied to reads. Data that reached disk is
    /// still valid, and refusing to serve it would turn a write fault into
    /// a total outage — the RPC surface and every query would fail — for
    /// no gain in integrity. Only the paths that could produce a *new*
    /// commit are latched, because a new commit is the thing that must
    /// not report success after a failure.
    fn check_writable(&self) -> Result<(), Error> {
        if self.inner.fatal.load(Ordering::SeqCst) {
            return Err(db_error(
                ErrorKind::Fatal,
                "a durable write to the metadata store failed; this handle refuses \
                 further writes -- stop the node, investigate the storage, and \
                 restart",
            ));
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
        // The overlay snapshot and the store snapshot are taken under
        // one hold of the cache lock, because a transaction's view is
        // the overlay shadowing the store: `fetch_raw` answers from
        // `cache_snap` before consulting the table.  Taking them
        // separately lets flushes land in between, and while one
        // intervening flush is harmless — the same batch is then seen
        // in both layers, with identical values — two are not.  Each
        // flush empties the overlay, so after two the pinned layer is
        // strictly older than the store for any key they share, and a
        // key the second flush deleted is resurrected by the stale
        // overlay.  The reader would then see a state that never
        // existed at any commit point.
        //
        // `Database::flush` holds this same lock across redb's commit
        // and the overlay clear (see `DbCache::flush`), so holding it
        // here means a reader observes a flush either wholly or not at
        // all.  The order is writer flag, then cache, then redb on both
        // paths, so the two cannot deadlock against each other.
        let cache = self.inner.cache.lock().expect("cache lock poisoned");
        let cache_snap = std::sync::Arc::clone(&cache.cached);
        let kv = match self.inner.kv.begin_read() {
            Ok(t) => t,
            Err(e) => {
                drop(cache);
                if writable {
                    release(&self.inner);
                }
                return Err(db_error(ErrorKind::DriverSpecific, e.to_string()));
            }
        };
        drop(cache);
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
        if writable {
            self.check_writable()?;
        }
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
        if writable {
            self.check_writable()?;
        }
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
            .flush(&self.inner.kv, &self.inner.block_store)
            .map_err(|e| self.inner.mark_fatal(e))?;
        Ok(())
    }

    /// Write all outstanding cached entries to disk (dcrd `Flush`):
    /// sync the flat block files, then durably commit the metadata
    /// write cache.
    pub fn flush(&self) -> Result<(), Error> {
        self.check_open()?;
        self.check_writable()?;
        let _writer = self.exclusive_writer();
        self.inner
            .cache
            .lock()
            .expect("cache lock poisoned")
            .flush(&self.inner.kv, &self.inner.block_store)
            .map_err(|e| self.inner.mark_fatal(e))?;
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod dirmode_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// dcrd creates the block database tree with `os.MkdirAll(dbPath,
    /// 0700)`, so a `--datadir` on a shared path is not traversable by
    /// other local users.  Plain `create_dir_all` would leave 0755
    /// under the usual 022 umask.
    #[test]
    fn a_created_database_directory_is_owner_only() {
        let tmp = tempfile::tempdir().unwrap();
        // Two missing levels, because dcrd makes the data directory and
        // the database directory beneath it both 0700.
        let path = tmp.path().join("data").join("blocks_redb");
        let db = Database::create(&Options::new(&path, 0x0709_1101)).unwrap();
        db.close().unwrap();

        assert_eq!(
            mode_of(path.parent().unwrap()),
            0o700,
            "every directory created for the database must be owner-only"
        );
        assert_eq!(mode_of(&path), 0o700, "the database directory must be 0700");
    }
}

#[cfg(test)]
mod already_open_tests {
    use super::*;

    /// A second open of a live data directory must be refused, and must
    /// say so as [`ErrorKind::DbAlreadyOpen`] rather than as an opaque
    /// driver error.
    ///
    /// This is what stops two daemons from sharing one directory, which
    /// matters more here than it would for dcrd: the flat block files are
    /// written in dcrd's exact record format while the metadata lives in
    /// redb rather than leveldb, so a shared directory yields block files
    /// that look mutually readable alongside indexes that are not.  redb
    /// takes the `flock` before any block file is touched, so the refusal
    /// happens before damage is possible — the only thing that was
    /// missing is the error kind, which dcrd has as `ErrDbAlreadyOpen`
    /// and which nothing here ever produced.
    #[test]
    fn a_second_open_is_refused_as_already_open() {
        let dir = tempfile::tempdir().expect("temp dir");
        let opts = Options::new(dir.path().join("blocks"), 0x1234_5678);

        let first = Database::create(&opts).expect("first create");

        let err = match Database::open(&opts) {
            Err(e) => e,
            Ok(_) => panic!("a live datadir must not open twice"),
        };
        assert_eq!(
            err.kind,
            ErrorKind::DbAlreadyOpen,
            "expected dcrd's ErrDbAlreadyOpen, got {err:?}"
        );
        assert!(
            err.description.contains("already open"),
            "the message must tell the operator what is wrong: {err:?}"
        );

        // Creating over an existing directory is refused earlier, by the
        // existence check, so it reports dcrd's ErrDbExists instead --
        // the lock is never reached.
        let err = match Database::create(&opts) {
            Err(e) => e,
            Ok(_) => panic!("an existing datadir must not be recreated"),
        };
        assert_eq!(err.kind, ErrorKind::DbExists);

        // `close` flushes and marks the handle closed, mirroring dcrd's
        // `Close`; the OS lock belongs to the open file, so it is released
        // when the handle is dropped rather than when close returns.
        first.close().expect("close");
        assert!(
            Database::open(&opts).is_err(),
            "the lock belongs to the handle, so closing alone must not release it"
        );
        drop(first);
        let reopened = Database::open(&opts).expect("reopen once the handle is dropped");
        reopened.close().expect("close again");
    }
}

#[cfg(test)]
mod raw_stats_tests {
    use super::*;

    /// The components `raw_stats` read from the real mainnet metadata
    /// store (14.483 GiB, 76,302,003 rows) on 2026-08-07.
    fn mainnet_sample() -> RawStats {
        RawStats {
            page_size: 4096,
            allocated_pages: 2_566_169,
            tree_height: 6,
            database_fragmented_bytes: 8_732_251_030,
            leaf_pages: 2_175_036,
            branch_pages: 43_580,
            stored_leaf_bytes: 6_069_306_631,
            metadata_bytes: 745_293_161,
            table_fragmented_bytes: 3_692_201_360,
        }
    }

    const GIB: f64 = (1024 * 1024 * 1024) as f64;

    /// The derived figures must reproduce the decomposition ADR-0004's
    /// amendment published, which was produced independently by a
    /// throwaway tool that no longer exists.
    ///
    /// This is the only check that the arithmetic here means what the ADR
    /// means, and it already caught one error: deriving the live tree as
    /// `(leaf_pages + branch_pages) * page_size` reports 8.46 GiB against
    /// the true 9.79, because `leaf_pages` counts leaf *nodes* while the
    /// allocator rounds each node to a power-of-two run of pages
    /// (`required_order = ceil_log2`, redb-4.1.0 `page_manager.rs:946`),
    /// so a single row too large to share a leaf can occupy 2, 4 or 32
    /// pages and still be counted once. Not overflow pages: redb has no
    /// such mechanism in 2.6.3 or 4.1.0. See
    /// [`RawStats::live_tree_bytes`].
    #[test]
    fn derived_figures_match_the_adr_0004_decomposition() {
        let s = mainnet_sample();

        let payload = s.stored_leaf_bytes as f64 / GIB;
        assert!(
            (payload - 5.65).abs() < 0.01,
            "payload {payload:.2} GiB, ADR says 5.65"
        );

        let overhead = s.metadata_bytes as f64 / GIB;
        assert!(
            (overhead - 0.69).abs() < 0.01,
            "overhead {overhead:.2} GiB, ADR says 0.69"
        );

        let slack = s.table_fragmented_bytes as f64 / GIB;
        assert!(
            (slack - 3.44).abs() < 0.01,
            "slack {slack:.2} GiB, ADR says 3.44"
        );

        let free = s.free_page_bytes() as f64 / GIB;
        assert!(
            (free - 4.69).abs() < 0.01,
            "free pages {free:.2} GiB, ADR says 4.69"
        );

        let live = s.live_tree_bytes() as f64 / GIB;
        assert!(
            (live - 9.79).abs() < 0.01,
            "live tree {live:.2} GiB, ADR says 9.79"
        );

        let fill = s.fill_ratio();
        assert!(
            (fill - 0.6486).abs() < 0.0001,
            "fill {fill:.4}, ADR says 0.6486"
        );
    }

    /// Live plus free must account for the file, bar redb's header and
    /// region metadata. A drift here means the decomposition has stopped
    /// describing the file it claims to describe.
    #[test]
    fn accounted_bytes_reconstructs_the_file_size() {
        let s = mainnet_sample();
        // The metadata.redb the sample was read from.
        const FILE_BYTES: u64 = 15_551_119_360;
        let accounted = s.accounted_bytes();
        let gap = FILE_BYTES.abs_diff(accounted);
        assert!(
            gap < 4 * 1024 * 1024,
            "accounted {accounted} vs file {FILE_BYTES}: {gap} bytes unexplained"
        );
    }

    /// The free-page figure must not silently absorb the table's slack:
    /// redb's database-wide `fragmented_bytes` is the sum of the two, and
    /// reading it whole is the mistake the type documents.
    #[test]
    fn free_pages_exclude_intra_page_slack() {
        let s = mainnet_sample();
        assert_eq!(
            s.free_page_bytes(),
            s.database_fragmented_bytes - s.table_fragmented_bytes
        );
        assert!(
            s.free_page_bytes() < s.database_fragmented_bytes,
            "the database figure must be the larger of the two"
        );
    }
}

#[cfg(test)]
mod bucket_stats_tests {
    use super::*;

    /// `bidx-cbid` is the bucket-id counter, not a bucket-index row, but it
    /// shares the `bidx` prefix and parses as one: the naive split reads
    /// `-cbi` as the parent id and `d` as the name, and binds `d` to the id
    /// the counter holds — the most recently allocated bucket. Because `-`
    /// (0x2d) sorts after the root parent's 0x00, the counter is read last
    /// and overwrites the real name.
    ///
    /// This is not hypothetical: it renamed `existsaddridx` to `d` in every
    /// per-bucket table this project has produced, on both sides of the
    /// 2026-08-11 dcrd comparison, because `tools/dcrdstat` ports the same
    /// parse. Nothing about the numbers was wrong, which is exactly why it
    /// survived — a mislabelled 66-million-row bucket looks like a real one.
    #[test]
    fn the_bucket_id_counter_is_not_read_as_a_bucket_name() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let db = Database::create(&Options::new(tmp.path().join("blocks_redb"), 0x0709_1101))
            .expect("create");

        // Two buckets, so the counter has advanced past the first and would
        // rename the second rather than a bucket nothing else names.
        let tx = db.begin(true).expect("begin");
        for name in [b"existsaddridx".as_slice(), b"utxosetv3".as_slice()] {
            let bucket = tx.metadata().create_bucket(name).expect("create bucket");
            bucket.put(b"k", b"v").expect("put");
        }
        tx.commit().expect("commit");
        // A commit stages into the metadata cache; `bucket_stats` reads redb
        // directly, so the rows have to be pushed down first.
        db.flush().expect("flush");

        let stats = db.bucket_stats().expect("bucket stats");
        let names: Vec<&str> = stats.iter().map(|b| b.name.as_str()).collect();
        assert!(
            !names.contains(&"d"),
            "the `bidx-cbid` counter was read as a bucket named `d`: {names:?}"
        );
        assert!(
            names.contains(&"existsaddridx") && names.contains(&"utxosetv3"),
            "both real buckets must keep their names: {names:?}"
        );
        db.close().expect("close");
    }

    /// A mean is not a distribution, and treating it as one cost this
    /// project a 1.74 GiB figure that reached two ADRs and nearly a storage
    /// format change. `spendjournalv3`'s real shape is a mostly-small
    /// bucket with a long tail: mean 2402, median 1248, largest 66699.
    ///
    /// This builds that shape deliberately — many small rows, a few very
    /// large — and asserts the percentiles separate from the mean. If
    /// someone reintroduces a mean-derived packing estimate, the numbers
    /// here are the counterexample.
    #[test]
    fn percentiles_separate_a_long_tail_from_the_mean() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let db = Database::create(&Options::new(tmp.path().join("blocks_redb"), 0x0709_1101))
            .expect("create");

        let tx = db.begin(true).expect("begin");
        {
            let bucket = tx
                .metadata()
                .create_bucket(b"skewed")
                .expect("create bucket");
            // 990 rows of ~64 B and 10 of ~64 KiB: the mean lands an order
            // of magnitude above where almost every row actually is.
            for i in 0..990u32 {
                bucket.put(&i.to_be_bytes(), &[0u8; 60]).expect("put");
            }
            for i in 990..1000u32 {
                bucket.put(&i.to_be_bytes(), &[0u8; 65_536]).expect("put");
            }
        }
        tx.commit().expect("commit");
        db.flush().expect("flush");

        let stats = db.bucket_stats().expect("bucket stats");
        let b = stats
            .iter()
            .find(|b| b.name == "skewed")
            .expect("skewed bucket");

        assert_eq!(b.rows, 1000);
        let mean = b.mean_row_bytes();
        let p50 = b.size_percentile(0.50);
        assert!(
            mean > 600.0,
            "the tail must drag the mean up, got {mean:.0}"
        );
        assert!(
            p50 <= 128,
            "the median must stay with the 99% of small rows, got {p50}"
        );
        assert!(
            (mean / p50 as f64) > 5.0,
            "mean {mean:.0} and median {p50} must separate, or the test is not \
             exercising the thing that misled"
        );
        assert!(
            b.largest_row_bytes >= 65_536,
            "largest row {} must see the tail",
            b.largest_row_bytes
        );
        db.close().expect("close");
    }
}

#[cfg(test)]
mod fatal_latch_tests {
    use super::*;

    /// Once a durable write has failed, every later write on the handle
    /// must fail too.
    ///
    /// This is the property that makes one storage-bug class unreachable:
    /// the bug needs a *second* commit to report success after a first one
    /// failed, and this forbids dcroxide from issuing it. It is stated
    /// without reference to any engine, so it survives an engine change —
    /// which is the point, since the engine dcroxide would move to
    /// (fjall 3.1.8) has exactly that bug open upstream as #308: its
    /// `WriteBatch::commit` does not poison on a journal write failure the
    /// way its `persist` does, so a later batch can commit after an
    /// unterminated record and be truncated away on recovery.
    ///
    /// **What this test covers and what it does not.** It pins the
    /// consequence — latched means closed to writes — deterministically,
    /// on every platform. It does *not* induce a real `ENOSPC` or `EIO`,
    /// so it does not prove that a genuine device failure reaches the
    /// latch. That wiring is three `map_err(|e| self.inner.mark_fatal(e))`
    /// calls, one per path that hands a durable commit to the engine
    /// (`Database::flush`, `Database::close`, and the flush inside
    /// `Transaction::commit_internal`). `tests/enospc.rs` closes that
    /// gap: it fills a 2 MiB filesystem under a live database and asserts
    /// that the resulting `ENOSPC` arrives as an error, latches the
    /// store, and leaves reads working. It is Linux-only and skips
    /// loudly where it cannot mount one, with CI setting
    /// `DCROXIDE_REQUIRE_FAULT_INJECTION=1` so a skip there is a
    /// failure.
    #[test]
    fn a_failed_durable_write_closes_the_handle_to_further_writes() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let opts = Options::new(tmp.path().join("blocks_redb"), 0x0709_1101);
        let db = Database::create(&opts).expect("create");

        // A durable generation, so there is committed state to protect.
        db.update(|tx| {
            let b = tx.metadata().create_bucket(b"data")?;
            b.put(b"k", b"v")
        })
        .expect("write");
        db.flush().expect("flush");

        // The latch, set through the same path the production code uses.
        let err = db.inner.mark_fatal(db_error(
            ErrorKind::DriverSpecific,
            "simulated write failure",
        ));
        assert_eq!(
            err.kind,
            ErrorKind::DriverSpecific,
            "the cause is returned unchanged"
        );

        // Every write path now refuses, with the fatal kind rather than
        // DbNotOpen -- an operator told "not open" would look in the
        // wrong place.
        for (what, got) in [
            (
                "update",
                db.update(|tx| tx.metadata().put(b"probe", b"x"))
                    .unwrap_err(),
            ),
            ("flush", db.flush().unwrap_err()),
            ("begin(true)", db.begin(true).map(|_| ()).unwrap_err()),
        ] {
            assert_eq!(
                got.kind,
                ErrorKind::Fatal,
                "{what} must refuse with ErrorKind::Fatal, got {got}"
            );
        }

        // Reads of already-committed state stay available: the data that
        // reached disk is still valid, and refusing reads would turn a
        // write fault into a total outage for no integrity gain.
        db.view(|tx| {
            let b = tx.metadata().bucket(b"data").expect("bucket");
            assert_eq!(b.get(b"k").as_deref(), Some(b"v".as_slice()));
            Ok(())
        })
        .expect("reads stay available");
    }

    /// The latch is on the shared state, not the handle, so a second
    /// handle cannot be used to route around it.
    #[test]
    fn the_latch_is_shared_by_every_clone_of_the_handle() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let opts = Options::new(tmp.path().join("blocks_redb"), 0x0709_1101);
        let db = Database::create(&opts).expect("create");
        let other = db.clone();

        db.inner.mark_fatal(db_error(
            ErrorKind::DriverSpecific,
            "simulated write failure",
        ));

        assert_eq!(
            other
                .update(|tx| tx.metadata().put(b"probe", b"x"))
                .unwrap_err()
                .kind,
            ErrorKind::Fatal,
            "a clone shares Arc<DbInner> and must refuse too"
        );
    }
}
