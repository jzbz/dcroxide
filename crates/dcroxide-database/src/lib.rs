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
//! ffldb's (see the `transaction` module docs), so bucket and cursor
//! semantics — iteration order, nested-bucket handling, error kinds,
//! and quirks like `Delete` on an empty key silently succeeding — match
//! dcrd behavior for behavior, which is pinned by the ported ffldb
//! interface test battery.
//!
//! One deliberate divergence from ffldb reaches the interface: the
//! internal block index keys a block by its big-endian height and then
//! its hash, where ffldb keys it by the hash alone, so the block
//! lookups (`has_block`, `fetch_block`, `fetch_block_header`,
//! `fetch_block_region` and their plural forms) take the block's height
//! beside its hash ([ADR-0010]).  The others stay within the interface
//! contract: the metadata write cache is a layered overlay rather than
//! goleveldb's treap pair (see `dbcache`), a nested bucket is found in a
//! copy of the bucket index held in memory, which `create` and `open`
//! read from the store, rather than by reading its index row on every
//! lookup (see `bucketindex`), no LRU block-file handle
//! cache, cursors materialize their view at creation (the interface
//! contract already declares cursors invalidated by any bucket
//! modification other than `Cursor::delete`), and `Cursor::delete` on
//! a read-only transaction returns the `ErrTxNotWritable` the contract
//! documents, where ffldb silently accepts the delete into pending
//! state that the read-only commit then discards.
//!
//! Two hooks have no ffldb counterpart and change nothing for a caller
//! that does not use them ([ADR-0011]): a [`FlushParticipant`], whose rows
//! ride inside the metadata flush's own redb transaction beside the
//! overlay's, and [`Transaction::on_commit`], which runs a closure once a
//! commit's own flush has taken the rows it will write and before the
//! commit's rows are published.
//!
//! [`Transaction::store_block_record`] has none either.  It stores a
//! block that was laid out as its block-file record ahead of the commit
//! ([`BlockRecord`]), on whichever thread held its bytes, and leaves the
//! file bytes and the index row that `store_block` leaves for the same
//! block.  [`Database::records_written_as_laid_out`] counts the records
//! that were written as they were handed in.
//!
//! [ADR-0004]: ../../../docs/adr/0004-storage-backend.md
//! [ADR-0010]: ../../../docs/adr/0010-height-first-block-keys.md
//! [ADR-0011]: ../../../docs/adr/0011-exists-address-layout-3-and-the-flush-participant.md

#![forbid(unsafe_code)]

mod blockfile;
pub mod bootstrap;
mod bucketindex;
pub(crate) mod dbcache;
mod error;
#[cfg(test)]
mod flush_sync_tests;
mod participant;
mod procmem;
mod transaction;

use std::path::{Path, PathBuf};
use std::sync::Condvar;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

pub use blockfile::BlockRecord;
use blockfile::{BlockStore, deserialize_write_row, serialize_write_row};
pub use bootstrap::ImportStats;
pub use error::{Error, ErrorKind};
pub use participant::{FlushParticipant, FlushWriter, ParticipantStats};
pub use procmem::{ARENA_HEAP_ALIGN, ArenaMaps, ProcessMemory};

/// A raw key, bucket id included, and its value, as the raw-keyspace
/// reads return them ([`Transaction::try_first_after`],
/// [`Transaction::try_scan_after`], [`FlushWriter::range`]).
pub type RawRow = (Vec<u8>, Vec<u8>);
use transaction::{
    BLOCK_IDX_BUCKET_ID, BLOCK_IDX_BUCKET_NAME, BUCKET_INDEX_PREFIX, CUR_BUCKET_ID_KEY, KvTxSeed,
    METADATA_BUCKET_ID, WRITE_LOC_KEY,
};
pub use transaction::{BlockRegion, Bucket, Cursor, Transaction};

use crate::dbcache::{DbCache, FillJob, FlushBatch, FlushOutcome, Opened};
use crate::error::db_error;

// redb 4 moved `begin_read` onto a trait; importing it keeps the call
// sites unchanged. See the ADR-0004 upgrade note for why we are on 4.x.
use redb::ReadableDatabase as _;

/// The single redb table holding the entire ffldb-layout keyspace.
pub(crate) const METADATA_TABLE: redb::TableDefinition<'static, &'static [u8], &'static [u8]> =
    redb::TableDefinition::new("metadata");

/// The name of the metadata store file within the database directory.
const METADATA_FILE: &str = "metadata.redb";

/// The name of dcrd ffldb's goleveldb metadata directory within the same
/// database directory (`metadataDbName`, `ffldb/db.go:34`).
const DCRD_METADATA_DIR: &str = "metadata";

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
    let mut tx = kv.begin_write().map_err(storage_error)?;
    tx.set_durability(redb::Durability::Immediate)
        .map_err(storage_error)?;
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
    ///
    /// The first cause is kept, and every refusal names it: a flush that
    /// failed because a flush participant found its own rows damaged
    /// (ADR-0011) latches the store like a storage fault, and the
    /// operator reading a later commit's refusal needs that cause and its
    /// remedy, not only the advice to look at the storage.
    pub(crate) fn mark_fatal(&self, e: Error) -> Error {
        {
            let mut cause = self.fatal_cause.lock().expect("fatal cause lock poisoned");
            if cause.is_none() {
                *cause = Some(e.description.clone());
            }
        }
        self.fatal.store(true, Ordering::SeqCst);
        e
    }

    /// Refuse a write once a durable write has failed.
    ///
    /// Deliberately **not** applied to reads. Data that reached disk is
    /// still valid, and refusing to serve it would turn a write fault into
    /// a total outage — the RPC surface and every query would fail — for
    /// no gain in integrity. Only the paths that could produce a *new*
    /// commit are latched, because a new commit is the thing that must
    /// not report success after a failure.
    ///
    /// A path that waits for the writer semaphore checks again once it
    /// holds it.  The latch is set by the semaphore's holder, or by the
    /// thread a flush handed its commit to, so a check made before the
    /// wait can pass while the writer being waited on is the one whose
    /// durable write fails, and a caller admitted past that would re-run
    /// the failed flush.  A holder that waits for a commit on its own
    /// thread ([`drain_flight`]) checks again after that wait for the
    /// same reason.
    ///
    /// A commit made on its own thread can also fail between a writer's
    /// last check and that writer's return.  Such a writer reports `Ok`:
    /// its rows were published to the write cache, nothing told it they
    /// were durable, and they are lost with the failed batch at the next
    /// start.  What cannot happen is a capture, or an acknowledgement of
    /// durability, after the failure: both follow a wait for the commit
    /// and a check made after it.
    pub(crate) fn check_writable(&self) -> Result<(), Error> {
        if self.fatal.load(Ordering::SeqCst) {
            let mut text = String::from(
                "a durable write to the metadata store failed; this handle refuses \
                 further writes -- stop the node, investigate the storage, and \
                 restart",
            );
            let cause = self
                .fatal_cause
                .lock()
                .expect("fatal cause lock poisoned")
                .clone();
            if let Some(cause) = cause {
                text.push_str(" (the first failure: ");
                text.push_str(&cause);
                text.push(')');
            }
            return Err(db_error(ErrorKind::Fatal, text));
        }
        Ok(())
    }

    /// The shared state over an opened metadata store and block store,
    /// with the overlay configured from the options -- one constructor
    /// for `create` and `open`, so an option wired into one cannot be
    /// forgotten in the other.
    ///
    /// It reads the store's bucket index, which every transaction's
    /// bucket lookups are then answered from, and fails when that read
    /// does ([`bucketindex::BucketIndex::load`]).
    fn new(kv: redb::Database, block_store: BlockStore, opts: &Options) -> Result<DbInner, Error> {
        let mut cache = crate::dbcache::DbCache::new();
        cache.set_observer(opts.flush_observer.clone(), opts.flush_stats_every);
        cache.set_write_log(opts.write_log.clone());
        cache.set_limits(opts.cache_max_size, opts.cache_flush_interval_secs);
        cache.set_bucket_index(bucketindex::BucketIndex::load(&kv)?);
        Ok(DbInner {
            kv: Mutex::new(Some(Arc::new(kv))),
            block_store: Mutex::new(block_store),
            closed: AtomicBool::new(false),
            fatal: AtomicBool::new(false),
            fatal_cause: Mutex::new(None),
            cache: Mutex::new(cache),
            writer_cv: Condvar::new(),
            writer_busy: Mutex::new(false),
            writer_waits_index: WaitTotal::default(),
            writer_waits_other: WaitTotal::default(),
            participant: Mutex::new(None),
            background: opts.background_commit,
            committer: Mutex::new(CommitThread {
                state: CommitState::NotStarted,
            }),
            flight: Mutex::new(None),
            waited_nanos: AtomicU64::new(0),
            durable_through: AtomicU64::new(0),
            log: opts.log.clone(),
            commit_snapshot: opts.commit_snapshot,
            before_commit: opts.before_commit.clone(),
            flush_end: Mutex::new(None),
            #[cfg(test)]
            before_fill: Mutex::new(None),
            #[cfg(test)]
            before_retire: Mutex::new(None),
            #[cfg(test)]
            between_snapshots: Mutex::new(None),
            #[cfg(test)]
            refuse_commit_thread: AtomicBool::new(false),
            #[cfg(test)]
            commit_threads_started: AtomicU64::new(0),
            #[cfg(test)]
            before_release: Mutex::new(None),
            #[cfg(test)]
            after_job: Mutex::new(None),
            #[cfg(test)]
            skip_drain: AtomicBool::new(false),
            #[cfg(test)]
            batch_dropped: Mutex::new(None),
        })
    }

    /// Take the writer semaphore, waiting out whoever holds it.
    ///
    /// A caller that finds it held is timed until it holds it, and the
    /// wait is added to the total for its kind of thread
    /// ([`WriterWaits`]).  One that finds it free reads no clock.
    fn acquire_writer(&self) {
        let mut busy = self.writer_busy.lock().expect("writer flag poisoned");
        if *busy {
            let started = std::time::Instant::now();
            while *busy {
                busy = self.writer_cv.wait(busy).expect("writer flag poisoned");
            }
            let total = if std::thread::current().name() == Some(INDEX_THREAD_NAME) {
                &self.writer_waits_index
            } else {
                &self.writer_waits_other
            };
            total.add(started.elapsed());
        }
        *busy = true;
    }

    /// The waits for the writer semaphore so far.
    fn writer_waits(&self) -> WriterWaits {
        WriterWaits {
            index: self.writer_waits_index.get(),
            other: self.writer_waits_other.get(),
        }
    }

    /// The registered flush participant, cloned out of its slot so the
    /// slot's lock is never held while the participant runs.
    pub(crate) fn registered(&self) -> Option<participant::Registration> {
        self.participant
            .lock()
            .expect("participant lock poisoned")
            .clone()
    }

    /// The registered participant's prefix, for the commit-time check
    /// that no transaction stages a row under it.
    pub(crate) fn participant_prefix(&self) -> Option<Arc<[u8]>> {
        self.participant
            .lock()
            .expect("participant lock poisoned")
            .as_ref()
            .map(|r| Arc::clone(&r.prefix))
    }

    /// Empty the participant slot, returning what it held.
    fn take_participant(&self) -> Option<Arc<dyn FlushParticipant>> {
        self.participant
            .lock()
            .expect("participant lock poisoned")
            .take()
            .map(|r| r.participant)
    }

    /// A clone of the metadata store's redb handle, or `None` once a clean
    /// close has let go of it ([`DbInner::kv`]).
    fn kv_handle(&self) -> Option<Arc<redb::Database>> {
        self.kv.lock().expect("kv slot poisoned").clone()
    }

    /// [`Self::kv_handle`], refused as dcrd refuses a closed database.
    fn kv_or_closed(&self) -> Result<Arc<redb::Database>, Error> {
        self.kv_handle()
            .ok_or_else(|| db_error(ErrorKind::DbNotOpen, "database is not open"))
    }

    /// Empty the redb handle's slot, returning what it held, for the
    /// caller to drop once the slot's lock is released: the drop that
    /// lets go of the last clone runs redb's close.
    fn take_kv(&self) -> Option<Arc<redb::Database>> {
        self.kv.lock().expect("kv slot poisoned").take()
    }
}

impl Drop for WriterGuard<'_> {
    fn drop(&mut self) {
        let mut busy = self.db.writer_busy.lock().expect("writer flag poisoned");
        *busy = false;
        self.db.writer_cv.notify_one();
        #[cfg(test)]
        release_hook();
    }
}

/// A test's probe into the release of the writer semaphore.
#[cfg(test)]
pub(crate) type ReleaseHook = Box<dyn Fn()>;

#[cfg(test)]
thread_local! {
    /// Run on the calling thread each time it releases the writer
    /// semaphore, by a guard's drop or a writable transaction's end, as
    /// it releases it, so a test can see what that thread still holds
    /// then: the layers its flush retired, which it must not have freed
    /// yet.  The semaphore's flag is still locked when this runs, so it
    /// must not come for the semaphore itself.
    pub(crate) static RELEASE_HOOK: std::cell::RefCell<Option<ReleaseHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Run [`RELEASE_HOOK`], if a test set one.
#[cfg(test)]
pub(crate) fn release_hook() {
    RELEASE_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow().as_ref() {
            hook();
        }
    });
}

pub(crate) struct DbInner {
    /// The metadata store's redb handle, until a clean close lets go of
    /// it ([`Database::close`]); `None` from then on.
    ///
    /// redb clears the recovery flag that its writable open set in the
    /// file's header only in the close its handle's drop runs
    /// (redb-4.3.0 `page_manager.rs:1458-1469`, `db.rs:1963-2028`,
    /// `page_manager.rs:2466-2486`), and until then the file reads as one
    /// whose writer did not stop: every open recovers it, and a read-only
    /// open is refused.  So the handle has to be dropped for a clean close
    /// to leave a clean file, and the drop of the last [`Database`] clone
    /// cannot be relied on to do it: the daemon's chain holds a clone in a
    /// reference cycle that lives to the end of the process.  Each
    /// transaction holds a clone of the handle from its begin to its end,
    /// so redb closes once the close and the last of them have let go, on
    /// whichever thread lets go last.  A flush holds one while it opens
    /// its write transaction; the close lets go only once no flush is in
    /// flight, and redb would leave its close to the end of a write
    /// transaction still open in any case (redb-4.3.0 `db.rs:2012-2028`).
    /// Asked for once it is `None`, it answers [`ErrorKind::DbNotOpen`].
    /// The lock is a leaf: nothing else is locked while it is held.
    kv: Mutex<Option<Arc<redb::Database>>>,
    pub(crate) block_store: Mutex<BlockStore>,
    closed: AtomicBool,
    /// Set when a durable write has failed. Every later write on this
    /// handle is then refused. See [`DbInner::mark_fatal`].
    fatal: AtomicBool,
    /// The description of the failure that set `fatal`, which every
    /// refusal repeats.
    fatal_cause: Mutex<Option<String>>,
    /// The metadata write cache (dcrd ffldb's `dbCache`).
    pub(crate) cache: Mutex<crate::dbcache::DbCache>,
    /// Serializes writable transactions for their whole lifetime
    /// (dcrd's `writeLock`); redb no longer provides this because
    /// writes only reach it at flush time.
    pub(crate) writer_cv: Condvar,
    pub(crate) writer_busy: Mutex<bool>,
    /// What the thread named [`INDEX_THREAD_NAME`], and every other
    /// thread, has spent waiting for the writer semaphore
    /// ([`WriterWaits`]).  Added to only by a thread that is taking the
    /// semaphore and read by a flush, which holds it, so a flush reads
    /// counts and times that belong together.
    writer_waits_index: WaitTotal,
    writer_waits_other: WaitTotal,
    /// The flush participant, if one is registered ([`FlushParticipant`]).
    ///
    /// A **strong** reference: the daemon drops its index handles before
    /// it closes the database, and the close's flush must still reach the
    /// participant then, or the keys it holds in memory for blocks whose
    /// tip rows that flush persists would be lost.  Changed only with the
    /// writer semaphore held ([`Database::set_flush_participant`],
    /// [`Database::clear_flush_participant`], [`Database::close`]), and
    /// only after a wait for the flush in flight, so a flush sees one
    /// value throughout: it is captured under the semaphore, and the
    /// part of it that may run later, on the commit thread, uses the
    /// clone it took then.
    /// The lock is a leaf: nothing else is locked while it is held.
    participant: Mutex<Option<participant::Registration>>,
    /// [`Options::background_commit`].
    background: bool,
    /// The store's commit thread ([`COMMIT_THREAD_NAME`]): not started
    /// until the first flush is handed to it ([`hand_off`]), then kept,
    /// idle between flushes, until the close or the drop of the last
    /// handle stops it.
    ///
    /// Taken only by the holder of the writer semaphore ([`hand_off`],
    /// [`Database::close`]) and by the store's drop.  The commit thread
    /// never takes it.  The lock is a leaf.
    committer: Mutex<CommitThread>,
    /// The ticket of the flush in flight, when a flush was handed to the
    /// commit thread and nothing has waited for it since: signalled once
    /// that flush has ended and the thread has let go of the store.
    ///
    /// Read and written only by the holder of the writer semaphore, which
    /// is what makes "at most one" hold: a flush stores a ticket here
    /// only after [`drain_flight`] emptied the slot under the same hold.
    /// The commit thread never touches the slot and never takes the
    /// semaphore, so a holder that waits on the ticket cannot deadlock
    /// with it.  The lock is a leaf.
    flight: Mutex<Option<mpsc::Receiver<()>>>,
    /// What semaphore holders have spent in [`drain_flight`] since the
    /// last capture, in nanoseconds; the next captured flush reports it
    /// as its [`FlushObservation::waited`].
    waited_nanos: AtomicU64,
    /// The commits known durable: every commit counted up to this figure
    /// ([`CommitMark`]) is in a durable commit of the store.  Raised by
    /// [`finish`] to the [`FlushBatch::through`] of a flush whose commit
    /// has landed and whose layers are retired, on whichever thread ends
    /// that flush, and never lowered; a flush that fails leaves it, and a
    /// latched store makes no flush that could raise it again.
    durable_through: AtomicU64,
    /// [`Options::log`], for the line a commit that fails on its own
    /// thread logs, having no caller to return its error to.
    log: Option<LogSink>,
    /// [`Options::commit_snapshot`].
    commit_snapshot: bool,
    /// [`Options::before_commit`].
    before_commit: Option<Arc<dyn Fn() + Send + Sync>>,
    /// What the last observed flush left when it ended, for the next
    /// one's observation ([`FlushMemory::process_after_previous`]).
    /// Written by the thread that ends a flush and taken at the next
    /// capture, which follows a wait for that flush to end.  The lock is
    /// a leaf.
    flush_end: Mutex<Option<FlushEnd>>,
    /// Run once, by the next flush to write its rows, just before it
    /// writes them, on whichever thread does: for a test that fails the
    /// storage under the rows of a flush handed to a thread of its own.
    #[cfg(test)]
    before_fill: Mutex<Option<TestHook>>,
    /// Run by the commit thread between a commit and the retirement
    /// of the layers it captured, for a test that needs a reader there.
    #[cfg(test)]
    before_retire: Mutex<Option<TestHook>>,
    /// Run once by the next transaction to begin, between the two
    /// snapshots it takes, for a test that lets a commit land there.
    #[cfg(test)]
    between_snapshots: Mutex<Option<TestHook>>,
    /// Makes a hand-off that would start the commit thread find no
    /// thread to be had, as when the operating system refuses one.
    #[cfg(test)]
    refuse_commit_thread: AtomicBool,
    /// How many commit threads the store has started.
    #[cfg(test)]
    commit_threads_started: AtomicU64,
    /// Run once, by the next flush handed to the commit thread, as that
    /// thread lets go of the store at the flush's end, just before it
    /// does ([`JobEnd::release`]), for a test that the end is signalled
    /// only after it has.
    #[cfg(test)]
    before_release: Mutex<Option<TestHook>>,
    /// Run once, by the commit thread after the next flush handed to it
    /// has ended and been signalled, for a test of a thread that dies
    /// between flights.
    #[cfg(test)]
    after_job: Mutex<Option<TestHook>>,
    /// Skips the wait that precedes a capture, for the test of what a
    /// capture does when it finds a flush in flight.
    #[cfg(test)]
    skip_drain: AtomicBool,
    /// Planted in each batch a flush captures, to run as that batch is
    /// dropped ([`crate::dbcache::FlushBatch::on_drop`]), for a test of
    /// where a flush lets go of the layers it retired.
    #[cfg(test)]
    batch_dropped: Mutex<Option<crate::dbcache::BatchProbe>>,
}

/// A closure a test plants in [`DbInner`].
#[cfg(test)]
type TestHook = Box<dyn Fn() + Send + Sync>;

/// How an observed flush ended, kept for the next one's observation.
#[derive(Clone, Copy)]
struct FlushEnd {
    /// The process's memory once the participant's `finished` had
    /// returned, the flush still holding its captured layers.
    told: Option<ProcessMemory>,
    /// The time from its retirement to then.
    telling: std::time::Duration,
    /// The process's memory once the flush had let go of everything it
    /// frees itself: all of it on the commit thread, and all but the
    /// layers it retired on the capturing thread, whose caller frees
    /// those after this reading: a commit and [`Database::flush`] once
    /// they have released the writer semaphore, and [`Database::close`]
    /// under it.
    memory: Option<ProcessMemory>,
    /// The time from its retirement to then.
    release: std::time::Duration,
}

/// The name of the thread whose waits for the writer semaphore are
/// totalled apart from every other thread's ([`WriterWaits`]): the
/// daemon's index thread, which holds the semaphore for each block's
/// index update while the thread connecting blocks wants it for the
/// next block.
pub const INDEX_THREAD_NAME: &str = "index";

/// The name of the thread that writes a flush's rows and makes its redb
/// commit when the flush hands them over ([`Options::background_commit`]):
/// one thread for the open store, started by the first flush handed to
/// it and kept, asleep between flushes, until [`Database::close`] or the
/// drop of the last handle stops it.  So the rows and the commit of every
/// flush handed over are written by the same thread, and the pages redb
/// allocates for them, which outlive the flush in redb's cache, come
/// from that one thread's allocator state: with glibc's allocator, one
/// arena, which no thread started later is given while the store is
/// open as long as glibc has arenas to give (past `MALLOC_ARENA_MAX`, or
/// eight per processor on a 64-bit system, it shares them among threads,
/// this one's included).  It writes one flush at a time, and is listed
/// from the first flush handed to it on, busy or idle, so its presence
/// says nothing of whether a commit is under way.  A [`FlushObserver`]
/// is called on it for such a flush.
pub const COMMIT_THREAD_NAME: &str = "dbcommit";

/// A point in the order of a database's commits: every transaction
/// committed on the handle, by any of its clones, up to the moment
/// [`Database::commit_mark`] was read.  [`Database::is_durable`] says
/// whether a durable commit of the store has carried all of them.
///
/// Marks of one open database compare in the order they were read.  A
/// mark means nothing to another open, the same store reopened
/// included: the count starts again at every open.  dcrd's database has
/// no such figure; it is for a caller that has handed a flush to a
/// thread of its own ([`Database::flush_in_background`]) and must not
/// count on the flush's rows until they are on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommitMark(u64);

/// The running total of one kind of thread's waits for the writer
/// semaphore.
#[derive(Default)]
struct WaitTotal {
    count: AtomicU64,
    nanos: AtomicU64,
}

impl WaitTotal {
    fn add(&self, waited: std::time::Duration) {
        let nanos = u64::try_from(waited.as_nanos()).unwrap_or(u64::MAX);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.nanos.fetch_add(nanos, Ordering::Relaxed);
    }

    fn get(&self) -> WriterWait {
        WriterWait {
            count: self.count.load(Ordering::Relaxed),
            nanos: self.nanos.load(Ordering::Relaxed),
        }
    }
}

/// What one kind of thread has spent waiting for the writer semaphore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WriterWait {
    /// How many times a thread of this kind found the semaphore held.
    pub count: u64,
    /// The time those waits took in all, in nanoseconds.
    pub nanos: u64,
}

/// The waits for the writer semaphore since the database was opened, in
/// a [`FlushObservation`].
///
/// The semaphore serializes writable transactions, flushes and the
/// close (dcrd's `writeLock`).  A caller that finds it held is timed
/// from then until it holds it; one that finds it free is neither timed
/// nor counted.  The waits are totalled for two kinds of thread, the
/// one named [`INDEX_THREAD_NAME`] and every other, because the time one
/// of them spends waiting is time the other spent holding: the totals
/// say how much of each thread's time went to the other's transactions
/// and flushes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WriterWaits {
    /// The waits of the thread named [`INDEX_THREAD_NAME`].
    pub index: WriterWait,
    /// The waits of every other thread.
    pub other: WriterWait,
}

impl WriterWaits {
    /// Render as one JSON object.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"index\":{{\"count\":{},\"ns\":{}}},\"other\":{{\"count\":{},\"ns\":{}}}}}",
            self.index.count, self.index.nanos, self.other.count, self.other.nanos,
        )
    }
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
    /// Flush count since the database was opened, starting at 1.  Every
    /// flush that commits takes one; a flush with nothing to commit (an
    /// empty overlay and no participant work) syncs the block files and
    /// takes none.
    pub sequence: u64,
    /// Overlay entries written or removed by this flush.  A participant's
    /// rows are counted in [`Self::participant`] instead.
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
    ///
    /// The three phases below, the participant's
    /// [`ParticipantStats::contribute`] when one was called, and the stats
    /// walk account for all of it but the capture, the opening of the
    /// write transaction, the participant's `seal` and the handoffs
    /// between them.
    ///
    /// From the capture to the retirement of what was captured.  When the
    /// commit ran on a thread of its own ([`Self::background`]) the
    /// writer semaphore was held for [`Self::foreground`] of it, not for
    /// all of it.
    pub elapsed: std::time::Duration,
    /// Of `elapsed`, the part spent walking the tree for
    /// [`Self::stats`]. Zero on unsampled flushes.
    pub stats_elapsed: std::time::Duration,
    /// Of `elapsed`, the fsync of the block files written since the last
    /// flush, which runs first (dcrd `syncBlocks`): on the capturing
    /// thread, before the write transaction is opened, or, for a flush
    /// that could be handed over ([`Options::background_commit`]), on the
    /// thread that writes its rows, before it writes them.
    pub block_sync: FlushPhase,
    /// Of `elapsed`, handing the overlay's entries to redb: every insert
    /// and remove, the stats walk excluded.  The write transaction is
    /// opened before this, on the capturing thread, outside the phases.
    /// redb copies each leaf it changes, so a leaf it does not have
    /// cached is read here first, and it allocates the pages it writes,
    /// growing the file when it has none free.
    pub insert: FlushPhase,
    /// Of `elapsed`, redb's commit: writing the dirty pages and syncing
    /// them.
    pub commit: FlushPhase,
    /// Footprint after this flush's writes and before its commit, present
    /// only on sampled flushes.
    ///
    /// Sampled rather than always taken because redb's `stats()` walks
    /// every branch and leaf page, which is seconds on a chain-sized
    /// tree — collecting it per flush would dominate the very timings the
    /// observer exists to measure.
    pub stats: Option<RawStats>,
    /// What the flush participant wrote in this flush, when one was
    /// called ([`FlushParticipant::contribute`]); `None` otherwise.
    ///
    /// [`Self::dirty_entries`] counts the overlay's entries alone, so a
    /// flush in which only the participant wrote is observed with zero
    /// there and this set.  Such a flush commits like any other and takes
    /// the next [`Self::sequence`].
    pub participant: Option<ParticipantStats>,
    /// The waits for the writer semaphore from the opening of the
    /// database to this flush, the flushing thread's own wait for it
    /// included.  Running totals, so the difference between two
    /// observations is what was waited between the two flushes.
    ///
    /// The observer is called on the thread that ran the flush, so
    /// `std::thread::current()` there says which of the two kinds of
    /// thread held the semaphore for [`Self::elapsed`].  The exception is
    /// a flush whose rows and commit were written on a thread of its own
    /// ([`Self::background`]): the observer is called on that thread,
    /// named [`COMMIT_THREAD_NAME`], which never holds the semaphore.
    pub writer_waits: WriterWaits,
    /// Whether a caller that waits for the flush to be durable,
    /// [`Database::flush`] or [`Database::close`], asked for it.  `false`
    /// for one a commit's own flush check tripped, by the overlay's
    /// thresholds or a participant's `wants_flush`, and for one
    /// [`Database::flush_in_background`] asked for, whose commit is handed
    /// over as a tripped one's is.
    pub explicit: bool,
    /// Whether the flush's block files were synced, its rows written and
    /// its redb commit made on another thread than the one that captured
    /// the overlay ([`Options::background_commit`]).
    pub background: bool,
    /// Of `elapsed`, the part the capturing thread spent in the flush,
    /// holding the writer semaphore: all of it when that thread made the
    /// commit too, and the time from the capture to the hand-off when
    /// [`Self::background`] is set, which is the taking of what the
    /// block-file sync owes, the opening of the write transaction and the
    /// participant's `seal`.  The block-file sync itself then runs on the
    /// thread the flush was handed to.
    pub foreground: std::time::Duration,
    /// What was spent, since the capture before this one and so outside
    /// `elapsed`, waiting for an earlier flush's commit on another thread
    /// to end, with the writer semaphore held: the capturing thread's own
    /// wait before the capture, and any other thread's, such as a
    /// commit's at the overlay's ceiling or
    /// [`Database::is_fatal_settled`]'s, which each count against the
    /// next capture whoever makes it.  Every other writer was kept out
    /// meanwhile, so `foreground + waited` is what this flush, with the
    /// waits counted against it, kept every other writer out for.
    pub waited: std::time::Duration,
    /// Whether the redb commit was made with a read snapshot of the
    /// store, as it stood before the commit, held across it by the flush
    /// itself ([`Options::commit_snapshot`]).  A flush takes one only for
    /// a commit it hands to another thread, and keeps it if no thread was
    /// to be had; any other commit made on the capturing thread reads
    /// `false` here whether or not a transaction was open across it, and
    /// so does a handed-over commit for which no snapshot could be had.
    pub snapshot: bool,
    /// What the flush pinned in the overlay and what the process held in
    /// memory around it.
    pub memory: FlushMemory,
}

/// What a flush pinned in the overlay, and the process's memory around
/// it, in a [`FlushObservation`].
///
/// A flush captures the overlay's layers and keeps them published until
/// its commit has landed.  While the commit runs on the capturing thread
/// nothing else is committed, so the overlay holds what was captured and
/// no more.  While it runs on a thread of its own
/// ([`Options::background_commit`]) commits go on above the captured
/// layers, and those are freed later and by another thread than before.
/// These figures say how much was held at each step and by whom, so that
/// a rise in the process's resident memory can be laid at the overlay, at
/// what was allocated while the commit ran, or at neither.
///
/// The byte counts are the overlay's own accounting, as
/// [`FlushObservation::dirty_bytes`] is: about the bytes requested from
/// the allocator, not what the allocator holds for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FlushMemory {
    /// Layers the flush captured, which stay published until it retires.
    pub pinned_layers: usize,
    /// Entries in those layers, a key counted once for each layer that
    /// holds it; [`FlushObservation::dirty_entries`] counts it once.
    pub pinned_entries: usize,
    /// Bytes the overlay held when the write transaction was open and
    /// its rows about to be written, on this thread or another: the
    /// hand-off of a flush that is handed over.  The capturing thread has
    /// held the writer semaphore since the capture, so this is
    /// [`FlushObservation::dirty_bytes`] unless something committed that
    /// should not have.
    pub overlay_at_hand_off: u64,
    /// Bytes the overlay held when the commit had returned and the
    /// captured layers were about to be retired: the captured bytes plus
    /// what was committed while the commit ran.
    pub overlay_at_retirement: u64,
    /// Layers the overlay had then, the captured ones included.
    pub layers_at_retirement: usize,
    /// Captured layers that something other than the flush still
    /// referenced once the overlay had let go of them: a transaction that
    /// began before the retirement holds them in its snapshot, and frees
    /// them on its own thread when it ends.  The others are freed by the
    /// thread that ends the flush.
    pub shared_layers: usize,
    /// Entries in those layers.
    pub shared_entries: usize,
    /// The process's memory just after the capture, heap mappings
    /// included.  `None`, as the four below are, off Linux and when no
    /// observer is attached: the readings are taken only for one.
    pub process_at_capture: Option<ProcessMemory>,
    /// The process's memory when the write transaction was open and its
    /// rows about to be written, as [`Self::overlay_at_hand_off`].
    pub process_at_hand_off: Option<ProcessMemory>,
    /// The process's memory when the commit had returned, before the
    /// captured layers were retired or anything of the flush was freed,
    /// heap mappings included.
    pub process_at_commit: Option<ProcessMemory>,
    /// The process's memory when the thread that ended the flush before
    /// this one had told the participant: after `finished` had returned,
    /// or at the point where it is called for a flush the participant had
    /// no part in, and before the flush's references to its captured
    /// layers were dropped.  Taken whether or not that flush committed
    /// anything, as the next is.
    pub process_after_previous_finished: Option<ProcessMemory>,
    /// The process's memory at the end of the flush before this one:
    /// after that thread had dropped those references too, when it made
    /// the commit on a thread of its own.  A flush that committed on the
    /// capturing thread hands them to that thread's caller instead, which
    /// drops them after this reading, so the frees of its layers are not
    /// in it: a commit and [`Database::flush`] once they have released
    /// the writer semaphore, [`Database::close`] under it.
    pub process_after_previous: Option<ProcessMemory>,
    /// What that thread spent between the retirement of the flush before
    /// this one and the return of the participant's `finished`.
    pub previous_finished: std::time::Duration,
    /// What it spent between that retirement and the flush's end: the
    /// participant's `finished` and, for a commit made on a thread of its
    /// own, the frees of whatever captured layers no transaction still
    /// held (see [`Self::process_after_previous`]).  For such a commit
    /// this is part of what the next capture waits for
    /// ([`FlushObservation::waited`]).
    pub previous_release: std::time::Duration,
}

impl FlushMemory {
    /// Render the layer counts as one JSON object.
    pub fn layers_json(&self) -> String {
        format!(
            "{{\"pinned\":{},\"entries\":{},\"at_retire\":{},\"shared\":{},\"shared_entries\":{}}}",
            self.pinned_layers,
            self.pinned_entries,
            self.layers_at_retirement,
            self.shared_layers,
            self.shared_entries,
        )
    }

    /// Render the overlay's byte counts as one JSON object.
    pub fn overlay_json(&self) -> String {
        format!(
            "{{\"handoff\":{},\"retire\":{}}}",
            self.overlay_at_hand_off, self.overlay_at_retirement,
        )
    }

    /// Render the readings of the process's memory as one JSON object,
    /// `null` for one that was not taken.
    pub fn process_json(&self) -> String {
        let reading =
            |m: &Option<ProcessMemory>| m.map_or_else(|| "null".to_string(), |m| m.to_json());
        format!(
            "{{\"capture\":{},\"handoff\":{},\"commit\":{},\"prev_finished\":{},\
             \"prev_end\":{},\"prev_finished_ms\":{:.3},\"prev_release_ms\":{:.3}}}",
            reading(&self.process_at_capture),
            reading(&self.process_at_hand_off),
            reading(&self.process_at_commit),
            reading(&self.process_after_previous_finished),
            reading(&self.process_after_previous),
            self.previous_finished.as_secs_f64() * 1000.0,
            self.previous_release.as_secs_f64() * 1000.0,
        )
    }
}

/// One phase of a metadata flush, in a [`FlushObservation`].
///
/// A flush window holds three phases in a row, and a stall inside it
/// points at a different cause in each: the block-file fsync, the insert
/// loop (reads of leaves redb has not cached, at a queue depth of one),
/// and the commit (page writes and their fsync).  Wall time alone cannot
/// say which one a thread blocked in page I/O was waiting in, and a
/// wait-channel sampler cannot either: reads and writeback wait in the
/// same kernel function.  The per-phase time and `read_bytes` can: a
/// slow phase with large `read_bytes` was waiting on reads.  Writeback
/// shows only as a phase's time, because `write_bytes` cannot see it
/// (see its note).  The processor times say how much of a phase the
/// thread was working rather than waiting at all: `on_cpu_ns` is its
/// time on a processor, which `utime_ms` and `stime_ms` divide between
/// its own code and the kernel's, and what `elapsed` holds beyond that
/// and `runq_wait_ns` it spent asleep.
///
/// Every counter of a phase is read on the thread that ran the phase, at
/// its start and its end, and "the flushing thread" below is that
/// thread.  For a flush whose rows and commit were written on a thread of
/// its own ([`FlushObservation::background`]) the figures of the
/// block-file sync, the insert loop, the participant's `contribute` and
/// the commit are that thread's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FlushPhase {
    /// Wall time the phase took.
    pub elapsed: std::time::Duration,
    /// Bytes the flushing thread caused to be read from storage in the
    /// phase: `read_bytes` in Linux's `/proc/thread-self/io`, which counts
    /// only reads that reached the block layer, so page-cache hits cost
    /// nothing here.  `None` off Linux, on a kernel without task I/O
    /// accounting, and when no observer is attached (the counters are
    /// read only for one).
    pub read_bytes: Option<u64>,
    /// Likewise `write_bytes`: bytes the thread caused to be written to
    /// storage, counted when it dirtied the page rather than when the
    /// page was written back, so time spent waiting on writeback shows
    /// in `elapsed` and not here.  The block-file sync phase therefore
    /// reads about 0 however much it flushes: its pages were dirtied when
    /// the blocks were written, before the flush began.  The commit's
    /// figure is what redb's page writes dirtied, not what reached disk.
    pub write_bytes: Option<u64>,
    /// Milliseconds the flushing thread ran in user mode in the phase:
    /// `utime` in Linux's `/proc/thread-self/stat`, which counts in clock
    /// ticks of 10 ms, so this is a multiple of 10 and a short phase
    /// often reads 0.  `None` off Linux and when no observer is attached.
    pub utime_ms: Option<u64>,
    /// Likewise `stime`: milliseconds the thread ran in the kernel, in
    /// its system calls and page faults.
    pub stime_ms: Option<u64>,
    /// Nanoseconds the flushing thread spent on a processor in the phase,
    /// in either mode: the first field of Linux's
    /// `/proc/thread-self/schedstat`.  On most architectures, x86 and ARM
    /// among them, the kernel reports `utime` and `stime` as a division
    /// of this figure, so their sum follows it to within their ticks.
    /// `None` off Linux, on a kernel without the file, and when no
    /// observer is attached; 0 on a kernel that has the file but keeps no
    /// scheduler accounting.
    ///
    /// The kernel brings the figure up to date at a scheduler tick or a
    /// context switch and not when it is read, so it can be off by a tick
    /// at either end of the phase, and a short phase can read more than
    /// its `elapsed`.
    pub on_cpu_ns: Option<u64>,
    /// Likewise the second field: nanoseconds the thread was runnable
    /// but waiting for a processor.  What is left of `elapsed` after this
    /// and `on_cpu_ns` the thread spent asleep: waiting for storage (a
    /// read, an fsync, writeback) or for a lock.
    pub runq_wait_ns: Option<u64>,
}

impl FlushPhase {
    /// Render as one JSON object, `null` for a missing counter.
    pub fn to_json(&self) -> String {
        let count = |v: Option<u64>| v.map_or_else(|| "null".to_string(), |v| v.to_string());
        format!(
            concat!(
                "{{\"ms\":{:.3},\"read_bytes\":{},\"write_bytes\":{},",
                "\"utime_ms\":{},\"stime_ms\":{},\"on_cpu_ns\":{},\"runq_wait_ns\":{}}}"
            ),
            self.elapsed.as_secs_f64() * 1000.0,
            count(self.read_bytes),
            count(self.write_bytes),
            count(self.utime_ms),
            count(self.stime_ms),
            count(self.on_cpu_ns),
            count(self.runq_wait_ns),
        )
    }
}

/// A callback invoked after each metadata flush.
///
/// Called with the cache lock held, so it must not block or re-enter the
/// database; append to a buffer and analyse later.  It is called on the
/// thread that made the flush's commit: the flushing thread, or the
/// thread named [`COMMIT_THREAD_NAME`] for a flush that handed its
/// commit over ([`Options::background_commit`]), in which case the
/// thread that tripped the flush may be many commits further on.
pub type FlushObserver = Arc<dyn Fn(&FlushObservation) + Send + Sync>;

/// A callback invoked once per key/value the engine is handed, in the
/// order it is handed them, with `None` for a delete.
///
/// Called inside the flush's redb write transaction, on the thread that
/// writes the flush's rows, WITHOUT the cache lock (`DbCache::fill` runs
/// unlocked so readers are not held for the flush): the flushing thread,
/// with the writer semaphore held, or for a flush handed to a thread of
/// its own ([`Options::background_commit`]) that thread, without it.  So
/// it must not block or re-enter the database. It exists to
/// capture the engine-level write sequence for ADR-0009's candidate
/// engine benchmark: the order the storage engine actually sees is
/// neither block order nor the sorted contents of the finished store,
/// and picking either would decide that benchmark by itself.
pub type WriteLogSink = Arc<dyn Fn(&[u8], Option<&[u8]>) + Send + Sync>;

/// The level of a line handed to a [`LogSink`] (the `slog` levels
/// dcrd's ffldb driver logs at).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// dcrd `log.Tracef`.
    Trace,
    /// dcrd `log.Debugf`.
    Debug,
    /// dcrd `log.Infof`.
    Info,
    /// dcrd `log.Warnf`.
    Warn,
    /// dcrd `log.Errorf`.
    Error,
}

/// The driver's package log sink (dcrd ffldb's package-level `log`,
/// which the daemon points at its `BCDB` logger through
/// `database.UseLogger`, dcrd `log.go`).
///
/// `None` in [`Options::log`] is ffldb's disabled default: nothing is
/// logged.  Called on whichever thread is opening, committing or
/// rolling back, sometimes with the block-store lock held, so it must
/// not block or re-enter the database.
pub type LogSink = Arc<dyn Fn(LogLevel, &str) + Send + Sync>;

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
    /// (redb-4.3.0 `cached_file.rs:348-353`) and a miss that would carry
    /// the total past the limit evicts a page's worth before returning
    /// (`:724-746`), so a small database never pays for a large setting
    /// and the resident cost is bounded by the file size.
    ///
    /// redb 4.3.0 keeps one cache figure and partitions it dynamically
    /// (`db.rs:2153-2156`, `cached_file.rs:285-300`): the write buffer
    /// is held at or below 50% of it, flushing the excess to disk best
    /// effort (`:897-932`), and the read cache may grow to 100% when no
    /// write is in flight. Once a commit's dirty set exceeds the write buffer,
    /// redb writes the spilled pages, re-reads them to finalize
    /// checksums, then writes the buffer again — measured against the
    /// mainnet metadata store on redb 2.6.3, whose `set_cache_size` cut
    /// the figure 90/10 into read cache and write buffer with no
    /// separate setter (redb-2.6.3 `db.rs:1186-1187`): at its 1 GiB
    /// default, 62,323 dirty pages cost 124,430 pwrites and 98,221
    /// preads, against 62,323 and 4 with the buffer large enough to hold
    /// them. The mechanism survives the upgrade; the counts were taken
    /// at a write buffer five times smaller than 4.3.0 permits.
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
    ///
    /// The default is 300 MiB (dcrd's is 100 MiB): a UTXO cache flush
    /// that only its size limit tripped leaves its rows here instead of
    /// forcing a flush, so this ceiling is the most a durable commit
    /// waits for.  [`Self::cache_flush_interval_secs`], or a flush
    /// participant that asks for a flush, can end the wait sooner.
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
    /// Where the driver's log lines go, when set (see [`LogSink`]): the
    /// unclean-shutdown repair on open, the `ROLLBACK` warnings, and the
    /// progress of a redb repair of the metadata store.
    pub log: Option<LogSink>,
    /// Whether a flush that a commit's own check trips, or that
    /// [`Database::flush_in_background`] asks for, hands the sync of the
    /// block files, the writing of its rows and its redb commit to a
    /// thread of its own, so that its caller returns once the write cache
    /// is captured, what the block-file sync owes is taken, redb's write
    /// transaction is open and a [`FlushParticipant`] with work has sealed
    /// it.  The block files are still synced before the redb commit, on
    /// that thread, and a block written meanwhile is left owed to the next
    /// flush's sync.
    ///
    /// `false` by default, in which case every flush writes and commits
    /// on the thread that ran it, under the writer semaphore, as dcrd's
    /// does.
    ///
    /// When set, the redb commit is still `Durability::Immediate`, its
    /// rows go into the transaction in the same order, and at most one
    /// flush is under way: the next flush, and any commit that finds the
    /// overlay over [`Self::cache_max_size`] meanwhile, waits for it.
    /// [`Database::flush`] and [`Database::close`] wait for it too and
    /// then write and commit on their own thread, so what they
    /// acknowledge is durable as before.  What changes is who is told of a
    /// failure in writing the rows or committing them: the commit that
    /// tripped the flush, and those made while the flush ran, have
    /// returned `Ok` by then and are lost with it at the next start; the
    /// store latches, and the next write, flush or close reports it
    /// ([`Database::is_fatal_settled`]).  A flush in which a
    /// [`FlushParticipant`] has work is handed over only if the
    /// participant allows its `contribute` and `finished` to be deferred
    /// ([`FlushParticipant::allows_deferred_contribute`]).
    ///
    /// The thread is the store's own, named [`COMMIT_THREAD_NAME`]: started
    /// by the first flush handed over, kept asleep between flushes, and
    /// stopped by [`Database::close`] or by the drop of the last handle.  A
    /// store that never hands a flush over, the option set or not, starts
    /// none.  A thread the operating system refuses is asked for again at
    /// the next hand-off, the flush writing and committing on its own
    /// thread meanwhile.
    pub background_commit: bool,
    /// Whether a commit handed to a thread of its own
    /// ([`Self::background_commit`]) is made with a read snapshot of the
    /// store held across it.  `true` by default, and without effect
    /// unless `background_commit` is set.
    ///
    /// A commit made on the committing thread always has one: the
    /// transaction that tripped the flush is still open there, with the
    /// snapshot it began with.  A handed-over commit lands after that
    /// transaction has ended, and with no reader open redb takes another
    /// path.  It frees the pages the commit replaced at once, in a second
    /// commit that is not synced and whose pages it keeps in its write
    /// buffer (redb-4.3.0 `transactions.rs:2207-2288`,
    /// `page_manager.rs:1880-1894`).  From then until the next durable
    /// commit has emptied that buffer, a read that misses redb's page
    /// cache while the cache is full makes room by writing a buffered
    /// page to the file (`cached_file.rs:698-712`), and the buffer by
    /// then holds the pages of the next flush's write transaction: each
    /// is written when it is evicted, read back when its commit needs it
    /// and written again.  The snapshot keeps a handed-over commit on the
    /// path every other commit takes, in which the pages a commit
    /// replaced are freed by the commit after it.
    ///
    /// It delays nothing a commit on the committing thread does not
    /// delay, and changes no result.
    pub commit_snapshot: bool,
    /// Called on the thread that commits a flush, once the flush's rows
    /// and its participant's are in redb's write transaction and before
    /// the transaction's commit, when set.
    ///
    /// `None` in [`Options::new`] and in the daemon.  For tests that must
    /// tell the writes redb makes ahead of a commit, while the rows go in,
    /// from the commit's own, now that both are made on the thread a
    /// handed-over flush runs on.  It must not block or re-enter the
    /// database.
    #[doc(hidden)]
    pub before_commit: Option<Arc<dyn Fn() + Send + Sync>>,
}

/// Storage shared between the caller and redb, so a test can keep a
/// handle on the backend it installed (to fail it, or to drop its
/// unsynced writes) while redb owns its own.
pub type SharedBackend = Arc<dyn redb::StorageBackend>;

/// The trait a [`SharedBackend`] implements, re-exported so a crate that
/// installs one -- a test in a crate above this one, failing reads under
/// the chain -- does not need a `redb` dependency of its own.
pub use redb::StorageBackend;

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
/// leave it where it is. Over full mainnet replays on m1 an 8192 MiB
/// cache measured 50% slower (5125-6294 s against 3866-3888 s) and 256
/// and 512 MiB overlapped their own baseline: the 2026-08-10 and
/// 2026-08-11 sweeps in `docs/bench-ledger.md`, both before ADR-0010's
/// block keys and ADR-0011's index layout, and not measured again since.
///
/// The table below is the superseded 2026-07 microbenchmark those
/// replays reversed: 2,000,000 scattered writes against the mainnet
/// metadata store (14.48 GiB).
///
/// | cache | 250k per commit | 2M per commit |
/// |---|---|---|
/// | 1 GiB | 78.6 s | 43.0 s |
/// | 4 GiB | 51.4 s | 19.6 s |
/// | 8 GiB | 48.7 s | 16.1 s |
///
/// Its multiplicative reading — 1.8x from batching alone, 2.7x from
/// cache alone, 4.9x together — is withdrawn. Only the flush-cadence
/// half survived those replays, at 11-12% on m1, in reach of dcrd's own
/// `--utxocachemaxsize`; one sync on m3 on 2026-10-10 gained 3.7% from it.
pub const DEFAULT_DB_CACHE_BYTES: usize = 1024 * 1024 * 1024;

/// The first cause a store is latched with when its commit thread
/// panicked, in a build whose panics unwind.
const COMMIT_THREAD_PANICKED: &str = "the background commit thread panicked";

/// Wait for the flush in flight, if there is one, to end: its commit to
/// return, [`finish`] to retire its layers or latch the store, and the
/// commit thread to let go of the store, which the flush's ticket is
/// signalled after ([`JobEnd`]).  The thread itself goes on, asleep until
/// the next flush is handed to it.
///
/// The caller holds the writer semaphore and no other lock of this crate.
/// The commit thread takes the cache lock and may call the participant,
/// so a caller holding either would deadlock with it; it never takes the
/// semaphore.  With [`Options::background_commit`] off nothing is ever in
/// flight and this finds the slot empty.
///
/// A ticket dropped unsent is a commit thread that panicked, which did
/// not finish its flush.  Release builds abort on a panic; where one
/// unwinds instead, the store is latched here, as for any flush that did
/// not end in a commit.
fn drain_flight(inner: &DbInner) {
    let ticket = inner.flight.lock().expect("flight slot poisoned").take();
    let Some(ticket) = ticket else {
        return;
    };
    let started = std::time::Instant::now();
    let ended = ticket.recv();
    let nanos = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    inner.waited_nanos.fetch_add(nanos, Ordering::Relaxed);
    if ended.is_err() {
        inner.mark_fatal(db_error(ErrorKind::DriverSpecific, COMMIT_THREAD_PANICKED));
    }
}

/// Who asked for a flush, which decides whether it is made at all and
/// whether its rows and commit may leave the thread that captures it
/// ([`flush_locked`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlushKind {
    /// A commit's own flush check (dcrd `commitTx`, which flushes only
    /// when `needsFlush` says so): made only when the overlay's
    /// thresholds or a participant's `wants_flush` ask for it, and handed
    /// over with background commits.
    Commit,
    /// [`Database::flush`] and [`Database::close`]: made whatever the
    /// thresholds say, and committed on the calling thread, which is told
    /// `Ok` only once the commit is durable.
    Durable,
    /// [`Database::flush_in_background`]: made whatever the thresholds
    /// say, and handed over with background commits as a commit's own
    /// flush is.
    Requested,
}

/// Run one flush with the cache lock released across the commit.
///
/// The caller must already hold the writer semaphore, which is what
/// serialises flushes against each other; the cache lock only has to be
/// held for the capture and the retirement. Holding it across the commit
/// as well — which is what this code used to do — blocks every reader in
/// the process for the commit's fsync. The median flush took 26.9 s in
/// m1's sync of 2026-08-16 (about 1.3 s on m3 in 2026-10).
///
/// [`FlushKind::Commit`] is the commit path's flush (dcrd `commitTx`,
/// which flushes only when `needsFlush` says so): the thresholds are
/// checked under the same lock hold as the capture.  `Database::flush`,
/// `Database::close` ([`FlushKind::Durable`]) and
/// `Database::flush_in_background` ([`FlushKind::Requested`]) flush
/// unconditionally.
///
/// **Synchronous to durability for `Database::flush` and
/// `Database::close`.**  A flush that either asked for returns only once
/// the data is on disk, because they are the chain's durability barrier
/// and the daemon's shutdown path.  So does every flush of a database
/// opened without [`Options::background_commit`].  With it, a flush on the
/// commit path, or one `Database::flush_in_background` asked for, stops
/// being synchronous once its write transaction is open: the capture, the
/// taking of what the block-file sync owes, the opening of the transaction
/// and the participant's `seal` run here, under the caller's semaphore,
/// and the rest is handed to the store's commit thread ([`hand_off`]),
/// which syncs the block files, writes the overlay's rows and the
/// participant's into the transaction, makes the redb commit, retires the
/// layers and calls `finished` when it lands.  The rows go in in the same
/// order on either thread, and the block files are synced before the
/// redb commit on either.  The caller is then told `Ok` with
/// nothing of that batch acknowledged as durable; no caller of a commit is
/// promised durability, and the caller of `Database::flush_in_background`
/// learns of it from [`Database::is_durable`].  A participant with work
/// must allow its `contribute` and `finished` to be deferred
/// ([`FlushParticipant::allows_deferred_contribute`]), or the whole flush
/// stays here.
///
/// **One flush at a time.**  A flush is in flight from its capture to its
/// retirement, and nothing is captured while one is: every capture is
/// made here, after [`drain_flight`] has waited for the flush before it
/// to end, and that is the only wait a capture depends on.  Should a
/// capture find a flush in flight all the same, the store is latched and
/// nothing is captured.  The latch is looked at on the way in and again
/// after the wait, because the flush waited for may be the one that
/// failed.  The same wait bounds the overlay: a commit that finds it over
/// its maximum with a flush in flight waits for that flush and adds
/// nothing until its layers are retired.
///
/// A failure latches the store in [`finish`].  For a flush that fails
/// here that is while the caller still holds the writer semaphore:
/// releasing it first wakes the next queued writer unlatched, to re-run
/// the failed flush (see [`DbInner::mark_fatal`]).  A flush that fails on
/// its own thread, in its rows, the participant's or the commit, latches
/// the store there, and whoever next reaches one of the latch checks,
/// here or at the start of a write, is refused.  Every flush goes through
/// this one helper so that ordering cannot drift between copies.
///
/// A registered [`FlushParticipant`] is driven from here too (ADR-0011).
/// On the commit path its `wants_flush` can trip a flush the overlay's
/// thresholds would not.  `DbCache::open` asks `has_work` after the
/// capture and, with work, calls `seal` once the write transaction is
/// open, both here; `DbCache::fill` calls `contribute`
/// within the transaction, after the overlay's rows, on the thread that
/// commits.  After the retirement, or after a failure has latched the
/// store, [`finish`] calls `finished` with the outcome, for every flush
/// that sealed: under the caller's semaphore for a flush that commits
/// here, and on the commit thread otherwise.
///
/// Returns the overlay layers the flush retired, none when it did not
/// flush or handed its commit to a thread of its own, which retires them
/// and lets go of them itself, holding no semaphore.  Dropping them frees
/// every row the flush wrote, unless a transaction begun before the
/// flush still reads them.  A commit and [`Database::flush`] drop them
/// once they have released the semaphore, so that the next writer does
/// not wait for the frees; [`Database::close`] drops them where it
/// flushed, since no transaction begins behind a close.
pub(crate) fn flush_locked(
    inner: &Arc<DbInner>,
    kind: FlushKind,
) -> Result<crate::dbcache::RetiredLayers, Error> {
    // Nothing is captured, and no block file synced, on a latched store.
    inner.check_writable()?;
    // One clone for the whole flush: registration changes only under the
    // writer semaphore, after a wait for the flush in flight, so this is
    // the participant the flush runs with from capture to `finished`.
    let registered = inner.registered();
    // Asked before the cache lock is taken, so a participant's own locks
    // never nest inside it.  Only an `on_commit` hook adds to a
    // participant's work, and hooks run under the semaphore this caller
    // holds, so the answer cannot rise between here and the capture.
    let wanted = kind == FlushKind::Commit
        && registered
            .as_ref()
            .is_some_and(|r| r.participant.wants_flush());
    // The answer of nearly every commit: nothing to flush and nothing to
    // wait for.
    if kind == FlushKind::Commit {
        let cache = inner.cache.lock().expect("cache lock poisoned");
        if !cache.needs_flush() && !wanted && !cache.over_ceiling() {
            return Ok(Vec::new());
        }
    }
    // The flush before this one has to be over before anything is
    // captured, and a commit that found the overlay over its ceiling
    // adds nothing until the layers in flight are retired.  The caller
    // waits with the semaphore held, so every other writer queues behind
    // it.
    #[cfg(test)]
    let waits = !inner.skip_drain.load(Ordering::SeqCst);
    #[cfg(not(test))]
    let waits = true;
    if waits {
        drain_flight(inner);
    }
    // The flush waited for may have failed.
    inner.check_writable()?;
    let mut batch = {
        let mut cache = inner.cache.lock().expect("cache lock poisoned");
        if kind == FlushKind::Commit && !cache.needs_flush() && !wanted {
            // The ceiling alone brought this commit here, and the wait
            // was all it asked for.
            return Ok(Vec::new());
        }
        if cache.in_flight() {
            drop(cache);
            return Err(inner.mark_fatal(db_error(
                ErrorKind::DriverSpecific,
                "a flush was captured while another was in flight",
            )));
        }
        cache.begin_flush()
    };
    #[cfg(test)]
    {
        batch.on_drop = crate::dbcache::DropProbe(
            inner
                .batch_dropped
                .lock()
                .expect("test hook poisoned")
                .clone(),
        );
    }
    // Final for this flush already: a wait ends when the semaphore is
    // taken, and the caller holds it until the capture is handed on.
    batch.writer_waits = inner.writer_waits();
    batch.explicit = kind == FlushKind::Durable;
    batch.waited = std::time::Duration::from_nanos(inner.waited_nanos.swap(0, Ordering::Relaxed));
    if batch.observed() {
        batch.memory.process_at_capture = ProcessMemory::read(true);
        if let Some(end) = inner.flush_end.lock().expect("flush end poisoned").take() {
            batch.memory.process_after_previous_finished = end.told;
            batch.memory.process_after_previous = end.memory;
            batch.memory.previous_finished = end.telling;
            batch.memory.previous_release = end.release;
        }
    }
    // What the block sync owes is taken here, under the semaphore,
    // after the capture, so it covers every block the captured metadata
    // names.  A flush that may leave this thread leaves running it to the
    // thread that commits (`DbCache::fill`), which syncs before it
    // writes a row and so before its redb commit: block files before
    // metadata, wherever the commit is made.  Blocks written meanwhile
    // keep their files owed to the next flush's sync.  Any other flush
    // syncs here before the transaction is opened, as it always has.  The
    // transaction is opened and the participant sealed on this thread
    // either way: no commit hook runs between the capture and the seal,
    // so what the participant sets apart is exactly what the captured
    // commits handed it.
    //
    // The store's redb handle opens the transaction.  A clean close lets
    // go of it only once its own flush has committed, and no writer
    // begins behind a close, so a flush that finds it gone has nothing to
    // write: it is a `Database::flush` that lost the writer to the close
    // (see the comment there), and it ends empty.
    let kv = inner.kv_handle();
    let may_hand_off = inner.background && kind != FlushKind::Durable;
    let opened = if may_hand_off {
        let plan = DbCache::plan_block_sync(&inner.block_store);
        DbCache::open(
            &batch,
            kv.as_deref(),
            registered.as_ref(),
            crate::FlushPhase::default(),
        )
        .map(|opened| (opened, Some(plan)))
    } else {
        DbCache::sync_blocks(&batch, &inner.block_store)
            .and_then(|block_sync| {
                DbCache::open(&batch, kv.as_deref(), registered.as_ref(), block_sync)
            })
            .map(|opened| (opened, None))
    };
    let job = match opened {
        Ok((Opened::Tx(mut job), plan)) => {
            if let Some(plan) = plan {
                job.defer_block_sync(plan);
            }
            job
        }
        // Nothing to commit: a sync left for the commit is run here.
        Ok((Opened::Empty(outcome), plan)) => {
            let outcome = match plan {
                Some(plan) => DbCache::run_block_sync(batch.observed(), plan, &inner.block_store)
                    .map(|block_sync| outcome.with_block_sync(block_sync)),
                None => Ok(outcome),
            };
            return finish(inner, batch, outcome, registered.as_ref(), false, false);
        }
        // A failure before the hand-off fails the caller, as it always
        // has: the commit that tripped the flush is unapplied and rolls
        // its block files back.  Nothing was sealed, so the participant
        // is owed nothing, and a sync left for the commit is dropped
        // unrun, its files still owed.
        Err(e) => {
            return finish(inner, batch, Err(e), registered.as_ref(), false, false);
        }
    };
    let sealed = job.sealed();
    // A commit's own flush is handed over, and so is one
    // `Database::flush_in_background` asked for.  `Database::flush` and
    // `Database::close` acknowledge durability, so theirs writes and
    // commits here.  So does one in which a participant has work without
    // allowing its `contribute` and `finished` to be deferred.
    let deferred = inner.background
        && kind != FlushKind::Durable
        && (!sealed
            || registered
                .as_ref()
                .is_some_and(|r| r.participant.allows_deferred_contribute()));
    if batch.observed() {
        batch.memory.overlay_at_hand_off = inner
            .cache
            .lock()
            .expect("cache lock poisoned")
            .overlay_bytes();
        batch.memory.process_at_hand_off = ProcessMemory::read(false);
    }
    // A commit made here has the caller's transaction open across it, or
    // was asked for with none; one that leaves this thread would land
    // with no reader open, and is given one ([`Options::commit_snapshot`]).
    // It is taken before the rows are written, which changes nothing it
    // sees: this flush holds redb's write transaction, so no commit lands
    // in between.  A snapshot that cannot be had is done without: the
    // commit then fails or lands as it would have.
    let snapshot = (deferred && inner.commit_snapshot)
        .then(|| kv.as_ref().and_then(|kv| kv.begin_read().ok()))
        .flatten();
    batch.snapshot = snapshot.is_some();
    let mut flight = Flight {
        job,
        batch,
        registered,
        sealed,
        snapshot,
    };
    if deferred {
        match hand_off(inner, flight) {
            // The commit thread writes the rows, commits, retires the
            // layers and lets go of them.
            HandOff::Taken => return Ok(Vec::new()),
            // No thread was to be had: the same transaction is written
            // and committed here.
            HandOff::Inline(refused) => flight = refused,
            // The commit thread had died: the store is latched and the
            // flight ended here as a failure.
            HandOff::Ended(ended) => return ended,
        }
    }
    let Flight {
        job,
        batch,
        registered,
        sealed,
        snapshot,
    } = flight;
    let result = write_and_commit(inner, &batch, job, registered.as_ref());
    drop(snapshot);
    finish(inner, batch, result, registered.as_ref(), sealed, false)
}

/// The part of a flush that may leave the capturing thread: run the block
/// sync the capture left to it, if any, write the overlay's rows and the
/// participant's into the open transaction ([`DbCache::fill`]), then make
/// redb's durable commit ([`DbCache::commit`]), all on the calling
/// thread.
fn write_and_commit(
    inner: &DbInner,
    batch: &FlushBatch,
    job: FillJob,
    registered: Option<&participant::Registration>,
) -> Result<FlushOutcome, Error> {
    #[cfg(test)]
    {
        let hook = inner.before_fill.lock().expect("test hook poisoned").take();
        if let Some(hook) = hook {
            hook();
        }
    }
    let job = DbCache::fill(batch, job, registered, &inner.block_store)?;
    if let Some(probe) = &inner.before_commit {
        probe();
    }
    DbCache::commit(job)
}

/// A flush from its open write transaction on: what the capturing thread
/// hands the thread that writes its rows and commits it.
struct Flight {
    job: FillJob,
    batch: FlushBatch,
    /// The participant registered when the flush was captured.
    registered: Option<participant::Registration>,
    /// Whether its `seal` was called, and `finished` is owed.
    sealed: bool,
    /// A read snapshot of the store taken before the hand-off, to be held
    /// until the commit has returned ([`Options::commit_snapshot`]).
    snapshot: Option<redb::ReadTransaction>,
}

/// A store's commit thread, named [`COMMIT_THREAD_NAME`]
/// ([`DbInner::committer`]): one for the open store, so that the memory
/// the rows and the commit of every flush handed over allocate is
/// allocated by one thread.
///
/// A flush's rows and its redb commit allocate most of what redb then
/// keeps in its page cache, long after the flush.  With glibc's allocator
/// a thread takes an arena at its first allocation and keeps it, a
/// starting thread is given the arena that an exited thread last left,
/// and the memory freed into an arena is reused only by the threads that
/// hold it.  A thread started for each flush could therefore land in a
/// different arena from one flush to the next, leaving what the earlier
/// ones allocated, and the holes their frees left, where no later flush
/// reuses them.  One thread kept for the store allocates the rows and
/// commit of every flush handed over from the one arena, and while glibc
/// has arenas to give, that arena goes to no thread started later while
/// the store is open.  Past its limit (`MALLOC_ARENA_MAX`, or eight per
/// processor on a 64-bit system) glibc shares arenas among threads, this
/// one's included, which shares the arena but does not move this thread
/// out of it.
///
/// Only this thread is the store's.  The threads that write to the store
/// and capture its flushes, which allocate the write cache's layers and
/// the pages their reads bring into redb's cache, are the caller's, and
/// live as long as the caller keeps them.
///
/// Dropped with the store, which stops a running thread
/// ([`Running::stop`]): no thread outlives the store, and the drop of the
/// last handle ends it as the close does.
struct CommitThread {
    state: CommitState,
}

/// Where a store's commit thread is in its life.
enum CommitState {
    /// No flush has been handed over yet, or the last start was refused:
    /// the next hand-off tries to start the thread.
    NotStarted,
    /// Started by a hand-off, and asleep in `recv` between flushes.
    Running(Running),
    /// Stopped by the close, or found dead by a hand-off, which latched
    /// the store: a hand-off now writes and commits on the calling
    /// thread, and no second thread is started.
    Stopped,
}

/// A started commit thread, and how to reach it.
struct Running {
    /// Where a hand-off puts its flush: a channel of one slot, made with
    /// the thread, so that a hand-off allocates nothing for it.
    jobs: mpsc::SyncSender<Job>,
    handle: std::thread::JoinHandle<()>,
    /// The thread's id, which tells the store's drop on that thread from
    /// a drop on another.
    id: std::thread::ThreadId,
    /// How the thread ended, once it has.
    #[cfg(test)]
    end: Arc<ThreadEnd>,
}

impl Running {
    /// Stop the thread: let go of its channel, which wakes it from its
    /// `recv` with nothing to do, so that it ends, and join it.
    ///
    /// When the store is dropped on its own commit thread, at the end of
    /// a flush whose hold on it was the last, the thread cannot wait for
    /// itself: it is let go instead, and ends at its next `recv`.  On any
    /// other thread the join waits for no flush: a flush handed over holds
    /// the store until it has ended ([`Job`]), so the store can be closed
    /// or dropped elsewhere only while the thread is asleep, or between
    /// letting go of the store and its next `recv`, where the ticket's
    /// send cannot block (its channel has one slot and one message).  A
    /// join that finds the thread panicked is not reported here: the wait
    /// for the flight it panicked in has latched the store already, and a
    /// panic between flights, which only the loop's own code could raise,
    /// latches it at the next hand-off, if one comes.
    fn stop(self) {
        let Running {
            jobs, handle, id, ..
        } = self;
        drop(jobs);
        if std::thread::current().id() == id {
            drop(handle);
        } else {
            let _ = handle.join();
        }
    }
}

impl Drop for CommitThread {
    fn drop(&mut self) {
        if let CommitState::Running(running) =
            std::mem::replace(&mut self.state, CommitState::Stopped)
        {
            running.stop();
        }
    }
}

/// Stop the store's commit thread, if it is running, and leave its slot
/// [`CommitState::Stopped`]: for [`Database::close`], with the writer
/// semaphore held and after [`drain_flight`], so the thread is asleep.
fn stop_commit_thread(inner: &DbInner) {
    let state = std::mem::replace(
        &mut inner
            .committer
            .lock()
            .expect("commit thread slot poisoned")
            .state,
        CommitState::Stopped,
    );
    if let CommitState::Running(running) = state {
        running.stop();
    }
}

/// A flush handed to the commit thread.
struct Job {
    /// The store, held for the flush's length only: a handle dropped
    /// meanwhile does not close the store under the commit.
    inner: Arc<DbInner>,
    flight: Flight,
    /// The flush's ticket, signalled once the flush has ended and `inner`
    /// has been let go of ([`JobEnd`]).
    done: mpsc::SyncSender<()>,
}

impl Job {
    /// The flight, back for the capturing thread to write and commit:
    /// the job's hold on the store and its ticket are let go of, and the
    /// batch is marked as never handed over.
    fn take_back(self) -> Flight {
        let Job { mut flight, .. } = self;
        flight.batch.take_back();
        flight
    }
}

/// What became of a flush offered to the commit thread ([`hand_off`]).
#[allow(
    clippy::large_enum_variant,
    reason = "returned once a flush and taken apart at once; boxing the flight would \
              allocate on the path taken when the system has no thread to give"
)]
enum HandOff {
    /// The commit thread has it.
    Taken,
    /// No thread was to be had: the caller writes and commits it.
    Inline(Flight),
    /// It was ended here as a failure, with the store latched, and
    /// nothing of it committed: what [`finish`] returned for it, for
    /// [`flush_locked`] to return.
    Ended(Result<crate::dbcache::RetiredLayers, Error>),
}

/// Hand `flight` to the store's commit thread, starting the thread if no
/// flush has been handed to it yet, and record the flight's ticket as
/// the flush in flight.
///
/// When the operating system has no thread to give, the flight is
/// returned for the caller to write and commit itself, so a refused
/// thread loses no flush, and the next hand-off tries again.  So it is
/// after the close has stopped the thread, which no flush reaches through
/// the public calls: a flush after the close finds the overlay empty and
/// no participant, and hands nothing over.
///
/// The thread is never waited for here.  The channel holds one flush, and
/// a flush is put in it without blocking: the flush before was taken out
/// of it before its ticket was signalled, and the caller has waited for
/// that ticket.  A channel found full all the same latches the store, as
/// a capture that finds a flush in flight does, and ends the flight here
/// as a failure ([`fail_flight`]); a build with debug assertions then
/// panics, with the store already latched and no lock of the hand-off
/// held.  No test reaches that arm.  One found with no thread
/// behind it is a thread that panicked between flights, in a build whose
/// panics unwind; one that panicked inside a flight had its ticket
/// dropped, and the wait for it latched the store before the capture.
/// The store is latched, the dead thread joined and no other started, and
/// the flight is ended here as a failure ([`fail_flight`]), so the commit
/// that tripped it fails and rolls its block files back.
///
/// The caller holds the writer semaphore and has just waited out the
/// flight before this one ([`drain_flight`]), so the slot is empty.
fn hand_off(inner: &Arc<DbInner>, mut flight: Flight) -> HandOff {
    flight.batch.hand_off();
    // Made for each flush: a pair of one slot, signalled once.
    let (done, ticket) = mpsc::sync_channel(1);
    let job = Job {
        inner: Arc::clone(inner),
        flight,
        done,
    };
    let mut committer = inner.committer.lock().expect("commit thread slot poisoned");
    if matches!(committer.state, CommitState::NotStarted) {
        #[cfg(test)]
        let refused = inner.refuse_commit_thread.load(Ordering::SeqCst);
        #[cfg(not(test))]
        let refused = false;
        let started = if refused {
            Err(std::io::Error::other("no thread, by a test's request"))
        } else {
            start_commit_thread()
        };
        match started {
            Ok(running) => {
                #[cfg(test)]
                inner.commit_threads_started.fetch_add(1, Ordering::SeqCst);
                committer.state = CommitState::Running(running);
            }
            Err(_) => {
                drop(committer);
                return HandOff::Inline(job.take_back());
            }
        }
    }
    let CommitState::Running(running) = &committer.state else {
        drop(committer);
        return HandOff::Inline(job.take_back());
    };
    let sent = running.jobs.try_send(job);
    match sent {
        Ok(()) => {
            drop(committer);
            *inner.flight.lock().expect("flight slot poisoned") = Some(ticket);
            HandOff::Taken
        }
        Err(mpsc::TrySendError::Disconnected(job)) => {
            let dead = std::mem::replace(&mut committer.state, CommitState::Stopped);
            drop(committer);
            if let CommitState::Running(dead) = dead {
                dead.stop();
            }
            HandOff::Ended(fail_flight(inner, job.take_back(), COMMIT_THREAD_PANICKED))
        }
        Err(mpsc::TrySendError::Full(job)) => {
            drop(committer);
            let ended = fail_flight(
                inner,
                job.take_back(),
                "a flush was handed over while another was in flight",
            );
            // Only once the store is latched and the flight ended, with
            // no lock of the hand-off held, so that a build with debug
            // assertions leaves the store as any other build does.
            debug_assert!(false, "a flush was handed over while another was in flight");
            HandOff::Ended(ended)
        }
    }
}

/// Start a commit thread, named [`COMMIT_THREAD_NAME`], with its channel.
fn start_commit_thread() -> std::io::Result<Running> {
    let (jobs, queue) = mpsc::sync_channel(1);
    #[cfg(test)]
    let end = Arc::new(ThreadEnd::default());
    #[cfg(test)]
    let mark = MarkEnd(Arc::clone(&end));
    let handle = std::thread::Builder::new()
        .name(COMMIT_THREAD_NAME.to_string())
        .spawn(move || {
            // Bound first, so dropped last: after `commit_thread` has let
            // go of its channel, by its return or by an unwind.
            #[cfg(test)]
            let _mark = mark;
            commit_thread(queue);
        })?;
    Ok(Running {
        id: handle.thread().id(),
        jobs,
        handle,
        #[cfg(test)]
        end,
    })
}

/// How a commit thread ended, for the tests of its life.
#[cfg(test)]
#[derive(Default)]
struct ThreadEnd {
    /// Set as the thread ends, once it has let go of its channel.
    ended: AtomicBool,
    /// Set before `ended` when the thread ends by an unwind.
    unwound: AtomicBool,
}

/// Records the end of the thread that drops it in a [`ThreadEnd`].
#[cfg(test)]
struct MarkEnd(Arc<ThreadEnd>);

#[cfg(test)]
impl Drop for MarkEnd {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.unwound.store(true, Ordering::SeqCst);
        }
        self.0.ended.store(true, Ordering::SeqCst);
    }
}

/// End a flight that cannot be handed over and must not be committed:
/// latch the store with `cause`, let the open write transaction go
/// unused, which redb aborts, and end the flush on this thread as one
/// that failed ([`finish`]): its accounting goes back and a participant
/// that was sealed is told `finished(false)`, with the store already
/// latched.  Returns what `finish` returns: the latch's refusal, which
/// names `cause` unless an earlier failure latched the store first.
fn fail_flight(
    inner: &DbInner,
    flight: Flight,
    cause: &str,
) -> Result<crate::dbcache::RetiredLayers, Error> {
    inner.mark_fatal(db_error(ErrorKind::DriverSpecific, cause));
    let refusal = inner
        .check_writable()
        .expect_err("the store was latched just now");
    let Flight {
        job,
        batch,
        registered,
        sealed,
        snapshot,
    } = flight;
    drop(job);
    drop(snapshot);
    finish(
        inner,
        batch,
        Err(refusal),
        registered.as_ref(),
        sealed,
        false,
    )
}

/// The body of the commit thread: write and commit each flush handed to
/// it, in turn, until its channel is let go of by the close or by the
/// store's drop.
///
/// Asleep in `recv` between flushes, it holds nothing of the store: no
/// handle, no participant, no snapshot and no lock.  A thread that held
/// the store between flushes would keep it open for the life of the
/// process, since the store's drop is what stops the thread.
fn commit_thread(jobs: mpsc::Receiver<Job>) {
    while let Ok(job) = jobs.recv() {
        run_job(job);
    }
}

/// Write the rows of a handed-over flush into its transaction, the
/// overlay's and then the participant's, make the redb commit, end the
/// flush as its capturing thread would have, and then end the job: let
/// go of the store and of everything of the flush, then signal its
/// ticket ([`JobEnd`]).
///
/// It takes the block-store lock, to discharge the block sync it runs
/// ([`DbCache::run_block_sync`]), and the cache lock, in [`finish`], and
/// calls the participant's `contribute` and `finished`; it never takes the
/// writer semaphore, the participant slot's lock or the commit thread's
/// slot, and never touches the flight slot that holds its ticket.  The
/// block-store lock is held only around block writes, block reads'
/// handles and rollbacks, none of which waits for this thread, so a
/// semaphore holder can still always wait for it.
fn run_job(job: Job) {
    let Job {
        inner,
        flight,
        done,
    } = job;
    let end = JobEnd {
        store: Some(inner),
        done: Some(done),
    };
    #[cfg(test)]
    let mut after = None;
    if let Some(inner) = end.store.as_deref() {
        #[cfg(test)]
        {
            after = inner.after_job.lock().expect("test hook poisoned").take();
        }
        let Flight {
            job,
            batch,
            registered,
            sealed,
            snapshot,
        } = flight;
        let result = write_and_commit(inner, &batch, job, registered.as_ref());
        drop(snapshot);
        // A failure is in the latch and the log by the time this returns;
        // there is no caller here to hand it to.
        let _ = finish(inner, batch, result, registered.as_ref(), sealed, true);
    }
    end.complete();
    #[cfg(test)]
    if let Some(hook) = after {
        hook();
    }
}

/// A handed-over flush's hold on the store and its ticket, let go of in
/// that order whether the flush ends or its thread unwinds.
///
/// The store is let go of first so that a caller whose wait for the
/// flush has returned can drop its last handle and find the store closed,
/// its files free to open again at once, as when the thread that made the
/// commit was joined.  An unwind drops the ticket unsent, which the wait
/// for it reads as a panic ([`drain_flight`]).
struct JobEnd {
    store: Option<Arc<DbInner>>,
    done: Option<mpsc::SyncSender<()>>,
}

impl JobEnd {
    /// End the job: let go of the store, then signal the ticket.
    fn complete(mut self) {
        self.release();
        self.signal();
    }

    /// Let go of the store.
    ///
    /// When this hold was the store's last, every handle having been
    /// dropped during the flush, the store is dropped here, on the
    /// commit thread, which lets the thread go ([`Running::stop`]); the
    /// ticket then has no one to tell.
    fn release(&mut self) {
        #[cfg(test)]
        if let Some(inner) = self.store.as_deref() {
            let hook = inner
                .before_release
                .lock()
                .expect("test hook poisoned")
                .take();
            if let Some(hook) = hook {
                hook();
            }
        }
        drop(self.store.take());
    }

    /// Signal the ticket: the flush has ended.
    fn signal(&mut self) {
        if let Some(done) = self.done.take() {
            let _ = done.send(());
        }
    }
}

impl Drop for JobEnd {
    fn drop(&mut self) {
        // Anything still held is let go of on an unwind: the store first,
        // then the ticket, unsent.
        drop(self.store.take());
        drop(self.done.take());
    }
}

/// End a flush whose commit has returned, or which failed before it:
/// retire the captured layers or latch the store, then tell the
/// participant.  Run by the thread that made, or would have made, the
/// commit; `background` says it is the commit thread.  `sealed` says the
/// participant was sealed for this flush, and so is owed its `finished`
/// whether or not its `contribute` was reached.
///
/// On success the layers are retired under the cache lock, which is where
/// the observer is called, then the commits the batch held are recorded
/// as durable ([`DbInner::durable_through`], which
/// [`Database::is_durable`] reads), and only then is a participant that
/// was sealed told `finished(true)`: all three follow the commit, so none
/// reports rows that are not durable.  A flush that had nothing to
/// commit records them too: an empty overlay means every commit before
/// the capture was retired by a flush that landed.  A retirement that
/// finds the pinned layers changed is a failure like any other, though
/// the commit has landed.  In that one case the accounting goes back
/// before the store is latched, since `DbCache::retire` restores it as
/// it refuses.
/// Nothing can be captured in between: a capture follows a wait for this
/// flush to end, or is made by the thread running this.
///
/// On failure the store is latched before anything else.  The accounting
/// then goes back under the cache lock, since the overlay still holds
/// every captured byte and the cache would otherwise never trip its own
/// ceiling again, and a participant that was sealed is told
/// `finished(false)` with the store already refusing writes, whether the
/// flush failed in the overlay's rows, in its `contribute` or in the
/// commit.  The
/// commit thread has no caller to return the error to, so it logs it as
/// well, once.
///
/// The batch, and with it the flush's references to the captured layers,
/// is dropped only after the cache lock is released.  The commit thread
/// drops it here.  A flush that committed on the capturing thread returns
/// those references instead, for [`flush_locked`]'s caller to drop: a
/// commit and [`Database::flush`] once they have released the writer
/// semaphore as well, and [`Database::close`] where it flushed, under it.
fn finish(
    inner: &DbInner,
    mut batch: FlushBatch,
    result: Result<FlushOutcome, Error>,
    registered: Option<&participant::Registration>,
    sealed: bool,
    background: bool,
) -> Result<crate::dbcache::RetiredLayers, Error> {
    let observed = batch.observed();
    let failure = match result {
        Ok(outcome) => {
            // Read for the observer, which sees only a flush that
            // committed; a failed one is latched with nothing before it.
            if observed {
                batch.memory.process_at_commit = ProcessMemory::read(true);
            }
            #[cfg(test)]
            if background
                && let Some(hook) = &*inner.before_retire.lock().expect("test hook poisoned")
            {
                hook();
            }
            let retired = inner
                .cache
                .lock()
                .expect("cache lock poisoned")
                .retire(&batch, Some(outcome));
            // `retire` put the accounting back itself before it refused.
            retired.err().map(|e| inner.mark_fatal(e))
        }
        Err(e) => {
            let e = inner.mark_fatal(e);
            let restored = inner
                .cache
                .lock()
                .expect("cache lock poisoned")
                .retire(&batch, None);
            debug_assert!(restored.is_ok(), "putting the bytes back cannot fail");
            Some(e)
        }
    };
    // Only once the retirement has succeeded as well: one that fails
    // latches the store though its commit landed, and a latched store
    // acknowledges no durability.  Never lowered, and never raised by a
    // flush that failed, so a store that latched leaves every mark read
    // after the last flush that landed short of it for good.
    if failure.is_none() {
        inner
            .durable_through
            .fetch_max(batch.through, Ordering::SeqCst);
    }
    if background && let Some(e) = &failure {
        log_line(
            inner.log.as_ref(),
            LogLevel::Error,
            &format!("Background commit of the metadata write cache failed: {e}"),
        );
    }
    let retired = observed.then(std::time::Instant::now);
    if sealed && let Some(registered) = registered {
        registered.participant.finished(failure.is_none());
    }
    // Read between the two, so that what `finished` allocated can be told
    // from what the frees below give back.
    let told = retired.map(|retired| (ProcessMemory::read(false), retired.elapsed()));
    // A committer holds no semaphore and lets go of the layers here.  A
    // flush that committed on the capturing thread hands them back, and
    // its caller frees them after the reading below: a commit and
    // `Database::flush` once they have released the writer, a close
    // under it.  One that failed hands back nothing: its layers are
    // still published, and the drop frees none of them.
    let handed_back = if background || failure.is_some() {
        drop(batch);
        crate::dbcache::RetiredLayers::new()
    } else {
        batch.into_retired()
    };
    if let (Some(retired), Some((told, telling))) = (retired, told) {
        let end = FlushEnd {
            told,
            telling,
            memory: ProcessMemory::read(false),
            release: retired.elapsed(),
        };
        *inner.flush_end.lock().expect("flush end poisoned") = Some(end);
    }
    match failure {
        Some(e) => Err(e),
        None => Ok(handed_back),
    }
}

/// Make one empty quick-repair commit, so the metadata store records its
/// allocator state and the next open loads it instead of repairing.
///
/// Every flush commits one-phase with no allocator state, so an open
/// after anything but redb's own `Database::drop` runs a full repair --
/// "3 full scans" of the file (redb-4.3.0 `db.rs:1473`) -- because only
/// that drop records the state.  `Database::close` makes it itself
/// before it lets go of redb's handle, so a failure is reported by the
/// close, which redb's drop cannot do, and a clean close leaves a store
/// that opens without a full repair even when a transaction still open
/// keeps the handle, and with it the recovery flag, past the end of the
/// process.  redb's own version of this commit is
/// `ensure_allocator_state_table_and_trim` (`db.rs:1922-1955`), which its
/// drop runs from `close_database` (`db.rs:1963`) before it clears the
/// flag.  Per-commit quick-repair would cover unclean stops too, at a
/// second fsync on every flush; that is unmeasured and not done here.
fn record_allocator_state(kv: &redb::Database) -> Result<(), Error> {
    let mut tx = begin_durable_write(kv)?;
    tx.set_quick_repair(true);
    tx.commit().map_err(storage_error)
}

impl Options {
    /// Options with dcrd's defaults for the given directory and
    /// network, except the overlay ceiling: see [`Self::cache_max_size`].
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
            log: None,
            background_commit: false,
            commit_snapshot: true,
            before_commit: None,
        }
    }
}

/// Hand a line to the sink, if there is one.
pub(crate) fn log_line(sink: Option<&LogSink>, level: LogLevel, msg: &str) {
    if let Some(sink) = sink {
        sink(level, msg);
    }
}

/// Open the metadata store, through `opts.backend` when one is
/// installed and directly otherwise.
///
/// `create_with_backend` is redb's only backend entry point and carries
/// its create-or-open semantics, so both call sites route through here
/// rather than one of them quietly ignoring the hook.
///
/// `report_repair` logs redb's repair of a store that was not shut down
/// cleanly; see [`redb_builder`].
fn open_metadata(
    opts: &Options,
    meta_path: &Path,
    report_repair: bool,
) -> Result<redb::Database, redb::DatabaseError> {
    match &opts.backend {
        Some(shared) => redb_builder(opts, report_repair)
            .create_with_backend(SharedBackendHandle(Arc::clone(shared))),
        None => redb_builder(opts, report_repair).create(meta_path),
    }
}

/// The redb builder both open paths use, so the cache setting cannot be
/// applied on one and forgotten on the other.
///
/// With `report_repair` and a log sink, redb's repair of a store that
/// was not shut down cleanly is logged as it runs.  That repair reads
/// the whole metadata file up to three times (redb-4.3.0 `db.rs:1473`)
/// and would otherwise be a silent stall after "Loading block database
/// from '...'".  redb calls back at the start and at each scan
/// boundary (`db.rs:1474`, `:1492`, `:1539`, `:1653`), so this is a
/// handful of lines.  `create` leaves it off: redb repairs every new
/// file once, because a fresh header records no allocator state, and
/// that is not an unclean shutdown.  dcrd has no line for this --
/// goleveldb replays its journal instead -- so the text is the port's,
/// worded after dcrd's reconcile line ("Detected unclean shutdown -
/// Repairing...") and followed by "Metadata store repair N% complete"
/// at each scan boundary.  The operator docs quote both.
fn redb_builder(opts: &Options, report_repair: bool) -> redb::Builder {
    let mut builder = redb::Builder::new();
    builder.set_cache_size(opts.db_cache_bytes);
    if let (true, Some(sink)) = (report_repair, &opts.log) {
        let sink = Arc::clone(sink);
        builder.set_repair_callback(move |session| {
            let progress = session.progress();
            let msg = if progress <= 0.0 {
                "Detected unclean shutdown of the metadata store - Repairing...".to_string()
            } else {
                format!("Metadata store repair {:.0}% complete", progress * 100.0)
            };
            sink(LogLevel::Info, &msg);
        });
    }
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
    /// on m1's mainnet store as of 2026-08-07 gave 8.46 GiB against a true
    /// 9.79 — a 1.32 GiB shortfall. The reason is that `leaf_pages` counts
    /// leaf *nodes*, one per node, while a node's allocation is rounded to
    /// a power-of-two run of pages (`required_order = ceil_log2`), so a
    /// single row too large to share a leaf can occupy 2, 4 or 32 pages and
    /// still be counted once. (An earlier version of this comment blamed
    /// "overflow pages"; redb 2.6.3 has no such mechanism, and the real one
    /// is the allocator rounding — also the source of roughly 14% of the
    /// slack in `spendjournalv3`, by ADR-0004's addendum of 2026-08-12.)
    /// Summing the three measured components is the honest figure.
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

/// Classify a redb error the way dcrd's `convertErr` classifies a
/// leveldb one (`ffldb/db.go:138-166`): corruption gets its own kind
/// and a closed engine reads as "not open", everything else is
/// driver-specific.
///
/// redb reports corruption through several types -- `StorageError`,
/// `TransactionError`, `CommitError`, `TableError` -- so this takes
/// anything that converts into `redb::Error` and matches once there.
/// `PreviousIo` and `RepairAborted` join `Corrupted` because all three
/// mean the file cannot be trusted as it stands: a prior I/O failure
/// left writes in an unknown state, and an aborted repair left the
/// recovery half-done.
///
/// Nothing outside this crate branches on the kind today; the value is
/// that the kind an operator is shown is the one dcrd's `convertErr`
/// would give.  Open failures come through here too, by way of
/// [`open_error`]'s fallback: header validation and the repair path are
/// where corruption is most often found.
///
/// This is narrower than it looks, and deliberately so.  Not every
/// damaged metadata page reaches here.  Since 4.2.0 redb reports as
/// `Corrupted` three malformed structures that used to abort the process,
/// so they now arrive here as [`ErrorKind::Corruption`]: a branch cycle
/// or over-deep chain, cut off at depth 128 (redb #1332; redb-4.3.0
/// `btree.rs:1097-1118`, `btree_cursor.rs:170-174`), an oversized page
/// order (#1331, `page_manager.rs:1251-1260`), and a corrupt freed-page
/// entry met while rebuilding the allocator (#1333,
/// `page_manager.rs:1554-1575`).  A page whose type byte is neither leaf
/// nor branch still hits `unreachable!()` in the descent
/// (`btree.rs:1112`) and aborts the process under this workspace's
/// `panic = "abort"`.  No read compares a page's checksum either: redb
/// does that only when verifying whole trees (`db.rs:816-850`), which
/// `check_integrity` and repair do, so damage that leaves a page
/// well-formed comes back as data.  The issues are recorded in
/// `docs/adr/0004-storage-backend.md`.  What does reach here is the
/// corruption redb *reports* -- checksum mismatches on the paths that
/// verify, the malformed structures above, an aborted repair, a
/// poisoned handle after a prior I/O failure.  Classifying those is
/// worth the twenty lines; it is not a substitute for the reporting
/// redb does not do.
pub(crate) fn storage_error<E: Into<redb::Error>>(e: E) -> Error {
    let e = e.into();
    let kind = match &e {
        redb::Error::Corrupted(_) | redb::Error::PreviousIo | redb::Error::RepairAborted => {
            ErrorKind::Corruption
        }
        redb::Error::DatabaseClosed => ErrorKind::DbNotOpen,
        _ => ErrorKind::DriverSpecific,
    };
    db_error(kind, e.to_string())
}

/// Classify a redb open failure.
///
/// redb locks the metadata file exclusively and reports
/// `DatabaseAlreadyOpen` when another process already holds the lock,
/// which is what stops two daemons from sharing one data directory.
/// redb-4.3.0 takes it before reading anything from the file
/// (`page_manager.rs:699-700`, `:1099`): byte-range locks on the open
/// file description on Linux and Apple targets
/// (`file_backend/range_lock.rs:377-394`), `LockFileEx` range locks on
/// Windows (`:95-307`), and on Linux also a best-effort whole-file
/// `flock`, the lock earlier redb versions take
/// (`file_backend/optimized.rs:87-104`).  That has to surface as
/// [`ErrorKind::DbAlreadyOpen`] — dcrd's `ErrDbAlreadyOpen` —
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
        // A data directory on an older redb file format. redb reads only
        // the current one and reports this rather than guessing, which is
        // the behaviour that makes a format change safe: an old directory
        // is refused, not misread. There is no in-place migration and
        // ADR-0004's fresh-sync stance means there does not need to be,
        // but the operator has to be told which of the two things
        // happened, because "delete the data directory and re-sync" and
        // "your disk is damaged" call for very different reactions.
        redb::DatabaseError::UpgradeRequired(version) => db_error(
            ErrorKind::Invalid,
            format!(
                "the metadata store is redb file format {version}, which this build \
                 cannot read -- it was written by an older dcroxide. There is no \
                 in-place upgrade: remove the data directory and sync again (see \
                 docs/operating.md). The chain is not damaged."
            ),
        ),
        // Everything else is classified as any other redb error, the
        // way dcrd hands a failed `leveldb.OpenFile` to `convertErr`
        // (`ffldb/db.go:2098-2101`): a header that fails validation or a
        // repair that finds every root corrupted is
        // `Storage(Corrupted)`, an aborted repair is `RepairAborted`,
        // and both are corruption, not a driver-specific failure.
        other => storage_error(other),
    }
}

/// Reconcile the metadata's block-file write cursor with the block files
/// on disk (dcrd `reconcileDB`, `ffldb/reconcile.go:53-118`), for
/// `create` and `open` alike as dcrd runs it for both.
///
/// Block data past the stored cursor is an unclean shutdown between the
/// file writes and the metadata commit, and is rolled back.  A rollback
/// step that fails is logged by the block store and the open carries on
/// with the cursor repositioned regardless, as dcrd's void
/// `handleRollback` does: whatever it could not undo lies past the
/// cursor, where the next write overwrites it.  Block data short of the
/// stored cursor means missing, deleted or truncated files, and is
/// `ErrCorruption`.  The log lines are dcrd's, at dcrd's levels.
fn reconcile_db(
    kv: &redb::Database,
    block_store: &mut BlockStore,
    log: Option<&LogSink>,
) -> Result<(), Error> {
    // Load the current write cursor position from the metadata.  A store
    // with no metadata table -- a crash between redb initializing the
    // file and `create`'s first commit -- holds no cursor either.
    let (cur_file, cur_offset) = {
        let missing = || db_error(ErrorKind::Corruption, "write cursor does not exist");
        let rtx = kv.begin_read().map_err(storage_error)?;
        let table = match rtx.open_table(METADATA_TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Err(missing()),
            Err(e) => return Err(storage_error(e)),
        };
        let mut key = METADATA_BUCKET_ID.to_vec();
        key.extend_from_slice(WRITE_LOC_KEY);
        let row = table
            .get(key.as_slice())
            .map_err(storage_error)?
            .ok_or_else(missing)?;
        deserialize_write_row(row.value())?
    };

    let stored = (cur_file, cur_offset);
    let scanned = (block_store.write_file_num, block_store.write_offset);
    if scanned > stored {
        log_line(
            log,
            LogLevel::Info,
            "Detected unclean shutdown - Repairing...",
        );
        log_line(
            log,
            LogLevel::Debug,
            &format!(
                "Metadata claims file {cur_file}, offset {cur_offset}. Block data is at \
                 file {}, offset {}",
                scanned.0, scanned.1
            ),
        );
        // Logged inside, and the cursor is repositioned either way.
        let _ = block_store.rollback_to(cur_file, cur_offset);
        log_line(log, LogLevel::Info, "Database sync complete");
    }

    let scanned = (block_store.write_file_num, block_store.write_offset);
    if scanned < stored {
        let str = format!(
            "metadata claims file {cur_file}, offset {cur_offset}, but block data is at \
             file {}, offset {}",
            scanned.0, scanned.1
        );
        log_line(
            log,
            LogLevel::Warn,
            &format!("***Database corruption detected***: {str}"),
        );
        return Err(db_error(ErrorKind::Corruption, str));
    }
    Ok(())
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

/// What [`Database::begin_seed`] acquires for a new transaction: the store
/// snapshot and the redb handle it was taken from, the overlay snapshot,
/// and the bucket index of the commits that overlay snapshot holds.
type TxSeed = (
    KvTxSeed,
    Arc<redb::Database>,
    Arc<crate::dbcache::CacheMap>,
    Arc<bucketindex::BucketIndex>,
);

impl Database {
    /// Create a new database at the directory in the options; errors
    /// with `ErrDbExists` when one is already there (dcrd
    /// `database.Create`).
    ///
    /// Like dcrd's `openDB(create=true)`, this ends in the same
    /// reconciliation as [`Self::open`] (`reconcileDB(pdb, create)`,
    /// `ffldb/db.go:2114`): block files already in the directory lie past
    /// the new store's (0, 0) write cursor, so they are rolled back --
    /// every file after the first deleted and the first truncated --
    /// before anything is written, rather than adopted with the durable
    /// cursor and the live one disagreeing until the first flush.
    ///
    /// After the reconciliation the store's bucket index is read, as
    /// [`Self::open`] reads it, and a store read error there fails the
    /// call.
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
        // dcrd's own metadata store at this path is a database that
        // already exists too: dcrd's create refuses it (`ErrorIfExist:
        // create`, `ffldb/db.go:2090-2097`), and this one must.  The
        // daemon's directory is `blocks_ffldb`, dcrd's name, and this
        // store's metadata file is not dcrd's, so without the check a
        // dcroxide pointed at a dcrd data directory would reach the
        // reconciliation below with dcrd's block files -- and delete
        // them.
        let dcrd_meta = opts.path.join(DCRD_METADATA_DIR);
        if dcrd_meta.exists() {
            return Err(db_error(
                ErrorKind::DbExists,
                format!(
                    "database already exists at the provided path: {} is a dcrd metadata \
                     store, and dcroxide cannot use a dcrd data directory -- give it a \
                     data directory of its own (see docs/operating.md)",
                    dcrd_meta.display()
                ),
            ));
        }
        // dcrd's ffldb only creates the tree when the database does not
        // exist (the guard above), and creates it 0700.
        // Not a redb error: `storage_error` would relabel it "I/O
        // error: ..." on the way through redb's own wrapper.
        create_dir_all_owner_only(&opts.path)
            .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;

        let kv = open_metadata(opts, &meta_path, false).map_err(open_error)?;

        // Initialize the ffldb-layout bookkeeping rows: the bucket
        // index entry and fixed ID for the internal block index, the
        // bucket ID counter, and the initial block-file write cursor.
        {
            let wtx = begin_durable_write(&kv)?;
            {
                let mut table = wtx.open_table(METADATA_TABLE).map_err(storage_error)?;
                #[allow(
                    clippy::arithmetic_side_effects,
                    reason = "constant lengths: 4 + 4 + 14 = 22"
                )]
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
                    table.insert(k, v).map_err(storage_error)?;
                }
            }
            wtx.commit().map_err(storage_error)?;
        }

        let mut block_store = BlockStore::open(
            &opts.path,
            opts.network,
            opts.max_block_file_size,
            opts.log.clone(),
        )?;
        reconcile_db(&kv, &mut block_store, opts.log.as_ref())?;
        Ok(Database {
            inner: Arc::new(DbInner::new(kv, block_store, opts)?),
        })
    }

    /// Open an existing database; errors with `ErrDbDoesNotExist` when
    /// there is none (dcrd `database.Open`).  Reconciles the metadata
    /// against the flat block files, rolling back any block file data
    /// beyond what the metadata records (an unclean shutdown between
    /// the file writes and the metadata commit), and erroring with
    /// `ErrCorruption` when the metadata claims more data than the
    /// files actually hold (dcrd `reconcileDB`).
    ///
    /// After the reconciliation the store's bucket index is read once,
    /// for every later bucket lookup to be answered from (see the
    /// `bucketindex` module), and a store read error there fails the open
    /// with the store's error.  dcrd's open reads only the write cursor
    /// (`ffldb/reconcile.go:53-118`) and meets such an error at the first
    /// lookup of the bucket, as a missing bucket.
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
        let kv = open_metadata(opts, &meta_path, true).map_err(open_error)?;
        let mut block_store = BlockStore::open(
            &opts.path,
            opts.network,
            opts.max_block_file_size,
            opts.log.clone(),
        )?;
        reconcile_db(&kv, &mut block_store, opts.log.as_ref())?;
        Ok(Database {
            inner: Arc::new(DbInner::new(kv, block_store, opts)?),
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
        // Held to the end, past the read transaction, as a transaction
        // holds it ([`DbInner::kv`]).
        let kv = self.inner.kv_or_closed()?;
        let tx = kv.begin_read().map_err(storage_error)?;
        let table = tx.open_table(METADATA_TABLE).map_err(storage_error)?;

        // Bucket id -> name, from the `bidx<parent><name>` index rows.
        let mut names: std::collections::BTreeMap<[u8; 4], String> =
            std::collections::BTreeMap::new();
        // Bucket id -> (rows, payload bytes, largest row).
        // (rows, payload, largest, log2 size bands)
        #[allow(clippy::type_complexity)]
        let mut agg: std::collections::BTreeMap<[u8; 4], (u64, u64, u64, [u64; 40])> =
            std::collections::BTreeMap::new();

        let iter = redb::ReadableTable::range::<&[u8]>(&table, ..).map_err(storage_error)?;
        for entry in iter {
            let (k, v) = entry.map_err(storage_error)?;
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
                #[allow(
                    clippy::arithmetic_side_effects,
                    reason = "constant lengths: 4 + 4 = 8"
                )]
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
        let kv = self.inner.kv_or_closed()?;
        let tx = begin_durable_write(&kv)?;
        let stats = {
            let db_stats = tx.stats().map_err(storage_error)?;
            let table = tx.open_table(METADATA_TABLE).map_err(storage_error)?;
            let table_stats = redb::ReadableTableMetadata::stats(&table).map_err(storage_error)?;
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
        tx.abort().map_err(storage_error)?;
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

    /// How many blocks this handle has written to the block files as the
    /// record they were handed in as
    /// ([`Transaction::store_block_record`]), where the record of every
    /// other block is laid out by the commit that writes it.  A record
    /// laid out for another network than the database's is not among
    /// them, since the store lays out its own; one whose commit failed
    /// after the write, and was rolled back, is.
    ///
    /// dcrd has no such figure.  It is for a person and for tests to
    /// read, to tell that the work of laying records out was done before
    /// the commit and not repeated in it: nothing in the store depends
    /// on it, and it starts at zero with every open.
    pub fn records_written_as_laid_out(&self) -> u64 {
        self.inner
            .block_store
            .lock()
            .expect("store lock")
            .laid_out_written
    }

    /// [`Self::is_fatal`], once any flush whose commit is still under way
    /// on its own thread has ended ([`Options::background_commit`]).
    ///
    /// For a caller that has just seen something fail and must decide
    /// whether storage was the cause.  redb refuses reads of pages it has
    /// not cached from the moment a write of a flush's transaction fails,
    /// in its rows or its commit, which is before the flush ends and the
    /// store latches.  A read made in
    /// between fails, or answers absence where an ffldb-layout read takes
    /// a store error for a missing row, with [`Self::is_fatal`] still
    /// `false`.  Waiting for the commit closes that window.
    ///
    /// With the option off, or the store already latched, this is
    /// [`Self::is_fatal`] and waits for nothing.  So `true` does not say
    /// the flush has ended: the commit thread latches the store first, and
    /// may still be logging the failure or telling the participant.  A flush
    /// or a close waits for that; this only answers.  Otherwise it waits
    /// out any writable transaction, as [`Self::flush`] does: calling it
    /// from a thread that holds one, or from a participant or
    /// `on_commit` hook, deadlocks.
    pub fn is_fatal_settled(&self) -> bool {
        if !self.inner.background || self.is_fatal() {
            return self.is_fatal();
        }
        let _writer = self.exclusive_writer();
        drain_flight(&self.inner);
        self.is_fatal()
    }

    /// Wait for the flush whose commit is under way on its own thread, if
    /// there is one, and report the latch: `Ok` when the store is
    /// writable afterwards, the latch's refusal when that commit, or any
    /// durable write before it, failed.
    ///
    /// For tests, which must not drop or reopen a store with a commit
    /// still running: the commit thread holds the store open until the
    /// flush has ended, and lets go of it before this returns, so a test
    /// that then drops its last handle closes the store.  The thread
    /// itself goes on, asleep, until the close or that drop stops it.
    /// Waits out any writable transaction, as [`Self::flush`] does.
    #[doc(hidden)]
    pub fn wait_background_commit(&self) -> Result<(), Error> {
        let _writer = self.exclusive_writer();
        drain_flight(&self.inner);
        self.inner.check_writable()
    }

    /// Acquire everything a new transaction needs, in the safe order:
    /// the writer semaphore (writable only, dcrd's `writeLock`), the
    /// cache overlay snapshot, and only then the redb read snapshot.
    /// A flush between the two snapshots is then seen twice (the
    /// overlay wins with identical values) instead of not at all.
    ///
    /// The bucket index is taken with the overlay snapshot, under the
    /// same hold of the cache lock: a commit changes both under one hold
    /// of it, so the map is the bucket index of exactly the commits the
    /// overlay snapshot holds.
    fn begin_seed(&self, writable: bool) -> Result<TxSeed, Error> {
        let release = |inner: &DbInner| {
            let mut busy = inner.writer_busy.lock().expect("writer flag poisoned");
            *busy = false;
            inner.writer_cv.notify_one();
        };
        if writable {
            self.inner.acquire_writer();
            // The database may have closed while this writer waited
            // (dcrd re-checks `closed` after taking its write lock).
            if self.inner.closed.load(Ordering::SeqCst) {
                release(&self.inner);
                return Err(db_error(ErrorKind::DbNotOpen, "database is not open"));
            }
            // So may the store have latched: the writer this one queued
            // behind can be the one whose durable write failed.
            if let Err(e) = self.inner.check_writable() {
                release(&self.inner);
                return Err(e);
            }
        }
        // The store's redb handle, which the transaction holds to its end
        // ([`DbInner::kv`]).  A writer past the `closed` check above
        // always finds it, since the close lets go of it with the writer
        // semaphore held; a reader that loses a race with the close is
        // refused, as a begin after the close is.
        let handle = match self.inner.kv_or_closed() {
            Ok(handle) => handle,
            Err(e) => {
                if writable {
                    release(&self.inner);
                }
                return Err(e);
            }
        };
        // The overlay snapshot and the store snapshot are taken under
        // one hold of the cache lock, because a transaction's view is
        // the overlay shadowing the store: `fetch_raw` answers from
        // `cache_snap` before consulting the table.  A flush commit that
        // lands between the two snapshots is harmless as long as its
        // layers are still in the overlay snapshot -- the same batch is
        // then seen in both, with identical values, and the overlay
        // wins.  What must not happen is a snapshot pair in which the
        // store has a flush whose layers the overlay snapshot does not
        // hold, while the overlay snapshot still holds an OLDER layer
        // for a key that flush deleted: the stale overlay would
        // resurrect it, a state that never existed at any commit point.
        //
        // What rules that out is not this lock being held across the
        // commit -- it is not: `flush_locked` releases it for the redb
        // commit so readers are not held for its fsync.  It is three
        // things together.  A flush's captured layers stay published
        // until `DbCache::retire` retires them, after its commit
        // is visible, and that retirement takes the cache lock, so it
        // cannot happen inside this hold.  `DbCache::begin_flush` takes
        // the lock too, so no new flush can be captured inside it.  And
        // at most one flush is captured and not yet retired: every
        // capture is made by a holder of the writer semaphore after it
        // has waited for the flush before it to end (`drain_flight` in
        // `flush_locked`), and a flush ends only once it has retired or
        // latched the store, on whichever thread made its commit.  So
        // one flush at most is in flight across this hold -- captured
        // before it, retired after it -- and its commit is the only one
        // that can land between the two snapshots, with its layers still
        // in the overlay snapshot.  A capture made without that wait
        // would break the last of these and with it this view, which is
        // why `flush_locked` refuses one in release builds too.  The
        // order is writer flag, then cache, then redb on both paths, so
        // the two cannot deadlock against each other.
        let cache = self.inner.cache.lock().expect("cache lock poisoned");
        let cache_snap = std::sync::Arc::clone(&cache.cached);
        let buckets = std::sync::Arc::clone(&cache.buckets);
        #[cfg(test)]
        {
            let hook = self
                .inner
                .between_snapshots
                .lock()
                .expect("test hook poisoned")
                .take();
            if let Some(hook) = hook {
                hook();
            }
        }
        let kv = match handle.begin_read() {
            Ok(t) => t,
            Err(e) => {
                drop(cache);
                // Let go of the handle before the writer semaphore, as a
                // transaction does (`Transaction::close`).
                drop(handle);
                if writable {
                    release(&self.inner);
                }
                return Err(storage_error(e));
            }
        };
        drop(cache);
        let seed = if writable {
            KvTxSeed::Write(kv)
        } else {
            KvTxSeed::Read(kv)
        };
        Ok((seed, handle, cache_snap, buckets))
    }

    /// Hold the writer semaphore for the guard's lifetime, waiting out
    /// any writable transaction (dcrd's `Flush` and `Close` exclude its
    /// writer too).
    ///
    /// Narrower than dcrd, which takes `closeLock` exclusively there and
    /// so also waits for every open read-only transaction
    /// (`ffldb/db.go:1969-1971`, `:2010-2012`).  A reader here holds its
    /// own overlay layers and redb snapshot, which a flush neither
    /// changes nor frees, so nothing it sees depends on the wait; a
    /// long-lived reader just does not hold up a flush or a close.  It
    /// defers redb's own close instead, which comes once the last open
    /// transaction has ended ([`DbInner::kv`]).
    fn exclusive_writer(&self) -> WriterGuard<'_> {
        self.inner.acquire_writer();
        WriterGuard { db: &self.inner }
    }

    /// Start a transaction, read-only or read-write per the flag (dcrd
    /// `Begin`).  Multiple read-only transactions may run concurrently;
    /// starting a read-write transaction blocks until any current one
    /// finishes, on the writer semaphore.  The transaction must be
    /// finalized with [`Transaction::commit`] or
    /// [`Transaction::rollback`].
    pub fn begin(&self, writable: bool) -> Result<Transaction, Error> {
        self.check_open()?;
        if writable {
            self.inner.check_writable()?;
        }
        let (seed, handle, cache_snap, buckets) = self.begin_seed(writable)?;
        Transaction::new(
            Arc::clone(&self.inner),
            seed,
            handle,
            cache_snap,
            buckets,
            false,
        )
    }

    fn begin_managed(&self, writable: bool) -> Result<Transaction, Error> {
        self.check_open()?;
        if writable {
            self.inner.check_writable()?;
        }
        let (seed, handle, cache_snap, buckets) = self.begin_seed(writable)?;
        Transaction::new(
            Arc::clone(&self.inner),
            seed,
            handle,
            cache_snap,
            buckets,
            true,
        )
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
    ///
    /// A registered [`FlushParticipant`] contributes to the final flush
    /// like any other and is released afterwards, whatever the outcome:
    /// no later flush may run it (see [`Self::flush`] on a flush that
    /// loses the writer to a close), and a participant kept past the
    /// close would hold its memory for as long as any clone of this
    /// handle lives.
    ///
    /// The store's commit thread ([`COMMIT_THREAD_NAME`]), when one was
    /// started, is stopped and joined here, latched or not, once the flush
    /// it was writing has ended: none outlives the close.
    ///
    /// A close that returns `Ok` lets go of the metadata store's redb
    /// handle, which closes the file, clearing the recovery flag redb
    /// keeps in its header while it has the file open for writing, and
    /// releases redb's lock on it, as dcrd's `Close` closes leveldb
    /// (`ffldb/dbcache.go:635-639`).  That happens here, or, when a
    /// transaction begun before the close is still open, as the last such
    /// transaction ends: each transaction holds the redb handle from its
    /// begin to its end, and clones of this handle do not hold it.  A
    /// close that fails, or finds the store latched, leaves
    /// the handle to the drop of the last clone, as before: the file then
    /// keeps the flag, and the next open recovers it.
    pub fn close(&self) -> Result<(), Error> {
        if self.inner.closed.swap(true, Ordering::SeqCst) {
            return Err(db_error(ErrorKind::DbNotOpen, "database is not open"));
        }
        // A latched handle does not get one last flush.  The latch
        // exists because a failed durable write leaves the cache
        // holding its dirty set, so a retry can report success for a
        // batch the engine already mishandled (`mark_fatal`); shutdown
        // is a retry like any other, and the one whose `Ok` is most
        // likely to be believed.  The handle is still marked closed
        // first, matching dcrd's `Close`, which marks it closed even
        // when the cache close fails (`ffldb/db.go:1978-1989`).
        if let Err(e) = self.inner.check_writable() {
            // No commit thread outlives the close, latched or not: the
            // flush that latched the store may still be telling the
            // participant, which is released only after it, and the
            // thread is stopped once that flush has ended.  That is a
            // wait for the writer, as on the path below, so it is made
            // only where a commit thread can exist.
            let writer = self.inner.background.then(|| {
                let writer = self.exclusive_writer();
                drain_flight(&self.inner);
                stop_commit_thread(&self.inner);
                writer
            });
            drop(self.inner.take_participant());
            drop(writer);
            return Err(e);
        }
        // Flush the metadata write cache so a clean shutdown persists
        // everything (dcrd `Close` flushes the cache), waiting out any
        // committing transaction first (dcrd's close/write locks) --
        // which can be the one that latches, so look again once it is
        // out of the way.
        let _writer = self.exclusive_writer();
        // And any flush whose commit is still under way: `close_locked`
        // looks at the latch before its own flush would wait for it.
        drain_flight(&self.inner);
        // Then the commit thread, asleep now.  The close's own flush is
        // made here and never handed over.
        stop_commit_thread(&self.inner);
        let closed = self.close_locked();
        drop(self.inner.take_participant());
        closed
    }

    /// The flush and allocator-state commit of [`Self::close`], and the
    /// release of redb's handle, with the writer semaphore held.
    fn close_locked(&self) -> Result<(), Error> {
        self.inner.check_writable()?;
        flush_locked(&self.inner, FlushKind::Durable)?;
        // Then record the allocator state.  redb's own close records it
        // too, but it can report no failure, and it runs only once the
        // last transaction holding the handle has ended -- never, if one
        // is still open when the process exits.  Without it the next open
        // would then repair the whole file.
        let kv = self.inner.kv_or_closed()?;
        record_allocator_state(&kv).map_err(|e| self.inner.mark_fatal(e))?;
        drop(kv);
        // And let go of the handle, so that redb closes the file: here,
        // unless a transaction begun before the close still holds it.  No
        // flush is in flight and none can capture anything behind the
        // close, so redb's close, which makes a commit of its own, has
        // the store to itself.
        drop(self.inner.take_kv());
        Ok(())
    }

    /// Register the flush participant whose rows live under `prefix`
    /// ([`FlushParticipant`], ADR-0011).
    ///
    /// The database holds `participant` by a strong reference until
    /// [`Self::clear_flush_participant`] or [`Self::close`], so the final
    /// flush of a close still reaches it after every other owner has
    /// gone.  It must not hold a clone of this database (see the trait).
    ///
    /// Waits out any writable transaction and any flush, as a flush does,
    /// a flush whose commit is still under way on its own thread
    /// included, so a flush runs with one participant from start to end.
    /// Calling it from a thread that holds a writable transaction of this
    /// database, or from a participant or `on_commit` hook, deadlocks.
    ///
    /// Refused with:
    /// - [`ErrorKind::DbNotOpen`] once the database is closed;
    /// - [`ErrorKind::DriverSpecific`] while a participant is registered
    ///   (clear it first: replacing one silently would drop whatever the
    ///   old one held in memory);
    /// - [`ErrorKind::IncompatibleValue`] for a prefix shorter than a
    ///   bucket id (four bytes), for one inside the database's own rows
    ///   (the metadata bucket, the block index or the bucket index), and
    ///   while the overlay holds a row under the prefix: such a row would
    ///   shadow the participant's.  Flush first; rows already in the store
    ///   are no obstacle.
    pub fn set_flush_participant(
        &self,
        prefix: &[u8],
        participant: Arc<dyn FlushParticipant>,
    ) -> Result<(), Error> {
        self.check_open()?;
        // The bucket index is reserved for a second reason: a flush
        // writes a participant's rows to the store without their passing
        // through a commit, and the bucket index held in memory
        // (`bucketindex`) follows commits alone.
        let reserved = [
            METADATA_BUCKET_ID.as_slice(),
            BLOCK_IDX_BUCKET_ID.as_slice(),
            BUCKET_INDEX_PREFIX,
        ];
        if prefix.len() < 4 || reserved.iter().any(|r| prefix.starts_with(r)) {
            return Err(db_error(
                ErrorKind::IncompatibleValue,
                format!(
                    "a flush participant's prefix must be a bucket id of its own, not {prefix:02x?}"
                ),
            ));
        }
        let _writer = self.exclusive_writer();
        // A flush whose commit is still under way ends with the
        // registration it began with.
        drain_flight(&self.inner);
        // The close may have run while this waited.
        self.check_open()?;
        if self.inner.registered().is_some() {
            return Err(db_error(
                ErrorKind::DriverSpecific,
                "a flush participant is already registered",
            ));
        }
        let shadowed = self
            .inner
            .cache
            .lock()
            .expect("cache lock poisoned")
            .cached
            .holds_prefix(prefix);
        if shadowed {
            return Err(db_error(
                ErrorKind::IncompatibleValue,
                format!(
                    "the metadata overlay holds rows under {prefix:02x?}, which would shadow the \
                     flush participant's; flush before registering it"
                ),
            ));
        }
        *self
            .inner
            .participant
            .lock()
            .expect("participant lock poisoned") = Some(participant::Registration {
            prefix: Arc::from(prefix),
            participant,
        });
        Ok(())
    }

    /// Unregister the flush participant, returning it, or `None` when
    /// none was registered.  Flushes from now on run without it.
    ///
    /// Waits out any writable transaction and any flush, as
    /// [`Self::set_flush_participant`] does, so a flush that started with
    /// the participant finishes with it, `finished` included.  Allowed on
    /// a closed database, where it finds nothing.  An index drop calls
    /// this first, so the flushes its deletions trigger cannot write the
    /// index's rows back.
    pub fn clear_flush_participant(&self) -> Option<Arc<dyn FlushParticipant>> {
        let _writer = self.exclusive_writer();
        // `finished` included even when it is called by the thread that
        // made the flush's commit, after the flush's own caller has gone
        // on.
        drain_flight(&self.inner);
        self.inner.take_participant()
    }

    /// Write all outstanding cached entries to disk (dcrd `Flush`):
    /// sync the flat block files, then durably commit the metadata
    /// write cache.
    pub fn flush(&self) -> Result<(), Error> {
        self.check_open()?;
        self.inner.check_writable()?;
        let writer = self.exclusive_writer();
        // No second `closed` check once the writer is held, unlike
        // `begin_seed`.  dcrd's `Flush` queues on `closeLock` itself,
        // and Go's `RWMutex.Lock` takes the writer mutex before it waits
        // out readers (`sync/rwmutex.go:150`), so a `Close` called after
        // a queued `Flush` waits for it (`ffldb/db.go:1972`, `:2013`)
        // and the flush returns nil.  A flush that passed the check
        // above comes before the close in the same way.  Should the
        // close wake first here, it has already flushed and no writer
        // can begin after it, so the flush below is empty and commits
        // nothing (`DbCache::open`; the close released any flush
        // participant, so none has work for it either): still dcrd's `Ok`.
        // Again with the writer held: the transaction waited out may be
        // the one whose flush failed and latched the store.  So may a
        // flush whose commit is still under way, which is waited for
        // first: nothing is acknowledged here until it has ended.
        drain_flight(&self.inner);
        self.inner.check_writable()?;
        let retired = flush_locked(&self.inner, FlushKind::Durable);
        // The layers the flush retired are freed once the writer is
        // released, so the next writer does not wait for the frees.
        drop(writer);
        retired.map(drop)
    }

    /// Write all outstanding cached entries to disk as [`Self::flush`]
    /// does, except that the redb commit may be left under way: with
    /// [`Options::background_commit`] the flush is handed to a thread of
    /// its own as a commit's own flush is, and this returns once the
    /// write cache is captured, what the block-file sync owes is taken
    /// and the flush's write transaction is open.  dcrd has no such call.
    ///
    /// `Ok` acknowledges nothing as durable.  Read a [`CommitMark`]
    /// ([`Self::commit_mark`]) before calling it and ask
    /// [`Self::is_durable`] afterwards: the flush captures every commit
    /// the mark covers, so the mark is durable once its commit has landed,
    /// or once any later flush's has.  A failure in writing the flush's
    /// rows or in its commit latches the store from that thread, and the
    /// next write, flush or close reports it; the mark then never becomes
    /// durable.
    ///
    /// Like [`Self::flush`] it waits out any writable transaction and a
    /// flush whose commit is still under way, and is refused on a closed
    /// or latched store.  It commits before it returns, and the mark is
    /// durable then, when the option is off, when a participant that does
    /// not allow its `contribute` and `finished` to be deferred has work,
    /// and when no thread is to be had.  The flush it makes is observed
    /// with [`FlushObservation::explicit`] unset, and calling it from a
    /// thread that holds a writable transaction of this database, or from
    /// a participant or `on_commit` hook, deadlocks, as for
    /// [`Self::flush`].
    ///
    /// For the chain's periodic UTXO cache flush, which needs its rows on
    /// disk within the interval but need not wait for them there.
    pub fn flush_in_background(&self) -> Result<(), Error> {
        self.check_open()?;
        self.inner.check_writable()?;
        let writer = self.exclusive_writer();
        // As in `flush`: the transaction or the commit waited out may be
        // the one that latched the store.
        drain_flight(&self.inner);
        self.inner.check_writable()?;
        let retired = flush_locked(&self.inner, FlushKind::Requested);
        drop(writer);
        retired.map(drop)
    }

    /// A mark covering every transaction committed on this database so
    /// far, by this handle or any clone of it, the caller's last commit
    /// included ([`CommitMark`]).
    pub fn commit_mark(&self) -> CommitMark {
        CommitMark(
            self.inner
                .cache
                .lock()
                .expect("cache lock poisoned")
                .commits(),
        )
    }

    /// Whether every transaction `mark` covers is in a durable commit of
    /// the store: a flush that captured all of them has made its redb
    /// commit, `Durability::Immediate`, and retired what it captured.
    ///
    /// One atomic read; it waits for nothing.  With
    /// [`Options::background_commit`] a mark can turn durable at any
    /// moment after a commit has tripped a flush or
    /// [`Self::flush_in_background`] has returned; without it, only
    /// during a call that flushes.  `false` for good once the store has
    /// latched, for a mark that the last flush to land did not cover.
    pub fn is_durable(&self, mark: CommitMark) -> bool {
        self.inner.durable_through.load(Ordering::SeqCst) >= mark.0
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
    /// takes its file lock before any block file is touched, so the refusal
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

        // `close` flushes, marks the handle closed and closes the metadata
        // file, releasing its lock, as dcrd's `Close` closes leveldb
        // (`ffldb/dbcache.go:635-639`) -- once no transaction begun
        // before it is still open, since redb's file stays open under
        // one.  A clone of the closed handle does not hold the lock.
        let reader = first.begin(false).expect("begin a reader");
        first.close().expect("close");
        assert_eq!(
            Database::open(&opts).err().map(|e| e.kind),
            Some(ErrorKind::DbAlreadyOpen),
            "the file stays open, and locked, under a reader begun before the close"
        );
        reader.rollback().expect("end the reader");
        let reopened = Database::open(&opts).expect("reopen once the last reader has ended");
        reopened.close().expect("close again");
        drop(first);
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
    /// (`required_order = ceil_log2`, redb-4.3.0 `page_manager.rs:2217`),
    /// so a single row too large to share a leaf can occupy 2, 4 or 32
    /// pages and still be counted once. Not overflow pages: redb has no
    /// such mechanism in 2.6.3, 4.1.0 or 4.3.0. See
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
    /// latch. That wiring is two sites: every durable flush
    /// (`Database::flush`, `Database::close`, and the flush inside
    /// `Transaction::commit_internal`) goes through `flush_locked`,
    /// whose `finish` latches a failure before the writer semaphore is
    /// released, or, for a commit handed to a thread of its own, on that
    /// thread before anything else; and `Database::close` latches a
    /// failure of its allocator-state commit
    /// (`record_allocator_state`). `tests/enospc.rs` closes that gap,
    /// for a commit on either thread: it fills a 2 MiB filesystem under
    /// a live database and asserts that the resulting `ENOSPC` arrives
    /// as an error, latches the store, and leaves reads working. It is
    /// Linux-only and skips
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
        // wrong place -- and names the first failure, not a later one.
        db.inner
            .mark_fatal(db_error(ErrorKind::DriverSpecific, "a later failure"));
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
            assert!(
                got.description
                    .ends_with("restart (the first failure: simulated write failure)"),
                "{what}: {got}"
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

    /// Shutdown does not get one last flush past the latch.
    ///
    /// `close` flushes the write cache, and the cache still holds the
    /// dirty set the failed durable write left behind -- so without the
    /// check it is a retry, and a retry that reports `Ok` is exactly the
    /// sequence `mark_fatal` exists to prevent, arriving at the moment
    /// its answer is least likely to be questioned.  dcrd has no latch
    /// to respect, but it does mark the handle closed even when the
    /// cache close fails (`ffldb/db.go:1978-1989`), so the ordering
    /// here matches: closed first, then refuse.
    #[test]
    fn close_refuses_to_flush_a_latched_handle() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let opts = Options::new(tmp.path().join("blocks_redb"), 0x0709_1101);
        let db = Database::create(&opts).expect("create");

        db.inner.mark_fatal(db_error(
            ErrorKind::DriverSpecific,
            "simulated write failure",
        ));

        assert_eq!(
            db.close().unwrap_err().kind,
            ErrorKind::Fatal,
            "close must not flush a latched cache"
        );
        // Still idempotent: the handle was marked closed regardless.
        assert_eq!(
            db.close().unwrap_err().kind,
            ErrorKind::DbNotOpen,
            "the handle is closed even though the flush was refused"
        );
    }
}

/// A flush that passed its `closed` check and then lost the writer to a
/// close (see the comment in `Database::flush`).  The semaphore on Linux
/// wakes its waiters in order, so `tests/review_close_race.rs` meets
/// only the flush-first order; this runs the flush's locked half by hand
/// after the close instead.
// Copies the files of a store that is still open, which Windows refuses:
// redb holds a byte-range lock on its file while the database is open.
#[cfg(all(test, not(windows)))]
mod late_flush_tests {
    use super::*;

    #[test]
    fn a_flush_that_runs_after_close_commits_nothing() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let path = tmp.path().join("db");
        let db = Database::create(&Options::new(&path, 0x12141c16)).expect("create");
        let raw = vec![7u8; 256];
        let hash = dcroxide_chainhash::hash_h(&raw[..180]);
        db.update(|tx| {
            tx.store_block_raw(&hash, raw.clone())?;
            tx.metadata().put(b"k", b"v")
        })
        .expect("write");
        db.close().expect("close");

        // What `flush` runs once it holds the writer.
        {
            let _writer = db.exclusive_writer();
            db.inner.check_writable().expect("not latched");
            flush_locked(&db.inner, FlushKind::Durable)
                .expect("the late flush succeeds, as dcrd's does");
        }

        // It committed nothing, so the allocator state `close` recorded
        // still stands: a copy of the store opens without redb's repair.
        let copy = tmp.path().join("copy");
        std::fs::create_dir_all(&copy).expect("mkdir copy");
        for entry in std::fs::read_dir(&path).expect("read db dir") {
            let entry = entry.expect("dir entry");
            std::fs::copy(entry.path(), copy.join(entry.file_name())).expect("copy");
        }
        let lines: Arc<Mutex<Vec<String>>> = Arc::default();
        let keep = Arc::clone(&lines);
        let mut opts = Options::new(&copy, 0x12141c16);
        opts.log = Some(Arc::new(move |_, msg: &str| {
            keep.lock().expect("log lock").push(msg.to_string());
        }));
        let reopened = Database::open(&opts).expect("open the copy");
        let lines = lines.lock().expect("log lock");
        assert!(
            !lines
                .iter()
                .any(|msg| msg.to_lowercase().contains("metadata store")),
            "a flush after the close must leave no repair to do: {lines:?}"
        );
        reopened
            .view(|tx| {
                assert_eq!(tx.metadata().get(b"k").as_deref(), Some(b"v".as_slice()));
                let height = transaction::serialized_block_height(&raw).expect("a header");
                assert!(tx.has_block(&hash, height)?);
                Ok(())
            })
            .expect("view");
        drop(db);
    }
}

/// The parts of a handed-over commit (`Options::background_commit`) that
/// only a seam inside the crate can reach: a reader placed between the
/// commit and the retirement, a commit made to land between a reader's
/// two snapshots, a thread the system refuses, a capture made without the
/// wait before it, a retirement that finds the pinned layers changed, a
/// commit thread that panics before it retires or between flushes, each
/// of the two looks a commit takes at the latch on its own, which thread
/// syncs the block files, and the commit thread's life: when it starts,
/// what stops it, and that it lets go of the store before a flush's end
/// is signalled.  What can be shown from outside is in
/// `tests/background_commit.rs`.
#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic over small counts"
)]
mod background_commit_tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use dcroxide_testutil::gate::GateBackend;
    use dcroxide_testutil::powerloss::PowerLossBackend;

    use super::*;

    const NET: u32 = 0x1214_1c16;

    /// The overlay's maximum: one [`fill`] arms the next commit's flush.
    const CACHE_MAX: u64 = 64 * 1024;

    /// Longer than anything here takes.
    const NEVER: Duration = Duration::from_secs(60);

    /// A store with background commits on, over storage that can hold the
    /// committer thread and lose power, and every flush it observed and
    /// every line it logged.
    struct Rig {
        dir: tempfile::TempDir,
        db: Database,
        power: Arc<PowerLossBackend>,
        gate: Arc<GateBackend>,
        seen: Arc<Mutex<Vec<FlushObservation>>>,
        /// The thread each observation in `seen` was made on.
        threads: Arc<Mutex<Vec<std::thread::ThreadId>>>,
        log: Arc<Mutex<Vec<(LogLevel, String)>>>,
    }

    impl Rig {
        fn new() -> Rig {
            Rig::with_page_cache(DEFAULT_DB_CACHE_BYTES)
        }

        /// A rig whose redb page cache is `db_cache_bytes`.
        fn with_page_cache(db_cache_bytes: usize) -> Rig {
            Rig::build(db_cache_bytes, true)
        }

        /// A rig with background commits off: every flush commits on the
        /// thread that runs it.
        fn inline() -> Rig {
            Rig::build(DEFAULT_DB_CACHE_BYTES, false)
        }

        fn build(db_cache_bytes: usize, background: bool) -> Rig {
            assert_eq!(
                COMMIT_THREAD_NAME,
                dcroxide_testutil::gate::COMMITTER_THREAD_NAME,
                "the gate holds the thread the database names"
            );
            let dir = tempfile::tempdir().expect("temp dir");
            let db_dir = dir.path().join("db");
            std::fs::create_dir_all(&db_dir).expect("mkdir");
            let power = PowerLossBackend::create(&db_dir.join(METADATA_FILE), true);
            let gate = GateBackend::new(Arc::clone(&power) as SharedBackend);
            let mut opts = Options::new(&db_dir, NET);
            opts.backend = Some(Arc::clone(&gate) as SharedBackend);
            opts.background_commit = background;
            opts.cache_max_size = CACHE_MAX;
            opts.db_cache_bytes = db_cache_bytes;
            let seen: Arc<Mutex<Vec<FlushObservation>>> = Arc::default();
            let threads: Arc<Mutex<Vec<std::thread::ThreadId>>> = Arc::default();
            {
                let seen = Arc::clone(&seen);
                let threads = Arc::clone(&threads);
                opts.flush_observer = Some(Arc::new(move |obs: &FlushObservation| {
                    // One lock order, so the two lists stay in step.
                    let mut seen = seen.lock().expect("observations");
                    threads
                        .lock()
                        .expect("threads")
                        .push(std::thread::current().id());
                    seen.push(*obs);
                }));
            }
            let log: Arc<Mutex<Vec<(LogLevel, String)>>> = Arc::default();
            let lines = Arc::clone(&log);
            opts.log = Some(Arc::new(move |level: LogLevel, msg: &str| {
                lines.lock().expect("log").push((level, msg.to_string()));
            }));
            let db = Database::create(&opts).expect("create");
            db.update(|tx| tx.metadata().create_bucket(b"rows").map(|_| ()))
                .expect("the bucket");
            db.flush().expect("flush");
            seen.lock().expect("observations").clear();
            threads.lock().expect("threads").clear();
            Rig {
                dir,
                db,
                power,
                gate,
                seen,
                threads,
                log,
            }
        }

        /// Forget the observations so far.
        fn forget_observations(&self) {
            let mut seen = self.seen.lock().expect("observations");
            self.threads.lock().expect("threads").clear();
            seen.clear();
        }

        /// Each observation so far with the thread it was made on.
        fn observed(&self) -> Vec<(std::thread::ThreadId, FlushObservation)> {
            let seen = self.seen.lock().expect("observations");
            let threads = self.threads.lock().expect("threads");
            threads.iter().copied().zip(seen.iter().copied()).collect()
        }

        /// Trip a flush with a fill under `tag` and a small commit under
        /// `tag + 1`, and wait for it to end.
        fn trip(&self, tag: u8) {
            self.fill(tag);
            self.small(tag + 1)
                .expect("the commit that trips the flush");
            self.db.wait_background_commit().expect("the flush landed");
        }

        /// The error lines logged so far.
        fn error_lines(&self) -> Vec<String> {
            self.log
                .lock()
                .expect("log")
                .iter()
                .filter(|(level, _)| *level == LogLevel::Error)
                .map(|(_, msg)| msg.clone())
                .collect()
        }

        /// Commit 48 rows of a kibibyte under `tag` ([`fill`]).
        fn fill(&self, tag: u8) {
            fill(&self.db, tag);
        }

        /// Commit one small row under `tag` ([`small`]).
        fn small(&self, tag: u8) -> Result<(), Error> {
            small(&self.db, tag)
        }

        /// Commit a fill under `tag`, shut the gate, and commit a small
        /// row under `tag + 1`, whose flush check captures the fill and
        /// hands its commit over: on return the committer is held at its
        /// first write.
        fn hold_a_commit(&self, tag: u8) {
            self.fill(tag);
            self.gate.arm();
            self.small(tag + 1)
                .expect("the commit that trips the flush");
            assert!(self.gate.wait_held(NEVER), "the commit is under way");
            assert!(
                !self.gate.holds_a_length_change(),
                "the commit was stopped growing the file, where no transaction can begin beside it"
            );
        }

        /// The keys a reader finds under the bucket, in order, each with
        /// the first byte of its value.
        fn rows(tx: &Transaction) -> Vec<(Vec<u8>, u8)> {
            let mut found = Vec::new();
            tx.metadata()
                .bucket(b"rows")
                .expect("bucket")
                .for_each(|key, value| {
                    found.push((key.to_vec(), value[0]));
                    Ok(())
                })
                .expect("scan");
            found
        }

        /// Wait for any commit under way, let go of the store without
        /// closing it, lose power, and reopen the file alone.
        fn crash_and_reopen(self) -> (tempfile::TempDir, Database) {
            let Rig { dir, db, power, .. } = self;
            let _ = db.wait_background_commit();
            *db.inner.before_retire.lock().expect("test hook poisoned") = None;
            drop(db);
            power.cut_power();
            let reopened =
                Database::open(&Options::new(dir.path().join("db"), NET)).expect("reopen");
            (dir, reopened)
        }

        /// Create a bucket for a participant's rows and make it durable;
        /// its id is the participant's prefix.
        fn journal_prefix(&self) -> [u8; 4] {
            let mut prefix = [0u8; 4];
            self.db
                .update(|tx| {
                    prefix = tx.metadata().create_bucket(b"journal")?.raw_id();
                    Ok(())
                })
                .expect("the journal bucket");
            self.db.flush().expect("flush");
            self.forget_observations();
            prefix
        }

        /// The bytes in the store's block files.
        ///
        /// Each file's size is read from the file itself: on Windows a
        /// directory entry's metadata is what the directory recorded,
        /// which can lag behind a file the store still holds open.
        fn block_file_bytes(&self) -> u64 {
            std::fs::read_dir(self.dir.path().join("db"))
                .expect("the database directory")
                .map(|entry| entry.expect("an entry").path())
                .filter(|path| path.extension().is_some_and(|e| e == "fdb"))
                .map(|path| std::fs::metadata(&path).expect("metadata").len())
                .sum()
        }
    }

    /// Commit 48 rows of a kibibyte under `tag` to `db`'s bucket `rows`:
    /// enough to arm the next commit's flush, and too little to trip this
    /// one's over an empty overlay.
    fn fill(db: &Database, tag: u8) {
        db.update(|tx| {
            let rows = tx.metadata().bucket(b"rows").expect("bucket");
            for i in 0..48u8 {
                rows.put(&[tag, i], &[tag; 1024])?;
            }
            Ok(())
        })
        .expect("fill");
    }

    /// Commit one small row under `tag` to `db`'s bucket `rows`.
    fn small(db: &Database, tag: u8) -> Result<(), Error> {
        db.update(|tx| {
            tx.metadata()
                .bucket(b"rows")
                .expect("bucket")
                .put(&[tag, 0xff], &[tag])
        })
    }

    /// A participant that allows its `contribute` and `finished` to be
    /// deferred, writes one row in every flush, asks for a flush when a
    /// test says so, and records its seals and contributes, how each flush
    /// ended and whether the store was latched by then.
    struct Asker {
        /// The store, for its latch; not a handle, which a participant
        /// must not keep.
        store: std::sync::Weak<DbInner>,
        want: AtomicBool,
        /// Calls of `seal` and of `contribute` so far.
        seals: AtomicU64,
        contributes: AtomicU64,
        /// `(committed, latched)` for each `finished`, in order.
        finished: Mutex<Vec<(bool, bool)>>,
    }

    impl Asker {
        fn new(db: &Database) -> Arc<Asker> {
            Arc::new(Asker {
                store: Arc::downgrade(&db.inner),
                want: AtomicBool::new(false),
                seals: AtomicU64::new(0),
                contributes: AtomicU64::new(0),
                finished: Mutex::default(),
            })
        }

        fn finished(&self) -> Vec<(bool, bool)> {
            self.finished.lock().expect("finished").clone()
        }

        /// `(seals, contributes)` so far.
        fn calls(&self) -> (u64, u64) {
            (
                self.seals.load(Ordering::SeqCst),
                self.contributes.load(Ordering::SeqCst),
            )
        }
    }

    impl FlushParticipant for Asker {
        fn wants_flush(&self) -> bool {
            self.want.load(Ordering::SeqCst)
        }

        fn has_work(&self) -> bool {
            true
        }

        fn seal(&self) {
            self.seals.fetch_add(1, Ordering::SeqCst);
        }

        fn contribute(&self, w: &mut FlushWriter<'_, '_>) -> Result<ParticipantStats, Error> {
            self.contributes.fetch_add(1, Ordering::SeqCst);
            let mut key = w.prefix().to_vec();
            key.push(b'K');
            w.insert(&key, b"")?;
            Ok(ParticipantStats::default())
        }

        fn finished(&self, committed: bool) {
            let latched = self
                .store
                .upgrade()
                .is_some_and(|inner| inner.fatal.load(Ordering::SeqCst));
            self.finished
                .lock()
                .expect("finished")
                .push((committed, latched));
        }

        fn allows_deferred_contribute(&self) -> bool {
            true
        }
    }

    /// A reader that begins after a handed-over commit has landed and
    /// before its layers are retired holds both: the overlay with the
    /// captured rows and a store that has them too.  It sees each row
    /// once, with the value the batch gave it, and a row the batch
    /// deleted not at all; and so does it still after the retirement,
    /// with the layers gone from the overlay under it.
    #[test]
    fn a_reader_between_the_commit_and_its_retirement_sees_the_captured_rows_once() {
        let rig = Rig::new();
        // Durable before the batch: one row it will rewrite and one it
        // will delete.
        rig.db
            .update(|tx| {
                let rows = tx.metadata().bucket(b"rows").expect("bucket");
                rows.put(&[0, 1], &[0xaa])?;
                rows.put(&[0, 2], &[0xbb])
            })
            .expect("the earlier rows");
        rig.db.flush().expect("flush");
        rig.forget_observations();

        // The batch: the fill, a rewrite and a delete.
        rig.db
            .update(|tx| {
                let rows = tx.metadata().bucket(b"rows").expect("bucket");
                for i in 0..48u8 {
                    rows.put(&[1, i], &[1; 1024])?;
                }
                rows.put(&[0, 1], &[0xcc])?;
                rows.delete(&[0, 2])
            })
            .expect("the batch");

        // Hold the committer between its commit and the retirement.
        let (reached, at_hook) = mpsc::channel();
        let (go, resume) = mpsc::channel::<()>();
        let resume = Mutex::new(resume);
        *rig.db
            .inner
            .before_retire
            .lock()
            .expect("test hook poisoned") = Some(Box::new(move || {
            let _ = reached.send(());
            let _ = resume.lock().expect("resume").recv_timeout(NEVER);
        }));
        rig.small(2).expect("the commit that trips the flush");
        at_hook
            .recv_timeout(NEVER)
            .expect("the commit landed and its thread is at the hook");
        assert!(
            rig.seen.lock().expect("observations").is_empty(),
            "nothing is retired yet"
        );

        let mut expected: Vec<(Vec<u8>, u8)> = vec![(vec![0, 1], 0xcc)];
        expected.extend((0..48u8).map(|i| (vec![1, i], 1)));
        expected.push((vec![2, 0xff], 2));
        let reader = rig.db.begin(false).expect("begin a reader");
        assert_eq!(
            Rig::rows(&reader),
            expected,
            "between the commit and the retirement"
        );

        go.send(()).expect("let the committer retire");
        rig.db.wait_background_commit().expect("the flush ended");
        assert_eq!(rig.seen.lock().expect("observations").len(), 1);
        assert_eq!(
            Rig::rows(&reader),
            expected,
            "the same reader, after the retirement"
        );
        reader.rollback().expect("end the reader");
        let later = rig.db.begin(false).expect("begin a reader");
        assert_eq!(Rig::rows(&later), expected, "a reader of the store alone");
        later.rollback().expect("end the reader");

        let (_dir, reopened) = rig.crash_and_reopen();
        let durable = reopened.begin(false).expect("begin a reader");
        expected.pop();
        assert_eq!(
            Rig::rows(&durable),
            expected,
            "the batch is durable, the commit that tripped it is not"
        );
        durable.rollback().expect("end the reader");
        reopened.close().expect("close");
    }

    /// A flush's commit can land between the two snapshots a beginning
    /// transaction takes; its retirement cannot.  The overlay's snapshot
    /// is taken first and the store's second, under one hold of the cache
    /// lock, which a retirement needs.  So a reader that begins across a
    /// commit has the batch in both, and reads each row once.  It never
    /// has a store from before the commit under an overlay from after the
    /// retirement, which would hold the batch in neither.
    ///
    /// The committer is held at its first write until the reader has its
    /// first snapshot, and the reader then waits where it is for the
    /// commit to land and, for a moment, for a retirement that must not
    /// come.
    #[test]
    fn a_commit_that_lands_inside_a_begin_is_retired_only_after_it() {
        let rig = Rig::new();
        rig.hold_a_commit(1);

        // The committer says when its commit has landed.
        let (landed, has_landed) = mpsc::channel();
        *rig.db
            .inner
            .before_retire
            .lock()
            .expect("test hook poisoned") = Some(Box::new(move || {
            let _ = landed.send(());
        }));
        let retired_inside = Arc::new(AtomicBool::new(false));
        {
            let gate = Arc::clone(&rig.gate);
            let seen = Arc::clone(&rig.seen);
            let has_landed = Mutex::new(has_landed);
            let retired_inside = Arc::clone(&retired_inside);
            *rig.db
                .inner
                .between_snapshots
                .lock()
                .expect("test hook poisoned") = Some(Box::new(move || {
                gate.open();
                has_landed
                    .lock()
                    .expect("landed")
                    .recv_timeout(NEVER)
                    .expect("the commit landed");
                let deadline = std::time::Instant::now() + Duration::from_millis(300);
                while std::time::Instant::now() < deadline {
                    if !seen.lock().expect("observations").is_empty() {
                        retired_inside.store(true, Ordering::SeqCst);
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }));
        }

        let reader = rig.db.begin(false).expect("begin a reader");
        assert!(
            !retired_inside.load(Ordering::SeqCst),
            "a flush was retired between a reader's two snapshots"
        );
        let mut expected: Vec<(Vec<u8>, u8)> = (0..48u8).map(|i| (vec![1, i], 1)).collect();
        expected.push((vec![2, 0xff], 2));
        assert_eq!(
            Rig::rows(&reader),
            expected,
            "a reader that began across the commit"
        );
        rig.db.wait_background_commit().expect("the flush ended");
        assert_eq!(rig.seen.lock().expect("observations").len(), 1);
        assert_eq!(
            Rig::rows(&reader),
            expected,
            "the same reader, after the retirement"
        );
        reader.rollback().expect("end the reader");

        let (_dir, reopened) = rig.crash_and_reopen();
        let durable = reopened.begin(false).expect("begin a reader");
        expected.pop();
        assert_eq!(
            Rig::rows(&durable),
            expected,
            "the batch is durable, the commit that tripped it is not"
        );
        durable.rollback().expect("end the reader");
        reopened.close().expect("close");
    }

    /// When the system has no thread to give, the flush is not lost: the
    /// same transaction commits on the thread that tripped it, before the
    /// tripping commit returns, and the observation says so.
    #[test]
    fn a_refused_commit_thread_commits_inline() {
        let rig = Rig::new();
        rig.db
            .inner
            .refuse_commit_thread
            .store(true, Ordering::SeqCst);
        rig.fill(1);
        // Were the commit handed over after all, it would be held.
        rig.gate.arm();
        rig.small(2).expect("the commit that trips the flush");
        {
            let seen = rig.seen.lock().expect("observations");
            assert_eq!(
                seen.len(),
                1,
                "the flush had ended when the commit that tripped it returned"
            );
            assert!(!seen[0].background && !seen[0].explicit, "{:?}", seen[0]);
            assert_eq!(seen[0].foreground, seen[0].elapsed);
        }
        assert!(
            rig.db
                .inner
                .flight
                .lock()
                .expect("flight slot poisoned")
                .is_none(),
            "nothing is in flight"
        );
        assert!(!rig.gate.is_held() && !rig.db.is_fatal());

        let (_dir, reopened) = rig.crash_and_reopen();
        let durable = reopened.begin(false).expect("begin a reader");
        assert_eq!(
            Rig::rows(&durable).len(),
            48,
            "the batch was committed and synced"
        );
        durable.rollback().expect("end the reader");
        reopened.close().expect("close");
    }

    /// A flush `Database::flush_in_background` asks for whose thread the
    /// system refuses is not lost either: it was to be handed over, and
    /// took the read snapshot a handed-over commit holds, but commits on
    /// the calling thread before the call returns, so the mark taken
    /// before the call is durable when it returns.
    #[test]
    fn a_requested_flush_whose_thread_is_refused_commits_before_it_returns() {
        let rig = Rig::new();
        rig.db
            .inner
            .refuse_commit_thread
            .store(true, Ordering::SeqCst);
        rig.fill(1);
        let mark = rig.db.commit_mark();
        assert!(!rig.db.is_durable(mark));
        // Were the commit handed over after all, it would be held.
        rig.gate.arm();
        rig.db.flush_in_background().expect("the requested flush");
        assert!(
            rig.db.is_durable(mark),
            "the flush had not landed when the call returned"
        );
        {
            let seen = rig.seen.lock().expect("observations");
            assert_eq!(seen.len(), 1, "{seen:?}");
            assert!(
                !seen[0].background && !seen[0].explicit && seen[0].snapshot,
                "{:?}",
                seen[0]
            );
            assert_eq!(seen[0].foreground, seen[0].elapsed);
        }
        assert!(
            rig.db
                .inner
                .flight
                .lock()
                .expect("flight slot poisoned")
                .is_none(),
            "nothing is in flight"
        );
        assert!(!rig.gate.is_held() && !rig.db.is_fatal());

        let (_dir, reopened) = rig.crash_and_reopen();
        let durable = reopened.begin(false).expect("begin a reader");
        assert_eq!(
            Rig::rows(&durable).len(),
            48,
            "the batch was committed and synced"
        );
        durable.rollback().expect("end the reader");
        reopened.close().expect("close");
    }

    /// A capture made while a flush is in flight is refused, and latches
    /// the store, in a build of any kind: the wait that precedes every
    /// capture is all that keeps two flushes from being captured at
    /// once, so this is what a capture without it does.  The commit that
    /// attempted it fails unapplied; the flush in flight is untouched and
    /// lands.
    #[test]
    fn a_capture_during_a_flight_is_refused_and_the_flight_lands() {
        let rig = Rig::new();
        rig.hold_a_commit(1);
        // Arms the next commit's flush, with the first still in flight.
        rig.fill(3);
        rig.db.inner.skip_drain.store(true, Ordering::SeqCst);
        // On a thread: a capture that was not refused would go on to
        // open a second write transaction, and wait for the held one.
        let attempt = {
            let (done, result) = mpsc::channel();
            let db = rig.db.clone();
            std::thread::spawn(move || {
                let outcome = db.update(|tx| {
                    tx.metadata()
                        .bucket(b"rows")
                        .expect("bucket")
                        .put(&[4, 0xff], &[4])
                });
                drop(db);
                let _ = done.send(outcome);
            });
            result
        };
        let err = attempt
            .recv_timeout(Duration::from_secs(10))
            .expect("a capture made during a flight went ahead and is waiting on it")
            .expect_err("a second capture");
        assert!(
            err.description
                .contains("a flush was captured while another was in flight"),
            "{err}"
        );
        assert!(rig.db.is_fatal(), "the refusal latched the store");
        rig.db.inner.skip_drain.store(false, Ordering::SeqCst);
        let refused = rig.small(5).expect_err("a write on a latched store");
        assert_eq!(refused.kind, ErrorKind::Fatal, "{refused}");
        assert!(
            refused
                .description
                .contains("the first failure: a flush was captured while another was in flight"),
            "{refused}"
        );
        assert!(
            rig.seen.lock().expect("observations").is_empty(),
            "the flight is still held"
        );

        rig.gate.open();
        let settled = rig.db.wait_background_commit().expect_err("latched");
        assert_eq!(settled.kind, ErrorKind::Fatal);
        {
            let seen = rig.seen.lock().expect("observations");
            assert_eq!(seen.len(), 1, "the flight landed and was retired");
            assert!(seen[0].background, "{:?}", seen[0]);
        }
        let reader = rig.db.begin(false).expect("begin a reader");
        let tags: std::collections::BTreeSet<u8> =
            Rig::rows(&reader).iter().map(|(key, _)| key[0]).collect();
        assert_eq!(
            tags.into_iter().collect::<Vec<_>>(),
            vec![1, 2, 3],
            "the refused commit published nothing"
        );
        reader.rollback().expect("end the reader");

        let (_dir, reopened) = rig.crash_and_reopen();
        let durable = reopened.begin(false).expect("begin a reader");
        let rows = Rig::rows(&durable);
        assert_eq!(rows.len(), 48, "exactly the flight's batch: {rows:?}");
        assert!(rows.iter().all(|(key, _)| key[0] == 1));
        durable.rollback().expect("end the reader");
        reopened.close().expect("close");
    }

    /// A retirement that finds the overlay's pinned layers are not the
    /// ones the flush captured truncates nothing, puts the flush's bytes
    /// back and latches the store: the commit has landed, but dropping
    /// layers of unknown content could drop rows no commit holds.  A
    /// participant that was sealed is told the flush failed, with the
    /// store already latched: what it holds in memory is not retired on
    /// the word of a flush that did not end as one.
    #[test]
    fn a_retirement_over_changed_layers_latches_and_drops_nothing() {
        let rig = Rig::new();
        let asker = Asker::new(&rig.db);
        let registration = participant::Registration {
            prefix: Arc::from([0u8, 0, 0, 9].as_slice()),
            participant: Arc::clone(&asker) as Arc<dyn FlushParticipant>,
        };
        rig.fill(1);
        let (batch, held) = {
            let mut cache = rig.db.inner.cache.lock().expect("cache lock poisoned");
            let held = cache.overlay_bytes();
            let batch = cache.begin_flush();
            // The same rows in layers of another identity, as a merge
            // across the pin would leave them.
            cache.reidentify_layers_for_test();
            (batch, held)
        };
        let err = finish(
            &rig.db.inner,
            batch,
            Ok(FlushOutcome::for_test()),
            Some(&registration),
            true,
            false,
        )
        .expect_err("the pinned layers changed");
        assert!(
            err.description
                .contains("no longer the ones the flush captured"),
            "{err}"
        );
        assert!(rig.db.is_fatal(), "the refusal latched the store");
        assert_eq!(
            asker.finished(),
            vec![(false, true)],
            "the participant is told the flush failed, after the latch"
        );
        {
            let cache = rig.db.inner.cache.lock().expect("cache lock poisoned");
            assert!(!cache.in_flight(), "the flush is over");
            assert_eq!(cache.overlay_bytes(), held, "the bytes went back");
        }
        let reader = rig.db.begin(false).expect("begin a reader");
        assert_eq!(Rig::rows(&reader).len(), 48, "no row was dropped");
        reader.rollback().expect("end the reader");
        assert!(rig.seen.lock().expect("observations").is_empty());
    }

    /// A commit thread that panics has not ended its flush, and the next
    /// wait for it latches the store, as for any flush that did not end in
    /// a commit.  Here it panics between its commit and the retirement, so
    /// the layers it captured are never retired: they stay published, a
    /// reader still finds every row, and no write, flush or close goes on
    /// from there, nor is a second thread started.  The thread has
    /// unwound, and the close, which joins it, returns the latch's
    /// refusal.  What the commit made durable before the panic is durable.
    ///
    /// Only a build whose panics unwind has this path, which a test build
    /// is; a release build aborts.
    #[test]
    fn a_committer_that_panics_latches_the_store() {
        let rig = Rig::new();
        rig.fill(1);
        *rig.db
            .inner
            .before_retire
            .lock()
            .expect("test hook poisoned") = Some(Box::new(|| {
            panic!("a committer thread that panics, by this test's request")
        }));
        rig.small(2).expect("the commit that trips the flush");
        let end = thread_end(&rig.db);

        let err = rig
            .db
            .wait_background_commit()
            .expect_err("the committer panicked");
        assert_eq!(err.kind, ErrorKind::Fatal, "{err}");
        assert!(
            err.description
                .contains("the first failure: the background commit thread panicked"),
            "{err}"
        );
        assert!(rig.db.is_fatal_settled());
        assert!(
            rig.seen.lock().expect("observations").is_empty(),
            "the flush was never retired"
        );
        let reader = rig.db.begin(false).expect("begin a reader");
        assert_eq!(
            Rig::rows(&reader).len(),
            49,
            "the captured rows and the commit after them are still read"
        );
        reader.rollback().expect("end the reader");
        for refused in [
            rig.small(3).expect_err("a write on a latched store"),
            rig.db.flush().expect_err("a flush on a latched store"),
            rig.db
                .flush_in_background()
                .expect_err("a requested flush on a latched store"),
            rig.db.close().expect_err("a close of a latched store"),
        ] {
            assert_eq!(refused.kind, ErrorKind::Fatal, "{refused}");
            assert!(refused.description.contains("panicked"), "{refused}");
        }
        assert!(
            end.ended.load(Ordering::SeqCst) && end.unwound.load(Ordering::SeqCst),
            "the thread unwound, and the close joined it"
        );
        assert_eq!(
            (slot(&rig.db), started(&rig.db)),
            (Slot::Stopped, 1),
            "no second thread was started on the latched store"
        );

        // Not through `crash_and_reopen`: the panic poisoned the hook's
        // lock, and the close has already joined the thread.
        let Rig { dir, db, power, .. } = rig;
        drop(db);
        power.cut_power();
        let reopened = Database::open(&Options::new(dir.path().join("db"), NET)).expect("reopen");
        let durable = reopened.begin(false).expect("begin a reader");
        let rows = Rig::rows(&durable);
        assert_eq!(rows.len(), 48, "the batch had landed: {rows:?}");
        assert!(rows.iter().all(|(key, _)| key[0] == 1));
        durable.rollback().expect("end the reader");
        reopened.close().expect("close");
    }

    /// A commit looks at the latch before it writes anything.  One that
    /// began on a healthy store and commits after a background commit has
    /// failed is refused there, with no block I/O at all: not a record
    /// written to a block file and rolled back out of it again, which is
    /// what the flush check's own look at the latch would leave.  Seen
    /// through the block store's hook on this thread.
    #[test]
    fn a_commit_on_a_store_latched_since_it_began_writes_no_block_bytes() {
        use std::cell::RefCell;
        use std::rc::Rc;

        let rig = Rig::new();
        rig.hold_a_commit(1);
        let tx = rig
            .db
            .begin(true)
            .expect("begin while the store is healthy");
        tx.metadata()
            .bucket(b"rows")
            .expect("bucket")
            .put(&[3, 0xff], &[3])
            .expect("a row");
        let raw = vec![0x5au8; 300];
        let hash = dcroxide_chainhash::hash_h(&raw[..180]);
        tx.store_block_raw(&hash, raw).expect("a pending block");

        rig.power.power_fails_after(0);
        rig.gate.open();
        let deadline = std::time::Instant::now() + NEVER;
        while !rig.db.is_fatal() {
            assert!(
                std::time::Instant::now() < deadline,
                "the held commit never failed"
            );
            std::thread::sleep(Duration::from_millis(1));
        }

        let seen: Rc<RefCell<Vec<&'static str>>> = Rc::default();
        let log = Rc::clone(&seen);
        crate::blockfile::IO_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |what| log.borrow_mut().push(what)));
        });
        let err = tx.commit().expect_err("a commit on a latched store");
        crate::blockfile::IO_HOOK.with(|hook| *hook.borrow_mut() = None);
        assert_eq!(err.kind, ErrorKind::Fatal, "{err}");
        assert!(err.description.contains("power cut"), "{err}");
        assert!(
            seen.borrow().is_empty(),
            "a commit refused at its start did block I/O: {:?}",
            seen.borrow()
        );
        drop(tx);

        let (_dir, reopened) = rig.crash_and_reopen();
        let durable = reopened.begin(false).expect("begin a reader");
        assert!(Rig::rows(&durable).is_empty(), "the held commit failed");
        durable.rollback().expect("end the reader");
        reopened.close().expect("close");
    }

    /// A commit's flush check looks at the latch again, after the commit
    /// has written its blocks: a background commit can fail between the
    /// commit's first look and that one.  Here it fails while the commit
    /// is writing its block.  The flush that failed was one the
    /// participant asked for, over an overlay far below its trigger, so
    /// the check finds nothing to flush and no commit to wait for, and
    /// only its look at the latch keeps the commit from running its hook
    /// and publishing its rows above a batch the store has lost.  The
    /// block it wrote is rolled back out of the block files.
    #[test]
    fn a_commit_latched_between_its_block_write_and_its_flush_check_is_refused() {
        use std::cell::Cell;
        use std::rc::Rc;

        let rig = Rig::new();
        let prefix = rig.journal_prefix();
        let asker = Asker::new(&rig.db);
        rig.db
            .set_flush_participant(&prefix, Arc::clone(&asker) as Arc<dyn FlushParticipant>)
            .expect("register");
        rig.small(1).expect("a small commit");
        asker.want.store(true, Ordering::SeqCst);
        rig.gate.arm();
        rig.small(2)
            .expect("the commit whose flush the participant asked for");
        assert!(rig.gate.wait_held(NEVER), "the commit is under way");
        asker.want.store(false, Ordering::SeqCst);

        let tx = rig
            .db
            .begin(true)
            .expect("begin while the store is healthy");
        let hook_ran = Arc::new(AtomicBool::new(false));
        {
            let hook_ran = Arc::clone(&hook_ran);
            tx.on_commit(move || hook_ran.store(true, Ordering::SeqCst))
                .expect("a hook");
        }
        tx.metadata()
            .bucket(b"rows")
            .expect("bucket")
            .put(&[3, 0xff], &[3])
            .expect("a row");
        let raw = vec![0x5au8; 300];
        let hash = dcroxide_chainhash::hash_h(&raw[..180]);
        tx.store_block_raw(&hash, raw).expect("a pending block");
        let before = rig.block_file_bytes();
        let published = || {
            rig.db
                .inner
                .cache
                .lock()
                .expect("cache lock poisoned")
                .overlay_bytes()
        };
        let held = published();

        // The held commit fails, and the store latches, inside this
        // commit's write of its block.
        let wrote = Rc::new(Cell::new(false));
        {
            let wrote = Rc::clone(&wrote);
            let power = Arc::clone(&rig.power);
            let gate = Arc::clone(&rig.gate);
            let inner = Arc::clone(&rig.db.inner);
            crate::blockfile::IO_HOOK.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move |what| {
                    if what != "write" || wrote.replace(true) {
                        return;
                    }
                    power.power_fails_after(0);
                    gate.open();
                    let deadline = std::time::Instant::now() + NEVER;
                    while !inner.fatal.load(Ordering::SeqCst) {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "the held commit never failed"
                        );
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }));
            });
        }
        let outcome = tx.commit();
        // The hook holds the store open; let go of it before anything
        // is asserted.
        crate::blockfile::IO_HOOK.with(|hook| *hook.borrow_mut() = None);
        drop(tx);
        assert!(wrote.get(), "the commit wrote its block");
        let err = outcome.expect_err("a commit whose flush check finds the store latched");
        assert_eq!(err.kind, ErrorKind::Fatal, "{err}");
        assert!(
            err.description.contains("(the first failure: ")
                && err.description.contains("power cut"),
            "{err}"
        );
        assert!(
            !hook_ran.load(Ordering::SeqCst),
            "a refused commit ran its hook"
        );
        assert_eq!(
            rig.block_file_bytes(),
            before,
            "a refused commit left block bytes behind"
        );
        rig.db.wait_background_commit().expect_err("latched");
        assert_eq!(
            asker.finished(),
            vec![(false, true)],
            "the failed flush told the participant once, after the latch"
        );
        // The failed flush put back what it had captured, so the write
        // cache holds what it held before the refused commit, and no row
        // of that commit's: not its own, not its block's.
        assert_eq!(published(), held, "a refused commit published its rows");

        let (_dir, reopened) = rig.crash_and_reopen();
        let durable = reopened.begin(false).expect("begin a reader");
        assert!(Rig::rows(&durable).is_empty(), "the held commit failed");
        durable.rollback().expect("end the reader");
        reopened.close().expect("close");
    }

    /// Record the name of the thread that runs each of `db`'s block-file
    /// fsyncs, through the block store's sync hook, which runs on that
    /// thread.
    fn record_sync_threads(db: &Database) -> Arc<Mutex<Vec<Option<String>>>> {
        let seen: Arc<Mutex<Vec<Option<String>>>> = Arc::default();
        let log = Arc::clone(&seen);
        db.inner
            .block_store
            .lock()
            .expect("block store lock poisoned")
            .sync_hook = Some(Arc::new(move |event| {
            if let crate::blockfile::SyncEvent::Fsync(..) = event {
                log.lock()
                    .expect("sync threads")
                    .push(std::thread::current().name().map(String::from));
            }
            Ok(())
        }));
        seen
    }

    /// Store a block and enough rows to arm the next commit's flush.
    fn store_a_block_and_fill(db: &Database) {
        let raw = vec![0x5au8; 300];
        let hash = dcroxide_chainhash::hash_h(&raw[..180]);
        db.update(|tx| {
            tx.store_block_raw(&hash, raw.clone())?;
            let rows = tx.metadata().bucket(b"rows").expect("bucket");
            for i in 0..48u8 {
                rows.put(&[1, i], &[1; 1024])?;
            }
            Ok(())
        })
        .expect("a block and enough rows to arm the flush");
    }

    /// A flush's block files are synced by the thread that commits it.  A
    /// flush handed over is synced on the commit thread, before that
    /// thread's first write to the metadata file and so before its redb
    /// commit: the metadata a handed-over commit makes durable never names
    /// block bytes that are not, and the capturing thread syncs nothing.
    /// A flush that stays on the capturing thread is synced there: one
    /// whose thread the system refuses, one `Database::flush` asks for,
    /// and every flush with background commits off.
    #[test]
    fn a_flush_syncs_its_block_files_on_the_thread_that_commits_it() {
        use std::cell::RefCell;
        use std::rc::Rc;

        let here = std::thread::current().name().map(String::from);
        let committer = Some(COMMIT_THREAD_NAME.to_string());

        // Handed over.
        let rig = Rig::new();
        let synced = record_sync_threads(&rig.db);
        store_a_block_and_fill(&rig.db);
        let seen: Rc<RefCell<Vec<&'static str>>> = Rc::default();
        let log = Rc::clone(&seen);
        crate::blockfile::IO_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |what| log.borrow_mut().push(what)));
        });
        rig.gate.arm();
        rig.small(2).expect("the commit that trips the flush");
        assert!(rig.gate.wait_held(NEVER), "the commit is under way");
        crate::blockfile::IO_HOOK.with(|hook| *hook.borrow_mut() = None);
        assert!(
            !seen.borrow().contains(&"fsync"),
            "the capturing thread synced nothing: {:?}",
            seen.borrow()
        );
        assert_eq!(
            *synced.lock().expect("sync threads"),
            vec![committer],
            "the commit thread synced the block file before its first metadata write"
        );
        rig.gate.open();
        rig.db.wait_background_commit().expect("the commit landed");
        let observed = rig.observed();
        assert!(
            observed.len() == 1 && observed[0].1.background,
            "{observed:?}"
        );
        rig.db.close().expect("close");

        // A thread refused: synced, and committed, here.
        let rig = Rig::new();
        rig.db
            .inner
            .refuse_commit_thread
            .store(true, Ordering::SeqCst);
        let synced = record_sync_threads(&rig.db);
        store_a_block_and_fill(&rig.db);
        rig.small(2).expect("the commit that trips the flush");
        assert_eq!(*synced.lock().expect("sync threads"), vec![here.clone()]);
        assert!(!rig.seen.lock().expect("observations")[0].background);
        rig.db.close().expect("close");

        // `Database::flush`, with background commits on.
        let rig = Rig::new();
        let synced = record_sync_threads(&rig.db);
        store_a_block_and_fill(&rig.db);
        rig.db.flush().expect("flush");
        assert_eq!(*synced.lock().expect("sync threads"), vec![here.clone()]);
        rig.db.close().expect("close");

        // Background commits off.
        let rig = Rig::inline();
        let synced = record_sync_threads(&rig.db);
        store_a_block_and_fill(&rig.db);
        rig.small(2).expect("the commit that trips the flush");
        assert_eq!(*synced.lock().expect("sync threads"), vec![here]);
        rig.db.close().expect("close");
    }

    /// A block handed in laid out as its record
    /// ([`Transaction::store_block_record`]) is written as it stands by
    /// the commit that stores it, on that commit's thread, and synced by
    /// the commit thread before the next flush's commit, as a block the
    /// commit lays out itself is.  Once the handed-over commit has landed,
    /// a power cut leaves the block's row naming the record's bytes.
    #[test]
    fn a_record_handed_in_is_written_as_it_stands_and_synced_before_the_commit() {
        use std::cell::RefCell;
        use std::rc::Rc;

        let rig = Rig::new();
        let synced = record_sync_threads(&rig.db);
        let block: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
        let hash = dcroxide_chainhash::hash_h(&block[..180]);
        let height =
            crate::transaction::serialized_block_height(&block).expect("a header's height");
        let mut buf = vec![0u8; 24];
        buf.extend_from_slice(&block);
        buf.reserve_exact(BlockRecord::SUFFIX_LEN);
        let record = Arc::new(BlockRecord::lay_out(buf, 24, NET).expect("a record"));

        let seen: Rc<RefCell<Vec<&'static str>>> = Rc::default();
        let log = Rc::clone(&seen);
        crate::blockfile::IO_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |what| log.borrow_mut().push(what)));
        });
        rig.db
            .update(|tx| {
                tx.store_block_record(&hash, &record)?;
                let rows = tx.metadata().bucket(b"rows").expect("bucket");
                for i in 0..48u8 {
                    rows.put(&[1, i], &[1; 1024])?;
                }
                Ok(())
            })
            .expect("a record and enough rows to arm the flush");
        assert_eq!(rig.db.records_written_as_laid_out(), 1);
        rig.gate.arm();
        rig.small(2).expect("the commit that trips the flush");
        assert!(rig.gate.wait_held(NEVER), "the commit is under way");
        crate::blockfile::IO_HOOK.with(|hook| *hook.borrow_mut() = None);
        let seen = seen.borrow().clone();
        assert_eq!(
            seen,
            ["write"],
            "this thread wrote the record as it stood, and synced nothing"
        );
        assert_eq!(
            *synced.lock().expect("sync threads"),
            [Some(COMMIT_THREAD_NAME.to_string())],
            "the commit thread synced it before its first metadata write"
        );
        rig.gate.open();
        rig.db.wait_background_commit().expect("the commit landed");

        let (_dir, reopened) = rig.crash_and_reopen();
        let tx = reopened.begin(false).expect("begin a reader");
        assert_eq!(
            tx.fetch_block(&hash, height).expect("the block is durable"),
            block
        );
        tx.rollback().expect("end the reader");
        reopened.close().expect("close");
    }

    /// A bucket is found from the bucket index its transaction began with
    /// (`bucketindex`), and that answer is what a read of the bucket's
    /// index row through the same transaction gives, however a commit
    /// handed to a thread of its own falls around the transaction: begun
    /// before or after a commit made while that commit is held, between
    /// its landing and the retirement of what it captured, after the
    /// retirement, as a writer with buckets of its own staged, and over
    /// the store alone once the power is cut.  The flush changes no
    /// bucket: the buckets its batch created and deleted reached the
    /// index at their own commits, and so did those committed while it
    /// ran, which the power cut takes away again.
    #[test]
    fn a_bucket_lookup_is_the_read_of_its_row_around_a_handed_over_commit() {
        // Each bucket's lookup and the read of its row, which must agree;
        // whether it was found.
        let found = |tx: &Transaction, when: &str| -> Vec<bool> {
            let meta = tx.metadata();
            let mut found = Vec::new();
            let names: [&[u8]; 6] = [b"rows", b"fresh", b"gone", b"kept", b"during", b"staged"];
            for name in names {
                let lookup = meta.bucket(name).map(|b| b.raw_id());
                let row = meta.bucket_from_rows(name).map(|b| b.raw_id());
                assert_eq!(lookup, row, "{when}: {}", String::from_utf8_lossy(name));
                found.push(lookup.is_some());
            }
            let lookup = meta
                .bucket(b"fresh")
                .and_then(|b| b.bucket(b"inner"))
                .map(|b| b.raw_id());
            let row = meta
                .bucket_from_rows(b"fresh")
                .and_then(|b| b.bucket_from_rows(b"inner"))
                .map(|b| b.raw_id());
            assert_eq!(lookup, row, "{when}: fresh/inner");
            found.push(lookup.is_some());
            found
        };
        // rows, fresh, gone, kept, during, staged, fresh/inner
        let before_during = [true, true, false, true, false, false, true];
        let after_during = [true, true, false, false, true, false, true];

        let rig = Rig::new();
        rig.db
            .update(|tx| {
                tx.metadata().create_bucket(b"gone")?;
                tx.metadata().create_bucket(b"kept").map(|_| ())
            })
            .expect("two buckets");
        rig.db.flush().expect("flush");
        rig.forget_observations();
        // The batch creates a bucket with one nested in it and deletes
        // another; the commit that trips its flush is then held.
        rig.db
            .update(|tx| {
                tx.metadata()
                    .create_bucket(b"fresh")?
                    .create_bucket(b"inner")?;
                tx.metadata().delete_bucket(b"gone")
            })
            .expect("the batch's buckets");
        rig.hold_a_commit(1);
        let early = rig.db.begin(false).expect("begin a reader");
        assert_eq!(
            found(&early, "begun while the commit is held"),
            before_during
        );
        // Committed beside the held commit.
        rig.db
            .update(|tx| {
                tx.metadata().create_bucket(b"during")?;
                tx.metadata().delete_bucket(b"kept")
            })
            .expect("buckets changed beside the commit");
        assert_eq!(rig.seen.lock().expect("observations").len(), 0);
        let held = rig.db.begin(false).expect("begin a reader");
        assert_eq!(found(&held, "begun after a commit beside it"), after_during);
        assert_eq!(found(&early, "the first reader again"), before_during);

        // Let the commit land, and hold its thread before the retirement.
        let (reached, at_hook) = mpsc::channel();
        let (go, resume) = mpsc::channel::<()>();
        let resume = Mutex::new(resume);
        *rig.db
            .inner
            .before_retire
            .lock()
            .expect("test hook poisoned") = Some(Box::new(move || {
            let _ = reached.send(());
            let _ = resume.lock().expect("resume").recv_timeout(NEVER);
        }));
        rig.gate.open();
        at_hook
            .recv_timeout(NEVER)
            .expect("the commit landed and its thread is at the hook");
        let landed = rig.db.begin(false).expect("begin a reader");
        assert_eq!(found(&landed, "begun before the retirement"), after_during);
        go.send(()).expect("let the committer retire");
        rig.db.wait_background_commit().expect("the flush ended");
        assert_eq!(rig.seen.lock().expect("observations").len(), 1);

        for (tx, when, expected) in [
            (
                &early,
                "the first reader, after the retirement",
                before_during,
            ),
            (&held, "the second, after it", after_during),
            (&landed, "the third, after it", after_during),
        ] {
            assert_eq!(found(tx, when), expected);
        }
        for tx in [early, held, landed] {
            tx.rollback().expect("end the reader");
        }
        let later = rig.db.begin(false).expect("begin a reader");
        assert_eq!(found(&later, "begun after the retirement"), after_during);
        later.rollback().expect("end the reader");
        let writer = rig.db.begin(true).expect("begin a writer");
        writer
            .metadata()
            .create_bucket(b"staged")
            .expect("create a bucket");
        writer
            .metadata()
            .delete_bucket(b"during")
            .expect("delete one");
        assert_eq!(
            found(&writer, "a writer's own changes"),
            [true, true, false, false, false, true, true]
        );
        writer.rollback().expect("roll the writer back");

        let (_dir, reopened) = rig.crash_and_reopen();
        let durable = reopened.begin(false).expect("begin a reader");
        assert_eq!(
            found(&durable, "the store after the power cut"),
            [true, true, false, true, false, false, true],
            "the batch is durable, and the commit beside it is not"
        );
        durable.rollback().expect("end the reader");
        reopened.close().expect("close");
    }

    /// What the probe in a flush's batch saw as the batch was dropped.
    #[derive(Debug, PartialEq, Eq)]
    struct AtDrop {
        /// The name of the thread that dropped it.
        thread: Option<String>,
        /// The handles left on the layers the test follows.
        handles: usize,
        /// Whether the cache lock was free.
        cache_free: bool,
        /// Whether the end of the flush had been recorded for the next
        /// capture's observation; `None` when that record's lock was held.
        end_recorded: Option<bool>,
    }

    /// Plant a probe in every batch the flushes of `db` capture from now
    /// on, which records what it sees of `layers` and of the store as the
    /// batch is dropped.
    fn probe_batch_drops(
        db: &Database,
        layers: Vec<std::sync::Weak<crate::dbcache::CacheLayer>>,
    ) -> Arc<Mutex<Vec<AtDrop>>> {
        let seen: Arc<Mutex<Vec<AtDrop>>> = Arc::default();
        let sink = Arc::clone(&seen);
        let store = Arc::downgrade(&db.inner);
        *db.inner.batch_dropped.lock().expect("test hook poisoned") = Some(Arc::new(move || {
            let Some(inner) = store.upgrade() else {
                return;
            };
            let at = AtDrop {
                thread: std::thread::current().name().map(str::to_owned),
                handles: layers.iter().map(std::sync::Weak::strong_count).sum(),
                cache_free: inner.cache.try_lock().is_ok(),
                end_recorded: inner.flush_end.try_lock().ok().map(|end| end.is_some()),
            };
            sink.lock().expect("drops").push(at);
        }));
        seen
    }

    /// The thread a commit was handed to lets go of the layers it retired
    /// itself, with the cache lock free, and before it reads the process's
    /// memory for the flush's end.  The commit that tripped the flush let
    /// go of its snapshot when it returned, and the retirement unpublished
    /// the layers, so the batch holds the last handles on them.  The probe
    /// runs inside the batch's drop, after those handles have gone: what
    /// it sees is the drop that frees the rows, and so a lock taken around
    /// that drop, or handles kept past it, would show.
    #[test]
    fn a_committer_frees_the_layers_it_retired_unlocked_and_before_its_end_reading() {
        let rig = Rig::new();
        rig.fill(1);
        let captured = rig
            .db
            .inner
            .cache
            .lock()
            .expect("cache")
            .published_layers_for_test();
        assert!(!captured.is_empty(), "the fill is in the overlay");
        let drops = probe_batch_drops(&rig.db, captured.clone());

        // A row whose flush check captures the fill and hands its commit
        // over, which is held at its first write.
        rig.gate.arm();
        rig.small(2).expect("the commit that trips the flush");
        assert!(rig.gate.wait_held(NEVER), "the commit is under way");
        assert!(
            captured.iter().all(|layer| layer.strong_count() > 0),
            "the overlay and the batch hold the captured layers"
        );
        assert!(
            rig.db.inner.flush_end.lock().expect("flush end").is_none(),
            "the capture took the record the flush before it left"
        );
        rig.gate.open();
        rig.db.wait_background_commit().expect("the flush ended");

        let drops = std::mem::take(&mut *drops.lock().expect("drops"));
        assert_eq!(
            drops,
            [AtDrop {
                thread: Some(COMMIT_THREAD_NAME.to_string()),
                handles: 0,
                cache_free: true,
                end_recorded: Some(false),
            }],
            "the committer's drop of the batch freed the layers"
        );
        assert!(
            rig.db.inner.flush_end.lock().expect("flush end").is_some(),
            "the end was recorded after the frees"
        );
        {
            let seen = rig.seen.lock().expect("observations");
            assert_eq!(seen.len(), 1);
            assert!(seen[0].background, "{:?}", seen[0]);
            assert_eq!(
                (seen[0].memory.shared_layers, seen[0].memory.shared_entries),
                (0, 0),
                "nothing but the batch held the layers at the retirement"
            );
        }
        *rig.db
            .inner
            .batch_dropped
            .lock()
            .expect("test hook poisoned") = None;
    }

    /// A handed-over flush's block sync, insert loop and commit are timed,
    /// processor time and I/O, on the thread that made them, at either end
    /// of each.  The capturing thread computes for a while just before, so
    /// a phase timed from its counters to the committer's would show no
    /// time on a processor at all, and the three phases must fit in the
    /// part of the flush that ran after the hand-off.  The committer is
    /// held at its first write until it has surely been switched out,
    /// which has the kernel bring its time on a processor up to date
    /// inside the commit, so a commit timed on the committer shows some.
    #[test]
    fn a_handed_over_commit_is_timed_on_the_thread_that_made_it() {
        /// Compute for `wall` on the calling thread, never sleeping.
        fn compute_for(wall: Duration) -> u64 {
            let began = std::time::Instant::now();
            let mut x = 1u64;
            while began.elapsed() < wall {
                for i in 0..10_000u64 {
                    x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(i);
                    x = std::hint::black_box(x);
                }
            }
            x
        }
        let has = |file: &str| {
            cfg!(target_os = "linux") && Path::new("/proc/thread-self").join(file).exists()
        };
        let nanos = |d: Duration| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);

        let rig = Rig::new();
        rig.fill(1);
        compute_for(Duration::from_millis(200));
        // Switched out, so the kernel brings this thread's times up to
        // date here and none of the computing is counted into the flush's
        // phases, however seldom its tick comes.
        std::thread::sleep(Duration::from_millis(1));
        // Whether the kernel keeps scheduler accounting: one that has the
        // file but does not writes zeros in it.
        let accounted = std::fs::read_to_string("/proc/thread-self/schedstat")
            .ok()
            .and_then(|s| s.split_ascii_whitespace().next()?.parse::<u64>().ok())
            .is_some_and(|on_cpu| on_cpu > 0);
        rig.gate.arm();
        rig.small(2).expect("the commit that trips the flush");
        assert!(rig.gate.wait_held(NEVER), "the commit is under way");
        // Long enough for the committer to be asleep at the gate.
        std::thread::sleep(Duration::from_millis(50));
        rig.gate.open();
        rig.db.wait_background_commit().expect("the flush ended");

        let obs = {
            let seen = rig.seen.lock().expect("observations");
            assert_eq!(seen.len(), 1);
            seen[0]
        };
        assert!(obs.background, "{obs:?}");
        for phase in [obs.block_sync, obs.insert, obs.commit] {
            assert_eq!(
                (phase.read_bytes.is_some(), phase.write_bytes.is_some()),
                (has("io"), has("io")),
                "{phase:?}"
            );
            assert_eq!(
                (phase.utime_ms.is_some(), phase.stime_ms.is_some()),
                (has("stat"), has("stat")),
                "{phase:?}"
            );
            assert_eq!(
                (phase.on_cpu_ns.is_some(), phase.runq_wait_ns.is_some()),
                (has("schedstat"), has("schedstat")),
                "{phase:?}"
            );
        }
        // Each phase's time on a processor fits in the part of the flush
        // that ran on its thread, give or take the tick the kernel's
        // figure can trail by at each end.
        let tick = Duration::from_millis(20);
        assert!(
            obs.commit.on_cpu_ns.unwrap_or(0) <= nanos(obs.commit.elapsed + tick),
            "{:?}",
            obs.commit
        );
        let after_hand_off = obs.elapsed.saturating_sub(obs.foreground);
        assert!(
            obs.block_sync.elapsed + obs.insert.elapsed + obs.commit.elapsed <= after_hand_off,
            "the block sync, the insert loop and the commit ran after the hand-off: {obs:?}"
        );
        assert!(
            obs.block_sync.on_cpu_ns.unwrap_or(0) <= nanos(after_hand_off + tick),
            "{:?} after a hand-off {:?} from the end",
            obs.block_sync,
            after_hand_off
        );
        assert!(
            obs.insert.on_cpu_ns.unwrap_or(0) <= nanos(after_hand_off + tick),
            "{:?} after a hand-off {:?} from the end",
            obs.insert,
            after_hand_off
        );
        if accounted {
            assert!(
                obs.commit.on_cpu_ns.expect("time on a processor") > 0,
                "the committer worked in its commit: {:?}",
                obs.commit
            );
        }
    }

    /// The rows of a flush handed to a thread of its own are written on
    /// that thread, so a storage failure while they go in fails there, and
    /// not in the commit that tripped the flush, which has returned `Ok`.
    /// It latches the store before anything else, is logged once as a
    /// background failure, and the participant, sealed and never reached,
    /// is told `finished(false)`.  The next write is refused with the
    /// failure as its cause, the rows of the failed batch are still read
    /// from the write cache, and the store reopens at the flush before.
    ///
    /// redb's page cache is a small part of the batch here, so the insert
    /// loop writes pages to the file ahead of the commit or grows it: the
    /// power is cut just before the rows go in, and the first of those
    /// operations fails.  A participant that was reached would show the
    /// failure came later, in the commit.
    #[test]
    fn an_insert_that_fails_on_the_commit_thread_latches_and_the_next_write_names_it() {
        let rig = Rig::with_page_cache(64 * 1024);
        let prefix = rig.journal_prefix();
        let asker = Asker::new(&rig.db);
        rig.db
            .set_flush_participant(&prefix, Arc::clone(&asker) as Arc<dyn FlushParticipant>)
            .expect("register");
        rig.fill(1);
        let power = Arc::clone(&rig.power);
        *rig.db.inner.before_fill.lock().expect("test hook poisoned") =
            Some(Box::new(move || power.power_fails_after(0)));
        rig.small(2)
            .expect("the commit that trips the flush returns before the flush's rows go in");
        let err = rig
            .db
            .wait_background_commit()
            .expect_err("the rows had no power to go in with");
        assert_eq!(err.kind, ErrorKind::Fatal, "{err}");
        assert!(
            err.description.contains("(the first failure: ")
                && err.description.contains("power cut"),
            "{err}"
        );
        assert!(rig.power.power_failed());
        assert_eq!(
            asker.calls(),
            (1, 0),
            "sealed under the writer, and the failure came before its contribute"
        );
        assert_eq!(
            asker.finished(),
            vec![(false, true)],
            "told the flush failed, with the store already latched"
        );
        let errors = rig.error_lines();
        assert_eq!(errors.len(), 1, "one line for the failure: {errors:?}");
        assert!(
            errors[0].starts_with("Background commit of the metadata write cache failed: ")
                && errors[0].contains("power cut"),
            "{errors:?}"
        );
        assert!(
            rig.seen.lock().expect("observations").is_empty(),
            "a failed flush is not observed"
        );
        let refused = rig.small(3).expect_err("a write on a latched store");
        assert_eq!(refused.kind, ErrorKind::Fatal, "{refused}");
        assert!(refused.description.contains("power cut"), "{refused}");
        let reader = rig.db.begin(false).expect("begin a reader");
        let tags: std::collections::BTreeSet<u8> =
            Rig::rows(&reader).iter().map(|(key, _)| key[0]).collect();
        assert_eq!(
            tags.into_iter().collect::<Vec<_>>(),
            vec![1, 2],
            "the failed batch and the commit that tripped it are still read"
        );
        reader.rollback().expect("end the reader");

        let (_dir, reopened) = rig.crash_and_reopen();
        let durable = reopened.begin(false).expect("begin a reader");
        assert!(
            Rig::rows(&durable).is_empty(),
            "the store is at the flush before"
        );
        durable.rollback().expect("end the reader");
        reopened.close().expect("close");
    }

    /// The backstop against an overlay row under the participant's prefix
    /// is on the thread that captured the flush, before anything is handed
    /// over: the commit that tripped the flush is refused with it, the
    /// store latches, the participant is neither sealed nor written to and
    /// is owed nothing, and no committer thread is made, so no background
    /// failure is logged.  No public path makes such a row; it is put into
    /// the overlay directly.  A debug build stops at the backstop's
    /// assertion, on the capturing thread; a release build fails the flush
    /// there.
    #[test]
    fn an_overlay_row_under_the_prefix_fails_the_tripping_commit_before_the_hand_off() {
        let rig = Rig::new();
        let prefix = rig.journal_prefix();
        let asker = Asker::new(&rig.db);
        rig.db
            .set_flush_participant(&prefix, Arc::clone(&asker) as Arc<dyn FlushParticipant>)
            .expect("register");
        {
            let mut cache = rig.db.inner.cache.lock().expect("cache lock poisoned");
            let mut puts = std::collections::BTreeMap::new();
            puts.insert([prefix.as_slice(), b"x"].concat(), b"shadow".to_vec());
            cache.commit_pending(puts, std::iter::empty());
            // Every commit's check trips a flush from here on.
            cache.set_limits(1, crate::dbcache::DEFAULT_FLUSH_SECS);
        }
        // Were the flush handed over after all, its commit would be held.
        rig.gate.arm();
        let outcome = {
            let _writer = rig.db.exclusive_writer();
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                flush_locked(&rig.db.inner, FlushKind::Commit)
            }))
        };
        match outcome {
            Err(panic) => {
                let text = panic.downcast_ref::<String>().cloned().unwrap_or_default();
                if !cfg!(debug_assertions) {
                    panic!("only a debug build stops at the assertion, and this one did: {text}");
                }
                assert!(
                    text.contains("an overlay row lies under the flush participant's prefix"),
                    "{text}"
                );
            }
            Ok(result) => {
                let err = result.expect_err("the backstop refuses the flush");
                assert_eq!(err.kind, ErrorKind::IncompatibleValue, "{err}");
                assert!(rig.db.is_fatal(), "the refusal latched the store");
            }
        }
        assert!(
            rig.db
                .inner
                .flight
                .lock()
                .expect("flight slot poisoned")
                .is_none(),
            "no committer thread was made"
        );
        assert_eq!(
            (slot(&rig.db), started(&rig.db)),
            (Slot::NotStarted, 0),
            "nothing was handed over"
        );
        assert!(!rig.gate.is_held());
        assert_eq!(asker.calls(), (0, 0), "nothing was sealed or written");
        assert!(
            asker.finished().is_empty(),
            "a participant never sealed is owed nothing"
        );
        assert!(rig.error_lines().is_empty(), "{:?}", rig.error_lines());
        assert!(rig.seen.lock().expect("observations").is_empty());
        rig.gate.open();
    }

    // -----------------------------------------------------------------
    // The commit thread's life
    // -----------------------------------------------------------------

    /// Where a store's commit thread is, as a test sees it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Slot {
        NotStarted,
        Running(std::thread::ThreadId),
        Stopped,
    }

    /// Where `db`'s commit thread is.
    fn slot(db: &Database) -> Slot {
        match &db
            .inner
            .committer
            .lock()
            .expect("commit thread slot poisoned")
            .state
        {
            CommitState::NotStarted => Slot::NotStarted,
            CommitState::Running(running) => Slot::Running(running.id),
            CommitState::Stopped => Slot::Stopped,
        }
    }

    /// The record of how `db`'s running commit thread ends.
    fn thread_end(db: &Database) -> Arc<ThreadEnd> {
        match &db
            .inner
            .committer
            .lock()
            .expect("commit thread slot poisoned")
            .state
        {
            CommitState::Running(running) => Arc::clone(&running.end),
            _ => panic!("no commit thread is running"),
        }
    }

    /// How many commit threads `db` has started.
    fn started(db: &Database) -> u64 {
        db.inner.commit_threads_started.load(Ordering::SeqCst)
    }

    /// Wait for `flag` to be set, for at most [`NEVER`]; whether it was.
    fn wait_set(flag: &AtomicBool) -> bool {
        let deadline = std::time::Instant::now() + NEVER;
        while !flag.load(Ordering::SeqCst) {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        true
    }

    /// A store with background commits on and the overlay's maximum of a
    /// [`Rig`], on a file of its own at `path`, which redb locks while the
    /// store is open, and its bucket `rows` durable.
    fn file_store(path: &Path) -> Database {
        let mut opts = Options::new(path, NET);
        opts.background_commit = true;
        opts.cache_max_size = CACHE_MAX;
        let db = Database::create(&opts).expect("create");
        db.update(|tx| tx.metadata().create_bucket(b"rows").map(|_| ()))
            .expect("the bucket");
        db.flush().expect("flush");
        db
    }

    /// How many rows `db` holds under `tag` in its bucket `rows`.
    fn rows_under(db: &Database, tag: u8) -> usize {
        let tx = db.begin(false).expect("begin a reader");
        let found = Rig::rows(&tx)
            .iter()
            .filter(|(key, _)| key[0] == tag)
            .count();
        tx.rollback().expect("end the reader");
        found
    }

    /// The commit thread is started by the first flush handed to it: not
    /// by the open, and not by a flush made on the thread that asked for
    /// it.  It is then kept, and every later flush handed over runs on it.
    /// A start the system refuses leaves the slot as it was, the flush
    /// commits on the thread that tripped it, and the next hand-off starts
    /// the thread.
    #[test]
    fn the_commit_thread_is_started_by_the_first_hand_off() {
        let rig = Rig::new();
        assert_eq!(
            (slot(&rig.db), started(&rig.db)),
            (Slot::NotStarted, 0),
            "the open started a thread"
        );
        rig.small(1).expect("a small commit");
        rig.db.flush().expect("an explicit flush");
        assert_eq!(
            (slot(&rig.db), started(&rig.db)),
            (Slot::NotStarted, 0),
            "a flush that is never handed over started a thread"
        );
        rig.forget_observations();

        rig.trip(2);
        let observed = rig.observed();
        assert_eq!(observed.len(), 1, "{observed:?}");
        let (id, first) = observed[0];
        assert!(first.background, "{first:?}");
        assert_ne!(id, std::thread::current().id());
        assert_eq!(
            (slot(&rig.db), started(&rig.db)),
            (Slot::Running(id), 1),
            "the first hand-off started the thread its flush ran on"
        );
        for tag in (4..24u8).step_by(2) {
            rig.trip(tag);
        }
        let observed = rig.observed();
        assert_eq!(observed.len(), 11, "{observed:?}");
        assert!(
            observed
                .iter()
                .all(|(thread, obs)| *thread == id && obs.background),
            "a flush ran on another thread: {observed:?}"
        );
        assert_eq!((slot(&rig.db), started(&rig.db)), (Slot::Running(id), 1));
        rig.db.close().expect("close");

        // The first start refused.
        let rig = Rig::new();
        rig.db
            .inner
            .refuse_commit_thread
            .store(true, Ordering::SeqCst);
        rig.trip(1);
        let observed = rig.observed();
        assert_eq!(observed.len(), 1, "{observed:?}");
        assert!(!observed[0].1.background, "{observed:?}");
        assert_eq!(observed[0].0, std::thread::current().id());
        assert_eq!(
            (slot(&rig.db), started(&rig.db)),
            (Slot::NotStarted, 0),
            "a refused start is not recorded"
        );
        rig.db
            .inner
            .refuse_commit_thread
            .store(false, Ordering::SeqCst);
        rig.trip(3);
        let observed = rig.observed();
        assert_eq!(observed.len(), 2, "{observed:?}");
        let (id, second) = observed[1];
        assert!(second.background, "{second:?}");
        assert_ne!(id, std::thread::current().id());
        assert_eq!(
            (slot(&rig.db), started(&rig.db)),
            (Slot::Running(id), 1),
            "the next hand-off started the thread"
        );
        rig.db.close().expect("close");
    }

    /// The close stops the commit thread and joins it: the thread has
    /// ended, without a panic, by the time the close returns, and no flush
    /// starts another.  So it has on a store a failed commit latched, whose
    /// close returns the latch's refusal.
    #[test]
    fn close_ends_the_commit_thread() {
        let rig = Rig::new();
        rig.trip(1);
        let end = thread_end(&rig.db);
        assert!(
            !end.ended.load(Ordering::SeqCst),
            "the thread waits for the next flush"
        );
        rig.db.close().expect("close");
        assert!(
            end.ended.load(Ordering::SeqCst) && !end.unwound.load(Ordering::SeqCst),
            "the close returned with the commit thread alive"
        );
        assert_eq!((slot(&rig.db), started(&rig.db)), (Slot::Stopped, 1));

        // Latched by a power cut under the commit.
        let rig = Rig::new();
        rig.hold_a_commit(1);
        let end = thread_end(&rig.db);
        rig.power.power_fails_after(0);
        rig.gate.open();
        let err = rig.db.close().expect_err("a close of a latched store");
        assert_eq!(err.kind, ErrorKind::Fatal, "{err}");
        assert!(err.description.contains("power cut"), "{err}");
        assert!(
            end.ended.load(Ordering::SeqCst) && !end.unwound.load(Ordering::SeqCst),
            "the close of a latched store returned with the commit thread alive"
        );
        assert_eq!((slot(&rig.db), started(&rig.db)), (Slot::Stopped, 1));
        assert_eq!(rig.error_lines().len(), 1, "{:?}", rig.error_lines());
    }

    /// The drop of the last handle stops the commit thread as the close
    /// does, so that no thread is left behind a store nobody can reach.
    ///
    /// Dropped while the thread is asleep, the store joins it: the thread
    /// has ended when the drop returns, and redb has let go of the store's
    /// file, which opens again at once.
    ///
    /// Dropped while a flush is under way, the handle is not the store's
    /// last: the flush holds the store until it has ended, so the drop
    /// returns at once and the commit lands when it is let go.  The store
    /// is then dropped on the commit thread, which cannot join itself and
    /// lets itself go instead: it ends at its next wait for a flush,
    /// without a panic, and the flush it wrote is durable.
    #[test]
    fn dropping_the_last_handle_ends_the_commit_thread() {
        // Asleep.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("db");
        let db = file_store(&path);
        fill(&db, 1);
        small(&db, 2).expect("the commit that trips the flush");
        db.wait_background_commit().expect("the flush landed");
        let end = thread_end(&db);
        assert!(!end.ended.load(Ordering::SeqCst));
        drop(db);
        assert!(
            end.ended.load(Ordering::SeqCst) && !end.unwound.load(Ordering::SeqCst),
            "the drop of the last handle returned with the commit thread alive"
        );
        let reopened = Database::open(&Options::new(&path, NET))
            .expect("the store's file is free once the last handle is dropped");
        assert_eq!(rows_under(&reopened, 1), 48, "the flush landed");
        reopened.close().expect("close");

        // A flush under way.
        let rig = Rig::new();
        rig.hold_a_commit(1);
        let end = thread_end(&rig.db);
        let Rig {
            dir,
            db,
            power,
            gate,
            seen,
            ..
        } = rig;
        drop(db);
        assert!(gate.is_held(), "the drop waited for the commit under way");
        assert!(!end.ended.load(Ordering::SeqCst));
        gate.open();
        assert!(
            wait_set(&end.ended),
            "the commit thread outlived the store it was the last to hold"
        );
        assert!(
            !end.unwound.load(Ordering::SeqCst),
            "the commit thread panicked letting itself go"
        );
        assert_eq!(
            seen.lock().expect("observations").len(),
            1,
            "the flush landed"
        );
        power.cut_power();
        let reopened = Database::open(&Options::new(dir.path().join("db"), NET)).expect("reopen");
        assert_eq!(rows_under(&reopened, 1), 48, "the batch is durable");
        assert_eq!(
            rows_under(&reopened, 2),
            0,
            "the commit that tripped it was never flushed"
        );
        reopened.close().expect("close");
    }

    /// The end of a flush is signalled only after the commit thread has
    /// let go of the store.  A caller whose wait for the flush has
    /// returned holds the last handle, so dropping it closes the store and
    /// the store's file opens again at once.  The thread lingers for a
    /// while just before it lets go of the store: were the end signalled
    /// before that, the wait would return while the thread still held the
    /// store, and the open would meet redb's lock on the file.
    #[test]
    fn a_wait_returns_only_after_the_commit_thread_let_go_of_the_store() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("db");
        let db = file_store(&path);
        *db.inner.before_release.lock().expect("test hook poisoned") =
            Some(Box::new(|| std::thread::sleep(Duration::from_millis(200))));
        fill(&db, 1);
        small(&db, 2).expect("the commit that trips the flush");
        db.wait_background_commit().expect("the flush landed");
        assert!(
            db.inner
                .before_release
                .lock()
                .expect("test hook poisoned")
                .is_none(),
            "the flush was handed over, and its thread lingered"
        );
        drop(db);
        let reopened = Database::open(&Options::new(&path, NET))
            .expect("the commit thread held the store after its flush's end was signalled");
        assert_eq!(rows_under(&reopened, 1), 48, "the flush landed");
        reopened.close().expect("close");
    }

    /// A flush that fails on the commit thread latches the store and
    /// leaves the thread asleep, for the close to stop: the latch refuses
    /// every later capture, so nothing reaches the thread again, and no
    /// other is started.  The power is cut just before the rows go in,
    /// as in the test of an insert that fails on the commit thread.
    #[test]
    fn a_failure_on_the_commit_thread_latches_and_leaves_the_thread_for_close() {
        let rig = Rig::with_page_cache(64 * 1024);
        let prefix = rig.journal_prefix();
        let asker = Asker::new(&rig.db);
        rig.db
            .set_flush_participant(&prefix, Arc::clone(&asker) as Arc<dyn FlushParticipant>)
            .expect("register");
        rig.fill(1);
        let power = Arc::clone(&rig.power);
        *rig.db.inner.before_fill.lock().expect("test hook poisoned") =
            Some(Box::new(move || power.power_fails_after(0)));
        rig.small(2)
            .expect("the commit that trips the flush returns before the flush's rows go in");
        let end = thread_end(&rig.db);
        let err = rig
            .db
            .wait_background_commit()
            .expect_err("the rows had no power to go in with");
        assert_eq!(err.kind, ErrorKind::Fatal, "{err}");
        assert!(err.description.contains("power cut"), "{err}");
        let errors = rig.error_lines();
        assert_eq!(errors.len(), 1, "one line for the failure: {errors:?}");
        assert!(
            errors[0].starts_with("Background commit of the metadata write cache failed: "),
            "{errors:?}"
        );
        let refused = rig.small(3).expect_err("a write on a latched store");
        assert_eq!(refused.kind, ErrorKind::Fatal, "{refused}");
        assert!(refused.description.contains("power cut"), "{refused}");
        assert_eq!(
            rig.db
                .flush_in_background()
                .expect_err("a requested flush on a latched store")
                .kind,
            ErrorKind::Fatal
        );
        assert!(
            !end.ended.load(Ordering::SeqCst),
            "the thread survives a failed flush"
        );
        assert!(matches!(slot(&rig.db), Slot::Running(_)));
        assert_eq!(started(&rig.db), 1);

        let err = rig.db.close().expect_err("a close of a latched store");
        assert_eq!(err.kind, ErrorKind::Fatal, "{err}");
        assert!(err.description.contains("power cut"), "{err}");
        assert!(
            end.ended.load(Ordering::SeqCst) && !end.unwound.load(Ordering::SeqCst),
            "the close stopped the thread"
        );
        assert_eq!((slot(&rig.db), started(&rig.db)), (Slot::Stopped, 1));
        assert_eq!(asker.finished(), vec![(false, true)]);
        assert_eq!(rig.error_lines().len(), 1);
    }

    /// With background commits off no flush is handed over, so no commit
    /// thread is ever started: forty flushes, twenty tripped by commits
    /// and twenty asked for, ten of them by `Database::flush` and ten by
    /// `Database::flush_in_background`, all run on the thread that made
    /// them.
    #[test]
    fn sync_commits_start_no_commit_thread() {
        let rig = Rig::inline();
        for round in 0..20u8 {
            let tag = round * 3;
            rig.fill(tag);
            rig.small(tag + 1).expect("the commit that trips a flush");
            rig.small(tag + 2).expect("a small commit");
            if round % 2 == 0 {
                rig.db.flush().expect("an explicit flush");
            } else {
                rig.db.flush_in_background().expect("a requested flush");
            }
        }
        let observed = rig.observed();
        assert_eq!(observed.len(), 40, "{observed:?}");
        let here = std::thread::current().id();
        assert!(
            observed
                .iter()
                .all(|(thread, obs)| *thread == here && !obs.background),
            "a flush left the thread that made it: {observed:?}"
        );
        assert_eq!(
            observed.iter().filter(|(_, obs)| obs.explicit).count(),
            10,
            "{observed:?}"
        );
        assert_eq!((slot(&rig.db), started(&rig.db)), (Slot::NotStarted, 0));
        rig.db.close().expect("close");
        assert_eq!(started(&rig.db), 0);
    }

    /// A flush offered to the commit thread after the close has stopped it
    /// commits on the thread that made it, and no thread is started for
    /// it.  No public call gets a flush there: one made after the close
    /// finds the overlay empty and no participant, and commits nothing,
    /// and once the close has returned the store's redb handle is gone as
    /// well.  Here the thread is stopped as the close stops it, ahead of
    /// its own flush, the store is left open, and a row is put into the
    /// overlay directly.
    #[test]
    fn a_hand_off_after_the_close_stopped_the_thread_commits_inline() {
        let rig = Rig::new();
        rig.trip(1);
        {
            let _writer = rig.db.exclusive_writer();
            drain_flight(&rig.db.inner);
            stop_commit_thread(&rig.db.inner);
        }
        assert_eq!((slot(&rig.db), started(&rig.db)), (Slot::Stopped, 1));
        rig.forget_observations();
        {
            let mut cache = rig.db.inner.cache.lock().expect("cache lock poisoned");
            let mut puts = std::collections::BTreeMap::new();
            puts.insert(
                [METADATA_BUCKET_ID.as_slice(), b"late"].concat(),
                b"row".to_vec(),
            );
            cache.commit_pending(puts, std::iter::empty());
        }
        // Were the flush handed over after all, its commit would be held.
        rig.gate.arm();
        {
            let _writer = rig.db.exclusive_writer();
            flush_locked(&rig.db.inner, FlushKind::Requested)
                .expect("the flush commits on this thread");
        }
        let observed = rig.observed();
        assert_eq!(observed.len(), 1, "{observed:?}");
        let (thread, obs) = observed[0];
        assert!(!obs.background && obs.snapshot, "{obs:?}");
        assert_eq!(thread, std::thread::current().id());
        assert!(!rig.gate.is_held());
        assert!(
            rig.db
                .inner
                .flight
                .lock()
                .expect("flight slot poisoned")
                .is_none(),
            "nothing is in flight"
        );
        assert_eq!((slot(&rig.db), started(&rig.db)), (Slot::Stopped, 1));
        rig.gate.open();
    }

    /// A commit thread that dies between flushes, which only a panic in
    /// its own loop could make it do, is found dead by the next hand-off:
    /// the store latches with the panic as its first cause, the commit
    /// that tripped the flush fails and rolls its block back out of the
    /// block files, the participant, sealed for that flush, is told it
    /// failed, and no second thread is started.  The flush before it ended
    /// and was signalled before the thread died, so the wait for it found
    /// nothing wrong.
    #[test]
    fn a_commit_thread_that_died_between_flights_latches_the_next_hand_off() {
        let rig = Rig::new();
        let prefix = rig.journal_prefix();
        let asker = Asker::new(&rig.db);
        rig.db
            .set_flush_participant(&prefix, Arc::clone(&asker) as Arc<dyn FlushParticipant>)
            .expect("register");
        *rig.db.inner.after_job.lock().expect("test hook poisoned") = Some(Box::new(|| {
            panic!("a commit thread that dies between flushes, by this test's request")
        }));
        rig.fill(1);
        rig.small(2).expect("the commit that trips the flush");
        let end = thread_end(&rig.db);
        rig.db
            .wait_background_commit()
            .expect("the flush ended before the thread died");
        assert!(wait_set(&end.ended), "the thread never died");
        assert!(end.unwound.load(Ordering::SeqCst));
        assert!(!rig.db.is_fatal(), "nothing has looked at the thread since");
        assert_eq!(asker.finished(), vec![(true, false)]);

        rig.fill(3);
        let tx = rig.db.begin(true).expect("begin");
        tx.metadata()
            .bucket(b"rows")
            .expect("bucket")
            .put(&[4, 0xff], &[4])
            .expect("a row");
        let raw = vec![0x5au8; 300];
        let hash = dcroxide_chainhash::hash_h(&raw[..180]);
        let height = transaction::serialized_block_height(&raw).expect("a header");
        tx.store_block_raw(&hash, raw).expect("a pending block");
        let before = rig.block_file_bytes();
        let err = tx
            .commit()
            .expect_err("the commit whose flush found the thread dead");
        assert_eq!(err.kind, ErrorKind::Fatal, "{err}");
        assert!(
            err.description
                .contains("(the first failure: the background commit thread panicked)"),
            "{err}"
        );
        assert_eq!(
            rig.block_file_bytes(),
            before,
            "the failed commit left its block in the block files"
        );
        assert_eq!(
            asker.finished(),
            vec![(true, false), (false, true)],
            "told the flush failed, with the store already latched"
        );
        assert_eq!(asker.calls(), (2, 1), "sealed, and never contributed");
        assert_eq!(
            (slot(&rig.db), started(&rig.db)),
            (Slot::Stopped, 1),
            "a second thread was started"
        );
        let reader = rig.db.begin(false).expect("begin a reader");
        assert!(
            !reader.has_block(&hash, height).expect("a lookup"),
            "the failed commit stored its block"
        );
        reader.rollback().expect("end the reader");
        let refused = rig.small(5).expect_err("a write on a latched store");
        assert!(refused.description.contains("panicked"), "{refused}");
        let err = rig.db.close().expect_err("a close of a latched store");
        assert!(err.description.contains("panicked"), "{err}");
        assert_eq!(started(&rig.db), 1);
    }

    /// Not a check: a look at the allocator's arena mappings over 200
    /// flushes handed to the commit thread, beside a thread that starts a
    /// short-lived thread every 50 ms which allocates and frees a mebibyte
    /// in small pieces, as the daemon's RPC handlers do.  It prints the
    /// mappings at the start and the end.  Its figures say nothing about a
    /// sync.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    #[ignore = "a diagnostic to run by hand, not a check"]
    fn diagnostic_arena_mappings_over_many_handed_over_flushes() {
        let rig = Rig::new();
        let stop = Arc::new(AtomicBool::new(false));
        let churn = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    std::thread::spawn(|| {
                        let pieces: Vec<Vec<u8>> = (0..1024).map(|i| vec![i as u8; 1024]).collect();
                        std::hint::black_box(&pieces);
                    })
                    .join()
                    .expect("a short-lived thread");
                    std::thread::sleep(Duration::from_millis(50));
                }
            })
        };
        let at_start = ProcessMemory::read(true);
        for round in 0..200u32 {
            let tag = u8::try_from(round % 120).expect("small") * 2;
            rig.fill(tag);
            rig.small(tag + 1).expect("the commit that trips the flush");
        }
        rig.db.wait_background_commit().expect("the flushes landed");
        let at_end = ProcessMemory::read(true);
        stop.store(true, Ordering::SeqCst);
        churn.join().expect("the churning thread");
        let arenas = |m: Option<ProcessMemory>| m.and_then(|m| m.arenas);
        eprintln!(
            "arena mappings at the start {:?}, at the end {:?}; commit threads started {}",
            arenas(at_start),
            arenas(at_end),
            started(&rig.db)
        );
        rig.db.close().expect("close");
    }
}

/// `close` releases the flush participant once its final flush is done.
#[cfg(test)]
mod participant_close_tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// Always has work; counts its contributions.
    struct Busy(Arc<AtomicUsize>);

    impl FlushParticipant for Busy {
        fn wants_flush(&self) -> bool {
            false
        }

        fn has_work(&self) -> bool {
            true
        }

        fn contribute(&self, w: &mut FlushWriter<'_, '_>) -> Result<ParticipantStats, Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            let mut key = w.prefix().to_vec();
            key.push(b'M');
            w.insert(&key, b"meta")?;
            Ok(ParticipantStats::default())
        }

        fn finished(&self, _: bool) {}
    }

    /// A flush that passed its `closed` check and then lost the writer to
    /// a close (see `Database::flush`) must commit nothing, as the close
    /// recorded the allocator state after its own flush.  A participant
    /// still registered would hand that flush rows to commit, so the
    /// close releases it.
    #[test]
    fn a_flush_that_runs_after_close_does_not_reach_the_participant() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let db =
            Database::create(&Options::new(tmp.path().join("db"), 0x1214_1c16)).expect("create");
        let calls = Arc::new(AtomicUsize::new(0));
        db.set_flush_participant(&[0, 0, 0, 9], Arc::new(Busy(Arc::clone(&calls))))
            .expect("register");
        db.close().expect("close");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "the close's flush ran it");
        {
            let _writer = db.exclusive_writer();
            db.inner.check_writable().expect("not latched");
            flush_locked(&db.inner, FlushKind::Durable).expect("the late flush succeeds");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the late flush reached a participant the close should have released"
        );
    }
}

/// The redb-error classifier against dcrd's `convertErr` table.
#[cfg(test)]
mod storage_error_tests {
    use super::*;

    /// dcrd's `convertErr` gives corruption its own kind and reads a
    /// closed engine as "not open" (`ffldb/db.go:138-166`); everything
    /// else stays driver-specific.  redb splits its errors across four
    /// types, so the mapping is checked through the two the port
    /// actually receives -- a bare `StorageError` and the `CommitError`
    /// a durable commit returns -- to prove the conversion, not just
    /// the match arms.
    #[test]
    fn redb_errors_carry_dcrds_kinds() {
        let cases: Vec<(redb::StorageError, ErrorKind)> = vec![
            (
                redb::StorageError::Corrupted("bad checksum".to_string()),
                ErrorKind::Corruption,
            ),
            (redb::StorageError::PreviousIo, ErrorKind::Corruption),
            (redb::StorageError::DatabaseClosed, ErrorKind::DbNotOpen),
            (
                redb::StorageError::ValueTooLarge(1 << 32),
                ErrorKind::DriverSpecific,
            ),
            (
                redb::StorageError::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
                ErrorKind::DriverSpecific,
            ),
        ];
        for (raw, want) in cases {
            let text = raw.to_string();
            let via_commit = storage_error(redb::CommitError::from(raw)).kind;
            assert_eq!(via_commit, want, "{text}");
        }

        // An aborted repair only exists as a `DatabaseError`, and means
        // the recovery stopped half-done.  It only ever arrives through
        // an open, so it is checked through `open_error`, the classifier
        // the open paths actually call.
        assert_eq!(
            open_error(redb::DatabaseError::RepairAborted).kind,
            ErrorKind::Corruption,
        );

        // The description is redb's own text, unwrapped.
        assert_eq!(
            storage_error(redb::StorageError::Corrupted("bad checksum".to_string())).description,
            "DB corrupted: bad checksum",
        );
    }

    /// Corruption is most often found at open -- header validation and
    /// the repair path -- so the open classifier must give it dcrd's
    /// kind too (`leveldb.OpenFile` failures go through `convertErr`,
    /// `ffldb/db.go:2098-2101`), keeping only its own two special cases.
    #[test]
    fn open_errors_carry_dcrds_kinds() {
        let cases: Vec<(redb::DatabaseError, ErrorKind)> = vec![
            (
                redb::DatabaseError::Storage(redb::StorageError::Corrupted(
                    "Invalid magic number".to_string(),
                )),
                ErrorKind::Corruption,
            ),
            (redb::DatabaseError::RepairAborted, ErrorKind::Corruption),
            (
                redb::DatabaseError::Storage(redb::StorageError::PreviousIo),
                ErrorKind::Corruption,
            ),
            (
                redb::DatabaseError::Storage(redb::StorageError::Io(std::io::Error::from(
                    std::io::ErrorKind::PermissionDenied,
                ))),
                ErrorKind::DriverSpecific,
            ),
            (
                redb::DatabaseError::DatabaseAlreadyOpen,
                ErrorKind::DbAlreadyOpen,
            ),
            (redb::DatabaseError::UpgradeRequired(2), ErrorKind::Invalid),
        ];
        for (raw, want) in cases {
            let text = raw.to_string();
            assert_eq!(open_error(raw).kind, want, "{text}");
        }
    }

    /// A metadata file whose header redb refuses as damaged opens as
    /// `ErrCorruption`, not as a driver-specific failure.
    ///
    /// Only the header past redb's nine-byte magic number is damaged: a
    /// file without the magic is "not a redb database", which redb
    /// reports as an I/O error and which stays driver-specific.
    #[test]
    fn a_damaged_metadata_header_opens_as_corruption() {
        use std::io::{Seek, SeekFrom, Write};

        let tmp = tempfile::tempdir().expect("temp dir");
        let path = tmp.path().join("blocks_redb");
        let opts = Options::new(&path, 0x0709_1101);
        let db = Database::create(&opts).expect("create");
        db.close().expect("close");
        drop(db);

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(path.join(METADATA_FILE))
            .expect("open metadata file");
        file.seek(SeekFrom::Start(9)).expect("seek past the magic");
        file.write_all(&[0xa5u8; 503]).expect("damage the header");
        drop(file);

        let err = match Database::open(&opts) {
            Err(e) => e,
            Ok(_) => panic!("a store with a damaged header must not open"),
        };
        assert_eq!(err.kind, ErrorKind::Corruption, "{err}");
    }

    /// A store whose metadata table was never created -- power lost
    /// between redb initializing the file and `create`'s first commit --
    /// has no write cursor, and dcrd's reconcile reports exactly that as
    /// `ErrCorruption` (`ffldb/reconcile.go:65-69`).
    #[test]
    fn a_store_without_its_metadata_table_reports_a_missing_write_cursor() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let path = tmp.path().join("blocks_redb");
        std::fs::create_dir_all(&path).expect("mkdir");
        drop(redb::Database::create(path.join(METADATA_FILE)).expect("bare redb file"));
        let err = match Database::open(&Options::new(&path, 0x0709_1101)) {
            Err(e) => e,
            Ok(_) => panic!("a store with no write cursor must not open"),
        };
        assert_eq!(err.kind, ErrorKind::Corruption, "{err}");
        assert_eq!(err.description, "write cursor does not exist");
    }
}
