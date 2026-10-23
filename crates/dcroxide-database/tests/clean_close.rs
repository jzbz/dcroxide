// SPDX-License-Identifier: ISC
//! What a close leaves in the metadata store's header.
//!
//! redb sets a recovery flag in the header of its file when it opens the
//! file for writing (redb-4.3.0 `page_manager.rs:1458-1469`, from
//! `db.rs:1672`), and clears it only in the close that runs when its
//! `Database` handle is dropped (`db.rs:1963-2028`,
//! `page_manager.rs:2466-2486`).  A file with the flag set is one whose
//! writer did not shut down: a writable open recovers it, and a read-only
//! open refuses it with "Database repair aborted"
//! (`page_manager.rs:876-879`).
//!
//! The store's close made a quick-repair commit, so that the next open
//! loaded the allocator state instead of repairing the whole file, but it
//! left redb's handle to the drop of the last clone of the store's own
//! handle.  The daemon never dropped that clone: the chain holds one, and
//! the chain sits in a reference cycle (its notification callback holds
//! the notification handler, which holds the transaction pool, which holds
//! the chain).  So the flag stayed set after "Shutdown complete", every
//! start began by recovering the file, and a read-only open of a stopped
//! node's store was refused.  The close now lets go of redb's handle
//! itself.
//!
//! - a clean close clears the flag while a clone of the handle lives on,
//!   with the store set up as the daemon runs it: background commits on,
//!   a commit's flush handed to the commit thread, and a flush
//!   participant registered;
//! - a close made while the commit thread is still committing a flush
//!   waits for that commit, and then clears the flag;
//! - a reader begun before the close reads on after it, and redb closes,
//!   clearing the flag, when that reader ends;
//! - a store stopped without a close keeps the flag, and the next open
//!   repairs it, logging the repair.

// Test-harness arithmetic over small, bounded counts.
#![allow(clippy::arithmetic_side_effects)]

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use dcroxide_database::{
    COMMIT_THREAD_NAME, Database, Error, FlushObservation, FlushParticipant, FlushWriter, LogLevel,
    Options, ParticipantStats, SharedBackend,
};
use dcroxide_testutil::gate::{COMMITTER_THREAD_NAME, GateBackend};
use tempfile::TempDir;

const NET: u32 = 0x12141c16; // simnet magic

/// The metadata store's first repair line, as the operator docs quote it.
const REDB_REPAIR: &str = "Detected unclean shutdown of the metadata store - Repairing...";

/// The overlay's maximum: a commit after a [`fill`] trips a flush.
const CACHE_MAX: u64 = 64 * 1024;

/// Longer than any wait the tests expect to end.
const NEVER: Duration = Duration::from_secs(60);

/// How long a close held behind a commit must go on waiting.
const WATCH: Duration = Duration::from_millis(300);

/// The metadata file of the store at `dir`.
fn metadata_file(dir: &Path) -> PathBuf {
    dir.join("metadata.redb")
}

/// Whether the header of the metadata file at `dir` has redb's recovery
/// flag set: bit 1 of the byte after the nine-byte magic number
/// (redb-4.3.0 `header.rs:46-62`).
fn recovery_flag(dir: &Path) -> bool {
    let header = std::fs::read(metadata_file(dir)).expect("read the metadata file");
    header[9] & 0b10 != 0
}

/// A participant that writes one row in every flush it is asked into,
/// standing in for the chain's UTXO cache.
struct Rows {
    prefix: Vec<u8>,
    pending: AtomicBool,
}

impl FlushParticipant for Rows {
    fn wants_flush(&self) -> bool {
        false
    }

    fn has_work(&self) -> bool {
        self.pending.load(Ordering::SeqCst)
    }

    fn contribute(&self, w: &mut FlushWriter<'_, '_>) -> Result<ParticipantStats, Error> {
        let mut key = self.prefix.clone();
        key.extend_from_slice(b"utxo");
        w.insert(&key, b"row")?;
        Ok(ParticipantStats::default())
    }

    fn finished(&self, committed: bool) {
        if committed {
            self.pending.store(false, Ordering::SeqCst);
        }
    }

    fn allows_deferred_contribute(&self) -> bool {
        true
    }
}

/// Commit enough rows under `tag` to arm the next commit's flush.
fn fill(db: &Database, tag: u8) {
    db.update(|tx| {
        let bucket = tx.metadata();
        for i in 0..48u32 {
            let mut key = vec![b'f', tag];
            key.extend_from_slice(&i.to_be_bytes());
            bucket.put(&key, &[tag; 1024])?;
        }
        Ok(())
    })
    .expect("fill");
}

/// A store opened as the daemon opens it, with a participant registered
/// and a flush already made by the commit thread; the names of the
/// threads that made each flush so far.
fn daemon_like(dir: &Path) -> (Database, Arc<Mutex<Vec<Option<String>>>>) {
    daemon_like_on(dir, None)
}

/// [`daemon_like`], over `backend` when one is given.
fn daemon_like_on(
    dir: &Path,
    backend: Option<SharedBackend>,
) -> (Database, Arc<Mutex<Vec<Option<String>>>>) {
    let threads: Arc<Mutex<Vec<Option<String>>>> = Arc::default();
    let mut opts = Options::new(dir, NET);
    opts.backend = backend;
    opts.background_commit = true;
    opts.cache_max_size = CACHE_MAX;
    {
        let threads = Arc::clone(&threads);
        opts.flush_observer = Some(Arc::new(move |_: &FlushObservation| {
            let name = std::thread::current().name().map(str::to_string);
            threads.lock().expect("thread list").push(name);
        }));
    }
    let db = Database::create(&opts).expect("create");
    let mut prefix = Vec::new();
    db.update(|tx| {
        prefix = tx.metadata().create_bucket(b"utxoset")?.raw_id().to_vec();
        Ok(())
    })
    .expect("the participant's bucket");
    db.flush().expect("flush the bucket");
    let rows = Arc::new(Rows {
        prefix: prefix.clone(),
        pending: AtomicBool::new(true),
    });
    db.set_flush_participant(&prefix, rows as Arc<dyn FlushParticipant>)
        .expect("register the participant");
    fill(&db, 1);
    // This commit's flush check captures the fill and hands its commit
    // to the commit thread.
    db.update(|tx| tx.metadata().put(b"tripped", b"x"))
        .expect("the commit that trips the flush");
    db.wait_background_commit().expect("the handed-over flush");
    assert!(
        threads
            .lock()
            .expect("thread list")
            .iter()
            .any(|name| name.as_deref() == Some(COMMIT_THREAD_NAME)),
        "no flush was made on the commit thread: {:?}",
        threads.lock().expect("thread list")
    );
    // And something for the close's own flush to write.
    db.update(|tx| tx.metadata().put(b"last", b"y"))
        .expect("a commit left to the close");
    (db, threads)
}

/// The daemon's close: its handle is closed while a clone, the one its
/// chain holds, lives on to the end of the process.  The flag must be
/// clear by then, and redb must open the file read-only.
#[test]
fn a_clean_close_clears_the_recovery_flag_while_a_clone_lives_on() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("db");
    let (db, threads) = daemon_like(&path);
    let held = db.clone();
    let flushes_before_close = threads.lock().expect("thread list").len();

    db.close().expect("close");
    drop(db);
    assert!(
        threads.lock().expect("thread list").len() > flushes_before_close,
        "the close made no flush of its own"
    );

    // The process ends here, with `held` still alive.
    assert!(
        !recovery_flag(&path),
        "a clean close left redb's recovery flag set"
    );
    let read_only = redb::ReadOnlyDatabase::open(metadata_file(&path))
        .expect("redb opens a cleanly closed store read-only");
    drop(read_only);

    // What was written is there, and nothing needed repairing.
    let lines: Arc<Mutex<Vec<String>>> = Arc::default();
    let mut opts = Options::new(&path, NET);
    {
        let lines = Arc::clone(&lines);
        opts.log = Some(Arc::new(move |_, msg: &str| {
            lines.lock().expect("log lock").push(msg.to_string());
        }));
    }
    let reopened = Database::open(&opts).expect("reopen while the old clone lives");
    reopened
        .view(|tx| {
            let meta = tx.metadata();
            assert_eq!(meta.get(b"tripped").as_deref(), Some(b"x".as_slice()));
            assert_eq!(meta.get(b"last").as_deref(), Some(b"y".as_slice()));
            Ok(())
        })
        .expect("view");
    reopened.close().expect("close the reopened store");
    assert!(
        !lines
            .lock()
            .expect("log lock")
            .iter()
            .any(|msg| msg.to_lowercase().contains("metadata store")),
        "a cleanly closed store was repaired: {:?}",
        lines.lock().expect("log lock")
    );
    assert!(!recovery_flag(&path));
    drop(held);
}

/// A close made while the commit thread is still committing a flush, as
/// the daemon's can be when its last commits tripped one: the close waits
/// for that commit, and then leaves the file clean, with the held flush's
/// rows in it.
#[test]
fn a_close_with_a_flush_still_committing_waits_for_it_and_clears_the_flag() {
    assert_eq!(
        COMMIT_THREAD_NAME, COMMITTER_THREAD_NAME,
        "the gate holds the thread the database names"
    );
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("db");
    std::fs::create_dir_all(&path).expect("mkdir");
    // redb's own file backend, the one its `create` opens, behind a gate
    // that can hold the commit thread's writes.
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(metadata_file(&path))
        .expect("open the metadata file");
    let gate = GateBackend::new(Arc::new(
        redb::backends::FileBackend::new(file).expect("redb's file backend"),
    ));
    let (db, threads) = daemon_like_on(&path, Some(Arc::clone(&gate) as SharedBackend));

    fill(&db, 2);
    gate.arm();
    db.update(|tx| tx.metadata().put(b"held", b"z"))
        .expect("the commit that trips the held flush");
    assert!(
        gate.wait_held(NEVER),
        "the flush's commit is under way on the commit thread"
    );
    let flushes_before_close = threads.lock().expect("thread list").len();

    let (done, closed) = mpsc::channel();
    {
        let db = db.clone();
        std::thread::spawn(move || {
            let _ = done.send(db.close());
        });
    }
    assert!(
        matches!(
            closed.recv_timeout(WATCH),
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "the close returned while the flush it must wait for was held"
    );
    gate.open();
    closed
        .recv_timeout(NEVER)
        .expect("the close returns")
        .expect("close");
    assert_eq!(
        threads.lock().expect("thread list")[flushes_before_close..].first(),
        Some(&Some(COMMIT_THREAD_NAME.to_string())),
        "the held flush ended on the commit thread before the close went on"
    );

    // redb's close let go of the file: the gate's handle is the last.
    assert_eq!(
        Arc::strong_count(&gate),
        1,
        "redb still holds the store's file after the close"
    );
    drop(gate);
    assert!(
        !recovery_flag(&path),
        "a close behind a held commit left redb's recovery flag set"
    );
    drop(
        redb::ReadOnlyDatabase::open(metadata_file(&path))
            .expect("redb opens a cleanly closed store read-only"),
    );

    // The held flush's rows are there, and nothing needed repairing.
    let lines: Arc<Mutex<Vec<String>>> = Arc::default();
    let mut opts = Options::new(&path, NET);
    {
        let lines = Arc::clone(&lines);
        opts.log = Some(Arc::new(move |_, msg: &str| {
            lines.lock().expect("log lock").push(msg.to_string());
        }));
    }
    let reopened = Database::open(&opts).expect("reopen");
    reopened
        .view(|tx| {
            let meta = tx.metadata();
            let mut filled = vec![b'f', 2];
            filled.extend_from_slice(&0u32.to_be_bytes());
            assert_eq!(meta.get(&filled).as_deref(), Some([2u8; 1024].as_slice()));
            assert_eq!(meta.get(b"held").as_deref(), Some(b"z".as_slice()));
            assert_eq!(meta.get(b"last").as_deref(), Some(b"y".as_slice()));
            Ok(())
        })
        .expect("view");
    reopened.close().expect("close the reopened store");
    assert!(
        !lines
            .lock()
            .expect("log lock")
            .iter()
            .any(|msg| msg.to_lowercase().contains("metadata store")),
        "a cleanly closed store was repaired: {:?}",
        lines.lock().expect("log lock")
    );
    assert!(!recovery_flag(&path));
    drop(db);
}

/// A reader begun before the close is not cut off by it: it reads on, and
/// redb's handle closes when the reader ends.  dcrd's `Close` waits for
/// open transactions instead (`ffldb/db.go:1970-1973`); the store's close
/// does not wait, and the file is left to the last of them.
// Reads the header of a file redb still has open, which Windows refuses:
// redb holds a byte-range lock on its file while the database is open.
#[cfg(not(windows))]
#[test]
fn a_reader_open_across_the_close_reads_on_and_the_flag_clears_when_it_ends() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("db");
    let (db, _threads) = daemon_like(&path);
    let reader = db.begin(false).expect("begin a reader");

    db.close().expect("close");
    assert!(
        recovery_flag(&path),
        "redb's handle closed under a reader that was still open"
    );
    assert_eq!(
        reader.metadata().get(b"tripped").as_deref(),
        Some(b"x".as_slice()),
        "the reader still reads"
    );
    assert!(
        redb::ReadOnlyDatabase::open(metadata_file(&path)).is_err(),
        "the store is still open under the reader"
    );

    reader.rollback().expect("end the reader");
    assert!(
        !recovery_flag(&path),
        "the last reader's end left redb's recovery flag set"
    );
    drop(
        redb::ReadOnlyDatabase::open(metadata_file(&path))
            .expect("redb opens the store read-only once the reader has ended"),
    );
    drop(db);
}

/// An unclean stop is unchanged: a store whose writer stopped without a
/// close keeps the flag, redb refuses to open it read-only, and the next
/// open repairs it and logs the repair.
// Copies the files of a store that is still open, which Windows refuses:
// redb holds a byte-range lock on its file while the database is open.
#[cfg(not(windows))]
#[test]
fn an_unclean_stop_keeps_the_flag_and_the_next_open_repairs() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("db");
    let (db, _threads) = daemon_like(&path);
    db.flush().expect("flush");

    // Killed after the flush: no close.
    let copy = dir.path().join("copy");
    std::fs::create_dir_all(&copy).expect("mkdir copy");
    for entry in std::fs::read_dir(&path).expect("read db dir") {
        let entry = entry.expect("dir entry");
        std::fs::copy(entry.path(), copy.join(entry.file_name())).expect("copy");
    }
    assert!(
        recovery_flag(&copy),
        "a store stopped without a close lost redb's recovery flag"
    );
    assert!(
        matches!(
            redb::ReadOnlyDatabase::open(metadata_file(&copy)),
            Err(redb::DatabaseError::RepairAborted)
        ),
        "redb opened a store that needs recovery read-only"
    );

    let lines: Arc<Mutex<Vec<(LogLevel, String)>>> = Arc::default();
    let mut opts = Options::new(&copy, NET);
    {
        let lines = Arc::clone(&lines);
        opts.log = Some(Arc::new(move |level, msg: &str| {
            lines
                .lock()
                .expect("log lock")
                .push((level, msg.to_string()));
        }));
    }
    let reopened = Database::open(&opts).expect("open the copy");
    assert!(
        lines
            .lock()
            .expect("log lock")
            .iter()
            .any(|(level, msg)| *level == LogLevel::Info && msg == REDB_REPAIR),
        "the repair must be logged as {REDB_REPAIR:?}: {:?}",
        lines.lock().expect("log lock")
    );
    reopened
        .view(|tx| {
            assert_eq!(
                tx.metadata().get(b"last").as_deref(),
                Some(b"y".as_slice()),
                "the flushed commit survived the repair"
            );
            Ok(())
        })
        .expect("view");
    reopened.close().expect("close the repaired copy");
    assert!(
        !recovery_flag(&copy),
        "the repaired copy's clean close left the flag set"
    );
    db.close().expect("close");
}
