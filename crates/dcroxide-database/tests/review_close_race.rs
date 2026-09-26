// SPDX-License-Identifier: ISC
//! A flush and a close queued together on the writer semaphore.
//!
//! dcrd's `Flush` and `Close` both take `closeLock` exclusively
//! (`database/ffldb/db.go:1972`, `:2013`), and a write transaction holds
//! it shared for its whole life (`:1831`).  Go's `RWMutex.Lock` takes the
//! writer mutex before it waits out readers (`sync/rwmutex.go:150`), so
//! whichever of the two queued first runs first:
//!
//! - a flush queued before a close returns nil, and the close after it
//!   returns nil too;
//! - a flush started once a close has queued waits it out and then
//!   answers `ErrDbNotOpen`.
//!
//! The port decides the order at its `closed` check, before either
//! waits, so the answers match whichever of them the semaphore wakes
//! first.  A flush therefore does not re-check `closed` after waiting,
//! as `begin_seed` does; doing so would answer `DbNotOpen` for the first
//! case, where dcrd answers nil.

use std::time::Duration;

use dcroxide_database::{Database, ErrorKind, Options};
use tempfile::TempDir;

const NET: u32 = 0x12141c16; // simnet magic

/// Poll until `close` has marked the handle closed; it is then queued on
/// the semaphore behind the held writer.
fn wait_until_closed(db: &Database) {
    loop {
        match db.begin(false) {
            Ok(tx) => {
                tx.rollback().expect("rollback");
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => {
                assert_eq!(e.kind, ErrorKind::DbNotOpen, "{e}");
                return;
            }
        }
    }
}

#[test]
fn a_flush_queued_before_a_close_succeeds_as_dcrds_does() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("db");
    let db = Database::create(&Options::new(&path, NET)).expect("create");
    db.update(|tx| tx.metadata().put(b"earlier", b"w"))
        .expect("earlier commit");

    // A writer holds the semaphore, so the flush and the close below
    // both queue behind it.
    let holder = db.begin(true).expect("begin");
    holder.metadata().put(b"held", b"x").expect("put");

    let (started, flush_started) = std::sync::mpsc::channel();
    let flusher = {
        let db = db.clone();
        std::thread::spawn(move || {
            started.send(()).expect("signal");
            db.flush()
        })
    };
    // The flusher is running and about to call `flush`; give it long
    // enough to pass the `closed` check and block on the semaphore,
    // which is the window under test.  Only the few instructions after
    // the signal have to fit, not the thread's start.
    flush_started.recv().expect("flusher started");
    std::thread::sleep(Duration::from_millis(300));

    let closer = {
        let db = db.clone();
        std::thread::spawn(move || db.close())
    };
    wait_until_closed(&db);

    // Release the writer: the flush and the close run in either order.
    // If the flush runs first it commits `earlier`; if the close does,
    // the flush finds nothing left to write.  Either way both succeed.
    holder.rollback().expect("rollback");
    closer.join().expect("closer").expect("close");
    flusher
        .join()
        .expect("flusher")
        .expect("a flush queued before the close must succeed, as dcrd's does");

    // A flush that ran after the close committed nothing, so the
    // allocator state the close recorded still stands: a copy of the
    // store opens without redb's repair, and holds what was committed.
    // (Copying the files of an open store is refused on Windows, where
    // redb holds a byte-range lock on them.)
    #[cfg(not(windows))]
    {
        use std::sync::{Arc, Mutex};

        let copy = dir.path().join("copy");
        std::fs::create_dir_all(&copy).expect("mkdir copy");
        for entry in std::fs::read_dir(&path).expect("read db dir") {
            let entry = entry.expect("dir entry");
            std::fs::copy(entry.path(), copy.join(entry.file_name())).expect("copy");
        }
        let lines: Arc<Mutex<Vec<String>>> = Arc::default();
        let keep = Arc::clone(&lines);
        let mut opts = Options::new(&copy, NET);
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
                assert_eq!(
                    tx.metadata().get(b"earlier").as_deref(),
                    Some(b"w".as_slice())
                );
                assert_eq!(tx.metadata().get(b"held"), None);
                Ok(())
            })
            .expect("view");
    }
    drop(db);
}

#[test]
fn a_flush_after_a_close_has_queued_reports_the_database_closed() {
    let dir = TempDir::new().expect("tempdir");
    let db = Database::create(&Options::new(dir.path().join("db"), NET)).expect("create");
    db.update(|tx| tx.metadata().put(b"earlier", b"w"))
        .expect("earlier commit");

    let holder = db.begin(true).expect("begin");
    let closer = {
        let db = db.clone();
        std::thread::spawn(move || db.close())
    };
    wait_until_closed(&db);

    // dcrd's flush would wait out the close holding `closeLock` and
    // then find `closed` set; the port finds it set straight away.
    let flushed = db.flush();
    assert_eq!(
        flushed.err().map(|e| e.kind),
        Some(ErrorKind::DbNotOpen),
        "a flush started after a close must report the database closed"
    );
    holder.rollback().expect("rollback");
    closer.join().expect("closer").expect("close");
}
