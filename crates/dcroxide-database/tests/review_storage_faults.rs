// SPDX-License-Identifier: ISC
//! Storage faults under the metadata store, and what each read and
//! write path makes of them.
//!
//! Every test here runs redb over [`FaultyBackend`], an in-memory store
//! that can be told to fail reads or writes and that counts reads, with
//! redb's page cache set to zero.  The zero cache is what makes the
//! faults reachable: a read-cache hit skips redb's failure check
//! (redb-4.3.0 `cached_file.rs:651-659`), so with a warm cache a test
//! would only ever exercise whichever pages it happened not to touch
//! first.  With no room to keep a page, each page a small store spreads
//! across the cache's 131 stripes is evicted as soon as it is read, so
//! every lookup reaches the backend -- except a tree's root, which redb
//! holds for the transaction's life (`Btree::cached_root`).
//!
//! The four findings pinned here:
//!
//! - a read error on a row dcrd keeps in its UTXO backend must come back
//!   as an error, not as a missing row, and a `begin` that cannot open
//!   the metadata table must fail rather than read everything as absent;
//! - a bucket walk must end at a store read error instead of spinning
//!   on redb's repeated `PreviousIo`;
//! - a walk reads each value once, and a cursor delete reads nothing;
//! - a writer queued on the semaphore behind a failing flush is refused
//!   by the fatal latch rather than re-running that flush.

// Test-harness arithmetic over bounded key counts.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use dcroxide_chainhash::{Hash, hash_h};
use dcroxide_database::{Database, ErrorKind, Options, SharedBackend};
use tempfile::TempDir;

const NET: u32 = 0x12141c16; // simnet magic
const BUCKET: &[u8] = b"rows";

/// redb storage that fails on request and counts the reads it serves.
#[derive(Debug)]
struct FaultyBackend {
    inner: redb::backends::InMemoryBackend,
    fail_reads: AtomicBool,
    fail_writes: AtomicBool,
    /// Reads to serve before failing every later one; negative for no
    /// limit.
    reads_left: AtomicI64,
    reads: AtomicU64,
}

impl Default for FaultyBackend {
    fn default() -> FaultyBackend {
        FaultyBackend {
            inner: redb::backends::InMemoryBackend::new(),
            fail_reads: AtomicBool::new(false),
            fail_writes: AtomicBool::new(false),
            reads_left: AtomicI64::new(-1),
            reads: AtomicU64::new(0),
        }
    }
}

impl FaultyBackend {
    fn injected(what: &str) -> std::io::Error {
        std::io::Error::other(format!("injected {what} failure"))
    }

    /// Serve `n` more reads, then fail every later one.
    fn allow_reads(&self, n: i64) {
        self.reads_left.store(n, Ordering::SeqCst);
    }

    fn write_fault(&self) -> Result<(), std::io::Error> {
        if self.fail_writes.load(Ordering::SeqCst) {
            return Err(Self::injected("write"));
        }
        Ok(())
    }
}

impl redb::StorageBackend for FaultyBackend {
    fn len(&self) -> Result<u64, std::io::Error> {
        self.inner.len()
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), std::io::Error> {
        if self.fail_reads.load(Ordering::SeqCst) {
            return Err(Self::injected("read"));
        }
        let limited = self
            .reads_left
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| match left {
                0 => None,
                n if n > 0 => Some(n - 1),
                n => Some(n),
            });
        if limited.is_err() {
            return Err(Self::injected("read"));
        }
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.read(offset, out)
    }

    fn set_len(&self, len: u64) -> Result<(), std::io::Error> {
        self.write_fault()?;
        self.inner.set_len(len)
    }

    fn sync_data(&self) -> Result<(), std::io::Error> {
        self.write_fault()?;
        self.inner.sync_data()
    }

    fn write(&self, offset: u64, data: &[u8]) -> Result<(), std::io::Error> {
        self.write_fault()?;
        self.inner.write(offset, data)
    }
}

/// A database over a fresh [`FaultyBackend`] with no page cache.
fn faulty_db(configure: impl FnOnce(&mut Options)) -> (TempDir, Arc<FaultyBackend>, Database) {
    let dir = TempDir::new().expect("tempdir");
    let backend = Arc::new(FaultyBackend::default());
    let mut opts = Options::new(dir.path().join("db"), NET);
    opts.db_cache_bytes = 0;
    opts.backend = Some(Arc::clone(&backend) as SharedBackend);
    configure(&mut opts);
    let db = Database::create(&opts).expect("create");
    (dir, backend, db)
}

fn key(i: u32) -> Vec<u8> {
    i.to_be_bytes().to_vec()
}

fn value(i: u32, generation: u8) -> Vec<u8> {
    let mut v = vec![generation; 16];
    v[..4].copy_from_slice(&i.to_be_bytes());
    v
}

/// Create the bucket and put `0..rows` into it, then push it all down
/// to redb so every row is store-resident.
fn fill_store(db: &Database, rows: u32) {
    db.update(|tx| {
        let bucket = tx.metadata().create_bucket(BUCKET)?;
        for i in 0..rows {
            bucket.put(&key(i), &value(i, 0))?;
        }
        Ok(())
    })
    .expect("fill");
    db.flush().expect("flush to the store");
}

/// dcrd's UTXO backend `Get` returns `nil` only for `ErrNotFound` and
/// propagates every other error; the chain reads those rows through
/// `Bucket::try_get`, which must do the same.  `Bucket::get` keeps
/// ffldb's error-as-absence answer (`dbCacheSnapshot.Get`), because the
/// rest of the ffldb-layout store is dcrd's metadata database.
#[test]
fn a_utxo_row_read_error_is_an_error_not_a_missing_row() {
    let (_dir, backend, db) = faulty_db(|_| {});
    // Enough rows that the table's root is a branch: redb keeps each
    // tree's root page for the transaction's life (`Btree::cached_root`),
    // so only a page beneath it can fail.
    fill_store(&db, 2000);

    db.view(|tx| {
        let bucket = tx.metadata().bucket(BUCKET).expect("bucket");
        assert_eq!(bucket.try_get(&key(7)), Ok(Some(value(7, 0))));
        assert_eq!(
            bucket.try_get(&key(1_000_000)),
            Ok(None),
            "absence is still Ok(None)"
        );

        backend.fail_reads.store(true, Ordering::SeqCst);
        let err = bucket
            .try_get(&key(7))
            .expect_err("a failed read must not answer as a missing row");
        assert_eq!(err.kind, ErrorKind::DriverSpecific, "{err}");
        // redb has latched the failure, so the next uncached read fails
        // with `PreviousIo` whether or not the disk has recovered.
        backend.fail_reads.store(false, Ordering::SeqCst);
        let err = bucket
            .try_get(&key(1500))
            .expect_err("redb keeps failing uncached reads after one failed");
        assert_eq!(err.kind, ErrorKind::Corruption, "{err}");
        backend.fail_reads.store(true, Ordering::SeqCst);
        assert_eq!(
            bucket.get(&key(7)),
            None,
            "the ffldb-layout read keeps dcrd's error-as-absence answer"
        );
        backend.fail_reads.store(false, Ordering::SeqCst);
        Ok(())
    })
    .expect("view");
}

/// A `begin` whose metadata table cannot be opened used to succeed with
/// no table, so every key of the transaction read as missing.  It must
/// fail, as ffldb's `begin` does when it cannot take its snapshot -- and
/// a writable one must hand the writer semaphore back as `begin` does.
///
/// `begin_read` reads redb's table tree root and `open_table` then the
/// metadata table's root, one page each with no cache; serving exactly
/// one read fails the second, which is the case that was mapped to "no
/// table" (a failing first read already failed the `begin`).
#[test]
fn begin_fails_when_the_metadata_table_cannot_be_opened() {
    for writable in [false, true] {
        let (_dir, backend, db) = faulty_db(|_| {});
        fill_store(&db, 8);

        backend.allow_reads(1);
        let err = db.begin(writable).map(|_| ()).expect_err(
            "a begin that cannot open the table must not hand out one that sees nothing",
        );
        assert_eq!(
            err.kind,
            ErrorKind::DriverSpecific,
            "writable {writable}: {err}"
        );
        backend.allow_reads(-1);

        // The next begin returns rather than waiting forever -- for a
        // writable one, proof the failed begin handed the semaphore
        // back.  It fails too, because redb latched the injected error.
        let again = finishes("a begin after the failed one", move || {
            db.begin(writable).map(|_| ())
        });
        assert_eq!(
            again.map_err(|e| e.kind),
            Err(ErrorKind::Corruption),
            "writable {writable}"
        );
    }
}

/// Run `f` on its own thread and fail if it does not finish: the walks
/// below spun forever on redb's repeated `PreviousIo` before the fix, and
/// a hung test is a worse report than a failed one.
fn finishes<T: Send + 'static>(what: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(60))
        .unwrap_or_else(|_| panic!("{what} did not finish: the walk is spinning"))
}

/// redb's range iterator returns `PreviousIo` on every `next()` once it
/// has failed and never `None` (redb-4.3.0
/// `btree_cursor_range.rs:208-216`), so a walk that skipped errors never
/// ended.  ffldb's cursor ends where its goleveldb iterator goes
/// invalid and carries on with the cached entries, and `ForEach` never
/// asks about the error; the UTXO backend's `FetchStats` does ask, which
/// is what `try_for_each` is for.
#[test]
fn a_walk_ends_at_a_store_read_error_instead_of_spinning() {
    let (_dir, backend, db) = faulty_db(|_| {});
    fill_store(&db, 256);
    // One row only in the cache overlay, past every stored key.
    db.update(|tx| {
        let bucket = tx.metadata().bucket(BUCKET).expect("bucket");
        bucket.put(&key(5000), &value(5000, 9))
    })
    .expect("overlay row");

    let seen = finishes("for_each / cursor under a read fault", {
        let db = db.clone();
        let backend = Arc::clone(&backend);
        move || {
            let mut out = (Vec::new(), Vec::new(), None);
            db.view(|tx| {
                let bucket = tx.metadata().bucket(BUCKET).expect("bucket");
                backend.fail_reads.store(true, Ordering::SeqCst);

                bucket.for_each(|k, v| {
                    out.0.push((k.to_vec(), v.to_vec()));
                    Ok(())
                })?;
                let mut cursor = bucket.cursor();
                let mut ok = cursor.first();
                while ok {
                    out.1.push(cursor.key().expect("key"));
                    ok = cursor.next();
                }
                out.2 = Some(bucket.try_for_each(|_, _| Ok(())));

                backend.fail_reads.store(false, Ordering::SeqCst);
                Ok(())
            })
            .expect("view");
            out
        }
    });

    let (walked, cursored, strict) = seen;
    assert_eq!(
        walked,
        vec![(key(5000), value(5000, 9))],
        "the store stream ends at the error and the overlay carries on"
    );
    assert_eq!(cursored, vec![key(5000)], "the cursor ends the same way");
    // `PreviousIo` by now: the walks above already met the injected
    // error, and redb latched it.
    let err = strict
        .expect("ran")
        .expect_err("try_for_each must report the read error");
    assert_eq!(err.kind, ErrorKind::Corruption, "{err}");
}

/// A walk used to scan keys only and then look every value up again,
/// and a cursor delete read the value it was deleting.  ffldb's
/// `ForEach` reads each value from its iterator and `Cursor.Delete`
/// reads nothing.  With no page cache every lookup is a backend read,
/// so the counts tell the two designs apart by an order of magnitude.
#[test]
fn walks_read_each_value_once_and_cursor_deletes_read_nothing() {
    const ROWS: u32 = 2000;
    let (_dir, backend, db) = faulty_db(|_| {});
    fill_store(&db, ROWS);

    let before = backend.reads.load(Ordering::SeqCst);
    let mut walked = 0u32;
    db.view(|tx| {
        let bucket = tx.metadata().bucket(BUCKET).expect("bucket");
        bucket.for_each(|k, v| {
            let i = u32::from_be_bytes(k.try_into().expect("key"));
            assert_eq!(v, value(i, 0).as_slice());
            walked += 1;
            Ok(())
        })
    })
    .expect("walk");
    let walk_reads = backend.reads.load(Ordering::SeqCst) - before;
    assert_eq!(walked, ROWS);
    assert!(
        walk_reads < u64::from(ROWS) / 4,
        "the walk read the store {walk_reads} times for {ROWS} rows: values are \
         being looked up again after the scan"
    );

    // A pending put, so one parked value comes from the transaction and
    // the rest from beneath it.
    let tx = db.begin(true).expect("begin");
    let bucket = tx.metadata().bucket(BUCKET).expect("bucket");
    bucket.put(&key(0), &value(0, 7)).expect("pending put");
    let mut cursor = bucket.cursor_window(None, ROWS as usize);
    let before = backend.reads.load(Ordering::SeqCst);
    let mut deleted = 0u32;
    let mut ok = cursor.first();
    while ok {
        cursor.delete().expect("delete");
        deleted += 1;
        ok = cursor.next();
    }
    let delete_reads = backend.reads.load(Ordering::SeqCst) - before;
    assert_eq!(deleted, ROWS);
    assert!(
        delete_reads < u64::from(ROWS) / 4,
        "deleting {ROWS} rows read the store {delete_reads} times: the cursor \
         is reading each value it deletes"
    );

    tx.rollback().expect("rollback");

    // A parked pair still answers with the value it had, from wherever
    // that value lived: the transaction's pending put for key 0, the
    // store beneath it for key 1.
    let tx = db.begin(true).expect("begin");
    let bucket = tx.metadata().bucket(BUCKET).expect("bucket");
    bucket.put(&key(0), &value(0, 7)).expect("pending put");
    for (i, want) in [(0u32, value(0, 7)), (1, value(1, 0))] {
        let mut cursor = bucket.cursor();
        assert!(cursor.seek(&key(i)));
        cursor.delete().expect("delete");
        assert_eq!(cursor.key(), Some(key(i)), "the deleted key stays parked");
        assert_eq!(cursor.value(), Some(want), "and so does its value");
        assert!(cursor.next());
        assert_eq!(cursor.key(), Some(key(i + 1)), "until the cursor moves");
    }
    tx.rollback().expect("rollback");
}

/// The merge a walk streams through, window after window, must be the
/// layered view exactly: store rows shadowed and deleted by the overlay,
/// overlay rows shadowed and deleted by the transaction, rows that only
/// the overlay or only the transaction holds -- spread over more rows
/// than one window holds.
#[test]
fn a_walk_across_windows_is_the_layered_view() {
    const ROWS: u32 = 10_000;
    let dir = TempDir::new().expect("tempdir");
    let db = Database::create(&Options::new(dir.path().join("db"), NET)).expect("create");
    let mut model: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();

    // Even keys in the store.
    db.update(|tx| {
        let bucket = tx.metadata().create_bucket(BUCKET)?;
        for i in (0..ROWS).step_by(2) {
            bucket.put(&key(i), &value(i, 0))?;
            model.insert(key(i), value(i, 0));
        }
        Ok(())
    })
    .expect("store rows");
    db.flush().expect("flush");

    // The overlay: odd keys of its own, every third stored row
    // rewritten, every fifth deleted.
    db.update(|tx| {
        let bucket = tx.metadata().bucket(BUCKET).expect("bucket");
        for i in 0..ROWS {
            if i % 2 == 1 {
                bucket.put(&key(i), &value(i, 1))?;
                model.insert(key(i), value(i, 1));
            } else if i % 5 == 0 {
                bucket.delete(&key(i))?;
                model.remove(&key(i));
            } else if i % 3 == 0 {
                bucket.put(&key(i), &value(i, 1))?;
                model.insert(key(i), value(i, 1));
            }
        }
        Ok(())
    })
    .expect("overlay rows");

    // The transaction's own changes on top.
    let tx = db.begin(true).expect("begin");
    let bucket = tx.metadata().bucket(BUCKET).expect("bucket");
    for i in 0..ROWS {
        if i % 7 == 0 {
            bucket.delete(&key(i)).expect("pending delete");
            model.remove(&key(i));
        } else if i % 11 == 0 {
            bucket.put(&key(i), &value(i, 2)).expect("pending put");
            model.insert(key(i), value(i, 2));
        }
    }
    for i in ROWS..ROWS + 50 {
        bucket.put(&key(i), &value(i, 2)).expect("pending-only put");
        model.insert(key(i), value(i, 2));
    }
    // A nested bucket, whose index row a walk must not report.
    bucket.create_bucket(b"nested").expect("nested");

    let mut walked: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    bucket
        .for_each(|k, v| {
            walked.push((k.to_vec(), v.to_vec()));
            Ok(())
        })
        .expect("walk");
    let want: Vec<(Vec<u8>, Vec<u8>)> = model.into_iter().collect();
    assert_eq!(walked.len(), want.len());
    assert!(walked == want, "the walk diverged from the layered view");
    tx.rollback().expect("rollback");
}

/// Hold the writer semaphore, queue `queued` behind it, then fail the
/// holder's commit-time flush.  Returns what the queued call returned.
fn queue_behind_a_failing_flush(
    queued: impl FnOnce(Database) -> Result<(), dcroxide_database::Error> + Send + 'static,
) -> (ErrorKind, dcroxide_database::Error) {
    // Flush whenever the overlay holds anything, and give it something:
    // a commit flushes the window before it (dcrd's `commitTx` order), so
    // the holder's commit is then a durable write.
    let (_dir, backend, db) = faulty_db(|opts| opts.cache_max_size = 1);
    db.update(|tx| tx.metadata().put(b"earlier", b"w"))
        .expect("earlier commit");
    let holder = db.begin(true).expect("begin");
    holder.metadata().put(b"held", b"x").expect("put");

    let waiter = {
        let db = db.clone();
        std::thread::spawn(move || queued(db))
    };
    // Long enough for the waiter to pass its pre-wait latch check and
    // block on the semaphore, which is the window under test.  Were it
    // slower, it would meet the latch before waiting and pass anyway.
    std::thread::sleep(Duration::from_millis(300));

    backend.fail_writes.store(true, Ordering::SeqCst);
    let first = holder.commit().expect_err("the flush must fail");
    let second = waiter
        .join()
        .expect("waiter")
        .expect_err("a writer queued behind a failed durable write must not succeed");
    (second.kind, first)
}

/// dcrd has no latch; this port's latch exists so that no write reports
/// success after a durable write failed.  A writer already queued on the
/// semaphore when that happened passed its latch check before waiting,
/// and the failing commit released the semaphore before latching, so
/// the queued writer ran the failed flush again.  A block-file fsync
/// that fails once can succeed on the retry without the bytes reaching
/// disk.
#[test]
fn a_writer_queued_behind_a_failing_flush_is_refused() {
    let (kind, first) =
        queue_behind_a_failing_flush(|db| db.update(|tx| tx.metadata().put(b"queued", b"y")));
    assert_ne!(
        first.kind,
        ErrorKind::Fatal,
        "the first failure is the cause"
    );
    assert_eq!(
        kind,
        ErrorKind::Fatal,
        "the queued writer must meet the latch, not retry the flush"
    );
}

/// `Database::flush` queued behind the failing commit: the same window.
#[test]
fn a_flush_queued_behind_a_failing_flush_is_refused() {
    let (kind, _) = queue_behind_a_failing_flush(|db| db.flush());
    assert_eq!(kind, ErrorKind::Fatal);
}

/// `Database::close` queued behind the failing commit: shutdown's flush
/// is a retry like any other.
#[test]
fn a_close_queued_behind_a_failing_flush_is_refused() {
    let (kind, _) = queue_behind_a_failing_flush(|db| db.close());
    assert_eq!(kind, ErrorKind::Fatal);
}

/// A raw block that is shorter than its header used to be accepted and
/// abort the process at commit, where the header is sliced out; one
/// filed under the wrong hash used to be accepted silently.
#[test]
fn store_block_raw_rejects_a_short_block_and_a_mismatched_hash() {
    let dir = TempDir::new().expect("tempdir");
    let db = Database::create(&Options::new(dir.path().join("db"), NET)).expect("create");

    let short = vec![1u8; 100];
    let err = db
        .update(|tx| tx.store_block_raw(&hash_h(&short), short.clone()))
        .expect_err("a block shorter than a header");
    assert_eq!(err.kind, ErrorKind::DriverSpecific, "{err}");

    let mut raw = vec![2u8; 180];
    raw.extend_from_slice(&[3u8; 40]);
    let err = db
        .update(|tx| tx.store_block_raw(&Hash([9u8; 32]), raw.clone()))
        .expect_err("a hash that is not the header's");
    assert_eq!(err.kind, ErrorKind::DriverSpecific, "{err}");

    // The well-formed pair still stores and reads back.
    let hash = hash_h(&raw[..180]);
    db.update(|tx| tx.store_block_raw(&hash, raw.clone()))
        .expect("store");
    db.view(|tx| {
        assert_eq!(tx.fetch_block(&hash)?, raw);
        assert_eq!(tx.fetch_block_header(&hash)?, raw[..180].to_vec());
        Ok(())
    })
    .expect("read back");
}
