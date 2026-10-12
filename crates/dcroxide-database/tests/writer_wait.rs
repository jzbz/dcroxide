// SPDX-License-Identifier: ISC
//! The waits for the writer semaphore, as a flush observer sees them.
//!
//! One writer at a time: a writable transaction holds the semaphore for
//! its whole life, and a flush and the close take it too (dcrd's
//! `writeLock`).  A caller that finds it held is timed until it holds
//! it, and the wait is added to a running total for its kind of thread,
//! the one named `index` or any other; each flush observation carries
//! the totals so far.  A caller that finds it free is neither timed nor
//! counted.

// Test-harness arithmetic over counts and times of a handful of waits.
#![allow(clippy::arithmetic_side_effects)]

use std::path::Path;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dcroxide_database::{
    Database, FlushObservation, INDEX_THREAD_NAME, Options, WriterWait, WriterWaits,
};
use tempfile::TempDir;

const NET: u32 = 0x12141c16; // simnet magic

/// How long the writer is held against each waiter.
const HOLD: Duration = Duration::from_millis(300);

/// Longer than anything here takes: a step that has not happened by
/// then never will.
const NEVER: Duration = Duration::from_secs(60);

/// Each flush as its observer saw it, with the name of the thread the
/// observer ran on.
type Seen = Arc<Mutex<Vec<(Option<String>, FlushObservation)>>>;

/// Options whose observer records every flush.
fn observed(path: &Path) -> (Options, Seen) {
    let mut opts = Options::new(path, NET);
    let seen: Seen = Arc::default();
    let sink = Arc::clone(&seen);
    opts.flush_observer = Some(Arc::new(move |obs: &FlushObservation| {
        let thread = std::thread::current().name().map(str::to_string);
        sink.lock().expect("observations").push((thread, *obs));
    }));
    (opts, seen)
}

/// The latest flush observed.
fn last(seen: &Seen) -> (Option<String>, FlushObservation) {
    seen.lock()
        .expect("observations")
        .last()
        .cloned()
        .expect("a flush was observed")
}

/// Hold the writer on this thread for [`HOLD`] while another thread,
/// named `name` or left without a name, runs `wants_the_writer`, which
/// therefore waits for it.  Returns a time the wait cannot have
/// exceeded.
fn hold_the_writer_against(
    db: &Database,
    name: Option<&str>,
    wants_the_writer: impl FnOnce(&Database) + Send + 'static,
) -> Duration {
    let holder = db.begin(true).expect("begin");
    let (started, waiter_started) = mpsc::channel();
    let before = Instant::now();
    let waiter = {
        let db = db.clone();
        let name = name.map(str::to_string);
        let mut thread = std::thread::Builder::new();
        if let Some(name) = &name {
            thread = thread.name(name.clone());
        }
        thread
            .spawn(move || {
                assert_eq!(std::thread::current().name(), name.as_deref());
                started.send(()).expect("signal");
                wants_the_writer(&db);
            })
            .expect("spawn the waiter")
    };
    // The waiter is running and about to ask for the writer; only the
    // few instructions after the signal have to fit before the release,
    // not the thread's start.
    waiter_started.recv().expect("waiter started");
    std::thread::sleep(HOLD);
    holder.rollback().expect("rollback");
    waiter.join().expect("waiter");
    before.elapsed()
}

/// One more wait than `before` held, of a plausible length: most of
/// the time the writer was held, and no more than the scenario took.
fn assert_one_more_wait(what: &str, before: WriterWait, after: WriterWait, at_most: Duration) {
    assert_eq!(after.count, before.count + 1, "{what}: the count");
    let waited = Duration::from_nanos(after.nanos - before.nanos);
    assert!(
        waited >= HOLD / 2 && waited <= at_most,
        "{what}: waited {waited:?} against a writer held for {HOLD:?}, in a scenario of {at_most:?}"
    );
}

#[test]
fn a_writer_that_is_free_is_not_waited_for() {
    let dir = TempDir::new().expect("tempdir");
    let (opts, seen) = observed(&dir.path().join("db"));
    let db = Database::create(&opts).expect("create");

    // Every way of taking the writer, with nobody holding it.
    for i in 0..3u8 {
        db.update(|tx| tx.metadata().put(&[i], b"v"))
            .expect("update");
        db.flush().expect("flush");
    }
    let tx = db.begin(true).expect("begin");
    tx.metadata().put(b"begin", b"v").expect("put");
    tx.commit().expect("commit");
    db.flush().expect("flush");
    db.update(|tx| tx.metadata().put(b"close", b"v"))
        .expect("update");
    db.close().expect("close");

    let seen = seen.lock().expect("observations");
    assert_eq!(seen.len(), 5, "four flushes and the close's");
    for (thread, obs) in seen.iter() {
        assert_eq!(
            obs.writer_waits,
            WriterWaits::default(),
            "flush {}: nothing waited, so nothing is counted",
            obs.sequence
        );
        assert_eq!(
            thread.as_deref(),
            std::thread::current().name(),
            "flush {}: the observer runs on the thread that flushed",
            obs.sequence
        );
    }
}

#[test]
fn a_wait_for_the_writer_is_added_to_the_waiting_threads_total() {
    let dir = TempDir::new().expect("tempdir");
    let (opts, seen) = observed(&dir.path().join("db"));
    let db = Database::create(&opts).expect("create");
    db.update(|tx| tx.metadata().put(b"first", b"v"))
        .expect("update");
    db.flush().expect("flush");
    let start = last(&seen).1.writer_waits;
    assert_eq!(start, WriterWaits::default(), "nothing has waited yet");

    // A writable transaction on the index thread waits for the writer.
    let at_most = hold_the_writer_against(&db, Some(INDEX_THREAD_NAME), |db| {
        db.update(|tx| tx.metadata().put(b"index", b"v"))
            .expect("the index thread's update");
    });
    db.flush().expect("flush");
    let (_, obs) = last(&seen);
    let after_index = obs.writer_waits;
    assert_one_more_wait(
        "the index thread's transaction",
        start.index,
        after_index.index,
        at_most,
    );
    assert_eq!(after_index.other, start.other, "no other thread waited");

    // A writable transaction on any other thread does too, and its wait
    // goes to the other total.
    let at_most = hold_the_writer_against(&db, Some("block"), |db| {
        db.update(|tx| tx.metadata().put(b"block", b"v"))
            .expect("the other thread's update");
    });
    db.flush().expect("flush");
    let mut after_update = last(&seen).1.writer_waits;
    assert_one_more_wait(
        "another thread's transaction",
        after_index.other,
        after_update.other,
        at_most,
    );
    assert_eq!(after_update.index, after_index.index, "the totals run on");

    // Only the thread named exactly `index` is the index thread.  One
    // without a name, as most of a daemon's threads are, is another
    // thread, and so is one whose name only starts as the index
    // thread's does.
    for name in [None, Some("index-2")] {
        let at_most = hold_the_writer_against(&db, name, |db| {
            db.update(|tx| tx.metadata().put(b"not the index thread", b"v"))
                .expect("the other thread's update");
        });
        db.flush().expect("flush");
        let waits = last(&seen).1.writer_waits;
        assert_one_more_wait(
            &format!("the transaction of a thread named {name:?}"),
            after_update.other,
            waits.other,
            at_most,
        );
        assert_eq!(
            waits.index, after_index.index,
            "a thread named {name:?} is not the index thread"
        );
        after_update = waits;
    }

    // A flush waits for the writer as a transaction does, and reports
    // its own wait: the totals in its observation include it.
    db.update(|tx| tx.metadata().put(b"to flush", b"v"))
        .expect("update");
    let at_most = hold_the_writer_against(&db, Some("flusher"), |db| db.flush().expect("flush"));
    let (thread, obs) = last(&seen);
    assert_eq!(thread.as_deref(), Some("flusher"), "who ran the flush");
    let after_flush = obs.writer_waits;
    assert_one_more_wait(
        "another thread's flush",
        after_update.other,
        after_flush.other,
        at_most,
    );
    assert_eq!(after_flush.index, after_index.index);

    // So does a flush on the index thread, to the index total.
    db.update(|tx| tx.metadata().put(b"to flush again", b"v"))
        .expect("update");
    let at_most = hold_the_writer_against(&db, Some(INDEX_THREAD_NAME), |db| {
        db.flush().expect("flush");
    });
    let (thread, obs) = last(&seen);
    assert_eq!(thread.as_deref(), Some(INDEX_THREAD_NAME));
    let after_index_flush = obs.writer_waits;
    assert_one_more_wait(
        "the index thread's flush",
        after_flush.index,
        after_index_flush.index,
        at_most,
    );
    assert_eq!(after_index_flush.other, after_flush.other);

    // And so does the close.
    db.update(|tx| tx.metadata().put(b"to close", b"v"))
        .expect("update");
    let at_most = hold_the_writer_against(&db, Some("closer"), |db| db.close().expect("close"));
    let (thread, obs) = last(&seen);
    assert_eq!(thread.as_deref(), Some("closer"), "who ran the close");
    assert_one_more_wait(
        "the close",
        after_index_flush.other,
        obs.writer_waits.other,
        at_most,
    );
    assert_eq!(obs.writer_waits.index, after_index_flush.index);
    assert_eq!(
        (obs.writer_waits.index.count, obs.writer_waits.other.count),
        (2, 5),
        "seven waits in all"
    );
}

/// The index thread waits out a transaction and then, inside its own,
/// holds the writer while `arrives` runs on another thread: the
/// arrival must not get the writer until the index thread commits.
/// Both waits are counted, each to its own kind of thread.
fn a_thread_that_waited_holds_the_writer_against(
    what: &str,
    arrives: impl FnOnce(&Database) + Send + 'static,
) {
    let dir = TempDir::new().expect("tempdir");
    let (opts, seen) = observed(&dir.path().join("db"));
    let db = Database::create(&opts).expect("create");
    db.update(|tx| tx.metadata().put(b"first", b"v"))
        .expect("update");
    db.flush().expect("flush");
    let start = last(&seen).1.writer_waits;
    assert_eq!(start, WriterWaits::default(), "nothing has waited yet");

    // The index thread asks for the writer while this thread holds it,
    // gets it at the rollback, and keeps it until released.
    let before = Instant::now();
    let holder = db.begin(true).expect("begin");
    let (started, waiter_started) = mpsc::channel();
    let (entered, waiter_entered) = mpsc::channel();
    let (release, released) = mpsc::channel::<()>();
    let waiter = {
        let db = db.clone();
        std::thread::Builder::new()
            .name(INDEX_THREAD_NAME.to_string())
            .spawn(move || {
                started.send(()).expect("signal");
                db.update(|tx| {
                    entered.send(()).expect("signal");
                    // A test that has failed dropped its end, which
                    // ends the wait too.
                    let _ = released.recv();
                    tx.metadata().put(b"the thread that waited", b"v")
                })
                .expect("the waiting thread's update");
            })
            .expect("spawn the waiter")
    };
    waiter_started.recv().expect("waiter started");
    std::thread::sleep(HOLD);
    holder.rollback().expect("rollback");
    waiter_entered
        .recv_timeout(NEVER)
        .expect("the thread that waited got the writer");

    // Another thread arrives while the one that waited holds the
    // writer, and is still waiting a hold's length later.
    let (arriving, arrival_started) = mpsc::channel();
    let (done, arrival_done) = mpsc::channel();
    let arrival = {
        let db = db.clone();
        std::thread::Builder::new()
            .name("block".to_string())
            .spawn(move || {
                arriving.send(()).expect("signal");
                arrives(&db);
                done.send(()).expect("signal");
            })
            .expect("spawn the arrival")
    };
    arrival_started.recv().expect("arrival started");
    assert_eq!(
        arrival_done.recv_timeout(HOLD),
        Err(mpsc::RecvTimeoutError::Timeout),
        "{what} got the writer while the thread that had waited for it held it"
    );
    release.send(()).expect("release the thread that waited");
    arrival_done
        .recv_timeout(NEVER)
        .expect("the arrival gets the writer once it is free");
    waiter.join().expect("waiter");
    arrival.join().expect("arrival");
    let at_most = before.elapsed();

    // The index thread's commit is still to flush, unless the arrival
    // was a flush and its observation is the last already.
    db.flush().expect("flush");
    let waits = last(&seen).1.writer_waits;
    assert_one_more_wait(
        "the index thread, which waited first",
        start.index,
        waits.index,
        at_most,
    );
    assert_one_more_wait(what, start.other, waits.other, at_most);
}

/// A thread that had to wait for the writer holds it once it has it,
/// as one that found it free does: a transaction or a flush arriving
/// while it works waits in turn, and is counted as waiting.
#[test]
fn a_thread_that_waited_for_the_writer_holds_it_against_the_next() {
    a_thread_that_waited_holds_the_writer_against("a writable transaction", |db| {
        let tx = db.begin(true).expect("begin");
        tx.metadata().put(b"arrival", b"v").expect("put");
        tx.commit().expect("commit");
    });
    a_thread_that_waited_holds_the_writer_against("a flush", |db| db.flush().expect("flush"));
}

#[test]
fn the_waits_render_as_one_json_object() {
    let waits = WriterWaits {
        index: WriterWait {
            count: 3,
            nanos: 1_234_567,
        },
        other: WriterWait {
            count: 70,
            nanos: 89_000_000_000,
        },
    };
    assert_eq!(
        waits.to_json(),
        r#"{"index":{"count":3,"ns":1234567},"other":{"count":70,"ns":89000000000}}"#
    );
}
