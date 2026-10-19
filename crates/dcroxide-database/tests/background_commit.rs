// SPDX-License-Identifier: ISC
//! A flush whose redb commit runs on a thread of its own
//! (`Options::background_commit`).
//!
//! With the option set, a flush that a commit's own check trips stops at
//! its last step: the overlay is captured, the block files are synced
//! and the rows are handed to redb on the committing thread, under the
//! writer semaphore, and the redb commit itself is made by the store's
//! commit thread, named `dbcommit`, while the commit that tripped the
//! flush returns.  The thread is one for the open store, started by the
//! first flush handed to it and kept until the close or the drop of the
//! last handle.  These tests hold it at its first write (`GateBackend`)
//! and look at the database while the commit is under way, then let it
//! land or fail.
//!
//! What they hold the store to:
//!
//! - commits made while a redb commit is under way return, and a reader
//!   sees their rows and the captured ones;
//! - nothing is acknowledged as durable that is not: a power cut keeps
//!   exactly the captured batch once its commit has landed and nothing
//!   of it before, and `Database::flush` and `Database::close` return
//!   only after the commit under way has ended and their own has synced;
//! - a commit that fails on its own thread latches the store before the
//!   participant is told and before anything can acknowledge durability,
//!   and the next write, flush and close name its cause; so does a
//!   committer thread that panics, at the next wait for it;
//! - every flush handed over is committed by the one commit thread,
//!   which no close outlives, and a participant is neither registered nor
//!   released under a flush it did not start with;
//! - one flush is in flight at a time: a commit whose flush the overlay
//!   or the participant asks for waits for the commit under way, and a
//!   caller that only asks whether the store has failed does not take
//!   that wait from it;
//! - a reader's view is always that of one commit: the captured layers
//!   and the store that takes them over never show a row twice, a deleted
//!   row again, or one commit's rows without another's;
//! - the overlay is bounded while a commit is under way: a commit that
//!   finds it over its maximum waits for that commit and adds nothing;
//! - a participant that has not allowed its `finished` to be deferred is
//!   never handed over;
//! - the storage a handed-over commit leaves behind takes writes and
//!   reads as it does after a commit made on the committing thread, and
//!   a power cut loses no commit and tears none where redb writes pages
//!   to the file ahead of the commit they belong to.
//!
//! The seams that only code inside the crate can reach -- a reader placed
//! between a commit and its retirement, a refused thread, a capture made
//! without its wait, a retirement over changed layers, a committer that
//! panics before it retires, each of a commit's two looks at the latch,
//! and the thread that syncs the block files -- are in the crate's own
//! `background_commit_tests`.
//!
//! **A test settles before it lets go of a store.**  The commit thread
//! keeps the store open until the flush it is committing has ended, and
//! a power cut on the test's backend does not stop it, so every test
//! waits for the flush in flight (`Database::wait_background_commit`, or
//! a flush or close that waits itself) before it drops its last handle
//! or reopens.  The thread lets go of the store before that wait returns.
//!
//! The waits that show a call is blocked are short sleeps, as in
//! `writer_wait.rs`: a call that wrongly returned at once is caught, and
//! a slow machine only makes the test slower.

// Test-harness arithmetic over bounded counts and short times.
#![allow(clippy::arithmetic_side_effects)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use dcroxide_database::{
    COMMIT_THREAD_NAME, Database, Error, ErrorKind, FlushObservation, FlushParticipant,
    FlushWriter, LogLevel, Options, ParticipantStats, SharedBackend, StorageBackend, Transaction,
};
use dcroxide_testutil::SplitMix64;
use dcroxide_testutil::gate::{COMMITTER_THREAD_NAME, GateBackend};
use dcroxide_testutil::powerloss::PowerLossBackend;
use tempfile::TempDir;

const NET: u32 = 0x12141c16; // simnet magic

/// The overlay's maximum.  A commit flushes once one and a half times
/// what the overlay holds is more than this, so one [`Rig::fill`] arms
/// the next commit's flush, and the few small commits a test makes while
/// that flush is in flight stay under the maximum itself.
const CACHE_MAX: u64 = 64 * 1024;

/// Rows a [`Rig::fill`] writes, and the length of each one's value.
const FILL_ROWS: u32 = 48;
const FILL_VALUE: usize = 1024;

/// Longer than anything here takes: a step that has not happened by then
/// never will.
const NEVER: Duration = Duration::from_secs(60);

/// How long a call that must be waiting is watched for a return.
const WATCH: Duration = Duration::from_millis(300);

/// The row every test's store holds durably before anything else.
const BASE: &[u8] = b"base";

/// The bucket whose id is a participant's prefix.
const JOURNAL: &[u8] = b"journal";

/// Each flush as its observer saw it, with the name of the thread the
/// observer ran on.
type Seen = Arc<Mutex<Vec<(Option<String>, FlushObservation)>>>;

/// A point a thread can be held at.
#[derive(Default)]
struct Hold {
    /// Whether to hold, and whether a thread has arrived.
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}

impl Hold {
    fn arm(&self) {
        self.state.lock().unwrap().0 = true;
    }

    fn release(&self) {
        self.state.lock().unwrap().0 = false;
        self.changed.notify_all();
    }

    /// Called by the thread to hold.
    fn pass(&self) {
        let mut state = self.state.lock().unwrap();
        if !state.0 {
            return;
        }
        state.1 = true;
        self.changed.notify_all();
        while state.0 {
            state = self.changed.wait(state).unwrap();
        }
    }

    /// Wait for a thread to arrive; whether one did.
    fn wait_reached(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut state = self.state.lock().unwrap();
        while !state.1 {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            state = self.changed.wait_timeout(state, left).unwrap().0;
        }
        true
    }
}

/// A database with background commits on, over storage that can hold the
/// committer thread and lose power.
struct Rig {
    dir: TempDir,
    db: Database,
    power: Arc<PowerLossBackend>,
    gate: Arc<GateBackend>,
    seen: Seen,
    /// The thread each observation in `seen` was made on.
    ids: Arc<Mutex<Vec<std::thread::ThreadId>>>,
    log: Arc<Mutex<Vec<(LogLevel, String)>>>,
    /// Shut the gate again as soon as a background flush is observed, so
    /// that a later commit wrongly made on a committer thread is held
    /// instead of racing the test.
    rearm: Arc<AtomicBool>,
    /// Holds whichever thread logs an error line, inside the log sink.
    log_hold: Arc<Hold>,
    /// The journal bucket's id.
    prefix: Vec<u8>,
}

impl Rig {
    fn new() -> Rig {
        assert_eq!(
            COMMIT_THREAD_NAME, COMMITTER_THREAD_NAME,
            "the gate holds the thread the database names"
        );
        let dir = TempDir::new().expect("tempdir");
        let db_dir = dir.path().join("db");
        std::fs::create_dir_all(&db_dir).expect("mkdir");
        let power = PowerLossBackend::create(&db_dir.join("metadata.redb"), true);
        let gate = GateBackend::new(Arc::clone(&power) as SharedBackend);

        let mut opts = Options::new(&db_dir, NET);
        opts.backend = Some(Arc::clone(&gate) as SharedBackend);
        opts.background_commit = true;
        opts.cache_max_size = CACHE_MAX;
        let seen: Seen = Arc::default();
        let ids: Arc<Mutex<Vec<std::thread::ThreadId>>> = Arc::default();
        let rearm = Arc::new(AtomicBool::new(false));
        {
            let seen = Arc::clone(&seen);
            let ids = Arc::clone(&ids);
            let rearm = Arc::clone(&rearm);
            let gate = Arc::clone(&gate);
            opts.flush_observer = Some(Arc::new(move |obs: &FlushObservation| {
                let thread = std::thread::current().name().map(str::to_string);
                // One lock order, so the two lists stay in step.
                let mut seen = seen.lock().unwrap();
                ids.lock().unwrap().push(std::thread::current().id());
                seen.push((thread, *obs));
                if obs.background && rearm.load(Ordering::SeqCst) {
                    gate.arm();
                }
            }));
        }
        let log: Arc<Mutex<Vec<(LogLevel, String)>>> = Arc::default();
        let log_hold = Arc::new(Hold::default());
        {
            let log = Arc::clone(&log);
            let log_hold = Arc::clone(&log_hold);
            opts.log = Some(Arc::new(move |level: LogLevel, msg: &str| {
                log.lock().unwrap().push((level, msg.to_string()));
                if level == LogLevel::Error {
                    log_hold.pass();
                }
            }));
        }

        let db = Database::create(&opts).expect("create");
        let mut prefix = Vec::new();
        db.update(|tx| {
            let meta = tx.metadata();
            meta.put(BASE, b"durable")?;
            prefix = meta.create_bucket(JOURNAL)?.raw_id().to_vec();
            Ok(())
        })
        .expect("the base rows");
        db.flush().expect("flush the base rows");
        seen.lock().unwrap().clear();
        ids.lock().unwrap().clear();
        Rig {
            dir,
            db,
            power,
            gate,
            seen,
            ids,
            log,
            rearm,
            log_hold,
            prefix,
        }
    }

    /// Commit generation `generation` as enough rows to arm the next
    /// commit's flush.  The overlay must be empty, or nearly, so that
    /// this commit's own check trips nothing.
    fn fill(&self, generation: u32) {
        self.db
            .update(|tx| put_generation(tx, generation, FILL_ROWS, FILL_VALUE))
            .expect("fill");
    }

    /// Commit generation `generation` as one small row.
    fn small(&self, generation: u32) {
        self.db
            .update(|tx| put_generation(tx, generation, 1, 8))
            .expect("a small commit");
    }

    /// Commit generation 1, shut the gate, and commit generation 2, whose
    /// flush check captures generation 1 and hands its commit to a
    /// committer thread: on return that thread is held at its first write
    /// and generation 2's commit has returned.
    fn hold_a_commit(&self) {
        self.fill(1);
        self.gate.arm();
        self.small(2);
        assert!(
            self.gate.wait_held(NEVER),
            "the flush's commit is under way on a thread of its own"
        );
        assert!(
            !self.gate.holds_a_length_change(),
            "the commit was stopped growing the file, where no transaction can begin beside it"
        );
    }

    fn observations(&self) -> Vec<(Option<String>, FlushObservation)> {
        self.seen.lock().unwrap().clone()
    }

    /// The thread each observation so far was made on, in order.
    fn observation_threads(&self) -> Vec<std::thread::ThreadId> {
        let _seen = self.seen.lock().unwrap();
        self.ids.lock().unwrap().clone()
    }

    /// The error lines logged so far.
    fn error_lines(&self) -> Vec<String> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|(level, _)| *level == LogLevel::Error)
            .map(|(_, msg)| msg.clone())
            .collect()
    }

    /// Which of the generations `1..=upto` a reader finds whole.
    fn readable(&self, upto: u32) -> Vec<u32> {
        generations(&self.db, upto)
    }

    /// Let go of the store as a process that dies does, then lose power:
    /// wait for any flush in flight, drop the handle without closing it,
    /// and discard everything the storage never synced.  Returns the
    /// directory, for a reopen.
    fn crash(self) -> (TempDir, PathBuf) {
        let Rig { dir, db, power, .. } = self;
        let _ = db.wait_background_commit();
        drop(db);
        power.cut_power();
        let path = dir.path().join("db");
        (dir, path)
    }
}

/// The key of generation `generation`'s row `i`, in the metadata bucket.
fn row_key(generation: u32, i: u32) -> Vec<u8> {
    let mut key = vec![b'r'];
    key.extend_from_slice(&generation.to_be_bytes());
    key.extend_from_slice(&i.to_be_bytes());
    key
}

/// Write generation `generation`: `rows` rows of `len` bytes each, and
/// last a row that records how many there are.
///
/// Every row is in the metadata bucket itself, whose id is fixed, so a
/// reader finds an unflushed one in the overlay without a lookup in the
/// store, which fails once a redb write has.
fn put_generation(tx: &Transaction, generation: u32, rows: u32, len: usize) -> Result<(), Error> {
    let meta = tx.metadata();
    for i in 0..rows {
        meta.put(&row_key(generation, i), &vec![generation as u8; len])?;
    }
    meta.put(&row_key(generation, u32::MAX), &rows.to_be_bytes())
}

/// Which of the generations `1..=upto` a reader of `db` finds, each of
/// which must be whole: all of its rows or none.
fn generations(db: &Database, upto: u32) -> Vec<u32> {
    let mut found = Vec::new();
    db.view(|tx| {
        let meta = tx.metadata();
        for generation in 1..=upto {
            let Some(count) = meta.get(&row_key(generation, u32::MAX)) else {
                assert!(
                    meta.get(&row_key(generation, 0)).is_none(),
                    "generation {generation} has a row but no count"
                );
                continue;
            };
            let rows = u32::from_be_bytes(count.as_slice().try_into().expect("a count"));
            for i in 0..rows {
                assert!(
                    meta.get(&row_key(generation, i)).is_some(),
                    "generation {generation} lacks row {i} of {rows}"
                );
            }
            found.push(generation);
        }
        Ok(())
    })
    .expect("view");
    found
}

/// Reopen a store after [`Rig::crash`], on its file alone, and return the
/// generations it holds; the base rows must have survived.
fn reopened(path: &std::path::Path, upto: u32) -> Vec<u32> {
    let db = Database::open(&Options::new(path, NET)).expect("reopen");
    db.view(|tx| {
        assert_eq!(
            tx.metadata().get(BASE).as_deref(),
            Some(b"durable".as_slice())
        );
        Ok(())
    })
    .expect("view");
    let found = generations(&db, upto);
    db.close().expect("close the reopened store");
    found
}

/// Run `call` on a thread of its own and hand back where its result will
/// arrive.  The thread's handle on the database is gone by the time the
/// result is, so it cannot be the last one a test lets go of.
fn in_background<T: Send + 'static>(
    db: &Database,
    call: impl FnOnce(&Database) -> T + Send + 'static,
) -> mpsc::Receiver<T> {
    let (done, result) = mpsc::channel();
    let db = db.clone();
    std::thread::spawn(move || {
        let outcome = call(&db);
        drop(db);
        let _ = done.send(outcome);
    });
    result
}

/// Assert that a call started by [`in_background`] is still waiting.
fn assert_waiting<T>(result: &mpsc::Receiver<T>, what: &str) {
    assert!(
        matches!(
            result.recv_timeout(WATCH),
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "{what} returned while the commit it must wait for was held"
    );
}

/// Assert that `err` is the latch's refusal, naming the power cut that
/// failed the background commit as its first cause.
fn assert_refused_for_the_power_cut(what: &str, err: &Error) {
    assert_eq!(err.kind, ErrorKind::Fatal, "{what}: {err}");
    assert!(
        err.description.contains("(the first failure: ") && err.description.contains("power cut"),
        "{what} does not name the failed commit: {err}"
    );
}

// ---------------------------------------------------------------------
// The participant
// ---------------------------------------------------------------------

/// One call a participant received, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call {
    Contribute,
    Finished(bool),
}

/// A participant that allows its `finished` to be deferred, and so sets
/// apart what each `contribute` wrote from what hooks hand in after it.
#[derive(Default)]
struct Recorder {
    prefix: Vec<u8>,
    /// Keys handed in by hooks and not yet in a committed flush.
    pending: Mutex<Vec<u32>>,
    /// How many of `pending` the flush in progress wrote.
    in_flight: Mutex<usize>,
    calls: Mutex<Vec<Call>>,
    /// What [`Self::probe`] answered inside each `finished`.
    latched: Mutex<Vec<bool>>,
    /// Whether the store is latched, asked of a handle the test lends.
    probe: Mutex<Option<Box<dyn Fn() -> bool + Send>>>,
    /// Whether the next commit should flush whatever the overlay holds.
    want: AtomicBool,
    /// Whether `finished` panics when a committer thread calls it.
    panics: bool,
}

impl Recorder {
    fn new(prefix: &[u8]) -> Arc<Recorder> {
        Arc::new(Recorder {
            prefix: prefix.to_vec(),
            ..Recorder::default()
        })
    }

    /// A participant whose `finished` panics on a committer thread, once
    /// the call is recorded and before anything is retired.
    fn panicking(prefix: &[u8]) -> Arc<Recorder> {
        Arc::new(Recorder {
            prefix: prefix.to_vec(),
            panics: true,
            ..Recorder::default()
        })
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    fn pending(&self) -> Vec<u32> {
        self.pending.lock().unwrap().clone()
    }
}

impl FlushParticipant for Recorder {
    fn wants_flush(&self) -> bool {
        self.want.load(Ordering::SeqCst)
    }

    fn has_work(&self) -> bool {
        !self.pending.lock().unwrap().is_empty()
    }

    fn contribute(&self, w: &mut FlushWriter<'_, '_>) -> Result<ParticipantStats, Error> {
        self.calls.lock().unwrap().push(Call::Contribute);
        let pending = self.pending.lock().unwrap();
        for key in pending.iter() {
            let mut row = self.prefix.clone();
            row.push(b'K');
            row.extend_from_slice(&key.to_be_bytes());
            w.insert(&row, b"")?;
        }
        *self.in_flight.lock().unwrap() = pending.len();
        Ok(ParticipantStats::default())
    }

    fn finished(&self, committed: bool) {
        self.calls.lock().unwrap().push(Call::Finished(committed));
        if self.panics && std::thread::current().name() == Some(COMMIT_THREAD_NAME) {
            panic!("a participant that panics on the committer thread, by this test's request");
        }
        if let Some(probe) = &*self.probe.lock().unwrap() {
            self.latched.lock().unwrap().push(probe());
        }
        let n = std::mem::take(&mut *self.in_flight.lock().unwrap());
        if committed {
            self.pending.lock().unwrap().drain(..n);
        }
    }

    fn allows_deferred_finish(&self) -> bool {
        true
    }
}

/// A participant that has not opted in: a [`Recorder`] behind a
/// participant that leaves `allows_deferred_finish` to the trait's
/// default, so that what a participant gets for not answering is what a
/// test of one that has not opted in sees.
struct NotOptedIn(Arc<Recorder>);

impl FlushParticipant for NotOptedIn {
    fn wants_flush(&self) -> bool {
        self.0.wants_flush()
    }

    fn has_work(&self) -> bool {
        self.0.has_work()
    }

    fn contribute(&self, w: &mut FlushWriter<'_, '_>) -> Result<ParticipantStats, Error> {
        self.0.contribute(w)
    }

    fn finished(&self, committed: bool) {
        self.0.finished(committed);
    }
}

/// Commit generation `generation` with `rows` rows, and hand its number
/// to the participant from an `on_commit` hook, as an index hands a
/// block's keys over.
fn connect(
    db: &Database,
    recorder: &Arc<Recorder>,
    generation: u32,
    rows: u32,
) -> Result<(), Error> {
    let recorder = Arc::clone(recorder);
    db.update(move |tx| {
        put_generation(tx, generation, rows, FILL_VALUE)?;
        tx.on_commit(move || recorder.pending.lock().unwrap().push(generation))
    })
}

// ---------------------------------------------------------------------
// A commit under way
// ---------------------------------------------------------------------

/// The commit that trips a flush returns once the flush's rows are
/// handed to redb, and so do commits after it, while the redb commit is
/// still to make its first write.  A reader sees every one of their rows.
/// Nothing is observed, because nothing is durable yet.  Once the commit
/// lands, one flush is observed, made on the committer thread, and a
/// power cut then keeps exactly what that flush captured: not the commit
/// that tripped it, whose rows were published after the capture, nor the
/// ones after.
#[test]
fn a_commit_that_trips_a_flush_returns_while_its_commit_is_held() {
    let rig = Rig::new();
    rig.hold_a_commit();
    let held_from = Instant::now();
    rig.small(3);
    rig.small(4);
    assert_eq!(
        rig.readable(4),
        vec![1, 2, 3, 4],
        "a reader sees the captured rows and those committed since"
    );
    assert!(
        rig.observations().is_empty(),
        "a flush was reported before its commit landed"
    );
    assert!(!rig.db.is_fatal());
    let held_for = held_from.elapsed();

    rig.gate.open();
    rig.db.wait_background_commit().expect("the commit landed");
    let seen = rig.observations();
    assert_eq!(seen.len(), 1, "one flush: {seen:?}");
    let (thread, obs) = &seen[0];
    assert_eq!(
        thread.as_deref(),
        Some(COMMIT_THREAD_NAME),
        "the observer runs on the thread that made the commit"
    );
    assert!(obs.background, "the commit was handed over");
    assert!(!obs.explicit, "a commit's own check tripped it");
    assert!(
        obs.dirty_entries >= FILL_ROWS as usize,
        "generation 1: {obs:?}"
    );
    assert!(
        obs.block_sync.elapsed + obs.insert.elapsed <= obs.foreground,
        "the sync and the insert loop ran before the hand-off: {obs:?}"
    );
    assert!(
        obs.foreground < obs.elapsed && obs.elapsed >= held_for,
        "the flush lasted until its commit landed, the committing thread's part did not: {obs:?}"
    );
    assert_eq!(
        obs.waited,
        Duration::ZERO,
        "no earlier commit was waited for"
    );
    assert_eq!(rig.readable(4), vec![1, 2, 3, 4], "after the retirement");

    let (_dir, path) = rig.crash();
    assert_eq!(
        reopened(&path, 4),
        vec![1],
        "exactly the captured batch is durable"
    );
}

/// Until the redb commit has landed nothing of the flush is durable, and
/// nobody was told otherwise: with the power gone before the held
/// commit's first write, the commit fails, the store latches, and the
/// store reopens at the commit before, though three commits returned
/// `Ok` in the meantime.
#[test]
fn nothing_of_a_held_commit_is_durable() {
    let rig = Rig::new();
    rig.hold_a_commit();
    rig.small(3);
    rig.small(4);

    rig.power.power_fails_after(0);
    rig.gate.open();
    let err = rig
        .db
        .wait_background_commit()
        .expect_err("the commit had no power to write with");
    assert_refused_for_the_power_cut("the wait", &err);
    assert!(rig.power.power_failed());
    assert!(rig.db.is_fatal());
    assert!(
        rig.observations().is_empty(),
        "a failed flush is not reported"
    );
    assert_eq!(
        rig.readable(4),
        vec![1, 2, 3, 4],
        "the rows stay readable in the write cache"
    );

    let (_dir, path) = rig.crash();
    assert_eq!(
        reopened(&path, 4),
        Vec::<u32>::new(),
        "the store is at the commit before"
    );
}

/// Rows committed while a commit is under way are published above the
/// layers it captured, so the retirement of those layers takes none of
/// them: a reader finds them after it, and a flush then makes them
/// durable.
#[test]
fn rows_committed_during_a_background_commit_survive_its_retirement() {
    let rig = Rig::new();
    rig.hold_a_commit();
    rig.small(3);
    rig.small(4);
    rig.gate.open();
    rig.db.wait_background_commit().expect("the commit landed");
    assert_eq!(
        rig.observations().len(),
        1,
        "the captured layers are retired"
    );
    assert_eq!(
        rig.readable(4),
        vec![1, 2, 3, 4],
        "the retirement took rows committed after the capture"
    );

    rig.db.flush().expect("flush");
    let (_dir, path) = rig.crash();
    assert_eq!(reopened(&path, 4), vec![1, 2, 3, 4]);
}

// ---------------------------------------------------------------------
// Readers beside commits
// ---------------------------------------------------------------------

/// The key of the row a step of the reader test leaves for good: no
/// later step rewrites or deletes it.
fn step_mark(step: u32) -> Vec<u8> {
    let mut key = vec![b'h'];
    key.extend_from_slice(&step.to_be_bytes());
    key
}

/// The rows of one step of the reader test: the step number under two
/// keys, a set of rows only that step has, the removal of the step
/// before's, and a row that stays.
fn put_step(tx: &Transaction, step: u32) -> Result<(), Error> {
    const ROWS: u32 = 24;
    let meta = tx.metadata();
    let own = |step: u32, i: u32| {
        let mut key = vec![b'o'];
        key.extend_from_slice(&step.to_be_bytes());
        key.extend_from_slice(&i.to_be_bytes());
        key
    };
    for i in 0..ROWS {
        meta.put(&own(step, i), &[step as u8; 1024])?;
        if step > 1 {
            meta.delete(&own(step - 1, i))?;
        }
    }
    meta.put(&step_mark(step), &[1u8; 64])?;
    meta.put(b"step-a", &step.to_be_bytes())?;
    meta.put(b"step-b", &step.to_be_bytes())
}

/// The step a reader of `tx` is at, checked for being one whole step with
/// every step before it behind it: both keys name it, every row of its
/// own is there, none of the step before's or the step after's is, and
/// the row each step up to it left for good is there.
fn step_seen(tx: &Transaction) -> u32 {
    let meta = tx.metadata();
    let number = |key: &[u8]| {
        meta.get(key)
            .map(|v| u32::from_be_bytes(v.as_slice().try_into().expect("a step")))
    };
    let (a, b) = (number(b"step-a"), number(b"step-b"));
    assert_eq!(a, b, "the two keys are written in one commit");
    let Some(step) = a else {
        return 0;
    };
    let own = |step: u32, i: u32| {
        let mut key = vec![b'o'];
        key.extend_from_slice(&step.to_be_bytes());
        key.extend_from_slice(&i.to_be_bytes());
        key
    };
    for i in 0..24u32 {
        assert!(
            meta.get(&own(step, i)).is_some(),
            "step {step} lacks its row {i}"
        );
        assert!(
            step == 1 || meta.get(&own(step - 1, i)).is_none(),
            "step {step} shows row {i} of the step before, which it deleted"
        );
        assert!(
            meta.get(&own(step + 1, i)).is_none(),
            "step {step} shows row {i} of the step after"
        );
    }
    for earlier in 1..=step {
        assert!(
            meta.get(&step_mark(earlier)).is_some(),
            "a reader at step {step} lacks the row step {earlier} left"
        );
    }
    step
}

/// Readers that run beside commits whose flushes land on a thread of
/// their own see one whole commit each time, with every commit before it,
/// and never an earlier one than they saw before.
///
/// A transaction reads the overlay over a snapshot of the store, and the
/// two are not taken at one instant.  What each check can show:
///
/// - The newest step is always still in the overlay, so its rows, and the
///   removal of the step before's, show a view whose overlay is short of
///   commits it should hold: a reader that goes back a step, or a step
///   half there.  A flush retired before its commit has landed does that.
/// - They cannot show a view that has lost the rows of a flush already
///   retired, because nothing of the newest step is in such a flush.  The
///   row each step leaves for good can: a store snapshot from before a
///   flush's commit under an overlay from after its retirement holds that
///   flush's steps in neither, and a reader at a later step misses their
///   rows.
///
/// Nothing is held here: the committer races the readers as it does in
/// the daemon, so a wrong pairing is caught only when the scheduler
/// happens to produce it, which it does often on a busy machine and
/// seldom on an idle one.  Two of the crate's own tests hold what this
/// one leaves to chance.
/// `a_reader_between_the_commit_and_its_retirement_sees_the_captured_rows_once`
/// places a reader where a batch is in the overlay and the store at once,
/// and `a_commit_that_lands_inside_a_begin_is_retired_only_after_it` lets
/// a commit land between a reader's two snapshots and shows its
/// retirement waiting, which is what keeps a retired flush's rows from
/// being lost.
///
/// The steps go on until enough flushes have committed on a thread of
/// their own, however many that takes: how often a step trips one depends
/// on how often a reader holds the overlay's newest layer when the step
/// commits, which is up to the scheduler.
#[test]
fn readers_never_see_a_state_between_commits() {
    /// Flushes on a thread of their own the readers must have run beside.
    const FLUSHES: usize = 50;
    /// Far more steps than that takes: about ten arm and trip one flush.
    const MAX_STEPS: u32 = 4000;
    const READERS: usize = 3;

    let rig = Rig::new();
    let background = || {
        rig.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, obs)| obs.background)
            .count()
    };
    let done = Arc::new(AtomicBool::new(false));
    let readers: Vec<_> = (0..READERS)
        .map(|_| {
            let db = rig.db.clone();
            let done = Arc::clone(&done);
            std::thread::spawn(move || {
                let (mut last, mut views) = (0u32, 0u64);
                while !done.load(Ordering::SeqCst) {
                    db.view(|tx| {
                        let step = step_seen(tx);
                        assert!(step >= last, "a reader went back from {last} to {step}");
                        last = step;
                        views += 1;
                        Ok(())
                    })
                    .expect("view");
                }
                drop(db);
                (last, views)
            })
        })
        .collect();

    let mut steps = 0u32;
    while background() < FLUSHES {
        if steps == MAX_STEPS {
            // The readers stop before the test fails, or they would go on
            // reading a store nobody writes to.
            done.store(true, Ordering::SeqCst);
            panic!(
                "only {} flushes committed on a thread of their own in {steps} steps, so the \
                 readers raced too few retirements to show anything",
                background()
            );
        }
        steps += 1;
        rig.db.update(|tx| put_step(tx, steps)).expect("a step");
    }
    done.store(true, Ordering::SeqCst);
    for reader in readers {
        let (last, views) = reader.join().expect("a reader failed");
        assert!(views > 0 && last <= steps);
    }
    rig.db
        .wait_background_commit()
        .expect("the last commit landed");
    assert!(background() >= FLUSHES);
    rig.db
        .view(|tx| {
            assert_eq!(step_seen(tx), steps);
            Ok(())
        })
        .expect("view");

    rig.db.flush().expect("flush");
    let (_dir, path) = rig.crash();
    let db = Database::open(&Options::new(&path, NET)).expect("reopen");
    db.view(|tx| {
        assert_eq!(step_seen(tx), steps, "the last step is durable and whole");
        Ok(())
    })
    .expect("view");
    db.close().expect("close");
}

// ---------------------------------------------------------------------
// A commit that fails on its own thread
// ---------------------------------------------------------------------

/// A background commit that fails latches the store, logs the failure
/// once, and only then tells the participant: `finished(false)` finds the
/// store already refusing writes.  The next write, the next flush and the
/// close are each refused with the failed commit as the first cause, the
/// refused write runs no hook, and the rows committed while the commit
/// was under way are still readable.
#[test]
fn a_failed_background_commit_latches_and_the_next_write_names_the_cause() {
    let rig = Rig::new();
    let recorder = Recorder::new(&rig.prefix);
    {
        let db = rig.db.clone();
        *recorder.probe.lock().unwrap() = Some(Box::new(move || db.is_fatal()));
    }
    rig.db
        .set_flush_participant(
            &rig.prefix,
            Arc::clone(&recorder) as Arc<dyn FlushParticipant>,
        )
        .expect("register");

    connect(&rig.db, &recorder, 1, FILL_ROWS).expect("generation 1");
    rig.gate.arm();
    connect(&rig.db, &recorder, 2, 1).expect("generation 2 trips the flush and returns");
    assert!(rig.gate.wait_held(NEVER), "the commit is under way");
    assert_eq!(recorder.calls(), vec![Call::Contribute]);
    connect(&rig.db, &recorder, 3, 1).expect("generation 3, during the commit");
    assert_eq!(recorder.pending(), vec![1, 2, 3]);

    rig.power.power_fails_after(0);
    rig.gate.open();
    assert!(
        rig.db.is_fatal_settled(),
        "the failed commit latched the store"
    );
    // The latch comes first and the rest after it, and a settled read
    // that finds the store latched waits for nothing more: the committer
    // itself is waited for before what it did next is looked at.
    let err = rig
        .db
        .wait_background_commit()
        .expect_err("the store is latched");
    assert_refused_for_the_power_cut("the wait", &err);
    assert_eq!(
        recorder.calls(),
        vec![Call::Contribute, Call::Finished(false)]
    );
    assert_eq!(
        *recorder.latched.lock().unwrap(),
        vec![true],
        "the store was latched before the participant was told"
    );
    let errors = rig.error_lines();
    assert_eq!(errors.len(), 1, "one line for the failure: {errors:?}");
    assert!(
        errors[0].starts_with("Background commit of the metadata write cache failed: ")
            && errors[0].contains("power cut"),
        "{errors:?}"
    );
    assert!(
        rig.observations().is_empty(),
        "a failed flush is not reported"
    );

    let err = connect(&rig.db, &recorder, 4, 1).expect_err("a write on a latched store");
    assert_refused_for_the_power_cut("the next write", &err);
    assert_eq!(
        recorder.pending(),
        vec![1, 2, 3],
        "the refused write ran its hook, or the failed flush retired keys"
    );
    let err = rig.db.flush().expect_err("a flush on a latched store");
    assert_refused_for_the_power_cut("the flush", &err);
    assert_eq!(
        rig.readable(4),
        vec![1, 2, 3],
        "rows committed before the failure are still readable"
    );

    // The probe holds a handle; let go of it with the participant.
    *recorder.probe.lock().unwrap() = None;
    let err = rig.db.close().expect_err("a close of a latched store");
    assert_refused_for_the_power_cut("the close", &err);
    assert_eq!(rig.db.close().unwrap_err().kind, ErrorKind::DbNotOpen);
    assert_eq!(
        recorder.calls(),
        vec![Call::Contribute, Call::Finished(false)],
        "nothing ran the participant again"
    );
    assert_eq!(rig.error_lines().len(), 1);
}

/// The error line is the committer's alone.  A flush that fails on the
/// thread that asked for it hands the failure to its caller, which is
/// where every flush's failure went before commits could leave their
/// thread, and logs nothing: the line says a commit failed with nobody
/// to tell.
#[test]
fn a_flush_that_fails_on_the_asking_thread_logs_no_background_failure() {
    let rig = Rig::new();
    rig.small(1);
    rig.power.power_fails_after(0);
    let err = rig.db.flush().expect_err("no power to write with");
    assert!(err.description.contains("power cut"), "{err}");
    assert!(rig.db.is_fatal());
    assert!(
        rig.error_lines().is_empty(),
        "a failure handed to its caller was logged as a background commit's: {:?}",
        rig.error_lines()
    );
    let (_dir, path) = rig.crash();
    assert_eq!(reopened(&path, 1), Vec::<u32>::new());
}

/// A committer thread that panics has not ended its flush as a flush
/// ends, and the next wait for it latches the store, naming the panic.
/// Here the participant panics in `finished`, after the commit has landed
/// and its layers are retired: the flush was observed, the batch is
/// durable, and from the wait on every write, flush and close is refused
/// while reads go on.  The participant's memory is as the panic left it,
/// which a store that takes no more writes never looks at again.
///
/// Only a build whose panics unwind has this path, which a test build
/// is; a release build aborts.
#[test]
fn a_committer_that_panics_after_its_commit_latches_the_store_at_the_next_wait() {
    let rig = Rig::new();
    let recorder = Recorder::panicking(&rig.prefix);
    rig.db
        .set_flush_participant(
            &rig.prefix,
            Arc::clone(&recorder) as Arc<dyn FlushParticipant>,
        )
        .expect("register");
    connect(&rig.db, &recorder, 1, FILL_ROWS).expect("generation 1");
    connect(&rig.db, &recorder, 2, 1).expect("generation 2 trips the flush and returns");

    let err = rig
        .db
        .wait_background_commit()
        .expect_err("the committer panicked");
    assert_eq!(err.kind, ErrorKind::Fatal, "{err}");
    assert!(
        err.description
            .contains("(the first failure: the background commit thread panicked"),
        "{err}"
    );
    assert!(rig.db.is_fatal());
    assert_eq!(
        recorder.calls(),
        vec![Call::Contribute, Call::Finished(true)]
    );
    let seen = rig.observations();
    assert_eq!(seen.len(), 1, "the flush was retired: {seen:?}");
    assert!(seen[0].1.background, "{seen:?}");

    let err = connect(&rig.db, &recorder, 3, 1).expect_err("a write on a latched store");
    assert_eq!(err.kind, ErrorKind::Fatal, "{err}");
    assert_eq!(
        recorder.pending(),
        vec![1, 2],
        "the refused write ran its hook"
    );
    assert_eq!(rig.db.flush().unwrap_err().kind, ErrorKind::Fatal);
    assert_eq!(rig.readable(3), vec![1, 2], "reads go on");
    // The close stops the thread that panicked, and returns.
    let closed = in_background(&rig.db, |db| db.close());
    let err = closed
        .recv_timeout(NEVER)
        .expect("the close of a store whose commit thread panicked returns")
        .expect_err("a close of a latched store");
    assert_eq!(err.kind, ErrorKind::Fatal, "{err}");
    assert!(
        err.description
            .contains("(the first failure: the background commit thread panicked"),
        "{err}"
    );
    assert_eq!(
        recorder.calls().len(),
        2,
        "nothing ran the participant again"
    );

    let (_dir, path) = rig.crash();
    assert_eq!(
        reopened(&path, 3),
        vec![1],
        "the batch whose commit had landed is durable"
    );
}

/// A block record whose header gives `height`, with its hash: what
/// `Transaction::store_block_raw` files it under.
fn raw_block(height: u32, fill: u8) -> (dcroxide_chainhash::Hash, Vec<u8>) {
    let mut raw = vec![fill; 300];
    raw[128..132].copy_from_slice(&height.to_le_bytes());
    (dcroxide_chainhash::hash_h(&raw[..180]), raw)
}

/// The bytes in the store's block files.
///
/// Each file's size is read from the file itself: on Windows a
/// directory entry's metadata is what the directory recorded, which can
/// lag behind a file the store still holds open.
fn block_file_bytes(db_dir: &std::path::Path) -> u64 {
    std::fs::read_dir(db_dir)
        .expect("the database directory")
        .map(|entry| entry.expect("an entry").path())
        .filter(|path| path.extension().is_some_and(|e| e == "fdb"))
        .map(|path| std::fs::metadata(&path).expect("metadata").len())
        .sum()
}

/// A transaction that was open when a background commit failed is
/// refused when it commits: the latch is looked at again by every commit,
/// before it writes a block or runs a hook.  Its block leaves no bytes in
/// the block files, its hook does not run, and its rows are not
/// published.
///
/// The flush that failed was one the participant asked for, over an
/// overlay far below its own trigger.  So nothing but the latch stands
/// between the open transaction and a commit that reports `Ok`: its flush
/// check has nothing to flush and no commit to wait for.
#[test]
fn a_commit_begun_before_a_background_failure_is_refused_after_it() {
    let rig = Rig::new();
    let db_dir = rig.dir.path().join("db");
    let recorder = Recorder::new(&rig.prefix);
    rig.db
        .set_flush_participant(
            &rig.prefix,
            Arc::clone(&recorder) as Arc<dyn FlushParticipant>,
        )
        .expect("register");
    connect(&rig.db, &recorder, 1, 1).expect("generation 1");
    recorder.want.store(true, Ordering::SeqCst);
    rig.gate.arm();
    connect(&rig.db, &recorder, 2, 1).expect("generation 2 trips the flush and returns");
    assert!(rig.gate.wait_held(NEVER), "the commit is under way");
    recorder.want.store(false, Ordering::SeqCst);

    commit_across_the_failure(&rig, &db_dir);
    assert_eq!(
        recorder.calls(),
        vec![Call::Contribute, Call::Finished(false)],
        "the refused commit ran the participant"
    );
    assert_eq!(
        recorder.pending(),
        vec![1, 2],
        "the refused commit ran its hook, or the failed flush retired keys"
    );
    let (_dir, path) = rig.crash();
    assert_eq!(reopened(&path, 3), Vec::<u32>::new());
}

/// The same when the flush that failed had captured an overlay over its
/// trigger.  The accounting a failed flush puts back arms the next
/// commit's flush check again, and that check, made after the wait for
/// the commit under way, is refused too: the commit's block is rolled
/// back out of the block files.
#[test]
fn a_commit_begun_before_a_background_failure_does_not_flush_again() {
    let rig = Rig::new();
    let db_dir = rig.dir.path().join("db");
    rig.hold_a_commit();
    commit_across_the_failure(&rig, &db_dir);
    let (_dir, path) = rig.crash();
    assert_eq!(reopened(&path, 3), Vec::<u32>::new());
}

/// A commit whose own flush has to wait for the commit under way is
/// refused when that commit fails, with the failed commit as the cause:
/// the latch is looked at again after the wait, before anything is
/// captured.  Without that look the waiting commit would capture a flush
/// of its own on the latched store and report whatever the storage engine
/// then says of a write after a failed one, which reads as corruption.
#[test]
fn a_commit_that_waited_for_a_failing_commit_is_refused_with_its_cause() {
    let rig = Rig::new();
    rig.hold_a_commit();
    // Arms the next commit's flush while the first is still held.
    rig.db
        .update(|tx| put_generation(tx, 3, FILL_ROWS - 8, FILL_VALUE))
        .expect("generation 3");
    let waiting = in_background(&rig.db, |db| db.update(|tx| put_generation(tx, 4, 1, 8)));
    assert_waiting(&waiting, "a commit whose flush must wait");

    rig.power.power_fails_after(0);
    rig.gate.open();
    let err = waiting
        .recv_timeout(NEVER)
        .expect("the commit returns")
        .expect_err("the commit it waited for failed");
    assert_refused_for_the_power_cut("the waiting commit", &err);
    assert!(
        rig.observations().is_empty(),
        "nothing was captured after the failure"
    );
    assert_eq!(rig.error_lines().len(), 1, "one failure, logged once");
    assert_eq!(
        rig.readable(4),
        vec![1, 2, 3],
        "the refused commit published its rows"
    );

    let (_dir, path) = rig.crash();
    assert_eq!(reopened(&path, 4), Vec::<u32>::new());
}

/// With a commit held on its own thread: begin a transaction that stores
/// a block, writes generation 3 and plants a hook; fail the held commit
/// and wait for the latch; then commit the transaction, which must be
/// refused with the failed commit as the cause, run no hook, leave the
/// block files as they were and publish nothing.  The committer has ended
/// when this returns.
fn commit_across_the_failure(rig: &Rig, db_dir: &std::path::Path) {
    // Begun with the store healthy.  It holds the writer from here on,
    // which the committer never needs.
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
    put_generation(&tx, 3, 1, 8).expect("rows");
    let (hash, raw) = raw_block(7, 0x33);
    tx.store_block_raw(&hash, raw).expect("a pending block");
    let before = block_file_bytes(db_dir);

    rig.power.power_fails_after(0);
    rig.gate.open();
    let deadline = Instant::now() + NEVER;
    while !rig.db.is_fatal() {
        assert!(Instant::now() < deadline, "the held commit never failed");
        std::thread::sleep(Duration::from_millis(1));
    }

    let err = tx.commit().expect_err("a commit on a latched store");
    assert_refused_for_the_power_cut("the commit", &err);
    assert!(
        !hook_ran.load(Ordering::SeqCst),
        "a refused commit ran its hook"
    );
    assert_eq!(
        block_file_bytes(db_dir),
        before,
        "a refused commit left block bytes behind"
    );
    assert_eq!(
        rig.readable(3),
        vec![1, 2],
        "a refused commit published its rows"
    );
    rig.db
        .view(|tx| {
            assert!(!tx.has_block(&hash, 7)?, "the refused block is not stored");
            Ok(())
        })
        .expect("view");
    // The committer latched the store before it told the participant:
    // it is waited for, now that the writer is free, so that a caller
    // finds everything it did.
    let err = rig
        .db
        .wait_background_commit()
        .expect_err("the store is latched");
    assert_refused_for_the_power_cut("the wait", &err);
}

/// `Database::is_fatal_settled` waits for the commit under way before it
/// answers, so a caller that asks while that commit is failing is not
/// told the store is healthy: `Database::is_fatal` read at the same
/// moment says `false`.  A reader open across the failure does not hold
/// it up.  With no commit under way, or the option off, it waits for
/// nothing.
#[test]
fn is_fatal_settled_waits_for_a_failing_commit() {
    let rig = Rig::new();
    assert!(!rig.db.is_fatal_settled(), "nothing is under way");

    rig.hold_a_commit();
    let reader = rig.db.begin(false).expect("begin a reader");
    rig.power.power_fails_after(0);
    let settled = in_background(&rig.db, |db| db.is_fatal_settled());
    assert_waiting(&settled, "the settled read");
    assert!(
        !rig.db.is_fatal(),
        "the latch itself knows nothing until the commit has returned"
    );
    rig.gate.open();
    assert!(
        settled
            .recv_timeout(NEVER)
            .expect("the settled read returns"),
        "the commit it waited for failed"
    );
    assert!(rig.db.is_fatal());
    assert!(
        rig.db.is_fatal_settled(),
        "latched: no wait, the same answer"
    );
    reader.rollback().expect("end the reader");

    let (_dir, path) = rig.crash();
    assert_eq!(reopened(&path, 2), Vec::<u32>::new());

    // A commit that lands: the wait, then `false`.
    let rig = Rig::new();
    rig.hold_a_commit();
    let settled = in_background(&rig.db, |db| db.is_fatal_settled());
    assert_waiting(&settled, "the settled read");
    rig.gate.open();
    assert!(
        !settled
            .recv_timeout(NEVER)
            .expect("the settled read returns")
    );
    let (_dir, path) = rig.crash();
    assert_eq!(reopened(&path, 2), vec![1]);
}

// ---------------------------------------------------------------------
// One flush in flight
// ---------------------------------------------------------------------

/// `Database::is_fatal_settled` waits for the commit under way with the
/// writer held, as every other wait for it is made.  A commit that comes
/// along meanwhile queues behind it, and makes its own wait once the
/// writer is its own.  Were the settled read to take the committer's
/// thread out of its slot without the writer, the commit would find the
/// slot empty, wait for nothing, and capture a second flush while the
/// first was still in flight, which latches a healthy store.
#[test]
fn a_settled_read_leaves_a_commits_wait_in_place() {
    let rig = Rig::new();
    rig.hold_a_commit();
    // Arms the next commit's flush while the first is still held.
    rig.db
        .update(|tx| put_generation(tx, 3, FILL_ROWS - 8, FILL_VALUE))
        .expect("generation 3");
    let settled = in_background(&rig.db, |db| db.is_fatal_settled());
    assert_waiting(&settled, "the settled read");
    let waiting = in_background(&rig.db, |db| db.update(|tx| put_generation(tx, 4, 1, 8)));
    assert_waiting(&waiting, "a commit whose flush must wait");

    rig.gate.open();
    waiting
        .recv_timeout(NEVER)
        .expect("the commit returns")
        .expect("generation 4");
    assert!(
        !settled
            .recv_timeout(NEVER)
            .expect("the settled read returns"),
        "the commit under way landed"
    );
    rig.db.wait_background_commit().expect("the commits landed");
    assert!(!rig.db.is_fatal());
    let seen = rig.observations();
    assert_eq!(seen.len(), 2, "each flush in its turn: {seen:?}");
    assert_eq!(rig.readable(4), vec![1, 2, 3, 4]);

    let (_dir, path) = rig.crash();
    assert_eq!(reopened(&path, 4), vec![1, 2, 3]);
}

/// A flush the participant asks for waits for the commit under way like
/// one the overlay's own thresholds trip: the commit that finds the
/// participant asking does not capture until the flush in flight has
/// ended, with its `finished`, so the participant sees its flushes one
/// after another.
#[test]
fn a_flush_the_participant_asks_for_waits_for_the_commit_under_way() {
    let rig = Rig::new();
    let recorder = Recorder::new(&rig.prefix);
    rig.db
        .set_flush_participant(
            &rig.prefix,
            Arc::clone(&recorder) as Arc<dyn FlushParticipant>,
        )
        .expect("register");
    connect(&rig.db, &recorder, 1, FILL_ROWS).expect("generation 1");
    rig.gate.arm();
    connect(&rig.db, &recorder, 2, 1).expect("generation 2 trips the flush and returns");
    assert!(rig.gate.wait_held(NEVER), "the commit is under way");

    // The overlay holds one small generation above the captured one, far
    // below its own trigger: only the participant asks.
    recorder.want.store(true, Ordering::SeqCst);
    let waiting = {
        let recorder = Arc::clone(&recorder);
        in_background(&rig.db, move |db| connect(db, &recorder, 3, 1))
    };
    assert_waiting(&waiting, "a commit whose participant asks for a flush");
    assert_eq!(recorder.calls(), vec![Call::Contribute]);

    rig.gate.open();
    waiting
        .recv_timeout(NEVER)
        .expect("the commit returns")
        .expect("generation 3");
    recorder.want.store(false, Ordering::SeqCst);
    rig.db.wait_background_commit().expect("the commits landed");
    assert!(!rig.db.is_fatal());
    assert_eq!(
        recorder.calls(),
        vec![
            Call::Contribute,
            Call::Finished(true),
            Call::Contribute,
            Call::Finished(true)
        ],
        "the second flush began after the first had finished"
    );

    let (_dir, path) = rig.crash();
    assert_eq!(reopened(&path, 3), vec![1, 2]);
}

// ---------------------------------------------------------------------
// The commit thread
// ---------------------------------------------------------------------

/// Every flush handed over is committed on one thread, the store's
/// commit thread, whether the flush before it was waited for or its
/// capture made the wait itself, and a flush that is asked for is made on
/// the thread that asked.  A thread made for each flush would show a new
/// one each time.  Every generation is durable once the flush asked for
/// has returned.
#[test]
fn every_handed_over_flush_runs_on_one_thread() {
    const FLUSHES: u32 = 40;
    let rig = Rig::new();
    for i in 0..FLUSHES {
        let generation = 2 * i + 1;
        rig.fill(generation);
        rig.small(generation + 1);
        // One flush in three is waited for here; the others are waited
        // for by the capture of the next.
        if i % 3 == 0 {
            rig.db.wait_background_commit().expect("the flush landed");
        }
    }
    let last = 2 * FLUSHES + 1;
    rig.small(last);
    rig.db.flush().expect("an explicit flush");

    let seen = rig.observations();
    let ids = rig.observation_threads();
    assert_eq!(seen.len(), FLUSHES as usize + 1, "{seen:?}");
    assert_eq!(ids.len(), seen.len());
    let committer = ids[0];
    assert_ne!(committer, std::thread::current().id());
    for (i, ((thread, obs), id)) in seen.iter().zip(&ids).take(FLUSHES as usize).enumerate() {
        assert!(obs.background && !obs.explicit, "flush {i}: {obs:?}");
        assert_eq!(thread.as_deref(), Some(COMMIT_THREAD_NAME), "flush {i}");
        assert_eq!(
            *id, committer,
            "flush {i} ran on another thread than the first"
        );
    }
    let (thread, obs) = &seen[FLUSHES as usize];
    assert!(obs.explicit && !obs.background, "{obs:?}");
    assert_ne!(thread.as_deref(), Some(COMMIT_THREAD_NAME));
    assert_eq!(ids[FLUSHES as usize], std::thread::current().id());

    let (_dir, path) = rig.crash();
    assert_eq!(reopened(&path, last), (1..=last).collect::<Vec<u32>>());
}

// ---------------------------------------------------------------------
// The calls that acknowledge durability
// ---------------------------------------------------------------------

/// A flush that was asked for has made its redb commit when it returns,
/// on the thread that asked: with the committer's storage shut off
/// behind the gate, the flush still lands, is observed before it
/// returns, and survives a power cut.  Were its commit handed to a
/// thread of its own it would be held, and the flush would have returned
/// `Ok` for rows that are not durable.
#[test]
fn an_asked_for_flush_has_committed_when_it_returns() {
    let rig = Rig::new();
    rig.db
        .wait_background_commit()
        .expect("nothing is under way");
    rig.small(1);
    rig.gate.arm();
    // On a thread of its own, so that this one can tell a flush that
    // returned from one that is waiting.
    let flushed = in_background(&rig.db, |db| db.flush());
    flushed
        .recv_timeout(NEVER)
        .expect("the flush returns")
        .expect("the flush");
    let seen = rig.observations();
    assert_eq!(
        seen.len(),
        1,
        "the flush returned before its commit had landed: {seen:?}"
    );
    let (thread, obs) = &seen[0];
    assert!(obs.explicit && !obs.background, "{obs:?}");
    assert_ne!(thread.as_deref(), Some(COMMIT_THREAD_NAME));
    assert!(!rig.gate.is_held(), "no commit left the thread that asked");

    let (_dir, path) = rig.crash();
    assert_eq!(reopened(&path, 1), vec![1]);
}

/// `Database::flush` waits for the commit under way, then makes its own
/// on the calling thread: when it returns `Ok`, every commit made before
/// it was called survives a power cut.
#[test]
fn flush_waits_for_the_background_commit() {
    let rig = Rig::new();
    rig.hold_a_commit();
    rig.small(3);
    // Were the flush's own commit handed to a committer thread, it would
    // be held too and the cut below would lose it.
    rig.rearm.store(true, Ordering::SeqCst);

    let flushed = in_background(&rig.db, |db| db.flush());
    assert_waiting(&flushed, "the flush");
    rig.gate.open();
    flushed
        .recv_timeout(NEVER)
        .expect("the flush returns")
        .expect("the flush");

    let seen = rig.observations();
    assert_eq!(
        seen.len(),
        2,
        "the commit under way, then the flush: {seen:?}"
    );
    let (thread, first) = &seen[0];
    assert_eq!(thread.as_deref(), Some(COMMIT_THREAD_NAME));
    assert!(first.background && !first.explicit, "{first:?}");
    let (thread, second) = &seen[1];
    assert_ne!(thread.as_deref(), Some(COMMIT_THREAD_NAME));
    assert!(
        second.explicit && !second.background,
        "an asked-for flush commits on the thread that asked: {second:?}"
    );
    assert_eq!(second.foreground, second.elapsed);
    assert!(
        second.waited > Duration::ZERO,
        "the flush reports what it waited for the commit before it: {second:?}"
    );
    assert!(!rig.gate.is_held());

    let (_dir, path) = rig.crash();
    assert_eq!(
        reopened(&path, 3),
        vec![1, 2, 3],
        "a flush acknowledged a commit a power cut then lost"
    );
}

/// A flush that waited for a commit that failed reports that failure,
/// and acknowledges nothing.
#[test]
fn flush_reports_a_background_commit_that_failed() {
    let rig = Rig::new();
    rig.hold_a_commit();
    rig.small(3);

    let flushed = in_background(&rig.db, |db| db.flush());
    assert_waiting(&flushed, "the flush");
    rig.power.power_fails_after(0);
    rig.gate.open();
    let err = flushed
        .recv_timeout(NEVER)
        .expect("the flush returns")
        .expect_err("the commit it waited for failed");
    assert_refused_for_the_power_cut("the flush", &err);
    assert!(rig.db.is_fatal());
    assert!(rig.observations().is_empty());

    let (_dir, path) = rig.crash();
    assert_eq!(reopened(&path, 3), Vec::<u32>::new());
}

/// `Database::close` waits for the commit under way and then flushes on
/// the closing thread: no committer outlives it, and everything
/// committed before it is durable.
#[test]
fn close_waits_for_the_background_commit() {
    let rig = Rig::new();
    rig.hold_a_commit();
    rig.small(3);
    rig.rearm.store(true, Ordering::SeqCst);

    let closed = in_background(&rig.db, |db| db.close());
    assert_waiting(&closed, "the close");
    rig.gate.open();
    closed
        .recv_timeout(NEVER)
        .expect("the close returns")
        .expect("the close");

    // The committer retired its flush, which is where it is observed,
    // before the close's own flush was captured.
    let seen = rig.observations();
    assert_eq!(
        seen.len(),
        2,
        "the commit under way, then the close: {seen:?}"
    );
    assert!(seen[0].1.background && !seen[0].1.explicit, "{seen:?}");
    assert!(seen[1].1.explicit && !seen[1].1.background, "{seen:?}");
    assert_ne!(seen[1].0.as_deref(), Some(COMMIT_THREAD_NAME));
    assert!(!rig.gate.is_held());

    let (_dir, path) = rig.crash();
    assert_eq!(reopened(&path, 3), vec![1, 2, 3]);
}

/// A close of a store that a background commit has just latched still
/// waits for that commit's thread, which has more to do after the latch:
/// here it is held while it logs the failure.
#[test]
fn close_of_a_latched_store_waits_for_the_committer_that_latched_it() {
    let rig = Rig::new();
    rig.hold_a_commit();
    rig.power.power_fails_after(0);
    rig.log_hold.arm();
    rig.gate.open();
    assert!(
        rig.log_hold.wait_reached(NEVER),
        "the committer logs its failure"
    );
    assert!(rig.db.is_fatal(), "latched before the line is logged");

    let closed = in_background(&rig.db, |db| db.close());
    assert_waiting(&closed, "the close of a latched store");
    rig.log_hold.release();
    let err = closed
        .recv_timeout(NEVER)
        .expect("the close returns")
        .expect_err("the store is latched");
    assert_refused_for_the_power_cut("the close", &err);
    assert_eq!(rig.error_lines().len(), 1);

    let (_dir, path) = rig.crash();
    assert_eq!(reopened(&path, 2), Vec::<u32>::new());
}

// ---------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------

/// Registering a participant and clearing one both wait for the commit
/// under way: a flush ends with the registration it began with, and a
/// cleared participant has had its `finished`.
#[test]
fn set_and_clear_wait_out_a_background_commit() {
    let rig = Rig::new();
    let recorder = Recorder::new(&rig.prefix);

    // A flush that began with no participant.
    rig.hold_a_commit();
    let registered = {
        let prefix = rig.prefix.clone();
        let participant = Arc::clone(&recorder) as Arc<dyn FlushParticipant>;
        in_background(&rig.db, move |db| {
            db.set_flush_participant(&prefix, participant)
        })
    };
    assert_waiting(&registered, "the registration");
    rig.gate.open();
    registered
        .recv_timeout(NEVER)
        .expect("the registration returns")
        .expect("register");
    assert!(recorder.calls().is_empty(), "that flush was not its own");

    // A flush it contributed to.  The first flush has retired, so
    // generation 3 arms the next commit's.
    connect(&rig.db, &recorder, 3, FILL_ROWS).expect("generation 3");
    rig.gate.arm();
    connect(&rig.db, &recorder, 4, 1).expect("generation 4 trips the flush and returns");
    assert!(rig.gate.wait_held(NEVER), "the commit is under way");
    assert_eq!(recorder.calls(), vec![Call::Contribute]);

    let cleared = in_background(&rig.db, |db| db.clear_flush_participant().is_some());
    assert_waiting(&cleared, "the clear");
    rig.gate.open();
    assert!(
        cleared.recv_timeout(NEVER).expect("the clear returns"),
        "the participant was registered"
    );
    assert_eq!(
        recorder.calls(),
        vec![Call::Contribute, Call::Finished(true)],
        "the participant was released before its flush finished"
    );
    assert_eq!(
        recorder.pending(),
        vec![4],
        "the key handed over during the commit waits for the next flush"
    );

    rig.db.flush().expect("flush");
    let (_dir, path) = rig.crash();
    assert_eq!(reopened(&path, 4), vec![1, 2, 3, 4]);
}

// ---------------------------------------------------------------------
// The overlay's bound
// ---------------------------------------------------------------------

/// While a commit is under way the overlay holds the layers it captured
/// and everything committed since.  A commit that finds the two together
/// over the overlay's maximum waits for the commit under way, with the
/// writer held, and adds its rows only once the captured layers are
/// retired.  It does not flush for that reason: the rows committed since
/// the capture are still under their own trigger.
#[test]
fn the_writer_blocks_at_the_overlay_ceiling_while_a_commit_is_in_flight() {
    let rig = Rig::new();
    rig.hold_a_commit();
    // Twelve kibibyte rows above the captured forty-eight: over the
    // maximum together, and on their own a third of the flush trigger.
    rig.db
        .update(|tx| put_generation(tx, 3, 12, FILL_VALUE))
        .expect("generation 3 fits under the maximum when its commit checks");

    let blocked = in_background(&rig.db, |db| db.update(|tx| put_generation(tx, 4, 1, 8)));
    assert_waiting(&blocked, "a commit over the overlay's maximum");
    assert_eq!(
        rig.readable(4),
        vec![1, 2, 3],
        "readers go on, and the waiting commit has published nothing"
    );
    assert!(rig.observations().is_empty());

    rig.gate.open();
    blocked
        .recv_timeout(NEVER)
        .expect("the commit returns")
        .expect("generation 4");
    let seen = rig.observations();
    assert_eq!(
        seen.len(),
        1,
        "the wait was all the ceiling asked for; nothing more was flushed: {seen:?}"
    );
    assert!(seen[0].1.background, "{seen:?}");
    // What the overlay held when the layers were retired: over its
    // maximum, which is why generation 4 waited, by no more than the one
    // transaction that took it there.
    let held = seen[0].1.memory.overlay_at_retirement;
    let generation_3 = 13 * (FILL_VALUE as u64 + 100);
    assert!(
        held > CACHE_MAX && held <= CACHE_MAX + generation_3,
        "the overlay held {held} bytes against a maximum of {CACHE_MAX}"
    );
    assert_eq!(rig.readable(4), vec![1, 2, 3, 4]);

    // The next flush reports the wait: the writer was held for it.
    rig.fill(5);
    rig.small(6);
    rig.db.wait_background_commit().expect("the commit landed");
    let seen = rig.observations();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert!(
        seen[1].1.waited > Duration::ZERO,
        "the wait at the ceiling is counted against the next flush: {:?}",
        seen[1].1
    );

    // And against that flush alone: the count starts again at each
    // capture, so the flush after it reports only the wait for its own
    // predecessor's commit, which was not held and so is shorter than
    // the wait at the ceiling.
    rig.fill(7);
    rig.small(8);
    rig.db.wait_background_commit().expect("the commit landed");
    let seen = rig.observations();
    assert_eq!(seen.len(), 3, "{seen:?}");
    assert!(
        seen[2].1.waited < seen[1].1.waited,
        "a wait is counted against one flush only: {:?} after {:?}",
        seen[2].1.waited,
        seen[1].1.waited
    );
    let (_dir, path) = rig.crash();
    assert_eq!(reopened(&path, 8), vec![1, 2, 3, 4, 5, 6, 7]);
}

// ---------------------------------------------------------------------
// A participant that has not opted in
// ---------------------------------------------------------------------

/// A flush that a participant contributed to is handed over only if the
/// participant allows its `finished` to be deferred, which it does not
/// unless it says so.  One that does not gets the commit on the thread
/// that tripped the flush: its `finished` has been called, after the
/// commit, by the time the tripping commit's hook runs.  A flush it had
/// nothing to contribute to is handed over like any other, since no
/// `finished` is owed.
#[test]
fn a_participant_that_does_not_opt_in_commits_inline() {
    let rig = Rig::new();
    let recorder = Recorder::new(&rig.prefix);
    rig.db
        .set_flush_participant(
            &rig.prefix,
            Arc::new(NotOptedIn(Arc::clone(&recorder))) as Arc<dyn FlushParticipant>,
        )
        .expect("register");

    connect(&rig.db, &recorder, 1, FILL_ROWS).expect("generation 1");
    // Were the commit handed over after all, it would be held.
    rig.gate.arm();
    connect(&rig.db, &recorder, 2, 1).expect("generation 2 trips the flush");
    assert_eq!(
        recorder.calls(),
        vec![Call::Contribute, Call::Finished(true)],
        "the participant was finished before the commit that tripped the flush returned"
    );
    assert_eq!(
        recorder.pending(),
        vec![2],
        "generation 2's hook ran after the flush had finished"
    );
    assert!(!rig.gate.is_held(), "no commit left this thread");
    let seen = rig.observations();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(!seen[0].1.background && !seen[0].1.explicit, "{seen:?}");
    assert_ne!(seen[0].0.as_deref(), Some(COMMIT_THREAD_NAME));

    // With nothing pending the participant contributes nothing, and the
    // flush is handed over.  Generation 2's key is written first.
    rig.gate.open();
    rig.db.flush().expect("flush");
    assert!(recorder.pending().is_empty());
    rig.fill(3);
    rig.gate.arm();
    rig.small(4);
    assert!(
        rig.gate.wait_held(NEVER),
        "a flush the participant has no part in is handed over"
    );
    rig.gate.open();
    rig.db.wait_background_commit().expect("the commit landed");
    let seen = rig.observations();
    assert!(seen.last().expect("a flush").1.background, "{seen:?}");
    assert_eq!(
        recorder.calls().len(),
        4,
        "two contributes, each with its finished, and none for the last flush: {:?}",
        recorder.calls()
    );

    let (_dir, path) = rig.crash();
    assert_eq!(reopened(&path, 4), vec![1, 2, 3]);
}

// ---------------------------------------------------------------------
// Power cuts
// ---------------------------------------------------------------------

/// Blocks stored by commits whose flushes land on a thread of their own
/// keep to the durable generation across a power cut, each under its own
/// height: the block files are synced before the commit is handed over,
/// and the rows that name the blocks are in the handed-over commit.  The
/// blocks of the commit that tripped the flush, written to the block
/// files after that sync and named by no durable row, are gone.
#[test]
fn power_loss_keeps_blocks_of_a_landed_background_commit_under_their_heights() {
    let rig = Rig::new();
    let durable: Vec<_> = [255u32, 256, 65_536, 1]
        .into_iter()
        .map(|height| (height, raw_block(height, 0x11)))
        .collect();
    let lost: Vec<_> = [257u32, 65_535, 16_777_216, 0]
        .into_iter()
        .map(|height| (height, raw_block(height, 0x22)))
        .collect();

    rig.db
        .update(|tx| {
            for (_, (hash, raw)) in &durable {
                tx.store_block_raw(hash, raw.clone())?;
            }
            put_generation(tx, 1, FILL_ROWS, FILL_VALUE)
        })
        .expect("the durable blocks");
    rig.gate.arm();
    rig.db
        .update(|tx| {
            for (_, (hash, raw)) in &lost {
                tx.store_block_raw(hash, raw.clone())?;
            }
            put_generation(tx, 2, 1, 8)
        })
        .expect("the blocks of the commit that trips the flush");
    assert!(rig.gate.wait_held(NEVER), "the commit is under way");
    rig.gate.open();
    rig.db.wait_background_commit().expect("the commit landed");
    let seen = rig.observations();
    assert!(seen.len() == 1 && seen[0].1.background, "{seen:?}");

    let (_dir, path) = rig.crash();
    let db = Database::open(&Options::new(&path, NET)).expect("reopen");
    db.view(|tx| {
        for (height, (hash, raw)) in &durable {
            assert!(tx.has_block(hash, *height)?, "{hash} at {height} survives");
            assert_eq!(&tx.fetch_block(hash, *height)?, raw);
            assert!(!tx.has_block(hash, height.swap_bytes())?, "{hash}");
        }
        for (height, (hash, _)) in &lost {
            assert!(!tx.has_block(hash, *height)?, "{hash} at {height} is gone");
        }
        Ok(())
    })
    .expect("view");
    assert_eq!(generations(&db, 2), vec![1]);
    // The store goes on from the durable generation.
    let (hash, raw) = raw_block(65_537, 0x44);
    db.update(|tx| tx.store_block_raw(&hash, raw))
        .expect("store after the power cut");
    db.close().expect("close");
}

/// One scripted run for the sweep below: six generations, each large
/// enough to arm the next commit's flush, with an asked-for flush after
/// the fourth.  Stops at the first refusal.  Returns the generations
/// committed, and how many of them the asked-for flush acknowledged.
fn scripted_run(rig: &Rig) -> (u32, u32) {
    let (mut committed, mut acknowledged) = (0u32, 0u32);
    for generation in 1..=6u32 {
        if rig
            .db
            .update(|tx| put_generation(tx, generation, FILL_ROWS, FILL_VALUE))
            .is_err()
        {
            break;
        }
        committed = generation;
        if generation == 4 {
            if rig.db.flush().is_err() {
                break;
            }
            acknowledged = 4;
        }
    }
    (committed, acknowledged)
}

/// The power can go at any storage operation of a run whose flushes
/// commit on a thread of their own, and the store comes back at one of
/// the run's commits: every generation up to some point whole and none
/// after it, with at least what an asked-for flush had acknowledged.
/// Commits land in the order they were captured, so a later generation
/// is never durable without the ones before it.
#[test]
fn a_power_cut_anywhere_leaves_a_prefix_of_the_commits() {
    // The run undisturbed, for the number of places to cut.
    let rig = Rig::new();
    let from = rig.power.ops();
    assert_eq!(scripted_run(&rig), (6, 4));
    rig.db
        .wait_background_commit()
        .expect("the last commit landed");
    let operations = rig.power.ops() - from;
    let background = rig
        .observations()
        .iter()
        .filter(|(_, obs)| obs.background)
        .count();
    assert!(
        background >= 3 && operations >= 20,
        "{background} flushes on a thread of their own over {operations} storage operations"
    );
    let (_dir, path) = rig.crash();
    assert_eq!(reopened(&path, 6), vec![1, 2, 3, 4, 5]);

    for cut in 0..operations {
        let rig = Rig::new();
        rig.power.power_fails_after(cut);
        let (committed, acknowledged) = scripted_run(&rig);
        let (_dir, path) = rig.crash();
        let found = reopened(&path, 6);
        let durable = found.len() as u32;
        assert_eq!(
            found,
            (1..=durable).collect::<Vec<u32>>(),
            "cut {cut}: the store is not at one of the run's commits"
        );
        assert!(
            durable <= committed,
            "cut {cut}: generation {durable} is durable and was never committed"
        );
        assert!(
            durable >= acknowledged,
            "cut {cut}: a flush acknowledged {acknowledged} generations and {durable} survived"
        );
    }
}

// ---------------------------------------------------------------------
// What a flush holds while its commit is under way
// ---------------------------------------------------------------------

/// A flush whose commit is under way reports what it pinned and what was
/// committed above it meanwhile: the layers it captured stay in the
/// overlay until the commit has landed, the commits made since are
/// counted beside them, and a transaction open across the retirement is
/// what still holds the captured layers afterwards.  With no such
/// transaction the flush held the last reference, and the thread that
/// made the commit freed them.
#[test]
fn a_background_flush_reports_what_it_pinned_and_what_was_committed_meanwhile() {
    let rig = Rig::new();
    rig.hold_a_commit();
    rig.small(3);
    // Open across the retirement, with the captured layers in its
    // snapshot.
    let reader = rig.db.begin(false).expect("begin a reader");
    rig.small(4);
    rig.gate.open();
    rig.db.wait_background_commit().expect("the commit landed");

    let seen = rig.observations();
    assert_eq!(seen.len(), 1, "{seen:?}");
    let obs = seen[0].1;
    let memory = obs.memory;
    assert!(obs.background && obs.snapshot, "{obs:?}");
    assert!(memory.pinned_layers >= 1, "{memory:?}");
    assert!(
        memory.pinned_entries >= obs.dirty_entries,
        "every entry written out was in a captured layer: {obs:?}"
    );
    assert_eq!(
        memory.overlay_at_hand_off, obs.dirty_bytes,
        "nothing is committed between the capture and the hand-off"
    );
    assert!(
        memory.overlay_at_retirement > obs.dirty_bytes,
        "generations 2 to 4 were committed above the captured layers: {memory:?}"
    );
    assert!(
        memory.layers_at_retirement > memory.pinned_layers,
        "they went into layers of their own: {memory:?}"
    );
    assert_eq!(
        (memory.shared_layers, memory.shared_entries),
        (memory.pinned_layers, memory.pinned_entries),
        "the open reader still names every captured layer"
    );
    #[cfg(target_os = "linux")]
    {
        let at_capture = memory.process_at_capture.expect("read at the capture");
        let at_hand_off = memory.process_at_hand_off.expect("read at the hand-off");
        let at_commit = memory
            .process_at_commit
            .expect("read when the commit returned");
        assert!(at_capture.arenas.is_some() && at_commit.arenas.is_some());
        assert_eq!(at_hand_off.arenas, None);
        assert!(
            at_commit.threads >= 2,
            "the committer was alive when its commit returned: {memory:?}"
        );
    }
    reader.rollback().expect("end the reader");

    // The next flush, with nothing open across its retirement.  Generation
    // 5 is over the trigger on its own, so generation 6's check trips.
    rig.fill(5);
    rig.small(6);
    rig.db.wait_background_commit().expect("the commit landed");
    let seen = rig.observations();
    assert_eq!(seen.len(), 2, "{seen:?}");
    let memory = seen[1].1.memory;
    assert_eq!(
        (memory.shared_layers, memory.shared_entries),
        (0, 0),
        "nothing but the flush held the captured layers: {memory:?}"
    );
    #[cfg(target_os = "linux")]
    assert!(
        memory.process_after_previous.is_some(),
        "the flush before left its reading: {memory:?}"
    );

    let (_dir, path) = rig.crash();
    assert_eq!(reopened(&path, 6), vec![1, 2, 3, 4, 5]);
}

// ---------------------------------------------------------------------
// What a handed-over commit leaves redb doing
// ---------------------------------------------------------------------

/// Storage that counts the writes made by every thread but the committer.
#[derive(Debug)]
struct ForegroundWrites {
    inner: SharedBackend,
    writes: AtomicU64,
}

impl StorageBackend for ForegroundWrites {
    fn len(&self) -> Result<u64, std::io::Error> {
        self.inner.len()
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), std::io::Error> {
        self.inner.read(offset, out)
    }

    fn set_len(&self, len: u64) -> Result<(), std::io::Error> {
        self.inner.set_len(len)
    }

    fn sync_data(&self) -> Result<(), std::io::Error> {
        self.inner.sync_data()
    }

    fn write(&self, offset: u64, data: &[u8]) -> Result<(), std::io::Error> {
        if std::thread::current().name() != Some(COMMIT_THREAD_NAME) {
            self.writes.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.write(offset, data)
    }
}

/// Row `i` of the paged store, its key scattered over the keyspace so
/// that a handful of rows land in as many leaves.
fn scattered_key(i: u32) -> Vec<u8> {
    let mut key = vec![b's'];
    key.extend_from_slice(&i.wrapping_mul(2_654_435_761).to_be_bytes());
    key
}

/// Over a store several times the size of redb's page cache, with that
/// cache full, count the storage writes each of six flushes makes on the
/// committing thread before its handed-over commit has written anything:
/// the writes of the insert loop, which hands rows to redb and should
/// write none of them.
///
/// Each counted flush follows one whose commit landed with no transaction
/// open, which is how a handed-over commit lands.  Its sixteen rows dirty
/// far fewer pages than half the page cache, the point at which redb
/// writes buffered pages out on its own account.
fn fill_writes_before_the_commit(snapshot: bool) -> Vec<u64> {
    const ROWS_A_COMMIT: u32 = 12;
    const STORED: u32 = 6_000;

    let dir = TempDir::new().expect("tempdir");
    let db_dir = dir.path().join("db");
    std::fs::create_dir_all(&db_dir).expect("mkdir");
    let power = PowerLossBackend::create(&db_dir.join("metadata.redb"), true);
    let counted = Arc::new(ForegroundWrites {
        inner: power as SharedBackend,
        writes: AtomicU64::new(0),
    });
    let gate = GateBackend::new(Arc::clone(&counted) as SharedBackend);
    let mut opts = Options::new(&db_dir, NET);
    opts.backend = Some(Arc::clone(&gate) as SharedBackend);
    opts.background_commit = true;
    opts.commit_snapshot = snapshot;
    // Two commits of twelve rows trip a flush; redb caches about a sixth
    // of what the store will hold.
    opts.cache_max_size = 24 * 1024;
    opts.db_cache_bytes = 1024 * 1024;
    let db = Database::create(&opts).expect("create");

    let mut next = 0u32;
    let mut put = |rows: u32| {
        db.update(|tx| {
            let meta = tx.metadata();
            for _ in 0..rows {
                meta.put(&scattered_key(next), &[7u8; 1000])?;
                next += 1;
            }
            Ok(())
        })
        .expect("put");
    };
    for _ in 0..STORED / ROWS_A_COMMIT {
        put(ROWS_A_COMMIT);
    }
    db.flush().expect("flush");
    // Fill redb's page cache.
    db.view(|tx| {
        let meta = tx.metadata();
        for i in 0..STORED {
            assert!(meta.get(&scattered_key(i)).is_some(), "row {i}");
        }
        Ok(())
    })
    .expect("read every row");

    let mut writes = Vec::new();
    for _ in 0..6 {
        // A flush whose commit lands with nothing open.
        put(16);
        put(1);
        db.wait_background_commit().expect("the commit landed");
        // The next one, held at its commit's first write.
        put(16);
        let before = counted.writes.load(Ordering::SeqCst);
        gate.arm();
        put(1);
        assert!(gate.wait_held(NEVER), "the commit is under way");
        writes.push(counted.writes.load(Ordering::SeqCst) - before);
        gate.open();
        db.wait_background_commit().expect("the commit landed");
    }
    db.close().expect("close");
    writes
}

/// The insert loop of a flush writes nothing to the store: its rows wait
/// in redb's write buffer for the commit.  That holds for a flush that
/// follows a handed-over commit only because that commit held a read
/// snapshot (`Options::commit_snapshot`).  Without one redb frees the
/// pages the commit replaced in a second commit of its own, keeps that
/// one's pages buffered, and from then on writes a buffered page out for
/// every read that misses its full page cache, the pages the next insert
/// loop has just dirtied among them.  The control shows this suite can
/// tell the two apart; if it stops failing, redb no longer takes that
/// path and the option has nothing left to do.
#[test]
fn the_insert_loop_writes_nothing_before_a_handed_over_commit() {
    let writes = fill_writes_before_the_commit(true);
    assert!(
        writes.iter().all(|&n| n == 0),
        "the committing thread wrote pages out before its flush's commit: {writes:?}"
    );
    let control = fill_writes_before_the_commit(false);
    assert!(
        control.iter().all(|&n| n > 0),
        "without the snapshot the insert loop was expected to write pages out: {control:?}"
    );
}

/// What one run of [`paged_run`] did and what its store held afterwards.
struct PagedRun {
    /// Storage operations the scripted commits made.
    ops: u64,
    /// The last commit that returned `Ok`.
    committed: u32,
    /// The last commit a flush was seen to have made durable.
    landed: u32,
    /// Storage writes made by threads other than the committer.
    early_writes: u64,
    /// Flushes whose commit ran on a thread of its own.
    background: usize,
    /// The commits the reopened store holds, in order.
    durable: Vec<u32>,
}

/// Commits a [`paged_run`] makes.
const PAGED_COMMITS: u32 = 12;

/// Rows of a kilobyte the store holds before a [`paged_run`].
const PAGED_BASE_ROWS: u32 = 2_000;

/// Scattered rows commit `commit` of a [`paged_run`] writes: an odd one
/// enough to arm the next commit's flush, an even one a single row.
fn paged_rows(commit: u32) -> u32 {
    if commit % 2 == 1 { 16 } else { 1 }
}

/// The key of the row that records how many rows `commit` wrote.
fn paged_marker(commit: u32) -> Vec<u8> {
    let mut key = vec![b'm'];
    key.extend_from_slice(&commit.to_be_bytes());
    key
}

/// A store of [`PAGED_BASE_ROWS`] scattered rows, closed clean: several
/// times the page cache [`paged_run`] opens a copy of it with.
fn paged_base(dir: &std::path::Path) {
    let mut opts = Options::new(dir, NET);
    opts.cache_max_size = 256 * 1024;
    let db = Database::create(&opts).expect("create");
    let mut next = 0u32;
    while next < PAGED_BASE_ROWS {
        db.update(|tx| {
            let meta = tx.metadata();
            for _ in 0..50 {
                meta.put(&scattered_key(1_000_000 + next), &[7u8; 1000])?;
                next += 1;
            }
            Ok(())
        })
        .expect("base rows");
    }
    db.close().expect("close the base");
}

/// Over a copy of the base store, behind a page cache an eighth of its
/// size and kept full by reads between the commits: twelve commits, each
/// of scattered rows and a marker that counts them, every second one
/// tripping a flush whose commit runs on a thread of its own and is
/// waited for before the next step, so that the storage operations come
/// in one order.  The power fails after `cut` of them when given.  Then
/// the store is let go of as a dying process lets go, the power is cut,
/// and the file reopened alone: every base row must be there, and every
/// commit whole or absent.
fn paged_run(base: &std::path::Path, snapshot: bool, cut: Option<u64>) -> PagedRun {
    let dir = TempDir::new().expect("tempdir");
    let db_dir = dir.path().join("db");
    std::fs::create_dir_all(&db_dir).expect("mkdir");
    for entry in std::fs::read_dir(base).expect("the base store") {
        let entry = entry.expect("an entry");
        std::fs::copy(entry.path(), db_dir.join(entry.file_name())).expect("copy");
    }
    let power = PowerLossBackend::create(&db_dir.join("metadata.redb"), true);
    let counted = Arc::new(ForegroundWrites {
        inner: Arc::clone(&power) as SharedBackend,
        writes: AtomicU64::new(0),
    });
    let mut opts = Options::new(&db_dir, NET);
    opts.backend = Some(Arc::clone(&counted) as SharedBackend);
    opts.background_commit = true;
    opts.commit_snapshot = snapshot;
    opts.cache_max_size = 24 * 1024;
    opts.db_cache_bytes = 256 * 1024;
    let (flushes, background) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    {
        let (flushes, background) = (Arc::clone(&flushes), Arc::clone(&background));
        opts.flush_observer = Some(Arc::new(move |obs: &FlushObservation| {
            flushes.fetch_add(1, Ordering::SeqCst);
            if obs.background {
                background.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    let db = Database::open(&opts).expect("open the copy");
    // Reads that miss the page cache, and so keep it full.  They fail
    // once the power has: redb refuses reads after a failed write.
    let read_some = |from: u32| {
        let _ = db.view(|tx| {
            let meta = tx.metadata();
            for i in 0..150u32 {
                let _ = meta.get(&scattered_key(
                    1_000_000 + (from * 131 + i * 5) % PAGED_BASE_ROWS,
                ));
            }
            Ok(())
        });
    };
    read_some(0);
    let (ops_before, writes_before) = (power.ops(), counted.writes.load(Ordering::SeqCst));
    if let Some(n) = cut {
        power.power_fails_after(n);
    }
    let (mut committed, mut landed) = (0u32, 0u32);
    for commit in 1..=PAGED_COMMITS {
        let flushed = flushes.load(Ordering::SeqCst);
        let result = db.update(|tx| {
            let meta = tx.metadata();
            for i in 0..paged_rows(commit) {
                meta.put(&scattered_key(commit * 100 + i), &[commit as u8; 1000])?;
            }
            meta.put(&paged_marker(commit), &paged_rows(commit).to_be_bytes())
        });
        if result.is_err() {
            break;
        }
        committed = commit;
        if db.wait_background_commit().is_err() {
            break;
        }
        // A flush is observed once its commit has landed, and the one
        // this commit tripped captured every commit before it.
        if flushes.load(Ordering::SeqCst) > flushed {
            landed = commit - 1;
        }
        read_some(commit);
    }
    let _ = db.wait_background_commit();
    let ops = power.ops() - ops_before;
    let early_writes = counted.writes.load(Ordering::SeqCst) - writes_before;
    let background = background.load(Ordering::SeqCst) as usize;
    drop(db);
    power.cut_power();

    let db = Database::open(&Options::new(&db_dir, NET)).expect("reopen after the cut");
    let mut durable = Vec::new();
    db.view(|tx| {
        let meta = tx.metadata();
        for i in 0..PAGED_BASE_ROWS {
            assert_eq!(
                meta.get(&scattered_key(1_000_000 + i)).as_deref(),
                Some([7u8; 1000].as_slice()),
                "cut {cut:?}: base row {i}"
            );
        }
        for commit in 1..=PAGED_COMMITS {
            let rows = paged_rows(commit);
            match meta.get(&paged_marker(commit)) {
                Some(count) => {
                    assert_eq!(count.as_slice(), rows.to_be_bytes().as_slice());
                    for i in 0..rows {
                        assert_eq!(
                            meta.get(&scattered_key(commit * 100 + i)).as_deref(),
                            Some([commit as u8; 1000].as_slice()),
                            "cut {cut:?}: commit {commit} lacks row {i}"
                        );
                    }
                    durable.push(commit);
                }
                None => {
                    for i in 0..rows {
                        assert!(
                            meta.get(&scattered_key(commit * 100 + i)).is_none(),
                            "cut {cut:?}: commit {commit} has row {i} and no marker"
                        );
                    }
                }
            }
        }
        Ok(())
    })
    .expect("view");
    db.close().expect("close");
    PagedRun {
        ops,
        committed,
        landed,
        early_writes,
        background,
        durable,
    }
}

/// Cut the power at storage operations spread over the whole of a
/// [`paged_run`], one in every `stride` from a start drawn afresh each
/// time, and hold what each cut leaves to a prefix of the run's commits
/// that is no shorter than what a flush had been seen to make durable.
/// `DCROXIDE_CRASH_SWEEP_EVERY` replaces the stride, as it does in the
/// chain's `utxo_flush_crash_sweep.rs`: 1 cuts at every operation, which
/// is a few minutes in a debug build.
fn paged_sweep(snapshot: bool, stride: u64, label: &str) {
    let stride = match std::env::var("DCROXIDE_CRASH_SWEEP_EVERY") {
        Ok(v) => v.parse().expect("DCROXIDE_CRASH_SWEEP_EVERY is a count"),
        Err(_) => stride,
    };
    assert!(stride > 0, "DCROXIDE_CRASH_SWEEP_EVERY is at least 1");
    let mut rng = SplitMix64::from_entropy(label);
    let base_dir = TempDir::new().expect("tempdir");
    let base = base_dir.path().join("base");
    paged_base(&base);

    let whole = paged_run(&base, snapshot, None);
    assert_eq!(whole.committed, PAGED_COMMITS);
    assert_eq!(
        whole.durable,
        (1..=whole.landed).collect::<Vec<u32>>(),
        "what the run's flushes made durable, and no commit after them"
    );
    assert!(
        whole.background >= 4 && whole.early_writes > 0,
        "{} flushes on a thread of their own and {} writes ahead of a commit over {} storage \
         operations: the run is not in the state the sweep is for",
        whole.background,
        whole.early_writes,
        whole.ops
    );
    let mut tips = std::collections::BTreeSet::new();
    let first = rng.below(stride);
    for cut in (first..whole.ops).step_by(stride as usize) {
        let run = paged_run(&base, snapshot, Some(cut));
        let durable = run.durable.len() as u32;
        assert_eq!(
            run.durable,
            (1..=durable).collect::<Vec<u32>>(),
            "cut {cut} of {}: the store is not at one of the run's commits",
            whole.ops
        );
        assert!(
            durable <= run.committed,
            "cut {cut}: commit {durable} is durable and {} were made",
            run.committed
        );
        assert!(
            durable >= run.landed,
            "cut {cut}: a flush made commit {} durable and {durable} survived",
            run.landed
        );
        tips.insert(durable);
    }
    assert!(
        tips.len() >= 3,
        "the cuts left the store at too few different commits to show anything: {tips:?}"
    );
}

/// A power cut loses no commit and tears none where redb has written
/// pages to the file ahead of the commit they belong to.
///
/// redb keeps a write transaction's pages in a buffer until its commit,
/// except when its page cache is full: then it writes buffered pages out
/// early, and the file holds pages of a commit that has not been made
/// and may never be.  Every other power-cut test here runs with a page
/// cache many times its store, where that never happens.  A syncing node
/// is in that state after every flush it asked for, and wherever a
/// flush's pages pass half the cache.  Whatever such a cut leaves, the
/// reopened store is at one of the run's commits with every row of the
/// store before the run.
#[test]
fn a_power_cut_with_pages_written_ahead_of_their_commit_leaves_a_prefix_of_the_commits() {
    paged_sweep(true, 11, "pages_written_ahead");
}

/// The same without the read snapshot a handed-over commit holds
/// (`Options::commit_snapshot`), where redb writes pages out early after
/// nearly every commit and many times as often.
#[test]
fn a_power_cut_with_pages_written_ahead_of_a_bare_commit_leaves_a_prefix_of_the_commits() {
    paged_sweep(false, 13, "pages_written_ahead_bare");
}
