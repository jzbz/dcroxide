// SPDX-License-Identifier: ISC
//! A pipelined client for `tools/oracle`: many requests in flight to one
//! oracle process, a bounded window of cases between the thread that
//! submits them and the thread that reads the answers, and every case
//! submitted coming back exactly once, answered or, after a fault, in the
//! failure.
//!
//! # The protocol it relies on
//!
//! The oracle answers one JSON line per request line, in order, echoing a
//! request's `"id"`.  It writes its answers out whenever its input holds no
//! further complete request, so answers to requests that arrived together
//! leave together, and a request that never returns holds back the answers
//! to those that arrived with it.  A request that panics ends the process
//! once the answers ahead of it are written; a Go `fatal error`, a kill or
//! the OOM killer end it with whatever it held unwritten.
//!
//! # Structure
//!
//! The submitting thread (the producer, P) sends each case's pending entry
//! into a `sync_channel` of `window` entries and then writes the case's
//! request lines into a 64 KiB `BufWriter` on the oracle's stdin, flushing
//! every `flush_every` requests.  A checker thread (C) receives pending
//! entries, reads one reply line per request from a 64 KiB `BufReader` on
//! the oracle's stdout, requires the ids to count up from the entry's
//! first, and hands the case and its replies to `on_case`.  Two rules make
//! it deadlock-free, whatever the pipes' capacities:
//!
//! 1. P flushes stdin before any send into the window that would block.
//! 2. P sends a case's pending entry before writing its requests.
//!
//! The waits are: P on a full window (C to receive) or a full stdin pipe
//! (the oracle, O, to read); O on an empty input (P to flush) or a full
//! stdout pipe (C to read); C on stdout (O to write) or an empty window (P
//! to submit).  P blocked on the window means C holds an outstanding entry;
//! by rule 1 its requests reached O, and O, by its flush rule, wrote their
//! answers before waiting on input, so C is not waiting on O.  O blocked
//! writing means C has bytes to read, and by rule 2 those answer an
//! outstanding entry, so C is reading.  C waiting on requests still in P's
//! buffer means P is not blocked on C: it is computing, writing (which O
//! relieves) or about to block on the window, which flushes first, and it
//! flushes every `flush_every` requests anyway.  A `BufWriter` flush
//! delivers whole lines (a case's lines are far smaller than its buffer),
//! and a partial write is finished with `write_all`.
//!
//! Every request reaches the oracle through a write P has counted for the
//! monitor, never through the writer emptying itself to make room: when a
//! case's lines do not fit beside what it holds, P flushes it first.  A
//! flush counts its requests as owed before it writes them, so an oracle
//! that stops reading while a flush is blocked on it is seen to owe
//! answers, and the monitor's hang timeout runs whatever the window and
//! flush batch.
//!
//! # Faults
//!
//! On end of file before every outstanding reply arrived, on the monitor's
//! kill of a hung oracle, or on a reply with no id, the wrong id or no
//! JSON, C marks the pipe failed, kills and reaps the child, reads the
//! tail of what this spawn appended to its stderr file, and keeps
//! receiving pending entries, collecting their payloads, until P drops its
//! sender; a receiver delivers every buffered entry before it reports the
//! senders gone, so none is lost.  P sees the failure at its next submit,
//! at a failed write or flush (the child, the only reader of stdin, is
//! dead, and Rust ignores SIGPIPE, so the write fails), or in `finish`; it
//! drops its sender and stdin, joins C and returns every payload that did
//! not reach `on_case`, in id order, its own unsent one last.  After a
//! fault C blocks only in `recv`, which P's send or P's drop ends.
//!
//! With `window` 0 the channel is a rendezvous: a send completes only when
//! C is in `recv`, which it enters only after the previous case's replies,
//! and P writes a case's requests only after its send, so with
//! `flush_every` 1 exactly one case is in the oracle at a time.  That is
//! the serial mode the run's isolation uses to find the case an oracle
//! failed on.

use std::ffi::OsString;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::cmd::{BUILD_INFO_LINE, Request};
use crate::reply::Reply;

/// Capacity of the stdin writer and the stdout reader.
const BUFFER: usize = 64 * 1024;

/// How much of an oracle's stderr a fault reports.
const STDERR_TAIL: u64 = 4 * 1024;

/// How long an oracle that closed its stdout has to exit by itself before it
/// is killed, so a Go panic's exit status is the one recorded.
const EXIT_GRACE: Duration = Duration::from_secs(2);

/// How to run an oracle.
#[derive(Debug, Clone)]
pub struct PipeConfig {
    /// The oracle binary.
    pub bin: PathBuf,
    /// Arguments to it (none for `tools/oracle`; the fake oracle of the
    /// pipe's tests takes its mode here).
    pub args: Vec<OsString>,
    /// Cases between the producer and the checker; 0 is serial mode.
    pub window: usize,
    /// Requests per producer flush, at least 1.
    pub flush_every: usize,
    /// The file the oracle's stderr is appended to; `None` inherits this
    /// process's.  Never a pipe nobody reads: a full one would block every
    /// write the oracle makes to it.
    pub stderr: Option<PathBuf>,
    /// `GOMAXPROCS` for the oracle, so many oracles at once do not each
    /// start a garbage collector thread per core.
    pub gomaxprocs: u32,
    /// How long a new oracle has to answer `build_info`.
    pub spawn_timeout: Duration,
}

impl PipeConfig {
    /// The defaults for `bin`: window 512, flush batch 64, stderr
    /// inherited, `GOMAXPROCS=2`, two minutes to answer `build_info`.
    pub fn new(bin: PathBuf) -> PipeConfig {
        PipeConfig {
            bin,
            args: Vec::new(),
            window: 512,
            flush_every: 64,
            stderr: None,
            gomaxprocs: 2,
            spawn_timeout: Duration::from_secs(120),
        }
    }
}

/// What travels through a pipe with each case: the case's requests are
/// read from it before it moves into the window, so the producer copies
/// nothing.
pub trait Payload: Send + 'static {
    /// The requests to send, one to 255 of them.
    fn requests(&self) -> &[Request];
}

/// What one oracle did wrong.
#[derive(Debug, Clone)]
pub enum OracleFault {
    /// The oracle's stdout ended: the process exited or was killed from
    /// outside.
    Exited {
        /// Its exit status, once reaped.
        status: Option<ExitStatus>,
        /// The last 4 KiB this spawn wrote to its stderr file.
        stderr_tail: String,
        /// Whether that tail shows a Go panic (a line starting `panic: `
        /// and none starting `fatal error: `), which flushes the answers
        /// ahead of the panicking request before the process ends.
        go_panic: bool,
    },
    /// The monitor killed it after the hang timeout without progress.
    Hung {
        /// The last 4 KiB this spawn wrote to its stderr file.
        stderr_tail: String,
    },
    /// A reply without an id, with the wrong id, or not JSON.
    Protocol {
        /// The offending line.
        line: String,
    },
}

impl OracleFault {
    /// Whether two faults are of one kind (an exit, a hang, a broken
    /// protocol), which is what a confirmation run is held to.
    pub fn same_kind(&self, other: &OracleFault) -> bool {
        core::mem::discriminant(self) == core::mem::discriminant(other)
    }

    /// Whether this is a Go panic, after which the case being answered is
    /// the first unanswered one.
    pub fn go_panic(&self) -> bool {
        matches!(self, OracleFault::Exited { go_panic: true, .. })
    }

    /// The stderr tail, where the fault has one.
    pub fn stderr_tail(&self) -> Option<&str> {
        match self {
            OracleFault::Exited { stderr_tail, .. } | OracleFault::Hung { stderr_tail } => {
                Some(stderr_tail)
            }
            OracleFault::Protocol { .. } => None,
        }
    }

    /// The exit status, for an exit.
    pub fn exit_status(&self) -> Option<ExitStatus> {
        match self {
            OracleFault::Exited { status, .. } => *status,
            _ => None,
        }
    }

    /// A one-word name: `exited`, `hung` or `protocol`.
    pub fn kind_name(&self) -> &'static str {
        match self {
            OracleFault::Exited { .. } => "exited",
            OracleFault::Hung { .. } => "hung",
            OracleFault::Protocol { .. } => "protocol",
        }
    }
}

impl fmt::Display for OracleFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OracleFault::Exited {
                status, go_panic, ..
            } => {
                f.write_str("the oracle exited")?;
                if let Some(status) = status {
                    write!(f, " ({status})")?;
                }
                if *go_panic {
                    f.write_str(" on a Go panic")?;
                }
                Ok(())
            }
            OracleFault::Hung { .. } => {
                f.write_str("the oracle stopped answering and was killed after the hang timeout")
            }
            OracleFault::Protocol { line } => write!(f, "the oracle broke the protocol: {line}"),
        }
    }
}

/// Why a pipe stopped.
#[derive(Debug)]
pub enum PipeFailure<T> {
    /// The oracle failed.  `unanswered` holds every payload submitted to
    /// this pipe that did not reach `on_case`, in id order.
    Oracle {
        /// What it did.
        fault: OracleFault,
        /// The payloads never answered.
        unanswered: Vec<T>,
    },
    /// The oracle could not be started, or did not answer `build_info`.
    Spawn(io::Error),
}

/// What the monitor reads and does: the producer's and checker's progress,
/// the failed flag, and the child to kill.
#[derive(Debug)]
pub struct PipeHealth {
    epoch: Instant,
    failed: AtomicBool,
    killed_by_monitor: AtomicBool,
    /// Requests handed to the oracle, counted as a flush starts, and when
    /// (ms since `epoch`).
    flushed: AtomicU64,
    flushed_at: AtomicU64,
    /// Requests answered, and when.
    answered: AtomicU64,
    answered_at: AtomicU64,
    child: Arc<Mutex<Child>>,
}

impl PipeHealth {
    fn new(child: Arc<Mutex<Child>>) -> PipeHealth {
        PipeHealth {
            epoch: Instant::now(),
            failed: AtomicBool::new(false),
            killed_by_monitor: AtomicBool::new(false),
            flushed: AtomicU64::new(0),
            flushed_at: AtomicU64::new(0),
            answered: AtomicU64::new(0),
            answered_at: AtomicU64::new(0),
            child,
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Whether the pipe has failed.
    pub fn failed(&self) -> bool {
        self.failed.load(Ordering::SeqCst)
    }

    /// Requests handed to the oracle so far, a flush still writing them
    /// included.
    pub fn flushed(&self) -> u64 {
        self.flushed.load(Ordering::SeqCst)
    }

    /// Requests answered so far.
    pub fn answered(&self) -> u64 {
        self.answered.load(Ordering::SeqCst)
    }

    /// How long the oracle has owed answers without a reply or a flush
    /// happening; `None` when it owes none.
    pub fn stalled_for(&self) -> Option<Duration> {
        if self.failed() || self.flushed() <= self.answered() {
            return None;
        }
        let last = self
            .flushed_at
            .load(Ordering::SeqCst)
            .max(self.answered_at.load(Ordering::SeqCst));
        Some(Duration::from_millis(self.now_ms().saturating_sub(last)))
    }

    /// Kills a hung oracle: the checker then reports [`OracleFault::Hung`].
    pub fn kill_hung(&self) {
        self.killed_by_monitor.store(true, Ordering::SeqCst);
        let _ = lock(&self.child).kill();
    }

    fn mark_flushed(&self, requests: u64) {
        self.flushed_at.store(self.now_ms(), Ordering::SeqCst);
        self.flushed.store(requests, Ordering::SeqCst);
    }

    fn mark_answered(&self, requests: u64) {
        self.answered_at.store(self.now_ms(), Ordering::SeqCst);
        self.answered.store(requests, Ordering::SeqCst);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A case in flight: its first request id, how many requests it has, and
/// its payload.
struct Pending<T> {
    first_id: u64,
    n: u8,
    payload: T,
}

/// How a checker ended.
struct CheckerEnd<T> {
    fault: Option<OracleFault>,
    unanswered: Vec<T>,
}

/// One oracle process with requests in flight to it.
pub struct OraclePipe<T: Payload> {
    child: Arc<Mutex<Child>>,
    stdin: Option<BufWriter<ChildStdin>>,
    tx: Option<SyncSender<Pending<T>>>,
    checker: Option<JoinHandle<CheckerEnd<T>>>,
    build_info: Reply,
    next_id: u64,
    unflushed: usize,
    flush_every: usize,
    line: String,
    health: Arc<PipeHealth>,
}

impl<T: Payload> OraclePipe<T> {
    /// Starts an oracle, asks it `build_info` (a new oracle that does not
    /// answer within `cfg.spawn_timeout` is a [`PipeFailure::Spawn`]), and
    /// starts the checker, which calls `on_case` with each answered payload
    /// and its replies, in id order.  `on_case` runs on the checker thread
    /// and must never wait on the producer or the oracle.
    pub fn spawn(
        cfg: &PipeConfig,
        on_case: impl FnMut(T, Vec<Reply>) + Send + 'static,
    ) -> Result<Self, PipeFailure<T>> {
        assert!(cfg.flush_every > 0, "flush_every is at least 1");
        let (stderr, stderr_file) = match &cfg.stderr {
            Some(path) => {
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(PipeFailure::Spawn)?;
                let start = file.metadata().map_err(PipeFailure::Spawn)?.len();
                (Stdio::from(file), Some((path.clone(), start)))
            }
            None => (Stdio::inherit(), None),
        };
        let mut child = Command::new(&cfg.bin)
            .args(&cfg.args)
            .env("GOMAXPROCS", cfg.gomaxprocs.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr)
            .spawn()
            .map_err(PipeFailure::Spawn)?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let child = Arc::new(Mutex::new(child));
        let health = Arc::new(PipeHealth::new(Arc::clone(&child)));

        let mut stdin = BufWriter::with_capacity(BUFFER, stdin);
        let kill_and_reap = |why: io::Error| {
            let _ = reap(&child, Duration::ZERO);
            PipeFailure::Spawn(why)
        };
        if let Err(e) = stdin
            .write_all(BUILD_INFO_LINE.as_bytes())
            .and_then(|()| stdin.flush())
        {
            return Err(kill_and_reap(e));
        }

        let (tx, rx) = mpsc::sync_channel(cfg.window);
        let (info_tx, info_rx) = mpsc::channel();
        let checker = Checker {
            reader: BufReader::with_capacity(BUFFER, stdout),
            rx,
            health: Arc::clone(&health),
            stderr_file,
            line: String::new(),
            on_case,
        };
        let checker = match thread::Builder::new()
            .name("oracle-checker".to_owned())
            .spawn(move || checker.run(&info_tx))
        {
            Ok(handle) => handle,
            Err(e) => return Err(kill_and_reap(e)),
        };
        let build_info = match info_rx.recv_timeout(cfg.spawn_timeout) {
            Ok(Ok(reply)) => reply,
            Ok(Err(why)) => {
                drop(tx);
                let _ = checker.join();
                return Err(kill_and_reap(io::Error::other(why)));
            }
            Err(_) => {
                // Killing the child ends the checker's read.  A reply it
                // reads all the same, written before the kill, finds the
                // receiver gone, or else the sender, so the checker returns
                // rather than waiting for cases that never come.
                let _ = lock(&child).kill();
                drop(info_rx);
                drop(tx);
                let _ = checker.join();
                return Err(kill_and_reap(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "the oracle did not answer build_info within {:?}",
                        cfg.spawn_timeout
                    ),
                )));
            }
        };
        Ok(OraclePipe {
            child,
            stdin: Some(stdin),
            tx: Some(tx),
            checker: Some(checker),
            build_info,
            next_id: 0,
            unflushed: 0,
            flush_every: cfg.flush_every,
            line: String::new(),
            health,
        })
    }

    /// The oracle's `build_info` reply.
    pub fn build_info(&self) -> &Reply {
        &self.build_info
    }

    /// The pipe's health, for the monitor.
    pub fn health(&self) -> Arc<PipeHealth> {
        Arc::clone(&self.health)
    }

    /// Sends a case: its pending entry first (flushing before a send that
    /// would block), then its request lines (flushing first when they do
    /// not fit in the writer), then a flush when `flush_every` requests are
    /// waiting.  On a fault the pipe is spent:
    /// the failure carries every payload that did not reach `on_case`,
    /// `payload` among them if it was never sent.
    pub fn submit(&mut self, payload: T) -> Result<(), PipeFailure<T>> {
        if self.health.failed() {
            return Err(self.fail(Some(payload), None));
        }
        let requests = payload.requests();
        let n = u8::try_from(requests.len())
            .ok()
            .filter(|&n| n > 0)
            .expect("a case has one to 255 requests");
        // The lines are built now, while the payload is at hand, and
        // written after its pending entry is sent (rule 2).
        self.line.clear();
        for (id, request) in (self.next_id..).zip(requests) {
            request.push_line(id, &mut self.line);
        }
        let pending = Pending {
            first_id: self.next_id,
            n,
            payload,
        };
        let tx = self.tx.as_ref().expect("a live pipe has its sender");
        match tx.try_send(pending) {
            Ok(()) => {}
            Err(TrySendError::Full(pending)) => {
                // Rule 1: everything outstanding reaches the oracle before
                // the producer waits on the checker.
                if let Err(e) = self.flush() {
                    return Err(self.fail(Some(pending.payload), Some(e)));
                }
                let tx = self.tx.as_ref().expect("a live pipe has its sender");
                if let Err(mpsc::SendError(pending)) = tx.send(pending) {
                    return Err(self.fail(Some(pending.payload), None));
                }
            }
            Err(TrySendError::Disconnected(pending)) => {
                return Err(self.fail(Some(pending.payload), None));
            }
        }
        // The lines reach the oracle only through a write the monitor has
        // counted.  Lines that do not fit beside what the writer holds would
        // make it write that out by itself, so it is flushed first; lines
        // longer than the whole writer go straight through, counted as they
        // start.
        let stdin = self.stdin.as_ref().expect("a live pipe has its stdin");
        let capacity = stdin.capacity();
        if stdin.buffer().len().saturating_add(self.line.len()) > capacity
            && let Err(e) = self.flush()
        {
            return Err(self.fail(None, Some(e)));
        }
        let end = self
            .next_id
            .checked_add(u64::from(n))
            .expect("request ids below 2^64");
        let direct = self.line.len() >= capacity;
        if direct {
            self.health.mark_flushed(end);
        }
        let stdin = self.stdin.as_mut().expect("a live pipe has its stdin");
        if let Err(e) = stdin.write_all(self.line.as_bytes()) {
            return Err(self.fail(None, Some(e)));
        }
        self.next_id = end;
        if !direct {
            self.unflushed = self.unflushed.saturating_add(usize::from(n));
        }
        if self.unflushed >= self.flush_every
            && let Err(e) = self.flush()
        {
            return Err(self.fail(None, Some(e)));
        }
        Ok(())
    }

    /// Flushes what the producer has written, counting it for the monitor
    /// first: a flush blocks while the oracle reads nothing, and an oracle
    /// that never reads again then owes these requests from now on, while a
    /// live one resets the clock with every reply.
    fn flush(&mut self) -> io::Result<()> {
        if self.unflushed == 0 {
            return Ok(());
        }
        self.health.mark_flushed(self.next_id);
        self.stdin
            .as_mut()
            .expect("a live pipe has its stdin")
            .flush()?;
        self.unflushed = 0;
        Ok(())
    }

    /// Flushes, closes the oracle's stdin (it then answers everything and
    /// exits), waits for the checker to pass on every answer, and reaps the
    /// oracle.
    pub fn finish(mut self) -> Result<(), PipeFailure<T>> {
        if self.health.failed() {
            return Err(self.fail(None, None));
        }
        if let Err(e) = self.flush() {
            return Err(self.fail(None, Some(e)));
        }
        drop(self.stdin.take());
        drop(self.tx.take());
        let end = self.join_checker();
        if let Some(fault) = end.fault {
            return Err(PipeFailure::Oracle {
                fault,
                unanswered: end.unanswered,
            });
        }
        let _ = reap(&self.child, EXIT_GRACE);
        Ok(())
    }

    /// The fault path on the producer's side: drop the sender and stdin,
    /// join the checker, and gather every payload not answered.
    fn fail(&mut self, unsent: Option<T>, write_error: Option<io::Error>) -> PipeFailure<T> {
        drop(self.stdin.take());
        drop(self.tx.take());
        let end = self.join_checker();
        let mut unanswered = end.unanswered;
        unanswered.extend(unsent);
        let fault = end.fault.unwrap_or_else(|| {
            // The checker saw every answer it was owed although a write
            // failed: the oracle closed its input and lived.  Report it as
            // an exit, with the write's error for a tail.
            let status = reap(&self.child, Duration::ZERO);
            OracleFault::Exited {
                status,
                stderr_tail: write_error
                    .map(|e| format!("writing to the oracle failed: {e}"))
                    .unwrap_or_default(),
                go_panic: false,
            }
        });
        PipeFailure::Oracle { fault, unanswered }
    }

    /// Joins the checker; a panic in `on_case` resumes here, its child
    /// already killed.
    fn join_checker(&mut self) -> CheckerEnd<T> {
        let handle = self.checker.take().expect("the checker is joined once");
        match handle.join() {
            Ok(end) => end,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
}

impl<T: Payload> Drop for OraclePipe<T> {
    /// A pipe dropped without `finish` (its owner returned early or is
    /// unwinding) kills its oracle and joins its checker.
    fn drop(&mut self) {
        if let Some(handle) = self.checker.take() {
            let _ = lock(&self.child).kill();
            drop(self.stdin.take());
            drop(self.tx.take());
            let _ = handle.join();
            let _ = reap(&self.child, Duration::ZERO);
        }
    }
}

/// Waits up to `grace` for the child to exit by itself, then kills it, and
/// returns its exit status once reaped.
fn reap(child: &Mutex<Child>, grace: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now().checked_add(grace);
    loop {
        let mut child = lock(child);
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {}
            Err(_) => return None,
        }
        if deadline.is_none_or(|d| Instant::now() >= d) {
            let _ = child.kill();
            return child.wait().ok();
        }
        drop(child);
        thread::sleep(Duration::from_millis(10));
    }
}

/// Kills the child if the checker unwinds (a panic in `on_case`), so a
/// producer writing to it gets an error instead of waiting for ever on an
/// oracle nobody reads.
struct KillOnPanic(Arc<Mutex<Child>>);

impl Drop for KillOnPanic {
    fn drop(&mut self) {
        if thread::panicking() {
            let _ = lock(&self.0).kill();
        }
    }
}

/// Why the checker stopped reading.
enum Cause {
    Eof,
    Protocol(String),
}

struct Checker<T, F> {
    reader: BufReader<ChildStdout>,
    rx: Receiver<Pending<T>>,
    health: Arc<PipeHealth>,
    /// The stderr file and its length when this oracle started.
    stderr_file: Option<(PathBuf, u64)>,
    line: String,
    on_case: F,
}

impl<T: Payload, F: FnMut(T, Vec<Reply>)> Checker<T, F> {
    fn run(mut self, info: &mpsc::Sender<Result<Reply, String>>) -> CheckerEnd<T> {
        let _kill = KillOnPanic(Arc::clone(&self.health.child));
        match self.read_build_info() {
            Ok(reply) => {
                if info.send(Ok(reply)).is_err() {
                    return CheckerEnd {
                        fault: None,
                        unanswered: Vec::new(),
                    };
                }
            }
            Err(why) => {
                let _ = info.send(Err(why));
                return CheckerEnd {
                    fault: None,
                    unanswered: Vec::new(),
                };
            }
        }
        loop {
            let Ok(pending) = self.rx.recv() else {
                return CheckerEnd {
                    fault: None,
                    unanswered: Vec::new(),
                };
            };
            let mut replies = Vec::with_capacity(usize::from(pending.n));
            for id in (pending.first_id..).take(usize::from(pending.n)) {
                match self.read_reply(id) {
                    Ok(reply) => replies.push(reply),
                    Err(cause) => return self.fail(cause, pending.payload),
                }
            }
            self.health
                .mark_answered(pending.first_id.saturating_add(u64::from(pending.n)));
            (self.on_case)(pending.payload, replies);
        }
    }

    fn read_build_info(&mut self) -> Result<Reply, String> {
        self.line.clear();
        match self.reader.read_line(&mut self.line) {
            Ok(_) if self.line.ends_with('\n') => {}
            Ok(_) => {
                return Err(format!(
                    "the oracle closed its output before answering build_info; stderr: {}",
                    self.stderr_tail()
                ));
            }
            Err(e) => return Err(format!("reading build_info: {e}")),
        }
        let reply = Reply::from_line(&self.line)?;
        if reply.id.is_some() || reply.error.is_some() || reply.go_version.is_none() {
            return Err(format!("build_info answered {}", reply.raw));
        }
        Ok(reply)
    }

    fn read_reply(&mut self, id: u64) -> Result<Reply, Cause> {
        self.line.clear();
        match self.reader.read_line(&mut self.line) {
            Ok(_) if self.line.ends_with('\n') => {}
            Ok(_) => return Err(Cause::Eof),
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                return Err(Cause::Protocol("a line that is not UTF-8".to_owned()));
            }
            Err(_) => return Err(Cause::Eof),
        }
        let line = self.line.trim_end();
        match Reply::from_line(line) {
            Ok(reply) if reply.id == Some(id) => Ok(reply),
            _ => Err(Cause::Protocol(line.to_owned())),
        }
    }

    /// The fault path: mark the pipe failed, end the oracle, read its
    /// stderr tail, and collect every payload still to come until the
    /// producer drops its sender.
    fn fail(self, cause: Cause, current: T) -> CheckerEnd<T> {
        self.health.failed.store(true, Ordering::SeqCst);
        let grace = match cause {
            Cause::Eof => EXIT_GRACE,
            Cause::Protocol(_) => Duration::ZERO,
        };
        let status = reap(&self.health.child, grace);
        let stderr_tail = self.stderr_tail();
        let fault = if self.health.killed_by_monitor.load(Ordering::SeqCst) {
            OracleFault::Hung { stderr_tail }
        } else {
            match cause {
                Cause::Eof => {
                    let go_panic = stderr_tail.lines().any(|l| l.starts_with("panic: "))
                        && !stderr_tail.lines().any(|l| l.starts_with("fatal error: "));
                    OracleFault::Exited {
                        status,
                        stderr_tail,
                        go_panic,
                    }
                }
                Cause::Protocol(line) => OracleFault::Protocol { line },
            }
        };
        let mut unanswered = vec![current];
        while let Ok(pending) = self.rx.recv() {
            unanswered.push(pending.payload);
        }
        CheckerEnd {
            fault: Some(fault),
            unanswered,
        }
    }

    /// The last 4 KiB this spawn appended to its stderr file.
    fn stderr_tail(&self) -> String {
        let Some((path, start)) = &self.stderr_file else {
            return String::new();
        };
        let read = || -> io::Result<String> {
            let mut file = std::fs::File::open(path)?;
            let end = file.metadata()?.len();
            let from = end.saturating_sub(STDERR_TAIL).max(*start);
            file.seek(SeekFrom::Start(from))?;
            let mut bytes = Vec::new();
            file.take(end.saturating_sub(from))
                .read_to_end(&mut bytes)?;
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        };
        read().unwrap_or_else(|e| format!("(stderr unreadable: {e})"))
    }
}
