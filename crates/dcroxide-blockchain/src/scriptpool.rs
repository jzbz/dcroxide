// SPDX-License-Identifier: ISC
//! The helper threads that check the scripts of a block being connected.
//!
//! dcrd's `txValidator.Validate` starts its goroutines anew for every
//! batch of inputs (scriptval.go:120-132), and the scoped workers of
//! `validate::validate_items` are created and joined per call in the same
//! way.  An OS thread costs far more to create than a goroutine, and a
//! block that is connected with its scripts checked brings two batches,
//! one per transaction tree.  For those batches the threads are kept: a
//! [`Pool`] of helpers that live as long as the process, sit parked while
//! there is nothing to check, and are lent to one [`Batch`] at a time.
//! The single-transaction path and the public block checks keep their
//! scoped workers.
//!
//! # The shape
//!
//! - The submitting thread always works on its own batch.  A batch is
//!   complete with no helper at all, and the submitter never waits for a
//!   helper that has not joined it.
//! - A batch is a shared index, a slot for the failure of lowest index
//!   and a count of the items that passed ([`Run`]): the work loop of
//!   the scoped path with that count added and that slot's rule changed.
//! - A helper joins a batch by taking one of its tickets while holding
//!   the pool's mutex, and leaves through an atomic count that unparks
//!   the submitter when it reaches zero, the way `std::thread::scope`
//!   joins its threads.  The submitter closes its batch under the same
//!   mutex, after which no helper can join, and returns once that count
//!   is zero.
//! - Parked helpers sit on a stack and are woken with `Thread::unpark`,
//!   the one parked most recently first, so a small batch wakes the same
//!   few helpers every block.
//! - A batch owns what its checks read.  This crate forbids unsafe code,
//!   so a thread that outlives the call cannot be lent the submitter's
//!   borrows.
//!
//! # What a verdict rests on
//!
//! Not on the protocol above.  [`Run::result`] answers `Ok` only when
//! the failure slot is empty and the count of passed items equals the
//! number of items, both checked in every build, and an error is always
//! one that a check of this batch returned.  A fault in the pool can
//! therefore stall the node or stop it, and cannot accept a block.
//!
//! # Which failure a batch names
//!
//! dcrd returns the first error off its result channel
//! (scriptval.go:141-163), so which of several failing inputs it names
//! depends on scheduling, and so it does on the scoped path for a batch
//! that path fans out.  A batch run here names its failing item of
//! lowest index, whatever the scheduling, the number of helpers and the
//! size of the batch.  Four things in [`Run`] and [`Pool::run`] make it
//! so:
//!
//! 1. Indices are claimed in increasing order.  One atomic counter hands
//!    them out, so at every moment the claimed indices are exactly those
//!    below some bound: an index is claimed only after every lower one.
//! 2. A claimed index is always checked.  The failure flag is read
//!    before a claim and never between a claim and its check, so nothing
//!    that fails meanwhile turns a worker away from an item it holds.
//! 3. Every error a check returns is offered to the slot, and the slot
//!    keeps the one of lowest index, in whatever order they are offered.
//! 4. The verdict is read only when no worker is inside the batch: the
//!    submitter's own loop has returned, the batch is closed to further
//!    helpers, and every helper that joined has left.  Every claimed
//!    index has then been checked to its end.
//!
//! Call an item failing when its check returns an error, on whichever
//! thread and at whatever time it runs; a script check answers the same
//! everywhere.  Suppose a check returned an error, at index `g`.  By 1
//! every index below `g` was claimed as well, and by 2 and 4 the check
//! of each has run to its end when the verdict is read.  The lowest
//! failing index of the whole batch, `f`, is `g` or lies below it, so
//! its check is among those: it ran, it returned its error, and by 3
//! that error is the one in the slot, there being no failing index
//! below `f`.  So the verdict is the error of `f`, on every run.  In
//! particular a failure at a high index does not hide one at a lower
//! index that was still being checked when it was recorded: the
//! submitter does not return before that check has ended.  If no check
//! returned an error, nothing but the end of the batch stopped the
//! claims (a panic leaves no verdict), so every item was checked and
//! passed, which the count confirms.
//!
//! The rule costs nothing the pool did not already do: the submitter
//! waited for the helpers inside its batch in any case, and an item
//! once claimed was always checked to its end.
//!
//! # The mutex
//!
//! One mutex guards the queue of open batches and the stack of parked
//! helpers.  It is never held across a check, a thread creation, an
//! unpark or a park, nothing a batch implements is called under it, and
//! no other lock is taken while it is held.  Its critical sections only
//! move counters, stack and queue entries, so they cannot panic and the
//! mutex cannot be poisoned.
//!
//! # Panics
//!
//! The release profile aborts on a panic, on a helper as on any other
//! thread.  In an unwinding build a helper catches a panic of a check,
//! stops the batch and hands the payload to the submitter, and keeps
//! serving.  The panic hook has by then run on the helper, and under
//! the test harness a helper's output belongs to whichever test first
//! created it.  So when the payload is the panic's message, a `&str` or
//! a `String`, the submitter panics anew with that message in its own:
//! the hook runs again, on the thread that asked for the checks, and
//! the message is printed where that thread's output goes.  Any other
//! payload is resumed as it is, without the hook.  A panic is never
//! turned into a verdict.

use std::any::Any;
use std::collections::VecDeque;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle, Thread};

use crate::ruleerror::RuleError;

/// The fewest script items of one tree of a block that go to the pool.
/// A smaller batch is checked in index order on the calling thread,
/// which for a handful of items is done before a woken helper could
/// take one.  Of the thresholds measured (4, 8 and 16) this was the
/// fastest, on one machine; on another a different value may be, at a
/// cost or a saving in time only.
///
/// The size decides where a batch runs and not which of several failing
/// items it names: the lowest index on either side of it.
pub(crate) const MIN_POOLED_ITEMS: usize = 4;

/// How many more batches are submitted after the OS refuses a helper
/// thread before the process-wide pool asks for one again.  Counted in
/// batches rather than time so that this crate reads no clock for it.
const SPAWN_RETRY_BATCHES: u64 = 1024;

/// The open batches the queue has room for from the start.  One per
/// thread that connects blocks at the same time, which outside the test
/// suites is one.
const QUEUE_ROOM: usize = 8;

/// A batch of checks the pool can run.  It owns everything its checks
/// read, because a helper outlives any borrow the submitter holds.
pub(crate) trait Batch: Send + Sync + 'static {
    /// The number of checks.  Read once, when the batch is submitted.
    fn len(&self) -> usize;

    /// Run the check at `index`, which is below [`Batch::len`].  Each
    /// index is checked at most once, on whichever thread claims it.
    fn check(&self, index: usize) -> Result<(), RuleError>;

    /// Called in this crate's unit-test builds only, by a worker in the
    /// step that claims `index`, before it reads anything else: where a
    /// test holds a worker between a claim and its check.  `index` is
    /// at or past [`Batch::len`] for the worker that finds every item
    /// claimed, which has taken a number all the same.
    #[cfg(test)]
    fn claimed(&self, _index: usize) {}
}

/// One batch being run: the shared state of the work loop of
/// `validate::validate_items`, and a count of the items that passed.
struct Run<B> {
    batch: B,
    /// The number of items, taken from the batch once so that the pool
    /// calls nothing of the batch's but its checks afterwards.
    len: usize,
    /// The next index to claim.
    next: AtomicUsize,
    /// How many checks returned `Ok`.
    passed: AtomicUsize,
    /// Set by the first failure, and by a panic; read before every claim.
    failed: AtomicBool,
    /// The failure of lowest index among those recorded so far, with
    /// that index.  Only a failure of a lower index replaces it.
    failure: Mutex<Option<(usize, RuleError)>>,
}

impl<B: Batch> Run<B> {
    fn new(batch: B) -> Run<B> {
        let len = batch.len();
        Run {
            batch,
            len,
            next: AtomicUsize::new(0),
            passed: AtomicUsize::new(0),
            failed: AtomicBool::new(false),
            failure: Mutex::new(None),
        }
    }

    /// Claim and check items until none is left or one has failed.
    /// The index hands each item to exactly one worker, and the worker
    /// adds what it passed to the shared count once, when it stops.
    ///
    /// This loop holds the first three of the four things the batch's
    /// choice of failure rests on (see the module documentation).  The
    /// counter hands the indices out in increasing order.  The failure
    /// flag is read before a claim and never between a claim and its
    /// check, so an index once claimed is checked whatever has failed
    /// meanwhile.  And a failure goes into the slot unless the slot
    /// holds one of a lower index, so the order in which failures arrive
    /// does not decide which one stays.
    fn work(&self) {
        let mut ok = 0usize;
        loop {
            if self.failed.load(Ordering::Relaxed) {
                break;
            }
            // From the claim to the check nothing is read that could
            // turn this worker away from an item of the batch, the
            // failure flag least of all: a failure recorded meanwhile
            // may be of a higher index than this one.
            let index = self.claim();
            if index >= self.len {
                break;
            }
            match self.batch.check(index) {
                #[allow(
                    clippy::arithmetic_side_effects,
                    reason = "one per claimed index, and every claimed index is below len"
                )]
                Ok(()) => ok += 1,
                Err(error) => {
                    self.failed.store(true, Ordering::Relaxed);
                    let mut slot = self.failure.lock().expect("failure slot poisoned");
                    if slot.as_ref().is_none_or(|(lowest, _)| index < *lowest) {
                        *slot = Some((index, error));
                    }
                    break;
                }
            }
        }
        self.passed.fetch_add(ok, Ordering::SeqCst);
    }

    /// Claim the next index.  It is the caller's from the counter's
    /// step on, and an item of the batch when it is below `len`.
    ///
    /// The unit-test builds tell the batch of the claim here, in the
    /// same step (`Batch::claimed`), so that a test can hold a worker
    /// that has claimed an index and read nothing since.
    fn claim(&self) -> usize {
        let index = self.next.fetch_add(1, Ordering::Relaxed);
        #[cfg(test)]
        self.batch.claimed(index);
        index
    }

    /// Whether a worker that joined now would find nothing to do.  The
    /// answer can be out of date by the time it is used, which costs a
    /// helper one empty visit at most.
    fn exhausted(&self) -> bool {
        self.failed.load(Ordering::Relaxed) || self.next.load(Ordering::Relaxed) >= self.len
    }

    /// Have every worker stop at its next claim.  For the panic paths
    /// only: a batch stopped this way has no verdict.
    fn stop(&self) {
        self.failed.store(true, Ordering::Relaxed);
    }

    /// The verdict, once no worker is inside the batch: the failure of
    /// the lowest failing index, or `Ok` when every item passed.
    ///
    /// It is the lowest of the whole batch, and not only of the
    /// failures recorded, because it is read this late: every claimed
    /// index has been checked to its end, and the claimed indices are
    /// all those below some bound.  Read while a worker was still
    /// inside an item, the slot could hold a failure above one that
    /// item was about to report.
    ///
    /// The two assertions hold in every build and do not depend on how
    /// the workers were brought to the batch: without a recorded failure
    /// the batch must not have been stopped, and the checks that
    /// returned `Ok` must number exactly the items.
    fn result(&self) -> Result<(), RuleError> {
        let failure = self.failure.lock().expect("failure slot poisoned").take();
        match failure {
            Some((_, error)) => Err(error),
            None => {
                assert!(
                    !self.failed.load(Ordering::Relaxed),
                    "a script batch stopped without a failure"
                );
                assert_eq!(
                    self.passed.load(Ordering::SeqCst),
                    self.len,
                    "a script batch returned before every item passed"
                );
                Ok(())
            }
        }
    }
}

/// A batch as the pool's queue and its helpers see it.
trait Job: Send + Sync {
    /// [`Run::work`].
    fn work(&self);
    /// [`Run::exhausted`].
    fn exhausted(&self) -> bool;
    /// [`Run::stop`].
    fn stop(&self);
}

impl<B: Batch> Job for Run<B> {
    fn work(&self) {
        Run::work(self);
    }

    fn exhausted(&self) -> bool {
        Run::exhausted(self)
    }

    fn stop(&self) {
        Run::stop(self);
    }
}

/// The body of a helper thread.
type HelperMain = Box<dyn FnOnce() + Send>;

/// Creates the thread of the helper with the given number.  The
/// process-wide pool asks the OS; tests stand in for an OS that refuses.
///
/// A spawner reports a refusal as an error and must not panic.  A
/// panic would unwind past the bookkeeping of [`Pool::create_helpers`].
/// The batch is still closed and waited for, so no verdict depends on
/// it; but the helpers reserved and not created stay counted as
/// existing, which leaves the pool that much narrower for good with no
/// later attempt to create them, and the handles of the helpers already
/// created are dropped, so dropping the pool no longer joins them.
type Spawner = Box<dyn Fn(usize, HelperMain) -> io::Result<JoinHandle<()>> + Send + Sync>;

/// A pool of parked helper threads that script batches borrow.
pub(crate) struct Pool {
    inner: Arc<Inner>,
}

/// What the pool's handle and its helpers share.
struct Inner {
    /// The most helpers the pool holds.
    width: usize,
    /// How many more batches pass after a refused thread creation
    /// before another is tried.
    spawn_retry: u64,
    /// The number of the next batch that wants a helper.
    seq: AtomicU64,
    state: Mutex<State>,
    spawner: Spawner,
    /// How often a submitter found helpers still inside its closed
    /// batch and parked.
    #[cfg(test)]
    waits: AtomicU64,
    /// Called by a helper with its number when it returns from a park,
    /// before it takes the mutex.
    #[cfg(test)]
    woke: OnceLock<Box<dyn Fn(usize) + Send + Sync>>,
}

/// What the pool's mutex guards.
struct State {
    /// The batches whose submitters have not closed them, oldest first.
    queue: VecDeque<Entry>,
    /// The helpers that found nothing to do, each at most once; the one
    /// that got here most recently is last.
    idle: Vec<(usize, Thread)>,
    /// The helpers alive or being created.
    helpers: usize,
    /// The number the next helper is given.
    next_helper: usize,
    /// The first batch that may ask for a thread again after a refusal.
    spawn_after: u64,
    /// Set when the pool is dropped; a helper that sees it exits.
    closed: bool,
    /// The helpers' threads, for the join when a pool is dropped.
    handles: Vec<JoinHandle<()>>,
    #[cfg(test)]
    stats: Stats,
}

/// A batch open to helpers.
struct Entry {
    id: u64,
    /// How many more helpers may join.
    tickets: usize,
    job: Arc<dyn Job>,
    latch: Arc<Latch>,
    /// The tickets the batch was queued with.
    #[cfg(test)]
    offered: usize,
    /// The helpers that have joined it, never more than `offered`.
    #[cfg(test)]
    joined: usize,
}

/// How the helpers of one batch report back to its submitter.
struct Latch {
    /// The helpers inside the batch.  It rises only under the pool's
    /// mutex while the batch is queued, so once the submitter has closed
    /// the batch it only falls.
    attached: AtomicUsize,
    /// Unparked by the helper that brings the count to zero.
    submitter: Thread,
    /// The payload of the first panic a helper caught in a check.
    panic: Mutex<Option<Box<dyn Any + Send>>>,
}

/// What a pool has done, kept in unit-test builds only and written only
/// where the mutex is already held.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
struct Stats {
    /// Batches that asked for at least one helper.
    batches: u64,
    /// Tickets those batches offered.
    tickets: u64,
    /// Times a helper joined a batch.
    attaches: u64,
    /// Times a helper joined a batch that had already been joined once
    /// for every ticket it offered.  Zero while tickets are counted
    /// rightly.
    overdrawn: u64,
    /// Helper threads created.
    helpers_created: u64,
    /// Batches that met a refused thread creation.
    refusals: u64,
    /// Times a helper found a queued batch with tickets left and nothing
    /// to claim, and took its tickets away.
    exhausted_skips: u64,
    /// Times a helper put itself on the stack of parked helpers.
    idle_pushes: u64,
    /// The helpers put on and taken off that stack, in order, when a
    /// test asked for the record.
    idle_order: Option<Vec<IdleEvent>>,
}

/// One change to the stack of parked helpers.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdleEvent {
    /// The helper put itself on the stack.
    Pushed(usize),
    /// A submitter took the helper off the stack to wake it.
    Popped(usize),
}

#[cfg(test)]
impl Stats {
    fn idle_event(&mut self, event: IdleEvent) {
        if let IdleEvent::Pushed(_) = event {
            self.idle_pushes = self.idle_pushes.wrapping_add(1);
        }
        if let Some(order) = &mut self.idle_order {
            order.push(event);
        }
    }
}

#[cfg(test)]
std::thread_local! {
    /// The batches this thread has handed to [`Pool::run`], on any pool
    /// and of any size.  It exists in this crate's unit-test builds
    /// only, where the tests of the block script check read it to tell a
    /// tree the pool ran from one that was only counted on its way
    /// there.
    pub(crate) static BATCHES_RUN: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

impl Pool {
    /// The process-wide pool: one helper fewer than the logical CPUs the
    /// process may run on, so that with the submitting thread a batch
    /// has one worker per CPU, as the scoped path gives it.  The helpers
    /// are created when a batch first wants them, are named
    /// `scriptval-N` and are never joined: the pool lives in a static.
    pub(crate) fn global() -> &'static Pool {
        static POOL: OnceLock<Pool> = OnceLock::new();
        POOL.get_or_init(|| {
            // Probed once, here: on Linux `available_parallelism`
            // re-reads the cgroup quota files on every call.
            let cpus = thread::available_parallelism().map_or(1, |n| n.get());
            Pool::with_spawner(
                cpus.saturating_sub(1),
                SPAWN_RETRY_BATCHES,
                Box::new(|id, main| {
                    thread::Builder::new()
                        .name(format!("scriptval-{id}"))
                        .spawn(main)
                }),
            )
        })
    }

    /// A pool of at most `width` helpers whose threads `spawner`
    /// creates.  After a creation is refused, none is tried until
    /// `spawn_retry` more batches have been submitted.
    fn with_spawner(width: usize, spawn_retry: u64, spawner: Spawner) -> Pool {
        Pool {
            inner: Arc::new(Inner {
                width,
                spawn_retry,
                seq: AtomicU64::new(0),
                state: Mutex::new(State {
                    queue: VecDeque::with_capacity(QUEUE_ROOM),
                    // Room for every helper, so that parking never
                    // allocates under the mutex.
                    idle: Vec::with_capacity(width),
                    helpers: 0,
                    next_helper: 0,
                    spawn_after: 0,
                    closed: false,
                    handles: Vec::new(),
                    #[cfg(test)]
                    stats: Stats::default(),
                }),
                spawner,
                #[cfg(test)]
                waits: AtomicU64::new(0),
                #[cfg(test)]
                woke: OnceLock::new(),
            }),
        }
    }

    /// The most helpers the pool holds.  Zero on a machine with one
    /// logical CPU, where a batch has nothing to gain from the pool.
    pub(crate) fn width(&self) -> usize {
        self.inner.width
    }

    /// Run every check of the batch, the calling thread among the
    /// workers, and return its verdict once no helper holds the batch.
    ///
    /// `Ok` means every check returned `Ok`.  An error is the one the
    /// check of the lowest failing index returned, whichever thread ran
    /// it and whenever it failed.
    ///
    /// # Panics
    ///
    /// When a check panicked, on this thread or on a helper: see the
    /// module documentation.
    pub(crate) fn run<B: Batch>(&self, batch: B) -> Result<(), RuleError> {
        #[cfg(test)]
        BATCHES_RUN.set(BATCHES_RUN.get().wrapping_add(1));
        let inner: &Inner = &self.inner;
        let run = Arc::new(Run::new(batch));

        // A helper for every item but the one the caller starts on, as
        // far as the pool is wide.  A batch that wants none never
        // touches the pool.
        let want = inner.width.min(run.len.saturating_sub(1));
        if want == 0 {
            run.work();
            return run.result();
        }

        // From here on the batch is closed and its helpers are waited
        // for on every way out, an unwinding of the caller's own checks
        // included.  The guard exists before the entry does; closing a
        // batch that was never queued does nothing.
        let id = inner.seq.fetch_add(1, Ordering::Relaxed);
        let latch = Arc::new(Latch {
            attached: AtomicUsize::new(0),
            submitter: thread::current(),
            panic: Mutex::new(None),
        });
        let finish = Finish {
            inner,
            id,
            job: &*run,
            latch: &latch,
        };

        // Queue the batch, take the helpers parked most recently off
        // the stack and reserve the helpers still to be created, all
        // under one acquisition: a helper either sees the entry when it
        // scans or is on the stack when it is popped.  The list of
        // helpers to wake has its room before the mutex is taken.
        let mut wake: Vec<Thread> = Vec::with_capacity(want);
        let job: Arc<dyn Job> = run.clone();
        let entry = Entry {
            id,
            tickets: want,
            job,
            latch: Arc::clone(&latch),
            #[cfg(test)]
            offered: want,
            #[cfg(test)]
            joined: 0,
        };
        let (first, grow) = {
            let mut st = inner.state.lock().expect("pool state poisoned");
            st.queue.push_back(entry);
            while wake.len() < want {
                let Some((_helper, parked)) = st.idle.pop() else {
                    break;
                };
                #[cfg(test)]
                st.stats.idle_event(IdleEvent::Popped(_helper));
                wake.push(parked);
            }
            #[cfg(test)]
            {
                st.stats.batches = st.stats.batches.wrapping_add(1);
                st.stats.tickets = st.stats.tickets.wrapping_add(want as u64);
            }
            // The helpers this batch wants beyond those that exist are
            // counted as existing from now, so that another submitter
            // does not create them too.
            let grow = want.saturating_sub(st.helpers);
            if grow > 0 && id >= st.spawn_after {
                let first = st.next_helper;
                st.helpers = want;
                st.next_helper = first.wrapping_add(grow);
                (first, grow)
            } else {
                (0, 0)
            }
        };

        // Wake and create outside the mutex.  A new helper needs no
        // wake: it scans the queue before it parks.
        for helper in &wake {
            helper.unpark();
        }
        if grow > 0 {
            self.create_helpers(id, first, grow);
        }

        run.work();

        // The caller's work is done without unwinding: close the batch
        // here rather than in the guard, which would also stop it.
        //
        // The wait is not only for the helpers' sake.  The caller's
        // loop may have stopped at a failure while a helper is still
        // inside an item of a lower index, and the verdict is that
        // item's if it fails too; so the verdict is read below, after
        // every helper that joined has left, and not before.
        core::mem::forget(finish);
        inner.close_and_wait(id, &latch);

        // A helper's panic is looked for before the verdict is, and
        // whatever the failure slot holds.  The check that panicked
        // never ended, so the batch has no verdict: a failure on record
        // may be of a higher index than the item that check held.
        let payload = latch.panic.lock().expect("latch poisoned").take();
        if let Some(payload) = payload {
            // The hook ran on the helper when the check panicked.  A
            // panic raised here runs it once more, on this thread, with
            // the helper's message; a payload that is not a message
            // cannot be quoted and goes on as it is.
            match panic_message(&*payload) {
                Some(message) => panic!("a script check panicked on a pool helper: {message}"),
                None => resume_unwind(payload),
            }
        }
        debug_assert_eq!(
            Arc::strong_count(&run),
            1,
            "a script batch is still shared after its helpers left"
        );
        run.result()
    }

    /// Create the `grow` helpers reserved for batch `id`, numbered from
    /// `first`, stopping at the first one the OS refuses.  The batch
    /// then runs on the helpers there are and on its caller; the unused
    /// reservations are returned, and no creation is tried again until
    /// `spawn_retry` more batches have been submitted.
    fn create_helpers(&self, id: u64, first: usize, grow: usize) {
        let inner: &Inner = &self.inner;
        let mut handles = Vec::with_capacity(grow);
        for offset in 0..grow {
            let helper = first.wrapping_add(offset);
            let shared = Arc::clone(&self.inner);
            let main: HelperMain = Box::new(move || helper_main(shared, helper));
            match (inner.spawner)(helper, main) {
                Ok(handle) => handles.push(handle),
                Err(_) => break,
            }
        }
        let refused = grow.saturating_sub(handles.len());
        let mut st = inner.state.lock().expect("pool state poisoned");
        #[cfg(test)]
        {
            st.stats.helpers_created = st.stats.helpers_created.wrapping_add(handles.len() as u64);
            st.stats.refusals = st.stats.refusals.wrapping_add(u64::from(refused > 0));
        }
        st.handles.append(&mut handles);
        if refused > 0 {
            st.helpers = st.helpers.saturating_sub(refused);
            st.spawn_after = id.wrapping_add(inner.spawn_retry);
        }
    }
}

impl Drop for Pool {
    /// Close the pool and join its helpers.  The process-wide pool is
    /// never dropped; this is for the pools tests make.  No batch can be
    /// running: [`Pool::run`] borrows the pool for the whole call.
    fn drop(&mut self) {
        let (idle, handles) = {
            let mut st = self.inner.state.lock().expect("pool state poisoned");
            st.closed = true;
            (
                core::mem::take(&mut st.idle),
                core::mem::take(&mut st.handles),
            )
        };
        for (_, helper) in &idle {
            helper.unpark();
        }
        for handle in handles {
            // A helper catches the panics of checks, so it has nothing
            // to report here.
            let _ = handle.join();
        }
    }
}

impl Inner {
    /// Close batch `id`: take its entry off the queue, after which no
    /// helper can join it, and wait until the helpers that did join
    /// have left.
    ///
    /// A helper drops its reference to the batch before it lowers the
    /// count, and the pool's own reference goes with the entry, so when
    /// this returns the submitter is the batch's only owner.
    fn close_and_wait(&self, id: u64, latch: &Latch) {
        let entry = {
            let mut st = self.state.lock().expect("pool state poisoned");
            match st.queue.iter().position(|entry| entry.id == id) {
                Some(at) => st.queue.remove(at),
                None => None,
            }
        };
        // The entry's references go outside the mutex.
        drop(entry);
        // An unpark that arrives after the count was seen at zero stays
        // behind as a token on this thread, as one does after
        // `std::thread::scope`; every park is in a loop on its
        // condition, this one included.
        while latch.attached.load(Ordering::SeqCst) != 0 {
            #[cfg(test)]
            self.waits.fetch_add(1, Ordering::SeqCst);
            thread::park();
        }
    }
}

/// Closes a batch when its submitter unwinds out of its own checks:
/// the batch is stopped, taken off the queue, and the helpers inside it
/// are waited for before the panic continues, so that no helper is left
/// holding a batch whose submitter is gone.
struct Finish<'a> {
    inner: &'a Inner,
    id: u64,
    job: &'a dyn Job,
    latch: &'a Latch,
}

impl Drop for Finish<'_> {
    fn drop(&mut self) {
        self.job.stop();
        self.inner.close_and_wait(self.id, self.latch);
    }
}

/// The message of a caught panic, when its payload is one: `panic!`
/// leaves a `&'static str` for a literal and a `String` for a formatted
/// message.  `None` for a payload of any other type
/// (`std::panic::panic_any`), which holds no text to quote.
fn panic_message(payload: &(dyn Any + Send)) -> Option<&str> {
    match payload.downcast_ref::<&'static str>() {
        Some(message) => Some(message),
        None => payload.downcast_ref::<String>().map(String::as_str),
    }
}

/// The life of helper `id`: join the oldest batch that has a ticket and
/// something left to claim, work on it, leave it, and park when there
/// is none.  It returns only when the pool is dropped.
fn helper_main(inner: Arc<Inner>, id: usize) {
    let me = thread::current();
    let mut st = inner.state.lock().expect("pool state poisoned");
    loop {
        // A wake that did not come from a submitter's pop (a stray
        // unpark, a spurious return from the park) finds this helper
        // still on the stack; it comes off before anything else, so the
        // stack never holds a helper twice.
        st.idle.retain(|(helper, _)| *helper != id);
        if st.closed {
            st.helpers = st.helpers.saturating_sub(1);
            return;
        }

        let mut found: Option<(Arc<dyn Job>, Arc<Latch>)> = None;
        #[cfg(test)]
        let (mut skips, mut overdrawn) = (0u64, false);
        for entry in st.queue.iter_mut() {
            let Some(left) = entry.tickets.checked_sub(1) else {
                continue;
            };
            // Every item is claimed or the batch has failed: no helper
            // is of use to it any more, this one or a later one.
            if entry.job.exhausted() {
                entry.tickets = 0;
                #[cfg(test)]
                {
                    skips = skips.wrapping_add(1);
                }
                continue;
            }
            entry.tickets = left;
            #[cfg(test)]
            {
                entry.joined = entry.joined.wrapping_add(1);
                overdrawn = entry.joined > entry.offered;
            }
            // Counted in before the mutex is released: the submitter
            // closes its batch under this mutex, so it sees every
            // helper that joined.
            entry.latch.attached.fetch_add(1, Ordering::SeqCst);
            found = Some((Arc::clone(&entry.job), Arc::clone(&entry.latch)));
            break;
        }
        #[cfg(test)]
        {
            st.stats.exhausted_skips = st.stats.exhausted_skips.wrapping_add(skips);
        }

        match found {
            None => {
                // On the stack only after a scan under this same
                // acquisition found nothing: a batch queued later pops
                // this helper and wakes it.
                st.idle.push((id, me.clone()));
                #[cfg(test)]
                st.stats.idle_event(IdleEvent::Pushed(id));
                drop(st);
                thread::park();
                #[cfg(test)]
                if let Some(woke) = inner.woke.get() {
                    woke(id);
                }
                st = inner.state.lock().expect("pool state poisoned");
            }
            Some((job, latch)) => {
                #[cfg(test)]
                {
                    st.stats.attaches = st.stats.attaches.wrapping_add(1);
                    st.stats.overdrawn = st.stats.overdrawn.wrapping_add(u64::from(overdrawn));
                }
                drop(st);
                // Inert under the release profile, which aborts at the
                // panic.  In an unwinding build the batch is stopped and
                // the payload goes to the submitter, which raises the
                // panic again on its own thread.
                let outcome = catch_unwind(AssertUnwindSafe(|| job.work()));
                if let Err(payload) = outcome {
                    job.stop();
                    let mut slot = latch.panic.lock().expect("latch poisoned");
                    if slot.is_none() {
                        *slot = Some(payload);
                    }
                }
                // The batch goes before the count does, so a submitter
                // that sees zero knows no helper holds its batch.
                drop(job);
                if latch.attached.fetch_sub(1, Ordering::SeqCst) == 1 {
                    latch.submitter.unpark();
                }
                drop(latch);
                st = inner.state.lock().expect("pool state poisoned");
            }
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic over small fixed values"
)]
mod tests {
    //! The pool on batches made for the tests.  A check tells the
    //! submitting thread from a helper by thread id, and threads are held
    //! and let go through [`Signal`]s, so that no test passes or fails by
    //! the length of a pause: the pauses in [`wait_until`] only space its
    //! polls.  Every wait of a test ends at [`WATCHDOG`] and every test
    //! that runs a pool or waits does so under [`watched`], so a pool
    //! that stalls fails a test rather than hanging the run.  The tests
    //! that only drive a [`Run`] on their own thread neither wait nor
    //! start a thread, and run bare.

    use std::hint::black_box;
    use std::sync::Condvar;
    use std::sync::atomic::AtomicU32;
    use std::sync::mpsc;
    use std::thread::ThreadId;
    use std::time::Duration;

    use super::*;
    use crate::ruleerror::{RuleErrorKind, rule_error};

    /// How long a test waits for something that must happen.
    const WATCHDOG: Duration = Duration::from_secs(60);

    /// The batches a test pool waits after a refused thread.
    const RETRY: u64 = 8;

    /// Run a test's body on a thread of its own and fail the test when
    /// the body has not returned after several watchdogs.  A pool that
    /// stalls its submitter then shows as a failed test and not as a
    /// test run that never ends.  A panic of the body is the test's.
    fn watched(body: impl FnOnce() + Send + 'static) {
        let (tx, rx) = mpsc::channel();
        let runner = thread::spawn(move || {
            body();
            let _ = tx.send(());
        });
        match rx.recv_timeout(WATCHDOG * 5) {
            Err(mpsc::RecvTimeoutError::Timeout) => panic!("the test did not finish"),
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                if let Err(payload) = runner.join() {
                    resume_unwind(payload);
                }
            }
        }
    }

    /// The logical CPUs, capped: what the repeat counts scale with, so
    /// that a small machine is not asked for a large machine's rounds.
    fn cpus() -> usize {
        thread::available_parallelism().map_or(1, |n| n.get().min(16))
    }

    /// A count that threads raise and wait for.
    #[derive(Default)]
    struct Signal {
        count: Mutex<usize>,
        raised: Condvar,
    }

    impl Signal {
        fn new() -> Arc<Signal> {
            Arc::new(Signal::default())
        }

        fn raise(&self) {
            *self.count.lock().expect("signal poisoned") += 1;
            self.raised.notify_all();
        }

        /// Wait until the count is at least `want`; `false` when the
        /// watchdog ended the wait.
        fn wait(&self, want: usize) -> bool {
            let count = self.count.lock().expect("signal poisoned");
            let (_count, timeout) = self
                .raised
                .wait_timeout_while(count, WATCHDOG, |count| *count < want)
                .expect("signal poisoned");
            !timeout.timed_out()
        }
    }

    /// Raises a signal when dropped, so that a test that fails lets go
    /// of the threads it holds.
    struct Release<'a>(&'a Signal);

    impl Drop for Release<'_> {
        fn drop(&mut self) {
            self.0.raise();
        }
    }

    /// Poll until `done` holds.
    fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
        for poll in 0..60_000u32 {
            if done() {
                return;
            }
            if poll < 200 {
                thread::yield_now();
            } else {
                thread::sleep(Duration::from_millis(1));
            }
        }
        panic!("timed out waiting until {what}");
    }

    fn item_error(index: usize) -> RuleError {
        rule_error(RuleErrorKind::ScriptValidation, format!("item {index}"))
    }

    /// The index of the failure a run holds, if it holds one.
    fn held_failure<B: Batch>(run: &Run<B>) -> Option<usize> {
        let slot = run.failure.lock().expect("failure slot poisoned");
        slot.as_ref().map(|(index, _)| *index)
    }

    /// What a check held by a signal returns: `Ok` once the signal has
    /// been raised `want` times, an error no test expects after the
    /// watchdog.
    fn held(signal: &Signal, want: usize) -> Result<(), RuleError> {
        if signal.wait(want) {
            Ok(())
        } else {
            Err(rule_error(
                RuleErrorKind::ScriptValidation,
                "the watchdog ended a check's wait",
            ))
        }
    }

    /// A batch whose checks are one closure.
    struct Checks<F> {
        len: usize,
        check: F,
    }

    impl<F> Batch for Checks<F>
    where
        F: Fn(usize) -> Result<(), RuleError> + Send + Sync + 'static,
    {
        fn len(&self) -> usize {
            self.len
        }

        fn check(&self, index: usize) -> Result<(), RuleError> {
            (self.check)(index)
        }
    }

    fn checks<F>(len: usize, check: F) -> Checks<F>
    where
        F: Fn(usize) -> Result<(), RuleError> + Send + Sync + 'static,
    {
        Checks { len, check }
    }

    /// How often each item of a batch was checked.
    type Seen = Arc<Vec<AtomicU32>>;

    fn seen(len: usize) -> Seen {
        Arc::new((0..len).map(|_| AtomicU32::new(0)).collect())
    }

    fn once(seen: &Seen) -> bool {
        seen.iter().all(|count| count.load(Ordering::SeqCst) == 1)
    }

    /// A little work, so that helpers get to an item before the caller
    /// has taken them all.
    fn busy(seed: usize) {
        let mut x = seed as u64;
        for _ in 0..200 {
            x = black_box(x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1));
        }
    }

    /// A batch that counts the checks of each item and fails the items
    /// in `bad`.
    fn counting(
        seen: &Seen,
        bad: &[usize],
    ) -> Checks<impl Fn(usize) -> Result<(), RuleError> + Send + Sync + 'static> {
        let (seen, bad) = (Arc::clone(seen), bad.to_vec());
        checks(seen.len(), move |index| {
            seen[index].fetch_add(1, Ordering::SeqCst);
            busy(index);
            if bad.contains(&index) {
                Err(item_error(index))
            } else {
                Ok(())
            }
        })
    }

    /// The OS as a test pool's spawner sees it: it counts the threads
    /// it is asked for, grants only as many as it has left, and counts
    /// the helpers that returned.
    struct Os {
        asked: AtomicUsize,
        grants: AtomicUsize,
        exited: AtomicUsize,
    }

    impl Os {
        fn granting(grants: usize) -> Arc<Os> {
            Arc::new(Os {
                asked: AtomicUsize::new(0),
                grants: AtomicUsize::new(grants),
                exited: AtomicUsize::new(0),
            })
        }

        fn asked(&self) -> usize {
            self.asked.load(Ordering::SeqCst)
        }

        fn pool(self: &Arc<Os>, width: usize) -> Pool {
            let os = Arc::clone(self);
            Pool::with_spawner(
                width,
                RETRY,
                Box::new(move |id, main| {
                    os.asked.fetch_add(1, Ordering::SeqCst);
                    let granted =
                        os.grants
                            .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                                left.checked_sub(1)
                            });
                    if granted.is_err() {
                        return Err(io::Error::from(io::ErrorKind::WouldBlock));
                    }
                    let os = Arc::clone(&os);
                    thread::Builder::new()
                        .name(format!("test-scriptval-{id}"))
                        .spawn(move || {
                            main();
                            os.exited.fetch_add(1, Ordering::SeqCst);
                        })
                }),
            )
        }
    }

    /// A pool whose OS refuses nothing.
    fn pool(width: usize) -> Pool {
        Os::granting(usize::MAX).pool(width)
    }

    // What the tests read of a pool's state.  Each takes the mutex,
    // copies and lets go: an assertion that failed while holding it
    // would poison the mutex the pool's `Drop` then takes.

    fn stats(pool: &Pool) -> Stats {
        let st = pool.inner.state.lock().expect("pool state poisoned");
        st.stats.clone()
    }

    /// The helpers on the stack of parked helpers, bottom first.
    fn idle(pool: &Pool) -> Vec<usize> {
        let st = pool.inner.state.lock().expect("pool state poisoned");
        st.idle.iter().map(|(helper, _)| *helper).collect()
    }

    fn queued(pool: &Pool) -> usize {
        pool.inner
            .state
            .lock()
            .expect("pool state poisoned")
            .queue
            .len()
    }

    fn helpers(pool: &Pool) -> usize {
        pool.inner
            .state
            .lock()
            .expect("pool state poisoned")
            .helpers
    }

    fn waits(pool: &Pool) -> u64 {
        pool.inner.waits.load(Ordering::SeqCst)
    }

    /// Wait until `helpers` helpers are on the stack of parked helpers.
    fn parked(pool: &Pool, helpers: usize) {
        wait_until("the helpers are parked", || idle(pool).len() == helpers);
    }

    /// Have every helper call `hook` with its number when it returns
    /// from a park.
    fn on_wake(pool: &Pool, hook: impl Fn(usize) + Send + Sync + 'static) {
        assert!(pool.inner.woke.set(Box::new(hook)).is_ok(), "one hook");
    }

    /// A batch that completes only when `threads` different threads are
    /// each inside one of its items at the same time.
    fn all_hands(
        threads: usize,
    ) -> Checks<impl Fn(usize) -> Result<(), RuleError> + Send + Sync + 'static> {
        let arrived = Signal::new();
        checks(threads, move |_| {
            arrived.raise();
            held(&arrived, threads)
        })
    }

    /// T1.  Every item of every batch is checked exactly once, whatever
    /// the batch's size and the pool's width, the empty batch included.
    #[test]
    fn every_item_is_checked_exactly_once() {
        watched(|| {
            for width in [0, 1, 3, 15] {
                let pool = pool(width);
                for round in 0..3 * cpus() {
                    for len in [0, 1, 2, 3, 4, 5, 15, 16, 17, 100, 1000] {
                        let items = seen(len);
                        assert_eq!(
                            pool.run(counting(&items, &[])),
                            Ok(()),
                            "width {width} len {len} round {round}"
                        );
                        assert!(once(&items), "width {width} len {len} round {round}");
                    }
                }
                assert_eq!(stats(&pool).overdrawn, 0, "width {width}");
            }
        });
    }

    /// An empty failure slot is not a verdict by itself: `result`
    /// refuses `Ok` while fewer checks have passed than the batch has
    /// items, here for a batch no worker has touched.
    #[test]
    #[should_panic(expected = "a script batch returned before every item passed")]
    fn result_refuses_ok_before_every_item_passed() {
        let run = Run::new(checks(3, |_| Ok(())));
        let _ = run.result();
    }

    /// And a batch that was stopped has no verdict, though every one of
    /// its items passed.
    #[test]
    #[should_panic(expected = "a script batch stopped without a failure")]
    fn result_refuses_ok_for_a_stopped_batch() {
        let run = Run::new(checks(2, |_| Ok(())));
        run.work();
        run.stop();
        let _ = run.result();
    }

    /// The passed count is of the checks that returned `Ok`: the item
    /// that failed and the items never claimed are not in it.
    #[test]
    fn the_passed_count_is_of_the_checks_that_passed() {
        let items = seen(5);
        let run = Run::new(counting(&items, &[1]));
        run.work();
        assert_eq!(run.passed.load(Ordering::SeqCst), 1);
        assert_eq!(run.result(), Err(item_error(1)));
    }

    /// T2.  The failure kept is the one of lowest index, whichever is
    /// recorded first: a later failure replaces the one held when its
    /// index is lower, and not otherwise.  A batch on the caller alone
    /// names its lowest failing index, and a batch with one failing
    /// item names that item whichever thread checked it.
    #[test]
    fn the_lowest_failure_is_kept() {
        watched(|| {
            // Two workers, each inside a failing item.  One item is let
            // go and its failure recorded before the other is let go:
            // first the higher one ahead of the lower, then the lower
            // one ahead of the higher.
            for recorded_first in [1usize, 0] {
                let entered = Signal::new();
                let gates = [Signal::new(), Signal::new()];
                let run = Run::new(checks(2, {
                    let (entered, gates) = (Arc::clone(&entered), gates.clone());
                    move |index| {
                        entered.raise();
                        held(&gates[index], 1)?;
                        Err(item_error(index))
                    }
                }));
                thread::scope(|s| {
                    let _release = (Release(&gates[0]), Release(&gates[1]));
                    for _ in 0..2 {
                        s.spawn(|| run.work());
                    }
                    assert!(entered.wait(2), "both workers are inside an item");
                    gates[recorded_first].raise();
                    wait_until("the first failure is recorded", || {
                        held_failure(&run).is_some()
                    });
                    assert_eq!(held_failure(&run), Some(recorded_first));
                    gates[1 - recorded_first].raise();
                });
                assert_eq!(
                    held_failure(&run),
                    Some(0),
                    "item {recorded_first} failed first"
                );
                assert_eq!(
                    run.result(),
                    Err(item_error(0)),
                    "item {recorded_first} failed first"
                );
            }

            // Index order on the caller.
            assert_eq!(
                pool(0).run(counting(&seen(20), &[13, 7])),
                Err(item_error(7))
            );

            for width in [1, 3, 15] {
                let pool = pool(width);
                for len in [2, 4, 5, 16, 40, 300] {
                    for bad in [0, len / 2, len - 1] {
                        let items = seen(len);
                        assert_eq!(
                            pool.run(counting(&items, &[bad])),
                            Err(item_error(bad)),
                            "width {width} len {len}"
                        );
                        assert_eq!(items[bad].load(Ordering::SeqCst), 1);
                        assert!(items.iter().all(|count| count.load(Ordering::SeqCst) <= 1));
                        // And the pool validates after a failure.
                        let items = seen(len);
                        assert_eq!(pool.run(counting(&items, &[])), Ok(()));
                        assert!(once(&items));
                    }
                }
            }
        });
    }

    /// T2, on a pool with helpers and two failing items of different
    /// kinds and texts.  The verdict is the failure of the one of lower
    /// index, every time, and no item is checked twice.  First with
    /// both items held until two workers are inside them at the same
    /// time, so that both failures are offered at once and either may
    /// be recorded first; then left to the scheduler, wherever the two
    /// items sit in the batch.
    #[test]
    fn a_batch_with_two_failures_names_the_lower_one() {
        fn failure(index: usize) -> RuleError {
            let kind = if index.is_multiple_of(2) {
                RuleErrorKind::ScriptMalformed
            } else {
                RuleErrorKind::ScriptValidation
            };
            rule_error(kind, format!("item {index} is bad"))
        }

        watched(|| {
            const LEN: usize = 8;
            let held_pool = pool(3);
            for (lower, higher) in [(0usize, 1usize), (2, 5), (6, 7)] {
                for round in 0..100 * cpus() {
                    let items = seen(LEN);
                    let both = Signal::new();
                    let batch = checks(LEN, {
                        let (items, both) = (Arc::clone(&items), Arc::clone(&both));
                        move |index| {
                            items[index].fetch_add(1, Ordering::SeqCst);
                            if index != lower && index != higher {
                                return Ok(());
                            }
                            both.raise();
                            assert!(both.wait(2), "two workers are inside the failing items");
                            Err(failure(index))
                        }
                    });
                    assert_eq!(
                        held_pool.run(batch),
                        Err(failure(lower)),
                        "items {lower} and {higher}, round {round}"
                    );
                    assert_eq!(items[lower].load(Ordering::SeqCst), 1, "round {round}");
                    assert_eq!(items[higher].load(Ordering::SeqCst), 1, "round {round}");
                    assert!(items.iter().all(|count| count.load(Ordering::SeqCst) <= 1));
                }
            }

            for width in [3, 15] {
                let pool = pool(width);
                for len in [4usize, 16, 40] {
                    for (lower, higher) in [(0, len - 1), (len / 2, len / 2 + 1), (1, 2)] {
                        for round in 0..20 * cpus() {
                            let items = seen(len);
                            let batch = checks(len, {
                                let items = Arc::clone(&items);
                                move |index| {
                                    items[index].fetch_add(1, Ordering::SeqCst);
                                    busy(index);
                                    if index == lower || index == higher {
                                        Err(failure(index))
                                    } else {
                                        Ok(())
                                    }
                                }
                            });
                            assert_eq!(
                                pool.run(batch),
                                Err(failure(lower)),
                                "width {width} len {len} items {lower} and {higher} round {round}"
                            );
                            assert_eq!(items[lower].load(Ordering::SeqCst), 1);
                            assert!(items.iter().all(|count| count.load(Ordering::SeqCst) <= 1));
                        }
                    }
                }
                // And the pool validates after them.
                let items = seen(40);
                assert_eq!(pool.run(counting(&items, &[])), Ok(()));
                assert!(once(&items));
            }
        });
    }

    /// An index claimed before a failure is recorded is still checked.
    /// A worker is held in the step that claims item 0, before it has
    /// read anything else, while item 1 fails and the batch shows as
    /// failed; let go, it checks item 0 all the same, and item 0's
    /// failure is the verdict.  Wherever between the claim and the
    /// check a worker looked at the failure flag, it would look after
    /// this hold.
    #[test]
    fn an_item_claimed_before_a_failure_is_still_checked() {
        /// Two failing items, and a hold on the worker that claims the
        /// first of them.
        struct HeldAtItsClaim {
            claimed: Arc<Signal>,
            gate: Arc<Signal>,
            items: Seen,
        }

        impl Batch for HeldAtItsClaim {
            fn len(&self) -> usize {
                2
            }

            fn check(&self, index: usize) -> Result<(), RuleError> {
                self.items[index].fetch_add(1, Ordering::SeqCst);
                Err(item_error(index))
            }

            fn claimed(&self, index: usize) {
                if index == 0 {
                    self.claimed.raise();
                    assert!(self.gate.wait(1), "the watchdog ended a held claim");
                }
            }
        }

        watched(|| {
            let (claimed, gate) = (Signal::new(), Signal::new());
            let items = seen(2);
            let run = Run::new(HeldAtItsClaim {
                claimed: Arc::clone(&claimed),
                gate: Arc::clone(&gate),
                items: Arc::clone(&items),
            });
            thread::scope(|s| {
                let _release = Release(&gate);
                s.spawn(|| run.work());
                assert!(claimed.wait(1), "item 0 is claimed");
                // This thread claims item 1, which fails.
                run.work();
                assert_eq!(held_failure(&run), Some(1));
                assert!(run.exhausted(), "the batch shows its failure");
                assert_eq!(
                    items[0].load(Ordering::SeqCst),
                    0,
                    "item 0 is claimed and not yet checked"
                );
                gate.raise();
            });
            assert_eq!(items[0].load(Ordering::SeqCst), 1, "item 0 was checked");
            assert_eq!(run.result(), Err(item_error(0)));
        });
    }

    /// A failure at a high index does not end the batch while an item
    /// of a lower index is still being checked: the submitter waits for
    /// that check, and when it fails too, its failure is the verdict.
    /// The pool's one helper is held inside the first item it claims,
    /// one of the first two, while the caller goes on to the failing
    /// item further up and stops there.
    #[test]
    fn a_failure_at_a_higher_index_waits_for_a_lower_one_still_running() {
        watched(|| {
            const LEN: usize = 6;
            const HIGH: usize = 4;
            let pool = pool(1);
            let (inside, gate) = (Signal::new(), Signal::new());
            let helper_item = Arc::new(AtomicUsize::new(usize::MAX));
            let items = seen(LEN);
            let waits_before = waits(&pool);
            let result = thread::scope(|s| {
                let _release = Release(&gate);
                let submitter = s.spawn(|| {
                    let caller = thread::current().id();
                    let (inside, gate) = (Arc::clone(&inside), Arc::clone(&gate));
                    let (helper_item, items) = (Arc::clone(&helper_item), Arc::clone(&items));
                    pool.run(checks(LEN, move |index| {
                        items[index].fetch_add(1, Ordering::SeqCst);
                        if thread::current().id() != caller {
                            helper_item.store(index, Ordering::SeqCst);
                            inside.raise();
                            held(&gate, 1)?;
                            return Err(item_error(index));
                        }
                        // The caller's first item is not done before the
                        // helper has one.
                        held(&inside, 1)?;
                        if index == HIGH {
                            Err(item_error(HIGH))
                        } else {
                            Ok(())
                        }
                    }))
                });
                wait_until("the submitter waits for its helper", || {
                    waits(&pool) > waits_before || submitter.is_finished()
                });
                assert!(
                    !submitter.is_finished(),
                    "run returned while a helper was inside an item of a lower index"
                );
                // The caller stopped at the higher item's failure, which
                // is thus recorded, and the helper is still inside the
                // lower one.
                let checked: Vec<u32> = items
                    .iter()
                    .map(|count| count.load(Ordering::SeqCst))
                    .collect();
                assert_eq!(checked, [1, 1, 1, 1, 1, 0]);
                gate.raise();
                submitter.join().expect("the submitter panicked")
            });
            let lower = helper_item.load(Ordering::SeqCst);
            assert!(lower < 2, "the helper held item {lower}");
            assert_eq!(result, Err(item_error(lower)));
        });
    }

    /// A worker that arrives after a failure claims nothing, and the
    /// failed batch shows as exhausted, which is what keeps further
    /// helpers from joining it.
    #[test]
    fn a_later_worker_claims_nothing_after_a_failure() {
        let items = seen(5);
        let run = Run::new(counting(&items, &[1]));
        run.work();
        assert!(run.exhausted(), "a failed batch has nothing for a helper");
        run.work();
        assert_eq!(
            run.next.load(Ordering::Relaxed),
            2,
            "a worker that arrives after a failure takes no index"
        );
        let counts: Vec<u32> = items
            .iter()
            .map(|count| count.load(Ordering::SeqCst))
            .collect();
        assert_eq!(counts, [1, 1, 0, 0, 0]);
        assert_eq!(run.result(), Err(item_error(1)));
    }

    /// T3.  Once an item has failed no worker claims another: with
    /// every other item held until the batch shows its failure, each
    /// worker finishes at most the item it had in hand.  A held check
    /// that its watchdog lets go fails the test: it would mean the batch
    /// never showed its failure.
    #[test]
    fn a_failure_stops_the_rest() {
        watched(|| {
            const LEN: usize = 10_000;
            for width in [1, 3, 15] {
                let pool = pool(width);
                let (failing, gate) = (Signal::new(), Signal::new());
                let executed = Arc::new(AtomicUsize::new(0));
                let batch = checks(LEN, {
                    let (failing, gate) = (Arc::clone(&failing), Arc::clone(&gate));
                    let executed = Arc::clone(&executed);
                    move |index| {
                        executed.fetch_add(1, Ordering::SeqCst);
                        if index == 0 {
                            failing.raise();
                            return Err(item_error(0));
                        }
                        assert!(gate.wait(1), "the watchdog ended a held check");
                        Ok(())
                    }
                });
                let result = thread::scope(|s| {
                    let _release = Release(&gate);
                    let submitter = s.spawn(|| pool.run(batch));
                    assert!(failing.wait(1), "item 0 is checked");
                    // The batch was queued before item 0 was claimed.  It
                    // shows as exhausted once the failure is set, and it
                    // leaves the queue only after its caller stopped
                    // working, which with the gate shut takes the failure.
                    wait_until("the batch shows its failure", || {
                        let st = pool.inner.state.lock().expect("pool state poisoned");
                        st.queue.front().is_none_or(|entry| entry.job.exhausted())
                    });
                    gate.raise();
                    submitter.join().expect("the submitter panicked")
                });
                assert_eq!(result, Err(item_error(0)), "width {width}");
                let executed = executed.load(Ordering::SeqCst);
                assert!(
                    executed <= width + 2,
                    "width {width}: {executed} of {LEN} items were checked"
                );
            }
        });
    }

    /// T4.  The submitter does not return while a helper is inside an
    /// item: it has parked by the time the helper's item is let go, and
    /// the failure that item then reports is the batch's verdict.
    #[test]
    fn run_waits_for_a_helper_inside_an_item() {
        watched(|| {
            let pool = pool(1);
            let (inside, gate) = (Signal::new(), Signal::new());
            let helper_item = Arc::new(AtomicUsize::new(usize::MAX));
            let waits_before = waits(&pool);
            let result = thread::scope(|s| {
                let _release = Release(&gate);
                let submitter = s.spawn(|| {
                    let caller = thread::current().id();
                    let (inside, gate) = (Arc::clone(&inside), Arc::clone(&gate));
                    let helper_item = Arc::clone(&helper_item);
                    pool.run(checks(2, move |index| {
                        if thread::current().id() == caller {
                            // Not done before the helper has an item.
                            return held(&inside, 1);
                        }
                        helper_item.store(index, Ordering::SeqCst);
                        inside.raise();
                        held(&gate, 1)?;
                        Err(item_error(index))
                    }))
                });
                wait_until("the submitter waits for its helper", || {
                    waits(&pool) > waits_before || submitter.is_finished()
                });
                assert!(
                    !submitter.is_finished(),
                    "run returned while a helper was inside an item"
                );
                assert_eq!(queued(&pool), 0, "the batch is closed before the wait");
                gate.raise();
                submitter.join().expect("the submitter panicked")
            });
            assert_eq!(result, Err(item_error(helper_item.load(Ordering::SeqCst))));
        });
    }

    /// T5.  When `run` returns nothing but the caller holds the batch:
    /// the queue's reference and every helper's are gone, so what the
    /// batch owns is released with it.  The submitting thread is sent
    /// unparks throughout, which makes its wait for the helpers a poll
    /// and so has it look at the count the moment a helper lowers it.
    #[test]
    fn the_batch_is_uniquely_owned_at_return() {
        watched(|| {
            struct Stop<'a>(&'a AtomicBool);
            impl Drop for Stop<'_> {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::SeqCst);
                }
            }

            let pool = pool(15);
            let owned = Arc::new(());
            let stop = AtomicBool::new(false);
            let submitter = thread::current();
            thread::scope(|s| {
                let _stop = Stop(&stop);
                s.spawn(|| {
                    while !stop.load(Ordering::SeqCst) {
                        submitter.unpark();
                        thread::yield_now();
                    }
                });
                for round in 0..2_000 * cpus() {
                    let len = 4 + round % 37;
                    let batch = checks(len, {
                        let owned = Arc::clone(&owned);
                        move |index| {
                            let _held = &owned;
                            busy(index);
                            Ok(())
                        }
                    });
                    assert_eq!(pool.run(batch), Ok(()));
                    assert_eq!(
                        Arc::strong_count(&owned),
                        1,
                        "round {round}: the batch outlived its run"
                    );
                }
            });
            assert_eq!(stats(&pool).overdrawn, 0);
        });
    }

    /// T6.  Two threads submit to one pool at once, one of them batches
    /// with a failing item, and each gets its own verdicts; and a
    /// submitter nobody helps does its own work, finishing while the
    /// pool's only helper is held inside another submitter's item.
    #[test]
    fn two_submitters() {
        watched(|| {
            let shared = pool(7);
            thread::scope(|s| {
                for who in 0..2usize {
                    let pool = &shared;
                    s.spawn(move || {
                        for round in 0..500 * cpus() {
                            let len = 3 + (round + who) % 30;
                            let bad = (who == 1 && round % 7 == 0).then_some(len / 2);
                            let items = seen(len);
                            let result = pool.run(counting(&items, bad.as_slice()));
                            match bad {
                                None => {
                                    assert_eq!(result, Ok(()), "submitter {who} round {round}");
                                    assert!(once(&items), "submitter {who} round {round}");
                                }
                                Some(bad) => {
                                    assert_eq!(result, Err(item_error(bad)), "round {round}");
                                    assert_eq!(items[bad].load(Ordering::SeqCst), 1);
                                }
                            }
                        }
                    });
                }
            });
            assert_eq!(queued(&shared), 0);
            // No batch was joined by more helpers than it had tickets,
            // with helpers coming free from one submitter's batch while
            // the other's was open.
            assert_eq!(stats(&shared).overdrawn, 0);

            let pool = pool(1);
            let (inside, gate) = (Signal::new(), Signal::new());
            thread::scope(|s| {
                let _release = Release(&gate);
                let first = s.spawn(|| {
                    let caller = thread::current().id();
                    let (inside, gate) = (Arc::clone(&inside), Arc::clone(&gate));
                    pool.run(checks(2, move |_| {
                        if thread::current().id() == caller {
                            return held(&inside, 1);
                        }
                        inside.raise();
                        held(&gate, 1)
                    }))
                });
                assert!(inside.wait(1), "the helper is inside the first batch");
                // The second batch finds no helper and is not kept waiting
                // for one.
                let items = seen(5);
                let (tx, rx) = mpsc::channel();
                s.spawn({
                    let (pool, batch) = (&pool, counting(&items, &[]));
                    move || {
                        let _ = tx.send(pool.run(batch));
                    }
                });
                let second = rx
                    .recv_timeout(WATCHDOG)
                    .expect("the second submitter finishes without a helper");
                assert_eq!(second, Ok(()));
                assert!(once(&items));
                assert_eq!(stats(&pool).attaches, 1, "the helper joined one batch");
                gate.raise();
                assert_eq!(first.join().expect("the first submitter panicked"), Ok(()));
            });
        });
    }

    /// T7.  A helper thread the OS refuses changes speed only: the
    /// batch that meets the refusal and the ones after it give the
    /// verdicts and errors of an unrestricted pool, creation stops at
    /// the first refusal, is not tried again for the next `RETRY - 1`
    /// batches, and brings the pool to its width once the OS grants
    /// threads again.
    #[test]
    fn a_refused_helper_thread_leaves_the_caller_to_do_the_work() {
        watched(|| {
            const WIDTH: usize = 7;
            const LEN: usize = 40;
            for budget in [0usize, 1, 3] {
                let os = Os::granting(budget);
                let pool = os.pool(WIDTH);
                let verdicts = |bad: Option<usize>| {
                    let items = seen(LEN);
                    let result = pool.run(counting(&items, bad.as_slice()));
                    match bad {
                        None => {
                            assert_eq!(result, Ok(()), "budget {budget}");
                            assert!(once(&items), "budget {budget}");
                        }
                        Some(bad) => {
                            assert_eq!(result, Err(item_error(bad)), "budget {budget}");
                            assert_eq!(items[bad].load(Ordering::SeqCst), 1);
                        }
                    }
                };

                // Batch 0 meets the refusal.
                verdicts(None);
                assert_eq!(os.asked(), budget + 1, "creation stops at the refusal");
                assert_eq!(helpers(&pool), budget, "the reservations are returned");
                assert_eq!(stats(&pool).helpers_created, budget as u64);
                assert_eq!(stats(&pool).refusals, 1);

                // Batches 1 to RETRY - 1 ask for nothing.
                for round in 1..RETRY {
                    verdicts((round % 2 == 0).then_some(LEN - 1));
                    assert_eq!(os.asked(), budget + 1, "budget {budget} batch {round}");
                }

                // Batch RETRY asks again and is refused again, at once.
                verdicts(Some(0));
                assert_eq!(os.asked(), budget + 2, "budget {budget}");
                assert_eq!(helpers(&pool), budget);
                assert_eq!(stats(&pool).refusals, 2);
                for round in 1..RETRY {
                    verdicts((round % 2 == 1).then_some(LEN / 2));
                    assert_eq!(os.asked(), budget + 2, "budget {budget} batch {round}");
                }

                // The OS grants threads again: the next batch that may ask
                // brings the pool to its width.
                os.grants.store(usize::MAX, Ordering::SeqCst);
                verdicts(None);
                assert_eq!(os.asked(), budget + 2 + (WIDTH - budget));
                assert_eq!(helpers(&pool), WIDTH);
                assert_eq!(stats(&pool).helpers_created, WIDTH as u64);
                verdicts(Some(LEN - 1));
                assert_eq!(os.asked(), budget + 2 + (WIDTH - budget));
            }
        });
    }

    /// Run a batch of two items on `pool` from the calling thread, whose
    /// own item is not done before a helper is inside the other one,
    /// where the helper calls `raise` with the item's index.  `raise`
    /// panics, and what the submitter then unwinds with is returned.
    fn helper_panic(
        pool: &Pool,
        raise: impl Fn(usize) + Send + Sync + 'static,
    ) -> Box<dyn Any + Send> {
        let inside = Signal::new();
        let caller = thread::current().id();
        let batch = checks(2, move |index| {
            if thread::current().id() == caller {
                return held(&inside, 1);
            }
            inside.raise();
            raise(index);
            Err(rule_error(
                RuleErrorKind::ScriptValidation,
                "the helper's check did not panic",
            ))
        });
        catch_unwind(AssertUnwindSafe(|| pool.run(batch)))
            .expect_err("the helper's panic reaches the submitter")
    }

    std::thread_local! {
        /// The messages of the panics the panic hook was run for on
        /// this thread since [`note_hooked_panics`] was called on it.
        static HOOKED: core::cell::RefCell<Option<Vec<String>>> =
            const { core::cell::RefCell::new(None) };
    }

    /// Have the process's panic hook note, for the calling thread, the
    /// message of each panic it is run for on that thread from now on.
    /// The noting hook is installed once for the test binary and stays:
    /// it hands every panic on to the hook that was in place, so what
    /// any test prints for a panic is what it printed before.
    fn note_hooked_panics() {
        static INSTALLED: std::sync::Once = std::sync::Once::new();
        INSTALLED.call_once(|| {
            let earlier = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                let message = info.payload_as_str().unwrap_or_default().to_string();
                let _ = HOOKED.try_with(|noted| {
                    if let Ok(mut noted) = noted.try_borrow_mut()
                        && let Some(noted) = noted.as_mut()
                    {
                        noted.push(message);
                    }
                });
                earlier(info);
            }));
        });
        HOOKED.set(Some(Vec::new()));
    }

    /// T8.  A panic in a check reaches the submitter whichever thread
    /// ran the check: a helper's is raised again there with the
    /// helper's message quoted, and the pool validates afterwards with
    /// the helpers it had.  A panic on the caller stops and closes the
    /// batch and waits for the helper inside it before it goes on, as
    /// it was raised.
    #[test]
    fn a_panic_in_a_check_reaches_the_submitter() {
        watched(|| {
            let os = Os::granting(usize::MAX);
            let pool = os.pool(1);

            // On a helper: the caller's item is not done before the helper
            // is inside the other one, which then panics.
            let helper_item = Arc::new(AtomicUsize::new(usize::MAX));
            let payload = helper_panic(&pool, {
                let helper_item = Arc::clone(&helper_item);
                move |index| {
                    helper_item.store(index, Ordering::SeqCst);
                    panic!("check {index} panicked on a helper");
                }
            });
            let index = helper_item.load(Ordering::SeqCst);
            assert!(index < 2, "the helper held item {index}");
            assert_eq!(
                panic_message(&*payload),
                Some(
                    format!(
                        "a script check panicked on a pool helper: check {index} panicked on a \
                         helper"
                    )
                    .as_str()
                )
            );
            assert_eq!(queued(&pool), 0);

            // The pool validates afterwards, and the helper is the one it
            // had: it still takes an item.
            let items = seen(100);
            assert_eq!(pool.run(counting(&items, &[])), Ok(()));
            assert!(once(&items));
            assert_eq!(pool.run(all_hands(2)), Ok(()));
            assert_eq!(os.asked(), 1);
            assert_eq!(helpers(&pool), 1);

            // On the caller, with the helper held inside another item
            // and most of the batch unclaimed.
            let (inside, gate) = (Signal::new(), Signal::new());
            let helper_left = Arc::new(AtomicBool::new(false));
            let executed = Arc::new(AtomicUsize::new(0));
            let waits_before = waits(&pool);
            let (payload, helper_had_left) = thread::scope(|s| {
                let _release = Release(&gate);
                let submitter = s.spawn(|| {
                    let caller = thread::current().id();
                    let (inside, gate) = (Arc::clone(&inside), Arc::clone(&gate));
                    let left = Arc::clone(&helper_left);
                    let executed = Arc::clone(&executed);
                    let batch = checks(50, move |_| {
                        executed.fetch_add(1, Ordering::SeqCst);
                        if thread::current().id() == caller {
                            assert!(inside.wait(1), "the helper is inside its item");
                            panic!("the caller's check panicked");
                        }
                        inside.raise();
                        let result = held(&gate, 1);
                        left.store(true, Ordering::SeqCst);
                        result
                    });
                    let outcome = catch_unwind(AssertUnwindSafe(|| pool.run(batch)));
                    (outcome, helper_left.load(Ordering::SeqCst))
                });
                wait_until("the unwinding submitter waits for its helper", || {
                    waits(&pool) > waits_before || submitter.is_finished()
                });
                assert!(
                    !submitter.is_finished(),
                    "the panic left run while a helper was inside an item"
                );
                assert_eq!(queued(&pool), 0, "the batch is closed before the wait");
                gate.raise();
                let (outcome, helper_had_left) = submitter.join().expect("the submitter panicked");
                (
                    outcome.expect_err("the caller's panic goes on"),
                    helper_had_left,
                )
            });
            assert_eq!(
                panic_message(&*payload),
                Some("the caller's check panicked"),
                "the caller's own panic is the one that goes on, as it was raised"
            );
            assert!(helper_had_left, "the helper was waited for");
            assert_eq!(
                executed.load(Ordering::SeqCst),
                2,
                "the helper stopped after the item it had in hand"
            );

            let items = seen(100);
            assert_eq!(pool.run(counting(&items, &[])), Ok(()));
            assert!(once(&items));
            assert_eq!(pool.run(all_hands(2)), Ok(()));
            assert_eq!(os.asked(), 1);
        });
    }

    /// T8, by payload.  A helper's panic whose payload is its message,
    /// the `&str` of a literal or the `String` of a formatted one, is
    /// raised again on the submitter as a panic of its own that quotes
    /// the message: the panic hook is run for it on the submitting
    /// thread, which is where a test's output is collected.  A payload
    /// of any other type cannot be quoted.  It is resumed as it is, the
    /// very value, and the hook is not run a second time.
    #[test]
    fn a_helper_panic_is_raised_again_with_its_message() {
        /// A payload that is not a message.
        #[derive(Debug, PartialEq, Eq)]
        struct NotAMessage(u32);

        watched(|| {
            let pool = pool(1);
            note_hooked_panics();
            let hooked = || HOOKED.replace(Some(Vec::new())).expect("the hook's notes");

            // A literal: the payload is a `&'static str`.
            let payload = helper_panic(&pool, |_| panic!("a literal message"));
            let raised = "a script check panicked on a pool helper: a literal message";
            assert_eq!(panic_message(&*payload), Some(raised));
            assert_eq!(hooked(), [raised], "the hook ran on the submitter");

            // A formatted message: the payload is a `String`.
            let helper_item = Arc::new(AtomicUsize::new(usize::MAX));
            let payload = helper_panic(&pool, {
                let helper_item = Arc::clone(&helper_item);
                move |index| {
                    helper_item.store(index, Ordering::SeqCst);
                    panic!("formatted for item {index}");
                }
            });
            let raised = format!(
                "a script check panicked on a pool helper: formatted for item {}",
                helper_item.load(Ordering::SeqCst)
            );
            assert_eq!(panic_message(&*payload), Some(raised.as_str()));
            assert_eq!(hooked(), [raised], "the hook ran on the submitter");

            // Neither: the helper's own payload comes back.
            let payload = helper_panic(&pool, |_| std::panic::panic_any(NotAMessage(7)));
            assert_eq!(panic_message(&*payload), None);
            assert_eq!(payload.downcast_ref::<NotAMessage>(), Some(&NotAMessage(7)));
            assert_eq!(
                hooked(),
                Vec::<String>::new(),
                "a resumed payload runs no hook"
            );

            // The pool validates after each of them.
            let items = seen(100);
            assert_eq!(pool.run(counting(&items, &[])), Ok(()));
            assert!(once(&items));
            assert_eq!(pool.run(all_hands(2)), Ok(()));
            assert_eq!(helpers(&pool), 1);
            HOOKED.set(None);
        });
    }

    /// T8, beside a failure.  A batch in which a check panicked on a
    /// helper has no verdict, whatever another check of it returned:
    /// the submitter raises the panic, and a failure on record does not
    /// stand in for it.  First the case the choice of failure rests on.
    /// The pool's one helper is held inside one of the first two items
    /// while the caller fails further up and waits for it, and panics
    /// only then, so the failure on record is of a higher index than an
    /// item whose check never ended.  Then a batch of two, in which the
    /// caller's item fails once the helper is inside the other one,
    /// which panics at once: the failure and the panic come in either
    /// order, and the failure lies at either index.
    #[test]
    fn a_recorded_failure_does_not_stand_in_for_a_helper_panic() {
        fn raised(index: usize) -> String {
            format!("a script check panicked on a pool helper: check {index} panicked on a helper")
        }

        watched(|| {
            const LEN: usize = 6;
            const HIGH: usize = 4;
            let pool = pool(1);

            let (inside, gate) = (Signal::new(), Signal::new());
            let helper_item = Arc::new(AtomicUsize::new(usize::MAX));
            let waits_before = waits(&pool);
            let payload = thread::scope(|s| {
                let _release = Release(&gate);
                let submitter = s.spawn(|| {
                    let caller = thread::current().id();
                    let (inside, gate) = (Arc::clone(&inside), Arc::clone(&gate));
                    let helper_item = Arc::clone(&helper_item);
                    let batch = checks(LEN, move |index| {
                        if thread::current().id() != caller {
                            helper_item.store(index, Ordering::SeqCst);
                            inside.raise();
                            assert!(gate.wait(1), "the watchdog ended a held check");
                            panic!("check {index} panicked on a helper");
                        }
                        // The caller's first item is not done before the
                        // helper has one.
                        held(&inside, 1)?;
                        if index == HIGH {
                            Err(item_error(HIGH))
                        } else {
                            Ok(())
                        }
                    });
                    catch_unwind(AssertUnwindSafe(|| pool.run(batch)))
                });
                wait_until("the submitter waits for its helper", || {
                    waits(&pool) > waits_before || submitter.is_finished()
                });
                assert!(
                    !submitter.is_finished(),
                    "run returned while a helper was inside an item of a lower index"
                );
                // The caller stopped at the higher item's failure, which
                // is thus recorded, and the helper has yet to panic.
                gate.raise();
                submitter
                    .join()
                    .expect("the submitter panicked")
                    .expect_err("a batch with a panicked check has no verdict")
            });
            let lower = helper_item.load(Ordering::SeqCst);
            assert!(lower < 2, "the helper held item {lower}");
            assert_eq!(panic_message(&*payload), Some(raised(lower).as_str()));

            for round in 0..50 {
                let inside = Signal::new();
                let caller = thread::current().id();
                let helper_item = Arc::new(AtomicUsize::new(usize::MAX));
                let batch = checks(2, {
                    let helper_item = Arc::clone(&helper_item);
                    move |index| {
                        if thread::current().id() == caller {
                            held(&inside, 1)?;
                            return Err(item_error(index));
                        }
                        helper_item.store(index, Ordering::SeqCst);
                        inside.raise();
                        panic!("check {index} panicked on a helper");
                    }
                });
                let payload = catch_unwind(AssertUnwindSafe(|| pool.run(batch)))
                    .expect_err("a batch with a panicked check has no verdict");
                let index = helper_item.load(Ordering::SeqCst);
                assert!(index < 2, "round {round}: the helper held item {index}");
                assert_eq!(
                    panic_message(&*payload),
                    Some(raised(index).as_str()),
                    "round {round}"
                );
            }

            // The pool validates afterwards, with the helper it had.
            let items = seen(100);
            assert_eq!(pool.run(counting(&items, &[])), Ok(()));
            assert!(once(&items));
            assert_eq!(pool.run(all_hands(2)), Ok(()));
            assert_eq!(helpers(&pool), 1);
        });
    }

    /// T9.  A helper that reaches a queued batch whose every item is
    /// claimed does not join it: it takes the batch's tickets away and
    /// parks.
    #[test]
    fn an_exhausted_batch_gains_no_helper() {
        watched(|| {
            let pool = pool(1);
            let armed = Arc::new(AtomicBool::new(false));
            let (at_hook, release) = (Signal::new(), Signal::new());
            let (in_last, finish) = (Signal::new(), Signal::new());
            on_wake(&pool, {
                let armed = Arc::clone(&armed);
                let (at_hook, release) = (Arc::clone(&at_hook), Arc::clone(&release));
                move |_| {
                    if armed.load(Ordering::SeqCst) {
                        at_hook.raise();
                        release.wait(1);
                    }
                }
            });
            let _release = (Release(&release), Release(&finish));

            // The helper exists and is parked.
            assert_eq!(pool.run(counting(&seen(2), &[])), Ok(()));
            parked(&pool, 1);
            let before = stats(&pool);
            armed.store(true, Ordering::SeqCst);

            let (result, after) = thread::scope(|s| {
                let _release = (Release(&release), Release(&finish));
                let submitter = s.spawn(|| {
                    let (in_last, finish) = (Arc::clone(&in_last), Arc::clone(&finish));
                    pool.run(checks(2, move |index| {
                        if index == 1 {
                            in_last.raise();
                            return held(&finish, 1);
                        }
                        Ok(())
                    }))
                });
                // The woken helper is held before it takes the mutex, so
                // the caller claims both items and stays inside the last:
                // the batch is queued, has its ticket, and nothing to claim.
                assert!(at_hook.wait(1), "the helper was woken");
                assert!(in_last.wait(1), "the caller is inside the last item");
                assert_eq!(queued(&pool), 1);
                release.raise();
                parked(&pool, 1);
                let after = stats(&pool);
                finish.raise();
                (submitter.join().expect("the submitter panicked"), after)
            });
            assert_eq!(result, Ok(()));
            assert_eq!(after.attaches, before.attaches, "the helper did not join");
            assert_eq!(after.exhausted_skips, before.exhausted_skips + 1);
        });
    }

    /// T10.  Dropping a pool ends and joins every helper it created,
    /// parked or on its way there.
    #[test]
    fn dropping_a_pool_joins_its_helpers() {
        watched(|| {
            for settle in [false, true] {
                let os = Os::granting(usize::MAX);
                let pool = os.pool(5);
                for _ in 0..20 {
                    assert_eq!(pool.run(counting(&seen(40), &[])), Ok(()));
                }
                assert_eq!(os.asked(), 5);
                if settle {
                    parked(&pool, 5);
                }
                assert_eq!(os.exited.load(Ordering::SeqCst), 0);
                drop(pool);
                assert_eq!(os.exited.load(Ordering::SeqCst), 5, "settled: {settle}");
            }
        });
    }

    /// T11.  A pool of width zero and a batch of fewer than two items
    /// never touch the pool: every check runs on the caller, no batch is
    /// queued and no thread is asked for.
    #[test]
    fn width_zero_and_single_items_stay_on_the_caller() {
        watched(|| {
            let caller = thread::current().id();
            for (width, lens) in [(0, &[0usize, 1, 2, 16, 100][..]), (15, &[0, 1][..])] {
                let os = Os::granting(usize::MAX);
                let pool = os.pool(width);
                assert_eq!(pool.width(), width);
                for &len in lens {
                    let items = seen(len);
                    let elsewhere = Arc::new(AtomicUsize::new(0));
                    let batch = checks(len, {
                        let (items, elsewhere) = (Arc::clone(&items), Arc::clone(&elsewhere));
                        move |index| {
                            items[index].fetch_add(1, Ordering::SeqCst);
                            if thread::current().id() != caller {
                                elsewhere.fetch_add(1, Ordering::SeqCst);
                            }
                            Ok(())
                        }
                    });
                    assert_eq!(pool.run(batch), Ok(()), "width {width} len {len}");
                    assert!(once(&items), "width {width} len {len}");
                    assert_eq!(elsewhere.load(Ordering::SeqCst), 0);
                }
                assert_eq!(os.asked(), 0, "width {width}");
                assert_eq!(stats(&pool).batches, 0, "width {width}");
                assert_eq!(helpers(&pool), 0, "width {width}");
            }
        });
    }

    /// T12.  Helpers are created once: however many batches follow, the
    /// pool holds as many as the widest batch wanted, at most its width.
    #[test]
    fn helpers_are_created_once() {
        watched(|| {
            for (width, len, want) in [(15, 100, 15), (3, 100, 3), (15, 5, 4)] {
                let os = Os::granting(usize::MAX);
                let pool = os.pool(width);
                for round in 0..1_000 {
                    assert_eq!(pool.run(counting(&seen(len), &[])), Ok(()));
                    assert_eq!(os.asked(), want, "width {width} len {len} round {round}");
                }
                assert_eq!(stats(&pool).helpers_created, want as u64);
                assert_eq!(helpers(&pool), want);
                assert_eq!(stats(&pool).refusals, 0);
            }
        });
    }

    /// T13.  A parked helper is woken by the batch that wants it: the
    /// caller's item does not finish before another thread has checked
    /// the other one.
    #[test]
    fn a_parked_helper_is_woken() {
        watched(|| {
            let pool = pool(1);
            assert_eq!(pool.run(counting(&seen(2), &[])), Ok(()));
            parked(&pool, 1);
            let caller = thread::current().id();
            let elsewhere = Signal::new();
            let batch = checks(2, {
                let elsewhere = Arc::clone(&elsewhere);
                move |_| {
                    if thread::current().id() == caller {
                        return held(&elsewhere, 1);
                    }
                    elsewhere.raise();
                    Ok(())
                }
            });
            assert_eq!(pool.run(batch), Ok(()));
            assert_eq!(helpers(&pool), 1);
        });
    }

    /// T14.  A batch offers one ticket for every item but the caller's
    /// first, at most the pool's width, and none when it has fewer than
    /// two items.
    #[test]
    fn tickets_follow_the_batch_and_the_machine() {
        watched(|| {
            for (width, len, tickets) in [
                (15, 0, 0u64),
                (15, 1, 0),
                (15, 2, 1),
                (15, 5, 4),
                (15, 15, 14),
                (15, 16, 15),
                (15, 17, 15),
                (15, 100, 15),
                (3, 100, 3),
                (3, 3, 2),
            ] {
                let pool = pool(width);
                let items = seen(len);
                assert_eq!(pool.run(counting(&items, &[])), Ok(()));
                assert!(once(&items));
                let stats = stats(&pool);
                assert_eq!(stats.tickets, tickets, "width {width} len {len}");
                assert_eq!(stats.batches, u64::from(tickets > 0));
                assert!(stats.attaches <= tickets, "width {width} len {len}");
                assert_eq!(stats.overdrawn, 0, "width {width} len {len}");
                assert!(helpers(&pool) as u64 <= tickets);
            }
        });
    }

    /// T14, on the queued batch itself: its entry holds one ticket for
    /// each helper it wants, and every helper that joins takes one.
    /// The helpers the batch wakes are held before they can look at the
    /// queue while the entry is read, then let go to join.
    #[test]
    fn a_queued_batch_holds_its_tickets() {
        watched(|| {
            const WIDTH: usize = 3;
            let pool = pool(WIDTH);
            let armed = Arc::new(AtomicBool::new(false));
            let (at_hook, release) = (Signal::new(), Signal::new());
            on_wake(&pool, {
                let armed = Arc::clone(&armed);
                let (at_hook, release) = (Arc::clone(&at_hook), Arc::clone(&release));
                move |_| {
                    if armed.load(Ordering::SeqCst) {
                        at_hook.raise();
                        release.wait(1);
                    }
                }
            });
            assert_eq!(pool.run(all_hands(WIDTH + 1)), Ok(()));
            parked(&pool, WIDTH);
            let before = stats(&pool);
            armed.store(true, Ordering::SeqCst);

            let tickets = |pool: &Pool| {
                let st = pool.inner.state.lock().expect("pool state poisoned");
                st.queue.front().map(|entry| entry.tickets)
            };
            let (inside, finish) = (Signal::new(), Signal::new());
            let result = thread::scope(|s| {
                let _release = (Release(&release), Release(&finish));
                let submitter = s.spawn(|| {
                    let (inside, finish) = (Arc::clone(&inside), Arc::clone(&finish));
                    // Three items: two tickets, on a pool of three.
                    pool.run(checks(3, move |_| {
                        inside.raise();
                        held(&finish, 1)
                    }))
                });
                // The two helpers the batch woke are held before the
                // mutex, so the entry still has both tickets.
                assert!(at_hook.wait(2), "two helpers were woken");
                assert!(inside.wait(1), "the caller is inside an item");
                assert_eq!(tickets(&pool), Some(2));
                release.raise();
                // Both join and each is inside an item: no ticket is left.
                assert!(inside.wait(3), "every item is claimed");
                assert_eq!(tickets(&pool), Some(0));
                let after = stats(&pool);
                assert_eq!(after.attaches, before.attaches + 2);
                assert_eq!(after.overdrawn, 0);
                finish.raise();
                submitter.join().expect("the submitter panicked")
            });
            assert_eq!(result, Ok(()));
        });
    }

    /// T15.  With every helper parked, a batch that wants one helper
    /// wakes the one that parked last.
    #[test]
    fn the_most_recently_parked_helper_is_woken_first() {
        watched(|| {
            const WIDTH: usize = 4;
            let pool = pool(WIDTH);
            assert_eq!(pool.run(all_hands(WIDTH + 1)), Ok(()));
            parked(&pool, WIDTH);
            let stack = idle(&pool);
            pool.inner
                .state
                .lock()
                .expect("pool state poisoned")
                .stats
                .idle_order = Some(Vec::new());
            assert_eq!(pool.run(counting(&seen(2), &[])), Ok(()));
            let order = stats(&pool).idle_order.expect("the order was recorded");
            assert_eq!(order.first(), Some(&IdleEvent::Popped(stack[WIDTH - 1])));
            let pops = order
                .iter()
                .filter(|event| matches!(event, IdleEvent::Popped(_)))
                .count();
            assert_eq!(pops, 1, "{order:?}");
        });
    }

    /// T16.  The submitter waits for the helpers that joined its batch,
    /// not for the ones it woke: with every woken helper held before it
    /// can look at the queue, `run` returns, and the helpers, let go,
    /// find nothing and park.
    #[test]
    fn a_helper_that_has_not_attached_does_not_delay_the_submitter() {
        watched(|| {
            const WIDTH: usize = 3;
            let pool = Arc::new(pool(WIDTH));
            let armed = Arc::new(AtomicBool::new(false));
            let (at_hook, release) = (Signal::new(), Signal::new());
            on_wake(&pool, {
                let armed = Arc::clone(&armed);
                let (at_hook, release) = (Arc::clone(&at_hook), Arc::clone(&release));
                move |_| {
                    if armed.load(Ordering::SeqCst) {
                        at_hook.raise();
                        release.wait(1);
                    }
                }
            });
            let _release = Release(&release);

            assert_eq!(pool.run(all_hands(WIDTH + 1)), Ok(()));
            parked(&pool, WIDTH);
            let before = stats(&pool);
            armed.store(true, Ordering::SeqCst);

            // On a thread of its own, so that a submitter that never
            // returns fails the test instead of hanging it.
            let items = seen(WIDTH + 1);
            let (tx, rx) = mpsc::channel();
            thread::spawn({
                let (pool, batch) = (Arc::clone(&pool), counting(&items, &[]));
                move || {
                    let _ = tx.send(pool.run(batch));
                }
            });
            let result = rx
                .recv_timeout(WATCHDOG)
                .expect("run returns while the helpers it woke are held");
            assert_eq!(result, Ok(()));
            assert!(once(&items));
            assert!(at_hook.wait(WIDTH), "every helper was woken and is held");
            assert_eq!(idle(&pool), Vec::<usize>::new());
            assert_eq!(stats(&pool).attaches, before.attaches);

            release.raise();
            parked(&pool, WIDTH);
            assert_eq!(stats(&pool).attaches, before.attaches);
            assert_eq!(queued(&pool), 0);
        });
    }

    /// T17.  A wake that no submitter sent leaves each helper on the
    /// stack of parked helpers once, and the next batch wakes every one
    /// of them.
    #[test]
    fn a_stray_wake_leaves_the_idle_stack_without_duplicates() {
        watched(|| {
            const WIDTH: usize = 3;
            let pool = pool(WIDTH);
            assert_eq!(pool.run(all_hands(WIDTH + 1)), Ok(()));
            parked(&pool, WIDTH);

            for at in [0, WIDTH - 1, 1] {
                let pushes = stats(&pool).idle_pushes;
                let stray = {
                    let st = pool.inner.state.lock().expect("pool state poisoned");
                    st.idle.get(at).map(|(_, thread)| thread.clone())
                };
                stray.expect("a parked helper").unpark();
                wait_until("the helper has parked again", || {
                    stats(&pool).idle_pushes == pushes + 1
                });
                let mut stack = idle(&pool);
                assert_eq!(stack.len(), WIDTH, "{stack:?}");
                stack.sort_unstable();
                stack.dedup();
                assert_eq!(stack.len(), WIDTH, "a helper is on the stack twice");
            }

            // Every helper takes an item of the next batch.
            assert_eq!(pool.run(all_hands(WIDTH + 1)), Ok(()));
        });
    }

    /// The process-wide pool is one helper narrower than the machine,
    /// and its helpers are the threads named `scriptval-N`.
    #[test]
    fn the_process_wide_pool_is_one_helper_short_of_the_cpus() {
        watched(|| {
            let cpus = thread::available_parallelism().map_or(1, |n| n.get());
            let pool = Pool::global();
            assert_eq!(pool.width(), cpus - 1);
            assert!(core::ptr::eq(pool, Pool::global()));

            let threads = pool.width().min(3) + 1;
            let caller: ThreadId = thread::current().id();
            let names = Arc::new(Mutex::new(Vec::new()));
            let arrived = Signal::new();
            let batch = checks(threads, {
                let names = Arc::clone(&names);
                move |_| {
                    if thread::current().id() != caller {
                        let name = thread::current().name().map(str::to_owned);
                        names.lock().expect("names poisoned").push(name);
                    }
                    arrived.raise();
                    held(&arrived, threads)
                }
            });
            assert_eq!(pool.run(batch), Ok(()));
            let mut names = names.lock().expect("names poisoned").clone();
            assert_eq!(names.len(), threads - 1);
            for name in &names {
                let number = name.as_deref().and_then(|n| n.strip_prefix("scriptval-"));
                assert!(
                    number.is_some_and(|n| n.parse::<usize>().is_ok()),
                    "{name:?}"
                );
            }
            names.sort();
            names.dedup();
            assert_eq!(names.len(), threads - 1, "one item per helper");
        });
    }
}
