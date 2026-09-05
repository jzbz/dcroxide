// SPDX-License-Identifier: ISC
//! The getwork semaphore and the per-request cancellation it waits on
//! (dcrd's `workState.workSem`, `internal/rpcserver/rpcserver.go:568`,
//! `makeSemaphore(1)` at `:595`).
//!
//! dcrd queues on the semaphore with a `select` that also watches the
//! request context:
//!
//! ```go
//! select {
//! case s.workState.workSem <- struct{}{}:
//! case <-ctx.Done():
//!     return nil, rpcConnectionClosedError()
//! }
//! defer s.workState.workSem.release()
//! ```
//!
//! so a client that hangs up while queued gives up its place rather than
//! holding it until the permit comes free.  A plain `Mutex` cannot wait
//! on two conditions, which is why this is a condvar semaphore rather
//! than the mutex it replaces.
//!
//! The cancellation signal reaches the handler through a thread-local
//! rather than a parameter.  Every RPC handler takes `(server, cmd)` —
//! there are 77 of them — and threading a token through all of them to
//! serve one call site would be far more disruptive than the property is
//! worth.  A thread-local is sound here because the transport serves each
//! connection on its own thread and processes one request at a time on
//! it, so "the request this thread is running" is well defined.  The
//! guard returned by [`scope_request_cancel`] clears the slot on every
//! exit path, including an unwinding panic, so a token can never leak
//! into an unrelated later request on a reused thread.

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// How often a waiter re-checks the cancellation flag.  A queued waiter
/// is otherwise woken by the permit's release, so this only bounds how
/// long a *cancelled* waiter lingers, and never delays a normal handoff.
/// The template waits inside the hold poll on the same interval, so the
/// two halves of dcrd's cancellation respond alike.
pub const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(50);

thread_local! {
    /// The cancellation flag for the request this thread is serving, if
    /// the transport installed one.  `None` means nothing can cancel —
    /// the in-process test harnesses and any caller that drives handlers
    /// directly — and a waiter then simply blocks until the permit is
    /// free, which is the behaviour this replaced.
    static REQUEST_CANCEL: RefCell<Option<Arc<AtomicBool>>> = const { RefCell::new(None) };
}

/// Clears the thread's cancellation slot when dropped.
pub struct RequestCancelGuard {
    previous: Option<Arc<AtomicBool>>,
}

impl Drop for RequestCancelGuard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        // A panicking handler still restores the slot; `with` on a
        // destructed thread-local would panic during unwind, so a failed
        // access is ignored rather than escalating to an abort.
        let _ = REQUEST_CANCEL.try_with(|slot| {
            *slot.borrow_mut() = previous;
        });
    }
}

/// Install `flag` as the cancellation signal for the request this thread
/// is about to serve.  The returned guard restores the previous value.
pub fn scope_request_cancel(flag: Arc<AtomicBool>) -> RequestCancelGuard {
    let previous = REQUEST_CANCEL.with(|slot| slot.borrow_mut().replace(flag));
    RequestCancelGuard { previous }
}

/// Whether the request this thread is serving has been cancelled.
///
/// Read by [`WorkSem::acquire`] before it queues, and by the template
/// waits that run while the permit is *held* -- dcrd cancels in all
/// three places (`rpcserver.go:4170-4174`, `:3914`, `:3932`), and a
/// signal the holder never reads would leave the permit pinned for the
/// rest of a wait the client is no longer listening to.
pub fn request_cancelled() -> bool {
    REQUEST_CANCEL.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire))
    })
}

/// Whether anything at all can cancel the work this thread is doing.
///
/// `false` means no token was installed -- the CPU miner's generator
/// thread, the in-process test harnesses, any caller driving handlers
/// directly -- and a waiter should then block outright rather than wake
/// periodically to re-read a flag that cannot change.  dcrd's
/// equivalent is a `context.Background()` whose `Done()` channel is nil
/// and so never selects.
pub fn request_is_cancellable() -> bool {
    REQUEST_CANCEL.with(|slot| slot.borrow().is_some())
}

/// A single-permit semaphore whose queue can be abandoned (dcrd
/// `workState.workSem`, a `makeSemaphore(1)` selected against
/// `ctx.Done()`).
pub struct WorkSem {
    taken: Mutex<bool>,
    bell: Condvar,
}

impl WorkSem {
    /// A semaphore with its single permit free.
    pub fn new() -> WorkSem {
        WorkSem {
            taken: Mutex::new(false),
            bell: Condvar::new(),
        }
    }

    /// Take the permit, giving up if the request is cancelled while
    /// queued.  `None` means cancelled, which the caller reports as
    /// dcrd's `rpcConnectionClosedError`.
    ///
    /// The flag is checked before waiting at all, so a request whose
    /// client left before it reached here never joins the queue.
    pub fn acquire(&self) -> Option<WorkPermit<'_>> {
        let mut taken = self
            .taken
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            if request_cancelled() {
                return None;
            }
            if !*taken {
                *taken = true;
                return Some(WorkPermit { sem: self });
            }
            let (guard, _) = self
                .bell
                .wait_timeout(taken, CANCEL_POLL_INTERVAL)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            taken = guard;
        }
    }
}

impl Default for WorkSem {
    fn default() -> WorkSem {
        WorkSem::new()
    }
}

/// The held permit; releasing it on drop covers every exit path from the
/// handler, as dcrd's `defer s.workState.workSem.release()` does.
pub struct WorkPermit<'a> {
    sem: &'a WorkSem,
}

impl Drop for WorkPermit<'_> {
    fn drop(&mut self) {
        *self
            .sem
            .taken
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = false;
        // `notify_all` rather than `notify_one`: a cancelled waiter
        // returns without taking the permit and without notifying
        // anyone, so waking only one could hand the wakeup to a waiter
        // that is about to give up and leave a live one asleep until its
        // next poll tick.  The permit is single, so the extra wakeups
        // cost one re-check each.
        self.sem.bell.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;

    /// The permit is exclusive: a second acquire waits for the first to
    /// be dropped.  This is the property `work_sem` exists for — dcrd
    /// serializes whole getwork invocations, requests and submissions
    /// alike, through one semaphore item.
    #[test]
    fn the_permit_is_exclusive() {
        let sem = Arc::new(WorkSem::new());
        let held = sem.acquire().expect("first permit");

        let other = Arc::clone(&sem);
        let (tx, rx) = mpsc::channel();
        let waiter = thread::spawn(move || {
            let permit = other.acquire();
            let _ = tx.send(permit.is_some());
        });

        assert!(
            rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "the second acquire must wait while the permit is held"
        );
        drop(held);
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)),
            Ok(true),
            "the second acquire must succeed once the permit is released"
        );
        waiter.join().expect("waiter");
    }

    /// A queued waiter whose request is cancelled gives up its place
    /// instead of holding the thread until the permit frees — dcrd's
    /// `case <-ctx.Done()` arm.  The permit is never released here, so
    /// without the cancellation arm this would block forever.
    #[test]
    fn a_cancelled_request_abandons_the_queue() {
        let sem = Arc::new(WorkSem::new());
        let _held = sem.acquire().expect("first permit");

        let flag = Arc::new(AtomicBool::new(false));
        let other = Arc::clone(&sem);
        let waiter_flag = Arc::clone(&flag);
        let (tx, rx) = mpsc::channel();
        let waiter = thread::spawn(move || {
            let _cancel = scope_request_cancel(waiter_flag);
            let permit = other.acquire();
            let _ = tx.send(permit.is_some());
        });

        assert!(
            rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "the waiter must be queued while the permit is held"
        );
        flag.store(true, Ordering::Release);
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)),
            Ok(false),
            "a cancelled waiter must return None rather than wait for the permit"
        );
        waiter.join().expect("waiter");
    }

    /// A request already cancelled before it reaches the semaphore never
    /// joins the queue at all, even though the permit is held.
    #[test]
    fn an_already_cancelled_request_never_queues() {
        let sem = WorkSem::new();
        let _held = sem.acquire().expect("first permit");

        let flag = Arc::new(AtomicBool::new(true));
        let _cancel = scope_request_cancel(flag);
        assert!(
            sem.acquire().is_none(),
            "an already-cancelled request must not queue"
        );
    }

    /// The guard restores the previous slot, so a token cannot leak into
    /// a later request served on the same thread.
    #[test]
    fn the_cancel_scope_does_not_leak_across_requests() {
        let flag = Arc::new(AtomicBool::new(true));
        {
            let _cancel = scope_request_cancel(flag);
            assert!(request_cancelled(), "in scope the request is cancelled");
        }
        assert!(
            !request_cancelled(),
            "out of scope nothing cancels the thread's next request"
        );
    }
}
