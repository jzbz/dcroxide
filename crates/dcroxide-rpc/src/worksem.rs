// SPDX-License-Identifier: ISC
//! The getwork semaphore and the per-request cancellation it waits on
//! (dcrd's `workState.workSem`, `internal/rpcserver/rpcserver.go:571`,
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
//! The queue is first come, first served, as the channel's is.  The
//! semaphore is a buffered channel of capacity one
//! (`rpcwebsocket.go:60-67`): a blocked sender waits in the channel's
//! send queue, and the receive that releases the permit completes the
//! sender at the head of that queue directly, so a request arriving at
//! that moment cannot overtake one that was already waiting.  A waiter
//! whose `select` has already taken the `ctx.Done()` arm is passed over.
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
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
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

/// The cancellation flag of the request this thread is serving, if any.
fn request_cancel_flag() -> Option<Arc<AtomicBool>> {
    REQUEST_CANCEL.with(|slot| slot.borrow().clone())
}

/// A single-permit semaphore whose queue can be abandoned (dcrd
/// `workState.workSem`, a `makeSemaphore(1)` selected against
/// `ctx.Done()`), serving its waiters in arrival order.
pub struct WorkSem {
    state: Mutex<SemState>,
    bell: Condvar,
}

/// The permit and the waiters queued for it.
struct SemState {
    /// Whether the permit is held, including while a release has handed
    /// it to a waiter that has not yet woken to claim it.  It is free
    /// only when nobody is queued.
    taken: bool,
    /// The waiters in arrival order (the channel's send queue).
    queue: VecDeque<Waiter>,
    /// The waiter a release handed the permit to, until it claims it.
    handed_to: Option<u64>,
    /// The id the next waiter queues under.
    next_id: u64,
}

/// One queued acquire.
struct Waiter {
    id: u64,
    /// The waiter's cancellation flag, which the release reads so the
    /// handoff passes over a waiter that has already given up.
    cancel: Option<Arc<AtomicBool>>,
}

impl WorkSem {
    /// A semaphore with its single permit free.
    pub fn new() -> WorkSem {
        WorkSem {
            state: Mutex::new(SemState {
                taken: false,
                queue: VecDeque::new(),
                handed_to: None,
                next_id: 0,
            }),
            bell: Condvar::new(),
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, SemState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Take the permit, giving up if the request is cancelled while
    /// queued.  `None` means cancelled, which the caller reports as
    /// dcrd's `rpcConnectionClosedError`.
    ///
    /// The flag is checked before waiting at all, so a request whose
    /// client left before it reached here never joins the queue.  A
    /// waiter the permit was handed to takes it even if its flag is set
    /// by the time it wakes: the handoff came first, as a completed
    /// channel send wins its `select`.
    pub fn acquire(&self) -> Option<WorkPermit<'_>> {
        let mut state = self.lock_state();
        if request_cancelled() {
            return None;
        }
        // A free permit means nobody is queued, so it is taken at once,
        // as a send on a channel with room completes without blocking.
        if !state.taken {
            state.taken = true;
            return Some(WorkPermit { sem: self });
        }

        let id = state.next_id;
        state.next_id = state.next_id.wrapping_add(1);
        state.queue.push_back(Waiter {
            id,
            cancel: request_cancel_flag(),
        });
        loop {
            let (guard, _) = self
                .bell
                .wait_timeout(state, CANCEL_POLL_INTERVAL)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = guard;
            if state.handed_to == Some(id) {
                state.handed_to = None;
                return Some(WorkPermit { sem: self });
            }
            if request_cancelled() {
                // Leave the queue; a release that already saw the flag
                // has taken this waiter out of it.
                state.queue.retain(|w| w.id != id);
                return None;
            }
        }
    }

    /// The number of queued waiters.
    #[cfg(test)]
    fn queued(&self) -> usize {
        self.lock_state().queue.len()
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
        {
            // Hand the permit straight to the longest-queued waiter still
            // live, as the channel receive completes the sender at the
            // head of the send queue; it stays taken, so nothing arriving
            // now can overtake that waiter.  A waiter whose flag is set
            // has given up and is passed over; it returns `None` when it
            // wakes.  The permit comes free only when nobody live is
            // queued.
            let mut state = self.sem.lock_state();
            loop {
                match state.queue.pop_front() {
                    Some(waiter)
                        if waiter
                            .cancel
                            .as_ref()
                            .is_some_and(|flag| flag.load(Ordering::Acquire)) => {}
                    Some(waiter) => {
                        state.handed_to = Some(waiter.id);
                        break;
                    }
                    None => {
                        state.taken = false;
                        break;
                    }
                }
            }
        }
        // `notify_all` rather than `notify_one`: the condvar has no way to
        // wake the one waiter the permit went to, and the waiters passed
        // over should see promptly that they are out of the queue.  The
        // permit is single, so the extra wakeups cost one re-check each.
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

    /// Poll until `cond` holds, failing after five seconds.
    fn wait_until(cond: impl Fn() -> bool) {
        let start = std::time::Instant::now();
        while !cond() {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "condition never held"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }

    /// Waiters are served in arrival order, and a request arriving as the
    /// permit is released queues behind them rather than taking it:
    /// dcrd's channel semaphore hands the freed slot to the head of its
    /// send queue.  A release that only freed the permit and woke every
    /// waiter let the releasing thread's own next acquire win the race
    /// ahead of both waiters.
    #[test]
    fn waiters_are_served_in_arrival_order() {
        let sem = Arc::new(WorkSem::new());
        let order = Arc::new(Mutex::new(Vec::new()));
        let held = sem.acquire().expect("first permit");

        let mut waiters = Vec::new();
        for (label, queued) in [("first", 1), ("second", 2)] {
            let sem2 = Arc::clone(&sem);
            let order2 = Arc::clone(&order);
            waiters.push(thread::spawn(move || {
                let permit = sem2.acquire().expect("waiter permit");
                order2.lock().expect("order").push(label);
                thread::sleep(Duration::from_millis(20));
                drop(permit);
            }));
            wait_until(|| sem.queued() == queued);
        }

        drop(held);
        let permit = sem.acquire().expect("newcomer permit");
        order.lock().expect("order").push("newcomer");
        drop(permit);
        for waiter in waiters {
            waiter.join().expect("waiter");
        }
        assert_eq!(
            *order.lock().expect("order"),
            vec!["first", "second", "newcomer"]
        );
    }

    /// The handoff passes over a queued waiter whose request was
    /// cancelled, as the channel receive skips a sender whose `select`
    /// already took `ctx.Done()`; the next live waiter gets the permit
    /// and the cancelled one gives up.
    #[test]
    fn the_handoff_passes_over_a_cancelled_waiter() {
        let sem = Arc::new(WorkSem::new());
        let held = sem.acquire().expect("first permit");
        let (tx, rx) = mpsc::channel();

        let flag = Arc::new(AtomicBool::new(false));
        let cancelled = {
            let sem = Arc::clone(&sem);
            let flag = Arc::clone(&flag);
            let tx = tx.clone();
            thread::spawn(move || {
                let _cancel = scope_request_cancel(flag);
                let permit = sem.acquire();
                let _ = tx.send(("cancelled", permit.is_some()));
            })
        };
        wait_until(|| sem.queued() == 1);
        let live = {
            let sem = Arc::clone(&sem);
            thread::spawn(move || {
                let _cancel = scope_request_cancel(Arc::new(AtomicBool::new(false)));
                let permit = sem.acquire();
                let _ = tx.send(("live", permit.is_some()));
            })
        };
        wait_until(|| sem.queued() == 2);

        flag.store(true, Ordering::Release);
        drop(held);
        let mut results = [
            rx.recv_timeout(Duration::from_secs(5)).expect("result"),
            rx.recv_timeout(Duration::from_secs(5)).expect("result"),
        ];
        results.sort_unstable();
        assert_eq!(results, [("cancelled", false), ("live", true)]);
        cancelled.join().expect("cancelled waiter");
        live.join().expect("live waiter");

        assert!(sem.acquire().is_some(), "the permit is free again");
        assert_eq!(sem.queued(), 0, "nobody is left queued");
    }
}
