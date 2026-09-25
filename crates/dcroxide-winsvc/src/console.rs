// SPDX-License-Identifier: ISC
//! The console control handler: a console close, logoff or shutdown
//! requests the daemon's graceful shutdown and holds the process until
//! the daemon has finished it, as Go's runtime holds dcrd.
//!
//! Windows ends a console process once a control handler returns TRUE
//! for `CTRL_CLOSE_EVENT`, `CTRL_LOGOFF_EVENT` or `CTRL_SHUTDOWN_EVENT`,
//! or once the grace period the system allows for the event runs out.
//! Go's runtime maps the three to SIGTERM and then blocks in its handler
//! (`runtime/os_windows.go` `ctrlHandler`), so dcrd's `shutdownListener`,
//! which takes SIGTERM on Windows too (`signal_syscall.go`), runs the
//! whole graceful shutdown inside that grace period and exits through
//! `main`.  ctrlc's handler, which serves the daemon's Ctrl-C, returns
//! TRUE for every event at once, so the process used to be ended before
//! its shutdown had begun, and the final UTXO and metadata flushes never
//! ran.
//!
//! Windows asks the most recently registered handler first, and the
//! daemon registers this one after ctrlc's.  For the three events it
//! runs the daemon's [`Terminate`] hook, which logs and requests the
//! graceful shutdown as SIGTERM does in dcrd, then waits until the
//! daemon reports through [`shutdown_complete`] that it has shut down,
//! and only then returns TRUE.  Ctrl-C and Ctrl-Break (Go's SIGINT) it
//! passes on with FALSE, so ctrlc keeps serving them as before.

use std::sync::{Condvar, Mutex, OnceLock, PoisonError};
use std::time::Duration;

/// What a console close, logoff or shutdown event does before the
/// handler waits: the daemon's reaction to Go's SIGTERM, which dcrd's
/// `shutdownListener` logs as `Received signal (terminated)` before it
/// cancels the daemon context.  It runs on the thread Windows creates
/// for the event.
pub type Terminate = Box<dyn Fn() + Send + Sync>;

/// The longest the handler holds a close, logoff or shutdown event
/// waiting for the daemon to finish.
///
/// Go's handler blocks for good.  This one gives up, so that a shutdown
/// that has hung cannot hold the process forever where the system sets
/// no deadline of its own.  It outlasts the grace periods Windows allows
/// by default, five seconds for a console close and at most twenty for
/// logoff and shutdown (`WaitToKillAppTimeout`,
/// `WaitToKillServiceTimeout`), so wherever the system does set one, a
/// slow shutdown is ended by the system's deadline, as dcrd's is, and
/// not early by this one, unless those timeouts were raised past it.
pub const SHUTDOWN_WAIT: Duration = Duration::from_secs(30);

const _: () = assert!(SHUTDOWN_WAIT.as_secs() > 20);

// The console control event numbers (`wincon.h`), which Windows passes
// to the handler.  On Windows they are checked against `windows-sys`'s
// at compile time.
const CTRL_C_EVENT: u32 = 0;
const CTRL_BREAK_EVENT: u32 = 1;
const CTRL_CLOSE_EVENT: u32 = 2;
const CTRL_LOGOFF_EVENT: u32 = 5;
const CTRL_SHUTDOWN_EVENT: u32 = 6;

/// Both sides of the handshake: the daemon's [`Terminate`] hook, and the
/// latch the daemon sets through [`shutdown_complete`] once it has shut
/// down, which releases a held event.
struct Handshake {
    terminate: Terminate,
    complete: Mutex<bool>,
    completed: Condvar,
}

impl Handshake {
    fn new(terminate: Terminate) -> Handshake {
        Handshake {
            terminate,
            complete: Mutex::new(false),
            completed: Condvar::new(),
        }
    }

    /// Handle one console control event as the registered routine does,
    /// holding a close, logoff or shutdown for at most `bound`: true
    /// when the event is handled (the routine's TRUE, after which
    /// Windows ends the process), false to pass it to the next handler.
    fn on_event(&self, ctrl_type: u32, bound: Duration) -> bool {
        match ctrl_type {
            CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => {
                (self.terminate)();
                self.wait_complete(bound);
                true
            }
            // Go's SIGINT, which ctrlc's handler serves.
            CTRL_C_EVENT | CTRL_BREAK_EVENT => false,
            // No other event is defined; Go's handler passes it on too.
            _ => false,
        }
    }

    /// Set the latch and release every held event.
    fn complete(&self) {
        *self.complete.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.completed.notify_all();
    }

    /// Wait until the latch is set, for at most `bound`; whether it was.
    fn wait_complete(&self, bound: Duration) -> bool {
        let complete = self.complete.lock().unwrap_or_else(PoisonError::into_inner);
        let (complete, _) = self
            .completed
            .wait_timeout_while(complete, bound, |complete| !*complete)
            .unwrap_or_else(PoisonError::into_inner);
        *complete
    }
}

/// The handshake the registered routine reaches; Windows passes the
/// routine nothing but the event number, so it rides a global, set once.
static HANDSHAKE: OnceLock<Handshake> = OnceLock::new();

/// Register the console control handler (Windows) with the daemon's
/// reaction to a close, logoff or shutdown event.  Register it after
/// ctrlc's handler, so that Windows asks it first.  Off Windows there
/// are no console control events, and nothing is registered.
///
/// A second call fails with `AlreadyExists`.
pub fn install_console_handler(terminate: Terminate) -> std::io::Result<()> {
    if HANDSHAKE.set(Handshake::new(terminate)).is_err() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "the console control handler is already installed",
        ));
    }
    imp::register()
}

/// Report that the daemon has shut down, releasing a close, logoff or
/// shutdown event the handler holds so that it returns TRUE, and making
/// any later one return TRUE without waiting.  The daemon calls it at
/// the end of `main`, once the block database is closed and the rest of
/// its shutdown has run.
pub fn shutdown_complete() {
    if let Some(handshake) = HANDSHAKE.get() {
        handshake.complete();
    }
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::Foundation::{FALSE, TRUE};
    use windows_sys::Win32::System::Console::{self as console, SetConsoleCtrlHandler};
    use windows_sys::core::BOOL;

    const _: () = assert!(
        super::CTRL_C_EVENT == console::CTRL_C_EVENT
            && super::CTRL_BREAK_EVENT == console::CTRL_BREAK_EVENT
            && super::CTRL_CLOSE_EVENT == console::CTRL_CLOSE_EVENT
            && super::CTRL_LOGOFF_EVENT == console::CTRL_LOGOFF_EVENT
            && super::CTRL_SHUTDOWN_EVENT == console::CTRL_SHUTDOWN_EVENT
    );

    /// The handler routine (a `PHANDLER_ROUTINE`), which Windows runs on
    /// a thread it creates for each event.
    extern "system" fn handler_routine(ctrl_type: u32) -> BOOL {
        let handled = super::HANDSHAKE
            .get()
            .is_some_and(|handshake| handshake.on_event(ctrl_type, super::SHUTDOWN_WAIT));
        if handled { TRUE } else { FALSE }
    }

    pub(super) fn register() -> std::io::Result<()> {
        // SAFETY: the call takes a flag and one pointer, to
        // `handler_routine`: a function linked statically into the
        // binary, so it stays valid for the life of the process, with
        // exactly the `PHANDLER_ROUTINE` signature and ABI Windows calls
        // it through (the type checks that).  Windows may run it on any
        // thread, at any time after this call, several at once: it reads
        // only `HANDSHAKE`, a `OnceLock` set before this call and never
        // changed, whose contents are `Sync` (a `Send + Sync` hook, a
        // mutex and a condition variable).  A panic inside it cannot
        // unwind into Windows: it aborts at the `extern "system"`
        // boundary.  Registration is never undone, so nothing it reaches
        // is freed while Windows can still call it.
        #[allow(unsafe_code)]
        let registered = unsafe { SetConsoleCtrlHandler(Some(handler_routine), TRUE) };
        if registered == FALSE {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(not(windows))]
mod imp {
    /// No console control events arrive off Windows.
    pub(super) fn register() -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Instant;

    /// A handshake whose hook counts its calls.
    fn counting() -> (Arc<Handshake>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let hook = Arc::clone(&calls);
        let handshake = Arc::new(Handshake::new(Box::new(move || {
            hook.fetch_add(1, Ordering::SeqCst);
        })));
        (handshake, calls)
    }

    /// A close, logoff or shutdown requests the shutdown, then holds
    /// the event until the daemon reports it has shut down, and only
    /// then returns TRUE (Go's handler blocking after its SIGTERM),
    /// where ctrlc returned at once and Windows ended the process.
    #[test]
    fn close_logoff_and_shutdown_wait_for_the_daemon() {
        for event in [CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT] {
            let requested = Arc::new(AtomicBool::new(false));
            let hook = Arc::clone(&requested);
            let handshake = Arc::new(Handshake::new(Box::new(move || {
                hook.store(true, Ordering::SeqCst);
            })));

            // The daemon: shut down once the request arrives, taking a
            // while about it, then report.
            let finished = Arc::new(AtomicBool::new(false));
            let daemon = {
                let handshake = Arc::clone(&handshake);
                let requested = Arc::clone(&requested);
                let finished = Arc::clone(&finished);
                std::thread::spawn(move || {
                    while !requested.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    std::thread::sleep(Duration::from_millis(200));
                    finished.store(true, Ordering::SeqCst);
                    handshake.complete();
                })
            };

            let started = Instant::now();
            assert!(handshake.on_event(event, SHUTDOWN_WAIT), "event {event}");
            assert!(
                finished.load(Ordering::SeqCst),
                "event {event} returned before the daemon had shut down"
            );
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "event {event} waited out its bound instead of the daemon"
            );
            daemon.join().expect("daemon thread");
        }
    }

    /// Ctrl-C and Ctrl-Break go on to ctrlc's handler untouched: no
    /// request, no wait.
    #[test]
    fn ctrl_c_and_ctrl_break_pass_to_the_next_handler() {
        for event in [CTRL_C_EVENT, CTRL_BREAK_EVENT, 3, 4, 7] {
            let (handshake, calls) = counting();
            let started = Instant::now();
            assert!(!handshake.on_event(event, SHUTDOWN_WAIT), "event {event}");
            assert_eq!(calls.load(Ordering::SeqCst), 0, "event {event}");
            assert!(started.elapsed() < Duration::from_secs(5), "event {event}");
        }
    }

    /// A shutdown that never reports is held only for the bound; the
    /// event is still handled, so Windows then ends the process.
    #[test]
    fn a_shutdown_that_never_finishes_is_held_for_the_bound() {
        let (handshake, calls) = counting();
        let bound = Duration::from_millis(150);
        let started = Instant::now();
        assert!(handshake.on_event(CTRL_CLOSE_EVENT, bound));
        assert!(started.elapsed() >= bound, "released before the bound");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!handshake.wait_complete(Duration::ZERO));
    }

    /// Once the daemon has shut down, a later event is requested (the
    /// daemon logs it as a repeat) and released at once.
    #[test]
    fn a_finished_shutdown_releases_at_once() {
        let (handshake, calls) = counting();
        handshake.complete();
        let started = Instant::now();
        assert!(handshake.on_event(CTRL_SHUTDOWN_EVENT, SHUTDOWN_WAIT));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// The handler installs once per process.
    #[test]
    fn the_handler_installs_once() {
        install_console_handler(Box::new(|| {})).expect("first install");
        let again = install_console_handler(Box::new(|| {})).expect_err("second install");
        assert_eq!(again.kind(), std::io::ErrorKind::AlreadyExists);
        // Nothing is held, so this only sets the latch.
        shutdown_complete();
        assert!(
            HANDSHAKE
                .get()
                .expect("installed")
                .wait_complete(Duration::ZERO)
        );
    }
}
