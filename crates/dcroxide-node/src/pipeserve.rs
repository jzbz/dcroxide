// SPDX-License-Identifier: ISC
//! The pipe IPC runtime — dcrd `ipc.go`'s reader and writer loops over
//! the descriptors a parent process (a supervisor such as Decrediton)
//! hands the daemon with `--piperx`/`--pipetx`, driving the ported
//! message encoding in [`crate::ipc`].
//!
//! The writer serializes every queued [`PipeMessage`] to the `--pipetx`
//! descriptor (`serviceControlPipeTx`); without one the queue drains
//! into nothing so senders never block (`drainOutgoingPipeMessages`).
//! The reader discards everything arriving on `--piperx` until the
//! descriptor reports end-of-file or an error, then requests the same
//! graceful shutdown as an interrupt signal (`serviceControlPipeRx`) —
//! the parent closing its end is the shutdown request, and a broken
//! descriptor is treated the same way, exactly as dcrd's failed reads
//! are.
//!
//! This crate forbids `unsafe`, so an inherited descriptor cannot be
//! adopted with `from_raw_fd` the way `os.NewFile` adopts it.  On Linux
//! the process duplicates it from itself instead (`pidfd_getfd`), which
//! serves every kind of descriptor; elsewhere on unix, and on Linux
//! kernels without that call, it is re-opened through the file system
//! (see `open_inherited_fd`).  On Windows the inherited pipe handle is
//! duplicated within the process by `dcroxide-winsvc`, the workspace's
//! one audited exception to the no-`unsafe` rule
//! (`adopt_inherited_handle`).

use std::fs::File;
use std::io::{Read, Write};
use std::sync::mpsc;
use std::thread;

use crate::ipc::{LifetimeAction, LifetimeEventId, PipeMessage};

/// The outgoing pipe-message queue with the lifetime-event and
/// bound-address gates (dcrd's `lifetimeEventServer` and
/// `boundAddrEventServer`, both over `outgoingPipeMessages`): the
/// notify methods queue events only when `--lifetimeevents` or
/// `--boundaddrevents` asked for them, and the queue goes to the
/// `--pipetx` writer when one is running or into nothing otherwise.
#[derive(Clone)]
pub struct PipeNotifier {
    sender: mpsc::Sender<Outgoing>,
    lifetime_events: bool,
    bound_addr_events: bool,
}

/// What the `--pipetx` writer takes off the queue: a message to write,
/// or a marker it acknowledges once everything queued ahead of it has
/// been written or drained (see [`PipeNotifier::wait_written`]).
enum Outgoing {
    Message(PipeMessage),
    Written(mpsc::Sender<()>),
}

impl PipeNotifier {
    /// Enable the bound-address events (dcrd building a
    /// `boundAddrEventServer` only under `--boundaddrevents`; the empty
    /// server sends nothing).
    pub fn with_bound_addr_events(mut self, enabled: bool) -> PipeNotifier {
        self.bound_addr_events = enabled;
        self
    }

    /// A P2P listener bound to the address, rendered as Go's
    /// `listener.Addr().String()` (dcrd `notifyP2PAddress`, called by
    /// `initListeners` once per listener that bound).
    pub fn notify_p2p_address(&self, addr: &str) {
        if self.bound_addr_events {
            let _ = self
                .sender
                .send(Outgoing::Message(PipeMessage::BoundP2pListenAddr(
                    addr.to_string(),
                )));
        }
    }

    /// An RPC listener bound to the address (dcrd `notifyRPCAddress`,
    /// called by `setupRPCListeners` once per listener that bound).
    pub fn notify_rpc_address(&self, addr: &str) {
        if self.bound_addr_events {
            let _ = self
                .sender
                .send(Outgoing::Message(PipeMessage::BoundRpcListenAddr(
                    addr.to_string(),
                )));
        }
    }

    /// A lifetime event announcing the action is about to start
    /// (dcrd `notifyStartupEvent`).
    pub fn notify_startup_event(&self, action: LifetimeAction) {
        if self.lifetime_events {
            let _ = self
                .sender
                .send(Outgoing::Message(PipeMessage::LifetimeEvent {
                    event: LifetimeEventId::StartupEvent,
                    action,
                }));
        }
    }

    /// All startup tasks completed (dcrd `notifyStartupComplete`); the
    /// action byte is ignored for this event kind.
    pub fn notify_startup_complete(&self) {
        if self.lifetime_events {
            let _ = self
                .sender
                .send(Outgoing::Message(PipeMessage::LifetimeEvent {
                    event: LifetimeEventId::StartupComplete,
                    action: LifetimeAction::DbOpen,
                }));
        }
    }

    /// A lifetime event announcing the action is about to stop
    /// (dcrd `notifyShutdownEvent`).
    pub fn notify_shutdown_event(&self, action: LifetimeAction) {
        if self.lifetime_events {
            let _ = self
                .sender
                .send(Outgoing::Message(PipeMessage::LifetimeEvent {
                    event: LifetimeEventId::ShutdownEvent,
                    action,
                }));
        }
    }

    /// Wait, for at most `timeout`, until the `--pipetx` writer has
    /// written everything queued so far, or has given up on the pipe and
    /// drained it; without a writer there is nothing to wait for.
    ///
    /// dcrd's queue is an unbuffered channel, so each notify call there
    /// returns only once the writer has taken the message, having
    /// written everything before it; this queue never blocks a sender.
    /// The daemon waits here before it exits instead, where a message
    /// still queued would otherwise be lost with the process -- most of
    /// all the `DbOpen` shutdown event, the last one it sends.
    pub fn wait_written(&self, timeout: std::time::Duration) {
        let (ack, written) = mpsc::channel();
        if self.sender.send(Outgoing::Written(ack)).is_ok() {
            let _ = written.recv_timeout(timeout);
        }
    }
}

/// Go's `os.ErrInvalid`, what every read or write on the nil file
/// `os.NewFile` returns for a number it rejects fails with.
#[cfg(unix)]
fn go_err_invalid() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid argument")
}

/// Whether the error is the nil file's `os.ErrInvalid` (see
/// `go_err_invalid` and `dcroxide_winsvc::adopt_inherited_handle`)
/// rather than an OS error, which always carries its code.
fn is_go_err_invalid(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::InvalidInput && err.raw_os_error().is_none()
}

/// The error dcrd logs for a failed read or write on a pipe (`Failed to
/// read from pipe: %v`, `Failed to write to pipe: %v`).  dcrd names the
/// file `|fd` (`os.NewFile(fd, fmt.Sprintf("|%v", fd))`), and
/// `os.File`'s reads and writes wrap what fails in a `*PathError` over
/// that name, the OS error spelled as `syscall.Errno` spells it (`read
/// |5: bad file descriptor`, on Windows `read |5: The handle is
/// invalid.`).  The nil file returns `os.ErrInvalid` bare.
fn go_pipe_error(op: &'static str, fd: u64, err: std::io::Error) -> String {
    if is_go_err_invalid(&err) {
        return err.to_string();
    }
    crate::gostd::GoPathError {
        op,
        path: format!("|{fd}"),
        err,
    }
    .to_string()
}

/// Take a descriptor the parent left open, the `unsafe`-free stand-in
/// for `os.NewFile(fd)`.
///
/// On Linux the process duplicates the descriptor from itself through
/// `pidfd_getfd`, which shares the open file description exactly as
/// adopting it does, whatever the descriptor is: a pipe, a file, or the
/// socketpair a Node or Electron parent hands its child for a `'pipe'`
/// stdio slot (libuv's `UV_CREATE_PIPE`), which the file system cannot
/// re-open (`ENXIO`).  A descriptor that is not open fails with
/// `EBADF`, as every read or write dcrd makes on it would.  Where the
/// call is missing (kernels before 5.6) or filtered by a sandbox, and on
/// the other unixes, the descriptor is re-opened by path instead; the
/// other unixes' `/dev/fd` open duplicates it, while Linux's
/// `/proc/self/fd` open serves pipes and files but not sockets.  A
/// number that is negative as Go's `int` gets the nil file from
/// `os.NewFile`, so it fails with `os.ErrInvalid`.
#[cfg(unix)]
fn open_inherited_fd(fd: u64, write: bool) -> std::io::Result<File> {
    if i64::try_from(fd).is_err() {
        return Err(go_err_invalid());
    }

    #[cfg(target_os = "linux")]
    match duplicate_own_fd(fd) {
        Ok(file) => return Ok(file),
        Err(e) if e.raw_os_error() == Some(rustix::io::Errno::BADF.raw_os_error()) => {
            return Err(e);
        }
        Err(_) => {}
    }

    // Linux exposes every open descriptor under /proc/self/fd; other
    // unixes expose the same set under /dev/fd.
    let proc_path = format!("/proc/self/fd/{fd}");
    let dev_path = format!("/dev/fd/{fd}");
    let path = if std::path::Path::new(&proc_path).exists() {
        proc_path
    } else {
        dev_path
    };
    std::fs::OpenOptions::new()
        .read(!write)
        .write(write)
        .open(path)
}

/// Duplicate one of this process's own descriptors through its pidfd
/// (`pidfd_open` on itself, then `pidfd_getfd`), which the kernel
/// always permits within a thread group.
#[cfg(target_os = "linux")]
fn duplicate_own_fd(fd: u64) -> std::io::Result<File> {
    use rustix::process::{PidfdFlags, PidfdGetfdFlags, getpid, pidfd_getfd, pidfd_open};

    // A number past the descriptor range names no open descriptor.
    let target = i32::try_from(fd).map_err(|_| std::io::Error::from(rustix::io::Errno::BADF))?;
    let pidfd = pidfd_open(getpid(), PidfdFlags::empty())?;
    Ok(File::from(pidfd_getfd(
        &pidfd,
        target,
        PidfdGetfdFlags::empty(),
    )?))
}

/// Take a pipe handle the parent left inheritable (dcrd's
/// `os.NewFile(fd)` on Windows): `dcroxide-winsvc` duplicates it within
/// the process, which shares the pipe as adopting it does, and hands
/// back the duplicate as a file the daemon owns.  `INVALID_HANDLE_VALUE`
/// fails with Go's `invalid argument`, the error every read or write on
/// `os.NewFile`'s nil file returns, and a number that names no open
/// handle with `ERROR_INVALID_HANDLE`, as dcrd's first read or write on
/// it does; both take the broken-descriptor path.  The duplicate keeps
/// the handle's access, so `write` has nothing to choose.
#[cfg(windows)]
fn open_inherited_fd(fd: u64, _write: bool) -> std::io::Result<File> {
    dcroxide_winsvc::adopt_inherited_handle(fd)
}

/// Only unix descriptors and Windows handles are taken.
#[cfg(not(any(unix, windows)))]
fn open_inherited_fd(_fd: u64, _write: bool) -> std::io::Result<File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "pipe descriptors are not supported on this platform yet",
    ))
}

/// Wait until a descriptor whose reads (or, with `write`, writes) would
/// block can go on, or has hung up: an inherited descriptor keeps the
/// non-blocking mode its parent gave it, and Go's `os.NewFile` parks
/// such a read or write in the runtime poller (`poll.FD.Read`,
/// `poll.FD.Write`) rather than failing it.
#[cfg(unix)]
fn wait_ready(pipe: &File, write: bool) -> std::io::Result<()> {
    use rustix::event::{PollFd, PollFlags, poll};
    let flags = if write { PollFlags::OUT } else { PollFlags::IN };
    let mut fds = [PollFd::new(pipe, flags)];
    match poll(&mut fds, None) {
        // A signal cut the wait short; the call that follows retries.
        Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Off unix nothing is left to wait for: std's reads and writes on a
/// Windows handle wait for the transfer themselves, even on a handle
/// opened for overlapped I/O, so they never report `WouldBlock` for a
/// pipe, and elsewhere nothing is taken.
#[cfg(not(unix))]
fn wait_ready(_pipe: &File, _write: bool) -> std::io::Result<()> {
    Ok(())
}

/// Write one whole message, waiting out a full buffer on a descriptor
/// left non-blocking (see [`wait_ready`]) the way Go's `poll.FD.Write`
/// does, where `write_all` would fail with `WouldBlock` and end the
/// writer.  A write that takes nothing is an error, as it is to Go
/// (`io.ErrUnexpectedEOF`, with its text).
fn write_all_waiting(mut pipe: &File, mut bytes: &[u8]) -> std::io::Result<()> {
    while !bytes.is_empty() {
        match pipe.write(bytes) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "unexpected EOF",
                ));
            }
            Ok(n) => bytes = bytes.get(n..).unwrap_or_default(),
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => wait_ready(pipe, true)?,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Build the outgoing message queue, and when `--pipetx` names a
/// descriptor, start the writer serving it (dcrd
/// `serviceControlPipeTx`); with none — or when the descriptor cannot
/// be opened — the queue drains into nothing so senders never block
/// (`drainOutgoingPipeMessages`).
pub fn new_pipe_notifier(pipe_tx: u64, lifetime_events: bool) -> PipeNotifier {
    let (sender, receiver) = mpsc::channel::<Outgoing>();
    if pipe_tx != 0 {
        match open_inherited_fd(pipe_tx, true) {
            Ok(pipe) => {
                let _ = thread::Builder::new().spawn(move || {
                    while let Ok(outgoing) = receiver.recv() {
                        match outgoing {
                            Outgoing::Message(message) => {
                                if let Err(e) = write_all_waiting(&pipe, &message.encode()) {
                                    // dcrd logs the failed write and falls
                                    // into the drain loop so senders keep
                                    // going.
                                    crate::logging::error(
                                        "DCRD",
                                        &format!(
                                            "Failed to write to pipe: {}",
                                            go_pipe_error("write", pipe_tx, e)
                                        ),
                                    );
                                    break;
                                }
                            }
                            Outgoing::Written(ack) => {
                                let _ = ack.send(());
                            }
                        }
                    }
                    // Drain whatever still arrives (dcrd's deferred
                    // drainOutgoingPipeMessages).
                    while let Ok(outgoing) = receiver.recv() {
                        if let Outgoing::Written(ack) = outgoing {
                            let _ = ack.send(());
                        }
                    }
                });
            }
            Err(e) => {
                crate::logging::warn(
                    "DCRD",
                    &format!("Unable to open the pipetx descriptor {pipe_tx}: {e}"),
                );
            }
        }
    }
    PipeNotifier {
        sender,
        lifetime_events,
        bound_addr_events: false,
    }
}

/// Watch the `--piperx` descriptor, discarding whatever arrives until
/// it reports end-of-file or an error, then request a graceful
/// shutdown (dcrd `serviceControlPipeRx`): the parent closing its end
/// of the pipe is the shutdown request, and a broken descriptor is
/// treated the same way.  On platforms without descriptor support the
/// watcher only logs, rather than shutting a healthy daemon down.
pub fn start_pipe_rx(pipe_rx: u64, request_shutdown: Box<dyn FnOnce() + Send>) {
    let _ = thread::Builder::new().spawn(move || {
        let mut pipe = match open_inherited_fd(pipe_rx, false) {
            Ok(pipe) => pipe,
            Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
                crate::logging::warn("DCRD", "--piperx is not supported on this platform yet");
                return;
            }
            Err(e) => {
                // dcrd's reads over a descriptor that is not open fail
                // at once and request the shutdown, and taking one fails
                // here the same way, logged as dcrd's first read fails
                // (`read |N: bad file descriptor`; on Windows `read |N:
                // The handle is invalid.`, or for `INVALID_HANDLE_VALUE`
                // the bare `invalid argument` of `os.NewFile`'s nil
                // file).  A re-open by path that fails on an open
                // descriptor -- a socket on a kernel without
                // `pidfd_getfd` -- has no dcrd counterpart; it shuts
                // down the same way rather than leave the daemon
                // running where its parent cannot stop it.
                crate::logging::error("DCRD", &read_failure(pipe_rx, e));
                request_shutdown();
                return;
            }
        };
        let mut scratch = [0u8; 1024];
        loop {
            match pipe.read(&mut scratch) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    match wait_ready(&pipe, false) {
                        Ok(()) => continue,
                        Err(e) => {
                            crate::logging::error("DCRD", &read_failure(pipe_rx, e));
                            break;
                        }
                    }
                }
                Err(e) => {
                    crate::logging::error("DCRD", &read_failure(pipe_rx, e));
                    break;
                }
            }
        }
        request_shutdown();
    });
}

/// dcrd's `Failed to read from pipe: %v` line for the `--piperx`
/// descriptor `fd` (see [`go_pipe_error`]).
fn read_failure(fd: u64, err: std::io::Error) -> String {
    format!(
        "Failed to read from pipe: {}",
        go_pipe_error("read", fd, err)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A read or write that fails is logged as Go's `*PathError` over
    /// the file dcrd names `|fd`, with the OS error spelled as
    /// `syscall.Errno` spells it, not as Rust's `(os error N)` form.
    #[test]
    fn a_failed_read_or_write_is_logged_as_dcrd_logs_it() {
        #[cfg(unix)]
        let (bad, text) = (
            rustix::io::Errno::BADF.raw_os_error(),
            "bad file descriptor",
        );
        // ERROR_INVALID_HANDLE, as Go asks for it in US English.
        #[cfg(windows)]
        let (bad, text) = (6, "The handle is invalid.");
        #[cfg(any(unix, windows))]
        {
            let err = std::io::Error::from_raw_os_error(bad);
            assert_eq!(
                read_failure(5, err),
                format!("Failed to read from pipe: read |5: {text}")
            );
            let err = std::io::Error::from_raw_os_error(bad);
            assert_eq!(go_pipe_error("write", 7, err), format!("write |7: {text}"));
        }

        // A write that takes nothing is Go's `io.ErrUnexpectedEOF`.
        let err = std::io::Error::new(std::io::ErrorKind::WriteZero, "unexpected EOF");
        assert_eq!(go_pipe_error("write", 7, err), "write |7: unexpected EOF");
    }

    /// The nil file `os.NewFile` returns for a number that is negative
    /// as Go's `int` (on Windows, `INVALID_HANDLE_VALUE`) fails with
    /// `os.ErrInvalid` itself, which dcrd logs unwrapped.
    #[cfg(any(unix, windows))]
    #[test]
    fn a_rejected_number_is_logged_as_go_s_nil_file() {
        #[cfg(unix)]
        let rejected = [u64::MAX, 1 << 63];
        #[cfg(windows)]
        let rejected = [u64::MAX];
        for fd in rejected {
            let err = open_inherited_fd(fd, false).expect_err("nil file");
            assert_eq!(
                read_failure(fd, err),
                "Failed to read from pipe: invalid argument"
            );
        }
    }

    /// A descriptor that is not open is logged as dcrd's first read on
    /// it fails.  The fallback re-open by path, used where `pidfd_getfd`
    /// is unavailable, fails differently and is not checked.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_descriptor_that_is_not_open_is_logged_as_dcrd_logs_it() {
        // Descriptors are allocated lowest first, so this one is free.
        let fd: u64 = 1 << 30;
        match duplicate_own_fd(fd) {
            Err(e) if e.raw_os_error() == Some(rustix::io::Errno::BADF.raw_os_error()) => {}
            other => {
                eprintln!("skipped: pidfd_getfd unavailable ({:?})", other.err());
                return;
            }
        }
        let err = open_inherited_fd(fd, false).expect_err("not open");
        assert_eq!(
            read_failure(fd, err),
            "Failed to read from pipe: read |1073741824: bad file descriptor"
        );
    }

    /// A handle number that names no open handle is logged as dcrd's
    /// first read on it fails.  Handle values are multiples of four
    /// below 2^26, so this one can name nothing.
    #[cfg(windows)]
    #[test]
    fn a_handle_that_is_not_open_is_logged_as_dcrd_logs_it() {
        let err = open_inherited_fd(0x0fff_fff0, false).expect_err("not open");
        assert_eq!(
            read_failure(0x0fff_fff0, err),
            "Failed to read from pipe: read |268435440: The handle is invalid."
        );
    }
}
