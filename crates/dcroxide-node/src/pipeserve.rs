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
//! The workspace forbids `unsafe`, so an inherited descriptor cannot be
//! adopted with `from_raw_fd` the way `os.NewFile` adopts it.  On Linux
//! the process duplicates it from itself instead (`pidfd_getfd`), which
//! serves every kind of descriptor; elsewhere on unix, and on Linux
//! kernels without that call, it is re-opened through the file system
//! (see `open_inherited_fd`).  Windows pipe handles cannot be taken
//! at all without `unsafe`, so there `--piperx` only logs that it is
//! unsupported and `--pipetx` sends nothing.

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
/// `/proc/self/fd` open serves pipes and files but not sockets.
#[cfg(unix)]
fn open_inherited_fd(fd: u64, write: bool) -> std::io::Result<File> {
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

/// Windows pipe handles cannot be taken without `unsafe`
/// (`OwnedHandle::from_raw_handle`), which the workspace forbids.
#[cfg(not(unix))]
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

/// Nothing is ever taken off unix, so nothing waits.
#[cfg(not(unix))]
fn wait_ready(_pipe: &File, _write: bool) -> std::io::Result<()> {
    Ok(())
}

/// Write one whole message, waiting out a full buffer on a descriptor
/// left non-blocking (see [`wait_ready`]) the way Go's `poll.FD.Write`
/// does, where `write_all` would fail with `WouldBlock` and end the
/// writer.  A write that takes nothing is an error, as it is to Go
/// (`io.ErrUnexpectedEOF`).
fn write_all_waiting(mut pipe: &File, mut bytes: &[u8]) -> std::io::Result<()> {
    while !bytes.is_empty() {
        match pipe.write(bytes) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
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
                                        &format!("Failed to write to pipe: {e}"),
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
                // here the same way (`EBADF`).  A re-open by path that
                // fails on an open descriptor -- a socket on a kernel
                // without `pidfd_getfd` -- has no dcrd counterpart; it
                // shuts down the same way rather than leave the daemon
                // running where its parent cannot stop it.
                crate::logging::error("DCRD", &format!("Failed to read from pipe: {e}"));
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
                            crate::logging::error(
                                "DCRD",
                                &format!("Failed to read from pipe: {e}"),
                            );
                            break;
                        }
                    }
                }
                Err(e) => {
                    crate::logging::error("DCRD", &format!("Failed to read from pipe: {e}"));
                    break;
                }
            }
        }
        request_shutdown();
    });
}
