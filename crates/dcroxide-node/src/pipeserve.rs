// SPDX-License-Identifier: ISC
//! The pipe IPC runtime — dcrd `ipc.go`'s reader and writer loops over
//! the descriptors a parent process (Decrediton, the coming service
//! wrapper) hands the daemon with `--piperx`/`--pipetx`, driving the
//! ported message encoding in [`crate::ipc`].
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
//! The workspace forbids `unsafe`, so the inherited descriptors are
//! re-opened through the file system (`/proc/self/fd` on Linux,
//! `/dev/fd` elsewhere on unix) rather than adopted with
//! `from_raw_fd`; Windows pipe handles are deferred with the service
//! wrapper.

use std::fs::File;
use std::io::{Read, Write};
use std::sync::mpsc;
use std::thread;

use crate::ipc::{LifetimeAction, LifetimeEventId, PipeMessage};

/// The outgoing pipe-message queue and the lifetime-event gate (dcrd's
/// `lifetimeEventServer` over `outgoingPipeMessages`): the notify
/// methods queue events only when `--lifetimeevents` asked for them,
/// and the queue goes to the `--pipetx` writer when one is running or
/// into nothing otherwise.
#[derive(Clone)]
pub struct PipeNotifier {
    sender: mpsc::Sender<PipeMessage>,
    lifetime_events: bool,
}

impl PipeNotifier {
    /// A lifetime event announcing the action is about to start
    /// (dcrd `notifyStartupEvent`).
    pub fn notify_startup_event(&self, action: LifetimeAction) {
        if self.lifetime_events {
            let _ = self.sender.send(PipeMessage::LifetimeEvent {
                event: LifetimeEventId::StartupEvent,
                action,
            });
        }
    }

    /// All startup tasks completed (dcrd `notifyStartupComplete`); the
    /// action byte is ignored for this event kind.
    pub fn notify_startup_complete(&self) {
        if self.lifetime_events {
            let _ = self.sender.send(PipeMessage::LifetimeEvent {
                event: LifetimeEventId::StartupComplete,
                action: LifetimeAction::DbOpen,
            });
        }
    }

    /// A lifetime event announcing the action is about to stop
    /// (dcrd `notifyShutdownEvent`).
    pub fn notify_shutdown_event(&self, action: LifetimeAction) {
        if self.lifetime_events {
            let _ = self.sender.send(PipeMessage::LifetimeEvent {
                event: LifetimeEventId::ShutdownEvent,
                action,
            });
        }
    }
}

/// Re-open an inherited descriptor through the file system, the
/// `unsafe`-free stand-in for `os.NewFile(fd)`.
#[cfg(unix)]
fn open_inherited_fd(fd: u64, write: bool) -> std::io::Result<File> {
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

/// Windows pipe handles are deferred with the service wrapper.
#[cfg(not(unix))]
fn open_inherited_fd(_fd: u64, _write: bool) -> std::io::Result<File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "pipe descriptors are not supported on this platform yet",
    ))
}

/// Build the outgoing message queue, and when `--pipetx` names a
/// descriptor, start the writer serving it (dcrd
/// `serviceControlPipeTx`); with none — or when the descriptor cannot
/// be opened — the queue drains into nothing so senders never block
/// (`drainOutgoingPipeMessages`).
pub fn new_pipe_notifier(pipe_tx: u64, lifetime_events: bool) -> PipeNotifier {
    let (sender, receiver) = mpsc::channel::<PipeMessage>();
    if pipe_tx != 0 {
        match open_inherited_fd(pipe_tx, true) {
            Ok(mut pipe) => {
                let _ = thread::Builder::new().spawn(move || {
                    while let Ok(message) = receiver.recv() {
                        let bytes = message.encode();
                        if pipe.write_all(&bytes).is_err() || pipe.flush().is_err() {
                            // dcrd logs the failed write and falls into
                            // the drain loop so senders keep going.
                            break;
                        }
                    }
                    // Drain whatever still arrives (dcrd's deferred
                    // drainOutgoingPipeMessages).
                    while receiver.recv().is_ok() {}
                });
            }
            Err(e) => {
                println!("[WRN] DCRD: Unable to open the pipetx descriptor {pipe_tx}: {e}");
            }
        }
    }
    PipeNotifier {
        sender,
        lifetime_events,
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
                println!("[WRN] DCRD: --piperx is not supported on this platform yet");
                return;
            }
            Err(e) => {
                // dcrd's reads over a bad descriptor fail immediately
                // and request the shutdown; a descriptor that cannot
                // even be opened is the same broken contract.
                println!("[ERR] DCRD: Failed to read from pipe: {e}");
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
                Err(e) => {
                    println!("[ERR] DCRD: Failed to read from pipe: {e}");
                    break;
                }
            }
        }
        request_shutdown();
    });
}
