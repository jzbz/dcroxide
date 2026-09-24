// SPDX-License-Identifier: ISC
//! The pipe IPC over a socket, the descriptor a Node or Electron parent
//! hands its child for a `'pipe'` stdio slot (libuv's `UV_CREATE_PIPE`
//! is a socketpair on unix).  dcrd adopts whatever descriptor it is
//! given (`os.NewFile`); the port re-opened it through `/proc/self/fd`,
//! which Linux refuses for a socket (`ENXIO`), so `--piperx` shut the
//! daemon down at startup and `--pipetx` never sent a message.
//!
//! The daemon now takes the descriptor with `pidfd_getfd`.  Where that
//! call is missing (kernels before 5.6) or filtered (Docker's and
//! podman's default seccomp profiles allow it only with
//! `CAP_SYS_PTRACE`), it falls back to the re-open, which still cannot
//! serve a socket; each test then skips with a note, as the documented
//! fallback leaves nothing to test.

#![cfg(target_os = "linux")]
// Test-harness arithmetic over fixed deadlines.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{Read, Write};
use std::os::unix::io::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use dcroxide_node::ipc::{LifetimeAction, LifetimeEventId, PipeMessage};
use dcroxide_node::pipeserve::{new_pipe_notifier, start_pipe_rx};

/// Whether this process can take its own descriptor with
/// `pidfd_getfd`, the call the daemon uses; prints the skip note when
/// it cannot.
fn pidfd_getfd_works(fd: &impl AsFd) -> bool {
    use rustix::process::{PidfdFlags, PidfdGetfdFlags, getpid, pidfd_getfd, pidfd_open};
    let probe = pidfd_open(getpid(), PidfdFlags::empty())
        .and_then(|pidfd| pidfd_getfd(&pidfd, fd.as_fd().as_raw_fd(), PidfdGetfdFlags::empty()));
    match probe {
        Ok(_) => true,
        Err(e) => {
            eprintln!("skipped: pidfd_getfd unavailable ({e})");
            false
        }
    }
}

/// The encoded startup-event pair the writer tests queue.
fn startup_events() -> Vec<u8> {
    [
        PipeMessage::LifetimeEvent {
            event: LifetimeEventId::StartupEvent,
            action: LifetimeAction::DbOpen,
        },
        PipeMessage::LifetimeEvent {
            event: LifetimeEventId::StartupComplete,
            action: LifetimeAction::DbOpen,
        },
    ]
    .iter()
    .flat_map(PipeMessage::encode)
    .collect()
}

/// The watcher runs until the parent closes its end of the socket,
/// discarding what arrives meanwhile, and only then requests the
/// shutdown (dcrd `serviceControlPipeRx`).
#[test]
fn the_piperx_watcher_serves_a_socket() {
    let (daemon_end, mut parent_end) = UnixStream::pair().expect("socketpair");
    if !pidfd_getfd_works(&daemon_end) {
        return;
    }
    let requested = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&requested);
    start_pipe_rx(
        daemon_end.as_raw_fd() as u64,
        Box::new(move || flag.store(true, Ordering::SeqCst)),
    );

    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !requested.load(Ordering::SeqCst),
        "a socket whose parent end is open must not request a shutdown"
    );
    parent_end
        .write_all(b"control bytes are discarded")
        .expect("write to the watcher");
    std::thread::sleep(Duration::from_millis(100));
    assert!(!requested.load(Ordering::SeqCst), "data is not a close");

    drop(parent_end);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !requested.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        requested.load(Ordering::SeqCst),
        "the parent closing its end must request a shutdown"
    );
    drop(daemon_end);
}

/// A descriptor the parent left in non-blocking mode keeps it when it
/// is taken, since the duplicate shares the open file description; Go's
/// `os.NewFile` parks such reads in its poller, so the watcher waits for
/// the close rather than failing its first read.
#[test]
fn the_piperx_watcher_waits_on_a_nonblocking_socket() {
    let (daemon_end, parent_end) = UnixStream::pair().expect("socketpair");
    if !pidfd_getfd_works(&daemon_end) {
        return;
    }
    daemon_end.set_nonblocking(true).expect("non-blocking");
    let requested = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&requested);
    start_pipe_rx(
        daemon_end.as_raw_fd() as u64,
        Box::new(move || flag.store(true, Ordering::SeqCst)),
    );

    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !requested.load(Ordering::SeqCst),
        "a read that would block is not a close"
    );

    drop(parent_end);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !requested.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        requested.load(Ordering::SeqCst),
        "the parent closing its end must request a shutdown"
    );
    drop(daemon_end);
}

/// The writer delivers the lifetime events over a socket in dcrd's
/// encoding (dcrd `serviceControlPipeTx`).
#[test]
fn the_pipetx_writer_serves_a_socket() {
    let (daemon_end, mut parent_end) = UnixStream::pair().expect("socketpair");
    if !pidfd_getfd_works(&daemon_end) {
        return;
    }
    let notifier = new_pipe_notifier(daemon_end.as_raw_fd() as u64, true);
    notifier.notify_startup_event(LifetimeAction::DbOpen);
    notifier.notify_startup_complete();

    let expected = startup_events();
    parent_end
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let mut received = vec![0u8; expected.len()];
    parent_end
        .read_exact(&mut received)
        .expect("the events arrive on the socket");
    assert_eq!(received, expected);
    drop(daemon_end);
}

/// A descriptor the parent left in non-blocking mode keeps it when it
/// is taken, so the writer can find the buffer full; Go's `os.NewFile`
/// parks such a write in its poller until the parent reads, where a
/// failed write would end the writer and drop every later event.
#[test]
fn the_pipetx_writer_waits_on_a_full_nonblocking_socket() {
    let (daemon_end, mut parent_end) = UnixStream::pair().expect("socketpair");
    if !pidfd_getfd_works(&daemon_end) {
        return;
    }
    daemon_end.set_nonblocking(true).expect("non-blocking");

    // Fill the socket until a write would block, so the writer's first
    // write finds no room.
    let filler = [0xa5u8; 4096];
    let mut prefilled = 0usize;
    loop {
        match (&daemon_end).write(&filler) {
            Ok(n) => prefilled += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("filling the socket: {e}"),
        }
    }

    let notifier = new_pipe_notifier(daemon_end.as_raw_fd() as u64, true);
    notifier.notify_startup_event(LifetimeAction::DbOpen);
    notifier.notify_startup_complete();
    // Give the writer time to meet the full buffer before any room opens.
    std::thread::sleep(Duration::from_millis(300));

    parent_end
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let mut drained = vec![0u8; prefilled];
    parent_end
        .read_exact(&mut drained)
        .expect("the filler comes back first");
    assert!(drained.iter().all(|&b| b == 0xa5), "the filler is intact");

    let expected = startup_events();
    let mut received = vec![0u8; expected.len()];
    parent_end
        .read_exact(&mut received)
        .expect("the events arrive once the parent makes room");
    assert_eq!(received, expected);
    drop(daemon_end);
}
