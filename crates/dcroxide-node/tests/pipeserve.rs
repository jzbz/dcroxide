// SPDX-License-Identifier: ISC
//! Checks for the pipe IPC runtime: the --pipetx writer serializes the
//! queued lifetime events in dcrd's encoding, the --lifetimeevents
//! gate keeps a disabled notifier silent, and the --piperx watcher
//! requests shutdown when the descriptor reaches end-of-file.

#![cfg(unix)]

use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use dcroxide_node::ipc::{LifetimeAction, LifetimeEventId, PipeMessage};
use dcroxide_node::pipeserve::{new_pipe_notifier, start_pipe_rx};

/// Wait until the file at the path holds at least `len` bytes.
fn wait_for_len(path: &std::path::Path, len: usize) -> Vec<u8> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(5))
        .expect("deadline");
    loop {
        let bytes = std::fs::read(path).unwrap_or_default();
        if bytes.len() >= len || Instant::now() >= deadline {
            return bytes;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn the_pipetx_writer_serializes_lifetime_events() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("pipetx");
    // The open write handle is the inherited descriptor the writer
    // re-opens by number; it must stay alive past the notifier start.
    let sink = std::fs::File::create(&path).expect("create sink");
    let fd = sink.as_raw_fd() as u64;

    let notifier = new_pipe_notifier(fd, true);
    notifier.notify_startup_event(LifetimeAction::DbOpen);
    notifier.notify_startup_complete();
    notifier.notify_shutdown_event(LifetimeAction::P2pServer);

    let expected: Vec<u8> = [
        PipeMessage::LifetimeEvent {
            event: LifetimeEventId::StartupEvent,
            action: LifetimeAction::DbOpen,
        },
        PipeMessage::LifetimeEvent {
            event: LifetimeEventId::StartupComplete,
            action: LifetimeAction::DbOpen,
        },
        PipeMessage::LifetimeEvent {
            event: LifetimeEventId::ShutdownEvent,
            action: LifetimeAction::P2pServer,
        },
    ]
    .iter()
    .flat_map(PipeMessage::encode)
    .collect();

    let written = wait_for_len(&path, expected.len());
    assert_eq!(written, expected, "the writer must serialize the queue");
}

#[test]
fn a_disabled_lifetime_gate_stays_silent() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("pipetx");
    let sink = std::fs::File::create(&path).expect("create sink");
    let fd = sink.as_raw_fd() as u64;

    // Without --lifetimeevents the notifier queues nothing.
    let notifier = new_pipe_notifier(fd, false);
    notifier.notify_startup_event(LifetimeAction::DbOpen);
    notifier.notify_startup_complete();
    std::thread::sleep(Duration::from_millis(150));
    let written = std::fs::read(&path).expect("read sink");
    assert!(written.is_empty(), "a disabled gate must write nothing");
}

#[test]
fn the_piperx_watcher_requests_shutdown_at_eof() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("piperx");
    std::fs::write(&path, b"anything arriving is discarded").expect("write");
    // The open read handle is the inherited descriptor; a regular file
    // reaches end-of-file after its content, the parent-closed-pipe
    // analog.
    let source = std::fs::File::open(&path).expect("open source");
    let fd = source.as_raw_fd() as u64;

    let requested = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&requested);
    start_pipe_rx(
        fd,
        Box::new(move || {
            flag.store(true, Ordering::SeqCst);
        }),
    );

    let deadline = Instant::now()
        .checked_add(Duration::from_secs(5))
        .expect("deadline");
    while !requested.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        requested.load(Ordering::SeqCst),
        "end-of-file on the rx pipe must request a shutdown"
    );
}
