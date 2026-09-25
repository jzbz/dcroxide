// SPDX-License-Identifier: ISC
//! The pipe IPC over Windows pipe handles.  dcrd adopts the inherited
//! anonymous-pipe handle a parent such as Decrediton passes with
//! `--piperx`/`--pipetx` (`os.NewFile`, `ipc.go:45`, `:74`), so the
//! parent closing its end stops the daemon and the lifetime events
//! reach the parent.  The port took nothing on Windows: `--piperx`
//! only warned that it was unsupported, so the daemon ignored its
//! parent's close, and `--pipetx` sent nothing.
//!
//! The handles are now taken through `dcroxide-winsvc`'s audited
//! adoption, which duplicates them within the process.  Each test
//! passes the watcher or the writer the number of one end of a std
//! pipe, as a parent passes the number of the end its child inherited.

#![cfg(windows)]
// Test-harness arithmetic over fixed deadlines.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{Read, Write};
use std::os::windows::io::AsRawHandle;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use dcroxide_node::ipc::{LifetimeAction, LifetimeEventId, PipeMessage};
use dcroxide_node::pipeserve::{new_pipe_notifier, start_pipe_rx};

/// The number a parent passes for a handle.
fn number(handle: &impl AsRawHandle) -> u64 {
    handle.as_raw_handle().addr() as u64
}

/// Wait up to five seconds for the flag.
fn wait_for(flag: &AtomicBool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !flag.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    flag.load(Ordering::SeqCst)
}

/// The watcher runs until the parent closes its end of the pipe,
/// discarding what arrives meanwhile, and only then requests the
/// shutdown (dcrd `serviceControlPipeRx`).
#[test]
fn the_piperx_watcher_serves_a_windows_pipe() {
    let (daemon_end, mut parent_end) = std::io::pipe().expect("pipe");
    let requested = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&requested);
    start_pipe_rx(
        number(&daemon_end),
        Box::new(move || flag.store(true, Ordering::SeqCst)),
    );

    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !requested.load(Ordering::SeqCst),
        "a pipe whose parent end is open must not request a shutdown"
    );
    parent_end
        .write_all(b"control bytes are discarded")
        .expect("write to the watcher");
    std::thread::sleep(Duration::from_millis(100));
    assert!(!requested.load(Ordering::SeqCst), "data is not a close");

    drop(parent_end);
    assert!(
        wait_for(&requested),
        "the parent closing its end must request a shutdown"
    );
    drop(daemon_end);
}

/// A number that names no open handle is dcrd's broken descriptor: its
/// first read fails, and the watcher requests the shutdown at once.
#[test]
fn the_piperx_watcher_shuts_down_on_a_handle_that_is_not_open() {
    let requested = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&requested);
    // Handle values are multiples of four below 2^26.
    start_pipe_rx(
        0x0fff_fff0,
        Box::new(move || flag.store(true, Ordering::SeqCst)),
    );
    assert!(
        wait_for(&requested),
        "a handle that is not open must request a shutdown"
    );
}

/// The writer delivers the lifetime events over the pipe in dcrd's
/// encoding (dcrd `serviceControlPipeTx`).
#[test]
fn the_pipetx_writer_serves_a_windows_pipe() {
    let (mut parent_end, daemon_end) = std::io::pipe().expect("pipe");
    let notifier = new_pipe_notifier(number(&daemon_end), true);
    notifier.notify_startup_event(LifetimeAction::DbOpen);
    notifier.notify_startup_complete();
    notifier.wait_written(Duration::from_secs(5));
    // The writer holds a handle of its own to the daemon's end, so
    // closing the inherited one leaves the events readable; with no
    // writer the read meets end-of-file instead of blocking.
    drop(daemon_end);

    let expected: Vec<u8> = [
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
    .collect();
    let mut received = vec![0u8; expected.len()];
    parent_end
        .read_exact(&mut received)
        .expect("the events arrive on the pipe");
    assert_eq!(received, expected);
    drop(notifier);
}
