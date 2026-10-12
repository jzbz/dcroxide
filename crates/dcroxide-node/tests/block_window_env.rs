// SPDX-License-Identifier: ISC
//! The daemon reads `DCROXIDE_BLOCK_WINDOW` and gives the sync manager
//! it builds the block download window the variable names.
//!
//! The window the daemon syncs with is not dcrd's (PARITY *Block
//! download window*), and the variable is the operator's way back to
//! dcrd's.  The line the daemon logs is built from the window its sync
//! manager reports after the setting was applied
//! (`dcroxide_node::sync::apply_block_window_setting`, pinned by that
//! module's own tests), so the line appearing means the manager the
//! daemon serves peers with has that window.  These tests pin the other
//! half: that the daemon reads the variable, applies it and logs the
//! line, and that an untouched daemon says nothing.

// Test-harness arithmetic over a fixed deadline.
#![allow(clippy::arithmetic_side_effects)]

use std::ffi::OsStr;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The line the daemon logs once it is serving peers, after the server
/// state, the sync manager included, has been built.
const SERVING: &str = "[INF] DCRD: Serving peers until a shutdown signal is received.";

/// Start the daemon on simnet with the variable set to `setting`, or
/// unset, and return its stdout lines up to the one that says it is
/// serving peers, each with its timestamp cut off.
///
/// Nothing is listened on, no RPC server runs and no seeder is asked,
/// so the daemon touches no network, and its data directory is its own.
fn startup_lines(setting: Option<&OsStr>) -> Vec<String> {
    let appdata = tempfile::tempdir().expect("appdata");
    let mut command = Command::new(env!("CARGO_BIN_EXE_dcroxide"));
    command
        .args(["--simnet", "--nolisten", "--norpc", "--noseeders"])
        .arg(format!("--appdata={}", appdata.path().display()))
        .env_remove("DCRD_APPDATA")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    match setting {
        Some(value) => command.env("DCROXIDE_BLOCK_WINDOW", value),
        None => command.env_remove("DCROXIDE_BLOCK_WINDOW"),
    };
    let mut child = command.spawn().expect("spawn dcroxide");

    // Read stdout on its own thread so the wait can be bounded.
    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let mut lines = Vec::new();
    let mut serving = false;
    let deadline = Instant::now() + Duration::from_secs(60);
    while !serving {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        match rx.recv_timeout(left) {
            Ok(line) => {
                // `YYYY-MM-DD hh:mm:ss.sss [LVL] TAG: message`.
                let untimed = line.find(" [").map_or(line.as_str(), |at| &line[at + 1..]);
                serving = untimed == SERVING;
                lines.push(untimed.to_string());
            }
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        serving,
        "the daemon did not start serving peers:\n{}",
        lines.join("\n")
    );
    lines
}

/// The lines that mention the block download window or its variable.
fn window_lines(lines: &[String]) -> Vec<&str> {
    lines
        .iter()
        .map(String::as_str)
        .filter(|line| line.contains("DCROXIDE_BLOCK_WINDOW") || line.contains("download window"))
        .collect()
}

/// Unset, the daemon keeps the window its sync manager is built with
/// and logs nothing about it.
#[test]
fn an_unset_block_window_says_nothing() {
    let lines = startup_lines(None);
    assert!(window_lines(&lines).is_empty(), "{}", lines.join("\n"));
}

/// `dcrd` puts dcrd's window back, and a count sets how many blocks the
/// budgeted window requests at most.
#[test]
fn a_block_window_setting_is_applied_and_logged() {
    let lines = startup_lines(Some(OsStr::new("dcrd")));
    assert_eq!(
        window_lines(&lines),
        vec![
            "[INF] DCRD: Block download window set to dcrd's 16 blocks in flight by \
             DCROXIDE_BLOCK_WINDOW"
        ],
        "{}",
        lines.join("\n")
    );

    let lines = startup_lines(Some(OsStr::new("64")));
    assert_eq!(
        window_lines(&lines),
        vec![
            "[INF] DCRD: Block download window set to at most 64 blocks in flight by \
             DCROXIDE_BLOCK_WINDOW"
        ],
        "{}",
        lines.join("\n")
    );
}

/// A value that names no window is ignored with a warning, and the
/// daemon starts with its default.
#[test]
fn a_bad_block_window_setting_warns_and_is_ignored() {
    let lines = startup_lines(Some(OsStr::new("506")));
    assert_eq!(
        window_lines(&lines),
        vec![
            "[WRN] DCRD: DCROXIDE_BLOCK_WINDOW=506 is neither dcrd nor a whole number of blocks \
             from 16 to 505; using the default"
        ],
        "{}",
        lines.join("\n")
    );
}

/// A value that is not valid Unicode is a value that names no window,
/// not an unset variable: the daemon warns, showing the bytes it could
/// not read as the replacement character, and starts with its default.
#[cfg(unix)]
#[test]
fn a_block_window_setting_that_is_not_unicode_warns() {
    use std::os::unix::ffi::OsStrExt;

    let lines = startup_lines(Some(OsStr::from_bytes(&[0xff])));
    assert_eq!(
        window_lines(&lines),
        vec![
            "[WRN] DCRD: DCROXIDE_BLOCK_WINDOW=\u{fffd} is neither dcrd nor a whole number of \
             blocks from 16 to 505; using the default"
        ],
        "{}",
        lines.join("\n")
    );
}
