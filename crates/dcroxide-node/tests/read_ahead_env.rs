// SPDX-License-Identifier: ISC
//! The daemon reads `DCROXIDE_READ_AHEAD` and serves its peers with the
//! read-ahead of blocks on or off as the variable says.
//!
//! Reading ahead of the block handler on the sync peer's connection is
//! not dcrd's (PARITY *Reading ahead of the block handler*), and the
//! variable is the operator's way back to dcrd's one read at a time.
//! What a value means is pinned by the setting's own test
//! (`dcroxide_node::readahead::read_ahead_setting`), and that the server
//! then never asks for a connection to be read ahead by
//! `tests/dispatch.rs`.  These tests pin the other half: that the daemon
//! reads the variable and logs the line, and that an untouched daemon
//! says nothing.

// Test-harness arithmetic over a fixed deadline.
#![allow(clippy::arithmetic_side_effects)]

use std::ffi::OsStr;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The line the daemon logs once it is serving peers, after the server
/// state has been built.
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
        Some(value) => command.env("DCROXIDE_READ_AHEAD", value),
        None => command.env_remove("DCROXIDE_READ_AHEAD"),
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

/// The lines that mention the read-ahead or its variable.
fn read_ahead_lines(lines: &[String]) -> Vec<&str> {
    lines
        .iter()
        .map(String::as_str)
        .filter(|line| line.contains("DCROXIDE_READ_AHEAD") || line.contains("ead-ahead"))
        .collect()
}

/// Unset, the daemon reads ahead and logs nothing about it.
#[test]
fn an_unset_read_ahead_says_nothing() {
    let lines = startup_lines(None);
    assert!(read_ahead_lines(&lines).is_empty(), "{}", lines.join("\n"));
}

/// `off` and `0` turn the read-ahead off, and the daemon says so.
#[test]
fn read_ahead_is_turned_off_and_logged() {
    for setting in ["off", "0"] {
        let lines = startup_lines(Some(OsStr::new(setting)));
        assert_eq!(
            read_ahead_lines(&lines),
            vec!["[INF] DCRD: Read-ahead of blocks disabled by DCROXIDE_READ_AHEAD"],
            "{setting}:\n{}",
            lines.join("\n")
        );
    }
}

/// A value that is neither is ignored with a warning, and the daemon
/// starts with its default.
#[test]
fn a_bad_read_ahead_setting_warns_and_is_ignored() {
    let lines = startup_lines(Some(OsStr::new("sometimes")));
    assert_eq!(
        read_ahead_lines(&lines),
        vec!["[WRN] DCRD: DCROXIDE_READ_AHEAD=sometimes is neither off nor 0; using the default"],
        "{}",
        lines.join("\n")
    );
}

/// A value that is not valid Unicode is a value that means nothing, not
/// an unset variable: the daemon warns, showing the bytes it could not
/// read as the replacement character, and starts with its default.
#[cfg(unix)]
#[test]
fn a_read_ahead_setting_that_is_not_unicode_warns() {
    use std::os::unix::ffi::OsStrExt;

    let lines = startup_lines(Some(OsStr::from_bytes(&[0xff])));
    assert_eq!(
        read_ahead_lines(&lines),
        vec!["[WRN] DCRD: DCROXIDE_READ_AHEAD=\u{fffd} is neither off nor 0; using the default"],
        "{}",
        lines.join("\n")
    );
}
