// SPDX-License-Identifier: ISC
//! The daemon's log output when stdout stops taking writes.  dcrd's
//! `logWriter` discards the result of `os.Stdout.Write`, so a terminal
//! that hung up or a full disk behind a redirect never stops it, and
//! only a broken pipe does: Go's runtime kills the process with
//! `SIGPIPE` for `EPIPE` on descriptor 1.  The port logged through
//! `println!`, which panics on any failed write, so the first log line
//! after the failure aborted the node.

#![cfg(target_os = "linux")]
// Test-harness arithmetic over a fixed deadline.
#![allow(clippy::arithmetic_side_effects)]

use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Run the daemon to a startup failure dcrd reports as `Unable to start
/// server` and exit one (a zero relay fee), with stdout on `stdout`.
fn run_failing_startup(appdata: &Path, stdout: Stdio) -> ExitStatus {
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .arg("--simnet")
        .arg(format!("--appdata={}", appdata.display()))
        .args([
            "--minrelaytxfee=0",
            "--noexistsaddrindex",
            "--nolisten",
            "--norpc",
            "--noseeders",
        ])
        .env_remove("DCRD_APPDATA")
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dcroxide");
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = child.try_wait().expect("wait") {
            return status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("the daemon kept running");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Every write to /dev/full fails with `ENOSPC`, which dcrd ignores: the
/// node runs on to its own exit.
#[test]
fn a_full_stdout_does_not_stop_the_node() {
    let appdata = tempfile::tempdir().expect("appdata");
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("open /dev/full");
    let status = run_failing_startup(appdata.path(), Stdio::from(full));
    assert_eq!(
        status.code(),
        Some(1),
        "the node must reach its own startup failure, not abort: {status:?}"
    );
}

/// A pipe with no reader fails every write with `EPIPE`, which ends
/// dcrd at once through `SIGPIPE`; the port exits at once with the
/// status a shell reports for that death.
#[test]
fn a_broken_stdout_pipe_ends_the_node_as_sigpipe_does() {
    let appdata = tempfile::tempdir().expect("appdata");
    let (reader, writer) = std::io::pipe().expect("pipe");
    drop(reader);
    let status = run_failing_startup(appdata.path(), Stdio::from(writer));
    assert_eq!(
        status.code(),
        Some(128 + 13),
        "a broken stdout pipe must end the node like SIGPIPE: {status:?}"
    );
}
