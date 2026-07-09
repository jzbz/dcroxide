// SPDX-License-Identifier: ISC
//! Integration checks for the dcroxide binary's configuration
//! front-end: the version, help, debug-level-show, and error command
//! line exits with dcrd's exit codes, and the successful startup path
//! that opens the block database and loads the genesis chain state
//! before idling on a shutdown signal.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

/// A unique application data directory under the system temp directory,
/// so a spawned daemon neither reads nor writes the real user
/// configuration and concurrent tests never share a data directory (and
/// its exclusively locked block database).  This is passed as --appdata
/// rather than via $HOME because on Windows the data directory is
/// resolved from the OS-native location (%LOCALAPPDATA%), where $HOME is
/// ignored, so an $HOME override would not isolate the run at all.  The
/// process id alone is not unique enough — tests in one binary share it
/// — so a per-call sequence number is mixed in.
fn isolated_appdata(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("dcroxide-cli-{tag}-{}-{seq}", std::process::id()))
}

fn run(args: &[&str]) -> (String, String, i32) {
    let appdata = isolated_appdata("run");
    let out = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .arg(format!("--appdata={}", appdata.display()))
        .args(args)
        .env_remove("DCRD_APPDATA")
        .output()
        .expect("run dcroxide binary");
    let _ = std::fs::remove_dir_all(&appdata);
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn version_exits_zero_with_version() {
    let (stdout, _, code) = run(&["--version"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("dcroxide version"), "stdout: {stdout}");
    assert!(stdout.contains("2.1.5+release.local"), "stdout: {stdout}");
}

#[test]
fn help_exits_zero() {
    let (stdout, _, code) = run(&["-h"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("Usage: dcroxide"), "stdout: {stdout}");
}

#[test]
fn debuglevel_show_lists_subsystems() {
    let (stdout, stderr, code) = run(&["--debuglevel=show"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("Supported subsystems"), "stdout: {stdout}");
    // A couple of the known subsystem identifiers.
    assert!(stdout.contains("DCRD"), "stdout: {stdout}");
    assert!(stdout.contains("SRVR"), "stdout: {stdout}");
}

#[test]
fn unknown_flag_exits_one_with_error() {
    let (_, stderr, code) = run(&["--thisisnotaflag"]);
    assert_eq!(code, 1);
    assert!(stderr.contains("unknown flag"), "stderr: {stderr}");
    assert!(stderr.contains("Use dcroxide -h"), "stderr: {stderr}");
}

/// Spawn the daemon with `args` (plus an isolated app data directory),
/// then wait up to 20s for a stdout or stderr line satisfying `wanted`,
/// returning that line.  On timeout the panic message includes every
/// line the daemon printed, so a startup failure on a CI platform that
/// cannot be reproduced locally is still diagnosable rather than a bare
/// "line never appeared".
fn wait_for_daemon_line(tag: &str, args: &[&str], wanted: impl Fn(&str) -> bool) -> String {
    let home = isolated_appdata(tag);
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .args(args)
        .arg(format!("--appdata={}", home.display()))
        .env_remove("DCRD_APPDATA")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcroxide binary");

    // Drain stdout and stderr on their own threads onto one channel, so
    // startup progress and any error diagnostics are captured together
    // and the wait can be time-bounded.
    let (tx, rx) = mpsc::channel();
    for stream in [
        Box::new(child.stdout.take().expect("piped stdout")) as Box<dyn std::io::Read + Send>,
        Box::new(child.stderr.take().expect("piped stderr")),
    ] {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
    }
    drop(tx);

    let mut seen = Vec::new();
    let mut found = None;
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(20) {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(line) if wanted(&line) => {
                found = Some(line);
                break;
            }
            Ok(line) => seen.push(line),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&home);

    found.unwrap_or_else(|| {
        panic!(
            "daemon did not print the expected startup line within 20s; captured output:\n{}",
            seen.join("\n")
        )
    })
}

#[test]
fn startup_opens_block_database_and_loads_genesis() {
    // --nolisten because this test is about the database, not the network.
    let loaded = wait_for_daemon_line("db", &["--nolisten"], |line| {
        line.contains("Block database loaded")
    });
    // A fresh database starts at the genesis block (height 0).
    assert!(
        loaded.contains("best block height 0"),
        "startup line: {loaded}"
    );
}

#[test]
fn startup_serves_peer_connections_on_a_listener() {
    // Bind an ephemeral loopback port so the test neither uses a fixed
    // port nor touches the network.  The helper panics with the captured
    // daemon output if the announcement never arrives.
    wait_for_daemon_line("listen", &["--listen=127.0.0.1:0"], |line| {
        line.contains("Serving peer-to-peer connections on 127.0.0.1:")
    });
}
