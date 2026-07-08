// SPDX-License-Identifier: ISC
//! Integration checks for the dcroxide binary's configuration
//! front-end: the version, help, debug-level-show, and error command
//! line exits with dcrd's exit codes, and the successful startup path
//! that opens the block database and loads the genesis chain state
//! before idling on a shutdown signal.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

fn run(args: &[&str]) -> (String, String, i32) {
    let out = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .args(args)
        // Use an isolated home so the run neither reads nor writes the
        // real user configuration.
        .env("HOME", std::env::temp_dir())
        .env_remove("DCRD_APPDATA")
        .output()
        .expect("run dcroxide binary");
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
    let (stdout, _, code) = run(&["--debuglevel=show"]);
    assert_eq!(code, 0);
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

#[test]
fn startup_opens_block_database_and_loads_genesis() {
    // Use an isolated home so a fresh block database is created under a
    // temporary directory and the run touches nothing else.
    let home = std::env::temp_dir().join(format!("dcroxide-cli-{}", std::process::id()));
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        // Do not bind a real listen port; this test is about the database.
        .arg("--nolisten")
        .env("HOME", &home)
        .env_remove("DCRD_APPDATA")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dcroxide binary");

    // Read startup lines on a background thread so the test can bound
    // how long it waits for the database-loaded announcement.
    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let mut loaded = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(line) if line.contains("Block database loaded") => {
                loaded = Some(line);
                break;
            }
            Ok(_) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&home);

    let loaded = loaded.expect("binary announced the block database was loaded");
    // A fresh database starts at the genesis block (height 0).
    assert!(
        loaded.contains("best block height 0"),
        "startup line: {loaded}"
    );
}

#[test]
fn startup_serves_peer_connections_on_a_listener() {
    // Bind an ephemeral loopback port so the test neither uses a fixed
    // port nor touches the network.
    let home = std::env::temp_dir().join(format!("dcroxide-cli-listen-{}", std::process::id()));
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .arg("--listen=127.0.0.1:0")
        .env("HOME", &home)
        .env_remove("DCRD_APPDATA")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dcroxide binary");

    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let mut serving = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(line) if line.contains("Serving peer-to-peer connections on 127.0.0.1:") => {
                serving = Some(line);
                break;
            }
            Ok(_) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&home);

    assert!(
        serving.is_some(),
        "binary should announce it is serving peers on the bound listener"
    );
}
