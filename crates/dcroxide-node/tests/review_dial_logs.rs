// SPDX-License-Identifier: ISC
//! The dial lifecycle lines dcrd prints for a `--connect` peer that
//! refuses the connection.
//!
//! dcrd's `attemptDcrdDial` adds the dial target to the address manager
//! and marks it attempted, logging `Marking address as attempted
//! failed: %v` at error level under SRVR when the manager does not hold
//! it, which it never does for an unroutable address such as loopback
//! (`server.go:1931-1937`).  Its connection manager logs each attempt,
//! failure and retry under CMGR at debug level
//! (`internal/connmgr/connmanager.go:927, 949, 1958`).  The port
//! discarded the attempt error and printed none of the CMGR lines.
//!
//! The run is on testnet: dcrd skips the address bookkeeping on simnet
//! and regnet.  `--connect` turns off automatic dialing and seeding, so
//! nothing leaves the host.

#![cfg(target_os = "linux")]
// Test-harness arithmetic over a fixed deadline.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[test]
fn a_refused_connect_peer_logs_dcrds_dial_lines() {
    // A loopback port nothing listens on.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let target = closed.local_addr().expect("addr").to_string();
    drop(closed);

    let appdata = tempfile::tempdir().expect("tempdir");
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .args([
            "--testnet",
            "--nolisten",
            "--norpc",
            "--noseeders",
            "--debuglevel=CMGR=debug",
        ])
        .arg(format!("--appdata={}", appdata.path().display()))
        .arg(format!("--connect={target}"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");

    // Each stdout line, its timestamp cut off, as `[LVL] TAG: message`.
    let (lines_tx, lines) = mpsc::channel::<String>();
    let stdout = child.stdout.take().expect("stdout");
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Some(at) = line.find(" [") {
                let _ = lines_tx.send(line[at + 1..].to_string());
            }
        }
    });

    let attempting = format!("[DBG] CMGR: Attempting to connect to {target} (id: ");
    let marking =
        format!("[ERR] SRVR: Marking address as attempted failed: address {target} not found");
    let failed = format!(
        "[DBG] CMGR: Failed to connect to {target}: dial tcp {target}: connect: connection refused"
    );
    let retrying = format!("[DBG] CMGR: Retrying connection to {target} in ");

    let mut seen: Vec<String> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(90);
    while !seen.iter().any(|l| l.starts_with(&retrying)) {
        let left = deadline.saturating_duration_since(Instant::now());
        match lines.recv_timeout(left) {
            Ok(line) => seen.push(line),
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();

    let at = |prefix: &str| {
        seen.iter()
            .position(|l| l.starts_with(prefix))
            .unwrap_or_else(|| panic!("missing {prefix:?} in {seen:#?}"))
    };
    let attempt = at(&attempting);
    assert!(
        seen[attempt].ends_with(", type: manual)"),
        "a --connect peer is a manual connection: {}",
        seen[attempt]
    );
    let (mark, fail, retry) = (at(&marking), at(&failed), at(&retrying));
    assert!(
        attempt < mark && mark < fail && fail < retry,
        "the lines come in dcrd's order: {seen:#?}"
    );
    assert!(
        seen[retry].ends_with(" (retries 1)"),
        "the first retry: {}",
        seen[retry]
    );
}
