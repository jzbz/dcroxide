// SPDX-License-Identifier: ISC
//! The daemon's RPC startup log lines against dcrd's: `genCertPair`
//! announces the certificate generation and its completion, a listen
//! address that cannot be bound is `Can't listen on %s: %v` and startup
//! carries on, and `Run` logs `RPC server listening on %s` once per
//! listener.  The port logged nothing around the generation and one
//! joined line for all listeners, and any bind failure aborted startup.

// 127.0.0.2 is a loopback address only on Linux.
#![cfg(target_os = "linux")]
// Test-harness arithmetic over a fixed deadline.
#![allow(clippy::arithmetic_side_effects)]

use std::io::Read;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Start the daemon with the given RPC listen addresses, collect stdout
/// until `count` listener lines have appeared or the deadline passes,
/// then stop it.
fn stdout_until_listening(rpclisten: &[String], count: usize) -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .arg("--simnet")
        .arg("--nolisten")
        .arg("--noseeders")
        .arg(format!("--appdata={}", dir.path().display()))
        .arg("--rpcuser=user")
        .arg("--rpcpass=pass")
        .args(rpclisten.iter().map(|addr| format!("--rpclisten={addr}")))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dcroxide");

    let mut out = child.stdout.take().expect("stdout pipe");
    let collected = Arc::new(Mutex::new(String::new()));
    let sink = Arc::clone(&collected);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = out.read(&mut buf) {
            if n == 0 {
                break;
            }
            sink.lock()
                .expect("sink")
                .push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    });

    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let listening = collected
            .lock()
            .expect("sink")
            .matches("RPC server listening on ")
            .count();
        if listening >= count || Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    collected.lock().expect("sink").clone()
}

#[test]
fn rpc_startup_logs_match_dcrd() {
    let busy = TcpListener::bind("127.0.0.1:0").expect("occupy a port");
    let busy_addr = busy.local_addr().expect("busy addr").to_string();
    let stdout = stdout_until_listening(
        &[
            "127.0.0.1:0".to_string(),
            "127.0.0.2:0".to_string(),
            busy_addr.clone(),
        ],
        2,
    );

    // dcrd `genCertPair`, bracketing the generation of the missing pair.
    let generating = stdout
        .find("[INF] RPCS: Generating TLS certificates...")
        .unwrap_or_else(|| panic!("no generation line: {stdout}"));
    let done = stdout
        .find("[INF] RPCS: Done generating TLS certificates")
        .unwrap_or_else(|| panic!("no completion line: {stdout}"));
    assert!(generating < done, "{stdout}");

    // dcrd `setupRPCListeners` warns about the unbindable address and
    // carries on with the rest.
    assert!(
        stdout.contains(&format!("[WRN] RPCS: Can't listen on {busy_addr}: ")),
        "{stdout}"
    );

    // dcrd `Run`: one line per listener.
    let listening: Vec<&str> = stdout
        .lines()
        .filter(|line| line.contains("[INF] RPCS: RPC server listening on "))
        .collect();
    assert_eq!(listening.len(), 2, "{stdout}");
    assert!(
        listening[0].contains("RPC server listening on 127.0.0.1:"),
        "{stdout}"
    );
    assert!(
        listening[1].contains("RPC server listening on 127.0.0.2:"),
        "{stdout}"
    );
    assert!(
        listening.iter().all(|line| !line.contains(", ")),
        "each listener is its own line: {stdout}"
    );
}
