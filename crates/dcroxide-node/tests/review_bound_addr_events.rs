// SPDX-License-Identifier: ISC
//! `--boundaddrevents` against dcrd: `initListeners` sends one
//! `p2plistenaddr` pipe message per bound peer-to-peer listener and
//! `setupRPCListeners` one `rpclistenaddr` per bound RPC listener, each
//! carrying Go's `listener.Addr().String()`.  The port parsed the flag
//! and sent nothing, so a parent that started the node on an ephemeral
//! port never learned it.

// The pipe descriptor is re-opened through /proc/self/fd.
#![cfg(target_os = "linux")]
// Test-harness arithmetic over bounded buffers and a fixed deadline.
#![allow(clippy::arithmetic_side_effects)]

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The bound-address messages in a byte stream, as (type, payload), in
/// order, skipping anything that is not one of the two framed kinds
/// (dcrd `ipc.go`: version 1, the type length and type, the
/// little-endian payload length and the payload).
fn bound_addr_messages(bytes: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &bytes[i..];
        let framed = ["p2plistenaddr", "rpclistenaddr"].iter().find(|kind| {
            rest.len() >= 2 + kind.len() + 4
                && rest[0] == 1
                && rest[1] as usize == kind.len()
                && &rest[2..2 + kind.len()] == kind.as_bytes()
        });
        let Some(kind) = framed else {
            i += 1;
            continue;
        };
        let at = 2 + kind.len();
        let len = u32::from_le_bytes(rest[at..at + 4].try_into().expect("four bytes")) as usize;
        if rest.len() < at + 4 + len {
            break;
        }
        let payload = String::from_utf8_lossy(&rest[at + 4..at + 4 + len]).into_owned();
        out.push((kind.to_string(), payload));
        i += at + 4 + len;
    }
    out
}

#[test]
fn bound_listener_addresses_reach_the_pipe() {
    let appdata = tempfile::tempdir().expect("appdata");
    // Stderr is the pipe the parent reads: the daemon re-opens
    // descriptor 2 as its --pipetx writer.
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .args([
            "--simnet",
            "--noseeders",
            "--noexistsaddrindex",
            "--listen=127.0.0.1:0",
            "--rpclisten=127.0.0.1:0",
            "--rpcuser=user",
            "--rpcpass=pass",
            "--pipetx=2",
            "--boundaddrevents",
        ])
        .arg(format!("--appdata={}", appdata.path().display()))
        .env_remove("DCRD_APPDATA")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcroxide");

    let mut pipe = child.stderr.take().expect("stderr pipe");
    let collected = Arc::new(Mutex::new(Vec::<u8>::new()));
    let sink = Arc::clone(&collected);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = pipe.read(&mut buf) {
            if n == 0 {
                break;
            }
            sink.lock().expect("sink").extend_from_slice(&buf[..n]);
        }
    });

    let deadline = Instant::now() + Duration::from_secs(60);
    let messages = loop {
        let messages = bound_addr_messages(&collected.lock().expect("sink"));
        if messages.len() >= 2 || Instant::now() > deadline {
            break messages;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let _ = child.kill();
    let _ = child.wait();

    let kinds: Vec<&str> = messages.iter().map(|(kind, _)| kind.as_str()).collect();
    assert_eq!(
        kinds,
        ["p2plistenaddr", "rpclistenaddr"],
        "one message per listener, the peer-to-peer ones first as dcrd's \
         newServer binds them first: {messages:?}"
    );
    for (_, addr) in &messages {
        let port = addr
            .strip_prefix("127.0.0.1:")
            .unwrap_or_else(|| panic!("the bound address: {addr}"));
        assert_ne!(
            port.parse::<u16>().expect("a port"),
            0,
            "the address is the one bound, not the one asked for"
        );
    }
}
