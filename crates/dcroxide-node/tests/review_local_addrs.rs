// SPDX-License-Identifier: ISC
//! `--externalip` against dcrd: `initListeners` adds every external
//! address to the address manager at manual priority, so the handshake
//! can advertise it to outbound peers and `getnetworkinfo` lists it
//! under `localaddresses`.  The port read the option only to switch off
//! address discovery and registered nothing, so a node behind NAT never
//! advertised itself and `localaddresses` stayed empty.

// The pipe descriptor is re-opened through /proc/self/fd.
#![cfg(target_os = "linux")]
// Test-harness arithmetic over bounded buffers and a fixed deadline.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The payload of the first `rpclistenaddr` pipe message in the stream
/// (dcrd `ipc.go` framing).
fn rpc_listen_addr(bytes: &[u8]) -> Option<String> {
    const KIND: &[u8] = b"rpclistenaddr";
    let at = bytes
        .windows(2 + KIND.len())
        .position(|w| w[0] == 1 && w[1] as usize == KIND.len() && &w[2..] == KIND)?;
    let len_at = at + 2 + KIND.len();
    let len = u32::from_le_bytes(bytes.get(len_at..len_at + 4)?.try_into().ok()?) as usize;
    let payload = bytes.get(len_at + 4..len_at + 4 + len)?;
    Some(String::from_utf8_lossy(payload).into_owned())
}

/// One JSON-RPC request over plain HTTP with basic credentials.
fn rpc_call(addr: &str, method: &str) -> String {
    let body = format!(r#"{{"jsonrpc":"1.0","id":1,"method":"{method}","params":[]}}"#);
    let mut stream = TcpStream::connect(addr).expect("connect to the RPC server");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    write!(
        stream,
        "POST / HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("send the request");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response).into_owned()
}

#[test]
fn external_ips_are_listed_as_local_addresses() {
    let appdata = tempfile::tempdir().expect("appdata");
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .args([
            "--simnet",
            "--noseeders",
            "--noexistsaddrindex",
            "--listen=127.0.0.1:0",
            "--rpclisten=127.0.0.1:0",
            "--notls",
            "--rpcuser=user",
            "--rpcpass=pass",
            "--externalip=1.2.3.4:18555",
            // The bound RPC address arrives over the pipe.
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
    let rpc_addr = loop {
        if let Some(addr) = rpc_listen_addr(&collected.lock().expect("sink")) {
            break Some(addr);
        }
        if Instant::now() > deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let response = rpc_addr
        .as_deref()
        .map(|addr| rpc_call(addr, "getnetworkinfo"));
    let _ = child.kill();
    let _ = child.wait();

    let response = response.expect("the RPC listener announced its address");
    assert!(
        response.contains(r#""localaddresses":[{"address":"1.2.3.4","port":18555,"score":0}]"#),
        "{response}"
    );
}
