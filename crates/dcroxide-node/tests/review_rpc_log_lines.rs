// SPDX-License-Identifier: ISC
//! The daemon's RPCS lines for authentication failures, internal errors
//! and websocket protocol violations, over a running node.
//!
//! dcrd installs its RPC server's package logger at startup
//! (`rpcserver.UseLogger(rpcsLog)`, `log.go:96`) and so logs every
//! failed Basic auth ("RPC authentication failure from <addr>"), every
//! internal error with its context (`rpcInternalErr`), the websocket
//! client that skips or repeats `authenticate`, and, at debug, every
//! websocket command it parses.  The port's
//! RPC crate had no logger, so an operator watching for the
//! authentication warning saw nothing.

#![cfg(target_os = "linux")]
// Test-harness arithmetic over a fixed deadline.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Kills the daemon however the test ends.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Wait until the collected stdout contains `needle`, returning it.
fn wait_for(collected: &Mutex<String>, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let out = collected.lock().expect("sink").clone();
        if out.contains(needle) {
            return out;
        }
        assert!(Instant::now() < deadline, "no {needle:?} in: {out}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// One JSON-RPC request over plain HTTP with the given Basic
/// credentials (base64); the response, and the client's address.
fn rpc_post(addr: &str, basic: &str, body: &str) -> (String, String) {
    let mut stream = TcpStream::connect(addr).expect("connect to the RPC server");
    let local = stream.local_addr().expect("local addr").to_string();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("timeout");
    write!(
        stream,
        "POST / HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Basic {basic}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("send the request");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    (String::from_utf8_lossy(&response).into_owned(), local)
}

/// An upgraded `/ws` connection without credentials, and its address.
fn websocket(addr: &str) -> (TcpStream, String) {
    let mut stream = TcpStream::connect(addr).expect("connect to the RPC server");
    let local = stream.local_addr().expect("local addr").to_string();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("timeout");
    write!(
        stream,
        "GET /ws HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    .expect("send the upgrade");
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).expect("read head");
        head.push(byte[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 101"), "{head:?}");
    (stream, local)
}

/// Write a masked client text frame.
fn send_frame(stream: &mut TcpStream, payload: &[u8]) {
    assert!(payload.len() < 126, "short payloads only");
    let mask = [0x12u8, 0x34, 0x56, 0x78];
    let mut frame = vec![0x81, 0x80 | payload.len() as u8];
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i & 3]));
    stream.write_all(&frame).expect("write frame");
}

/// Read one short server text frame's payload.
fn read_frame(stream: &mut TcpStream) -> String {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).expect("read frame header");
    assert_eq!(header[0], 0x81, "a final text frame");
    let mut payload = vec![0u8; usize::from(header[1] & 0x7f)];
    stream.read_exact(&mut payload).expect("read frame payload");
    String::from_utf8(payload).expect("utf8 payload")
}

#[test]
fn rpc_failures_are_logged_as_dcrd_logs_them() {
    let appdata = tempfile::tempdir().expect("appdata");
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .args([
            "--simnet",
            "--noseeders",
            "--nolisten",
            "--rpclisten=127.0.0.1:0",
            "--notls",
            "--rpcuser=user",
            "--rpcpass=pass",
            "--debuglevel=RPCS=debug",
        ])
        .arg(format!("--appdata={}", appdata.path().display()))
        .env_remove("DCROXIDE_APPDATA")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dcroxide");
    let mut out = child.stdout.take().expect("stdout pipe");
    let _daemon = Daemon(child);
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
    let listening = wait_for(&collected, "RPC server listening on ");
    let addr = listening
        .split("RPC server listening on ")
        .nth(1)
        .and_then(|rest| rest.lines().next())
        .expect("the listener address")
        .trim()
        .to_string();

    // A wrong password: `checkAuthMAC`'s warning names the client.
    // "user:wrong" in base64.
    let (response, client) = rpc_post(&addr, "dXNlcjp3cm9uZw==", "{}");
    assert!(response.starts_with("HTTP/1.1 401"), "{response}");
    wait_for(
        &collected,
        &format!("[WRN] RPCS: RPC authentication failure from {client}\n"),
    );

    // An internal error: `rpcInternalErr` logs its context.  "user:pass".
    let zero_txid = "0".repeat(64);
    let (response, _) = rpc_post(
        &addr,
        "dXNlcjpwYXNz",
        &format!(
            r#"{{"jsonrpc":"1.0","id":1,"method":"getrawtransaction","params":["{zero_txid}"]}}"#
        ),
    );
    assert!(response.contains("specify --txindex"), "{response}");
    wait_for(
        &collected,
        "[ERR] RPCS: Configuration: the transaction index must be enabled to query the \
         blockchain (specify --txindex)\n",
    );

    // A websocket client that talks before authenticating: the command
    // is logged at debug as it parses, then the warning.
    let (mut ws, client) = websocket(&addr);
    send_frame(
        &mut ws,
        br#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":1}"#,
    );
    let out = wait_for(
        &collected,
        "[WRN] RPCS: Unauthenticated websocket message received\n",
    );
    let received = format!("[DBG] RPCS: Received command <getblockcount> from {client}\n");
    let received_at = out.find(&received).expect("the received-command line");
    let warned_at = out
        .find("[WRN] RPCS: Unauthenticated websocket message")
        .expect("the warning");
    assert!(received_at < warned_at, "{out}");
    drop(ws);

    // One that authenticates with the wrong passphrase.
    let (mut ws, client) = websocket(&addr);
    send_frame(
        &mut ws,
        br#"{"jsonrpc":"1.0","method":"authenticate","params":["user","nope"],"id":1}"#,
    );
    wait_for(
        &collected,
        &format!("[WRN] RPCS: RPC authentication failure from {client}\n"),
    );
    drop(ws);

    // And one that authenticates twice.
    let (mut ws, client) = websocket(&addr);
    let authenticate =
        br#"{"jsonrpc":"1.0","method":"authenticate","params":["user","pass"],"id":1}"#;
    send_frame(&mut ws, authenticate);
    let reply = read_frame(&mut ws);
    assert!(reply.contains(r#""error":null"#), "{reply}");
    send_frame(&mut ws, authenticate);
    wait_for(
        &collected,
        &format!("[WRN] RPCS: Websocket client {client} is already authenticated\n"),
    );
}
