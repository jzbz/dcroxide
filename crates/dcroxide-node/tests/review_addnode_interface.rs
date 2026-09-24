// SPDX-License-Identifier: ISC
//! `addnode` with an interface name, over the running daemon.
//!
//! dcrd's `normalizeAddress` looks the host up as a network interface
//! (`net.InterfaceByName`) and dials the interface's first address.  The
//! port had the substitution behind the `InterfaceLookup` seam, but the
//! daemon installed `NoInterfaces`, so `addnode lo:<port> onetry` tried
//! to resolve the host name `lo` instead of dialing 127.0.0.1.

// The pipe descriptor is re-opened through /proc/self/fd, and the
// interface lookup is netlink's.
#![cfg(target_os = "linux")]
// Test-harness arithmetic over bounded buffers and a fixed deadline.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
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

/// One JSON-RPC request over plain HTTP with basic credentials; the
/// response.
fn rpc_call(addr: &str, method: &str, params: &str) -> String {
    let body = format!(r#"{{"jsonrpc":"1.0","id":1,"method":"{method}","params":{params}}}"#);
    let mut stream = TcpStream::connect(addr).expect("connect to the RPC server");
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
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

/// Kills the daemon however the test ends.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn addnode_dials_an_interface_at_its_address() {
    // A stand-in peer on the loopback interface's first address.
    let peer = TcpListener::bind("127.0.0.1:0").expect("bind the stand-in peer");
    peer.set_nonblocking(true).expect("nonblocking");
    let port = peer.local_addr().expect("local addr").port();

    let appdata = tempfile::tempdir().expect("appdata");
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .args([
            "--simnet",
            "--noseeders",
            "--noexistsaddrindex",
            "--nolisten",
            "--rpclisten=127.0.0.1:0",
            "--notls",
            "--rpcuser=user",
            "--rpcpass=pass",
            // The bound RPC address arrives over the pipe.
            "--pipetx=2",
            "--boundaddrevents",
        ])
        .arg(format!("--appdata={}", appdata.path().display()))
        .env_remove("DCROXIDE_APPDATA")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcroxide");
    let mut pipe = child.stderr.take().expect("stderr pipe");
    let _daemon = Daemon(child);
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
    let addr = loop {
        if let Some(addr) = rpc_listen_addr(&collected.lock().expect("sink")) {
            break addr;
        }
        assert!(
            Instant::now() < deadline,
            "the RPC listener never announced its address"
        );
        std::thread::sleep(Duration::from_millis(50));
    };

    // The call answers once the dial settles; the connection arriving
    // is what shows where it went.
    let response = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&response);
    std::thread::spawn(move || {
        let reply = rpc_call(&addr, "addnode", &format!(r#"["lo:{port}","onetry"]"#));
        *slot.lock().expect("slot") = Some(reply);
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match peer.accept() {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("accept: {e}"),
        }
        assert!(
            Instant::now() < deadline,
            "the daemon never dialed 127.0.0.1:{port}; addnode answered {:?}",
            response.lock().expect("slot")
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
