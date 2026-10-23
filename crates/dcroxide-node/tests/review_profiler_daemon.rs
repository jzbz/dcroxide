// SPDX-License-Identifier: ISC
//! `startprofiler`, `stopprofiler` and `--profile` over the running
//! daemon.
//!
//! The daemon handed the RPC server the `()` stand-in for the profile
//! server manager, so every `startprofiler` answered -8 "unable to start
//! profile server: RPC server seam start is not wired in this build",
//! even for an address dcrd refuses up front, and `--profile` skipped the
//! start dcrd's `dcrdMain` makes, so an address dcrd's `Start` refuses
//! after the configuration accepted it left the daemon running where dcrd
//! logs the refusal and exits one.  `profiler_vectors.rs` covers the
//! manager and the RPC dispatch; this drives the daemon binary, so it
//! fails if `rpc_config` or `run_node` stops handing them the manager.

// The pipe descriptor is re-opened through /proc/self/fd.
#![cfg(target_os = "linux")]
// Test-harness arithmetic over bounded buffers and a fixed deadline.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The text every trait default reports (`server.rs` `unwired_seam`).
const UNWIRED: &str = "is not wired in this build";

/// The reply to an address dcrd would listen on.
const NOT_PORTED_REPLY: &str = r#"{"jsonrpc":"1.0","result":null,"error":{"code":-8,"message":"unable to start profile server: the profile server is not part of this port of dcrd"},"id":1}"#;

/// dcrd's reply to `stopprofiler` with no server running.
const NOT_STARTED_REPLY: &str = r#"{"jsonrpc":"1.0","result":null,"error":{"code":-26,"message":"profile server is not started"},"id":1}"#;

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
/// response body, without the newline dcrd ends it with.
fn rpc_call(addr: &str, method: &str, params: &str) -> String {
    let body = format!(r#"{{"jsonrpc":"1.0","method":"{method}","params":{params},"id":1}}"#);
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
    let response = String::from_utf8_lossy(&response).into_owned();
    match response.split_once("\r\n\r\n") {
        Some((_, body)) => body.trim_end().to_string(),
        None => response,
    }
}

/// Kills the daemon however the test ends.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Start the daemon on simnet with the RPC server on an ephemeral
/// loopback port and no peer listener, plus `args`; the daemon and the
/// RPC server's bound address, which arrives over the pipe.
fn start_daemon(appdata: &Path, args: &[&str]) -> (Daemon, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .args([
            "--simnet",
            "--nolisten",
            "--noseeders",
            "--rpclisten=127.0.0.1:0",
            "--notls",
            "--rpcuser=user",
            "--rpcpass=pass",
            // The bound RPC address arrives over the pipe.
            "--pipetx=2",
            "--boundaddrevents",
        ])
        .args(args)
        .arg(format!("--appdata={}", appdata.display()))
        .env_remove("DCROXIDE_APPDATA")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcroxide");
    let mut pipe = child.stderr.take().expect("stderr pipe");
    let daemon = Daemon(child);
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
    (daemon, addr)
}

/// The daemon's RPC server answers dcrd's refusals byte for byte, the
/// four a dcrd 2.1.7 node gave dcrctl among them, and the deliberate
/// refusal where dcrd listens; `stopprofiler` then finds no server.
#[test]
fn the_daemon_answers_startprofiler_with_dcrds_checks() {
    let appdata = tempfile::tempdir().expect("appdata");
    let (_daemon, addr) = start_daemon(appdata.path(), &[]);

    let refused = [
        (
            r#"["bogus"]"#,
            r#"{"jsonrpc":"1.0","result":null,"error":{"code":-8,"message":"unable to start profile server: address bogus: missing port in address"},"id":1}"#,
        ),
        (
            r#"["127.0.0.1"]"#,
            r#"{"jsonrpc":"1.0","result":null,"error":{"code":-8,"message":"unable to start profile server: address 127.0.0.1: missing port in address"},"id":1}"#,
        ),
        (
            r#"["192.0.2.1:20104"]"#,
            r#"{"jsonrpc":"1.0","result":null,"error":{"code":-8,"message":"unable to start profile server: not permitted to listen on non loopback address \"192.0.2.1:20104\" without setting the flag to allow it"},"id":1}"#,
        ),
        (
            r#"["127.0.0.1:80"]"#,
            r#"{"jsonrpc":"1.0","result":null,"error":{"code":-8,"message":"unable to start profile server: address \"127.0.0.1:80\": port must be between 1024 and 65535"},"id":1}"#,
        ),
        (
            r#"["localhost:20104",true]"#,
            r#"{"jsonrpc":"1.0","result":null,"error":{"code":-8,"message":"unable to start profile server: 'localhost' is not a valid IP address"},"id":1}"#,
        ),
    ];
    for (params, reply) in refused {
        let got = rpc_call(&addr, "startprofiler", params);
        assert!(!got.contains(UNWIRED), "{params}: {got}");
        assert_eq!(got, reply, "{params}");
    }
    for params in [r#"["127.0.0.1:20103"]"#, r#"["20103"]"#] {
        assert_eq!(
            rpc_call(&addr, "startprofiler", params),
            NOT_PORTED_REPLY,
            "{params}"
        );
    }
    assert_eq!(rpc_call(&addr, "stopprofiler", "[]"), NOT_STARTED_REPLY);
}

/// A `--profile` address dcrd would listen on starts nothing and does not
/// stop the daemon, and `startprofiler` still makes its checks, where
/// dcrd's running server answers "profile server is already running"
/// (PARITY.md, the daemon row).
#[test]
fn a_profile_flag_dcrd_would_serve_leaves_the_daemon_running() {
    let appdata = tempfile::tempdir().expect("appdata");
    let (_daemon, addr) = start_daemon(appdata.path(), &["--profile=127.0.0.1:20103"]);
    assert_eq!(
        rpc_call(&addr, "startprofiler", r#"["127.0.0.1:20103"]"#),
        NOT_PORTED_REPLY
    );
    assert_eq!(rpc_call(&addr, "stopprofiler", "[]"), NOT_STARTED_REPLY);
}

/// Run the daemon on simnet to completion, bounded so a daemon that idles
/// instead of exiting fails the test rather than hanging it; returns the
/// status and stdout.
fn run_to_exit(appdata: &Path, args: &[&str]) -> (ExitStatus, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .arg("--simnet")
        .arg(format!("--appdata={}", appdata.display()))
        .args(args)
        .env_remove("DCROXIDE_APPDATA")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dcroxide");
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if child.try_wait().expect("wait").is_some() {
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let out = child.wait_with_output().expect("output");
            panic!(
                "the daemon kept running: {}",
                String::from_utf8_lossy(&out.stdout)
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().expect("output");
    (
        out.status,
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// The configuration accepts any `host:port` for `--profile`, and dcrd's
/// `dcrdMain` then starts the profile server with addresses that are not
/// loopback allowed (`dcrd.go:118-126`).  A host `parseListeners` refuses
/// fails that start: dcrd logs `unable to start profile server: ...` as a
/// warning and exits one, before it loads the block database, and its
/// deferred `Shutdown complete` follows.  The port started normally.
#[test]
fn a_profile_flag_dcrd_cannot_start_ends_the_daemon() {
    for (flag, err) in [
        (
            "--profile=localhost:6060",
            "'localhost' is not a valid IP address",
        ),
        (
            "--profile=127.0.0.1%lo:6060",
            "'127.0.0.1%lo' is not a valid IP address",
        ),
    ] {
        let appdata = tempfile::tempdir().expect("appdata");
        let (status, stdout) = run_to_exit(
            appdata.path(),
            &[flag, "--nolisten", "--norpc", "--noseeders"],
        );
        assert_eq!(status.code(), Some(1), "{flag}: {status:?}: {stdout}");
        let line = format!("[WRN] DCRD: unable to start profile server: {err}");
        let warned = stdout
            .find(&line)
            .unwrap_or_else(|| panic!("{flag}: no {line:?}: {stdout}"));
        let complete = stdout
            .find("[INF] DCRD: Shutdown complete")
            .unwrap_or_else(|| panic!("{flag}: no shutdown line: {stdout}"));
        assert!(warned < complete, "{flag}: {stdout}");
        assert!(
            !stdout.contains("Loading block database"),
            "{flag}: no block database: {stdout}"
        );
    }
}
