// SPDX-License-Identifier: ISC
//! The `--lifetimeevents` sequence and the lifecycle log lines against
//! dcrd's `dcrdMain`:
//!
//! - The startup `P2PServer` event goes out just ahead of `newServer`,
//!   which is where the chain loads and the indexes catch up, so a
//!   parent sees those phases as the server starting.  The port sent it
//!   only once they were done, and a server that failed to build never
//!   sent it at all.
//! - The shutdown `P2PServer` event is deferred once startup completes,
//!   so it fires after `svr.Run` has returned and `Server shutdown
//!   complete` is logged.  The port sent it as the teardown began.
//! - `--assumevalid` logs `Assume valid is disabled` or `Assume valid
//!   set to <hash>`, and a bad value fails `newServer` as `Unable to
//!   start server: invalid hex for --assumevalid: ...`.  Ahead of it,
//!   `--allowoldforks` logs `Processing forks deep in history is
//!   enabled`, which the port never logged.
//! - A `stop` request logs `Shutdown requested.  Shutting down...`, the
//!   server `Server shutting down`, and the missing-config warning goes
//!   out under DCRD rather than a MAIN tag no `--debuglevel` reaches.

// The pipe descriptor is re-opened through /proc/self/fd.
#![cfg(target_os = "linux")]
// Test-harness arithmetic over bounded buffers and fixed deadlines.
#![allow(clippy::arithmetic_side_effects)]

use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Startup event, startup complete and shutdown event (dcrd `ipc.go`).
const STARTUP: u8 = 0;
const COMPLETE: u8 = 1;
const SHUTDOWN: u8 = 2;
/// The two lifetime actions.
const DB_OPEN: u8 = 0;
const P2P_SERVER: u8 = 1;

/// The framed pipe messages in a byte stream, as (type, payload), in
/// order (dcrd `ipc.go`: version 1, the type length and type, the
/// little-endian payload length and the payload), skipping any byte
/// that does not start one.
fn pipe_messages(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    const KINDS: [&str; 3] = ["lifetimeevent", "p2plistenaddr", "rpclistenaddr"];
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &bytes[i..];
        let framed = KINDS.iter().find(|kind| {
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
        out.push((kind.to_string(), rest[at + 4..at + 4 + len].to_vec()));
        i += at + 4 + len;
    }
    out
}

/// The lifetime events in a byte stream, as (event, action).
fn lifetime_events(bytes: &[u8]) -> Vec<(u8, u8)> {
    pipe_messages(bytes)
        .into_iter()
        .filter(|(kind, payload)| kind == "lifetimeevent" && payload.len() == 2)
        .map(|(_, payload)| (payload[0], payload[1]))
        .collect()
}

/// The bound RPC address a `rpclistenaddr` message announced.
fn rpc_listen_addr(bytes: &[u8]) -> Option<String> {
    pipe_messages(bytes)
        .into_iter()
        .find(|(kind, _)| kind == "rpclistenaddr")
        .map(|(_, payload)| String::from_utf8_lossy(&payload).into_owned())
}

/// Kills the daemon however the test ends.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Spawn the simnet daemon with its log going to `log` and its stderr
/// -- the `--pipetx=2` descriptor -- collected as it arrives.
fn spawn(appdata: &Path, log: &Path, args: &[&str]) -> (Daemon, Arc<Mutex<Vec<u8>>>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .arg("--simnet")
        .arg(format!("--appdata={}", appdata.display()))
        .args([
            "--pipetx=2",
            "--lifetimeevents",
            "--noexistsaddrindex",
            "--noseeders",
        ])
        .args(args)
        .env_remove("DCROXIDE_APPDATA")
        .stdout(Stdio::from(File::create(log).expect("log file")))
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
    (Daemon(child), collected)
}

/// Wait for the daemon to exit, bounded so one that keeps running fails
/// the test rather than hanging it.
fn wait_exit(daemon: &mut Daemon, log: &Path) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = daemon.0.try_wait().expect("wait") {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "the daemon kept running: {}",
            read_log(log)
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Poll the collected pipe bytes until `ready` holds for them.
fn wait_for<T>(collected: &Mutex<Vec<u8>>, what: &str, ready: impl Fn(&[u8]) -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(found) = ready(&collected.lock().expect("sink")) {
            return found;
        }
        assert!(Instant::now() < deadline, "{what} never arrived");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn read_log(log: &Path) -> String {
    std::fs::read_to_string(log).unwrap_or_default()
}

/// The position of `line` in the log, which must hold it.
fn position(log: &str, line: &str) -> usize {
    log.find(line)
        .unwrap_or_else(|| panic!("missing {line:?}:\n{log}"))
}

/// One JSON-RPC request over plain HTTP with basic credentials; the
/// response body.
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

/// A server that fails to build has already announced itself: dcrd
/// sends the startup `P2PServer` event ahead of `newServer`, where the
/// bad `--assumevalid` is refused, then its deferred `DBOpen` shutdown
/// event.  The error text is dcrd's, under `Unable to start server`.
#[test]
fn a_failed_server_build_follows_dcrds_events_and_text() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("stdout.log");
    let missing_config = dir.path().join("missing.conf");
    let (mut daemon, collected) = spawn(
        &dir.path().join("appdata"),
        &log,
        &[
            "--assumevalid=xyz",
            "--nolisten",
            "--norpc",
            &format!("--configfile={}", missing_config.display()),
        ],
    );
    let status = wait_exit(&mut daemon, &log);
    let text = read_log(&log);
    assert_eq!(status.code(), Some(1), "{text}");
    assert_eq!(
        lifetime_events(&collected.lock().expect("sink")),
        [
            (STARTUP, DB_OPEN),
            (STARTUP, P2P_SERVER),
            (SHUTDOWN, DB_OPEN)
        ],
        "{text}"
    );
    // The whole line: server.go's wrap around hex.InvalidByteError's text.
    position(
        &text,
        "[ERR] DCRD: Unable to start server: invalid hex for --assumevalid: \
         encoding/hex: invalid byte: U+0078 'x'\n",
    );
    // The missing configuration file is dcrdLog's warning.
    position(
        &text,
        &format!("[WRN] DCRD: open {}: ", missing_config.display()),
    );
}

/// dcrd logs what `--assumevalid` did before the chain loads: exactly
/// "0" disables it and any other value overrides the network's hash.
/// `--allowoldforks` is announced just ahead of it, and only when set.
/// `--dumpblockchain` stops each run once the chain has loaded.
#[test]
fn assume_valid_logs_dcrds_lines() {
    const OLD_FORKS: &str = "[INF] SRVR: Processing forks deep in history is enabled";
    let hash = "000000000000000000000000000000000000000000000000000000000000abcd";
    for (value, old_forks, line) in [
        (
            "0",
            false,
            "[INF] SRVR: Assume valid is disabled".to_string(),
        ),
        (
            hash,
            true,
            format!("[INF] SRVR: Assume valid set to {hash}"),
        ),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("stdout.log");
        let dump = dir.path().join("dump.bin");
        let mut args = vec![
            format!("--assumevalid={value}"),
            format!("--dumpblockchain={}", dump.display()),
            "--nolisten".to_string(),
            "--norpc".to_string(),
        ];
        if old_forks {
            args.push("--allowoldforks".to_string());
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let (mut daemon, _collected) = spawn(&dir.path().join("appdata"), &log, &args);
        let status = wait_exit(&mut daemon, &log);
        let text = read_log(&log);
        assert_eq!(status.code(), Some(1), "{text}");
        let at = position(&text, &line);
        assert!(
            at < position(&text, "[INF] CHAN: Loading block index..."),
            "{text}"
        );
        if old_forks {
            assert!(position(&text, OLD_FORKS) < at, "{text}");
        } else {
            assert!(!text.contains(OLD_FORKS), "{text}");
        }
    }
}

/// A `stop` request runs dcrd's whole shutdown: the listener's
/// `Shutdown requested` line, the server's `Server shutting down` and,
/// once the teardown is done, `Server shutdown complete`, and only then
/// the `P2PServer` shutdown event, then the database's.
#[test]
fn a_stop_request_follows_dcrds_shutdown_sequence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("stdout.log");
    let (mut daemon, collected) = spawn(
        &dir.path().join("appdata"),
        &log,
        &[
            "--listen=127.0.0.1:0",
            "--rpclisten=127.0.0.1:0",
            "--notls",
            "--rpcuser=user",
            "--rpcpass=pass",
            "--boundaddrevents",
        ],
    );
    let addr = wait_for(&collected, "the RPC address", rpc_listen_addr);
    wait_for(&collected, "startup complete", |bytes| {
        lifetime_events(bytes)
            .iter()
            .any(|(event, _)| *event == COMPLETE)
            .then_some(())
    });
    assert_eq!(
        lifetime_events(&collected.lock().expect("sink")),
        [
            (STARTUP, DB_OPEN),
            (STARTUP, P2P_SERVER),
            (COMPLETE, DB_OPEN)
        ]
    );

    let stopped = rpc_call(&addr, "stop", "[]");
    assert!(stopped.contains(r#""error":null"#), "{stopped}");

    // Everything logged before the event was queued is in the log file
    // by the time the event arrives.
    wait_for(&collected, "the P2P server shutdown event", |bytes| {
        lifetime_events(bytes)
            .contains(&(SHUTDOWN, P2P_SERVER))
            .then_some(())
    });
    let at_event = read_log(&log);
    let requested = position(
        &at_event,
        "[INF] DCRD: Shutdown requested.  Shutting down...",
    );
    let shutting = position(&at_event, "[WRN] SRVR: Server shutting down");
    let complete = position(&at_event, "[INF] SRVR: Server shutdown complete");
    assert!(requested < shutting && shutting < complete, "{at_event}");

    let status = wait_exit(&mut daemon, &log);
    let text = read_log(&log);
    assert_eq!(status.code(), Some(0), "{text}");
    assert_eq!(
        lifetime_events(&collected.lock().expect("sink")),
        [
            (STARTUP, DB_OPEN),
            (STARTUP, P2P_SERVER),
            (COMPLETE, DB_OPEN),
            (SHUTDOWN, P2P_SERVER),
            (SHUTDOWN, DB_OPEN),
        ],
        "{text}"
    );
    let closing = position(
        &text,
        "[INF] DCRD: Gracefully shutting down the block database...",
    );
    let done = position(&text, "[INF] DCRD: Shutdown complete");
    assert!(complete < closing && closing < done, "{text}");
}
