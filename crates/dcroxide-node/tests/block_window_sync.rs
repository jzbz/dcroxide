// SPDX-License-Identifier: ISC
//! A daemon syncs a chain of blocks from another daemon through each
//! block download window.
//!
//! The window the daemon syncs with by default is not dcrd's (PARITY
//! *Block download window*): its first request is for up to 128 blocks
//! where dcrd's is for 16.  What the sync manager asks for under each
//! window is pinned by its own tests
//! (`crates/dcroxide-netsync/tests/block_window.rs`).  This test is the
//! two ends together: one daemon mines a simnet chain five times as
//! long as dcrd's window, which the default window asks for in one
//! request, and two more sync it from that daemon over the loopback
//! interface, one with the default window and one with dcrd's put back
//! by `DCROXIDE_BLOCK_WINDOW=dcrd`.  Both reach the miner's tip,
//! neither has its sync peer dropped as stalled, and the default window
//! is not narrowed on the way.
//!
//! The chain is no longer than that because simnet's difficulty rises
//! with every block mined faster than its one-second target: the next
//! fifty blocks take the CPU miner a minute and more.

// The bound addresses arrive over a pipe the daemon re-opens through
// /proc/self/fd.
#![cfg(target_os = "linux")]
// Test-harness arithmetic over a fixed deadline and small counts.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The blocks the miner mines: five of dcrd's windows, all within the
/// 128 blocks the default window requests at first, and short of the
/// height from which simnet blocks need votes (144).
const NUM_BLOCKS: i64 = 80;

/// Kills a daemon however the test ends.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A running daemon, what it has written to its pipe and to its log so
/// far, and its application data directory.
struct Daemon {
    _child: KillOnDrop,
    pipe: Arc<Mutex<Vec<u8>>>,
    log: Arc<Mutex<Vec<u8>>>,
    _appdata: tempfile::TempDir,
}

/// Collect everything read from `source` until it ends.
fn collect(mut source: impl Read + Send + 'static) -> Arc<Mutex<Vec<u8>>> {
    let collected = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&collected);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = source.read(&mut buf) {
            if n == 0 {
                break;
            }
            sink.lock().expect("sink").extend_from_slice(&buf[..n]);
        }
    });
    collected
}

/// Start a simnet daemon with its own data directory, an RPC server on a
/// port of its choosing and no seeders, so it touches nothing beyond the
/// loopback interface.  `window` is its `DCROXIDE_BLOCK_WINDOW`.
fn daemon(args: &[String], window: Option<&str>) -> Daemon {
    let appdata = tempfile::tempdir().expect("appdata");
    let mut command = Command::new(env!("CARGO_BIN_EXE_dcroxide"));
    command
        .args([
            "--simnet",
            "--noseeders",
            "--noexistsaddrindex",
            "--rpclisten=127.0.0.1:0",
            "--notls",
            "--rpcuser=user",
            "--rpcpass=pass",
            // The bound addresses arrive over the pipe.
            "--pipetx=2",
            "--boundaddrevents",
        ])
        .arg(format!("--appdata={}", appdata.path().display()))
        .args(args)
        .env_remove("DCRD_APPDATA")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match window {
        Some(value) => command.env("DCROXIDE_BLOCK_WINDOW", value),
        None => command.env_remove("DCROXIDE_BLOCK_WINDOW"),
    };
    let mut child = command.spawn().expect("spawn dcroxide");
    let pipe = collect(child.stderr.take().expect("stderr pipe"));
    let log = collect(child.stdout.take().expect("stdout"));
    Daemon {
        _child: KillOnDrop(child),
        pipe,
        log,
        _appdata: appdata,
    }
}

impl Daemon {
    /// The payload of the first pipe message of the kind (dcrd `ipc.go`
    /// framing), once the daemon has sent it.
    fn bound_addr(&self, kind: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(addr) = framed_payload(&self.pipe.lock().expect("pipe"), kind.as_bytes()) {
                return addr;
            }
            assert!(
                Instant::now() < deadline,
                "the daemon never announced its {kind}:\n{}",
                self.log_text()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Everything the daemon has logged so far.
    fn log_text(&self) -> String {
        String::from_utf8_lossy(&self.log.lock().expect("log")).into_owned()
    }
}

/// The payload of the first pipe message of the kind in the stream.
fn framed_payload(bytes: &[u8], kind: &[u8]) -> Option<String> {
    let at = bytes
        .windows(2 + kind.len())
        .position(|w| w[0] == 1 && w[1] as usize == kind.len() && &w[2..] == kind)?;
    let len_at = at + 2 + kind.len();
    let len = u32::from_le_bytes(bytes.get(len_at..len_at + 4)?.try_into().ok()?) as usize;
    let payload = bytes.get(len_at + 4..len_at + 4 + len)?;
    Some(String::from_utf8_lossy(payload).into_owned())
}

/// One JSON-RPC request over plain HTTP with the `user`/`pass`
/// credentials; the response body, or `None` when the server could not
/// be reached.
fn rpc_call(addr: &str, method: &str, params: &str) -> Option<String> {
    let body = format!(r#"{{"jsonrpc":"1.0","id":1,"method":"{method}","params":{params}}}"#);
    let mut stream = TcpStream::connect(addr).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .expect("timeout");
    write!(
        stream,
        "POST / HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .ok()?;
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let response = String::from_utf8_lossy(&response).into_owned();
    Some(match response.split_once("\r\n\r\n") {
        Some((_, body)) => body.to_string(),
        None => response,
    })
}

/// The numeric result of a JSON-RPC response, if it has one.
fn number_result(response: &str) -> Option<i64> {
    let rest = response.split_once(r#""result":"#)?.1;
    rest[..rest.find([',', '}'])?].parse().ok()
}

/// The string result of a JSON-RPC response.
fn string_result(response: &str) -> String {
    let rest = response
        .split_once(r#""result":""#)
        .unwrap_or_else(|| panic!("no string result: {response}"))
        .1;
    rest[..rest.find('"').expect("closing quote")].to_string()
}

/// Sync a new daemon from the miner with the given window setting and
/// return its log once its tip is the miner's.
fn synced_log(miner_p2p: &str, tip: &str, window: Option<&str>) -> String {
    let syncer = daemon(
        &["--nolisten".to_string(), format!("--connect={miner_p2p}")],
        window,
    );
    let rpc = syncer.bound_addr("rpclistenaddr");
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let height = rpc_call(&rpc, "getblockcount", "[]")
            .as_deref()
            .and_then(number_result);
        if height == Some(NUM_BLOCKS) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the daemon with window {window:?} stopped at {height:?} of {NUM_BLOCKS} blocks:\n{}",
            syncer.log_text()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let best = rpc_call(&rpc, "getbestblockhash", "[]").expect("best block");
    assert_eq!(string_result(&best), tip, "window {window:?}");
    syncer.log_text()
}

#[test]
fn a_daemon_syncs_a_chain_through_either_window() {
    let params = dcroxide_chaincfg::simnet_params();
    assert!(NUM_BLOCKS < params.stake_validation_height);
    let mining_addr = dcroxide_txscript::stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(
        &[0x5a; 20],
        &params,
    )
    .expect("mining address");
    let miner = daemon(
        &[
            "--listen=127.0.0.1:0".to_string(),
            format!("--miningaddr={}", mining_addr.encode()),
        ],
        None,
    );
    let miner_p2p = miner.bound_addr("p2plistenaddr");
    let miner_rpc = miner.bound_addr("rpclistenaddr");
    let mined = rpc_call(&miner_rpc, "generate", &format!("[{NUM_BLOCKS}]")).expect("generate");
    assert!(
        mined.contains(r#""error":null"#),
        "{mined}\n{}",
        miner.log_text()
    );
    let tip = string_result(&rpc_call(&miner_rpc, "getbestblockhash", "[]").expect("tip"));

    // The default window: nothing is said about it, and it stays at its
    // full width.
    let log = synced_log(&miner_p2p, &tip, None);
    assert!(!log.contains("download window"), "{log}");
    assert!(!log.contains("appears to be stalled"), "{log}");

    // dcrd's window, from the same binary.
    let log = synced_log(&miner_p2p, &tip, Some("dcrd"));
    assert!(
        log.contains(
            "[INF] DCRD: Block download window set to dcrd's 16 blocks in flight by \
             DCROXIDE_BLOCK_WINDOW"
        ),
        "{log}"
    );
    assert!(!log.contains("appears to be stalled"), "{log}");
}
