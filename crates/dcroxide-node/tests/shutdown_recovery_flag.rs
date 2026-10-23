// SPDX-License-Identifier: ISC
//! What the daemon's shutdown leaves in the header of the metadata store.
//!
//! redb keeps a recovery flag set in the header of `metadata.redb` while
//! it has the file open for writing, and clears it only in the close its
//! handle's drop runs (redb-4.3.0 `page_manager.rs:1458-1469`,
//! `page_manager.rs:2466-2486`).  The daemon logged "Shutdown complete"
//! with the flag still set: the block database's close flushed and
//! recorded the allocator state but left redb's handle to the drop of the
//! last clone of the database handle, and the chain's clone never drops.
//! The chain sits in a reference cycle (its notification callback holds
//! the notification handler, which holds the transaction pool, which
//! holds the chain), so the handle lived until the process exited.  Every
//! start then began by recovering the file, and redb refused to open a
//! stopped node's store read-only ("Database repair aborted").  The
//! close now lets go of redb's handle itself.
//!
//! A regnet daemon mines blocks more than its one-second flush interval
//! apart, so that their commits trip flushes the store's commit thread
//! makes (`dbcommit`), and is stopped:
//!
//! - by the `stop` RPC, and by an interrupt: the flag is clear;
//! - by `SIGKILL`: the flag is set, and the next open of the store
//!   repairs it, as before.

#![cfg(unix)]
// Test-harness arithmetic over deadlines a minute away.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dcroxide_database::{Database, LogLevel, Options};

/// The metadata store's first repair line, as the operator docs quote it.
const REDB_REPAIR: &str = "Detected unclean shutdown of the metadata store - Repairing...";

/// Kills a daemon however the test ends.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// How a test stops the daemon.
#[derive(Clone, Copy, Debug)]
enum Stop {
    /// The `stop` RPC.
    Rpc,
    /// `SIGINT`, as Ctrl-C sends it.
    Interrupt,
    /// `SIGKILL`: no shutdown at all.
    Kill,
}

/// Collect everything a pipe carries, on a thread of its own, which ends
/// when the pipe's writer has gone.
fn collect(
    mut pipe: impl Read + Send + 'static,
) -> (Arc<Mutex<Vec<u8>>>, std::thread::JoinHandle<()>) {
    let collected = Arc::new(Mutex::new(Vec::<u8>::new()));
    let sink = Arc::clone(&collected);
    let reader = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = pipe.read(&mut buf) {
            if n == 0 {
                break;
            }
            sink.lock().expect("sink").extend_from_slice(&buf[..n]);
        }
    });
    (collected, reader)
}

/// The payload of the first `rpclistenaddr` pipe message in the stream
/// (dcrd `ipc.go` framing).
fn rpc_listen_addr(bytes: &[u8]) -> Option<String> {
    const KIND: &[u8] = b"rpclistenaddr";
    let at = bytes
        .windows(KIND.len().saturating_add(2))
        .position(|w| w[0] == 1 && w[1] as usize == KIND.len() && &w[2..] == KIND)?;
    let len_at = at.saturating_add(2).saturating_add(KIND.len());
    let len_end = len_at.saturating_add(4);
    let len = u32::from_le_bytes(bytes.get(len_at..len_end)?.try_into().ok()?) as usize;
    let payload = bytes.get(len_end..len_end.saturating_add(len))?;
    Some(String::from_utf8_lossy(payload).into_owned())
}

/// One JSON-RPC request over plain HTTP with the `user`/`pass`
/// credentials; the response body.
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
    let response = String::from_utf8_lossy(&response).into_owned();
    match response.split_once("\r\n\r\n") {
        Some((_, body)) => body.to_string(),
        None => response,
    }
}

/// The regnet block database under an application data directory.
fn regnet_db_path(appdata: &Path) -> PathBuf {
    appdata.join("data").join("regnet").join("blocks_ffldb")
}

/// Whether the header of the metadata file in `db_path` has redb's
/// recovery flag set: bit 1 of the byte after the nine-byte magic number
/// (redb-4.3.0 `header.rs:46-62`).
fn recovery_flag(db_path: &Path) -> bool {
    let header = std::fs::read(db_path.join("metadata.redb")).expect("read the metadata file");
    header[9] & 0b10 != 0
}

/// What one run of the daemon left.
struct Ran {
    status: ExitStatus,
    log: String,
    flushes: String,
}

/// Run a regnet daemon in `appdata`, mine three blocks more than its
/// one-second flush interval apart, and stop it as `stop` says.
fn run(appdata: &Path, stop: Stop) -> Ran {
    let params = dcroxide_chaincfg::regnet_params();
    let mining_addr = dcroxide_txscript::stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(
        &[0x5a; 20],
        &params,
    )
    .expect("mining address")
    .encode();
    let flush_log = appdata.join("flushes.jsonl");
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .arg("--regnet")
        .arg(format!("--appdata={}", appdata.display()))
        .args([
            "--noseeders",
            "--nolisten",
            "--rpclisten=127.0.0.1:0",
            "--notls",
            "--rpcuser=user",
            "--rpcpass=pass",
            // The bound RPC address arrives over the pipe.
            "--pipetx=2",
            "--boundaddrevents",
        ])
        .arg(format!("--miningaddr={mining_addr}"))
        .env_remove("DCRD_APPDATA")
        .env_remove("DCROXIDE_DB_SYNC_COMMIT")
        .env("DCROXIDE_DB_FLUSHLOG", &flush_log)
        .env("DCROXIDE_DB_FLUSH_SECS", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcroxide");
    let (events, _) = collect(child.stderr.take().expect("stderr pipe"));
    let (log, log_reader) = collect(child.stdout.take().expect("stdout pipe"));
    let mut daemon = KillOnDrop(child);
    let log_text = || String::from_utf8_lossy(&log.lock().expect("log")).into_owned();

    let deadline = Instant::now() + Duration::from_secs(60);
    let addr = loop {
        if let Some(addr) = rpc_listen_addr(&events.lock().expect("events")) {
            break addr;
        }
        assert!(
            Instant::now() < deadline,
            "the RPC listener never announced its address: {}",
            log_text()
        );
        std::thread::sleep(Duration::from_millis(50));
    };

    for _ in 0..3 {
        // Longer than the flush interval, so the block's commits find it
        // elapsed and trip a flush.
        std::thread::sleep(Duration::from_millis(1500));
        let mined = rpc_call(&addr, "generate", "[1]");
        assert!(mined.contains(r#""error":null"#), "{mined}");
    }
    // The last block's flush, if it was handed over, has landed.
    let deadline = Instant::now() + Duration::from_secs(10);
    while !std::fs::read_to_string(&flush_log)
        .unwrap_or_default()
        .contains(r#""thread":"dbcommit""#)
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(20));
    }

    let pid = daemon.0.id().to_string();
    match stop {
        Stop::Rpc => {
            let stopped = rpc_call(&addr, "stop", "[]");
            assert!(stopped.contains("dcrd stopping."), "{stopped}");
        }
        Stop::Interrupt => {
            let sent = Command::new("kill").args(["-INT", &pid]).status();
            assert!(sent.expect("run kill").success(), "SIGINT was not sent");
        }
        Stop::Kill => {
            let sent = Command::new("kill").args(["-9", &pid]).status();
            assert!(sent.expect("run kill").success(), "SIGKILL was not sent");
        }
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = daemon.0.try_wait().expect("wait") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "the daemon never stopped: {}",
            log_text()
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    // The daemon held the pipe's only writing end, so the collector reads
    // to its end now.
    log_reader.join().expect("log reader");
    Ran {
        status,
        log: log_text(),
        flushes: std::fs::read_to_string(&flush_log).unwrap_or_default(),
    }
}

/// Run the daemon and stop it cleanly as `stop` says; the flag must be
/// clear afterwards, and redb must open the store with no repair.
fn assert_clean_stop(stop: Stop) {
    let appdata = tempfile::tempdir().expect("appdata");
    let ran = run(appdata.path(), stop);
    assert!(
        ran.status.success(),
        "{stop:?}: {:?}: {}",
        ran.status,
        ran.log
    );
    assert!(
        ran.log
            .contains("Gracefully shutting down the block database...")
            && ran.log.contains("Shutdown complete"),
        "{stop:?}: {}",
        ran.log
    );
    assert!(
        !ran.log.contains("Unable to close the block database"),
        "{stop:?}: {}",
        ran.log
    );
    assert!(
        ran.flushes.contains(r#""thread":"dbcommit""#),
        "{stop:?}: no flush was made on the commit thread, so this run shows nothing: {}",
        ran.flushes
    );
    let db_path = regnet_db_path(appdata.path());
    assert!(
        !recovery_flag(&db_path),
        "{stop:?}: a clean shutdown left redb's recovery flag set: {}",
        ran.log
    );

    let lines: Arc<Mutex<Vec<String>>> = Arc::default();
    let mut opts = Options::new(&db_path, dcroxide_chaincfg::regnet_params().net.0);
    {
        let lines = Arc::clone(&lines);
        opts.log = Some(Arc::new(move |_, msg: &str| {
            lines.lock().expect("log lock").push(msg.to_string());
        }));
    }
    let db = Database::open(&opts).expect("open the stopped node's store");
    db.close().expect("close");
    assert!(
        !lines
            .lock()
            .expect("log lock")
            .iter()
            .any(|msg| msg.to_lowercase().contains("metadata store")),
        "{stop:?}: the store was repaired after a clean shutdown: {:?}",
        lines.lock().expect("log lock")
    );
}

/// The `stop` RPC shuts the daemon down cleanly, and the store's header
/// says so.
#[test]
fn the_stop_rpc_leaves_the_recovery_flag_clear() {
    assert_clean_stop(Stop::Rpc);
}

/// So does an interrupt.
#[test]
fn an_interrupt_leaves_the_recovery_flag_clear() {
    assert_clean_stop(Stop::Interrupt);
}

/// A daemon killed outright leaves the flag set, and the next open of its
/// store repairs it and logs the repair.
#[test]
fn a_killed_daemon_leaves_the_flag_set_and_the_next_open_repairs() {
    let appdata = tempfile::tempdir().expect("appdata");
    let ran = run(appdata.path(), Stop::Kill);
    assert!(!ran.status.success(), "{:?}: {}", ran.status, ran.log);
    assert!(!ran.log.contains("Shutdown complete"), "{}", ran.log);
    let db_path = regnet_db_path(appdata.path());
    assert!(
        recovery_flag(&db_path),
        "a killed daemon's store lost redb's recovery flag"
    );

    let lines: Arc<Mutex<Vec<(LogLevel, String)>>> = Arc::default();
    let mut opts = Options::new(&db_path, dcroxide_chaincfg::regnet_params().net.0);
    {
        let lines = Arc::clone(&lines);
        opts.log = Some(Arc::new(move |level, msg: &str| {
            lines
                .lock()
                .expect("log lock")
                .push((level, msg.to_string()));
        }));
    }
    let db = Database::open(&opts).expect("open the killed node's store");
    assert!(
        lines
            .lock()
            .expect("log lock")
            .iter()
            .any(|(level, msg)| *level == LogLevel::Info && msg == REDB_REPAIR),
        "the repair must be logged as {REDB_REPAIR:?}: {:?}",
        lines.lock().expect("log lock")
    );
    db.close().expect("close the repaired store");
    assert!(
        !recovery_flag(&db_path),
        "the repaired store's clean close left the flag set"
    );
}
