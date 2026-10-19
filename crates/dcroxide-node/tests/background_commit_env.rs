// SPDX-License-Identifier: ISC
//! Where the daemon makes the redb commit of a metadata flush that a
//! commit trips: on a thread of its own by default, and on the committing
//! thread when `DCROXIDE_DB_SYNC_COMMIT` is set to a positive whole
//! number.
//!
//! The switch decides what a measurement of the two compares, so it is
//! read back from the daemon itself.  A simnet daemon is started with a
//! one-second flush interval and mines three blocks more than a second
//! apart, so the commits of the later blocks each trip a flush of their
//! own; its flush log (`DCROXIDE_DB_FLUSHLOG`) then says, line by line,
//! whether a flush was asked for (`explicit`), whether its commit ran on
//! a thread of its own (`bg`) and which thread ended it (`thread`).
//!
//! The flushes the daemon asks for, at shutdown, commit on the thread
//! that asked whatever the variable says: they acknowledge durability.
//!
//! On Linux the daemon's threads are listed too, after each block's flush
//! and before the stop: by default one thread named `dbcommit` is there
//! from the first flush handed to it on, the same one each time, asleep
//! between flushes, and with the variable set there is none.
//!
//! A commit made on a thread of its own holds a read snapshot of the
//! store while it runs (`snap`), and one made on the thread that ran the
//! flush is given none, unless the operating system refused the thread
//! it was to be handed to, which no run here meets.

#![cfg(unix)]
// Test-harness arithmetic over deadlines a minute away.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The variable that puts every commit on the committing thread.
const VAR: &str = "DCROXIDE_DB_SYNC_COMMIT";

/// Kills a daemon however the test ends.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
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

/// What one run of the daemon left: its log, its flush log's lines, and
/// what each look at its threads found.
struct Ran {
    log: String,
    flushes: Vec<String>,
    looks: Vec<Look>,
}

/// One look at the daemon's threads.
#[derive(Debug)]
struct Look {
    /// The flush log's lines of tripped flushes just before the look.
    tripped: usize,
    /// The ids of the daemon's threads named `dbcommit`.
    committers: Vec<u32>,
}

/// The lines of tripped flushes in the flush log at `path` so far.  A
/// flush's line is written when it has landed, on the thread that wrote
/// it, so a line here means that thread had started.
fn tripped_so_far(path: &std::path::Path) -> usize {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| line.contains(r#""explicit":false"#))
        .count()
}

/// Look at the threads of the process `pid`, on Linux; elsewhere, find
/// none.  The flush log at `flush_log` is read first, so that a thread
/// its lines speak of is there by the time the threads are listed.
fn look(pid: u32, flush_log: &std::path::Path) -> Look {
    let tripped = tripped_so_far(flush_log);
    let mut committers = Vec::new();
    if cfg!(target_os = "linux") {
        for task in std::fs::read_dir(format!("/proc/{pid}/task")).expect("the daemon's threads") {
            let Ok(task) = task else { continue };
            let Ok(name) = std::fs::read_to_string(task.path().join("comm")) else {
                continue;
            };
            if name.trim_end() == "dbcommit" {
                let tid = task.file_name().to_string_lossy().parse::<u32>();
                committers.push(tid.expect("a thread id"));
            }
        }
    }
    Look {
        tripped,
        committers,
    }
}

impl Ran {
    /// The lines of the flushes a commit's own check tripped.
    fn tripped(&self) -> Vec<&String> {
        self.flushes
            .iter()
            .filter(|line| line.contains(r#""explicit":false"#))
            .collect()
    }

    /// The lines of the flushes the daemon asked for.
    fn asked_for(&self) -> Vec<&String> {
        self.flushes
            .iter()
            .filter(|line| line.contains(r#""explicit":true"#))
            .collect()
    }

    /// Assert that, on Linux, every look taken once a tripped flush had
    /// landed found exactly one thread named `dbcommit`, and the same one
    /// each time: the store keeps its commit thread between flushes.
    fn assert_one_commit_thread(&self) {
        if !cfg!(target_os = "linux") {
            return;
        }
        let after: Vec<&Look> = self.looks.iter().filter(|l| l.tripped > 0).collect();
        assert!(
            !after.is_empty(),
            "no look followed a tripped flush, so this run shows nothing: {:?}",
            self.looks
        );
        let first = &after[0].committers;
        assert_eq!(
            first.len(),
            1,
            "not one commit thread after a tripped flush: {:?}",
            self.looks
        );
        for look in &after {
            assert_eq!(
                &look.committers, first,
                "the commit thread changed or went: {:?}",
                self.looks
            );
        }
    }

    /// Assert that no look found a thread named `dbcommit`.
    fn assert_no_commit_thread(&self) {
        assert!(
            !self.looks.is_empty() && self.looks.iter().all(|l| l.committers.is_empty()),
            "a commit thread was started: {:?}",
            self.looks
        );
    }
}

/// Run a simnet daemon with `VAR` set to `value`, or unset for `None`,
/// mine three blocks more than its one-second flush interval apart, and
/// stop it.
fn run(value: Option<&str>) -> Ran {
    let params = dcroxide_chaincfg::simnet_params();
    let mining_addr = dcroxide_txscript::stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(
        &[0x5a; 20],
        &params,
    )
    .expect("mining address")
    .encode();
    let appdata = tempfile::tempdir().expect("appdata");
    let flush_log = appdata.path().join("flushes.jsonl");
    let mut command = Command::new(env!("CARGO_BIN_EXE_dcroxide"));
    command
        .arg("--simnet")
        .arg(format!("--appdata={}", appdata.path().display()))
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
        .env_remove(VAR)
        .env("DCROXIDE_DB_FLUSHLOG", &flush_log)
        .env("DCROXIDE_DB_FLUSH_SECS", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(value) = value {
        command.env(VAR, value);
    }
    let mut child = command.spawn().expect("spawn dcroxide");
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

    let pid = daemon.0.id();
    let mut looks = Vec::new();
    for _ in 0..3 {
        // Longer than the flush interval, so the next block's commits
        // find it elapsed and flush on their own.
        std::thread::sleep(Duration::from_millis(1500));
        let before = tripped_so_far(&flush_log);
        let mined = rpc_call(&addr, "generate", "[1]");
        assert!(mined.contains(r#""error":null"#), "{mined}");
        // Once the block's flush is in the log, and a moment after, by
        // which a thread made for that flush alone would have ended.
        let deadline = Instant::now() + Duration::from_secs(10);
        while tripped_so_far(&flush_log) == before && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        std::thread::sleep(Duration::from_millis(200));
        looks.push(look(pid, &flush_log));
    }
    looks.push(look(pid, &flush_log));

    let _ = rpc_call(&addr, "stop", "[]");
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
    let log = log_text();
    assert!(status.success(), "{status:?}: {log}");
    assert!(log.contains("Server shutdown complete"), "{log}");
    assert!(
        !log.contains("Background commit of the metadata write cache failed"),
        "{log}"
    );
    let flushes = std::fs::read_to_string(&flush_log).expect("the flush log");
    assert!(flushes.ends_with("}\n"), "whole lines: {flushes:?}");
    Ran {
        log,
        flushes: flushes.lines().map(str::to_string).collect(),
        looks,
    }
}

/// By default every flush a commit trips makes its commit on the thread
/// named `dbcommit`, and the flushes the daemon asks for do not.  The
/// thread is the store's own: once a tripped flush has landed, one thread
/// of that name is there at every look, the same one, between flushes too.
#[test]
fn the_daemon_commits_tripped_flushes_on_a_thread_of_their_own_by_default() {
    let ran = run(None);
    ran.assert_one_commit_thread();
    let tripped = ran.tripped();
    assert!(
        !tripped.is_empty(),
        "no commit tripped a flush, so this run shows nothing: {:?}",
        ran.flushes
    );
    for line in &tripped {
        assert!(
            line.contains(r#""bg":true"#) && line.contains(r#""thread":"dbcommit""#),
            "a tripped flush committed on the committing thread: {line}"
        );
        assert!(
            line.contains(r#""snap":true"#),
            "a handed-over commit held no read snapshot: {line}"
        );
        // What the flush pinned and the process's memory around it.
        assert!(
            line.contains(r#""layers":{"pinned":"#) && line.contains(r#""overlay":{"handoff":"#),
            "{line}"
        );
        #[cfg(target_os = "linux")]
        assert!(
            line.contains(r#""mem":{"capture":{"rss":"#)
                && line.contains(r#""handoff":{"rss":"#)
                && line.contains(r#""commit":{"rss":"#),
            "the process's memory was not read around the flush: {line}"
        );
    }
    let asked_for = ran.asked_for();
    assert!(
        !asked_for.is_empty(),
        "the shutdown flush is missing: {:?}",
        ran.flushes
    );
    for line in &asked_for {
        assert!(
            line.contains(r#""bg":false"#) && !line.contains(r#""thread":"dbcommit""#),
            "a flush the daemon asked for was handed over: {line}"
        );
        assert!(line.contains(r#""snap":false"#), "{line}");
    }
    assert!(
        !ran.log.contains(VAR),
        "a default was announced as a setting: {}",
        ran.log
    );
}

/// `DCROXIDE_DB_SYNC_COMMIT=1` puts every commit back on the thread that
/// ran the flush, and the daemon says so once.  No commit thread is ever
/// started.
#[test]
fn sync_commit_keeps_every_flush_on_the_committing_thread() {
    let ran = run(Some("1"));
    ran.assert_no_commit_thread();
    assert!(
        !ran.tripped().is_empty(),
        "no commit tripped a flush, so this run shows nothing: {:?}",
        ran.flushes
    );
    for line in &ran.flushes {
        assert!(
            line.contains(r#""bg":false"#) && !line.contains(r#""thread":"dbcommit""#),
            "a flush was handed over: {line}"
        );
        // With the commit on the flushing thread, that thread spent the
        // whole flush in it and waited for no other.
        assert!(line.contains(r#""wait_ms":0.000"#), "{line}");
        // Nor is a commit made there given a snapshot of its own.
        assert!(line.contains(r#""snap":false"#), "{line}");
    }
    assert_eq!(
        ran.log
            .matches(
                "Metadata write cache commits on the committing thread by DCROXIDE_DB_SYNC_COMMIT"
            )
            .count(),
        1,
        "{}",
        ran.log
    );
}

/// A value that is not a positive whole number is a warning, and the
/// default stays in force.
#[test]
fn a_malformed_sync_commit_value_warns_and_keeps_the_default() {
    let ran = run(Some("0"));
    ran.assert_one_commit_thread();
    let tripped = ran.tripped();
    assert!(!tripped.is_empty(), "{:?}", ran.flushes);
    for line in &tripped {
        assert!(line.contains(r#""bg":true"#), "{line}");
    }
    assert!(
        ran.log
            .contains("DCROXIDE_DB_SYNC_COMMIT=0 is not a positive whole number"),
        "{}",
        ran.log
    );
}
