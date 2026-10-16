// SPDX-License-Identifier: ISC
//! A daemon syncs a chain of blocks from another daemon with the
//! read-ahead of blocks on and with it off.
//!
//! During the initial chain sync the daemon reads its sync peer's
//! connection ahead of the thread that connects the blocks (PARITY
//! *Reading ahead of the block handler*), which dcrd does not do, and
//! `DCROXIDE_READ_AHEAD=off` leaves that connection to its input thread
//! alone.  What the two ways of reading have in common is pinned at the
//! connection (`tests/read_ahead.rs`) and at the server
//! (`tests/dispatch.rs`).  This test is the two ends together: one
//! daemon mines a simnet chain and two more sync it from that daemon
//! over the loopback interface, one reading ahead and one not.  Both
//! reach the miner's tip, neither has its sync peer dropped, and the
//! line the one that read ahead logs as it shuts down says how many
//! blocks its reader thread read and hashed, and that no more than four
//! frames were ever queued.  The reader thread also hands each block on
//! with the payload it arrived in laid out as its block-file record,
//! which the daemon writes as it stands: the block files of the two
//! syncing daemons are the same byte for byte, and are the miner's.

// The bound addresses arrive over a pipe the daemon re-opens through
// /proc/self/fd.
#![cfg(target_os = "linux")]
// Test-harness arithmetic over a fixed deadline and small counts.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The blocks the miner mines: enough for the reader thread to run with
/// its queue full, and short of the height from which simnet blocks need
/// votes (144).
const NUM_BLOCKS: i64 = 64;

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
/// loopback interface.  `read_ahead` is its `DCROXIDE_READ_AHEAD`.
fn daemon(args: &[String], read_ahead: Option<&str>) -> Daemon {
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
            // The line that says a connection is read ahead is a debug
            // line of the peer subsystem.
            "--debuglevel=PEER=debug",
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
    match read_ahead {
        Some(value) => command.env("DCROXIDE_READ_AHEAD", value),
        None => command.env_remove("DCROXIDE_READ_AHEAD"),
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

    /// The daemon's block files, by name: every flat file its block
    /// database has written, as it stands on disk.
    fn block_files(&self) -> Vec<(String, Vec<u8>)> {
        let mut files = Vec::new();
        collect_block_files(self._appdata.path(), &mut files);
        files.sort();
        files
    }
}

/// Add every block file under the directory to `files`.
fn collect_block_files(dir: &Path, files: &mut Vec<(String, Vec<u8>)>) {
    for entry in std::fs::read_dir(dir).expect("read a data directory") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            collect_block_files(&path, files);
        } else if path.extension().is_some_and(|ext| ext == "fdb") {
            let name = path
                .file_name()
                .expect("name")
                .to_string_lossy()
                .into_owned();
            files.push((name, std::fs::read(&path).expect("read a block file")));
        }
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

/// Sync a new daemon from the miner with the given read-ahead setting,
/// stop it once its tip is the miner's, and return its whole log and
/// the block files it leaves.
fn synced(
    miner_p2p: &str,
    tip: &str,
    read_ahead: Option<&str>,
) -> (String, Vec<(String, Vec<u8>)>) {
    let syncer = daemon(
        &["--nolisten".to_string(), format!("--connect={miner_p2p}")],
        read_ahead,
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
            "the daemon with read-ahead {read_ahead:?} stopped at {height:?} of {NUM_BLOCKS} \
             blocks:\n{}",
            syncer.log_text()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let best = rpc_call(&rpc, "getbestblockhash", "[]").expect("best block");
    assert_eq!(string_result(&best), tip, "read-ahead {read_ahead:?}");

    // A clean shutdown, so that the daemon logs what its readers did.
    let _ = rpc_call(&rpc, "stop", "[]");
    let deadline = Instant::now() + Duration::from_secs(60);
    while !syncer.log_text().contains("Server shutdown complete") {
        assert!(
            Instant::now() < deadline,
            "the daemon with read-ahead {read_ahead:?} did not shut down:\n{}",
            syncer.log_text()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    (syncer.log_text(), syncer.block_files())
}

/// The whole number in `line` that ends where `after` begins.
fn number_before(line: &str, after: &str) -> u64 {
    let head = line
        .split_once(after)
        .unwrap_or_else(|| panic!("{after:?} is not in: {line}"))
        .0;
    let digits = head
        .rsplit(|c: char| !c.is_ascii_digit())
        .next()
        .expect("a last word");
    digits
        .parse()
        .unwrap_or_else(|_| panic!("no number before {after:?} in: {line}"))
}

#[test]
fn a_daemon_syncs_a_chain_with_and_without_read_ahead() {
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

    // Reading ahead, the default: the sync peer's connection gets its
    // reader thread behind the first block, and the daemon accounts for
    // it as it shuts down.
    let (log, ahead_files) = synced(&miner_p2p, &tip, None);
    assert!(!log.contains("DCROXIDE_READ_AHEAD"), "{log}");
    assert!(!log.contains("appears to be stalled"), "{log}");
    assert_eq!(
        log.matches("[DBG] PEER: Reading ahead of the block handler for peer ")
            .count(),
        1,
        "{log}"
    );
    let line = log
        .lines()
        .find(|line| line.contains("[INF] SRVR: Read-ahead: "))
        .unwrap_or_else(|| panic!("no shutdown line:\n{log}"));
    assert!(
        line.contains("; checksum and decode ") && line.contains(" s and hashing "),
        "{line}"
    );
    let blocks = number_before(line, " blocks (");
    // Every block but the first, which was read before the reader thread
    // existed, give or take the few at the end of the sync that a reader
    // no longer told to read ahead takes in turn.
    assert!(
        (NUM_BLOCKS as u64 - 8..NUM_BLOCKS as u64).contains(&blocks),
        "{line}"
    );
    assert_eq!(number_before(line, " connections;"), 1, "{line}");
    let queued = number_before(line, " items queued;");
    assert!((1..=4).contains(&queued), "{line}");
    // Every block the reader thread read went on with its payload laid
    // out as its block-file record, and the daemon's database wrote
    // every one of those records as it stood: it laid out none of them
    // again, which it does for a record that is not for its network.
    assert!(
        line.contains("; block-file records laid out for "),
        "{line}"
    );
    assert_eq!(number_before(line, " blocks in "), blocks, "{line}");
    assert_eq!(
        number_before(line, " written as laid out"),
        blocks,
        "{line}"
    );
    assert!(line.ends_with(" written as laid out"), "{line}");
    let shutdown_at = log.find("Server shutdown complete").expect("shutdown");
    assert!(log.find(line).expect("the line") < shutdown_at, "{log}");

    // Not reading ahead, from the same binary: the same tip, and nothing
    // to account for.
    let (log, inline_files) = synced(&miner_p2p, &tip, Some("off"));
    assert!(
        log.contains("[INF] DCRD: Read-ahead of blocks disabled by DCROXIDE_READ_AHEAD"),
        "{log}"
    );
    assert!(!log.contains("appears to be stalled"), "{log}");
    assert!(!log.contains("Reading ahead of the block handler"), "{log}");
    assert!(!log.contains("Read-ahead: "), "{log}");

    // The daemon that read ahead wrote the records its reader thread
    // laid out from the payloads; the one that did not serialized each
    // block and laid its record out as it stored it, as the miner did
    // with the blocks it mined.  All three hold the genesis block and
    // the mined blocks in one order, in the same bytes.
    let stored: usize = inline_files.iter().map(|(_, file)| file.len()).sum();
    assert!(
        stored > (NUM_BLOCKS as usize + 1) * (180 + 12),
        "{stored} bytes of block files"
    );
    let names = |files: &[(String, Vec<u8>)]| -> Vec<(String, usize)> {
        files
            .iter()
            .map(|(name, file)| (name.clone(), file.len()))
            .collect()
    };
    assert!(
        ahead_files == inline_files,
        "the block files differ: {:?} read ahead, {:?} not",
        names(&ahead_files),
        names(&inline_files)
    );
    let miner_files = miner.block_files();
    assert!(
        miner_files == inline_files,
        "the block files differ: {:?} mined, {:?} synced",
        names(&miner_files),
        names(&inline_files)
    );
}
