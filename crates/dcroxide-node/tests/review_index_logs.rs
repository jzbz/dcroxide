// SPDX-License-Identifier: ISC
//! The daemon and addblock print dcrd's INDX lines for the index
//! startup and the index drops.
//!
//! dcrd binds the indexers' package logger to INDX at init (`log.go:90`;
//! `cmd/addblock/addblock.go:78`), so the catch-up ("Catching up from
//! height X to Y", "Caught up to height Y"), a recovery, a resumed drop
//! and the drops behind `--droptxindex` and `--dropexistsaddrindex`
//! ("Dropping all ... entries", "Deleted N keys (M total) from ...",
//! "Dropped ...", "Not dropping ... because it does not exist") all
//! print.  The port's indexers had no logging at all: those phases ran
//! silently for as long as they took, and `--droptxindex` on a node
//! without the index exited successfully without a word.  The daemon
//! also announced both enabled indexes before creating either, where
//! dcrd announces each just ahead of creating it, so the lines a
//! creation logs sit between the two announcements.

#![cfg(target_os = "linux")]
// Test-harness arithmetic over a fixed deadline and small counts.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_indexers::{EXISTS_ADDR_INDEX_KEY, LogLevel, LogSink, TX_INDEX_KEY};
use dcroxide_node::indexes::{IndexLogs, start_indexes};
use dcroxide_testutil::unhex;

/// Blocks one to `count` of a simnet chain the daemon mines over RPC,
/// as raw block bytes.  Simnet, not the regnet `fullblocktests` battery
/// the test once imported: a regnet start removes the block database the
/// test builds, as dcrd's `loadBlockDB` does.  None of the simnet corpora
/// dumped from dcrd imports into a fresh chain (their blocks are
/// unsolved, skeletons, or spend seeded outputs), so the daemon mines
/// them: `generate`, then each block's raw bytes from `getblock`.
fn mined_simnet_blocks(count: usize) -> Vec<Vec<u8>> {
    let params = dcroxide_chaincfg::simnet_params();
    let mining_addr = dcroxide_txscript::stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(
        &[0x5a; 20],
        &params,
    )
    .expect("mining address");
    let appdata = tempfile::tempdir().expect("appdata");
    let mut child = daemon(
        appdata.path(),
        &[
            "--noseeders",
            "--nolisten",
            "--noexistsaddrindex",
            "--rpclisten=127.0.0.1:0",
            "--notls",
            "--rpcuser=user",
            "--rpcpass=pass",
            // The bound RPC address arrives over the pipe.
            "--pipetx=2",
            "--boundaddrevents",
        ],
    )
    .arg(format!("--miningaddr={}", mining_addr.encode()))
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::piped())
    .spawn()
    .expect("spawn dcroxide");
    let mut pipe = child.stderr.take().expect("stderr pipe");
    let mut miner = KillOnDrop(child);
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

    let mined = rpc_call(&addr, "generate", &format!("[{count}]"));
    assert!(mined.contains(r#""error":null"#), "{mined}");
    let blocks = (1..=count)
        .map(|height| {
            let hash = string_result(&rpc_call(&addr, "getblockhash", &format!("[{height}]")));
            unhex(&string_result(&rpc_call(
                &addr,
                "getblock",
                &format!(r#"["{hash}",false]"#),
            )))
        })
        .collect();

    let _ = rpc_call(&addr, "stop", "[]");
    let deadline = Instant::now() + Duration::from_secs(60);
    while miner.0.try_wait().expect("wait").is_none() {
        assert!(Instant::now() < deadline, "the mining daemon never stopped");
        std::thread::sleep(Duration::from_millis(50));
    }
    blocks
}

/// Kills a daemon however the test ends.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

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

/// The string result of a JSON-RPC response.
fn string_result(response: &str) -> String {
    let rest = response
        .split_once(r#""result":""#)
        .unwrap_or_else(|| panic!("no string result: {response}"))
        .1;
    rest[..rest.find('"').expect("closing quote")].to_string()
}

/// A capturing sink tagging each line with the subsystem it stands for
/// and dropping everything below `Info`, as the daemon's default level
/// does.
fn tagged_sink(tag: &'static str, lines: &Arc<Mutex<Vec<String>>>) -> LogSink {
    let lines = Arc::clone(lines);
    Arc::new(move |level, msg: &str| {
        if level == LogLevel::Info {
            lines.lock().expect("lines").push(format!("{tag}: {msg}"));
        }
    })
}

/// The rows in an index bucket.
fn bucket_rows(db: &Database, key: &[u8]) -> usize {
    let db_tx = db.begin(false).expect("begin");
    let rows = db_tx.metadata().bucket(key).map_or(0, |bucket| {
        let mut cursor = bucket.cursor();
        let mut n = 0;
        let mut ok = cursor.first();
        while ok {
            n += 1;
            ok = cursor.next();
        }
        n
    });
    db_tx.rollback().expect("rollback");
    rows
}

/// Run a binary to its exit, bounded so one that idles fails the test
/// instead of hanging it; returns its exit code and the INDX and MAIN
/// lines of its stdout with the timestamps cut off, alongside the whole
/// stdout for failure messages.
fn run_bounded(mut command: Command) -> (Option<i32>, Vec<String>, String) {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let deadline = Instant::now() + Duration::from_secs(120);
    while child.try_wait().expect("wait").is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let out = child.wait_with_output().expect("output");
            panic!(
                "the binary kept running: {}",
                String::from_utf8_lossy(&out.stdout)
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().expect("output");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let lines = stdout
        .lines()
        .filter_map(|line| line.find(" [").map(|at| &line[at + 1..]))
        .filter(|line| line.contains("] INDX: ") || line.contains("] MAIN: "))
        .map(str::to_string)
        .collect();
    (out.status.code(), lines, stdout)
}

/// The daemon over a simnet application data directory.
fn daemon(appdata: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dcroxide"));
    command
        .arg("--simnet")
        .arg(format!("--appdata={}", appdata.display()))
        .args(args)
        .env_remove("DCRD_APPDATA");
    command
}

/// The INDX lines of a daemon run: every one at `[INF]`, as dcrd's
/// default level shows them.
fn indx(lines: &[String]) -> Vec<&str> {
    lines
        .iter()
        .filter_map(|l| l.strip_prefix("[INF] INDX: "))
        .collect()
}

/// A simnet chain four blocks high with both indexes built, and the
/// transaction index then dropped part way (interrupted after its first
/// batch), as a node stopped during a `--droptxindex` leaves it.  The
/// index startup is checked on the way: each index is announced just
/// ahead of its creation, and the catch-up logs through the indexers'
/// sink.
fn build_datadir(db_path: &Path, params: &Params) {
    dcroxide_database::create_dir_all_owner_only(db_path).expect("db dir");
    let db = Database::create(&Options::new(db_path, params.net.0)).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db.clone(), params, Hash([0u8; 32]), false, 0).expect("open chain"),
    ));
    chain.lock().expect("chain").bulk_import_mode = true;
    let mut stream = Vec::new();
    for raw in mined_simnet_blocks(4) {
        dcroxide_database::bootstrap::write_block(&mut stream, params.net.0, &raw)
            .expect("write record");
    }
    let (stats, err) = dcroxide_node::addblock::run_import(
        &chain,
        params,
        &mut stream.as_slice(),
        60,
        &mut |_| {},
    );
    assert_eq!((err, stats.blocks_imported), (None, 4), "the import");

    let lines = Arc::new(Mutex::new(Vec::new()));
    let logs = IndexLogs {
        indexers: Some(tagged_sink("INDX", &lines)),
        announce: Some(tagged_sink("ANNOUNCE", &lines)),
    };
    let indexes = start_indexes(
        Arc::new(AtomicBool::new(false)),
        Arc::new(db.clone()),
        Arc::clone(&chain),
        params.clone(),
        true,
        true,
        &logs,
    )
    .expect("start indexes");
    assert_eq!(
        *lines.lock().expect("lines"),
        [
            "ANNOUNCE: Transaction index is enabled",
            "ANNOUNCE: Exists address index is enabled",
            "INDX: Catching up from height 0 to 4",
            "INDX: Caught up to height 4",
        ]
    );
    drop(indexes);

    let err = dcroxide_indexers::drop_tx_index(&Arc::new(AtomicBool::new(true)), &db, None)
        .expect_err("the drop stops at the interrupt");
    assert_eq!(err.kind_name(), Some("ErrInterruptRequested"), "{err}");

    chain
        .lock()
        .expect("chain")
        .flush(params)
        .expect("flush the chain");
    drop(chain);
    db.close().expect("close");
}

/// The daemon resumes the interrupted drop inside the transaction
/// index's own startup, then catches up; `--droptxindex` reports each
/// batch it deletes, and says so when there is no index to drop; and
/// `--dropexistsaddrindex` drops the other index the same way.
#[test]
fn the_daemon_logs_the_index_startup_and_drops_under_indx() {
    let params = dcroxide_chaincfg::simnet_params();
    let appdata = tempfile::tempdir().expect("appdata");
    let db_path: PathBuf = appdata
        .path()
        .join("data")
        .join("simnet")
        .join("blocks_ffldb");
    build_datadir(&db_path, &params);

    // `--dumpblockchain` stops the daemon straight after the index
    // catch-up (dcrd's `newServer`).
    let dump = appdata.path().join("dump.dat");
    let (code, lines, stdout) = run_bounded(daemon(
        appdata.path(),
        &[
            "--txindex",
            "--nolisten",
            "--norpc",
            "--noseeders",
            &format!("--dumpblockchain={}", dump.display()),
        ],
    ));
    assert_eq!(code, Some(1), "{stdout}");
    assert_eq!(
        indx(&lines),
        [
            "Transaction index is enabled",
            "Resuming transaction index drop",
            "Dropping all transaction index entries.  This might take a while...",
            "Dropped transaction index",
            "Exists address index is enabled",
            "Catching up from height 0 to 4",
            "Caught up to height 4",
        ],
        "{stdout}"
    );

    let opts = Options::new(&db_path, params.net.0);
    let (tx_rows, exists_rows) = {
        let db = Database::open(&opts).expect("reopen");
        let rows = (
            bucket_rows(&db, TX_INDEX_KEY),
            bucket_rows(&db, EXISTS_ADDR_INDEX_KEY),
        );
        db.close().expect("close");
        rows
    };
    assert!(tx_rows > 0 && exists_rows > 0, "both indexes hold entries");

    let (code, lines, stdout) = run_bounded(daemon(appdata.path(), &["--droptxindex"]));
    assert_eq!(code, Some(0), "{stdout}");
    assert_eq!(
        indx(&lines),
        [
            "Dropping all transaction index entries.  This might take a while...".to_string(),
            format!("Deleted {tx_rows} keys ({tx_rows} total) from transaction index"),
            "Dropped transaction index".to_string(),
        ],
        "{stdout}"
    );

    let (code, lines, stdout) = run_bounded(daemon(appdata.path(), &["--droptxindex"]));
    assert_eq!(code, Some(0), "{stdout}");
    assert_eq!(
        indx(&lines),
        ["Not dropping transaction index because it does not exist"],
        "{stdout}"
    );

    let (code, lines, stdout) = run_bounded(daemon(
        appdata.path(),
        &["--noexistsaddrindex", "--dropexistsaddrindex"],
    ));
    assert_eq!(code, Some(0), "{stdout}");
    assert_eq!(
        indx(&lines),
        [
            "Dropping all exists address index entries.  This might take a while...".to_string(),
            format!("Deleted {exists_rows} keys ({exists_rows} total) from exists address index"),
            "Dropped exists address index".to_string(),
        ],
        "{stdout}"
    );
}

/// addblock announces each enabled index under MAIN and logs the
/// indexers' lines under INDX, interleaved as dcrd's
/// `newBlockImporter` interleaves them: here, the resumption of a
/// transaction index drop interrupted at the genesis tip.
#[test]
fn addblock_logs_the_index_startup_under_indx() {
    let params = dcroxide_chaincfg::simnet_params();
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("simnet").join("blocks_ffldb");
    {
        dcroxide_database::create_dir_all_owner_only(&db_path).expect("db dir");
        let db = Database::create(&Options::new(&db_path, params.net.0)).expect("create database");
        let chain = Arc::new(Mutex::new(
            Chain::open(db.clone(), &params, params.assume_valid, false, 0).expect("open chain"),
        ));
        let indexes = start_indexes(
            Arc::new(AtomicBool::new(false)),
            Arc::new(db.clone()),
            chain,
            params.clone(),
            true,
            false,
            &IndexLogs::default(),
        )
        .expect("start the tx index");
        drop(indexes);
        dcroxide_indexers::drop_tx_index(&Arc::new(AtomicBool::new(true)), &db, None)
            .expect_err("the drop stops at the interrupt");
        db.close().expect("close");
    }

    let infile = dir.path().join("bootstrap.dat");
    std::fs::write(&infile, b"").expect("write empty bootstrap");
    let mut command = Command::new(env!("CARGO_BIN_EXE_addblock"));
    command.args([
        "--datadir",
        dir.path().to_str().expect("utf8 path"),
        "--simnet",
        "--txindex",
        "--infile",
        infile.to_str().expect("utf8 path"),
    ]);
    let (code, lines, stdout) = run_bounded(command);
    assert_eq!(code, Some(0), "{stdout}");
    let from_enabled: Vec<&str> = lines
        .iter()
        .map(String::as_str)
        .skip_while(|l| !l.ends_with("Transaction index is enabled"))
        .take_while(|l| !l.ends_with("Starting import"))
        .collect();
    assert_eq!(
        from_enabled,
        [
            "[INF] MAIN: Transaction index is enabled",
            "[INF] INDX: Resuming transaction index drop",
            "[INF] INDX: Dropping all transaction index entries.  This might take a while...",
            "[INF] INDX: Dropped transaction index",
            "[INF] MAIN: Exists address index is enabled",
        ],
        "{stdout}"
    );
}
