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

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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
use dcroxide_wire::MsgBlock;

/// The leading consecutive main-chain prefix of accepted blocks from
/// dcrd's `fullblocktests.Generate` battery, as raw regnet block bytes.
fn accepted_prefix_raw(limit: usize) -> Vec<Vec<u8>> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcroxide-blockchain/tests/data/fullblock_vectors.txt"
    );
    let data = std::fs::read_to_string(path).expect("fullblock vectors");
    let mut tip = dcroxide_chaincfg::regnet_params().genesis_hash;
    let mut blocks = Vec::new();
    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        if f[0] != "accept" {
            continue;
        }
        let raw = unhex(f[4]);
        let (block, _) = MsgBlock::from_bytes(&raw).expect("block");
        if f[2] != "true" || block.header.prev_block != tip {
            continue;
        }
        tip = block.header.block_hash();
        blocks.push(raw);
        if blocks.len() == limit {
            break;
        }
    }
    assert_eq!(blocks.len(), limit, "battery must provide the prefix");
    blocks
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

/// The daemon over a regnet application data directory.
fn daemon(appdata: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dcroxide"));
    command
        .arg("--regnet")
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

/// A regnet chain four blocks high with both indexes built, and the
/// transaction index then dropped part way (interrupted after its first
/// batch), as a node stopped during a `--droptxindex` leaves it.  The
/// index startup is checked on the way: each index is announced just
/// ahead of its creation, and the catch-up logs through the indexers'
/// sink.
fn build_regnet_datadir(db_path: &Path, params: &Params) {
    dcroxide_database::create_dir_all_owner_only(db_path).expect("db dir");
    let db = Database::create(&Options::new(db_path, params.net.0)).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db.clone(), params, Hash([0u8; 32]), false, 0).expect("open chain"),
    ));
    chain.lock().expect("chain").bulk_import_mode = true;
    let mut stream = Vec::new();
    for raw in accepted_prefix_raw(4) {
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
    let params = dcroxide_chaincfg::regnet_params();
    let appdata = tempfile::tempdir().expect("appdata");
    let db_path: PathBuf = appdata
        .path()
        .join("data")
        .join("regnet")
        .join("blocks_ffldb");
    build_regnet_datadir(&db_path, &params);

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
