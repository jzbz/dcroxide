// SPDX-License-Identifier: ISC
//! The daemon's early exits against dcrd's `dcrdMain`, which defers
//! `db.Close()` straight after `loadBlockDB` and returns as soon as a
//! shutdown has been requested.
//!
//! - `--droptxindex` exited zero without closing the database, so the
//!   drop's commits stayed in the metadata overlay and were discarded:
//!   the next start still found the index.
//! - A shutdown requested during startup was only noticed at the idle
//!   wait, after the RPC and peer listeners were already serving.
//! - `--minrelaytxfee=0` aborted on an `expect` where dcrd logs
//!   `Unable to start server: ...` and exits one.

#![cfg(target_os = "linux")]
// Test-harness arithmetic over a fixed deadline.
#![allow(clippy::arithmetic_side_effects)]

use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};

/// The simnet block database under an application data directory.
fn simnet_db_path(appdata: &Path) -> PathBuf {
    appdata.join("data").join("simnet").join("blocks_ffldb")
}

/// Run the daemon to completion, bounded so a daemon that idles instead
/// of exiting fails the test rather than hanging it; returns the status
/// and stdout.  Stderr goes to /dev/null, which also makes it a
/// descriptor that reads end-of-file at once.
fn run_to_exit(appdata: &Path, args: &[&str]) -> (ExitStatus, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .arg("--simnet")
        .arg(format!("--appdata={}", appdata.display()))
        .args(args)
        .env_remove("DCRD_APPDATA")
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

/// Whether the transaction index has a tip in the database.
fn tx_index_exists(db: &Database) -> bool {
    let tx = db.begin(false).expect("begin");
    let exists = tx
        .metadata()
        .bucket(b"idxtips")
        .is_some_and(|bucket| bucket.get(dcroxide_indexers::TX_INDEX_KEY).is_some());
    tx.rollback().expect("rollback");
    exists
}

/// dcrd's `DropTxIndex` then `return nil` runs the deferred `db.Close()`,
/// whose cache flush makes the drop durable.  The port returned without
/// closing, so a drop too small to trip a size or interval flush never
/// left the overlay.
#[test]
fn droptxindex_persists_the_drop() {
    let params = dcroxide_chaincfg::simnet_params();
    let appdata = tempfile::tempdir().expect("appdata");
    let db_path = simnet_db_path(appdata.path());
    let opts = Options::new(&db_path, params.net.0);

    // A genesis-only chain with the transaction index built and closed
    // cleanly, as a node run with --txindex leaves it.
    {
        dcroxide_database::create_dir_all_owner_only(&db_path).expect("db dir");
        let db = Database::create(&opts).expect("create database");
        let chain = Arc::new(Mutex::new(
            Chain::open(db.clone(), &params, params.assume_valid, false, 0).expect("open chain"),
        ));
        let indexes = dcroxide_node::indexes::start_indexes(
            Arc::new(AtomicBool::new(false)),
            Arc::new(db.clone()),
            chain,
            params.clone(),
            true,
            false,
        )
        .expect("start the tx index");
        drop(indexes);
        assert!(tx_index_exists(&db), "the index was built");
        db.close().expect("close");
    }

    let (status, stdout) = run_to_exit(appdata.path(), &["--droptxindex"]);
    assert_eq!(status.code(), Some(0), "{stdout}");
    assert!(
        stdout.contains("[INF] DCRD: Gracefully shutting down the block database..."),
        "{stdout}"
    );
    assert!(stdout.contains("[INF] DCRD: Shutdown complete"), "{stdout}");

    let db = Database::open(&opts).expect("reopen");
    assert!(
        !tx_index_exists(&db),
        "the drop reported success, so the next start must not find the index"
    );
}

/// A shutdown requested while the node starts is honoured at dcrd's
/// `shutdownRequested` checks, before anything listens.  `--piperx` over
/// a descriptor at end-of-file requests it as soon as the watcher runs.
#[test]
fn a_shutdown_requested_during_startup_binds_nothing() {
    let appdata = tempfile::tempdir().expect("appdata");
    let (status, stdout) = run_to_exit(
        appdata.path(),
        &[
            "--piperx=2",
            "--noexistsaddrindex",
            "--noseeders",
            "--listen=127.0.0.1:0",
            "--rpclisten=127.0.0.1:0",
            "--rpcuser=user",
            "--rpcpass=pass",
        ],
    );
    assert_eq!(status.code(), Some(0), "{stdout}");
    assert!(
        !stdout.contains("RPC server listening on"),
        "the RPC server must not start: {stdout}"
    );
    assert!(
        !stdout.contains("Serving peer-to-peer connections"),
        "the peer listeners must not start: {stdout}"
    );
    assert!(stdout.contains("[INF] DCRD: Shutdown complete"), "{stdout}");
}

/// The fee estimator refuses a zero relay fee with dcrd's text (both
/// bucket bounds are zero, so the first sanity check fails), and
/// `newServer` failing is `Unable to start server: ...` and exit one --
/// not an abort.
#[test]
fn a_zero_relay_fee_fails_startup_cleanly() {
    let appdata = tempfile::tempdir().expect("appdata");
    let (status, stdout) = run_to_exit(
        appdata.path(),
        &[
            "--minrelaytxfee=0",
            "--noexistsaddrindex",
            "--nolisten",
            "--norpc",
            "--noseeders",
        ],
    );
    assert_eq!(status.code(), Some(1), "{status:?}: {stdout}");
    assert!(
        stdout.contains(
            "[ERR] DCRD: Unable to start server: maximum bucket fee should not be lower \
             than minimum bucket fee"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains("[INF] DCRD: Gracefully shutting down the block database..."),
        "{stdout}"
    );
}
