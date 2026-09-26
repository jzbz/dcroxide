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
//! - A regnet start reopened the block database the last run left, where
//!   dcrd's `loadBlockDB` removes it first so every run starts at genesis.
//! - A negative `--maxpeers` and a `--listen` nothing could bind failed
//!   the start only after the chain loaded and the RPC server bound, and
//!   a persistent peer that could not be added only once every listener
//!   was serving; dcrd's `newServer` fails on the first two before the
//!   chain and on the third before any RPC listener.  That failure and an
//!   RPC certificate failure also logged port-specific text instead of
//!   `Unable to start server: ...`.

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

/// Run the daemon on simnet to completion (see [`run_to_exit_on`]).
fn run_to_exit(appdata: &Path, args: &[&str]) -> (ExitStatus, String) {
    run_to_exit_on("--simnet", appdata, args)
}

/// Run the daemon on the network `net_flag` selects to completion,
/// bounded so a daemon that idles instead of exiting fails the test
/// rather than hanging it; returns the status and stdout.  Stderr goes
/// to /dev/null, which also makes it a descriptor that reads end-of-file
/// at once.
fn run_to_exit_on(net_flag: &str, appdata: &Path, args: &[&str]) -> (ExitStatus, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .arg(net_flag)
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

/// Build a genesis-only chain at `db_path` with the transaction index
/// built and closed cleanly, as a node run with --txindex leaves it.
fn build_tx_indexed_db(params: &dcroxide_chaincfg::Params, db_path: &Path) {
    let opts = Options::new(db_path, params.net.0);
    dcroxide_database::create_dir_all_owner_only(db_path).expect("db dir");
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db.clone(), params, params.assume_valid, false, 0).expect("open chain"),
    ));
    let indexes = dcroxide_node::indexes::start_indexes(
        Arc::new(AtomicBool::new(false)),
        Arc::new(db.clone()),
        chain,
        params.clone(),
        true,
        false,
        &dcroxide_node::indexes::IndexLogs::default(),
    )
    .expect("start the tx index");
    drop(indexes);
    assert!(tx_index_exists(&db), "the index was built");
    db.close().expect("close");
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
    build_tx_indexed_db(&params, &db_path);

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
/// `shutdownRequested` checks, before anything is served: the peer
/// listeners may be bound by then, as `newServer` binds dcrd's, but
/// accept nothing.  `--piperx` over a descriptor at end-of-file requests
/// it as soon as the watcher runs.
#[test]
fn a_shutdown_requested_during_startup_serves_nothing() {
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
        !stdout.contains("Server listening on"),
        "the peer listeners must not accept: {stdout}"
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

/// dcrd's `loadBlockDB` removes an existing regnet block database before
/// it logs `Loading block database from ...` and opens one
/// (`removeRegressionDB`, `blockdb.go:39-52`), and `LoadUtxoDB` does the
/// same for the UTXO database, so every regnet run starts from genesis
/// with nothing the last run left: no blocks, no UTXO set, no indexes.
/// The port reopened the old store.  A transaction index the last run
/// built marks it: `--dropexistsaddrindex` leaves that index alone, so it
/// is gone afterwards only because the whole store was.
#[test]
fn regnet_removes_the_last_runs_block_database() {
    let params = dcroxide_chaincfg::regnet_params();
    let appdata = tempfile::tempdir().expect("appdata");
    let db_path = appdata
        .path()
        .join("data")
        .join("regnet")
        .join("blocks_ffldb");
    build_tx_indexed_db(&params, &db_path);

    let (status, stdout) = run_to_exit_on(
        "--regnet",
        appdata.path(),
        &["--dropexistsaddrindex", "--noexistsaddrindex"],
    );
    assert_eq!(status.code(), Some(0), "{stdout}");
    let removing = stdout
        .find(&format!(
            "[INF] DCRD: Removing regression test database from '{}'",
            db_path.display()
        ))
        .unwrap_or_else(|| panic!("no removal line: {stdout}"));
    let loading = stdout
        .find("[INF] DCRD: Loading block database from")
        .unwrap_or_else(|| panic!("no loading line: {stdout}"));
    assert!(removing < loading, "removed before the load: {stdout}");

    let db = Database::open(&Options::new(&db_path, params.net.0)).expect("reopen");
    assert!(
        !tx_index_exists(&db),
        "the store the last regnet run left must not survive the next start"
    );
}

/// RPC on an ephemeral loopback port, so a start that got as far as
/// binding it says so in the log.
const RPC_ON: [&str; 3] = [
    "--rpclisten=127.0.0.1:0",
    "--rpcuser=user",
    "--rpcpass=pass",
];

/// Run a start expected to fail with RPC enabled, and check it failed
/// with exit one before the RPC server generated a certificate or bound
/// a listener; returns stdout.
fn run_failing_start(appdata: &Path, args: &[&str]) -> String {
    let mut all: Vec<&str> = vec!["--noseeders", "--noexistsaddrindex"];
    all.extend_from_slice(&RPC_ON);
    all.extend_from_slice(args);
    let (status, stdout) = run_to_exit(appdata, &all);
    assert_eq!(status.code(), Some(1), "{status:?}: {stdout}");
    assert!(
        !stdout.contains("Generating TLS certificates"),
        "no RPC certificate work: {stdout}"
    );
    assert!(
        !stdout.contains("RPC server listening on"),
        "no RPC listener: {stdout}"
    );
    stdout
}

/// dcrd dies on a negative --maxpeers in `newServer`'s server literal,
/// just after `initListeners` and before the fee estimator, the chain,
/// the indexes and the RPC listeners.  The port refused only once all of
/// those were done, with the RPC server already serving.
#[test]
fn a_negative_maxpeers_fails_before_the_chain_loads() {
    let appdata = tempfile::tempdir().expect("appdata");
    let stdout = run_failing_start(appdata.path(), &["--maxpeers=-1", "--listen=127.0.0.1:0"]);
    assert!(
        stdout.contains("[ERR] DCRD: The maxpeers option may not be less than 0 -- parsed [-1]"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("CHAN: Chain state:"),
        "no chain load: {stdout}"
    );
}

/// dcrd binds the peer-to-peer listeners first in `newServer`, so a
/// --listen nothing can bind fails with `no valid listen address` before
/// any chain work.  The port loaded the chain and served RPC first.
#[test]
fn an_unbindable_listener_fails_before_the_chain_loads() {
    let held = std::net::TcpListener::bind("127.0.0.1:0").expect("hold a port");
    let port = held.local_addr().expect("local addr").port();
    let appdata = tempfile::tempdir().expect("appdata");
    let listen = format!("--listen=127.0.0.1:{port}");
    let stdout = run_failing_start(appdata.path(), &[&listen]);
    assert!(
        stdout.contains(&format!("[WRN] SRVR: Can't listen on 127.0.0.1:{port}: ")),
        "{stdout}"
    );
    assert!(
        stdout.contains("[ERR] DCRD: Unable to start server: no valid listen address"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("CHAN: Chain state:"),
        "no chain load: {stdout}"
    );
}

/// A persistent peer `newServer` cannot add fails it, and `dcrdMain`
/// reports that as it reports every server construction failure --
/// `Unable to start server: ...` under DCRD -- where the port logged
/// `Unable to add persistent peer ...` under SRVR.  dcrd adds the
/// persistent peers ahead of `setupRPCListeners`, so the failure comes
/// before any RPC certificate work or bind; the port failed with the
/// RPC server already serving.  Nine distinct peers pass one past
/// connmgr's `MaxPersistent`, with no name to resolve.
#[test]
fn a_persistent_peer_failure_is_a_server_start_failure() {
    let appdata = tempfile::tempdir().expect("appdata");
    let connects: Vec<String> = (1..=9)
        .map(|i| format!("--connect=192.0.2.{i}:9108"))
        .collect();
    let args: Vec<&str> = connects.iter().map(String::as_str).collect();
    let stdout = run_failing_start(appdata.path(), &args);
    assert!(
        stdout.contains(
            "[ERR] DCRD: Unable to start server: a maximum of 8 persistent connections is allowed"
        ),
        "{stdout}"
    );
    assert!(
        !appdata.path().join("rpc.cert").exists(),
        "no certificate generated"
    );
}

/// dcrd's `setupRPCListeners` returns a certificate generation failure
/// from `newServer`, which `dcrdMain` reports as `Unable to start
/// server: ...` under DCRD; the port logged `Unable to set up RPC TLS:
/// ...`.  A certificate path under a regular file cannot be written.
#[test]
fn an_rpc_certificate_failure_is_a_server_start_failure() {
    let appdata = tempfile::tempdir().expect("appdata");
    let blocker = appdata.path().join("blocker");
    std::fs::write(&blocker, b"not a directory").expect("blocker file");
    let cert = format!("--rpccert={}", blocker.join("rpc.cert").display());
    let key = format!("--rpckey={}", blocker.join("rpc.key").display());
    let mut args: Vec<&str> = vec!["--noseeders", "--noexistsaddrindex", "--nolisten"];
    args.extend_from_slice(&RPC_ON);
    args.extend_from_slice(&[&cert, &key]);
    let (status, stdout) = run_to_exit(appdata.path(), &args);
    assert_eq!(status.code(), Some(1), "{status:?}: {stdout}");
    assert!(
        stdout.contains("[ERR] DCRD: Unable to start server: "),
        "{stdout}"
    );
    assert!(!stdout.contains("Unable to set up RPC TLS"), "{stdout}");
    assert!(
        !stdout.contains("RPC server listening on"),
        "no RPC listener: {stdout}"
    );
}
