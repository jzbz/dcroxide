// SPDX-License-Identifier: ISC
//! The daemon and addblock print dcrd's CHAN startup lines.
//!
//! dcrd installs the CHAN logger at init (`log.go:85`;
//! `cmd/addblock/addblock.go:77`) and builds the UTXO cache with its
//! size ahead of `blockchain.New` (`server.go:4005-4009`;
//! `cmd/addblock/import.go:315-319`), so the chain open reports the
//! block index load, the UTXO cache initialization at the configured
//! size, and the chain state it arrived at.  The daemon installed its
//! sink and applied `--utxocachemaxsize` only after `Chain::open` had
//! returned, and addblock installed no sink at all, so neither printed
//! any of it.  The daemon also reported the block database as loaded
//! only once the chain had opened, where dcrd's `loadBlockDB` prints
//! "Block database loaded" before the chain is built.
//!
//! The expected lines below are what dcrd at the parity pin prints for
//! the same runs, on a fresh simnet data directory, apart from its
//! `Loading UTXO database from` and `UTXO database loaded` lines: the
//! port has no separate UTXO database to load.

#![cfg(target_os = "linux")]
// Test-harness arithmetic over a fixed deadline.
#![allow(clippy::arithmetic_side_effects)]

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The simnet genesis hash the chain state lines name.
const SIMNET_GENESIS: &str = "6bef82c645999585f7255cb02672921ac2f5492820090cd635fe3a59d16b4f87";

/// The CHAN lines of a simnet open at genesis, fresh or restarted, as
/// dcrd prints them, with the cache size given in MiB.  The debug timing line, when the level
/// shows it, is matched by its prefix since it carries a duration.
fn genesis_simnet_chan_lines(max_mib: u64, with_debug: bool) -> Vec<String> {
    let deployment = dcroxide_blockchain::thresholdstate::current_deployment_version(
        &dcroxide_chaincfg::simnet_params(),
    );
    let mut want = vec!["[INF] CHAN: Loading block index...".to_string()];
    if with_debug {
        want.push("[DBG] CHAN: Block index loaded in ".to_string());
    }
    want.extend([
        format!("[INF] CHAN: Deployment version {deployment} loaded"),
        format!("[INF] CHAN: UTXO cache initializing (max size: {max_mib} MiB)..."),
        "[INF] CHAN: UTXO cache initialization completed".to_string(),
        "[INF] CHAN: Blockchain database version info: chain: 14, compression: 1, block \
         index: 3, spend journal: 3"
            .to_string(),
        "[INF] CHAN: UTXO database version info: version: 3, compression: 1, utxo set: 3"
            .to_string(),
        format!("[INF] CHAN: Best known header: height 0, hash {SIMNET_GENESIS}"),
        format!(
            "[INF] CHAN: Chain state: height 0, hash {SIMNET_GENESIS}, total transactions 1, \
             work 2, progress 0.00%"
        ),
    ]);
    want
}

/// Every stdout line with its `YYYY-MM-DD hh:mm:ss.sss ` timestamp cut
/// off, so lines compare as `[LVL] TAG: message`.
fn untimed_lines(stdout: &str) -> Vec<&str> {
    stdout
        .lines()
        .filter_map(|line| line.find(" [").map(|at| &line[at + 1..]))
        .collect()
}

/// The CHAN lines of `lines`, checked against `want` in order.
fn assert_chan_lines(lines: &[&str], want: &[String], stdout: &str) {
    let chan: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|l| l.contains("] CHAN: "))
        .collect();
    assert_eq!(chan.len(), want.len(), "CHAN lines differ: {stdout}");
    for (got, want) in chan.iter().zip(want) {
        if want.ends_with(" in ") {
            assert!(
                got.starts_with(want.as_str()) && got.len() > want.len(),
                "{got:?} is not {want:?} and a duration: {stdout}"
            );
        } else {
            assert_eq!(got, want, "{stdout}");
        }
    }
}

/// The index of the first line starting with `prefix`.
fn position(lines: &[&str], prefix: &str, stdout: &str) -> usize {
    lines
        .iter()
        .position(|l| l.starts_with(prefix))
        .unwrap_or_else(|| panic!("missing {prefix:?}: {stdout}"))
}

/// Run a binary to its exit, bounded so one that idles fails the test
/// instead of hanging it; returns its exit code and stdout.
fn run_bounded(mut command: Command) -> (Option<i32>, String) {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let deadline = Instant::now() + Duration::from_secs(60);
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
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// A daemon run that stops once the chain has loaded: `--dumpblockchain`
/// dumps and exits one straight after the chain open and the index
/// catch-up, as dcrd's `newServer` does (`server.go:4149-4157`).
fn run_daemon_to_dump(appdata: &Path, extra: &[&str]) -> String {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dcroxide"));
    command
        .args([
            "--simnet",
            "--nolisten",
            "--norpc",
            "--noseeders",
            "--noexistsaddrindex",
        ])
        .arg(format!("--appdata={}", appdata.display()))
        .arg(format!(
            "--dumpblockchain={}",
            appdata.join("dump.dat").display()
        ))
        .args(extra)
        .env_remove("DCRD_APPDATA");
    let (code, stdout) = run_bounded(command);
    assert_eq!(code, Some(1), "{stdout}");
    stdout
}

/// The daemon's chain open prints dcrd's CHAN lines at the configured
/// cache size, with `--debuglevel CHAN=` governing the debug one.
///
/// They follow dcrd's two block database lines, which `loadBlockDB`
/// prints before the chain exists (`blockdb.go:139`, `:185`): the chain
/// is built later, in `newServer`.
#[test]
fn the_daemon_prints_the_chain_startup_lines_under_chan() {
    let appdata = tempfile::tempdir().expect("appdata");

    // A fresh data directory, with the debug level and a cache size of
    // its own.
    let stdout = run_daemon_to_dump(
        appdata.path(),
        &["--utxocachemaxsize=30", "--debuglevel=CHAN=debug"],
    );
    let lines = untimed_lines(&stdout);
    assert_chan_lines(&lines, &genesis_simnet_chan_lines(30, true), &stdout);
    let db_path = appdata
        .path()
        .join("data")
        .join("simnet")
        .join("blocks_ffldb");
    let loading = position(
        &lines,
        &format!(
            "[INF] DCRD: Loading block database from '{}'",
            db_path.display()
        ),
        &stdout,
    );
    let loaded = position(&lines, "[INF] DCRD: Block database loaded", &stdout);
    let first_chan = position(&lines, "[INF] CHAN: Loading block index...", &stdout);
    assert_eq!(
        lines[loaded], "[INF] DCRD: Block database loaded",
        "{stdout}"
    );
    assert!(
        loading < loaded && loaded < first_chan,
        "the block database is loaded before the chain opens: {stdout}"
    );

    // A restart at the defaults: the index is read back, the cache is
    // dcrd's 150 MiB default, and the debug line stays below the level.
    let stdout = run_daemon_to_dump(appdata.path(), &[]);
    assert_chan_lines(
        &untimed_lines(&stdout),
        &genesis_simnet_chan_lines(150, false),
        &stdout,
    );
}

/// addblock prints the same lines under CHAN, at dcrd's addblock cache
/// size of 100 MiB, between loading the block database and starting the
/// import.
#[test]
fn addblock_prints_the_chain_startup_lines_under_chan() {
    let dir = tempfile::tempdir().expect("tempdir");
    let infile = dir.path().join("bootstrap.dat");
    std::fs::write(&infile, b"").expect("write empty bootstrap");
    let mut command = Command::new(env!("CARGO_BIN_EXE_addblock"));
    command.args([
        "--datadir",
        dir.path().to_str().expect("utf8 path"),
        "--simnet",
        "--infile",
        infile.to_str().expect("utf8 path"),
    ]);
    let (code, stdout) = run_bounded(command);
    assert_eq!(code, Some(0), "{stdout}");

    let lines = untimed_lines(&stdout);
    assert_chan_lines(&lines, &genesis_simnet_chan_lines(100, false), &stdout);
    let loaded = position(&lines, "[INF] MAIN: Block database loaded", &stdout);
    let first_chan = position(&lines, "[INF] CHAN: Loading block index...", &stdout);
    let chain_state = position(&lines, "[INF] CHAN: Chain state:", &stdout);
    let import = position(&lines, "[INF] MAIN: Starting import", &stdout);
    assert!(
        loaded < first_chan && chain_state < import,
        "the chain lines belong to the importer's construction: {stdout}"
    );
}
