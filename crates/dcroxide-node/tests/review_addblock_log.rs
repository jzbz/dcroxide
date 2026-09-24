// SPDX-License-Identifier: ISC
//! addblock prints the block database's BCDB lines, as dcrd's addblock
//! does: dcrd hands the driver its BCDB logger
//! (`database.UseLogger(backendLogger.Logger("BCDB"))`,
//! `cmd/addblock/addblock.go:76`), so an unclean-shutdown repair found
//! when the tool opens the database is reported rather than silent.

use std::io::Write;
use std::process::{Command, Stdio};

use dcroxide_database::{Database, Options};

/// A database the tool will find in need of dcrd's reconcile: a clean
/// store whose first block file holds bytes past the stored write
/// cursor, the state an unclean stop between a block write and the
/// metadata flush leaves behind.
#[test]
fn addblock_logs_the_unclean_shutdown_repair_under_bcdb() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let params = dcroxide_chaincfg::simnet_params();
    // addblock's layout: `<datadir>/<network>/blocks_<dbtype>`.
    let db_path = dir.path().join(params.name).join("blocks_ffldb");
    let db = Database::create(&Options::new(&db_path, params.net.0)).expect("create");
    db.close().expect("close");
    drop(db);
    let mut block_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(db_path.join("000000000.fdb"))
        .expect("open block file");
    block_file
        .write_all(&[0xa5; 64])
        .expect("write stray bytes");
    drop(block_file);

    let infile = dir.path().join("bootstrap.dat");
    std::fs::write(&infile, b"").expect("write empty bootstrap");
    let out = Command::new(env!("CARGO_BIN_EXE_addblock"))
        .args([
            "--datadir",
            dir.path().to_str().expect("utf8 path"),
            "--simnet",
            "--infile",
            infile.to_str().expect("utf8 path"),
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run addblock binary");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );

    // dcrd's reconcile lines (`ffldb/reconcile.go:90`, `:95`), at Info
    // under BCDB, between the tool's own load lines.
    let position = |needle: &str| {
        stdout
            .find(needle)
            .unwrap_or_else(|| panic!("missing {needle:?} in stdout: {stdout}"))
    };
    let loading = position("[INF] MAIN: Loading block database from");
    let repair = position("[INF] BCDB: Detected unclean shutdown - Repairing...");
    let synced = position("[INF] BCDB: Database sync complete");
    let loaded = position("[INF] MAIN: Block database loaded");
    assert!(
        loading < repair && repair < synced && synced < loaded,
        "stdout: {stdout}"
    );

    // The repair did what it says: the stray bytes were truncated, so
    // the file now opens with the genesis record the chain stored after
    // it (a record starts with the network magic, little-endian).
    let bytes = std::fs::read(db_path.join("000000000.fdb")).expect("block file");
    assert_eq!(
        bytes.get(..4),
        Some(params.net.0.to_le_bytes().as_slice()),
        "the stray bytes must be gone"
    );
}
