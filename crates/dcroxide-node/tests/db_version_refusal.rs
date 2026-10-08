// SPDX-License-Identifier: ISC
//! The daemon and addblock refuse a block database an older dcroxide
//! wrote, and say what to do about it (ADR-0010).
//!
//! The chain database version is 15, one past dcrd's 14, for the
//! height-first keys of the seven per-block buckets.  A version-14
//! directory holds its rows under keys this build does not look them up
//! by, and there is no in-place upgrade, so both binaries stop with exit
//! status one, leaving every row as they found it, and name the
//! directory to delete.  (Opening and closing the database can still
//! rewrite its file; the rows are what must not change.)  The
//! library-level refusal, without the path, is pinned in
//! `dcroxide-blockchain`'s `review_db_versions.rs`.

#![cfg(target_os = "linux")]
// Test-harness arithmetic over a fixed deadline.
#![allow(clippy::arithmetic_side_effects)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use dcroxide_blockchain::chaindb::{
    CURRENT_DATABASE_VERSION, db_fetch_database_info, db_put_database_info, older_version_refusal,
};
use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Bucket, Database, Options};

/// The version a dcroxide from before the re-keying wrote.
const OLDER: u32 = 14;

/// The simnet block database under an application data directory, where
/// both binaries look for it.
fn simnet_db_path(appdata: &Path) -> PathBuf {
    appdata.join("data").join("simnet").join("blocks_ffldb")
}

/// A genesis-only simnet chain database at `db_path` whose version row
/// reads `version`, closed cleanly.
fn chain_db_at_version(db_path: &Path, version: u32) {
    let params = dcroxide_chaincfg::simnet_params();
    let opts = Options::new(db_path, params.net.0);
    dcroxide_database::create_dir_all_owner_only(db_path).expect("db dir");
    let db = Database::create(&opts).expect("create database");
    let chain =
        Chain::open(db.clone(), &params, params.assume_valid, false, 0).expect("open chain");
    db.update(|tx| {
        let mut info = db_fetch_database_info(tx)
            .expect("read info")
            .expect("info row");
        info.version = version;
        db_put_database_info(tx, &info).map_err(|e| panic!("put info: {e:?}"))
    })
    .expect("rewrite the version row");
    drop(chain);
    db.close().expect("close");
}

/// One row: the path of nested buckets it sits in, its key and value.
type Row = (Vec<Vec<u8>>, Vec<u8>, Vec<u8>);

/// Every row of `bucket` and of the buckets nested in it, in walk order.
fn bucket_rows(bucket: &Bucket<'_>, path: &[Vec<u8>], out: &mut Vec<Row>) {
    bucket
        .for_each(|key, value| {
            out.push((path.to_vec(), key.to_vec(), value.to_vec()));
            Ok(())
        })
        .expect("walk the bucket");
    let mut names = Vec::new();
    bucket
        .for_each_bucket(|name| {
            names.push(name.to_vec());
            Ok(())
        })
        .expect("walk the nested buckets");
    for name in names {
        let nested = bucket.bucket(&name).expect("a nested bucket");
        let mut nested_path = path.to_vec();
        nested_path.push(name);
        bucket_rows(&nested, &nested_path, out);
    }
}

/// Every row of the chain database at `db_path`, nested buckets
/// included, and its version row.
fn stored_rows(db_path: &Path) -> (Vec<Row>, u32) {
    let params = dcroxide_chaincfg::simnet_params();
    let db = Database::open(&Options::new(db_path, params.net.0)).expect("open database");
    let mut rows = Vec::new();
    let mut version = 0;
    db.view(|tx| {
        bucket_rows(&tx.metadata(), &[], &mut rows);
        version = db_fetch_database_info(tx)
            .expect("read info")
            .expect("info row")
            .version;
        Ok(())
    })
    .expect("read the rows");
    db.close().expect("close");
    (rows, version)
}

/// Run a binary to its exit, bounded so one that keeps running fails
/// the test instead of hanging it; returns its exit code and stdout.
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

/// The refusal both binaries print for the directory at `db_path`.
fn refusal(db_path: &Path) -> String {
    older_version_refusal(OLDER, Some(&db_path.display().to_string()))
}

/// The daemon stops at the chain open with exit status one, naming the
/// block database directory to delete, and leaves the directory as it
/// found it.
#[test]
fn the_daemon_refuses_an_older_database_and_names_the_directory() {
    assert_eq!(OLDER + 1, CURRENT_DATABASE_VERSION);
    let appdata = tempfile::tempdir().expect("appdata");
    let db_path = simnet_db_path(appdata.path());
    chain_db_at_version(&db_path, OLDER);
    let (before, version) = stored_rows(&db_path);
    assert_eq!(version, OLDER);
    let nested: std::collections::BTreeSet<&[Vec<u8>]> =
        before.iter().map(|(path, ..)| path.as_slice()).collect();
    assert!(
        nested.len() > 5,
        "the walk reaches the nested buckets: {nested:?}"
    );

    let mut command = Command::new(env!("CARGO_BIN_EXE_dcroxide"));
    command
        .args([
            "--simnet",
            "--nolisten",
            "--norpc",
            "--noseeders",
            "--noexistsaddrindex",
        ])
        .arg(format!("--appdata={}", appdata.path().display()))
        .env_remove("DCRD_APPDATA");
    let (code, stdout) = run_bounded(command);
    assert_eq!(code, Some(1), "{stdout}");
    let want = format!("[ERR] DCRD: Unable to start server: {}", refusal(&db_path));
    assert!(stdout.contains(&want), "missing {want:?}: {stdout}");
    assert!(
        stdout.contains(&format!("delete '{}' and start again", db_path.display())),
        "{stdout}"
    );
    assert!(
        !stdout.contains("CHAN: Chain state:"),
        "no chain load: {stdout}"
    );
    assert_eq!(
        stored_rows(&db_path).0,
        before,
        "the refusal changed no row"
    );
}

/// addblock refuses the same directory with dcrd's importer failure
/// line, before it imports anything.
#[test]
fn addblock_refuses_an_older_database_and_names_the_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("data");
    let db_path = simnet_db_path(dir.path());
    chain_db_at_version(&db_path, OLDER);
    let (before, _) = stored_rows(&db_path);
    let infile = dir.path().join("bootstrap.dat");
    std::fs::write(&infile, b"").expect("write empty bootstrap");

    let mut command = Command::new(env!("CARGO_BIN_EXE_addblock"));
    command.args([
        "--datadir",
        data_dir.to_str().expect("utf8 path"),
        "--simnet",
        "--infile",
        infile.to_str().expect("utf8 path"),
    ]);
    let (code, stdout) = run_bounded(command);
    assert_eq!(code, Some(1), "{stdout}");
    let want = format!(
        "[ERR] MAIN: Failed create block importer: {}",
        refusal(&db_path)
    );
    assert!(stdout.contains(&want), "missing {want:?}: {stdout}");
    assert!(!stdout.contains("Starting import"), "{stdout}");
    assert_eq!(
        stored_rows(&db_path).0,
        before,
        "the refusal changed no row"
    );
}

/// addblock logs any chain open failure as dcrd's `Failed create block
/// importer: %v` line (`cmd/addblock/addblock.go:110`), with the error's
/// description: here dcrd's own downgrade refusal of a newer database.
/// It used to print the error's Rust `Debug` form,
/// `Corrupt("the current ...")`.
#[test]
fn addblock_logs_a_chain_open_failure_with_its_description() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("data");
    let db_path = simnet_db_path(dir.path());
    let newer = CURRENT_DATABASE_VERSION + 1;
    chain_db_at_version(&db_path, newer);
    let infile = dir.path().join("bootstrap.dat");
    std::fs::write(&infile, b"").expect("write empty bootstrap");

    let mut command = Command::new(env!("CARGO_BIN_EXE_addblock"));
    command.args([
        "--datadir",
        data_dir.to_str().expect("utf8 path"),
        "--simnet",
        "--infile",
        infile.to_str().expect("utf8 path"),
    ]);
    let (code, stdout) = run_bounded(command);
    assert_eq!(code, Some(1), "{stdout}");
    let want = format!(
        "[ERR] MAIN: Failed create block importer: the current blockchain database is no \
         longer compatible with this version of the software ({newer} > \
         {CURRENT_DATABASE_VERSION})\n"
    );
    assert!(stdout.contains(&want), "missing {want:?}: {stdout}");
    assert!(!stdout.contains("Corrupt("), "{stdout}");
}
