// SPDX-License-Identifier: ISC
//! Recovery at open and rollback at commit, against dcrd's ffldb.
//!
//! - `create` reconciles like `open` (dcrd's `reconcileDB(pdb, create)`),
//!   so block files already in the directory are rolled back rather than
//!   adopted -- and a directory holding dcrd's own metadata store is
//!   refused before they could be;
//! - a rollback repositions the write cursor whatever fails, as dcrd's
//!   `handleRollback` does, so a block-file rotation that could not
//!   create its file does not leave a cursor the next open calls
//!   corruption;
//! - a failed block write advances the cursor by what it wrote, as
//!   dcrd's `writeData` does, so the rollback truncates the torn record;
//! - the unclean-shutdown reconcile and a corrupt store are logged with
//!   dcrd's BCDB lines, and a redb repair of the metadata store is
//!   logged too;
//! - a clean `close` leaves a metadata store that opens without redb's
//!   full repair, however long the handle outlives it.

// Test-harness arithmetic over small, bounded sizes.
#![allow(clippy::arithmetic_side_effects)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use dcroxide_chainhash::{Hash, hash_h};
use dcroxide_database::{Database, ErrorKind, LogLevel, LogSink, Options};
use tempfile::TempDir;

const NET: u32 = 0x12141c16; // simnet magic

/// The header length the store slices out of every block.
const HDR: usize = 180;

/// The metadata store's first repair line (see `redb_builder`), exactly
/// as the operator docs quote it.
const REDB_REPAIR: &str = "Detected unclean shutdown of the metadata store - Repairing...";

/// A raw block of `len` bytes whose header is unique to `seed`, and the
/// hash `store_block_raw` requires for it.
fn raw_block(seed: u8, len: usize) -> (Hash, Vec<u8>) {
    let mut raw = vec![seed; len.max(HDR)];
    raw[0] = seed;
    raw[1] = seed.wrapping_mul(31);
    (hash_h(&raw[..HDR]), raw)
}

/// The on-disk length of a stored record: network, length, block, CRC.
fn record_len(block_len: usize) -> u64 {
    block_len as u64 + 12
}

fn block_file(dir: &Path, num: u32) -> PathBuf {
    dir.join(format!("{num:09}.fdb"))
}

fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).expect("block file").len()
}

/// The lines a [`capture`] sink kept, with their levels.
type Lines = Arc<Mutex<Vec<(LogLevel, String)>>>;

/// A log sink that keeps every line, with its level.
fn capture() -> (LogSink, Lines) {
    let lines: Lines = Arc::default();
    let keep = Arc::clone(&lines);
    let sink: LogSink = Arc::new(move |level, msg: &str| {
        keep.lock()
            .expect("log lock")
            .push((level, msg.to_string()));
    });
    (sink, lines)
}

fn logged(lines: &Mutex<Vec<(LogLevel, String)>>, level: LogLevel, text: &str) -> bool {
    lines
        .lock()
        .expect("log lock")
        .iter()
        .any(|(l, m)| *l == level && m.contains(text))
}

fn store(db: &Database, hash: &Hash, raw: &[u8]) -> Result<(), dcroxide_database::Error> {
    db.update(|tx| tx.store_block_raw(hash, raw.to_vec()))
}

/// Copy every file of a live database directory, as a process that died
/// right now would leave it (the handle is never dropped).
fn snapshot(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("mkdir snapshot");
    for entry in std::fs::read_dir(from).expect("read db dir") {
        let entry = entry.expect("dir entry");
        std::fs::copy(entry.path(), to.join(entry.file_name())).expect("copy");
    }
}

/// Whether the process can create files in a directory it has made
/// read-only -- true for root, which ignores the mode bits, so the tests
/// that need a failing create skip there.
#[cfg(unix)]
fn mode_bits_are_ignored(dir: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let probe = dir.join("probe");
    std::fs::create_dir(&probe).expect("mkdir probe");
    std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o555)).expect("chmod");
    let ignored = std::fs::write(probe.join("x"), b"x").is_ok();
    std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    ignored
}

/// Block files left in a directory with no metadata store are rolled
/// back by `create`, as dcrd's create-time `reconcileDB` rolls them
/// back to its fresh (0, 0) cursor -- not adopted, with the durable
/// cursor at (0, 0) and the live one at their end until the first
/// flush, and a crash in between deleting them at the next open.
#[test]
fn create_rolls_back_block_files_already_in_the_directory() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("db");
    std::fs::create_dir_all(&path).expect("mkdir");
    std::fs::write(block_file(&path, 0), vec![0x11u8; 700]).expect("stale file 0");
    std::fs::write(block_file(&path, 1), vec![0x22u8; 300]).expect("stale file 1");

    let (sink, lines) = capture();
    let mut opts = Options::new(&path, NET);
    opts.log = Some(sink);
    let db = Database::create(&opts).expect("create");

    assert!(
        !block_file(&path, 1).exists(),
        "every stale file after the first is deleted"
    );
    assert_eq!(
        file_len(&block_file(&path, 0)),
        0,
        "the first stale file is truncated to the fresh cursor"
    );
    assert!(logged(
        &lines,
        LogLevel::Info,
        "Detected unclean shutdown - Repairing..."
    ));
    assert!(logged(&lines, LogLevel::Info, "Database sync complete"));

    // The store then starts at (0, 0): a block lands at the start of the
    // first file and survives a close and reopen.
    let (hash, raw) = raw_block(7, 400);
    store(&db, &hash, &raw).expect("store");
    assert_eq!(file_len(&block_file(&path, 0)), record_len(raw.len()));
    db.close().expect("close");
    drop(db);
    let db = Database::open(&Options::new(&path, NET)).expect("reopen");
    db.view(|tx| {
        assert_eq!(tx.fetch_block(&hash)?, raw);
        Ok(())
    })
    .expect("view");
}

/// A directory that holds dcrd's own metadata store is refused, before
/// anything is created in it and before its block files could be rolled
/// back: the daemon's directory is dcrd's `blocks_ffldb`, so this is
/// what a dcroxide pointed at a dcrd data directory meets.
#[test]
fn create_refuses_a_directory_holding_a_dcrd_metadata_store() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("blocks_ffldb");
    std::fs::create_dir_all(path.join("metadata")).expect("mkdir metadata");
    std::fs::write(path.join("metadata").join("CURRENT"), b"MANIFEST-000002\n").expect("CURRENT");
    std::fs::write(block_file(&path, 0), vec![0x33u8; 900]).expect("dcrd block file 0");
    std::fs::write(block_file(&path, 1), vec![0x44u8; 500]).expect("dcrd block file 1");

    let err = match Database::create(&Options::new(&path, NET)) {
        Err(e) => e,
        Ok(_) => panic!("a dcrd data directory must not be taken over"),
    };
    assert_eq!(err.kind, ErrorKind::DbExists, "{err}");
    assert!(err.description.contains("dcrd"), "{err}");
    assert_eq!(
        file_len(&block_file(&path, 0)),
        900,
        "dcrd's files are untouched"
    );
    assert_eq!(
        file_len(&block_file(&path, 1)),
        500,
        "dcrd's files are untouched"
    );
    assert!(
        !path.join("metadata.redb").exists(),
        "nothing of this store is created beside dcrd's"
    );
}

/// A rotation whose new block file cannot be created rolls back with
/// the write cursor put back on the last good file, as dcrd's
/// `handleRollback` repositions it whatever fails.
///
/// Before, the failed delete of the never-created file returned early
/// with the cursor left on it; every later commit staged that cursor,
/// the close made it durable, and the next open refused the store as
/// corrupt although every block was intact.
#[cfg(unix)]
#[test]
fn a_failed_rotation_leaves_a_cursor_the_next_open_accepts() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().expect("tempdir");
    if mode_bits_are_ignored(dir.path()) {
        eprintln!("skipping: running as a user that ignores directory modes");
        return;
    }
    let path = dir.path().join("db");
    let block_len = 400;
    let (sink, lines) = capture();
    let mut opts = Options::new(&path, NET);
    // Two records per file.
    opts.max_block_file_size = (2 * record_len(block_len)) as u32;
    opts.log = Some(sink);
    let db = Database::create(&opts).expect("create");

    let (a, raw_a) = raw_block(1, block_len);
    let (b, raw_b) = raw_block(2, block_len);
    let (c, raw_c) = raw_block(3, block_len);
    store(&db, &a, &raw_a).expect("store a");
    store(&db, &b, &raw_b).expect("store b");
    assert!(!block_file(&path, 1).exists(), "file 0 holds both");

    // The third block rotates to file 1, which cannot be created.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o555)).expect("chmod");
    let failed = store(&db, &c, &raw_c);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    assert!(failed.is_err(), "creating the rotated-to file must fail");
    assert!(!block_file(&path, 1).exists());
    assert!(logged(
        &lines,
        LogLevel::Warn,
        "ROLLBACK: Failed to delete block file number 1"
    ));

    // A commit with no blocks stages the write cursor; the close makes
    // it durable.
    db.update(|tx| tx.metadata().put(b"after", b"rotation"))
        .expect("metadata commit");
    db.close().expect("close");
    drop(db);

    let db = Database::open(&opts).expect("the store must reopen: no block data was lost");
    db.view(|tx| {
        assert_eq!(tx.fetch_block(&a)?, raw_a);
        assert_eq!(tx.fetch_block(&b)?, raw_b);
        assert!(!tx.has_block(&c)?);
        Ok(())
    })
    .expect("view");
    // And the next block goes where the failed one would have.
    store(&db, &c, &raw_c).expect("store c");
    assert_eq!(file_len(&block_file(&path, 1)), record_len(block_len));
}

/// A rollback step that fails while opening is logged and the open
/// carries on with the cursor repositioned, as dcrd's reconcile does
/// with its void `handleRollback` -- it no longer aborts the open.
#[cfg(unix)]
#[test]
fn a_rollback_that_fails_at_open_is_logged_and_the_open_goes_on() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().expect("tempdir");
    if mode_bits_are_ignored(dir.path()) {
        eprintln!("skipping: running as a user that ignores directory modes");
        return;
    }
    let path = dir.path().join("db");
    let db = Database::create(&Options::new(&path, NET)).expect("create");
    let (a, raw_a) = raw_block(1, 400);
    store(&db, &a, &raw_a).expect("store");
    db.close().expect("close");
    drop(db);

    // Block data past the durable cursor, in a later file the rollback
    // cannot delete.
    std::fs::write(block_file(&path, 1), vec![0x55u8; 64]).expect("stray file 1");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o555)).expect("chmod");
    let (sink, lines) = capture();
    let mut opts = Options::new(&path, NET);
    opts.log = Some(sink);
    let opened = Database::open(&opts);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("chmod");

    let db = opened.expect("the open goes on past a failed rollback step");
    assert!(logged(
        &lines,
        LogLevel::Info,
        "Detected unclean shutdown - Repairing..."
    ));
    assert!(logged(
        &lines,
        LogLevel::Warn,
        "ROLLBACK: Failed to delete block file number 1"
    ));
    db.view(|tx| {
        assert_eq!(tx.fetch_block(&a)?, raw_a);
        Ok(())
    })
    .expect("view");
}

/// Block data past the durable cursor at open is dcrd's unclean
/// shutdown, repaired with its BCDB lines at its levels.
#[test]
fn an_unclean_shutdown_repair_at_open_is_logged_like_dcrd() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("db");
    let db = Database::create(&Options::new(&path, NET)).expect("create");
    let (a, raw_a) = raw_block(1, 400);
    store(&db, &a, &raw_a).expect("store");
    db.close().expect("close");
    drop(db);
    let durable = record_len(raw_a.len());

    // A block written but never described by the metadata.
    let mut bytes = std::fs::read(block_file(&path, 0)).expect("read");
    bytes.extend_from_slice(&[0x66u8; 250]);
    std::fs::write(block_file(&path, 0), bytes).expect("append");

    let (sink, lines) = capture();
    let mut opts = Options::new(&path, NET);
    opts.log = Some(sink);
    let db = Database::open(&opts).expect("open");
    assert_eq!(file_len(&block_file(&path, 0)), durable, "rolled back");
    assert!(logged(
        &lines,
        LogLevel::Info,
        "Detected unclean shutdown - Repairing..."
    ));
    assert!(logged(
        &lines,
        LogLevel::Debug,
        &format!(
            "Metadata claims file 0, offset {durable}. Block data is at file 0, offset {}",
            durable + 250
        )
    ));
    assert!(logged(
        &lines,
        LogLevel::Debug,
        &format!("ROLLBACK: Rolling back to file 0, offset {durable}")
    ));
    assert!(logged(&lines, LogLevel::Info, "Database sync complete"));
    db.close().expect("close");
}

/// Block data short of the durable cursor is dcrd's corruption: the
/// error carries dcrd's text and the warning is logged first.
#[test]
fn missing_block_data_at_open_is_corruption_with_dcrds_warning() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("db");
    let db = Database::create(&Options::new(&path, NET)).expect("create");
    let (a, raw_a) = raw_block(1, 400);
    store(&db, &a, &raw_a).expect("store");
    db.close().expect("close");
    drop(db);
    let durable = record_len(raw_a.len());
    std::fs::write(block_file(&path, 0), b"").expect("truncate");

    let (sink, lines) = capture();
    let mut opts = Options::new(&path, NET);
    opts.log = Some(sink);
    let err = match Database::open(&opts) {
        Err(e) => e,
        Ok(_) => panic!("missing block data must not open"),
    };
    let want =
        format!("metadata claims file 0, offset {durable}, but block data is at file 0, offset 0");
    assert_eq!(err.kind, ErrorKind::Corruption);
    assert_eq!(err.description, want);
    assert!(logged(
        &lines,
        LogLevel::Warn,
        &format!("***Database corruption detected***: {want}")
    ));
}

/// A clean `close` leaves the metadata store in a state redb opens
/// without a full repair, even though the handle is never dropped --
/// the daemon's handle has clones on threads that can outlive it.  redb
/// records the allocator state that makes a repair unnecessary only
/// from its own drop, or on a quick-repair commit, which `close` now
/// makes.
// Copies the files of a store that is still open, which Windows refuses:
// redb holds a byte-range lock on its file while the database is open.
#[cfg(not(windows))]
#[test]
fn a_clean_close_needs_no_repair_even_if_the_handle_lives_on() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("db");
    let db = Database::create(&Options::new(&path, NET)).expect("create");
    db.update(|tx| tx.metadata().put(b"k", b"v")).expect("put");
    db.close().expect("close");

    // The process ends here, with `db` still alive.
    let copy = dir.path().join("copy");
    snapshot(&path, &copy);

    let (sink, lines) = capture();
    let mut opts = Options::new(&copy, NET);
    opts.log = Some(sink);
    let reopened = Database::open(&opts).expect("open the copy");
    // No repair line of any wording: the first line and the progress
    // lines all name the metadata store.
    assert!(
        !lines
            .lock()
            .expect("log lock")
            .iter()
            .any(|(_, msg)| msg.to_lowercase().contains("metadata store")),
        "a cleanly closed store must not need redb's full repair: {:?}",
        lines.lock().expect("log lock")
    );
    reopened
        .view(|tx| {
            assert_eq!(tx.metadata().get(b"k").as_deref(), Some(b"v".as_slice()));
            Ok(())
        })
        .expect("view");
    drop(db);
}

/// The other side: a store that stopped without a close is repaired by
/// redb on the next open, and the repair is logged rather than being a
/// silent stall.
// Copies the files of a store that is still open, which Windows refuses:
// redb holds a byte-range lock on its file while the database is open.
#[cfg(not(windows))]
#[test]
fn an_unclean_stop_logs_the_metadata_store_repair() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("db");
    let db = Database::create(&Options::new(&path, NET)).expect("create");
    db.update(|tx| tx.metadata().put(b"k", b"v")).expect("put");
    db.flush().expect("flush");

    // Killed after the flush: no close.
    let copy = dir.path().join("copy");
    snapshot(&path, &copy);

    let (sink, lines) = capture();
    let mut opts = Options::new(&copy, NET);
    opts.log = Some(sink);
    let reopened = Database::open(&opts).expect("open the copy");
    // The exact line, not a prefix: the operator docs tell people to
    // look for this text.
    assert!(
        lines
            .lock()
            .expect("log lock")
            .iter()
            .any(|(level, msg)| *level == LogLevel::Info && msg == REDB_REPAIR),
        "the repair must be logged as {REDB_REPAIR:?}: {:?}",
        lines.lock().expect("log lock")
    );
    reopened
        .view(|tx| {
            assert_eq!(tx.metadata().get(b"k").as_deref(), Some(b"v".as_slice()));
            Ok(())
        })
        .expect("view");
    drop(db);
}

/// Set in the child that runs under a file-size limit.
#[cfg(unix)]
const TORN_WRITE_CHILD: &str = "DCROXIDE_TORN_WRITE_CHILD";

/// A block write that fails part way advances the write cursor by what
/// it wrote, as dcrd's `writeData` does, so the commit's rollback
/// truncates the torn record.
///
/// Before, the cursor moved only once all four writes succeeded, so a
/// failure in a commit's first block left the cursor on the rollback
/// point, the rollback returned at once, and the partial record stayed
/// in the file past the cursor.
///
/// The partial write comes from `RLIMIT_FSIZE`: the test re-runs itself
/// under `ulimit -f` with `SIGXFSZ` ignored, so a write that crosses the
/// limit stores what fits and the next one fails with `EFBIG`.
#[cfg(unix)]
#[test]
fn a_torn_block_write_is_truncated_by_the_rollback() {
    if std::env::var_os(TORN_WRITE_CHILD).is_some() {
        torn_write_child();
        return;
    }
    let exe = std::env::current_exe().expect("test binary path");
    let out = std::process::Command::new("sh")
        .arg("-c")
        // 16384 blocks: 8 MiB in POSIX sh's 512-byte units, 16 MiB in
        // bash's 1024-byte ones -- both far past the metadata store's
        // first commit and far short of the 64 MiB block.
        .arg(
            "ulimit -f 16384 && trap '' XFSZ && exec \"$0\" --exact \
             a_torn_block_write_is_truncated_by_the_rollback --nocapture",
        )
        .arg(&exe)
        .env(TORN_WRITE_CHILD, "1")
        .output()
        .expect("run the limited child");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "the child failed:\n{stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("torn-write child ran") || stderr.contains("torn-write child ran"),
        "the child must have run the check, not skipped it:\n{stdout}\n{stderr}"
    );
}

#[cfg(unix)]
fn torn_write_child() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("db");
    let db = Database::create(&Options::new(&path, NET)).expect("create");
    let (small, raw_small) = raw_block(1, 400);
    store(&db, &small, &raw_small).expect("store the small block");
    let before = file_len(&block_file(&path, 0));

    // The first block of its commit, crossing the limit part way.
    let (big, raw_big) = raw_block(2, 64 * 1024 * 1024);
    let err = store(&db, &big, &raw_big).expect_err("the write must cross the file-size limit");
    assert!(
        err.description.contains("failed to write block to file 0"),
        "the failure is the block write: {err}"
    );
    assert_eq!(
        file_len(&block_file(&path, 0)),
        before,
        "the rollback must truncate the torn record"
    );
    db.view(|tx| {
        assert_eq!(tx.fetch_block(&small)?, raw_small);
        assert!(!tx.has_block(&big)?);
        Ok(())
    })
    .expect("view");
    eprintln!("torn-write child ran");
}
