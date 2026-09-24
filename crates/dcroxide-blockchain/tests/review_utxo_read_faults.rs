// SPDX-License-Identifier: ISC
//! A storage read fault under the UTXO set reaches the chain as an
//! error, never as a missing output or a short set.
//!
//! dcrd's UTXO backend keeps the two apart: `levelDbUtxoBackend.Get`
//! returns `nil` only for `leveldb.ErrNotFound` and propagates every
//! other error (`internal/blockchain/utxobackend.go:392-401`), which
//! `dbFetchUtxoEntry` and `FetchState` pass on, and `FetchStats` fails
//! on its iterator's error after the walk (`:577-579`).  This port keeps
//! those rows in the ffldb-layout store, whose `Bucket::get` answers
//! ffldb's error-as-absence; the chain reads them through
//! `Bucket::try_get` and `Bucket::try_for_each` instead.  Read as
//! absence, a failing disk rejects a valid block with `ErrMissingTxOut`
//! and makes `gettxout` answer null.
//!
//! The database crate pins the two `try_` reads themselves; this pins
//! the chain's use of them, so a chain read switched back to the
//! error-dropping form fails here.
//!
//! Each probe runs once per point at which the store can start failing,
//! from its first read to its last, against a fresh store each time:
//! redb latches a read failure, and every later uncached read fails with
//! `PreviousIo` until the database is reopened.  redb gets no page cache,
//! because a cache hit skips its failure check (redb-4.3.0
//! `cached_file.rs:651-659`) and would hide the very pages under test.

// Test-harness arithmetic over bounded row counts.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use dcroxide_blockchain::UtxoEntry;
use dcroxide_blockchain::UtxoSetState;
use dcroxide_blockchain::chaindb::{self, ChainDbError, UTXO_SET_BUCKET_NAME};
use dcroxide_blockchain::process::{Chain, UtxoStats};
use dcroxide_chainhash::{Hash, hash_h};
use dcroxide_database::{Database, Options, SharedBackend, StorageBackend};
use dcroxide_stake::TxType;
use dcroxide_wire::OutPoint;
use tempfile::TempDir;

const NET: u32 = 0x12141c16; // simnet magic

/// Enough rows that the metadata table's root is a branch page: redb
/// keeps each tree's root for a transaction's life, so only a page
/// beneath it is read from the store.
const ROWS: u32 = 600;

/// An in-memory store that serves a set number of reads and fails
/// every later one.
#[derive(Debug)]
struct FailingStore {
    bytes: Mutex<Vec<u8>>,
    /// Reads to serve before failing; negative for no limit.
    reads_left: AtomicI64,
    /// Whether a read has been refused since the limit was last set.
    refused: AtomicBool,
}

impl FailingStore {
    fn new() -> FailingStore {
        FailingStore {
            bytes: Mutex::new(Vec::new()),
            reads_left: AtomicI64::new(-1),
            refused: AtomicBool::new(false),
        }
    }

    /// Serve `n` more reads, then fail every later one; negative lifts
    /// the limit.
    fn serve(&self, n: i64) {
        self.refused.store(false, Ordering::SeqCst);
        self.reads_left.store(n, Ordering::SeqCst);
    }

    fn range(len: usize, offset: u64, n: usize) -> Result<std::ops::Range<usize>, std::io::Error> {
        let start = usize::try_from(offset)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        match start.checked_add(n) {
            Some(end) if end <= len => Ok(start..end),
            _ => Err(std::io::Error::from(std::io::ErrorKind::InvalidInput)),
        }
    }
}

impl StorageBackend for FailingStore {
    fn len(&self) -> Result<u64, std::io::Error> {
        Ok(self.bytes.lock().expect("store lock").len() as u64)
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), std::io::Error> {
        let allowed = self
            .reads_left
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| match left {
                0 => None,
                n if n > 0 => Some(n - 1),
                n => Some(n),
            });
        if allowed.is_err() {
            self.refused.store(true, Ordering::SeqCst);
            return Err(std::io::Error::other("injected read failure"));
        }
        let bytes = self.bytes.lock().expect("store lock");
        let range = Self::range(bytes.len(), offset, out.len())?;
        out.copy_from_slice(&bytes[range]);
        Ok(())
    }

    fn set_len(&self, len: u64) -> Result<(), std::io::Error> {
        let len = usize::try_from(len)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        self.bytes.lock().expect("store lock").resize(len, 0);
        Ok(())
    }

    fn sync_data(&self) -> Result<(), std::io::Error> {
        Ok(())
    }

    fn write(&self, offset: u64, data: &[u8]) -> Result<(), std::io::Error> {
        let mut bytes = self.bytes.lock().expect("store lock");
        let range = Self::range(bytes.len(), offset, data.len())?;
        bytes[range].copy_from_slice(data);
        Ok(())
    }
}

fn outpoint(i: u32) -> OutPoint {
    OutPoint {
        hash: hash_h(&i.to_be_bytes()),
        index: 0,
        tree: 0,
    }
}

fn amount(i: u32) -> i64 {
    1000 + i64::from(i)
}

fn entry(i: u32) -> UtxoEntry {
    UtxoEntry::new(
        amount(i),
        vec![0x51],
        1,
        0,
        0,
        false,
        false,
        TxType::Regular,
        None,
    )
}

fn state() -> UtxoSetState {
    UtxoSetState {
        last_flush_height: 7,
        last_flush_hash: Hash([7; 32]),
    }
}

/// A UTXO set of [`ROWS`] rows and its state row, flushed out of the
/// cache overlay so every row is answered by the store alone.
fn stored_set() -> (TempDir, Arc<FailingStore>, Database) {
    let dir = TempDir::new().expect("tempdir");
    let store = Arc::new(FailingStore::new());
    let mut opts = Options::new(dir.path().join("db"), NET);
    opts.db_cache_bytes = 0;
    opts.backend = Some(Arc::clone(&store) as SharedBackend);
    let db = Database::create(&opts).expect("create");
    db.update(|tx| {
        tx.metadata().create_bucket(UTXO_SET_BUCKET_NAME)?;
        for i in 0..ROWS {
            chaindb::db_put_utxo(tx, &outpoint(i), Some(&entry(i))).expect("utxo row");
        }
        chaindb::db_put_utxo_set_state(tx, &state()).expect("state row");
        Ok(())
    })
    .expect("fill");
    db.flush().expect("flush to the store");
    (dir, store, db)
}

/// Run `probe` once for each read at which the store can start failing,
/// on a fresh store each time, until a run completes with no read
/// refused.  The probe arms the limit it is handed with
/// [`FailingStore::serve`] where its sweep should start.  Returns every
/// run's result in order; the last is the fault-free run.
fn at_every_fault<T>(
    probe: impl Fn(&Database, &FailingStore, i64) -> Result<T, ChainDbError>,
) -> Vec<Result<T, ChainDbError>> {
    let mut results = Vec::new();
    for served in 0i64..10_000 {
        let (_dir, store, db) = stored_set();
        let result = probe(&db, &store, served);
        let refused = store.refused.load(Ordering::SeqCst);
        store.serve(-1);
        results.push(result);
        if !refused {
            return results;
        }
    }
    panic!("the probe never completed");
}

/// Run a chain read inside a read-only transaction, with the store
/// failing after `served` more reads from the moment the read starts,
/// so the sweep covers the chain read and not the `begin` before it.
fn in_view<T>(
    db: &Database,
    store: &FailingStore,
    served: i64,
    read: impl FnOnce(&dcroxide_database::Transaction) -> Result<T, ChainDbError>,
) -> Result<T, ChainDbError> {
    let mut out = None;
    db.view(|tx| {
        store.serve(served);
        out = Some(read(tx));
        Ok(())
    })?;
    out.expect("the view ran")
}

/// Check a sweep: every faulted run is an error or the full answer, and
/// the fault-free run is the full answer.  A chain read that erases the
/// error answers some faulted run with absence or a short set instead.
///
/// The run that failed the last read, the page holding the rows, must
/// be a store error.  That is the run an erased error answers with
/// absence, and it also shows the rows were read from the store at all:
/// were they still in the cache overlay, a keyed read's last store read
/// would be its bucket lookup, whose failure ffldb reads as a missing
/// bucket (`ChainDbError::Corrupt`), and the state row would need none.
fn check_sweep<T: std::fmt::Debug>(
    what: &str,
    results: &[Result<T, ChainDbError>],
    full: impl Fn(&T) -> bool,
) {
    let (clean, faulted) = results.split_last().expect("at least the fault-free run");
    match clean {
        Ok(v) if full(v) => {}
        other => panic!("{what}: the fault-free run answered {other:?}"),
    }
    assert!(!faulted.is_empty(), "{what}: no read reached the store");
    for (served, result) in faulted.iter().enumerate() {
        if let Ok(v) = result {
            assert!(
                full(v),
                "{what}: with the store failing after {served} reads the chain read \
                 answered {v:?} instead of an error"
            );
        }
    }
    match faulted.last() {
        Some(Err(ChainDbError::Db(_))) => {}
        other => panic!("{what}: a failed read of the rows must be a store error, got {other:?}"),
    }
}

#[test]
fn a_utxo_entry_read_fault_is_an_error_not_a_missing_output() {
    let results = at_every_fault(|db, store, served| {
        in_view(db, store, served, |tx| {
            chaindb::db_fetch_utxo_entry(tx, &outpoint(7))
        })
    });
    check_sweep("db_fetch_utxo_entry", &results, |found| {
        found.as_ref().is_some_and(|e| e.amount() == amount(7))
    });
}

#[test]
fn a_utxo_batch_read_fault_is_an_error_not_missing_outputs() {
    let wanted = [3u32, 300, 599];
    let outpoints: Vec<OutPoint> = wanted.iter().map(|&i| outpoint(i)).collect();
    let results = at_every_fault(|db, store, served| {
        in_view(db, store, served, |tx| {
            chaindb::db_fetch_utxo_entries(tx, &outpoints)
        })
    });
    check_sweep("db_fetch_utxo_entries", &results, |found| {
        found.len() == wanted.len()
            && found
                .iter()
                .zip(wanted)
                .all(|(e, i)| e.as_ref().is_some_and(|e| e.amount() == amount(i)))
    });
}

#[test]
fn a_utxo_set_state_read_fault_is_an_error_not_a_fresh_set() {
    let results = at_every_fault(|db, store, served| {
        in_view(db, store, served, chaindb::db_fetch_utxo_set_state)
    });
    check_sweep("db_fetch_utxo_set_state", &results, |found| {
        found.as_ref() == Some(&state())
    });
}

#[test]
fn a_utxo_stats_walk_fault_is_an_error_not_a_short_set() {
    // The walk opens its own transaction, so this sweep starts at its
    // `begin`: an error there is an error as well.
    let results = at_every_fault(|db, store, served| {
        store.serve(served);
        Chain::utxo_stats_from_backend(db)
    });
    let full = |stats: &UtxoStats| {
        stats.utxos == i64::from(ROWS) && stats.total == (0..ROWS).map(amount).sum::<i64>()
    };
    check_sweep("utxo_stats_from_backend", &results, full);
}
