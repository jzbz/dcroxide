// SPDX-License-Identifier: ISC
//! Crash-consistency rig (Phase 7 exit criterion): reproduce the torn
//! states an unclean shutdown can leave behind — block file bytes
//! written but the metadata commit lost, and metadata claiming more
//! than the files hold — and verify recovery matches dcrd's
//! `reconcileDB` semantics.
//!
//! This file is also the gate on any change to the storage engine, and
//! [ADR-0009] records that it was not adequate for that job: the original
//! four tests exercised only `store_block`/`fetch_block`/`has_block`, so
//! **none of them wrote a single byte of metadata** and none could have
//! failed a storage change that broke bucket atomicity. The engine
//! benchmark in that ADR made the gap urgent — a candidate engine with an
//! open upstream bug on exactly that invariant cannot be judged by a suite
//! that never tests it.
//!
//! What the tests below add, in the terms ADR-0009 asks for:
//!
//! - **A commit spanning the buckets `process.rs` pairs.** `Chain::flush`
//!   writes block index rows, UTXO entries and *both* state markers in one
//!   transaction, with a comment that a crash must never leave the flushed
//!   set ahead of or behind its recorded state. That pairing is now
//!   reproduced and torn.
//! - **Detection of each desync direction.** A marker that claims more
//!   rows than survive is lost data; a marker that claims fewer is leaked
//!   data. Both are failures, and a test that only checks one direction
//!   passes on an engine that silently keeps uncommitted writes.
//! - **A kill between durability domains.** `DbCache::flush` syncs the
//!   flat block files *before* committing metadata, so the window between
//!   them is a real state a crash can land in: block bytes on disk that no
//!   metadata references.
//!
//! There are two crash primitives, and the difference between them is
//! the whole point.
//!
//! `drop` without `close` discards the write cache exactly as process
//! death would, and bounds the engine's transactional behaviour. It does
//! **not** model power loss: the page cache survives it, so every byte
//! written but never `fsync`ed is still readable after the reopen.
//! Killing the process outright would be no better for the same reason.
//! Every test using it passes on a store that never syncs at all.
//!
//! `PowerLossBackend` closes that gap by discarding what was never
//! synced, which is the only thing that tells a durable commit from a
//! merely-written one. It exists because the async-commit work in
//! ADR-0009 would defer exactly that step, and the suite could not have
//! caught a mistake there. `power_loss_detects_a_store_that_never_syncs`
//! is the control: it runs the same sequence against a backend whose
//! `sync_data` is a no-op and requires the data to be GONE, so if the
//! rig ever stops testing durability that test fails rather than the
//! other two silently passing.
//!
//! **These tests were checked against a broken store, not just a working
//! one.** Deleting the state-marker write from `DbCache::flush` — so the
//! rows advance while the marker naming them does not — fails four of the
//! metadata tests below with the invariant named in the message, and
//! passes all five of the tests that existed before. That is the whole
//! reason for the additions: the old suite was green on a store that had
//! lost the property the chain depends on. Any future change here should
//! be checked the same way, by breaking the thing on purpose and watching
//! it fail.
//!
//! [ADR-0009]: ../../../docs/adr/0009-storage-shape.md

use std::fs::OpenOptions;
use std::io::Write;

use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, ErrorKind, Options};
use dcroxide_testutil::SplitMix64;
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint, TxIn, TxOut, TxSerializeType};
use tempfile::TempDir;

const NET: u32 = 0x12141c16; // simnet magic

fn make_block(rng: &mut SplitMix64) -> MsgBlock {
    let mut raw_header = [0u8; 180];
    rng.fill(&mut raw_header);
    let (header, _) = BlockHeader::from_bytes(&raw_header).expect("header");
    let mut prev = [0u8; 32];
    rng.fill(&mut prev);
    MsgBlock {
        header,
        transactions: vec![MsgTx {
            ser_type: TxSerializeType::Full,
            version: 1,
            tx_in: vec![TxIn {
                previous_out_point: OutPoint {
                    hash: Hash(prev),
                    index: 0,
                    tree: 0,
                },
                sequence: 0xffff_ffff,
                value_in: 1,
                block_height: 0,
                block_index: 0,
                signature_script: rng.bytes(16),
            }],
            tx_out: vec![TxOut {
                value: 1,
                version: 0,
                pk_script: rng.bytes(20),
            }],
            lock_time: 0,
            expiry: 0,
        }],
        stransactions: Vec::new(),
    }
}

/// Torn write: block bytes hit the flat file but the metadata commit
/// never happened.  Reopening must roll the file back to the recorded
/// write position and the database must keep working from there.
#[test]
fn reconcile_truncates_orphaned_block_data() {
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("db"), NET);
    let db = Database::create(&opts).expect("create");
    let mut rng = SplitMix64::from_entropy("db-crash-torn");

    let committed = make_block(&mut rng);
    let committed_hash = committed.header.block_hash();
    db.update(|tx| tx.store_block(&committed)).expect("store");
    db.close().expect("close");
    drop(db);

    // Simulate the crash: append garbage "block" bytes directly to the
    // block file, as if writeBlock ran but the metadata commit did not.
    let file0 = dir.path().join("db").join("000000000.fdb");
    let clean_len = std::fs::metadata(&file0).expect("metadata").len();
    let mut f = OpenOptions::new()
        .append(true)
        .open(&file0)
        .expect("open block file");
    f.write_all(&[0xde; 300]).expect("append garbage");
    drop(f);

    // Reopen: the orphaned bytes must be truncated away.
    let db = Database::open(&opts).expect("reopen");
    assert_eq!(
        std::fs::metadata(&file0).expect("metadata").len(),
        clean_len,
        "orphaned block data was not truncated"
    );

    // The committed block is intact and new stores land correctly.
    let next = make_block(&mut rng);
    let next_hash = next.header.block_hash();
    db.update(|tx| tx.store_block(&next))
        .expect("store after recovery");
    db.view(|tx| {
        assert_eq!(tx.fetch_block(&committed_hash)?, committed.serialize());
        assert_eq!(tx.fetch_block(&next_hash)?, next.serialize());
        Ok(())
    })
    .expect("view");
}

/// The reverse tear: metadata says more block data exists than the
/// files actually hold.  That is unrecoverable data loss and must be
/// reported as corruption, exactly like dcrd.
#[test]
fn reconcile_detects_missing_block_data() {
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("db"), NET);
    let db = Database::create(&opts).expect("create");
    let mut rng = SplitMix64::from_entropy("db-crash-missing");

    let block = make_block(&mut rng);
    db.update(|tx| tx.store_block(&block)).expect("store");
    db.close().expect("close");
    drop(db);

    // Chop the tail off the block file.
    let file0 = dir.path().join("db").join("000000000.fdb");
    let len = std::fs::metadata(&file0).expect("metadata").len();
    let f = OpenOptions::new()
        .write(true)
        .open(&file0)
        .expect("open block file");
    f.set_len(len - 10).expect("truncate");
    drop(f);

    let err = match Database::open(&opts) {
        Ok(_) => panic!("open must fail"),
        Err(e) => e,
    };
    assert_eq!(err.kind, ErrorKind::Corruption);
}

/// Repeated random interleavings of commits and simulated tears: after
/// every recovery the database must contain exactly the committed
/// blocks and continue accepting new ones.
#[test]
fn reconcile_random_tear_soak() {
    let mut rng = SplitMix64::from_entropy("db-crash-soak");

    for round in 0..10 {
        let dir = TempDir::new().expect("tempdir");
        let opts = Options::new(dir.path().join("db"), NET);
        let db = Database::create(&opts).expect("create");

        let mut committed = Vec::new();
        for _ in 0..(rng.below(6) + 1) {
            let block = make_block(&mut rng);
            db.update(|tx| tx.store_block(&block)).expect("store");
            committed.push(block);
        }
        db.close().expect("close");
        drop(db);

        // Tear: append a random amount of garbage to the newest file.
        let mut newest = None;
        for num in 0..10u32 {
            let p = dir.path().join("db").join(format!("{num:09}.fdb"));
            if p.exists() {
                newest = Some(p);
            }
        }
        let newest = newest.expect("at least one block file");
        let garbage_len = rng.below(600) as usize + 1;
        let mut f = OpenOptions::new().append(true).open(&newest).expect("open");
        f.write_all(&vec![0xa5u8; garbage_len]).expect("append");
        drop(f);

        let db = Database::open(&opts).expect("recover");
        db.view(|tx| {
            for block in &committed {
                assert_eq!(
                    tx.fetch_block(&block.header.block_hash())?,
                    block.serialize(),
                    "round {round}: committed block lost after recovery"
                );
            }
            Ok(())
        })
        .expect("view");

        // The store must still accept and serve new blocks.
        let extra = make_block(&mut rng);
        db.update(|tx| tx.store_block(&extra))
            .expect("store after recovery");
        db.view(|tx| {
            assert_eq!(
                tx.fetch_block(&extra.header.block_hash())?,
                extra.serialize()
            );
            Ok(())
        })
        .expect("view");
    }
}

/// An unclean shutdown inside the write-cache window: the cached
/// metadata never reached the store, so reopening rolls the block
/// files back to the last durable flush and the database keeps
/// working — a consistent chain that is merely shorter, exactly
/// dcrd's contract (the daemon re-syncs the lost window).
#[test]
fn unclean_shutdown_loses_only_the_cached_window() {
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("db"), NET);
    let mut rng = SplitMix64::from_entropy("db-crash-window");

    // A durable base: one block, flushed to disk.
    let db = Database::create(&opts).expect("create");
    let base = make_block(&mut rng);
    let base_hash = base.header.block_hash();
    db.update(|tx| tx.store_block(&base)).expect("store base");
    db.flush().expect("flush");

    // A second block that stays in the cache window; the drop without
    // close is the crash.
    let lost = make_block(&mut rng);
    let lost_hash = lost.header.block_hash();
    db.update(|tx| tx.store_block(&lost)).expect("store lost");
    drop(db);

    let db = Database::open(&opts).expect("reopen");
    db.view(|tx| {
        assert_eq!(tx.fetch_block(&base_hash)?, base.serialize());
        assert!(!tx.has_block(&lost_hash)?, "cached block must be gone");
        Ok(())
    })
    .expect("view");

    // The rolled-back store accepts new blocks from there.
    let next = make_block(&mut rng);
    db.update(|tx| tx.store_block(&next)).expect("store next");
    db.close().expect("close");
}

// ---------------------------------------------------------------------
// Metadata crash consistency.
//
// Everything above this line stores blocks. Everything below writes
// buckets, which is what `process.rs` actually pairs and what a storage
// engine change would most plausibly break.
// ---------------------------------------------------------------------

/// The buckets `Chain::flush` writes in one transaction, named here so a
/// reader can check the correspondence: block index rows, UTXO entries,
/// and the two state markers that must never disagree with them.
const IDX_BUCKET: &[u8] = b"blockidxv3";
const UTXO_BUCKET: &[u8] = b"utxosetv3";
const UTXO_STATE_KEY: &[u8] = b"utxosetstate";
const CHAIN_STATE_KEY: &[u8] = b"chainstate";

/// Write `n` paired rows across both buckets plus both state markers, in
/// ONE transaction — the shape of `Chain::flush`.
fn write_paired_generation(
    db: &Database,
    generation: u32,
    n: u32,
) -> Result<(), dcroxide_database::Error> {
    db.update(|tx| {
        let meta = tx.metadata();
        let idx = meta.create_bucket_if_not_exists(IDX_BUCKET)?;
        let utxo = meta.create_bucket_if_not_exists(UTXO_BUCKET)?;
        for i in 0..n {
            let key = row_key(generation, i);
            idx.put(&key, &generation.to_be_bytes())?;
            utxo.put(&key, &generation.to_be_bytes())?;
        }
        // Both markers, in the same transaction as the rows they describe.
        meta.put(UTXO_STATE_KEY, &marker(generation, n))?;
        meta.put(CHAIN_STATE_KEY, &marker(generation, n))?;
        Ok(())
    })
}

fn row_key(generation: u32, i: u32) -> [u8; 8] {
    let mut k = [0u8; 8];
    k[..4].copy_from_slice(&generation.to_be_bytes());
    k[4..].copy_from_slice(&i.to_be_bytes());
    k
}

fn marker(generation: u32, n: u32) -> [u8; 8] {
    let mut v = [0u8; 8];
    v[..4].copy_from_slice(&generation.to_be_bytes());
    v[4..].copy_from_slice(&n.to_be_bytes());
    v
}

/// Read back what the store claims and what it holds, and assert they
/// agree in BOTH directions.
///
/// A marker claiming more rows than survive is lost data. A marker
/// claiming fewer is leaked data — a write that was never committed but
/// is visible anyway, which is the failure mode an engine with a
/// non-atomic batch produces and which a one-directional check misses.
fn assert_markers_agree_with_rows(db: &Database, context: &str) {
    db.view(|tx| {
        let meta = tx.metadata();
        let utxo_state = meta.get(UTXO_STATE_KEY);
        let chain_state = meta.get(CHAIN_STATE_KEY);
        assert_eq!(
            utxo_state, chain_state,
            "{context}: the two state markers disagree with each other"
        );
        let Some(state) = utxo_state else {
            // Nothing durable yet: then no rows may exist either.
            for bucket_name in [IDX_BUCKET, UTXO_BUCKET] {
                if let Some(b) = meta.bucket(bucket_name) {
                    let mut count = 0u32;
                    b.for_each(|_, _| {
                        count = count.saturating_add(1);
                        Ok(())
                    })?;
                    assert_eq!(
                        count, 0,
                        "{context}: no state marker, but {bucket_name:?} holds {count} rows"
                    );
                }
            }
            return Ok(());
        };
        let generation = u32::from_be_bytes(state[..4].try_into().expect("generation"));
        let claimed = u32::from_be_bytes(state[4..].try_into().expect("count"));

        for bucket_name in [IDX_BUCKET, UTXO_BUCKET] {
            let b = meta
                .bucket(bucket_name)
                .unwrap_or_else(|| panic!("{context}: marker present but {bucket_name:?} missing"));
            // Every row the marker claims must be present...
            for i in 0..claimed {
                assert!(
                    b.get(&row_key(generation, i)).is_some(),
                    "{context}: marker claims generation {generation} row {i}, which is missing \
                     from {bucket_name:?} -- the commit was torn"
                );
            }
            // ...and nothing from a LATER generation may be, which is the
            // direction a non-atomic engine fails.
            let mut leaked = 0u32;
            b.for_each(|k, _| {
                let g = u32::from_be_bytes(k[..4].try_into().expect("generation"));
                if g > generation {
                    leaked = leaked.saturating_add(1);
                }
                Ok(())
            })?;
            assert_eq!(
                leaked, 0,
                "{context}: {bucket_name:?} holds {leaked} rows from a generation after the \
                 marker's {generation} -- uncommitted writes survived"
            );
        }
        Ok(())
    })
    .expect("view");
}

/// A transaction spanning several buckets and both state markers is all
/// or nothing across an unclean shutdown.
///
/// This is the direct analogue of `Chain::flush`: if the engine can apply
/// the block index rows without the UTXO rows, or either without the
/// markers, the chain can come back claiming a state it does not hold.
#[test]
fn a_commit_spanning_buckets_is_all_or_nothing() {
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("db"), NET);

    // Generation 0, made durable.
    let db = Database::create(&opts).expect("create");
    write_paired_generation(&db, 0, 64).expect("generation 0");
    db.flush().expect("flush");

    // Generation 1 stays in the cache window; the drop is the crash.
    write_paired_generation(&db, 1, 64).expect("generation 1");
    drop(db);

    let db = Database::open(&opts).expect("reopen");
    assert_markers_agree_with_rows(&db, "after crash in the cache window");
    db.view(|tx| {
        let meta = tx.metadata();
        let state = meta.get(UTXO_STATE_KEY).expect("marker");
        assert_eq!(
            u32::from_be_bytes(state[..4].try_into().unwrap()),
            0,
            "the uncommitted generation must not be visible"
        );
        Ok(())
    })
    .expect("view");
    db.close().expect("close");
}

/// The same pairing, torn at many different points.
///
/// One crash can land in a quiet moment. This walks the tear across a
/// range of commit sizes so the window between "rows written" and
/// "markers written" is hit at different offsets.
#[test]
fn paired_commits_never_desync_under_repeated_tears() {
    let mut rng = SplitMix64::from_entropy("db-crash-paired");

    for round in 0..12u32 {
        let dir = TempDir::new().expect("tempdir");
        let opts = Options::new(dir.path().join("db"), NET);
        let db = Database::create(&opts).expect("create");

        // A few durable generations.
        let durable = rng.below(4) as u32 + 1;
        for generation in 0..durable {
            write_paired_generation(&db, generation, rng.below(200) as u32 + 1)
                .expect("durable generation");
        }
        db.flush().expect("flush");

        // Then one that is not, of a size that varies per round.
        write_paired_generation(&db, durable, rng.below(500) as u32 + 1).expect("torn generation");
        drop(db);

        let db = Database::open(&opts).expect("recover");
        assert_markers_agree_with_rows(&db, &format!("round {round}"));

        // And the store must keep working from there.
        write_paired_generation(&db, durable + 1, 8).expect("write after recovery");
        db.flush().expect("flush after recovery");
        assert_markers_agree_with_rows(&db, &format!("round {round} after recovery"));
        db.close().expect("close");
    }
}

/// Block data and the metadata describing it roll back together.
///
/// `DbCache::flush` syncs the flat block files *before* it commits
/// metadata, so a crash can land between the two durability domains. What
/// must never happen is a block that recovery keeps while the metadata
/// naming it is gone, or metadata naming a block whose bytes were rolled
/// back.
#[test]
fn block_data_and_its_metadata_roll_back_together() {
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("db"), NET);
    let mut rng = SplitMix64::from_entropy("db-crash-domains");

    let db = Database::create(&opts).expect("create");

    // Durable: a block plus the metadata row naming it, one transaction.
    let kept = make_block(&mut rng);
    let kept_hash = kept.header.block_hash();
    db.update(|tx| {
        tx.store_block(&kept)?;
        let b = tx.metadata().create_bucket_if_not_exists(IDX_BUCKET)?;
        b.put(&kept_hash.0, b"kept")?;
        Ok(())
    })
    .expect("store kept");
    db.flush().expect("flush");

    // Not durable: the same pairing, lost to the crash.
    let lost = make_block(&mut rng);
    let lost_hash = lost.header.block_hash();
    db.update(|tx| {
        tx.store_block(&lost)?;
        let b = tx.metadata().create_bucket_if_not_exists(IDX_BUCKET)?;
        b.put(&lost_hash.0, b"lost")?;
        Ok(())
    })
    .expect("store lost");
    drop(db);

    let db = Database::open(&opts).expect("reopen");
    db.view(|tx| {
        let b = tx.metadata().bucket(IDX_BUCKET).expect("index bucket");

        // The durable pair survived intact, both halves.
        assert_eq!(tx.fetch_block(&kept_hash)?, kept.serialize());
        assert_eq!(b.get(&kept_hash.0).as_deref(), Some(b"kept".as_slice()));

        // The torn pair is gone, both halves. Either half surviving alone
        // is the desync this test exists to catch.
        let has_block = tx.has_block(&lost_hash)?;
        let has_meta = b.get(&lost_hash.0).is_some();
        assert!(
            !has_block && !has_meta,
            "torn commit half-survived: block={has_block} metadata={has_meta}"
        );
        Ok(())
    })
    .expect("view");
    db.close().expect("close");
}

/// Committed metadata survives the block-file rollback.
///
/// `reconcile_truncates_orphaned_block_data` proves the flat files are
/// rewound. This proves the rewind does not take durable metadata with
/// it — recovery reconciles two domains, and a fix to one that damages
/// the other would pass every test in this file before today.
#[test]
fn durable_metadata_survives_block_file_truncation() {
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("db"), NET);
    let mut rng = SplitMix64::from_entropy("db-crash-truncate-meta");

    let db = Database::create(&opts).expect("create");
    let block = make_block(&mut rng);
    let block_hash = block.header.block_hash();
    db.update(|tx| tx.store_block(&block)).expect("store");
    write_paired_generation(&db, 0, 32).expect("metadata");
    db.close().expect("close");
    drop(db);

    // Orphaned block bytes, as if writeBlock ran and the commit did not.
    let file0 = dir.path().join("db").join("000000000.fdb");
    let clean_len = std::fs::metadata(&file0).expect("metadata").len();
    let mut f = OpenOptions::new()
        .append(true)
        .open(&file0)
        .expect("open block file");
    f.write_all(&[0x5a; 512]).expect("append garbage");
    drop(f);

    let db = Database::open(&opts).expect("reopen");
    assert_eq!(
        std::fs::metadata(&file0).expect("metadata").len(),
        clean_len,
        "orphaned block data was not truncated"
    );
    assert_markers_agree_with_rows(&db, "after block-file truncation");
    db.view(|tx| {
        assert_eq!(tx.fetch_block(&block_hash)?, block.serialize());
        Ok(())
    })
    .expect("view");
    db.close().expect("close");
}

/// Deletes are part of the pairing too.
///
/// The spend journal is *removed* on a disconnect, so a reorganisation is
/// a commit of puts and deletes together. An engine that made deletes
/// durable on a different path from puts would leave a store that has
/// forgotten a row it still claims, and no test above would see it.
#[test]
fn deletes_are_atomic_with_the_puts_beside_them() {
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("db"), NET);

    let db = Database::create(&opts).expect("create");
    write_paired_generation(&db, 0, 128).expect("generation 0");
    db.flush().expect("flush");

    // A disconnect-shaped commit: drop half of generation 0's rows and
    // rewrite both markers to match, in one transaction. Not flushed.
    db.update(|tx| {
        let meta = tx.metadata();
        let idx = meta.bucket(IDX_BUCKET).expect("index bucket");
        let utxo = meta.bucket(UTXO_BUCKET).expect("utxo bucket");
        for i in 64..128u32 {
            idx.delete(&row_key(0, i))?;
            utxo.delete(&row_key(0, i))?;
        }
        meta.put(UTXO_STATE_KEY, &marker(0, 64))?;
        meta.put(CHAIN_STATE_KEY, &marker(0, 64))?;
        Ok(())
    })
    .expect("disconnect");
    drop(db);

    // The whole disconnect is rolled back: the marker says 128 again and
    // all 128 rows must be there. A store that kept the deletes while
    // losing the marker rewrite would claim 128 and hold 64.
    let db = Database::open(&opts).expect("reopen");
    assert_markers_agree_with_rows(&db, "after a torn disconnect");
    db.view(|tx| {
        let state = tx.metadata().get(UTXO_STATE_KEY).expect("marker");
        assert_eq!(
            u32::from_be_bytes(state[4..].try_into().unwrap()),
            128,
            "the torn disconnect must roll back to the durable count"
        );
        Ok(())
    })
    .expect("view");

    // And the same disconnect, made durable, must stick.
    db.update(|tx| {
        let meta = tx.metadata();
        let idx = meta.bucket(IDX_BUCKET).expect("index bucket");
        let utxo = meta.bucket(UTXO_BUCKET).expect("utxo bucket");
        for i in 64..128u32 {
            idx.delete(&row_key(0, i))?;
            utxo.delete(&row_key(0, i))?;
        }
        meta.put(UTXO_STATE_KEY, &marker(0, 64))?;
        meta.put(CHAIN_STATE_KEY, &marker(0, 64))?;
        Ok(())
    })
    .expect("disconnect");
    db.flush().expect("flush");
    drop(db);

    let db = Database::open(&opts).expect("reopen");
    assert_markers_agree_with_rows(&db, "after a durable disconnect");
    db.view(|tx| {
        let idx = tx.metadata().bucket(IDX_BUCKET).expect("index bucket");
        assert!(
            idx.get(&row_key(0, 100)).is_none(),
            "a durable delete came back"
        );
        assert!(
            idx.get(&row_key(0, 10)).is_some(),
            "a durable delete took a row it should not have"
        );
        Ok(())
    })
    .expect("view");
    db.close().expect("close");
}

/// A data directory written by a dcroxide built against redb 2.x must be
/// refused with an actionable message, not misread and not reported as
/// damage.
///
/// The 4.x upgrade changed the on-disk format, and dcroxide has no
/// in-place migration — ADR-0004's fresh-sync stance means it does not
/// need one. What it does need is for the two failures an operator can
/// hit to look different: "this directory predates the upgrade, re-sync"
/// and "this directory is corrupt" call for opposite reactions, and a
/// generic driver error would conflate them.
///
/// This writes a genuine old-format file with the previous major rather
/// than a handcrafted fixture, so it keeps testing the real thing if
/// either version moves.
#[test]
fn a_redb2_data_directory_is_refused_with_an_upgrade_message() {
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("db");
    std::fs::create_dir_all(&db_path).expect("mkdir");
    let metadata = db_path.join("metadata.redb");

    // A real redb 2.x store, written by redb 2.x.
    {
        let old = redb2::Database::create(&metadata).expect("create v2");
        let tx = old.begin_write().expect("begin");
        {
            let table: redb2::TableDefinition<&[u8], &[u8]> =
                redb2::TableDefinition::new("metadata");
            let mut t = tx.open_table(table).expect("open");
            t.insert(b"k".as_slice(), b"v".as_slice()).expect("insert");
        }
        tx.commit().expect("commit");
    }

    let err = match Database::open(&Options::new(&db_path, NET)) {
        Ok(_) => panic!("a redb 2.x store must not open under redb 4"),
        Err(e) => e,
    };
    assert_eq!(
        err.kind,
        ErrorKind::Invalid,
        "an old format must not be reported as corruption: {err}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("redb 2.x") && msg.contains("sync again"),
        "the message must tell the operator what to do, got: {msg}"
    );
    assert!(
        msg.contains("not damaged"),
        "the message must distinguish this from corruption, got: {msg}"
    );
}

// ---------------------------------------------------------------------
// Power loss
//
// Everything above this line uses `drop` without `close` as its crash
// primitive. That models process death and nothing more: the page cache
// survives it, so every byte written but never `fsync`ed is still
// readable after the reopen. Killing the process outright would be no
// better for the same reason. A store that skipped its durability step
// entirely passes all of it.
//
// The tests below close that gap with storage that discards what was
// never synced, which is the one thing that tells a durable commit from
// a merely-written one. They exist ahead of any deferred-fsync work
// rather than after it, because that work is exactly what they guard —
// and `power_loss_detects_a_store_that_never_syncs` checks that they can
// actually fail, by running the same sequence against a backend whose
// `sync_data` does nothing.
// ---------------------------------------------------------------------

use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

/// Storage that models power loss.
///
/// Every write is forwarded to a real file, but the bytes it overwrote
/// are kept first, so `cut_power` can put the file back exactly as it
/// stood at the last successful `sync_data`. An extending write is
/// undone by the recorded durable length rather than by its old bytes,
/// since it had none.
///
/// `honest_sync` is what gives the rig teeth: with it false the backend
/// acknowledges `sync_data` without doing anything, which is precisely
/// the mistake a deferred-fsync design can make, and the suite must
/// notice.
#[derive(Debug)]
struct PowerLossBackend {
    file: Mutex<std::fs::File>,
    /// `(offset, previous bytes)` for each write since the last sync,
    /// oldest first; replayed in reverse to undo them.
    undo: Mutex<Vec<(u64, Vec<u8>)>>,
    /// File length as of the last sync, so extensions are truncated away.
    durable_len: Mutex<u64>,
    honest_sync: bool,
}

impl PowerLossBackend {
    fn create(path: &std::path::Path, honest_sync: bool) -> Arc<PowerLossBackend> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .expect("open backing file");
        let len = file.metadata().expect("metadata").len();
        Arc::new(PowerLossBackend {
            file: Mutex::new(file),
            undo: Mutex::new(Vec::new()),
            durable_len: Mutex::new(len),
            honest_sync,
        })
    }

    /// Discard every write since the last successful sync, as a power
    /// cut would.
    fn cut_power(&self) {
        let mut file = self.file.lock().expect("file lock");
        let mut undo = self.undo.lock().expect("undo lock");
        let durable = *self.durable_len.lock().expect("len lock");
        // Reverse order: a region written twice must end up holding what
        // it held before the FIRST of those writes.
        for (offset, previous) in undo.drain(..).rev() {
            if offset < durable {
                let keep =
                    std::cmp::min(previous.len() as u64, durable.saturating_sub(offset)) as usize;
                file.seek(SeekFrom::Start(offset)).expect("seek");
                file.write_all(&previous[..keep]).expect("undo write");
            }
        }
        file.set_len(durable).expect("truncate to durable length");
        file.sync_all().expect("sync after power cut");
    }
}

impl redb::StorageBackend for PowerLossBackend {
    fn len(&self) -> Result<u64, std::io::Error> {
        Ok(self.file.lock().expect("file lock").metadata()?.len())
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), std::io::Error> {
        let mut file = self.file.lock().expect("file lock");
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(out)
    }

    fn set_len(&self, len: u64) -> Result<(), std::io::Error> {
        self.file.lock().expect("file lock").set_len(len)
    }

    fn sync_data(&self) -> Result<(), std::io::Error> {
        if !self.honest_sync {
            // Acknowledge without persisting: the failure mode under test.
            return Ok(());
        }
        let file = self.file.lock().expect("file lock");
        file.sync_data()?;
        let len = file.metadata()?.len();
        drop(file);
        self.undo.lock().expect("undo lock").clear();
        *self.durable_len.lock().expect("len lock") = len;
        Ok(())
    }

    fn write(&self, offset: u64, data: &[u8]) -> Result<(), std::io::Error> {
        let mut file = self.file.lock().expect("file lock");
        let len = file.metadata()?.len();
        // Keep whatever this write is about to destroy, but only the part
        // that exists: past EOF there is nothing to restore and the
        // truncate in `cut_power` removes it instead.
        if offset < len {
            let keep = std::cmp::min(data.len() as u64, len.saturating_sub(offset)) as usize;
            let mut previous = vec![0u8; keep];
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(&mut previous)?;
            self.undo
                .lock()
                .expect("undo lock")
                .push((offset, previous));
        }
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(data)
    }
}

/// Options wired to a power-loss backend over this directory's metadata
/// file, plus the handle the test keeps to cut power with.
fn power_loss_opts(dir: &std::path::Path, honest_sync: bool) -> (Options, Arc<PowerLossBackend>) {
    std::fs::create_dir_all(dir).expect("mkdir");
    let backend = PowerLossBackend::create(&dir.join("metadata.redb"), honest_sync);
    let mut opts = Options::new(dir, NET);
    opts.backend = Some(Arc::clone(&backend) as dcroxide_database::SharedBackend);
    (opts, backend)
}

/// A durably flushed generation survives a power cut intact.
#[test]
fn power_loss_after_a_flush_keeps_the_flushed_generation() {
    let dir = TempDir::new().expect("tempdir");
    let db_dir = dir.path().join("db");
    let (opts, backend) = power_loss_opts(&db_dir, true);

    let db = Database::create(&opts).expect("create");
    write_paired_generation(&db, 1, 64).expect("generation 1");
    db.flush().expect("flush");
    drop(db);
    backend.cut_power();

    // Reopen WITHOUT the backend: the file now holds only what was synced.
    let reopened = Database::open(&Options::new(&db_dir, NET)).expect("reopen");
    assert_markers_agree_with_rows(&reopened, "after power loss following a flush");
    reopened
        .view(|tx| {
            assert_eq!(
                tx.metadata().get(UTXO_STATE_KEY),
                Some(marker(1, 64).to_vec()),
                "the flushed generation must survive a power cut"
            );
            Ok(())
        })
        .expect("view");
}

/// An unflushed window is lost, but what survives is internally
/// consistent — the property a node actually needs, since it re-syncs
/// the rest.
#[test]
fn power_loss_before_a_flush_stays_internally_consistent() {
    let dir = TempDir::new().expect("tempdir");
    let db_dir = dir.path().join("db");
    let (opts, backend) = power_loss_opts(&db_dir, true);

    let db = Database::create(&opts).expect("create");
    write_paired_generation(&db, 1, 64).expect("generation 1");
    db.flush().expect("flush");
    // Committed to the overlay but never flushed: the window a crash eats.
    write_paired_generation(&db, 2, 64).expect("generation 2");
    drop(db);
    backend.cut_power();

    let reopened = Database::open(&Options::new(&db_dir, NET)).expect("reopen");
    assert_markers_agree_with_rows(&reopened, "after power loss before a flush");
    reopened
        .view(|tx| {
            assert_eq!(
                tx.metadata().get(UTXO_STATE_KEY),
                Some(marker(1, 64).to_vec()),
                "the store must land on the last DURABLE generation, not a later one"
            );
            Ok(())
        })
        .expect("view");
}

/// The rig has teeth.
///
/// Same sequence as the first test, against a backend that acknowledges
/// `sync_data` without doing anything — the mistake a deferred-fsync
/// design makes. The flushed generation must NOT survive. If this ever
/// starts passing, the two tests above have stopped testing durability
/// and are only testing that files can be written.
#[test]
fn power_loss_detects_a_store_that_never_syncs() {
    let dir = TempDir::new().expect("tempdir");
    let db_dir = dir.path().join("db");
    let (opts, backend) = power_loss_opts(&db_dir, false);

    let db = Database::create(&opts).expect("create");
    write_paired_generation(&db, 1, 64).expect("generation 1");
    db.flush().expect("flush");
    drop(db);
    backend.cut_power();

    // Everything the "flush" claimed to persist is gone, so the store is
    // either unopenable or empty of that generation. Both are detections;
    // silently returning generation 1 is not.
    let mut survived: Option<Vec<u8>> = None;
    if let Ok(reopened) = Database::open(&Options::new(&db_dir, NET)) {
        let _ = reopened.view(|tx| {
            survived = tx.metadata().get(UTXO_STATE_KEY);
            Ok(())
        });
    }
    assert_ne!(
        survived,
        Some(marker(1, 64).to_vec()),
        "a backend that never syncs must not be able to produce a surviving flush — \
         if it can, these tests cannot detect a missing fsync and the rig is decorative"
    );
}
