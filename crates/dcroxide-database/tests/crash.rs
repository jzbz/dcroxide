// SPDX-License-Identifier: ISC
//! Crash-consistency rig (Phase 7 exit criterion): reproduce the torn
//! states an unclean shutdown can leave behind — block file bytes
//! written but the metadata commit lost, and metadata claiming more
//! than the files hold — and verify recovery matches dcrd's
//! `reconcileDB` semantics.

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
