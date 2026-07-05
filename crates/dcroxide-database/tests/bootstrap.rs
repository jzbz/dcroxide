// SPDX-License-Identifier: ISC
//! Bootstrap-format bulk import/export tests: round trips through the
//! database, dcrd `readBlock` behaviors (clean EOF termination, network
//! mismatch, oversized payloads, truncated records), duplicate
//! skipping, and byte-identical re-export.

use std::io::Cursor;

use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, ErrorKind, Options, bootstrap};
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

/// Build a bootstrap stream for the given blocks.
fn bootstrap_bytes(blocks: &[MsgBlock], network: u32) -> Vec<u8> {
    let mut out = Vec::new();
    for block in blocks {
        bootstrap::write_block(&mut out, network, &block.serialize()).expect("write");
    }
    out
}

#[test]
fn import_export_round_trip() {
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("db"), NET);
    let db = Database::create(&opts).expect("create");
    let mut rng = SplitMix64::from_entropy("db-bootstrap-roundtrip");

    // Enough blocks to span several import batches.
    let blocks: Vec<MsgBlock> = (0..600).map(|_| make_block(&mut rng)).collect();
    let hashes: Vec<Hash> = blocks.iter().map(|b| b.header.block_hash()).collect();
    let stream = bootstrap_bytes(&blocks, NET);

    // Import stores every block.
    let stats = db
        .import_blocks(&mut Cursor::new(&stream), NET)
        .expect("import");
    assert_eq!(stats.read, 600);
    assert_eq!(stats.imported, 600);
    assert_eq!(stats.skipped, 0);
    db.view(|tx| {
        assert_eq!(tx.has_blocks(&hashes)?, vec![true; hashes.len()]);
        Ok(())
    })
    .expect("view");

    // Importing the same stream again skips everything.
    let stats = db
        .import_blocks(&mut Cursor::new(&stream), NET)
        .expect("re-import");
    assert_eq!(stats.read, 600);
    assert_eq!(stats.imported, 0);
    assert_eq!(stats.skipped, 600);

    // Export reproduces the byte-identical stream.
    let mut exported = Vec::new();
    let n = db
        .export_blocks(&mut exported, NET, &hashes)
        .expect("export");
    assert_eq!(n, 600);
    assert_eq!(exported, stream);

    // Exporting an unknown hash errors with ErrBlockNotFound.
    let unknown = [Hash([0x77; 32])];
    assert_eq!(
        db.export_blocks(&mut Vec::new(), NET, &unknown)
            .err()
            .map(|e| e.kind),
        Some(ErrorKind::BlockNotFound)
    );
}

#[test]
fn reader_error_behaviors() {
    let mut rng = SplitMix64::from_entropy("db-bootstrap-reader");
    let block = make_block(&mut rng);
    let raw = block.serialize();

    // Clean EOF at a record boundary terminates with None.
    let stream = bootstrap_bytes(std::slice::from_ref(&block), NET);
    let mut r = Cursor::new(&stream);
    assert!(bootstrap::read_block(&mut r, NET).expect("read").is_some());
    assert!(bootstrap::read_block(&mut r, NET).expect("eof").is_none());

    // An empty stream is a clean termination too.
    let mut r = Cursor::new(&[] as &[u8]);
    assert!(bootstrap::read_block(&mut r, NET).expect("eof").is_none());

    // Network mismatch errors.
    let mut r = Cursor::new(&stream);
    assert!(bootstrap::read_block(&mut r, NET + 1).is_err());

    // A block length beyond MaxBlockPayload errors.
    let mut oversized = Vec::new();
    oversized.extend_from_slice(&NET.to_le_bytes());
    oversized.extend_from_slice(&(1_310_720u32 + 1).to_le_bytes());
    let mut r = Cursor::new(&oversized);
    assert!(bootstrap::read_block(&mut r, NET).is_err());

    // A record truncated mid-block errors rather than terminating.
    let mut truncated = Vec::new();
    bootstrap::write_block(&mut truncated, NET, &raw).expect("write");
    truncated.truncate(truncated.len() - 5);
    let mut r = Cursor::new(&truncated);
    assert!(bootstrap::read_block(&mut r, NET).is_err());

    // A record truncated mid-length-field errors as well.
    let mut r = Cursor::new(&stream[..6]);
    assert!(bootstrap::read_block(&mut r, NET).is_err());

    // A malformed (undeserializable) block fails the import.
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("db"), NET);
    let db = Database::create(&opts).expect("create");
    let mut garbage_stream = Vec::new();
    bootstrap::write_block(&mut garbage_stream, NET, &[0xab; 40]).expect("write");
    assert!(
        db.import_blocks(&mut Cursor::new(&garbage_stream), NET)
            .is_err()
    );
}
