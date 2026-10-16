// SPDX-License-Identifier: ISC
//! Block storage API battery, ported from the block-storage portions of
//! dcrd's database/ffldb `interface_test.go` and `whitebox_test.go`
//! behaviors: store/fetch round trips, pending-block visibility inside
//! the transaction, plural fetch APIs, region bounds, error kinds,
//! persistence across reopen, flat-file rollover, and the exact ffldb
//! record byte format.

use std::sync::Arc;

use dcroxide_chainhash::Hash;
use dcroxide_database::{BlockRecord, BlockRegion, Database, Error, ErrorKind, Options};
use dcroxide_testutil::SplitMix64;
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint, TxIn, TxOut, TxSerializeType};
use tempfile::TempDir;

const NET: u32 = 0x12141c16; // simnet magic

fn kind_of(err: Error) -> ErrorKind {
    err.kind
}

/// Each block's hash with the height its header records, the pair that
/// keys its index row.
fn keys_of(blocks: &[MsgBlock]) -> Vec<(Hash, u32)> {
    blocks
        .iter()
        .map(|b| (b.header.block_hash(), b.header.height))
        .collect()
}

fn make_block(rng: &mut SplitMix64) -> MsgBlock {
    let mut raw_header = [0u8; 180];
    rng.fill(&mut raw_header);
    let (header, _) = BlockHeader::from_bytes(&raw_header).expect("header");

    let mut prev = [0u8; 32];
    rng.fill(&mut prev);
    let tx = MsgTx {
        ser_type: TxSerializeType::Full,
        version: 1,
        tx_in: vec![TxIn {
            previous_out_point: OutPoint {
                hash: Hash(prev),
                index: rng.below(4) as u32,
                tree: 0,
            },
            sequence: 0xffff_ffff,
            value_in: rng.below(1 << 40) as i64,
            block_height: 0,
            block_index: 0,
            signature_script: rng.bytes(32),
        }],
        tx_out: vec![TxOut {
            value: rng.below(1 << 40) as i64,
            version: 0,
            pk_script: rng.bytes(40),
        }],
        lock_time: 0,
        expiry: 0,
    };
    MsgBlock {
        header,
        transactions: vec![tx],
        stransactions: Vec::new(),
    }
}

#[test]
fn block_store_fetch_round_trip() {
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("db"), NET);
    let db = Database::create(&opts).expect("create");
    let mut rng = SplitMix64::from_entropy("db-block-roundtrip");

    let blocks: Vec<MsgBlock> = (0..10).map(|_| make_block(&mut rng)).collect();
    let hashes = keys_of(&blocks);
    let serialized: Vec<Vec<u8>> = blocks.iter().map(MsgBlock::serialize).collect();

    db.update(|tx| {
        for (i, block) in blocks.iter().enumerate() {
            let (hash, height) = hashes[i];
            // Not present before the store.
            assert!(!tx.has_block(&hash, height)?);
            assert_eq!(
                tx.fetch_block(&hash, height).err().map(kind_of),
                Some(ErrorKind::BlockNotFound)
            );

            tx.store_block(block)?;

            // Storing the same block again in the same tx fails.
            assert_eq!(
                tx.store_block(block).err().map(kind_of),
                Some(ErrorKind::BlockExists)
            );

            // Pending blocks are fully visible within the transaction.
            assert!(tx.has_block(&hash, height)?);
            assert_eq!(tx.fetch_block(&hash, height)?, serialized[i]);
            assert_eq!(tx.fetch_block_header(&hash, height)?, serialized[i][..180]);
            let region = BlockRegion {
                hash,
                offset: 8,
                len: 12,
            };
            assert_eq!(
                tx.fetch_block_region(&region, height)?,
                serialized[i][8..20]
            );

            // Out-of-bounds regions on a pending block.
            let bad = BlockRegion {
                hash,
                offset: serialized[i].len() as u32 - 4,
                len: 8,
            };
            assert_eq!(
                tx.fetch_block_region(&bad, height).err().map(kind_of),
                Some(ErrorKind::BlockRegionInvalid)
            );

            // A pending block is not found under another height.
            let other = height.wrapping_add(1);
            assert!(!tx.has_block(&hash, other)?);
            assert_eq!(
                tx.fetch_block(&hash, other).err().map(kind_of),
                Some(ErrorKind::BlockNotFound)
            );
        }
        Ok(())
    })
    .expect("update");

    // Everything is visible after the commit, incl. the plural APIs.
    db.view(|tx| {
        assert_eq!(tx.has_blocks(&hashes)?, vec![true; hashes.len()]);
        assert_eq!(tx.fetch_blocks(&hashes)?, serialized);
        let headers = tx.fetch_block_headers(&hashes)?;
        for (i, header) in headers.iter().enumerate() {
            assert_eq!(header.as_slice(), &serialized[i][..180]);
        }

        // Regions across several blocks.
        let regions: Vec<(BlockRegion, u32)> = hashes
            .iter()
            .map(|&(hash, height)| {
                let region = BlockRegion {
                    hash,
                    offset: 4,
                    len: 20,
                };
                (region, height)
            })
            .collect();
        let datas = tx.fetch_block_regions(&regions)?;
        for (i, data) in datas.iter().enumerate() {
            assert_eq!(data.as_slice(), &serialized[i][4..24]);
        }

        // A committed region may reach into the record's trailing
        // overhead bytes: dcrd bounds the check by the full record
        // length (raw block + 12 bytes of network/length/checksum
        // overhead), so the first byte past the raw block serves the
        // checksum rather than erroring.
        let (hash0, height0) = hashes[0];
        let into_overhead = BlockRegion {
            hash: hash0,
            offset: serialized[0].len() as u32,
            len: 1,
        };
        assert_eq!(tx.fetch_block_region(&into_overhead, height0)?.len(), 1);

        // Past the full record the region is invalid.
        let bad = BlockRegion {
            hash: hash0,
            offset: serialized[0].len() as u32 + 12,
            len: 1,
        };
        assert_eq!(
            tx.fetch_block_region(&bad, height0).err().map(kind_of),
            Some(ErrorKind::BlockRegionInvalid)
        );

        // Unknown block.
        let unknown = Hash([0x55; 32]);
        assert!(!tx.has_block(&unknown, 0)?);
        assert_eq!(
            tx.fetch_block_header(&unknown, 0).err().map(kind_of),
            Some(ErrorKind::BlockNotFound)
        );

        // A stored block is not found under another height: the height
        // is part of its index row's key.
        let other = height0.wrapping_add(1);
        assert!(!tx.has_block(&hash0, other)?);
        for err in [
            tx.fetch_block(&hash0, other).err(),
            tx.fetch_block_header(&hash0, other).err(),
            tx.fetch_block_region(&into_overhead, other).err(),
        ] {
            let err = err.expect("no block under another height");
            assert_eq!(err.kind, ErrorKind::BlockNotFound);
            assert_eq!(err.description, format!("block {hash0} does not exist"));
        }
        Ok(())
    })
    .expect("view");

    // Storing an already-committed block in a new tx fails; rolled
    // back stores do not persist.
    let extra = make_block(&mut rng);
    let (extra_hash, extra_height) = (extra.header.block_hash(), extra.header.height);
    db.update(|tx| {
        assert_eq!(
            tx.store_block(&blocks[0]).err().map(kind_of),
            Some(ErrorKind::BlockExists)
        );
        Ok(())
    })
    .expect("update");
    {
        let tx = db.begin(true).expect("begin");
        tx.store_block(&extra).expect("store");
        tx.rollback().expect("rollback");
    }
    db.view(|tx| {
        assert!(!tx.has_block(&extra_hash, extra_height)?);
        Ok(())
    })
    .expect("view");

    // Read-only transactions cannot store blocks.
    db.view(|tx| {
        assert_eq!(
            tx.store_block(&extra).err().map(kind_of),
            Some(ErrorKind::TxNotWritable)
        );
        Ok(())
    })
    .expect("view");

    // Everything survives a reopen.
    db.close().expect("close");
    drop(db);
    let db = Database::open(&opts).expect("reopen");
    db.view(|tx| {
        assert_eq!(tx.fetch_blocks(&hashes)?, serialized);
        Ok(())
    })
    .expect("view");
}

#[test]
fn block_file_rollover_and_record_format() {
    let dir = TempDir::new().expect("tempdir");
    let mut opts = Options::new(dir.path().join("db"), NET);
    // Small file cap to force rollover across several files.
    opts.max_block_file_size = 2048;
    let db = Database::create(&opts).expect("create");
    let mut rng = SplitMix64::from_entropy("db-block-rollover");

    let blocks: Vec<MsgBlock> = (0..12).map(|_| make_block(&mut rng)).collect();
    let hashes = keys_of(&blocks);
    let serialized: Vec<Vec<u8>> = blocks.iter().map(MsgBlock::serialize).collect();

    for block in &blocks {
        db.update(|tx| tx.store_block(block)).expect("store");
    }

    // Multiple physical files must exist.
    let file0 = dir.path().join("db").join("000000000.fdb");
    let file1 = dir.path().join("db").join("000000001.fdb");
    assert!(file0.exists());
    assert!(file1.exists(), "expected block file rollover");

    // All blocks read back correctly across the files.
    db.view(|tx| {
        assert_eq!(tx.fetch_blocks(&hashes)?, serialized);
        Ok(())
    })
    .expect("view");

    // The first record in the first file uses dcrd's exact ffldb byte
    // format: network (LE) || length (LE) || block || CRC-32C (BE) of
    // all preceding record bytes.
    let raw = std::fs::read(&file0).expect("read block file");
    let want_len = serialized[0].len();
    assert_eq!(&raw[0..4], NET.to_le_bytes().as_slice());
    assert_eq!(&raw[4..8], (want_len as u32).to_le_bytes().as_slice());
    assert_eq!(&raw[8..8 + want_len], serialized[0].as_slice());
    let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);
    let want_crc = crc.checksum(&raw[..8 + want_len]);
    assert_eq!(
        &raw[8 + want_len..12 + want_len],
        want_crc.to_be_bytes().as_slice()
    );

    // Anchor the polynomial itself: CRC-32C has check value 0xe3069283
    // over "123456789".
    assert_eq!(crc.checksum(b"123456789"), 0xe306_9283);
}

#[test]
fn corrupted_block_file_detected() {
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("db"), NET);
    let db = Database::create(&opts).expect("create");
    let mut rng = SplitMix64::from_entropy("db-block-corrupt");

    let block = make_block(&mut rng);
    let (hash, height) = (block.header.block_hash(), block.header.height);
    db.update(|tx| tx.store_block(&block)).expect("store");
    db.close().expect("close");
    drop(db);

    // Flip a byte in the middle of the stored block data.
    let file0 = dir.path().join("db").join("000000000.fdb");
    let mut raw = std::fs::read(&file0).expect("read");
    raw[20] ^= 0xff;
    std::fs::write(&file0, &raw).expect("write");

    let db = Database::open(&opts).expect("open");
    db.view(|tx| {
        // Full block reads verify the checksum.
        assert_eq!(
            tx.fetch_block(&hash, height).err().map(kind_of),
            Some(ErrorKind::Corruption)
        );
        // Headers come from the metadata index and remain intact.
        assert_eq!(tx.fetch_block_header(&hash, height)?.len(), 180);
        Ok(())
    })
    .expect("view");
}

/// The internal block index files a block's row under its big-endian
/// height and then its hash -- dcroxide's layout, where ffldb keys it by
/// hash -- so the rows of consecutive blocks sit side by side and a walk
/// meets them in height order, blocks sharing a height by hash.  The row
/// itself is ffldb's: the block's location, then its header.
#[test]
fn block_index_rows_are_keyed_by_height_then_hash() {
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("db"), NET);
    let db = Database::create(&opts).expect("create");
    let mut rng = SplitMix64::from_entropy("db-block-index-order");

    // Heights that little-endian or hash order would scatter: byte
    // boundaries, and two blocks at one height.
    let heights = [65_536u32, 1, 256, 255, 0, 7, 7, 16_777_216];
    let blocks: Vec<MsgBlock> = heights
        .iter()
        .map(|&height| {
            let mut block = make_block(&mut rng);
            block.header.height = height;
            block
        })
        .collect();
    db.update(|tx| blocks.iter().try_for_each(|block| tx.store_block(block)))
        .expect("store");

    let mut want: Vec<(Vec<u8>, Vec<u8>)> = blocks
        .iter()
        .map(|block| {
            let mut key = block.header.height.to_be_bytes().to_vec();
            key.extend_from_slice(&block.header.block_hash().0);
            (key, block.header.serialize().to_vec())
        })
        .collect();
    want.sort();

    // The committed rows, read through the overlay and then the store.
    assert_eq!(block_index_rows(&db), want, "the overlay");
    db.close().expect("close");
    drop(db);
    let db = Database::open(&opts).expect("reopen");
    assert_eq!(block_index_rows(&db), want, "the store");
}

/// A block stored under a hash the caller holds is the block
/// `store_block` stores: the same record in the block file, the same
/// index row and the same answers, with the same errors for a block the
/// database has and for a transaction that cannot write.  The one
/// difference is that the header is not hashed by the store.
#[test]
fn a_block_stored_under_its_hash_in_hand_is_stored_as_store_block_stores_it() {
    let dir = TempDir::new().expect("tempdir");
    let mut rng = SplitMix64::from_entropy("db-block-hash-in-hand");
    let blocks: Vec<MsgBlock> = (0..10).map(|_| make_block(&mut rng)).collect();
    let hashes = keys_of(&blocks);
    let serialized: Vec<Vec<u8>> = blocks.iter().map(MsgBlock::serialize).collect();

    let hashing = Database::create(&Options::new(dir.path().join("hashing"), NET)).expect("create");
    let handed = Database::create(&Options::new(dir.path().join("handed"), NET)).expect("create");

    // Half the blocks in one transaction and the rest one a transaction.
    let store = |db: &Database, in_hand: bool, range: std::ops::Range<usize>| {
        db.update(|tx| {
            for i in range.clone() {
                let before = dcroxide_wire::header_hashes_on_this_thread();
                if in_hand {
                    tx.store_block_hashed(&hashes[i].0, &blocks[i])?;
                } else {
                    tx.store_block(&blocks[i])?;
                }
                assert_eq!(
                    dcroxide_wire::header_hashes_on_this_thread() - before,
                    u64::from(!in_hand),
                    "block {i}"
                );
                // The block is pending under its hash and height either
                // way, and a second store of it is refused.
                assert!(tx.has_block(&hashes[i].0, hashes[i].1)?);
                assert_eq!(tx.fetch_block(&hashes[i].0, hashes[i].1)?, serialized[i]);
                let again = if in_hand {
                    tx.store_block_hashed(&hashes[i].0, &blocks[i])
                } else {
                    tx.store_block(&blocks[i])
                };
                let err = again.expect_err("the block is pending");
                assert_eq!(err.kind, ErrorKind::BlockExists);
                assert_eq!(
                    err.description,
                    format!("block {} already exists", hashes[i].0)
                );
            }
            Ok(())
        })
        .expect("store");
    };
    for (db, in_hand) in [(&hashing, false), (&handed, true)] {
        store(db, in_hand, 0..5);
        for i in 5..10 {
            store(db, in_hand, i..i + 1);
        }
    }

    // The same rows and the same blocks.
    assert_eq!(block_index_rows(&handed), block_index_rows(&hashing));
    for db in [&hashing, &handed] {
        db.view(|tx| {
            assert_eq!(tx.has_blocks(&hashes)?, vec![true; hashes.len()]);
            assert_eq!(tx.fetch_blocks(&hashes)?, serialized);
            Ok(())
        })
        .expect("view");
    }

    // A committed block is refused again, and a read-only transaction
    // cannot store, with the texts `store_block` gives.
    let refusals = |db: &Database, in_hand: bool| -> Vec<(ErrorKind, String)> {
        let attempt = |tx: &dcroxide_database::Transaction| {
            if in_hand {
                tx.store_block_hashed(&hashes[0].0, &blocks[0])
            } else {
                tx.store_block(&blocks[0])
            }
        };
        let mut errors = Vec::new();
        let exists = db.update(|tx| attempt(tx)).expect_err("the block exists");
        errors.push((exists.kind, exists.description));
        db.view(|tx| {
            let read_only = attempt(tx).expect_err("the transaction cannot write");
            errors.push((read_only.kind, read_only.description));
            Ok(())
        })
        .expect("view");
        errors
    };
    let refused = refusals(&handed, true);
    assert_eq!(refused, refusals(&hashing, false));
    assert_eq!(
        refused.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
        vec![ErrorKind::BlockExists, ErrorKind::TxNotWritable]
    );

    // The same bytes in the block files, once both are closed.
    hashing.close().expect("close");
    handed.close().expect("close");
    let block_file = |name: &str| {
        std::fs::read(dir.path().join(name).join("000000000.fdb")).expect("read block file")
    };
    let records = block_file("handed");
    assert!(records.len() > serialized.iter().map(Vec::len).sum::<usize>());
    assert_eq!(records, block_file("hashing"));
}

/// Every row of the internal block index in walk order: the key, and
/// the header that follows the block's 12-byte location.
fn block_index_rows(db: &Database) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut rows: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    db.view(|tx| {
        let bucket = tx
            .metadata()
            .bucket(b"ffldb-blockidx")
            .expect("block index bucket");
        bucket.for_each(|key, row| {
            assert_eq!(row.len(), 12 + 180, "row for {key:02x?}");
            rows.push((key.to_vec(), row[12..].to_vec()));
            Ok(())
        })
    })
    .expect("walk the block index");
    rows
}

/// The block laid out as its block-file record for the network, in a
/// buffer that holds a message header's worth of other bytes ahead of
/// it, as the frame a block is read in does.
fn record_of(block: &MsgBlock, network: u32) -> Arc<BlockRecord> {
    let mut buf = vec![0xa5u8; 24];
    buf.extend_from_slice(&block.serialize());
    Arc::new(BlockRecord::lay_out(buf, 24, network).expect("a record"))
}

/// Every block file of the database, by name.
fn block_files(db_dir: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(db_dir)
        .expect("read the database directory")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "fdb"))
        .map(|path| {
            let name = path
                .file_name()
                .expect("name")
                .to_string_lossy()
                .into_owned();
            (name, std::fs::read(&path).expect("read block file"))
        })
        .collect();
    files.sort();
    files
}

/// Every row of the internal block index, whole: key, location and
/// header.
fn whole_block_index_rows(db: &Database) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut rows = Vec::new();
    db.view(|tx| {
        let bucket = tx
            .metadata()
            .bucket(b"ffldb-blockidx")
            .expect("block index bucket");
        bucket.for_each(|key, row| {
            rows.push((key.to_vec(), row.to_vec()));
            Ok(())
        })
    })
    .expect("walk the block index");
    rows
}

/// A block stored as a record laid out ahead is stored as `store_block`
/// stores it: the same block files byte for byte across a rollover, the
/// same index rows, the same answers inside the transaction that holds
/// it pending and after its commit, and after a reopen.  That holds for
/// a record laid out for another network too, which the store does not
/// write.
#[test]
fn a_block_stored_as_a_laid_out_record_is_stored_as_store_block_stores_it() {
    const OTHER_NET: u32 = 0x0102_0304;
    let dir = TempDir::new().expect("tempdir");
    let open = |name: &str| {
        let mut opts = Options::new(dir.path().join(name), NET);
        // Small enough to roll over several times.
        opts.max_block_file_size = 2048;
        (Database::create(&opts).expect("create"), opts)
    };
    let (serialized_db, serialized_opts) = open("serialized");
    let (laid_db, laid_opts) = open("laid");
    let mut rng = SplitMix64::from_entropy("db-block-record");

    let blocks: Vec<MsgBlock> = (0..14).map(|_| make_block(&mut rng)).collect();
    let hashes = keys_of(&blocks);
    let serialized: Vec<Vec<u8>> = blocks.iter().map(MsgBlock::serialize).collect();

    for (i, block) in blocks.iter().enumerate() {
        let (hash, height) = hashes[i];
        serialized_db
            .update(|tx| tx.store_block(block))
            .expect("store");

        // Every third record is for another network.
        let network = if i % 3 == 2 { OTHER_NET } else { NET };
        let record = record_of(block, network);
        assert_eq!(record.block(), serialized[i]);
        assert_eq!(*record.hash(), hash);
        laid_db
            .update(|tx| {
                assert!(!tx.has_block(&hash, height)?);
                tx.store_block_record(&hash, &record)?;
                // The transaction shares the record; it does not copy it.
                assert_eq!(Arc::strong_count(&record), 2);

                // Pending, it reads as a pending block does.
                assert!(tx.has_block(&hash, height)?);
                assert_eq!(tx.fetch_block(&hash, height)?, serialized[i]);
                assert_eq!(tx.fetch_block_header(&hash, height)?, serialized[i][..180]);
                let region = BlockRegion {
                    hash,
                    offset: 8,
                    len: 12,
                };
                assert_eq!(
                    tx.fetch_block_region(&region, height)?,
                    serialized[i][8..20]
                );
                assert_eq!(
                    tx.store_block_record(&hash, &record).err().map(kind_of),
                    Some(ErrorKind::BlockExists)
                );
                assert_eq!(
                    tx.store_block(block).err().map(kind_of),
                    Some(ErrorKind::BlockExists)
                );
                Ok(())
            })
            .expect("store record");
        // The transaction let go of the record when it ended.
        assert_eq!(Arc::strong_count(&record), 1);
    }

    let compare = |serialized_db: &Database, laid_db: &Database, when: &str| {
        let want = block_files(&serialized_opts.path);
        assert!(want.len() > 2, "{when}: the blocks rolled over");
        assert_eq!(block_files(&laid_opts.path), want, "{when}: block files");
        assert_eq!(
            whole_block_index_rows(laid_db),
            whole_block_index_rows(serialized_db),
            "{when}: index rows"
        );
        laid_db
            .view(|tx| {
                assert_eq!(tx.fetch_blocks(&hashes)?, serialized, "{when}");
                Ok(())
            })
            .expect("view");
    };
    compare(&serialized_db, &laid_db, "committed");
    // The records for this database's network were written as they were
    // handed in; the four for another network were laid out again.
    assert_eq!(laid_db.records_written_as_laid_out(), 10);
    assert_eq!(serialized_db.records_written_as_laid_out(), 0);

    // A stored block is refused again, as a record and as a block.
    let again = record_of(&blocks[0], NET);
    assert_eq!(
        laid_db
            .update(|tx| tx.store_block_record(&hashes[0].0, &again))
            .err()
            .map(kind_of),
        Some(ErrorKind::BlockExists)
    );
    assert_eq!(Arc::strong_count(&again), 1);

    for db in [&serialized_db, &laid_db] {
        db.close().expect("close");
    }
    drop((serialized_db, laid_db));
    let serialized_db = Database::open(&serialized_opts).expect("reopen");
    let laid_db = Database::open(&laid_opts).expect("reopen");
    compare(&serialized_db, &laid_db, "reopened");
}

/// A record is stored under the hash of the header its block begins
/// with and under no other, in a writable transaction only, and a
/// transaction that is rolled back leaves nothing of it.  The refusals
/// are `store_block_raw`'s, text included.
#[test]
fn a_laid_out_record_is_refused_as_mismatched_bytes_are() {
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("db"), NET);
    let db = Database::create(&opts).expect("create");
    let mut rng = SplitMix64::from_entropy("db-block-record-refusals");
    let block = make_block(&mut rng);
    let (hash, height) = (block.header.block_hash(), block.header.height);
    let record = record_of(&block, NET);

    let wrong = Hash([9u8; 32]);
    let err = db
        .update(|tx| tx.store_block_record(&wrong, &record))
        .expect_err("another hash");
    let raw_err = db
        .update(|tx| tx.store_block_raw(&wrong, block.serialize()))
        .expect_err("another hash");
    assert_eq!(err.kind, ErrorKind::DriverSpecific);
    assert_eq!(
        err.to_string(),
        format!("block {wrong} was given bytes whose header hashes to {hash}")
    );
    assert_eq!(err.to_string(), raw_err.to_string());

    let err = db
        .view(|tx| tx.store_block_record(&hash, &record))
        .expect_err("a read-only transaction");
    assert_eq!(err.kind, ErrorKind::TxNotWritable);
    // The hash is the last thing looked at, as `store_block_raw` looks
    // at it last: a read-only transaction refuses a record under another
    // hash as something it cannot write, not as a mismatch.
    let err = db
        .view(|tx| tx.store_block_record(&wrong, &record))
        .expect_err("a read-only transaction and another hash");
    let raw_err = db
        .view(|tx| tx.store_block_raw(&wrong, block.serialize()))
        .expect_err("a read-only transaction and another hash");
    assert_eq!(err.kind, ErrorKind::TxNotWritable);
    assert_eq!(
        (err.kind, err.to_string()),
        (raw_err.kind, raw_err.to_string())
    );

    // Rolled back: nothing reaches the files, and the record is let go.
    let rolled_back = db.update(|tx| {
        tx.store_block_record(&hash, &record)?;
        Err(Error {
            kind: ErrorKind::DriverSpecific,
            description: "give up".to_string(),
        })
    });
    assert!(rolled_back.is_err());
    assert_eq!(Arc::strong_count(&record), 1);
    assert!(
        block_files(&opts.path)
            .iter()
            .all(|(_, bytes)| bytes.is_empty())
    );
    db.view(|tx| {
        assert!(!tx.has_block(&hash, height)?);
        Ok(())
    })
    .expect("view");

    // And it is stored after all of that, the one record this database
    // has written as it was handed in.
    assert_eq!(db.records_written_as_laid_out(), 0);
    db.update(|tx| tx.store_block_record(&hash, &record))
        .expect("store");
    assert_eq!(db.records_written_as_laid_out(), 1);
    db.view(|tx| {
        assert_eq!(tx.fetch_block(&hash, height)?, block.serialize());
        Ok(())
    })
    .expect("view");

    // With the block stored, the record of another block of its height
    // handed in under its hash is a block that exists already: the
    // existence check comes before the hash is compared with the
    // record's own, as it does for those bytes in `store_block_raw`.
    let mut other = make_block(&mut rng);
    other.header.height = height;
    let other_record = record_of(&other, NET);
    assert_ne!(*other_record.hash(), hash);
    let err = db
        .update(|tx| tx.store_block_record(&hash, &other_record))
        .expect_err("a stored block's hash");
    let raw_err = db
        .update(|tx| tx.store_block_raw(&hash, other.serialize()))
        .expect_err("a stored block's hash");
    assert_eq!(err.kind, ErrorKind::BlockExists);
    assert_eq!(
        (err.kind, err.to_string()),
        (raw_err.kind, raw_err.to_string())
    );
    assert_eq!(Arc::strong_count(&other_record), 1);
    assert_eq!(db.records_written_as_laid_out(), 1);
}
