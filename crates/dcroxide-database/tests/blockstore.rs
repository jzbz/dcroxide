// SPDX-License-Identifier: ISC
//! Block storage API battery, ported from the block-storage portions of
//! dcrd's database/ffldb `interface_test.go` and `whitebox_test.go`
//! behaviors: store/fetch round trips, pending-block visibility inside
//! the transaction, plural fetch APIs, region bounds, error kinds,
//! persistence across reopen, flat-file rollover, and the exact ffldb
//! record byte format.

use dcroxide_chainhash::Hash;
use dcroxide_database::{BlockRegion, Database, Error, ErrorKind, Options};
use dcroxide_testutil::SplitMix64;
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint, TxIn, TxOut, TxSerializeType};
use tempfile::TempDir;

const NET: u32 = 0x12141c16; // simnet magic

fn kind_of(err: Error) -> ErrorKind {
    err.kind
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
    let hashes: Vec<Hash> = blocks.iter().map(|b| b.header.block_hash()).collect();
    let serialized: Vec<Vec<u8>> = blocks.iter().map(MsgBlock::serialize).collect();

    db.update(|tx| {
        for (i, block) in blocks.iter().enumerate() {
            // Not present before the store.
            assert!(!tx.has_block(&hashes[i])?);
            assert_eq!(
                tx.fetch_block(&hashes[i]).err().map(kind_of),
                Some(ErrorKind::BlockNotFound)
            );

            tx.store_block(block)?;

            // Storing the same block again in the same tx fails.
            assert_eq!(
                tx.store_block(block).err().map(kind_of),
                Some(ErrorKind::BlockExists)
            );

            // Pending blocks are fully visible within the transaction.
            assert!(tx.has_block(&hashes[i])?);
            assert_eq!(tx.fetch_block(&hashes[i])?, serialized[i]);
            assert_eq!(tx.fetch_block_header(&hashes[i])?, serialized[i][..180]);
            let region = BlockRegion {
                hash: hashes[i],
                offset: 8,
                len: 12,
            };
            assert_eq!(tx.fetch_block_region(&region)?, serialized[i][8..20]);

            // Out-of-bounds regions on a pending block.
            let bad = BlockRegion {
                hash: hashes[i],
                offset: serialized[i].len() as u32 - 4,
                len: 8,
            };
            assert_eq!(
                tx.fetch_block_region(&bad).err().map(kind_of),
                Some(ErrorKind::BlockRegionInvalid)
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
        let regions: Vec<BlockRegion> = hashes
            .iter()
            .map(|h| BlockRegion {
                hash: *h,
                offset: 4,
                len: 20,
            })
            .collect();
        let datas = tx.fetch_block_regions(&regions)?;
        for (i, data) in datas.iter().enumerate() {
            assert_eq!(data.as_slice(), &serialized[i][4..24]);
        }

        // Committed out-of-bounds region.
        let bad = BlockRegion {
            hash: hashes[0],
            offset: serialized[0].len() as u32,
            len: 1,
        };
        assert_eq!(
            tx.fetch_block_region(&bad).err().map(kind_of),
            Some(ErrorKind::BlockRegionInvalid)
        );

        // Unknown block.
        let unknown = Hash([0x55; 32]);
        assert!(!tx.has_block(&unknown)?);
        assert_eq!(
            tx.fetch_block_header(&unknown).err().map(kind_of),
            Some(ErrorKind::BlockNotFound)
        );
        Ok(())
    })
    .expect("view");

    // Storing an already-committed block in a new tx fails; rolled
    // back stores do not persist.
    let extra = make_block(&mut rng);
    let extra_hash = extra.header.block_hash();
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
        assert!(!tx.has_block(&extra_hash)?);
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
    let hashes: Vec<Hash> = blocks.iter().map(|b| b.header.block_hash()).collect();
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
    let hash = block.header.block_hash();
    db.update(|tx| tx.store_block(&block)).expect("store");
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
            tx.fetch_block(&hash).err().map(kind_of),
            Some(ErrorKind::Corruption)
        );
        // Headers come from the metadata index and remain intact.
        assert_eq!(tx.fetch_block_header(&hash)?.len(), 180);
        Ok(())
    })
    .expect("view");
}
