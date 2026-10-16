// SPDX-License-Identifier: ISC
//! A block that arrives with the bytes it was decoded from is stored as
//! those bytes, and they are the bytes the chain stores for a block that
//! arrives without: its serialization.
//!
//! dcrd stores the bytes a block was received in
//! (`dcrutil.NewBlockFromBlockAndBytes`, `server.go:1359`; `Block.Bytes`,
//! `dcrutil/block.go:54-58`).  A block here may carry those bytes laid
//! out as its record for the block files (`HashedBlock::keep_wire_bytes`),
//! which the chain then writes as it stands
//! (`Transaction::store_block_record`) where it otherwise serializes the
//! block and lays the record out as it commits (`Transaction::store_block`).
//! The bytes are kept only when they compare equal to the block's
//! serialization, in every build, so the block files and the block index
//! do not depend on which of the two happened.  That is pinned here over
//! dcrd's full block battery
//! (`data/fullblock_vectors.txt`), whose rows are blocks as dcrd
//! serialized them: at the database, for every block of the battery, and
//! through the chain, for every row.  Bytes that are not a block's
//! serialization, in every way a frame could differ from it, are not
//! kept, and the block is stored as its serialization all the same.

// Test-harness arithmetic over small counts.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::{HashedBlock, RuleError, RuleErrorKind};
use dcroxide_chaincfg::regnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_database::{BlockRecord, Database, Options};
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;
use tempfile::TempDir;

/// The size of the message header a block's payload follows in a frame.
const FRAME_HEADER: usize = 24;

/// One row of the battery that holds a block.
struct Row {
    /// The row's name.
    name: String,
    /// Whether dcrd accepts the block.
    accept: bool,
    /// The adjusted time the row is processed at.
    now: i64,
    /// The block as dcrd serialized it.
    raw: Vec<u8>,
}

/// Every row of the battery that holds a block, in order.
fn rows() -> Vec<Row> {
    let mut now = 0;
    let mut rows = Vec::new();
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let hex = match f[0] {
            "now" => {
                now = f[1].parse().expect("now");
                continue;
            }
            "accept" => f[4],
            "reject" => f[3],
            "orphanorreject" => f[2],
            _ => continue,
        };
        rows.push(Row {
            name: f[1].to_string(),
            accept: f[0] == "accept",
            now,
            raw: unhex(hex),
        });
    }
    rows
}

/// The block the bytes decode to, all of them.
fn decode(raw: &[u8]) -> MsgBlock {
    let (block, used) = MsgBlock::from_bytes(raw).expect("block");
    assert_eq!(used, raw.len(), "the row holds one block and nothing else");
    block
}

/// A frame's buffer: a message header's worth of other bytes, then the
/// payload, with room behind it for a record's checksum.
fn framed(payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(FRAME_HEADER + payload.len() + BlockRecord::SUFFIX_LEN);
    buf.resize(FRAME_HEADER, 0x5a);
    buf.extend_from_slice(payload);
    buf
}

/// The block hashed, having kept the bytes it was decoded from, in the
/// buffer they were handed in: the record is laid out around them where
/// they lie, and they are not copied on the way.
fn with_wire_bytes(block: &MsgBlock, raw: &[u8], network: u32) -> HashedBlock {
    let mut hashed = HashedBlock::new(Arc::new(block.clone()));
    let buf = framed(raw);
    let payload_at = buf[FRAME_HEADER..].as_ptr();
    assert!(
        hashed.keep_wire_bytes(buf, FRAME_HEADER, network),
        "the bytes a block was decoded from are its serialization"
    );
    assert_eq!(
        hashed.record().expect("kept").block().as_ptr(),
        payload_at,
        "the bytes were copied on their way to the record"
    );
    hashed
}

/// Every block file of the database, by name.
fn block_files(db_dir: &Path) -> Vec<(String, Vec<u8>)> {
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

/// Every row of the database's block index, whole: the key, and the
/// block's location and header.
fn block_index_rows(db: &Database) -> Vec<(Vec<u8>, Vec<u8>)> {
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

/// What a processing call reported, in a form that compares.
fn outcome(result: &(i64, Vec<RuleError>)) -> (i64, Vec<(RuleErrorKind, String)>) {
    (
        result.0,
        result
            .1
            .iter()
            .map(|err| (err.kind, err.description.clone()))
            .collect(),
    )
}

/// The hash of the chain's best block.
fn tip_hash(chain: &Chain) -> Hash {
    chain.store.node(chain.best_chain.tip().expect("tip")).hash
}

/// A new chain over a database of its own.
fn open(dir: &TempDir, name: &str) -> Chain {
    let params = regnet_params();
    let opts = Options::new(dir.path().join(name), params.net.0);
    let db = Database::create(&opts).expect("create database");
    Chain::open(db, &params, Hash::ZERO, false, 0).expect("open chain")
}

/// The chain's database.
fn db_of(chain: &Chain) -> &Database {
    chain.db.as_ref().expect("a chain over a database")
}

/// Every block of the battery, as dcrd serialized it, is kept as the
/// record of the block it decodes to, and stored as that record it
/// leaves the block files and the index rows that storing the decoded
/// block leaves: the same bytes and the same checksums at the same
/// places.
#[test]
fn every_battery_block_is_stored_as_the_bytes_it_was_decoded_from() {
    let network = regnet_params().net.0;
    let dir = TempDir::new().expect("tempdir");
    let serialized_path = dir.path().join("serialized");
    let kept_path = dir.path().join("kept");
    let serialized = Database::create(&Options::new(&serialized_path, network)).expect("create");
    let kept = Database::create(&Options::new(&kept_path, network)).expect("create");

    let rows = rows();
    assert_eq!(rows.len(), 561, "the battery's blocks");
    let mut stored = BTreeSet::new();
    let mut bytes = 0usize;
    for row in &rows {
        let name = &row.name;
        let block = decode(&row.raw);
        let hash = block.header.block_hash();
        let hashed = with_wire_bytes(&block, &row.raw, network);
        let record = hashed.record().expect("the bytes were kept");
        assert_eq!(record.block(), row.raw, "{name}");
        assert_eq!(record.block(), block.serialize(), "{name}");
        assert_eq!(record.hash(), hashed.hash(), "{name}");
        assert_eq!(record.network(), network, "{name}");

        // Two rows of the battery may hold blocks with one header; the
        // database refuses the second either way.
        let first = stored.insert(hash.0);
        let by_block = serialized.update(|tx| tx.store_block(&block));
        let by_record = kept.update(|tx| tx.store_block_record(&hash, record));
        assert_eq!(by_block.is_ok(), first, "{name}: {by_block:?}");
        assert_eq!(
            by_record.as_ref().map_err(ToString::to_string),
            by_block.as_ref().map_err(ToString::to_string),
            "{name}"
        );
        // The database let go of the record as its transaction ended.
        assert_eq!(Arc::strong_count(record), 1, "{name}");
        if first {
            bytes += row.raw.len() + 12;
        }
    }
    assert!(stored.len() > 500, "{} blocks stored", stored.len());

    let files = block_files(&serialized_path);
    assert_eq!(
        files.iter().map(|(_, file)| file.len()).sum::<usize>(),
        bytes,
        "one record a block"
    );
    assert_eq!(block_files(&kept_path), files, "block files");
    let index = block_index_rows(&serialized);
    assert_eq!(index.len(), stored.len());
    assert_eq!(block_index_rows(&kept), index, "index rows");
    // Every record went to the files as it was handed in; the database
    // handed the blocks laid every record out itself.
    assert_eq!(kept.records_written_as_laid_out(), stored.len() as u64);
    assert_eq!(serialized.records_written_as_laid_out(), 0);
}

/// Every row of the battery gives the same result on a chain whose
/// blocks arrive with the bytes they were decoded from as on a chain
/// that is lent the blocks, and the two leave the same block files and
/// the same block index.  The chain handed the bytes stores every block
/// it stores as its record, which its database writes as it stands, and
/// the other none.
#[test]
fn the_battery_leaves_the_same_block_files_however_its_blocks_arrive() {
    let params = regnet_params();
    let dir = TempDir::new().expect("tempdir");
    let mut lent = open(&dir, "lent");
    let mut kept = open(&dir, "kept");

    let rows = rows();
    for row in &rows {
        let name = &row.name;
        let block = decode(&row.raw);
        let with = with_wire_bytes(&block, &row.raw, params.net.0);

        let l = lent.process_block(&block, row.now, &params);
        let k = kept.process_hashed_block(&with, row.now, &params);
        assert_eq!(outcome(&k), outcome(&l), "{name}");
        assert_eq!(tip_hash(&kept), tip_hash(&lent), "{name}");
        // The chain shares a record with its database only while the
        // database's transaction is open.
        assert_eq!(Arc::strong_count(with.record().expect("kept")), 1, "{name}");
    }

    let index = block_index_rows(db_of(&lent));
    // The genesis block, which a chain stores as it is opened, and the
    // blocks of the battery whose data the chain accepted.
    assert!(index.len() > 300, "{} blocks stored", index.len());
    assert_eq!(block_index_rows(db_of(&kept)), index);
    assert_eq!(
        block_files(&dir.path().join("kept")),
        block_files(&dir.path().join("lent"))
    );
    assert_eq!(db_of(&lent).records_written_as_laid_out(), 0);
    assert_eq!(
        db_of(&kept).records_written_as_laid_out(),
        index.len() as u64 - 1
    );
}

/// One way for the bytes handed in with a block not to be its
/// serialization: the buffer and the offset the block is said to start
/// at, given the block's serialization.
type Odd = fn(&[u8]) -> (Vec<u8>, usize);

/// The ways, by name.  The last two leave the length of what is handed
/// in as it was: another header, and another block under the same
/// header, which are bytes the block could only be handed by a caller
/// that paired it with another block's.
const ODD_BYTES: [(&str, Odd); 10] = [
    ("the transaction count as a three-byte integer", |raw| {
        // The count of regular transactions follows the header.
        assert!(raw[180] < 0xfd);
        let mut odd = raw[..180].to_vec();
        odd.extend_from_slice(&[0xfd, raw[180], 0]);
        odd.extend_from_slice(&raw[181..]);
        // The decoder refuses such a block, so it never arrives.
        assert!(MsgBlock::from_bytes(&odd).is_err());
        (framed(&odd), FRAME_HEADER)
    }),
    ("the transaction count as a nine-byte integer", |raw| {
        let mut odd = raw[..180].to_vec();
        odd.extend_from_slice(&[0xff, raw[180], 0, 0, 0, 0, 0, 0, 0]);
        odd.extend_from_slice(&raw[181..]);
        assert!(MsgBlock::from_bytes(&odd).is_err());
        (framed(&odd), FRAME_HEADER)
    }),
    ("a byte behind the block", |raw| {
        let mut odd = raw.to_vec();
        odd.push(0);
        (framed(&odd), FRAME_HEADER)
    }),
    ("another block behind the block", |raw| {
        (framed(&[raw, raw].concat()), FRAME_HEADER)
    }),
    ("the last byte missing", |raw| {
        (framed(&raw[..raw.len() - 1]), FRAME_HEADER)
    }),
    ("a payload said to start four bytes early", |raw| {
        (framed(raw), FRAME_HEADER - 4)
    }),
    ("a payload said to start past the buffer", |raw| {
        (framed(raw), FRAME_HEADER + raw.len() + 1)
    }),
    ("seven bytes ahead of the block", |raw| {
        let mut buf = vec![0x5a; 7];
        buf.extend_from_slice(raw);
        (buf, 7)
    }),
    ("another header of the same length", |raw| {
        let mut odd = raw.to_vec();
        odd[140] ^= 0x01;
        (framed(&odd), FRAME_HEADER)
    }),
    (
        "another block of the same length under the same header",
        |raw| {
            // Inside the outpoint of the first transaction's first input:
            // past the header, the transaction count, the version and the
            // input count.
            let mut odd = raw.to_vec();
            odd[180 + 1 + 4 + 1 + 5] ^= 0x01;
            let (block, another) = (decode(raw), decode(&odd));
            assert_eq!(another.header, block.header);
            assert_ne!(another, block);
            (framed(&odd), FRAME_HEADER)
        },
    ),
];

/// Bytes that are not the block's serialization are not kept, whatever
/// makes them differ, and the block is then stored as every block that
/// arrives without bytes is: the chain leaves the block files and the
/// index rows that the chain handed the plain blocks leaves.  The last
/// block arrives with its serialization, which is kept and stored as
/// its record, to the same effect.
#[test]
fn bytes_that_are_not_the_serialization_are_dropped_and_the_block_is_stored_as_ever() {
    let params = regnet_params();
    let dir = TempDir::new().expect("tempdir");
    let mut plain = open(&dir, "plain");
    let mut odd = open(&dir, "odd");

    let rows = rows();
    let accepted: Vec<&Row> = rows.iter().filter(|row| row.accept).collect();
    assert!(accepted.len() > ODD_BYTES.len());
    for (row, (what, make)) in accepted.iter().zip(ODD_BYTES) {
        let block = decode(&row.raw);
        let (buf, block_at) = make(&row.raw);
        let mut hashed = HashedBlock::new(Arc::new(block.clone()));
        assert!(
            !hashed.keep_wire_bytes(buf, block_at, params.net.0),
            "{what}"
        );
        assert!(hashed.record().is_none(), "{what}");
        // The block and its hashes are untouched.
        assert_eq!(**hashed.block(), block, "{what}");
        assert_eq!(*hashed.hash(), block.header.block_hash(), "{what}");

        let p = plain.process_block(&block, row.now, &params);
        let o = odd.process_hashed_block(&hashed, row.now, &params);
        assert_eq!(outcome(&p), (0, Vec::new()), "{what}: {}", row.name);
        assert_eq!(outcome(&o), outcome(&p), "{what}");
        assert_eq!(tip_hash(&odd), tip_hash(&plain), "{what}");
    }
    assert_eq!(db_of(&odd).records_written_as_laid_out(), 0);

    let row = accepted[ODD_BYTES.len()];
    let block = decode(&row.raw);
    let hashed = with_wire_bytes(&block, &row.raw, params.net.0);
    let p = plain.process_block(&block, row.now, &params);
    let o = odd.process_hashed_block(&hashed, row.now, &params);
    assert_eq!(outcome(&p), (0, Vec::new()), "{}", row.name);
    assert_eq!(outcome(&o), outcome(&p));
    assert_eq!(db_of(&odd).records_written_as_laid_out(), 1);

    let index = block_index_rows(db_of(&plain));
    assert_eq!(index.len(), ODD_BYTES.len() + 2, "genesis and each block");
    assert_eq!(block_index_rows(db_of(&odd)), index);
    assert_eq!(
        block_files(&dir.path().join("odd")),
        block_files(&dir.path().join("plain"))
    );
}

/// A record laid out for another network than the database's is kept
/// with the block and is not what the database writes: it lays out its
/// own, and the chain leaves the block files a chain handed plain blocks
/// leaves.
#[test]
fn a_record_for_another_network_is_not_written() {
    let params = regnet_params();
    let other = dcroxide_chaincfg::simnet_params().net.0;
    assert_ne!(other, params.net.0);
    let dir = TempDir::new().expect("tempdir");
    let mut plain = open(&dir, "plain");
    let mut foreign = open(&dir, "foreign");

    let rows = rows();
    for row in rows.iter().filter(|row| row.accept).take(6) {
        let block = decode(&row.raw);
        let hashed = with_wire_bytes(&block, &row.raw, other);
        assert_eq!(hashed.record().expect("kept").network(), other);
        let p = plain.process_block(&block, row.now, &params);
        let f = foreign.process_hashed_block(&hashed, row.now, &params);
        assert_eq!(outcome(&p), (0, Vec::new()), "{}", row.name);
        assert_eq!(outcome(&f), outcome(&p), "{}", row.name);
    }
    assert_eq!(db_of(&foreign).records_written_as_laid_out(), 0);
    assert_eq!(
        block_files(&dir.path().join("foreign")),
        block_files(&dir.path().join("plain"))
    );
    assert_eq!(
        block_index_rows(db_of(&foreign)),
        block_index_rows(db_of(&plain))
    );
}

/// A block holding transactions of every serialization type is kept as
/// the bytes it decodes from: a transaction's type is part of what the
/// decoder reads into the block and the serialization writes back, so a
/// prefix-only or witness-only transaction inside a block, which no
/// rule accepts, still goes back to the bytes it came from.
#[test]
fn a_block_of_every_serialization_type_is_kept_as_the_bytes_it_decodes_from() {
    use dcroxide_wire::TxSerializeType;

    let rows = rows();
    let mut tried = 0usize;
    for row in rows.iter().filter(|row| row.raw.len() < 4000) {
        let original = decode(&row.raw);
        if original.transactions.is_empty() || original.stransactions.is_empty() {
            continue;
        }
        for (regular, stake) in [
            (TxSerializeType::NoWitness, TxSerializeType::Full),
            (TxSerializeType::OnlyWitness, TxSerializeType::Full),
            (TxSerializeType::Full, TxSerializeType::NoWitness),
            (TxSerializeType::OnlyWitness, TxSerializeType::OnlyWitness),
        ] {
            let mut odd = original.clone();
            odd.transactions[0].ser_type = regular;
            let last = odd.stransactions.len() - 1;
            odd.stransactions[last].ser_type = stake;
            let raw = odd.serialize();
            assert_ne!(raw.len(), row.raw.len(), "{}", row.name);

            // What arrives is what those bytes decode to, which is not
            // the block they were written from: a transaction read
            // without a part holds that part empty.
            let block = decode(&raw);
            assert_eq!(block.transactions[0].ser_type, regular, "{}", row.name);
            assert_eq!(block.stransactions[last].ser_type, stake, "{}", row.name);
            let hashed = with_wire_bytes(&block, &raw, 1);
            assert_eq!(hashed.record().expect("kept").block(), raw, "{}", row.name);
            tried += 1;
        }
    }
    assert!(tried > 400, "{tried} blocks");
}

/// dcrd's own block with a count written longer than it need be (the
/// battery's `bvl1`) does not decode, and its bytes are not kept for the
/// block they would be the long form of.
#[test]
fn dcrds_block_with_a_long_form_count_is_not_kept() {
    let raw = include_str!("data/fullblock_vectors.txt")
        .lines()
        .find_map(|line| line.strip_prefix("noncanon bvl1 "))
        .map(unhex)
        .expect("the battery's non-canonical block");
    assert!(MsgBlock::from_bytes(&raw).is_err());
    // The count of regular transactions, in nine bytes.
    assert_eq!(raw[180], 0xff);
    let count = u64::from_le_bytes(raw[181..189].try_into().expect("eight bytes"));
    assert!(count < 0xfd, "{count}");
    let mut short = raw[..180].to_vec();
    short.push(count as u8);
    short.extend_from_slice(&raw[189..]);
    let block = decode(&short);
    assert_eq!(block.transactions.len() as u64, count);

    let mut hashed = HashedBlock::new(Arc::new(block.clone()));
    assert!(!hashed.keep_wire_bytes(framed(&raw), FRAME_HEADER, 1));
    assert!(hashed.record().is_none());
    // The short form is the block's serialization, and is kept.
    assert!(hashed.keep_wire_bytes(framed(&short), FRAME_HEADER, 1));
    assert_eq!(hashed.record().expect("kept").block(), short);
}

/// Bytes are kept exactly when they are the serialization of the block
/// they decode to, over every one-bit change that still decodes to one
/// in ten of the battery's smaller blocks.
///
/// A changed block that decodes with bytes left over, because a count
/// or a length became smaller, is not kept: it is longer than its
/// serialization.  One that decodes to the last byte is a different
/// block whose serialization is the changed bytes, so no fixed-width
/// field is read into anything but what `MsgBlock::serialize` writes it
/// back from; that is why the comparison holds for every payload the
/// decoder accepts whole, and a reader loses no record to it.
#[test]
fn changed_bytes_are_kept_only_when_they_are_the_serialization_of_what_they_decode_to() {
    let (mut whole, mut partial, mut refused) = (0usize, 0usize, 0usize);
    let mut seen = BTreeSet::new();
    for (n, row) in rows().iter().enumerate() {
        if row.raw.len() > 1500 || !seen.insert(row.raw.clone()) || seen.len() % 10 != 0 {
            continue;
        }
        for at in 0..row.raw.len() {
            let mut changed = row.raw.clone();
            changed[at] ^= 1 << ((at + n) % 8);
            let Ok((block, used)) = MsgBlock::from_bytes(&changed) else {
                refused += 1;
                continue;
            };
            let what = format!("{} with byte {at} changed", row.name);
            assert_eq!(block.serialize_size(), used, "{what}");
            assert_eq!(block.serialize(), changed[..used], "{what}");

            let mut hashed = HashedBlock::new(Arc::new(block));
            let kept = hashed.keep_wire_bytes(framed(&changed), FRAME_HEADER, 1);
            assert_eq!(kept, used == changed.len(), "{what}");
            if kept {
                assert_eq!(hashed.record().expect("kept").block(), changed, "{what}");
                whole += 1;
            } else {
                partial += 1;
            }
        }
    }
    // Most single bits sit in fixed-width fields and scripts.
    assert!(whole > 10_000, "{whole} changed blocks decoded whole");
    assert!(partial > 10, "{partial} decoded with bytes left over");
    assert!(refused > 100, "{refused} did not decode");
}
