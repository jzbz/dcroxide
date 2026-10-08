// SPDX-License-Identifier: ISC
//! The per-block rows under dcroxide's height-first keys (review finding
//! XC4a#1, ADR-0010).
//!
//! dcrd keys the spend journal, GCS filter, header commitment and
//! treasury rows by block hash, the stake undo and new ticket rows by
//! little-endian height, and ffldb's block index rows by hash, so the
//! blocks of one metadata flush scatter across every bucket.  The port
//! keys all seven by big-endian height first (`chaindb::block_row_key`,
//! `stakedb::height_key` and the database's own block index key).  These
//! tests pin the layout itself over a chain with side chains and
//! reorganizations, the order a walk meets the rows in, and that every
//! reader still answers what it answered from the recent in-memory
//! window: once the window is pruned, and once a restart has warmed it
//! back from the database.
//!
//! The expected keys are spelled out byte by byte here rather than taken
//! from the encoders under test.  The battery's main chain ends at height
//! 191, and below 256 a little-endian height walks in the same order as a
//! big-endian one, so the battery alone cannot tell the two apart for the
//! stake buckets, whose keys are the height alone; the row helpers test
//! below puts rows at heights from 255 to 16,777,216 for that, alongside
//! the encoders' own unit tests (`stakedb.rs`, `chaindb.rs` and the
//! database's `transaction.rs`).  `rekey_reorg.rs` covers the rows that
//! reorganizations and invalidations read back after a restart.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet};

use dcroxide_blockchain::blockindex::BlockStatus;
use dcroxide_blockchain::chaindb::{
    ChainDbError, GCS_FILTER_BUCKET_NAME, HEADER_CMTS_BUCKET_NAME, SPEND_JOURNAL_BUCKET_NAME,
    TREASURY_BUCKET_NAME, block_row_key, db_fetch_gcs_filter, db_fetch_header_commitments,
    db_fetch_raw_gcs_filter, db_fetch_spend_journal_entry, db_put_gcs_filter,
    db_put_header_commitments, db_put_spend_journal_entry, db_remove_spend_journal_entry,
};
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::treasurydb::{
    TreasuryState, db_fetch_treasury_balance, db_put_treasury_balance,
};
use dcroxide_chaincfg::{Params, regnet_params, simnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_stake::stakedb::{
    db_fetch_block_undo_data, db_fetch_new_tickets, db_put_block_undo_data, db_put_new_tickets,
};
use dcroxide_stake::ticketdb::{
    STAKE_BLOCK_UNDO_DATA_BUCKET_NAME, TICKETS_IN_BLOCK_BUCKET_NAME, UndoTicketData,
};
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;
use tempfile::TempDir;

/// A regnet corpus of blocks every one of which the chain accepts, in
/// order, with its clock.
struct Corpus {
    now: i64,
    blocks: Vec<MsgBlock>,
}

/// The full-block battery's accepted blocks: a long chain with side
/// chains and reorganizations (and no header commitments or treasury).
fn battery() -> Corpus {
    let mut now = 0;
    let mut blocks = Vec::new();
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("now"),
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                blocks.push(block);
            }
            _ => {}
        }
    }
    Corpus { now, blocks }
}

/// A database-backed chain that has connected every block of the
/// corpus through `process_block`, reorganizations included.
fn corpus_chain(opts: &Options, params: &Params, corpus: &Corpus) -> Chain {
    let db = Database::create(opts).expect("create database");
    let mut chain = Chain::open(db, params, Hash::ZERO, false, 0).expect("open chain");
    for block in &corpus.blocks {
        let (_, errs) = chain.process_block(block, corpus.now, params);
        assert!(errs.is_empty(), "{}: {errs:?}", block.header.block_hash());
    }
    chain
}

/// The main chain's blocks, genesis first: hash and height.
fn main_chain(chain: &Chain) -> Vec<(Hash, u32)> {
    let tip = chain.best_snapshot().height;
    (0..=tip)
        .map(|height| {
            let hash = chain
                .block_hash_by_height(height)
                .expect("main chain block");
            (hash, height as u32)
        })
        .collect()
}

/// Every key of a bucket, in walk order.
fn bucket_keys(db: &Database, bucket: &[u8]) -> Vec<Vec<u8>> {
    let mut keys = Vec::new();
    db.view(|tx| {
        let meta = tx.metadata();
        let bucket = meta.bucket(bucket).expect("bucket");
        bucket.for_each(|key, _| {
            keys.push(key.to_vec());
            Ok(())
        })
    })
    .expect("walk the bucket");
    keys
}

/// Split a height-first key into its height and hash, checking that the
/// block index knows the block at that height.
fn indexed_block(chain: &Chain, key: &[u8]) -> (u32, Hash) {
    assert_eq!(key.len(), 36, "height || hash: {key:02x?}");
    let height = u32::from_be_bytes(key[..4].try_into().expect("height"));
    let hash = Hash(key[4..].try_into().expect("hash"));
    let node = chain
        .index
        .lookup_node(&hash)
        .unwrap_or_else(|| panic!("{hash} is not in the block index"));
    assert_eq!(chain.store.node(node).height, i64::from(height), "{hash}");
    assert_eq!(key, height_then_hash(height, &hash).as_slice());
    assert_eq!(key, block_row_key(&hash, height).as_slice());
    (height, hash)
}

/// A height-first key spelled out: the height's four bytes, most
/// significant first, and then the hash.
fn height_then_hash(height: u32, hash: &Hash) -> Vec<u8> {
    let mut key = height.to_be_bytes().to_vec();
    key.extend_from_slice(&hash.0);
    key
}

/// Every per-block row sits under its block's big-endian height and
/// then its hash (or its height alone, for the two stake buckets), so a
/// walk meets the rows in height order.
#[test]
fn per_block_rows_are_keyed_by_height_then_hash() {
    let params = regnet_params();
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let chain = corpus_chain(&opts, &params, &battery());
    let db = chain.db.as_ref().expect("db-backed").clone();
    let main = main_chain(&chain);
    assert!(main.len() > 100, "the battery builds a real chain");

    // The spend journal holds exactly the main chain's rows past
    // genesis: a disconnect removes its block's row.
    let journal: Vec<(u32, Hash)> = bucket_keys(&db, SPEND_JOURNAL_BUCKET_NAME)
        .iter()
        .map(|key| indexed_block(&chain, key))
        .collect();
    let want: Vec<(u32, Hash)> = main[1..].iter().map(|&(hash, h)| (h, hash)).collect();
    assert_eq!(journal, want, "the spend journal in height order");

    // Filters stay once written, side chains included, and every main
    // chain block has one.
    let rows = height_first_rows(&chain, &db, GCS_FILTER_BUCKET_NAME);
    let have: BTreeSet<(u32, Hash)> = rows.into_iter().collect();
    for &(hash, height) in &main {
        assert!(have.contains(&(height, hash)), "filter for {hash}");
    }

    // One undo row and one new tickets row per main chain height, keyed
    // by the height big-endian.  (The battery stops below 256, where a
    // little-endian height would walk in this order too; the row helpers
    // test covers the larger heights.)
    let heights: Vec<Vec<u8>> = main
        .iter()
        .map(|&(_, height)| height.to_be_bytes().to_vec())
        .collect();
    for bucket in [
        STAKE_BLOCK_UNDO_DATA_BUCKET_NAME,
        TICKETS_IN_BLOCK_BUCKET_NAME,
    ] {
        assert_eq!(bucket_keys(&db, bucket), heights, "{bucket:?}");
    }

    // The database's own block index: every stored block, by height
    // then hash.
    let stored: Vec<(u32, Hash)> = bucket_keys(&db, b"ffldb-blockidx")
        .iter()
        .map(|key| indexed_block(&chain, key))
        .collect();
    assert!(stored.windows(2).all(|w| w[0] < w[1]));
    let stored: BTreeSet<(u32, Hash)> = stored.into_iter().collect();
    for &(hash, height) in &main {
        assert!(stored.contains(&(height, hash)), "stored block {hash}");
    }
}

/// A height-first bucket's rows, each checked against the block index,
/// in walk order -- which is strictly ascending (height, hash).
fn height_first_rows(chain: &Chain, db: &Database, bucket: &[u8]) -> Vec<(u32, Hash)> {
    let rows: Vec<(u32, Hash)> = bucket_keys(db, bucket)
        .iter()
        .map(|key| indexed_block(chain, key))
        .collect();
    assert!(
        rows.windows(2).all(|w| w[0] < w[1]),
        "{bucket:?} walks in height order"
    );
    rows
}

/// The four hash-keyed buckets' own helpers, over heights that
/// little-endian or hash order would scatter: each row lands under
/// height || hash, a walk meets them in height order, a lookup finds a
/// row only under its block's height, and a removal takes the row it
/// names.  (The battery carries no header commitments or treasury rows
/// through `connect_block`, so this is where those two are pinned along
/// with the others.)  The two stake buckets' helpers go in at the same
/// heights, under the height alone, since the battery's heights cannot
/// tell their byte order apart.
#[test]
fn row_helpers_key_by_height_then_hash() {
    let params = regnet_params();
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let chain = Chain::open(
        Database::create(&opts).expect("create database"),
        &params,
        Hash::ZERO,
        false,
        0,
    )
    .expect("open chain");
    let db = chain.db.as_ref().expect("db-backed").clone();
    // Genesis has a filter row already, under (0, genesis).
    let genesis = (0u32, params.genesis_hash);
    let blocks: Vec<(u32, Hash)> = [65_536u32, 1, 256, 255, 7, 7, 16_777_216]
        .iter()
        .enumerate()
        .map(|(i, &height)| (height, Hash([i as u8 + 1; 32])))
        .collect();
    let filter =
        dcroxide_gcs::blockcf2::regular(&params.genesis_block, &NoScripts).expect("a filter");
    let state = TreasuryState {
        balance: 7,
        values: Vec::new(),
    };
    db.update(|tx| {
        for (i, &(height, hash)) in blocks.iter().enumerate() {
            let fail = |e: ChainDbError| panic!("put {hash}: {e:?}");
            db_put_spend_journal_entry(tx, &hash, height, &[i as u8]).unwrap_or_else(fail);
            db_put_gcs_filter(tx, &hash, height, &filter).unwrap_or_else(fail);
            db_put_header_commitments(tx, &hash, height, &[hash]).unwrap_or_else(fail);
            db_put_treasury_balance(tx, &hash, height, &state).unwrap_or_else(fail);
        }
        Ok(())
    })
    .expect("put the rows");

    let mut want: Vec<(u32, Hash)> = blocks.clone();
    want.sort();
    let keys_of = |rows: &[(u32, Hash)]| -> Vec<Vec<u8>> {
        rows.iter()
            .map(|(h, hash)| height_then_hash(*h, hash))
            .collect()
    };
    let mut with_genesis = want.clone();
    with_genesis.insert(0, genesis);
    assert_eq!(bucket_keys(&db, SPEND_JOURNAL_BUCKET_NAME), keys_of(&want));
    assert_eq!(
        bucket_keys(&db, GCS_FILTER_BUCKET_NAME),
        keys_of(&with_genesis)
    );
    assert_eq!(bucket_keys(&db, HEADER_CMTS_BUCKET_NAME), keys_of(&want));
    assert_eq!(bucket_keys(&db, TREASURY_BUCKET_NAME), keys_of(&want));

    db.view(|tx| {
        for (i, &(height, hash)) in blocks.iter().enumerate() {
            let journal = db_fetch_spend_journal_entry(tx, &hash, height);
            assert_eq!(journal, Some(vec![i as u8]));
            let got = db_fetch_raw_gcs_filter(tx, &hash, height).expect("read");
            assert_eq!(got.as_deref(), Some(filter.bytes()));
            let leaves = db_fetch_header_commitments(tx, &hash, height).expect("read");
            assert_eq!(leaves, vec![hash]);
            let ts = db_fetch_treasury_balance(tx, &hash, height).expect("read");
            assert_eq!(ts.map(|ts| ts.balance), Some(7));

            // Under any other height the block has no rows.
            let other = height.wrapping_add(1);
            assert_eq!(db_fetch_spend_journal_entry(tx, &hash, other), None);
            assert_eq!(
                db_fetch_raw_gcs_filter(tx, &hash, other).expect("read"),
                None
            );
            assert!(
                db_fetch_gcs_filter(tx, &hash, other)
                    .expect("read")
                    .is_none()
            );
            let leaves = db_fetch_header_commitments(tx, &hash, other).expect("read");
            assert!(leaves.is_empty());
            let ts = db_fetch_treasury_balance(tx, &hash, other).expect("read");
            assert!(ts.is_none());
        }
        Ok(())
    })
    .expect("read the rows");

    // A removal takes exactly the row it names.
    let (height, hash) = blocks[2];
    db.update(|tx| {
        db_remove_spend_journal_entry(tx, &hash, height)
            .unwrap_or_else(|e| panic!("remove: {e:?}"));
        Ok(())
    })
    .expect("remove the row");
    want.retain(|&row| row != (height, hash));
    assert_eq!(bucket_keys(&db, SPEND_JOURNAL_BUCKET_NAME), keys_of(&want));

    // The stake buckets, keyed by the height alone: 255 and 256 walk in
    // the other order little-endian, and 1 and 16,777,216 are each
    // other's bytes reversed.  Genesis has its rows already, at 0.
    let heights: BTreeSet<u32> = blocks.iter().map(|&(height, _)| height).collect();
    let undo = |height: u32| {
        vec![UndoTicketData {
            ticket_hash: Hash([0x5a; 32]),
            ticket_height: height,
            missed: true,
            revoked: false,
            spent: false,
            expired: true,
        }]
    };
    let tickets = |height: u32| {
        let mut hash = [0xa5; 32];
        hash[..4].copy_from_slice(&height.to_le_bytes());
        vec![Hash(hash)]
    };
    db.update(|tx| {
        for &height in &heights {
            db_put_block_undo_data(tx, height, &undo(height))
                .unwrap_or_else(|e| panic!("put undo at {height}: {e:?}"));
            db_put_new_tickets(tx, height, &tickets(height))
                .unwrap_or_else(|e| panic!("put tickets at {height}: {e:?}"));
        }
        Ok(())
    })
    .expect("put the stake rows");
    let want: Vec<Vec<u8>> = std::iter::once(0)
        .chain(heights.iter().copied())
        .map(|height| height.to_be_bytes().to_vec())
        .collect();
    assert_eq!(bucket_keys(&db, STAKE_BLOCK_UNDO_DATA_BUCKET_NAME), want);
    assert_eq!(bucket_keys(&db, TICKETS_IN_BLOCK_BUCKET_NAME), want);
    db.view(|tx| {
        for &height in &heights {
            let got = db_fetch_block_undo_data(tx, height);
            assert_eq!(got.expect("undo"), undo(height), "undo at {height}");
            let got = db_fetch_new_tickets(tx, height);
            assert_eq!(
                got.expect("tickets"),
                tickets(height),
                "tickets at {height}"
            );
        }
        Ok(())
    })
    .expect("read the stake rows");
}

/// No previous output scripts, which a coinbase-only block needs none of.
struct NoScripts;

impl dcroxide_gcs::blockcf2::PrevScripter for NoScripts {
    fn prev_script(&self, _out: &dcroxide_wire::OutPoint) -> Option<(u16, &[u8])> {
        None
    }
}

/// What the chain serves for its main chain blocks: bodies, spend
/// journals, filters with proofs, and one batched filter range.
fn answers(chain: &Chain, params: &Params) -> Vec<String> {
    let main = main_chain(chain);
    let mut out = Vec::new();
    for &(hash, height) in &main {
        let block = chain.block_by_hash(&hash).expect("block body");
        out.push(format!("block {height} {:?}", block.serialize()));
        if height > 0 {
            let treasury = chain
                .is_treasury_agenda_active(&block.header.prev_block, params)
                .expect("treasury agenda state");
            let journal = chain.fetch_spend_journal(&block, treasury);
            out.push(format!("journal {height} {journal:?}"));
        }
        let filter = chain
            .filter_by_block_hash(&hash)
            .map(|(filter, proof)| (filter.bytes().to_vec(), proof));
        out.push(format!("filter {height} {filter:?}"));
    }
    let tip = main.len() - 1;
    let start = tip.saturating_sub(dcroxide_wire::MAX_CFILTERS_V2_PER_BATCH as usize - 1);
    let range = chain.locate_cfilters_v2(&main[start].0, &main[tip].0);
    out.push(format!("range {range:?}"));
    out
}

/// A block's rows as the recent window held them: the spend journal
/// row, the serialized filter and the header commitment leaves.
type WindowRows = (Vec<u8>, Vec<u8>, Vec<Hash>);

/// Every reader answers from the database what it answered from the
/// recent window: once the window is pruned to the tip, and once a
/// restart has warmed it back from the rows.
#[test]
fn readers_answer_from_the_database_as_from_the_window() {
    let params = regnet_params();
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let mut chain = corpus_chain(&opts, &params, &battery());
    let want = answers(&chain, &params);
    let window: BTreeMap<[u8; 32], WindowRows> = chain
        .spend_journal
        .iter()
        .filter_map(|(hash, journal)| {
            let filter = chain.filters.get(hash)?.bytes().to_vec();
            let leaves = chain.header_commitments.get(hash)?.clone();
            Some((*hash, (journal.clone(), filter, leaves)))
        })
        .collect();
    assert!(!window.is_empty());

    // Pruned: the old blocks' rows come from the database.
    chain.prune_chain_memory(0);
    assert!(
        chain.filters.len() < 4 && chain.spend_journal.len() < 4,
        "the window is pruned to the tip"
    );
    assert!(chain.blocks.len() < 4, "and so are the bodies");
    assert_eq!(answers(&chain, &params), want, "after pruning");

    // Restarted: the open warms the window from the rows, and they are
    // the rows the window held.
    chain.flush(&params).expect("flush");
    chain
        .db
        .as_ref()
        .expect("db-backed")
        .close()
        .expect("close");
    drop(chain);
    let db = Database::open(&opts).expect("reopen database");
    let chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("reopen chain");
    assert!(!chain.spend_journal.is_empty(), "the warm-up found rows");
    for (hash, journal) in &chain.spend_journal {
        let (want_journal, want_filter, want_leaves) =
            window.get(hash).expect("a row the window held");
        assert_eq!(journal, want_journal);
        assert_eq!(chain.filters[hash].bytes(), want_filter.as_slice());
        // The warm-up keeps only commitments there are.
        let leaves = chain.header_commitments.get(hash).cloned();
        assert_eq!(leaves.unwrap_or_default(), *want_leaves);
    }
    assert_eq!(answers(&chain, &params), want, "after a restart");
}

/// The treasury rows, written where the treasury agenda is active, sit
/// under their block's height and hash too.
#[test]
fn treasury_rows_are_keyed_by_height_then_hash() {
    let params = simnet_params();
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let mut chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("open chain");
    let mut written = BTreeSet::new();
    for line in include_str!("data/treasury_vectors.txt").lines() {
        let Some(hex) = line.strip_prefix("blk ") else {
            continue;
        };
        let (block, _) =
            MsgBlock::from_bytes(&unhex(hex.split(' ').next().expect("hex"))).expect("block");
        let prev = chain
            .index
            .lookup_node(&block.header.prev_block)
            .expect("previous node");
        let id = chain.store.new_node(&block.header, Some(prev));
        {
            let node = chain.store.node_mut(id);
            node.status = BlockStatus(BlockStatus::DATA_STORED.0 | BlockStatus::VALIDATED.0);
            node.is_fully_linked = true;
        }
        chain.index.add_node(&chain.store, id);
        chain.blocks.insert(
            block.header.block_hash().0,
            std::sync::Arc::new(block.clone()),
        );
        chain
            .fetch_stake_node(id, &params)
            .unwrap_or_else(|e| panic!("stake node: {e:?}"));
        chain
            .put_treasury_records(id, &block, &params)
            .unwrap_or_else(|e| panic!("treasury records: {e:?}"));
        chain.best_chain.set_tip(&chain.store, Some(id));
        written.insert((block.header.height, block.header.block_hash()));
    }

    let db = chain.db.as_ref().expect("db-backed").clone();
    let rows: Vec<(u32, Hash)> = bucket_keys(&db, TREASURY_BUCKET_NAME)
        .iter()
        .map(|key| indexed_block(&chain, key))
        .collect();
    assert!(rows.windows(2).all(|w| w[0] < w[1]), "height order");
    assert_eq!(rows.into_iter().collect::<BTreeSet<_>>(), written);
}
