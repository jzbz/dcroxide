// SPDX-License-Identifier: ISC
//! UTXO set statistics (dcrd `FetchStats`): the flushed set's counts,
//! sizes, total amount, and serialized hash over a database-backed
//! chain — the utxo set bucket on disk — including the flush of
//! pending cache state the stats force and the serialized-key
//! iteration order dcrd's backend walks.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::UtxoEntry;
use dcroxide_blockchain::process::{Chain, UtxoStats};
use dcroxide_blockchain::{outpoint_key, serialize_utxo_entry};
use dcroxide_chainhash::{Hash, hash_h};
use dcroxide_database::{Database, Options};
use dcroxide_stake::TxType;
use dcroxide_standalone::calc_merkle_root_in_place;
use dcroxide_wire::{MsgTx, OutPoint, TxOut};
use tempfile::TempDir;

/// A fresh genesis simnet chain over a temporary database.
fn open_chain() -> (TempDir, Chain) {
    let params = dcroxide_chaincfg::simnet_params();
    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain");
    (dir, chain)
}

/// A regular unspent entry with the given amount.
fn regular_entry(amount: i64) -> UtxoEntry {
    UtxoEntry::new(
        amount,
        vec![0x51],
        0,
        0,
        0,
        false,
        false,
        TxType::Regular,
        None,
    )
}

/// The stats an independent fold over the given backend rows computes:
/// serialize each entry, order by serialized outpoint key, and take
/// the merkle root of the BLAKE-256 leaf hashes.
/// A fold row: serialized key, serialized entry, amount, tx hash.
type Row = (Vec<u8>, Vec<u8>, i64, [u8; 32]);

fn expected_stats(rows: &[(OutPoint, UtxoEntry)]) -> UtxoStats {
    let mut keyed: Vec<Row> = rows
        .iter()
        .map(|(op, entry)| {
            let serialized = serialize_utxo_entry(entry).expect("unspent entry");
            (outpoint_key(op), serialized, entry.amount(), op.hash.0)
        })
        .collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    let mut tx_hashes: std::collections::BTreeSet<[u8; 32]> = std::collections::BTreeSet::new();
    let mut leaves = Vec::new();
    let mut stats = UtxoStats {
        utxos: 0,
        transactions: 0,
        size: 0,
        total: 0,
        serialized_hash: Hash::ZERO,
    };
    for (_, serialized, amount, tx_hash) in keyed {
        stats.utxos += 1;
        stats.size += serialized.len() as i64;
        tx_hashes.insert(tx_hash);
        leaves.push(hash_h(&serialized));
        stats.total += amount;
    }
    stats.serialized_hash = calc_merkle_root_in_place(&mut leaves);
    stats.transactions = tx_hashes.len() as i64;
    stats
}

#[test]
fn stats_over_an_empty_set_are_zero() {
    let (_dir, mut chain) = open_chain();
    let stats = chain.fetch_utxo_stats().expect("stats");
    assert_eq!(
        stats,
        UtxoStats {
            utxos: 0,
            transactions: 0,
            size: 0,
            total: 0,
            serialized_hash: Hash::ZERO,
        }
    );
}

#[test]
fn stats_flush_the_cache_and_fold_the_full_set() {
    let (_dir, mut chain) = open_chain();

    // Two outputs of transaction A and one of B in the flushed set —
    // written straight to the utxo set bucket like a prior flush
    // left them...
    let a = Hash([0x0a; 32]);
    let b = Hash([0x0b; 32]);
    let c = Hash([0x0c; 32]);
    let outpoint = |hash: Hash, index: u32| OutPoint {
        hash,
        index,
        tree: 0,
    };
    chain
        .db
        .as_ref()
        .expect("db")
        .update(|tx| {
            for (op, entry) in [
                (outpoint(a, 0), regular_entry(1000)),
                (outpoint(a, 1), regular_entry(2500)),
                (outpoint(b, 0), regular_entry(5000)),
            ] {
                dcroxide_blockchain::chaindb::db_put_utxo(tx, &op, Some(&entry))
                    .expect("write utxo row");
            }
            Ok(())
        })
        .expect("seed the flushed set");

    // ...an unflushed fresh entry of C pending in the cache, and a
    // pending spend of B's output pulled in as a tombstone.  The
    // stats force the flush first, so C joins the fold and B leaves
    // it.
    let mut c_entry = regular_entry(70);
    c_entry.set_state_bits(
        dcroxide_blockchain::UTXO_STATE_MODIFIED | dcroxide_blockchain::UTXO_STATE_FRESH,
    );
    chain
        .utxo_cache
        .borrow_mut()
        .insert((c.0, 0, 0), Some(c_entry));
    let mut spent = regular_entry(5000);
    spent.spend();
    chain
        .utxo_cache
        .borrow_mut()
        .insert((b.0, 0, 0), Some(spent));

    let stats = chain.fetch_utxo_stats().expect("stats");
    let expected = expected_stats(&[
        (
            OutPoint {
                hash: a,
                index: 0,
                tree: 0,
            },
            regular_entry(1000),
        ),
        (
            OutPoint {
                hash: a,
                index: 1,
                tree: 0,
            },
            regular_entry(2500),
        ),
        (
            OutPoint {
                hash: c,
                index: 0,
                tree: 0,
            },
            regular_entry(70),
        ),
    ]);
    assert_eq!(stats, expected);
    // A's two outputs share one transaction: 3 utxos over 2 txs.
    assert_eq!(stats.utxos, 3);
    assert_eq!(stats.transactions, 2);
    assert_eq!(stats.total, 3570);
    // The flush kept the now-clean entry as read cache and evicted
    // the spent tombstone (dcrd's flush eviction).
    let cache = chain.utxo_cache.borrow();
    assert_eq!(
        cache.len(),
        1,
        "the flush kept the clean entry and evicted the spent one"
    );
    let retained = cache
        .get(&(c.0, 0, 0))
        .and_then(|e| e.clone())
        .expect("the fresh entry stays cached");
    assert!(
        !retained.is_modified() && !retained.is_fresh(),
        "the retained entry has its cache flags cleared"
    );
}

#[test]
fn iteration_follows_serialized_key_order() {
    // dcrd's backend walks the set in serialized-key byte order, and
    // the VLQ-coded output index is NOT order-preserving across its
    // length boundaries: index 16512 (the first three-byte VLQ)
    // serializes to a key that sorts BEFORE index 16511 (the last
    // two-byte VLQ).
    let hash = Hash([0x0d; 32]);
    let low = OutPoint {
        hash,
        index: 16511,
        tree: 0,
    };
    let high = OutPoint {
        hash,
        index: 16512,
        tree: 0,
    };
    assert!(
        outpoint_key(&high) < outpoint_key(&low),
        "the VLQ boundary must invert the byte order"
    );

    let (_dir, mut chain) = open_chain();
    chain
        .db
        .as_ref()
        .expect("db")
        .update(|tx| {
            dcroxide_blockchain::chaindb::db_put_utxo(tx, &low, Some(&regular_entry(1)))
                .expect("write utxo row");
            dcroxide_blockchain::chaindb::db_put_utxo(tx, &high, Some(&regular_entry(2)))
                .expect("write utxo row");
            Ok(())
        })
        .expect("seed the flushed set");

    // The serialized hash must fold the higher index FIRST, exactly
    // as dcrd's byte-ordered iteration does.
    let stats = chain.fetch_utxo_stats().expect("stats");
    let mut leaves = vec![
        hash_h(&serialize_utxo_entry(&regular_entry(2)).expect("unspent")),
        hash_h(&serialize_utxo_entry(&regular_entry(1)).expect("unspent")),
    ];
    assert_eq!(
        stats.serialized_hash,
        calc_merkle_root_in_place(&mut leaves)
    );
}

#[test]
fn ticket_minimal_outputs_decode_through_the_entry() {
    // A ticket submission entry carries the ticket's outputs in their
    // serialized minimal form; the entry accessor must decode them to
    // exactly what the stake converter produces from the transaction.
    let tx = MsgTx {
        tx_out: vec![
            TxOut {
                value: 2000000,
                version: 0,
                pk_script: vec![0xba, 0x76, 0xa9, 0x14],
            },
            TxOut {
                value: 0,
                version: 0,
                pk_script: vec![0x6a, 0x1e, 0x01, 0x02],
            },
        ],
        ..MsgTx::default()
    };
    let mut data = vec![0u8; dcroxide_blockchain::chainio::serialize_size_for_minimal_outputs(&tx)];
    dcroxide_blockchain::chainio::put_tx_to_minimal_outputs(&mut data, &tx);

    let entry = UtxoEntry::new(
        2000000,
        vec![0xba],
        100,
        0,
        0,
        false,
        true,
        TxType::SStx,
        Some(data),
    );
    assert_eq!(
        entry.ticket_minimal_outputs(),
        Some(dcroxide_stake::convert_to_minimal_outputs(&tx))
    );
    assert_eq!(regular_entry(1).ticket_minimal_outputs(), None);
}

/// A chain with no database folds its in-memory backend to the same
/// statistics the database-backed walk produces.
///
/// `Chain::new` leaves `db: None`, and `fetch_utxo_stats` then walks
/// `utxo_backend` instead of the utxo bucket.  That branch has to sort
/// by serialized key before folding, because the VLQ-coded output index
/// makes serialized-key order diverge from the map's tuple order across
/// VLQ length boundaries — and the merkle root over the entry hashes
/// depends on that order.  The database branch gets the ordering for
/// free from the bucket walk; this one does not.
///
/// `expected_stats` is the independent oracle both branches are checked
/// against, so this also pins the two against each other.
#[test]
fn a_chain_without_a_database_folds_its_memory_backend_the_same_way() {
    let params = dcroxide_chaincfg::simnet_params();
    let mut chain = Chain::new(&params, params.assume_valid, false);
    assert!(
        chain.db.is_none(),
        "Chain::new leaves the chain database-less; this test covers that branch"
    );

    // The two orders genuinely invert here.  `outpoint_key` lays a key
    // out as prefix||hash||vlq(tree)||vlq(index) (utxoio.rs:43-60),
    // while `utxo_backend`'s key is the tuple (hash, index, tree) —
    // index before tree.  So for one transaction hash, an entry with a
    // low index on the stake tree and one with a higher index on the
    // regular tree sort opposite ways in the two orders, and folding
    // the map without sorting yields a different merkle root.
    let a = Hash([0x0a; 32]);
    let b = Hash([0x0b; 32]);
    let outpoint = |hash: Hash, index: u32, tree: i8| OutPoint { hash, index, tree };
    let rows = [
        // map order: (a,1,1) before (a,5,0); key order: tree 0 first.
        (outpoint(a, 5, 0), regular_entry(1000)),
        (outpoint(a, 1, 1), regular_entry(2500)),
        (outpoint(a, 128, 0), regular_entry(3300)),
        (outpoint(a, 0, 1), regular_entry(4100)),
        (outpoint(b, 1, 0), regular_entry(7000)),
    ];
    for (op, entry) in &rows {
        chain
            .utxo_backend
            .insert((op.hash.0, op.index, op.tree), entry.clone());
    }

    let stats = chain.fetch_utxo_stats().expect("stats");
    assert_eq!(
        stats,
        expected_stats(&rows),
        "the database-less fold matches the reference statistics"
    );
    assert_eq!(stats.utxos, 5, "every entry counted");
    assert_eq!(stats.transactions, 2, "two distinct transactions");
    assert_eq!(stats.total, 1000 + 2500 + 3300 + 4100 + 7000, "total value");
}

/// The backend walk holds no chain state, so it can run while another
/// thread owns the chain — which is the whole point of splitting it out
/// of [`Chain::fetch_utxo_stats`].
///
/// dcrd's `FetchStats` force-flushes under `cacheLock`, releases it, and
/// then walks the backend holding nothing at all
/// (`utxocache.go:532`/`:537`, `utxobackend.go:529`), so `gettxoutsetinfo`
/// never stalls block connection there.  The port used to hold the
/// exclusive chain mutex across the walk, which on mainnet is millions of
/// entries.
///
/// This is a real negative rather than a timing probe: the test holds the
/// chain lock for the entire walk.  If the walk ever needs chain access
/// again it either stops compiling — `utxo_stats_from_backend` takes only
/// the database handle, no `self` — or, if routed back through the locked
/// chain, deadlocks here instead of passing.
#[test]
fn the_backend_walk_needs_no_chain_access() {
    let (_dir, mut chain) = open_chain();

    let a = Hash([0x33; 32]);
    let outpoint = |hash: Hash, index: u32| OutPoint {
        hash,
        index,
        tree: 0,
    };
    let dirty = |amount: i64| {
        let mut entry = regular_entry(amount);
        // Only modified entries reach the backend on a flush.
        entry.set_state_bits(
            dcroxide_blockchain::UTXO_STATE_MODIFIED | dcroxide_blockchain::UTXO_STATE_FRESH,
        );
        entry
    };
    let rows = [(outpoint(a, 0), dirty(1200)), (outpoint(a, 7), dirty(3400))];
    for (op, entry) in &rows {
        chain
            .utxo_cache
            .borrow_mut()
            .insert((op.hash.0, op.index, op.tree), Some(entry.clone()));
    }

    // Flush under exclusive access, exactly as the RPC seam does, then
    // take the handle out so the walk can proceed without the chain.
    chain.flush_utxo_cache_for_stats().expect("forced flush");
    let db = chain.db.clone().expect("database-backed chain");

    let chain = std::sync::Mutex::new(chain);
    let held = chain.lock().expect("chain lock");
    let stats = Chain::utxo_stats_from_backend(&db).expect("stats without the chain");
    drop(held);

    assert_eq!(
        stats,
        expected_stats(&rows),
        "the unlocked walk produces the same statistics as the locked path"
    );
}
