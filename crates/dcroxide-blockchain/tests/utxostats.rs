// SPDX-License-Identifier: ISC
//! UTXO set statistics (dcrd `FetchStats`): the flushed set's counts,
//! sizes, total amount, and serialized hash over a database-backed
//! chain, including the flush of pending cache state the stats force
//! and the serialized-key iteration order dcrd's backend walks.

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

    // Two outputs of transaction A and one of B in the flushed set...
    let a = Hash([0x0a; 32]);
    let b = Hash([0x0b; 32]);
    let c = Hash([0x0c; 32]);
    chain.utxo_backend.insert((a.0, 0, 0), regular_entry(1000));
    chain.utxo_backend.insert((a.0, 1, 0), regular_entry(2500));
    chain.utxo_backend.insert((b.0, 0, 0), regular_entry(5000));

    // ...an unflushed entry of C pending in the cache, and a pending
    // spend of B's output.  The stats force the flush first, so C
    // joins the fold and B leaves it.
    chain
        .utxo_cache
        .insert((c.0, 0, 0), Some(regular_entry(70)));
    let mut spent = regular_entry(5000);
    spent.spend();
    chain.utxo_cache.insert((b.0, 0, 0), Some(spent));

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
    assert!(chain.utxo_cache.is_empty(), "the stats flushed the cache");
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
        .utxo_backend
        .insert((hash.0, low.index, 0), regular_entry(1));
    chain
        .utxo_backend
        .insert((hash.0, high.index, 0), regular_entry(2));

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
