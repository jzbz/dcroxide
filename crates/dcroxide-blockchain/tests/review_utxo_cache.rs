// SPDX-License-Identifier: ISC
//! Adding an entry over a cached entry the backend already holds
//! clears the incoming fresh bit (review finding B1-p#5).
//!
//! dcrd's `UtxoCache.addEntry` takes the existing entry's freshness and
//! explicitly clears it otherwise (`utxocache.go:305-309`).  The port
//! only ever set the bit, so an entry that arrived already marked fresh
//! stayed fresh over a backend row.  Spending it then replaced it with
//! a plain "absent" marker, the flush never deleted the backend row,
//! and the spent output came back as unspent.

use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_blockchain::{UTXO_STATE_FRESH, UTXO_STATE_MODIFIED, UTXO_STATE_SPENT, UtxoEntry};
use dcroxide_chaincfg::regnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_stake::TxType;
use dcroxide_wire::OutPoint;

#[test]
fn a_fresh_entry_over_a_backend_row_is_not_fresh_and_its_spend_reaches_the_backend() {
    let params = regnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    let outpoint = OutPoint {
        hash: Hash([7; 32]),
        index: 0,
        tree: 0,
    };
    let key = (outpoint.hash.0, outpoint.index, outpoint.tree);
    let entry = UtxoEntry::new(
        5_000,
        vec![0x76, 0xa9],
        1,
        0,
        0,
        false,
        false,
        TxType::Regular,
        None,
    );

    // The backend holds the row, and the cache has it loaded clean.
    chain.utxo_backend.insert(key, entry.clone());
    chain
        .utxo_cache
        .borrow_mut()
        .insert(key, Some(entry.clone()));

    // A view hands back the same output already marked fresh.
    let mut incoming = entry.clone();
    incoming.set_state_bits(UTXO_STATE_MODIFIED | UTXO_STATE_FRESH);
    let mut view = UtxoView::new();
    view.insert_entry(&outpoint, incoming);
    chain.commit_view(&mut view);
    let cached = chain.utxo_cache.borrow().get(&key).cloned();
    let cached = cached.flatten().expect("the entry is cached");
    assert!(
        !cached.is_fresh(),
        "an entry over a backend row must not be fresh"
    );

    // Spend it: the cache has to keep a spent tombstone so the flush
    // deletes the backend row.
    let mut spent = entry.clone();
    spent.set_state_bits(UTXO_STATE_MODIFIED | UTXO_STATE_SPENT);
    let mut view = UtxoView::new();
    view.insert_entry(&outpoint, spent);
    chain.commit_view(&mut view);
    chain.flush_utxo_cache_for_stats().expect("flush");
    assert!(
        !chain.utxo_backend.contains_key(&key),
        "the spent output survived in the backend"
    );
}

/// The batch writer the cache flush uses (review finding B1-p#2) has
/// exactly the per-row semantics of `db_put_utxo`: an entry is written
/// whatever its cache state bits, and `None` deletes the row.
#[test]
fn the_batch_utxo_writer_matches_the_single_row_writer() {
    use dcroxide_blockchain::chaindb::{db_fetch_utxo_entry, db_put_utxo, db_put_utxos};
    use dcroxide_database::{Database, Options};

    let params = regnet_params();
    let dir = tempfile::tempdir().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let chain = Chain::open(
        Database::create(&opts).expect("create database"),
        &params,
        Hash::ZERO,
        false,
        0,
    )
    .expect("open chain");
    let db = chain.db.as_ref().expect("db-backed");

    let outpoint = |n: u8| OutPoint {
        hash: Hash([n; 32]),
        index: u32::from(n),
        tree: 0,
    };
    let entry = |n: u8| {
        let mut e = UtxoEntry::new(
            1_000 * i64::from(n),
            vec![0x51, n],
            u32::from(n),
            0,
            0,
            false,
            false,
            TxType::Regular,
            None,
        );
        // Cache state bits must not reach the row.
        e.set_state_bits(UTXO_STATE_MODIFIED | UTXO_STATE_FRESH);
        e
    };
    let (a, b, c) = (entry(1), entry(2), entry(3));

    db.update(|tx| {
        db_put_utxo(tx, &outpoint(3), Some(&c)).map_err(|e| panic!("{e:?}"))?;
        db_put_utxos(
            tx,
            [
                (outpoint(1), Some(&a)),
                (outpoint(2), Some(&b)),
                (outpoint(3), None),
            ],
        )
        .map_err(|e| panic!("{e:?}"))
    })
    .expect("write the batch");

    db.view(|tx| {
        for (n, want) in [(1u8, Some(&a)), (2, Some(&b)), (3, None)] {
            let got = db_fetch_utxo_entry(tx, &outpoint(n)).expect("fetch");
            match want {
                None => assert!(got.is_none(), "row {n} was not deleted"),
                Some(want) => {
                    let got = got.expect("row written");
                    assert_eq!(got.amount(), want.amount());
                    assert_eq!(got.pk_script(), want.pk_script());
                    assert_eq!(got.block_height(), want.block_height());
                    assert!(!got.is_fresh() && !got.is_modified());
                }
            }
        }
        Ok(())
    })
    .expect("read back");
}
