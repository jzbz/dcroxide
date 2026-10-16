// SPDX-License-Identifier: ISC
//! Rows of dcrd's `TestSpendEntry` and `TestCommit`
//! (`internal/blockchain/utxocache_test.go` at `382ff4dd`), run through
//! [`Chain::commit_view`], which applies a view to the UTXO cache as
//! dcrd's `UtxoCache.Commit` does and spends through the port of
//! `UtxoCache.spendEntry`.
//!
//! dcrd `9112e4e6` removed the cache's double-spend assertion: a spend
//! of an output the cache already holds spent leaves the cache as it is
//! (`utxocache.go:340-355`).  The view holds a single spend of the
//! output, and double spends are refused when the transactions are
//! validated against the view.  dcrd's comment names the path that
//! reaches it even when every block is flushed: the spend of an output
//! not yet flushed to the backend, undone by a disapproval and spent
//! again in the block that disapproves it.
//!
//! The entries are dcrd's fixtures, in the states its
//! `makeEntryStates` builds.  The cache is seeded with entries in
//! exactly the given states, as dcrd's `createTestUtxoCache` does.

use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_blockchain::{UTXO_STATE_FRESH, UTXO_STATE_MODIFIED, UTXO_STATE_SPENT, UtxoEntry};
use dcroxide_chaincfg::regnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_stake::TxType;
use dcroxide_testutil::unhex;
use dcroxide_wire::OutPoint;

type Key = ([u8; 32], u32, i8);

fn key_of(outpoint: &OutPoint) -> Key {
    (outpoint.hash.0, outpoint.index, outpoint.tree)
}

/// dcrd `outpoint299`.
fn outpoint299() -> OutPoint {
    OutPoint {
        hash: "e299d2cc5deb5b39d230ad2a6046ff9cc164064f431a2893eb628b467d018452"
            .parse()
            .expect("hash"),
        index: 0,
        tree: 0,
    }
}

/// dcrd `entry299`, in the given state.
fn entry299(state: u8) -> UtxoEntry {
    let mut entry = UtxoEntry::new(
        58_795_424,
        unhex("76a914454017705ab80470d089c7f644e39cc9e0fd308e88ac"),
        299,
        1,
        0,
        false,
        false,
        TxType::Regular,
        None,
    );
    entry.set_state_bits(state);
    entry
}

/// dcrd `outpoint1200`.
fn outpoint1200() -> OutPoint {
    OutPoint {
        hash: "72914cae2d4bc75f7777373b7c085c4b92d59f3e059fc7fd39def71c9fe188b5"
            .parse()
            .expect("hash"),
        index: 2,
        tree: 0,
    }
}

/// dcrd `entry1200`, in the given state.
fn entry1200(state: u8) -> UtxoEntry {
    let mut entry = UtxoEntry::new(
        1_871_749_598,
        unhex("76a9142ec5027abadede723c47b6acdbace3be10b7e93788ac"),
        1200,
        0,
        0,
        true,
        false,
        TxType::Regular,
        None,
    );
    entry.set_state_bits(state);
    entry
}

const MODIFIED_SPENT: u8 = UTXO_STATE_MODIFIED | UTXO_STATE_SPENT;

/// A chain without a database whose cache holds exactly `cached`
/// and whose backend holds exactly `backend`.
fn chain_with(
    cached: &[(OutPoint, Option<UtxoEntry>)],
    backend: &[(OutPoint, UtxoEntry)],
) -> Chain {
    let mut chain = Chain::new(&regnet_params(), Hash::ZERO, false);
    for (outpoint, entry) in backend {
        chain.utxo_backend.insert(key_of(outpoint), entry.clone());
    }
    for (outpoint, entry) in cached {
        chain
            .utxo_cache
            .borrow_mut()
            .insert(key_of(outpoint), entry.clone());
    }
    chain
}

/// A view holding exactly `entries`.
fn view_with(entries: &[(OutPoint, UtxoEntry)]) -> UtxoView {
    let mut view = UtxoView::new();
    for (outpoint, entry) in entries {
        view.insert_entry(outpoint, entry.clone());
    }
    view
}

/// Everything the cache holds, in key order.
fn cache_of(chain: &Chain) -> Vec<(Key, Option<UtxoEntry>)> {
    let cache = chain.utxo_cache.borrow();
    let mut keys: Vec<Key> = Vec::new();
    for outpoint in [outpoint299(), outpoint1200()] {
        if cache.get(&key_of(&outpoint)).is_some() {
            keys.push(key_of(&outpoint));
        }
    }
    assert_eq!(keys.len(), cache.len(), "the cache holds only the fixtures");
    keys.sort();
    keys.into_iter()
        .map(|key| (key, cache.get(&key).cloned().expect("present")))
        .collect()
}

/// `TestSpendEntry` "spending cache entry already marked spent is a
/// noop": the cache entry stays as it was.
#[test]
fn spending_a_cache_entry_already_marked_spent_is_a_noop() {
    let outpoint = outpoint299();
    let mut chain = chain_with(&[(outpoint, Some(entry299(MODIFIED_SPENT)))], &[]);
    let mut view = view_with(&[(outpoint, entry299(MODIFIED_SPENT))]);

    chain.commit_view(&mut view);

    assert_eq!(
        cache_of(&chain),
        vec![(key_of(&outpoint), Some(entry299(MODIFIED_SPENT)))]
    );
    assert_eq!(view.entries().count(), 0, "the view entry is committed");
}

/// `TestCommit` "modified spent view entry w/ existing spent cache
/// entry is a noop": the view entry leaves the view and the cache is
/// unchanged.
#[test]
fn modified_spent_view_entry_over_an_existing_spent_cache_entry_is_a_noop() {
    let outpoint = outpoint1200();
    let mut chain = chain_with(&[(outpoint, Some(entry1200(MODIFIED_SPENT)))], &[]);
    let mut view = view_with(&[(outpoint, entry1200(MODIFIED_SPENT))]);

    chain.commit_view(&mut view);

    assert_eq!(view.entries().count(), 0, "want an empty view");
    assert_eq!(
        cache_of(&chain),
        vec![(key_of(&outpoint), Some(entry1200(MODIFIED_SPENT)))]
    );
}

/// dcrd tests whether the cached entry is spent before whether it is
/// fresh (`utxocache.go:353` ahead of `:408`), so a spent entry is left
/// as it is even when it is also fresh, where a fresh unspent one
/// would become an explicit spent marker.
#[test]
fn a_spent_cache_entry_is_left_as_it_is_even_when_fresh() {
    let spent = outpoint299();
    let unspent = outpoint1200();
    let spent_fresh = MODIFIED_SPENT | UTXO_STATE_FRESH;
    let unspent_fresh = UTXO_STATE_MODIFIED | UTXO_STATE_FRESH;
    let mut chain = chain_with(
        &[
            (spent, Some(entry299(spent_fresh))),
            (unspent, Some(entry1200(unspent_fresh))),
        ],
        &[],
    );
    let mut view = view_with(&[
        (spent, entry299(MODIFIED_SPENT)),
        (unspent, entry1200(MODIFIED_SPENT)),
    ]);

    chain.commit_view(&mut view);

    let mut want = vec![
        (key_of(&spent), Some(entry299(spent_fresh))),
        (key_of(&unspent), None),
    ];
    want.sort_by_key(|(key, _)| *key);
    assert_eq!(cache_of(&chain), want);
}

/// The path dcrd's comment names, as the cache sees it: a commit spends
/// an output the backend holds, leaving a spent tombstone, and a later
/// commit before any flush spends it again.  The second spend leaves
/// the tombstone in place, and the next flush deletes the backend row.
#[test]
fn a_second_spend_before_a_flush_leaves_the_tombstone_for_the_flush() {
    let outpoint = outpoint1200();
    let key = key_of(&outpoint);
    let mut chain = chain_with(&[], &[(outpoint, entry1200(0))]);

    // The first spend loads the backend row into the cache as a spent
    // tombstone.
    chain.commit_view(&mut view_with(&[(outpoint, entry1200(MODIFIED_SPENT))]));
    assert_eq!(
        cache_of(&chain),
        vec![(key, Some(entry1200(MODIFIED_SPENT)))]
    );

    // The second spend of the same output finds the tombstone.
    chain.commit_view(&mut view_with(&[(outpoint, entry1200(MODIFIED_SPENT))]));
    assert_eq!(
        cache_of(&chain),
        vec![(key, Some(entry1200(MODIFIED_SPENT)))]
    );

    chain.flush_utxo_cache_for_stats().expect("flush");
    assert!(
        !chain.utxo_backend.contains_key(&key),
        "the flush deletes the spent output's row"
    );
    assert_eq!(
        chain.fetch_utxo_entry(&outpoint),
        None,
        "the output is spent through the cache and the backend"
    );
}
