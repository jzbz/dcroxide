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
//! dcrd `e60cedc5` turned the commit's remaining check, a
//! zero-confirmation spend that is not also marked spent, from an
//! `AssertError` into a panic (`utxocache.go:594-601`), and `TestCommit`
//! now expects the panic.
//!
//! dcrd `22fd2431` added a second panic for a zero-confirmation spend:
//! such an output only ever existed in the view, so the cache must not
//! hold an unspent entry for it (`utxocache.go:602-606`).  `6b5bc9d0`
//! added the `TestCommit` rows for it, and a row for the
//! zero-confirmation spends a commit drops without touching the cache,
//! even when the cache holds the output spent: an output spent later in
//! its own block's regular tree can have a cache or backend entry when
//! the same transaction was created by a different block.
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

/// dcrd `outpoint1100`.
fn outpoint1100() -> OutPoint {
    OutPoint {
        hash: "ce1d0f74440c391d15516015224755a8661e56e796ac25490f30ad1081c5d638"
            .parse()
            .expect("hash"),
        index: 1,
        tree: 0,
    }
}

/// dcrd `entry1100`, in the given state.
fn entry1100(state: u8) -> UtxoEntry {
    let mut entry = UtxoEntry::new(
        52_454_022,
        unhex("76a9146b65f16ebca9b848158701d5a2eb5124547a214488ac"),
        1100,
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
/// The spent-by-zero-confirmation state bit (dcrd
/// `utxoStateSpentByZeroConf`), which the crate does not export.
const UTXO_STATE_SPENT_BY_ZERO_CONF: u8 = 1 << 2;

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
    for outpoint in [outpoint299(), outpoint1100(), outpoint1200()] {
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

/// `TestCommit` "modified spent by zero conf view entry w/o spent
/// panics": a view entry marked as a zero-confirmation spend but not
/// spent stops the commit with dcrd's text.
#[test]
fn a_zero_conf_view_entry_that_is_not_spent_panics() {
    let outpoint = outpoint1200();
    let mut chain = chain_with(&[], &[]);
    let mut view = view_with(&[(
        outpoint,
        entry1200(UTXO_STATE_MODIFIED | UTXO_STATE_SPENT_BY_ZERO_CONF),
    )]);
    let want = format!(
        "output {outpoint} (tree 0) from view@{} is simultaneously marked spent by a \
         transaction later in the same block and not spent",
        Hash::ZERO
    );
    let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        chain.commit_view(&mut view);
    }))
    .expect_err("the commit panics");
    assert_eq!(payload.downcast_ref::<String>(), Some(&want));
}

/// `TestCommit`'s modified spent-by-zero-confirmation view entry, in
/// dcrd's `modifiedSpentByZeroConf` state.
const MODIFIED_SPENT_BY_ZERO_CONF: u8 = MODIFIED_SPENT | UTXO_STATE_SPENT_BY_ZERO_CONF;

/// The text of the panic a commit of `outpoint` over an unspent cache
/// entry raises (dcrd `utxocache.go:602-606`).
fn unspent_cache_entry_panic(outpoint: &OutPoint) -> String {
    format!(
        "output {outpoint} (tree {}) from view@{} is marked as only having ever existed in the \
         view, but has an unspent cache entry",
        outpoint.tree,
        Hash::ZERO
    )
}

/// Commit `view` and return the text it panics with.
fn commit_panic_text(chain: &mut Chain, view: &mut UtxoView) -> Option<String> {
    let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        chain.commit_view(view);
    }))
    .err()?;
    payload.downcast_ref::<String>().cloned()
}

/// `TestCommit` "modified spent by zero conf view entry w/ unmodified
/// unspent cache entry panics": the cache holds a clean copy of the
/// backend's row for an output the view marks as spent within its own
/// block.
#[test]
fn a_zero_conf_view_entry_over_a_clean_unspent_cache_entry_panics() {
    let outpoint = outpoint1200();
    let mut chain = chain_with(
        &[(outpoint, Some(entry1200(0)))],
        &[(outpoint, entry1200(0))],
    );
    let mut view = view_with(&[(outpoint, entry1200(MODIFIED_SPENT_BY_ZERO_CONF))]);
    assert_eq!(
        commit_panic_text(&mut chain, &mut view),
        Some(unspent_cache_entry_panic(&outpoint))
    );
}

/// `TestCommit` "modified spent by zero conf view entry w/ modified
/// unspent fresh cache entry panics": the cache holds an output no flush
/// has written yet.
#[test]
fn a_zero_conf_view_entry_over_a_fresh_unspent_cache_entry_panics() {
    let outpoint = outpoint1200();
    let mut chain = chain_with(
        &[(
            outpoint,
            Some(entry1200(UTXO_STATE_MODIFIED | UTXO_STATE_FRESH)),
        )],
        &[],
    );
    let mut view = view_with(&[(outpoint, entry1200(MODIFIED_SPENT_BY_ZERO_CONF))]);
    assert_eq!(
        commit_panic_text(&mut chain, &mut view),
        Some(unspent_cache_entry_panic(&outpoint))
    );
}

/// `TestCommit` "several modified spent zero conf view entry
/// combinations": a zero-confirmation spend with no cache or backend
/// entry, and one over a spent fresh cache entry, both leave the view
/// and leave the cache as it was.  An explicit spent marker in the
/// cache, dcrd's nil entry, is no unspent entry either.
#[test]
fn zero_conf_view_entries_over_no_or_spent_cache_entries_leave_the_cache_as_it_was() {
    let spent_fresh = MODIFIED_SPENT | UTXO_STATE_FRESH;
    let mut chain = chain_with(&[(outpoint1100(), Some(entry1100(spent_fresh)))], &[]);
    let mut view = view_with(&[
        (outpoint299(), entry299(MODIFIED_SPENT_BY_ZERO_CONF)),
        (outpoint1100(), entry1100(MODIFIED_SPENT_BY_ZERO_CONF)),
    ]);

    chain.commit_view(&mut view);

    assert_eq!(view.entries().count(), 0, "want an empty view");
    assert_eq!(
        cache_of(&chain),
        vec![(key_of(&outpoint1100()), Some(entry1100(spent_fresh)))]
    );

    let mut chain = chain_with(&[(outpoint1200(), None)], &[]);
    let mut view = view_with(&[(outpoint1200(), entry1200(MODIFIED_SPENT_BY_ZERO_CONF))]);
    chain.commit_view(&mut view);
    assert_eq!(view.entries().count(), 0, "want an empty view");
    assert_eq!(cache_of(&chain), vec![(key_of(&outpoint1200()), None)]);
}
