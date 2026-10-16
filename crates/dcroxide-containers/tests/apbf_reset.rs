// SPDX-License-Identifier: ISC
//! `Filter::reset` leaves exactly what dcrd's `Reset` leaves
//! (`container/apbf/filter.go:494-503`) whether or not it had anything
//! to clear: the rotated key, the first slice back at the start of the
//! ring, an empty generation and all-zero data.
//!
//! The port only walks the data when a bit was set since it was last
//! all zero.  The reference each test compares against never relies on
//! that: it replaces the filter with a newly built one of the same
//! parameters, whose data is freshly allocated zeros, and gives it the
//! key dcrd's `Reset` derives.  `apbf_vectors` pins that same state
//! against dcrd's own package for a reset after additions.
//!
//! These tests pin the state a reset leaves and the flag that says the
//! data may hold a bit.  They cannot see whether a reset walked the
//! data: a reset that zeroed it every time would pass them all.  That
//! the walk is skipped is pinned by the unit test beside the filter
//! (`a_reset_passes_over_the_data_only_after_an_addition`), which
//! counts the passes.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_containers::apbf::{Filter, new_filter, new_filter_kl, siphash128};
use dcroxide_testutil::SplitMix64;

/// A filter whose reset always starts from freshly zeroed data.
struct Reference {
    min_capacity: u32,
    filter: Filter,
}

impl Reference {
    fn new(min_capacity: u32, k: u8, l: u8, keys: (u64, u64)) -> Reference {
        let mut filter = new_filter_kl(min_capacity, k, l);
        filter.set_keys(keys.0, keys.1);
        Reference {
            min_capacity,
            filter,
        }
    }

    fn reset(&mut self) {
        let (key0, key1) = self.filter.keys();
        let (key0, key1) = siphash128(key0, key1, b"reset");
        let mut fresh = new_filter_kl(self.min_capacity, self.filter.k(), self.filter.l());
        fresh.set_keys(key0, key1);
        self.filter = fresh;
    }
}

/// A filter under test and its reference, built alike.
fn pair(min_capacity: u32, k: u8, l: u8, keys: (u64, u64)) -> (Filter, Reference) {
    let mut filter = new_filter_kl(min_capacity, k, l);
    filter.set_keys(keys.0, keys.1);
    (filter, Reference::new(min_capacity, k, l, keys))
}

fn item(i: u32) -> [u8; 4] {
    i.to_be_bytes()
}

/// The filter matches the reference in everything a caller or a later
/// operation can depend on, and its claim that no bit is set is true.
fn assert_same(filter: &Filter, reference: &Reference, what: &str) {
    assert_eq!(filter.keys(), reference.filter.keys(), "{what}: keys");
    assert_eq!(
        filter.internal_state(),
        reference.filter.internal_state(),
        "{what}: base index, generation count and data"
    );
    assert_eq!(
        filter.internal_params(),
        reference.filter.internal_params(),
        "{what}: parameters"
    );
    let (_, _, data) = filter.internal_state();
    if !filter.maybe_set() {
        assert!(
            data.iter().all(|b| *b == 0),
            "{what}: the filter claims no bit is set while its data holds one"
        );
    }
}

/// The membership answers over a range match, false positives included.
fn assert_same_answers(filter: &Filter, reference: &Reference, range: u32, what: &str) {
    for i in 0..range {
        assert_eq!(
            filter.contains(&item(i)),
            reference.filter.contains(&item(i)),
            "{what}: contains({i})"
        );
    }
}

#[test]
fn a_reset_with_nothing_added_leaves_what_a_clearing_reset_leaves() {
    const KEYS: (u64, u64) = (0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210);

    // Small parameters with a high false positive rate, so the answers
    // after the reset depend on the key it rotated to.
    let (mut filter, mut reference) = pair(40, 2, 3, KEYS);
    for round in 0..4 {
        filter.reset();
        reference.reset();
        assert_same(&filter, &reference, &format!("empty reset {round}"));
        assert!(!filter.maybe_set(), "nothing was added in round {round}");
        assert_ne!(filter.keys(), KEYS, "the key rotates on every reset");
    }

    // The additions that follow land where the reference's land and are
    // answered alike, which they only are under the same key.
    for i in 0..60 {
        filter.add(&item(i));
        reference.filter.add(&item(i));
    }
    assert_same(&filter, &reference, "additions after the empty resets");
    assert_same_answers(&filter, &reference, 4000, "after the empty resets");
    assert!(
        (60..4000).any(|i| filter.contains(&item(i))),
        "the parameters are meant to yield false positives"
    );
}

#[test]
fn a_reset_with_nothing_added_still_rewinds_an_aged_filter() {
    // Aging moves the first slice and clears bits but sets none, so the
    // data is still all zero and the reset has only the ring position
    // and the generation count to restore.
    let (mut filter, mut reference) = pair(40, 2, 3, (7, 11));
    for _ in 0..3 {
        filter.next_generation();
        reference.filter.next_generation();
    }
    let (base_index, _, _) = filter.internal_state();
    assert_ne!(base_index, 0, "aging moved the first slice");
    assert!(!filter.maybe_set());

    filter.reset();
    reference.reset();
    assert_same(&filter, &reference, "reset of an aged empty filter");
    let (base_index, items_in_cur_generation, _) = filter.internal_state();
    assert_eq!((base_index, items_in_cur_generation), (0, 0));
}

#[test]
fn a_reset_with_nothing_set_still_empties_the_generation() {
    // With no slices to match, an addition counts toward the generation
    // and sets no bit, so this is the one filter whose generation count
    // can be above zero while its data is untouched.  The count is
    // cleared all the same.
    let (mut filter, mut reference) = pair(40, 0, 3, (13, 17));
    for i in 0..7 {
        filter.add(&item(i));
        reference.filter.add(&item(i));
    }
    let (_, items_in_cur_generation, _) = filter.internal_state();
    assert_eq!(items_in_cur_generation, 7);
    assert!(!filter.maybe_set());

    filter.reset();
    reference.reset();
    assert_same(&filter, &reference, "reset of a filter with no slices");
    let (base_index, items_in_cur_generation, _) = filter.internal_state();
    assert_eq!((base_index, items_in_cur_generation), (0, 0));
}

#[test]
fn a_reset_after_an_addition_clears_the_data() {
    // The rejected transaction filter's own parameters (dcrd
    // `maxRejectedTxns` and `rejectedTxnsFPRate`,
    // `internal/netsync/manager.go`).
    let mut filter = new_filter(62500, 0.000_000_1);
    filter.set_keys(3, 5);
    let mut reference = Reference::new(62500, filter.k(), filter.l(), (3, 5));
    assert_same(&filter, &reference, "as built");
    assert!(!filter.maybe_set());

    // One addition is enough to make the reset clear.
    filter.add(&item(1));
    reference.filter.add(&item(1));
    assert!(filter.maybe_set());
    assert!(filter.internal_state().2.iter().any(|b| *b != 0));
    assert!(filter.contains(&item(1)));

    filter.reset();
    reference.reset();
    assert_same(&filter, &reference, "reset after one addition");
    assert!(!filter.maybe_set());
    assert!(filter.internal_state().2.iter().all(|b| *b == 0));
    assert!(!filter.contains(&item(1)));

    // The same after enough additions to age the filter, with an empty
    // reset in between and after.
    filter.reset();
    reference.reset();
    for i in 0..10_000 {
        filter.add(&item(i));
        reference.filter.add(&item(i));
    }
    assert_ne!(
        filter.internal_state().0,
        0,
        "the additions aged the filter"
    );
    assert_same(&filter, &reference, "additions after two resets");
    filter.reset();
    reference.reset();
    assert_same(&filter, &reference, "reset after many additions");
    assert!(filter.internal_state().2.iter().all(|b| *b == 0));
    filter.reset();
    reference.reset();
    assert_same(&filter, &reference, "empty reset after a clearing one");
    assert_same_answers(&filter, &reference, 10_000, "after the resets");
}

#[test]
fn random_additions_and_resets_match_a_reference_that_always_clears() {
    let mut rng = SplitMix64::from_entropy("apbf reset differential");

    // (min capacity, k, l): generations of 1, 10 and 34 items, so the
    // sequences below age the filters many times over.
    for (min_capacity, k, l) in [(4u32, 1u8, 3u8), (40, 2, 3), (500, 7, 14)] {
        let keys = (rng.next_u64(), rng.next_u64());
        let (mut filter, mut reference) = pair(min_capacity, k, l, keys);
        let domain = 4 * min_capacity;
        let what = format!("capacity {min_capacity}, k {k}, l {l}");

        for step in 0..4000 {
            // Resets are frequent enough that many find nothing added
            // since the previous one, and many others find a filter
            // that has been added to, aged, or both.
            match rng.below(10) {
                0..=4 => {
                    let i = rng.below(u64::from(domain)) as u32;
                    filter.add(&item(i));
                    reference.filter.add(&item(i));
                }
                5..=7 => {
                    filter.reset();
                    reference.reset();
                    assert!(!filter.maybe_set(), "{what}: step {step}");
                }
                8 => {
                    filter.next_generation();
                    reference.filter.next_generation();
                }
                _ => {
                    let i = rng.below(u64::from(domain)) as u32;
                    assert_eq!(
                        filter.contains(&item(i)),
                        reference.filter.contains(&item(i)),
                        "{what}: step {step}: contains({i})"
                    );
                }
            }
            assert_same(&filter, &reference, &format!("{what}: step {step}"));
        }
        assert_same_answers(&filter, &reference, domain, &what);
    }
}
