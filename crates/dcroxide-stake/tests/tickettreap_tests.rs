// SPDX-License-Identifier: ISC
//! dcrd's own immutable ticket treap test battery
//! (tickettreap/immutable_test.go at stake/v5 v5.0.2) ported: empty
//! treap behavior, sequential and reverse-sequential insert/delete
//! with exact size accounting, unordered keys, duplicate puts, early
//! iteration stop, height-bounded iteration, snapshot immutability,
//! and the heap invariant throughout.  The unordered test derives its
//! keys from a deterministic generator instead of Go's sha256 counter
//! (only distinctness and disorder matter), and dcrd's nil-value
//! no-op `Put` is unrepresentable here since values are passed by
//! value.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_stake::tickettreap::{Immutable, Key, Value};

/// Per-node size per dcrd's accounting with 64-bit pointers.
const NODE_SIZE: u64 = 104;

fn uint32_to_key(ui: u32) -> Key {
    let mut key = [0u8; 32];
    key[28..].copy_from_slice(&ui.to_be_bytes());
    key
}

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn key(&mut self) -> Key {
        let mut key = [0u8; 32];
        for chunk in key.chunks_mut(8) {
            chunk.copy_from_slice(&self.next().to_le_bytes());
        }
        key
    }
}

/// dcrd `TestImmutableEmpty`.
#[test]
fn immutable_empty() {
    let treap = Immutable::new();
    assert_eq!(treap.len(), 0, "len");
    assert_eq!(treap.size(), 0, "size");
    let key = uint32_to_key(0);
    assert!(!treap.has(&key), "has");
    assert_eq!(treap.value(&key), None, "get");
    let deleted = treap.delete(&key);
    assert_eq!(deleted.len(), 0, "delete on empty");
    let mut num_iterated = 0;
    treap.for_each(|_, _| {
        num_iterated += 1;
        true
    });
    assert_eq!(num_iterated, 0, "foreach count");
    assert!(
        std::panic::catch_unwind(|| treap.get_by_index(0)).is_err(),
        "get_by_index(0) must panic on empty"
    );
}

/// dcrd `TestImmutableSequential`: 1,000 sequential puts with exact
/// length/size/index checks, iteration order, height-bounded
/// iteration, and sequential deletes.
#[test]
fn immutable_sequential() {
    let num_items: usize = 1000;
    let mut expected_size: u64 = 0;
    let mut treap = Immutable::new();
    for i in 0..num_items {
        let key = uint32_to_key(i as u32);
        let value = Value::new(i as u32);
        treap = treap.put(key, value);
        assert_eq!(treap.len(), i + 1, "len #{i}");
        assert!(treap.has(&key), "has #{i}");
        assert_eq!(treap.value(&key), Some(value), "get #{i}");
        expected_size += NODE_SIZE;
        assert_eq!(treap.size(), expected_size, "size #{i}");
        let (k, v) = treap.get_by_index(i);
        assert_eq!(k, key, "get_by_index key #{i}");
        assert_eq!(v, value, "get_by_index value #{i}");
    }
    {
        let treap = treap.clone();
        assert!(
            std::panic::catch_unwind(move || treap.get_by_index(num_items)).is_err(),
            "get_by_index(len) must panic"
        );
    }
    assert!(treap.heap_invariant_ok(), "heap invariant");

    let mut num_iterated = 0usize;
    treap.for_each(|k, v| {
        assert_eq!(*k, uint32_to_key(num_iterated as u32), "foreach key");
        assert_eq!(*v, Value::new(num_iterated as u32), "foreach value");
        num_iterated += 1;
        true
    });
    assert_eq!(num_iterated, num_items, "foreach count");

    let mut num_iterated = 0u32;
    let query_height = 50 / 20;
    treap.for_each_by_height(query_height, |_, v| {
        assert!(v.height < query_height, "height bound");
        num_iterated += 1;
        true
    });
    assert_eq!(num_iterated, query_height, "foreach by height count");

    for i in 0..num_items {
        let key = uint32_to_key(i as u32);
        treap = treap.delete(&key);
        let expected_len = num_items - i - 1;
        let expected_head = i + 1;
        assert_eq!(treap.len(), expected_len, "len after delete #{i}");
        assert!(!treap.has(&key), "has after delete #{i}");
        if expected_len > 0 {
            let (k, _) = treap.get_by_index(0);
            assert_eq!(k, uint32_to_key(expected_head as u32), "head #{i}");
            let half_idx = expected_len / 2;
            let (k, _) = treap.get_by_index(half_idx);
            assert_eq!(
                k,
                uint32_to_key((expected_head + half_idx) as u32),
                "half #{i}"
            );
            let (k, _) = treap.get_by_index(expected_len - 1);
            assert_eq!(
                k,
                uint32_to_key((expected_head + expected_len - 1) as u32),
                "tail #{i}"
            );
        }
        assert_eq!(treap.value(&key), None, "get after delete #{i}");
        expected_size -= NODE_SIZE;
        assert_eq!(treap.size(), expected_size, "size after delete #{i}");
    }
}

/// dcrd `TestImmutableReverseSequential`: reverse inserts, in-order
/// iteration, forward deletes with the heap invariant maintained.
#[test]
fn immutable_reverse_sequential() {
    let num_items: usize = 1000;
    let mut expected_size: u64 = 0;
    let mut treap = Immutable::new();
    for i in 0..num_items {
        let n = (num_items - i - 1) as u32;
        let key = uint32_to_key(n);
        let value = Value::new(n);
        treap = treap.put(key, value);
        assert_eq!(treap.len(), i + 1, "len #{i}");
        assert!(treap.has(&key), "has #{i}");
        assert_eq!(treap.value(&key), Some(value), "get #{i}");
        expected_size += NODE_SIZE;
        assert_eq!(treap.size(), expected_size, "size #{i}");
    }
    assert!(treap.heap_invariant_ok(), "heap invariant");

    let mut num_iterated = 0usize;
    treap.for_each(|k, v| {
        assert_eq!(*k, uint32_to_key(num_iterated as u32), "foreach key");
        assert_eq!(*v, Value::new(num_iterated as u32), "foreach value");
        num_iterated += 1;
        true
    });
    assert_eq!(num_iterated, num_items, "foreach count");

    for i in 0..num_items {
        let key = uint32_to_key(i as u32);
        treap = treap.delete(&key);
        assert_eq!(treap.len(), num_items - i - 1, "len after delete #{i}");
        assert!(!treap.has(&key), "has after delete #{i}");
        assert_eq!(treap.value(&key), None, "get after delete #{i}");
        assert!(
            treap.heap_invariant_ok(),
            "heap invariant after delete #{i}"
        );
        expected_size -= NODE_SIZE;
        assert_eq!(treap.size(), expected_size, "size after delete #{i}");
    }
}

/// dcrd `TestImmutableUnordered` with deterministic pseudorandom keys
/// in place of the sha256 counter.
#[test]
fn immutable_unordered() {
    let num_items: usize = 1000;
    let mut expected_size: u64 = 0;
    let mut treap = Immutable::new();
    let mut rng = Lcg(0x74726561);
    let mut keys = Vec::with_capacity(num_items);
    for i in 0..num_items {
        let key = rng.key();
        keys.push(key);
        let value = Value::new(i as u32);
        treap = treap.put(key, value);
        assert_eq!(treap.len(), i + 1, "len #{i}");
        assert!(treap.has(&key), "has #{i}");
        assert_eq!(treap.value(&key), Some(value), "get #{i}");
        expected_size += NODE_SIZE;
        assert_eq!(treap.size(), expected_size, "size #{i}");
    }
    assert!(treap.heap_invariant_ok(), "heap invariant");

    // Iteration must be in key order.
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    let mut num_iterated = 0usize;
    treap.for_each(|k, _| {
        assert_eq!(*k, sorted[num_iterated], "foreach key order");
        num_iterated += 1;
        true
    });
    assert_eq!(num_iterated, num_items, "foreach count");

    for (i, key) in keys.iter().enumerate() {
        treap = treap.delete(key);
        assert_eq!(treap.len(), num_items - i - 1, "len after delete #{i}");
        assert!(!treap.has(key), "has after delete #{i}");
        assert_eq!(treap.value(key), None, "get after delete #{i}");
        expected_size -= NODE_SIZE;
        assert_eq!(treap.size(), expected_size, "size after delete #{i}");
    }
    assert!(treap.heap_invariant_ok(), "heap invariant after deletes");
}

/// dcrd `TestImmutableDuplicatePut`.
#[test]
fn immutable_duplicate_put() {
    let expected_val = Value::new(10000);
    let mut expected_size: u64 = 0;
    let num_items: usize = 1000;
    let mut treap = Immutable::new();
    for i in 0..num_items {
        let key = uint32_to_key(i as u32);
        treap = treap.put(key, Value::new(i as u32));
        expected_size += NODE_SIZE;

        // Put a duplicate and ensure the value was updated while the
        // length and size stayed the same.
        treap = treap.put(key, expected_val);
        assert_eq!(treap.len(), i + 1, "len #{i}");
        assert_eq!(treap.value(&key), Some(expected_val), "value #{i}");
        assert_eq!(treap.size(), expected_size, "size #{i}");
    }
}

/// dcrd `TestImmutableForEachStopIterator`.
#[test]
fn immutable_for_each_stop_iterator() {
    let num_items: usize = 10;
    let mut treap = Immutable::new();
    for i in 0..num_items {
        treap = treap.put(uint32_to_key(i as u32), Value::new(i as u32));
    }
    let mut num_iterated = 0usize;
    treap.for_each(|_, _| {
        num_iterated += 1;
        num_iterated != num_items / 2
    });
    assert_eq!(num_iterated, num_items / 2, "stopped early");
}

/// dcrd `TestImmutableSnapshot`: older versions must be unaffected by
/// later puts and deletes.
#[test]
fn immutable_snapshot() {
    let num_items: usize = 1000;
    let mut treap = Immutable::new();
    for i in 0..num_items {
        let key = uint32_to_key(i as u32);
        let value = Value::new(i as u32);

        let snap = treap.clone();
        let snap_len = snap.len();
        let snap_size = snap.size();
        treap = treap.put(key, value);
        assert_eq!(snap.len(), snap_len, "snapshot len after put #{i}");
        assert!(!snap.has(&key), "snapshot has after put #{i}");
        assert_eq!(snap.value(&key), None, "snapshot get after put #{i}");
        assert_eq!(snap.size(), snap_size, "snapshot size after put #{i}");
    }
    for i in 0..num_items {
        let key = uint32_to_key(i as u32);
        let value = Value::new(i as u32);

        let snap = treap.clone();
        let snap_len = snap.len();
        let snap_size = snap.size();
        treap = treap.delete(&key);
        assert_eq!(snap.len(), snap_len, "snapshot len after delete #{i}");
        assert!(snap.has(&key), "snapshot has after delete #{i}");
        assert_eq!(
            snap.value(&key),
            Some(value),
            "snapshot get after delete #{i}"
        );
        assert_eq!(snap.size(), snap_size, "snapshot size after delete #{i}");
    }
}

/// Supplementary: `fetch_winners_and_expired` index selection and the
/// expiry sweep over a mixed-height treap.
#[test]
fn fetch_winners_and_expired() {
    let mut treap = Immutable::new();
    for i in 0..20u32 {
        treap = treap.put(uint32_to_key(i), Value::new(i));
    }
    // None indexes yield nothing.
    let (w, e) = treap.fetch_winners_and_expired(None, 5);
    assert!(w.is_empty() && e.is_empty(), "nil idxs");

    // Winners are selected by in-order index; keys equal heights here.
    let idxs = [3usize, 7, 11];
    let (w, e) = treap.fetch_winners_and_expired(Some(&idxs), 5);
    let want: Vec<_> = idxs.iter().map(|&i| uint32_to_key(i as u32)).collect();
    assert_eq!(w, want, "winners");
    // Heights 0..=5 are expired at height 5.
    assert_eq!(e.len(), 6, "expired count");
}
