// SPDX-License-Identifier: ISC
//! The memtable: every key of an indexed block that is not yet in a run.
//!
//! 256 partitions, each behind its own `RwLock`, so a lookup reads one
//! partition and never waits on the others.  Two writers change it, and
//! both hold the database's writer semaphore while they do, so they never
//! overlap: the connect's `on_commit` hook, which inserts, and the flush
//! participant's `finished`, which folds and clears.  The participant's
//! `contribute` only reads.
//!
//! The memtable does not hash: every call names the partition, which the
//! caller computes with the index's [`super::policy::Partitioner`].
//!
//! A partition keeps its journaled keys in one sorted vector and its
//! unjournaled keys in a few sorted runs of geometrically falling length,
//! merged as they grow.  However the inserts arrive -- a key a block, or
//! a block's worth into one partition -- each key is copied
//! O(log n) times before the flush that journals it, so a partition an
//! adversary crowds costs n log n, not n squared, under the writer
//! semaphore.  Every vector is grown by exact-capacity merges, so the
//! memtable costs 21 bytes a key plus a transient copy of one partition.

use std::sync::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::Key;
use super::policy::PARTITIONS;

/// One partition's keys.  The vectors are pairwise disjoint.
#[derive(Default)]
struct Part {
    /// Journaled by a committed flush, awaiting a merge.  Sorted.
    journaled: Vec<Key>,
    /// Not yet journaled: sorted runs, each more than twice as long as
    /// the next, so there are at most `log2(n) + 1` of them.
    fresh: Vec<Vec<Key>>,
    /// Keys in `fresh`.
    fresh_len: usize,
}

impl Part {
    fn contains(&self, key: &Key) -> bool {
        self.journaled.binary_search(key).is_ok()
            || self.fresh.iter().any(|run| run.binary_search(key).is_ok())
    }

    fn len(&self) -> usize {
        self.journaled.len().saturating_add(self.fresh_len)
    }

    /// Add a sorted run of keys this partition does not hold, then merge
    /// the newest runs while the newer is at least half the older, which
    /// restores the length invariant.  Returns the keys the merges copied.
    ///
    /// A key's run at least grows by half each time an older run merges
    /// with it, so a key is copied O(log n) times as an older run, plus
    /// once per run it passes as the newest, of which there are at most
    /// `log2(n) + 1`.
    fn add_run(&mut self, run: Vec<Key>) -> usize {
        self.fresh_len = self.fresh_len.saturating_add(run.len());
        self.fresh.push(run);
        let mut copied = 0usize;
        while let [.., older, newer] = self.fresh.as_slice()
            && older.len() <= newer.len().saturating_mul(2)
        {
            let newer = self.fresh.pop().expect("two runs");
            let older = self.fresh.pop().expect("two runs");
            let merged = merge_sorted(&older, &newer);
            copied = copied.saturating_add(merged.len());
            self.fresh.push(merged);
        }
        copied
    }

    /// The unjournaled keys, sorted, in one vector.
    fn unjournaled(&self) -> Vec<Key> {
        let mut runs = self.fresh.iter().rev();
        let Some(newest) = runs.next() else {
            return Vec::new();
        };
        let mut all = newest.clone();
        for older in runs {
            all = merge_sorted(older, &all);
        }
        all
    }
}

/// Merge two sorted, disjoint vectors into one of exact capacity.
pub(crate) fn merge_sorted(a: &[Key], b: &[Key]) -> Vec<Key> {
    let mut out = Vec::with_capacity(a.len().saturating_add(b.len()));
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() && j < b.len() {
        if a[i] <= b[j] {
            out.push(a[i]);
            i = i.saturating_add(1);
        } else {
            out.push(b[j]);
            j = j.saturating_add(1);
        }
    }
    out.extend_from_slice(&a[i..]);
    out.extend_from_slice(&b[j..]);
    out
}

/// The keys of indexed blocks not yet merged into a run, partitioned by
/// the index's partition hash.
pub(crate) struct Memtable {
    parts: Box<[RwLock<Part>]>,
    /// Keys held, over every partition.
    len: AtomicUsize,
    /// Keys held and not yet journaled.
    unjournaled: AtomicUsize,
    /// Keys copied by the merges of unjournaled runs, for the test that
    /// bounds the insert cost.
    #[cfg(test)]
    copied: AtomicUsize,
}

impl Memtable {
    /// An empty memtable.
    pub(crate) fn new() -> Memtable {
        Memtable {
            parts: (0..PARTITIONS)
                .map(|_| RwLock::new(Part::default()))
                .collect(),
            len: AtomicUsize::new(0),
            unjournaled: AtomicUsize::new(0),
            #[cfg(test)]
            copied: AtomicUsize::new(0),
        }
    }

    fn part(&self, p: usize) -> std::sync::RwLockReadGuard<'_, Part> {
        self.parts[p].read().expect("memtable partition poisoned")
    }

    fn part_mut(&self, p: usize) -> std::sync::RwLockWriteGuard<'_, Part> {
        self.parts[p].write().expect("memtable partition poisoned")
    }

    /// Keys held.
    pub(crate) fn len(&self) -> usize {
        self.len.load(Ordering::SeqCst)
    }

    /// Keys held and not yet journaled.
    pub(crate) fn unjournaled(&self) -> usize {
        self.unjournaled.load(Ordering::SeqCst)
    }

    /// Whether partition `p` holds `key`: a binary search of each sorted
    /// vector, under the partition's read lock.
    pub(crate) fn contains(&self, p: u8, key: &Key) -> bool {
        self.part(usize::from(p)).contains(key)
    }

    /// Insert every key not already held; returns how many were new.
    ///
    /// `keys` pairs each key with its partition, sorted by partition (and
    /// best by key within one); each partition's lock is taken once, and
    /// its new keys go in as one run.
    ///
    /// Only for a holder of the database's writer semaphore: the
    /// participant reads the memtable without locks of its own between
    /// `contribute` and `finished`, relying on nothing else writing then.
    pub(crate) fn insert_candidates(&self, keys: &[(u8, Key)]) -> usize {
        debug_assert!(
            keys.windows(2).all(|w| w[0].0 <= w[1].0),
            "candidates must be grouped by partition"
        );
        let mut added = 0usize;
        let mut copied = 0usize;
        let mut rest = keys;
        while let Some(&(p, _)) = rest.first() {
            let end = rest.partition_point(|&(q, _)| q == p);
            let (group, tail) = rest.split_at(end);
            rest = tail;
            let mut part = self.part_mut(usize::from(p));
            let mut run: Vec<Key> = group
                .iter()
                .map(|&(_, key)| key)
                .filter(|key| !part.contains(key))
                .collect();
            if run.is_empty() {
                continue;
            }
            run.sort_unstable();
            run.dedup();
            added = added.saturating_add(run.len());
            copied = copied.saturating_add(part.add_run(run));
        }
        #[cfg(test)]
        self.copied.fetch_add(copied, Ordering::SeqCst);
        let _ = copied;
        self.len.fetch_add(added, Ordering::SeqCst);
        self.unjournaled.fetch_add(added, Ordering::SeqCst);
        added
    }

    /// Keys held in each partition.
    pub(crate) fn sizes(&self) -> [usize; PARTITIONS] {
        let mut sizes = [0usize; PARTITIONS];
        for (p, size) in sizes.iter_mut().enumerate() {
            *size = self.part(p).len();
        }
        sizes
    }

    /// Partition `p`'s unjournaled keys, sorted.
    pub(crate) fn unjournaled_sorted(&self, p: usize) -> Vec<Key> {
        self.part(p).unjournaled()
    }

    /// Every key of partition `p`, sorted.
    pub(crate) fn all_sorted(&self, p: usize) -> Vec<Key> {
        let part = self.part(p);
        merge_sorted(&part.journaled, &part.unjournaled())
    }

    /// Every key held, sorted.
    pub(crate) fn snapshot(&self) -> Vec<Key> {
        let mut all = Vec::with_capacity(self.len());
        for p in 0..PARTITIONS {
            all.extend(self.all_sorted(p));
        }
        all.sort_unstable();
        all
    }

    /// Apply a committed flush: every unjournaled key is now journaled,
    /// and the partitions it merged are empty, their keys in runs.
    ///
    /// Each partition is changed under its own write lock, after the
    /// flush's commit, so a lookup that misses a cleared partition here
    /// begins its read transaction afterwards and finds the keys in the
    /// runs that commit wrote.
    pub(crate) fn commit_flush(&self, merged: &[bool; PARTITIONS]) {
        let mut removed = 0usize;
        for (p, &was_merged) in merged.iter().enumerate() {
            let mut part = self.part_mut(p);
            if was_merged {
                removed = removed.saturating_add(part.len());
                *part = Part::default();
                continue;
            }
            if part.fresh_len > 0 {
                let fresh = part.unjournaled();
                part.journaled = merge_sorted(&part.journaled, &fresh);
                part.fresh = Vec::new();
                part.fresh_len = 0;
            }
        }
        self.len.fetch_sub(removed, Ordering::SeqCst);
        self.unjournaled.store(0, Ordering::SeqCst);
    }

    /// Replace the contents with `parts`, one vector a partition, all
    /// journaled: what a restart reads back from the journal.  Each must
    /// be sorted and hold each key once; the vectors are kept as they are,
    /// not copied.
    pub(crate) fn load(&self, parts: Vec<Vec<Key>>) {
        debug_assert!(parts.is_empty() || parts.len() == PARTITIONS);
        let mut parts = parts.into_iter();
        let mut len = 0usize;
        for p in 0..PARTITIONS {
            let journaled = parts.next().unwrap_or_default();
            debug_assert!(journaled.windows(2).all(|w| w[0] < w[1]));
            len = len.saturating_add(journaled.len());
            *self.part_mut(p) = Part {
                journaled,
                fresh: Vec::new(),
                fresh_len: 0,
            };
        }
        self.len.store(len, Ordering::SeqCst);
        self.unjournaled.store(0, Ordering::SeqCst);
    }

    /// Empty the memtable.
    pub(crate) fn clear(&self) {
        self.load(Vec::new());
    }

    /// Partition `p`'s journaled count and its unjournaled runs' lengths,
    /// for tests.
    #[cfg(test)]
    pub(crate) fn shape(&self, p: usize) -> (usize, Vec<usize>) {
        let part = self.part(p);
        (
            part.journaled.len(),
            part.fresh.iter().map(Vec::len).collect(),
        )
    }

    /// Keys copied by unjournaled-run merges so far, for tests.
    #[cfg(test)]
    pub(crate) fn copied(&self) -> usize {
        self.copied.load(Ordering::SeqCst)
    }

    /// Partition `p`'s journaled vector's spare capacity, for tests.
    #[cfg(test)]
    pub(crate) fn spare_capacity(&self, p: usize) -> usize {
        let part = self.part(p);
        part.journaled
            .capacity()
            .saturating_sub(part.journaled.len())
    }
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic over small counts"
)]
mod tests {
    use super::*;

    fn key(t: u8, p: u8, rest: u8) -> Key {
        let mut k = [rest; 21];
        k[0] = t;
        k[1] = p;
        k
    }

    /// Candidates with the partition the tests file them under: the
    /// key's second byte, sorted as a connect sorts them.
    fn cands(keys: &[Key]) -> Vec<(u8, Key)> {
        let mut c: Vec<(u8, Key)> = keys.iter().map(|k| (k[1], *k)).collect();
        c.sort_unstable();
        c
    }

    /// Every run is more than twice the next.
    fn runs_fall_geometrically(m: &Memtable, p: usize) -> bool {
        let (_, runs) = m.shape(p);
        runs.windows(2).all(|w| w[0] > 2 * w[1])
    }

    /// Insert, contains and the counts; held keys are skipped.
    #[test]
    fn inserts_skip_held_keys_and_keep_the_runs_falling() {
        let m = Memtable::new();
        let mut keys: Vec<Key> = (0..=200u8).map(|r| key(0, 7, r)).collect();
        keys.push(key(3, 9, 1));
        assert_eq!(m.insert_candidates(&cands(&keys)), 202);
        assert_eq!(m.len(), 202);
        assert_eq!(m.unjournaled(), 202);
        for k in &keys {
            assert!(m.contains(k[1], k));
        }
        assert!(!m.contains(7, &key(0, 7, 255)));
        assert!(!m.contains(7, &key(1, 7, 3)), "same hash, other type");
        assert!(!m.contains(8, &key(0, 7, 3)), "another partition");
        // A second insert of held keys adds nothing.
        assert_eq!(m.insert_candidates(&cands(&keys[..5])), 0);
        assert_eq!(m.len(), 202);
        // One key at a time, then a batch: the runs keep falling, each
        // more than twice the next.
        for r in 0..=255u8 {
            m.insert_candidates(&cands(&[key(1, 7, r)]));
            assert!(runs_fall_geometrically(&m, 7), "{:?}", m.shape(7));
        }
        let batch: Vec<Key> = (0..=255u8).map(|r| key(2, 7, r)).collect();
        m.insert_candidates(&cands(&batch));
        assert!(runs_fall_geometrically(&m, 7), "{:?}", m.shape(7));
        assert_eq!(m.len(), 202 + 256 + 256);
        let all = m.all_sorted(7);
        assert_eq!(all.len(), 201 + 512);
        assert!(all.windows(2).all(|w| w[0] < w[1]));
    }

    /// Inserting n keys into one partition copies O(n log n) keys,
    /// however they are batched.  Folding a fixed-size buffer into one
    /// sorted vector, as this memtable once did, copies about n^2/128 for
    /// keys that crowd one partition: 78 million for these 100,000, where
    /// the bound below allows 6.8 million.
    #[test]
    fn crowding_one_partition_costs_n_log_n_copies() {
        let n: u32 = 100_000;
        let bound = 4 * n as usize * (n as f64).log2().ceil() as usize;
        for batch in [1usize, 7, 64, 1_000, 36_000] {
            let m = Memtable::new();
            let mut next = 0u32;
            while next < n {
                let end = n.min(next + batch as u32);
                // Interleaved values, so each batch lands among the
                // earlier keys rather than after them.
                let keys: Vec<(u8, Key)> = (next..end)
                    .map(|i| {
                        let mut k = [0u8; 21];
                        k[1] = 0;
                        k[2..6].copy_from_slice(&i.reverse_bits().to_be_bytes());
                        (0, k)
                    })
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect();
                m.insert_candidates(&keys);
                next = end;
            }
            assert_eq!(m.len(), n as usize);
            assert!(runs_fall_geometrically(&m, 0));
            assert!(
                m.copied() <= bound,
                "batches of {batch}: {} copies for {n} keys, bound {bound}",
                m.copied()
            );
        }
    }

    /// A committed flush folds every unjournaled key into the journaled
    /// vector and clears the merged partitions; exact capacity throughout.
    #[test]
    fn a_committed_flush_folds_and_clears() {
        let m = Memtable::new();
        let keys: Vec<Key> = (0..100u8)
            .flat_map(|r| [key(0, 1, r), key(2, 2, r)])
            .collect();
        for chunk in keys.chunks(9) {
            m.insert_candidates(&cands(chunk));
        }
        let mut merged = [false; PARTITIONS];
        merged[2] = true;
        m.commit_flush(&merged);
        assert_eq!(m.len(), 100);
        assert_eq!(m.unjournaled(), 0);
        assert_eq!(m.shape(1), (100, vec![]));
        assert_eq!(m.shape(2), (0, vec![]));
        assert!(m.contains(1, &key(0, 1, 50)));
        assert!(!m.contains(2, &key(2, 2, 50)));
        assert_eq!(m.spare_capacity(1), 0);
        let part = m.part(1);
        assert!(part.journaled.windows(2).all(|w| w[0] < w[1]));
    }

    /// Loading keeps the vectors given; the snapshot is sorted.
    #[test]
    fn load_and_snapshot() {
        let m = Memtable::new();
        let mut parts = vec![Vec::new(); PARTITIONS];
        parts[0] = vec![key(0, 0, 9), key(3, 0, 1)];
        parts[255] = vec![key(0, 255, 2)];
        m.load(parts);
        assert_eq!(m.len(), 3);
        assert_eq!(m.unjournaled(), 0);
        assert_eq!(
            m.snapshot(),
            vec![key(0, 0, 9), key(0, 255, 2), key(3, 0, 1)]
        );
        assert_eq!(m.shape(0), (2, vec![]));
        m.clear();
        assert_eq!(m.len(), 0);
        assert!(m.snapshot().is_empty());
    }

    /// Readers on other threads see every key throughout a fold: the
    /// write lock covers each partition's whole change.
    #[test]
    fn readers_see_every_key_while_partitions_fold() {
        let m = std::sync::Arc::new(Memtable::new());
        let keys: Vec<Key> = (0..=255u8)
            .flat_map(|p| (0..40u8).map(move |r| key(0, p, r)))
            .collect();
        m.insert_candidates(&cands(&keys));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let readers: Vec<_> = (0..4)
            .map(|t| {
                let m = std::sync::Arc::clone(&m);
                let stop = std::sync::Arc::clone(&stop);
                let keys = keys.clone();
                std::thread::spawn(move || {
                    let mut i = t;
                    while !stop.load(Ordering::SeqCst) {
                        let k = keys[i % keys.len()];
                        assert!(m.contains(k[1], &k));
                        i = i.wrapping_add(7);
                    }
                })
            })
            .collect();
        for round in 0..50u8 {
            let more: Vec<Key> = (0..=255u8).map(|p| key(1, p, round)).collect();
            m.insert_candidates(&cands(&more));
            m.commit_flush(&[false; PARTITIONS]);
        }
        stop.store(true, Ordering::SeqCst);
        for r in readers {
            r.join().expect("reader");
        }
        assert_eq!(m.len(), keys.len() + 50 * 256);
    }
}
