// SPDX-License-Identifier: ISC
//! The memtable: every key of an indexed block that is not yet in a run.
//!
//! 256 partitions, each behind its own `RwLock`, so a lookup reads one
//! partition and never waits on the others.  Three callers change it.
//! The connect's `on_commit` hook inserts.  The flush participant's
//! `contribute` reads it and then seals what it read ([`Memtable::seal`]).
//! Its `finished` folds the sealed keys in and clears what the flush
//! merged ([`Memtable::fold_sealed`]), or puts them back
//! ([`Memtable::unseal`]).  The first two hold the database's writer
//! semaphore, so no insert lands inside a `contribute`.  `finished` need
//! not hold it, and hooks may insert between a `contribute` and its
//! `finished` or beside the `finished` itself: an insert only adds to a
//! partition's unjournaled keys, a `finished` only touches its journaled
//! and sealed ones, and each takes the partition's write lock for the
//! whole of its change.
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
//!
//! A partition also counts the changes to the keys it holds and to which
//! of them are journaled, its version.  A connect filters its keys
//! against the memtable before its hook inserts them, and each key the
//! filter keeps carries the version its partition had when it was
//! searched for.  The hook searches again only where a version has moved
//! since: an insert by another connect, a flush's fold or clear, a load.
//! A flush's seal, which sets keys apart without changing which are
//! held, does not move it.
//!
//! Sorted is by the keys' bytes.  The searches, merges and sorts of a
//! lookup, a connect and a flush compare with [`super::cmp_keys`], which
//! gives that order without a call to the C library for each comparison.
//! [`Memtable::snapshot`], which is for tests and diagnostics, sorts by
//! the array type's own comparison, the same order.

use std::sync::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::policy::PARTITIONS;
use super::{Key, cmp_keys};

/// One partition's keys.  The vectors are pairwise disjoint: a key is in
/// exactly one of `journaled`, `sealed` and `fresh`.
#[derive(Default)]
struct Part {
    /// Journaled by a committed flush, awaiting a merge.  Sorted.
    journaled: Vec<Key>,
    /// Handed to a flush that has not finished: the runs that were
    /// `fresh` when its `contribute` sealed them, which it journaled or
    /// merged.  Empty outside a flush.
    sealed: Vec<Vec<Key>>,
    /// Keys in `sealed`.
    sealed_len: usize,
    /// Not yet journaled, and in no flush: sorted runs, each more than
    /// twice as long as the next, so there are at most `log2(n) + 1` of
    /// them.
    fresh: Vec<Vec<Key>>,
    /// Keys in `fresh`.
    fresh_len: usize,
    /// Moved by every change to which keys the partition holds or to
    /// which of them are journaled: [`Part::add_run`], [`Part::replace`]
    /// and a flush's fold or clear ([`Memtable::fold_sealed`]), each under
    /// the partition's write lock.  A seal and an unseal leave it: they
    /// only move keys between `fresh` and `sealed`, and the partition
    /// holds the same keys after either.  So a search under the read lock
    /// that pairs its answer with this, and a holder of the write lock
    /// that finds this where the search left it, agree on every key:
    /// nothing was added or removed in between.  It counts up from the
    /// partition's creation and is never set back, a flush's clear and a
    /// load included, so it never returns to a value it has had.
    version: u64,
}

impl Part {
    fn contains(&self, key: &Key) -> bool {
        let holds = |keys: &[Key]| keys.binary_search_by(|held| cmp_keys(held, key)).is_ok();
        holds(&self.journaled)
            || self.sealed.iter().any(|run| holds(run))
            || self.fresh.iter().any(|run| holds(run))
    }

    fn len(&self) -> usize {
        self.journaled
            .len()
            .saturating_add(self.sealed_len)
            .saturating_add(self.fresh_len)
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
        self.version = self.version.wrapping_add(1);
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

    /// Replace the keys with `journaled`, sorted and all of them
    /// journaled, none sealed by a flush: what a load leaves.
    fn replace(&mut self, journaled: Vec<Key>) {
        self.version = self.version.wrapping_add(1);
        self.journaled = journaled;
        self.sealed = Vec::new();
        self.sealed_len = 0;
        self.fresh = Vec::new();
        self.fresh_len = 0;
    }

    /// The unjournaled keys no flush holds, sorted, in one vector.
    fn unjournaled(&self) -> Vec<Key> {
        merge_runs(&self.fresh)
    }

    /// Every key, sorted, in one vector.
    fn all(&self) -> Vec<Key> {
        let unjournaled = self.unjournaled();
        if self.sealed.is_empty() {
            return merge_sorted(&self.journaled, &unjournaled);
        }
        let sealed = merge_runs(&self.sealed);
        merge_sorted(&merge_sorted(&self.journaled, &sealed), &unjournaled)
    }
}

/// Merge sorted, pairwise disjoint runs into one sorted vector, the
/// newest and shortest first.
fn merge_runs(runs: &[Vec<Key>]) -> Vec<Key> {
    let mut runs = runs.iter().rev();
    let Some(newest) = runs.next() else {
        return Vec::new();
    };
    let mut all = newest.clone();
    for older in runs {
        all = merge_sorted(older, &all);
    }
    all
}

/// Merge two sorted, disjoint vectors into one of exact capacity.
pub(crate) fn merge_sorted(a: &[Key], b: &[Key]) -> Vec<Key> {
    let mut out = Vec::with_capacity(a.len().saturating_add(b.len()));
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() && j < b.len() {
        if cmp_keys(&a[i], &b[j]).is_le() {
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

/// A key [`Memtable::filter`] found its partition not to hold.
///
/// The order is by partition and then by the key's bytes; no two
/// candidates of one filter share both, so the version never decides it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Candidate {
    /// The key's partition.
    pub(crate) p: u8,
    /// The key.
    pub(crate) key: Key,
    /// The partition's version when it was searched for the key.
    pub(crate) seen: u64,
}

/// The keys of indexed blocks not yet merged into a run, partitioned by
/// the index's partition hash.
pub(crate) struct Memtable {
    parts: Box<[RwLock<Part>]>,
    /// Keys held, over every partition.
    len: AtomicUsize,
    /// Keys held that no flush has journaled or sealed: the `fresh` keys
    /// of every partition.
    unjournaled: AtomicUsize,
    /// Keys copied by the merges of unjournaled runs, for the test that
    /// bounds the insert cost.
    #[cfg(test)]
    copied: AtomicUsize,
    /// The tests' control: an insert searches for every key it is handed,
    /// whatever the versions say.
    #[cfg(test)]
    pub(crate) search_always: std::sync::atomic::AtomicBool,
    /// Keys inserted without a search, for the tests that must see which
    /// way an insert went.
    #[cfg(test)]
    unsearched: AtomicUsize,
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
            #[cfg(test)]
            search_always: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            unsearched: AtomicUsize::new(0),
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

    /// Keys held that are neither journaled nor sealed by a flush in
    /// progress: what the next flush has to journal.
    pub(crate) fn unjournaled(&self) -> usize {
        self.unjournaled.load(Ordering::SeqCst)
    }

    /// Whether partition `p` holds `key`, sealed keys included: a binary
    /// search of each sorted vector, under the partition's read lock.
    pub(crate) fn contains(&self, p: u8, key: &Key) -> bool {
        self.part(usize::from(p)).contains(key)
    }

    /// The keys of `keys`, each given with its partition, that the
    /// memtable does not hold, sorted by partition and key: what a connect
    /// hands to [`Self::insert_candidates`].
    ///
    /// Each key is searched for under its partition's read lock, and the
    /// version that goes with it is read under that same hold, before
    /// the search.  The one hold is what makes the pair exact: no change
    /// can fall between the two.  The order is a second defence, should
    /// the hold ever be split.  A version read first and overtaken by a
    /// change is only out of date, which costs the key a second search.
    /// A version read after the search could be the one that followed
    /// another connect's insert of this very key, and the hook would then
    /// put the key in a second time.
    pub(crate) fn filter(&self, keys: impl IntoIterator<Item = (u8, Key)>) -> Vec<Candidate> {
        let mut candidates: Vec<Candidate> = keys
            .into_iter()
            .filter_map(|(p, key)| {
                let part = self.part(usize::from(p));
                let seen = part.version;
                (!part.contains(&key)).then_some(Candidate { p, key, seen })
            })
            .collect();
        candidates.sort_unstable();
        candidates
    }

    /// Insert every key not already held; returns how many were new.
    ///
    /// `keys` must be sorted by partition (and best by key within one);
    /// each partition's lock is taken once, and its new keys go in as one
    /// run.
    ///
    /// A partition whose version is the one every key of its group was
    /// filtered at has not changed since, so it holds none of them; when
    /// the group's keys also ascend, the group is the run as it stands,
    /// and goes in without a search or a sort.  Any other group is
    /// searched for key by key and what is left sorted, each key once,
    /// which makes the same run wherever the first way applies.  The
    /// versions are compared under the partition's write lock, the lock
    /// every change to the partition is made under.
    ///
    /// A version says that only of the memtable it was read from.  So
    /// every candidate must come from a [`Self::filter`] of this very
    /// memtable, or carry a version its partition has never had, which
    /// has it searched for: a key filtered against another memtable goes
    /// in unsearched wherever the two partitions' versions happen to be
    /// equal, held here or not.
    ///
    /// Only for a holder of the database's writer semaphore, which is
    /// what keeps an insert out of a `contribute`: the participant reads
    /// the memtable there a partition at a time, relying on nothing else
    /// writing until it has sealed what it read.  After the seal an
    /// insert goes to keys the flush in progress no longer touches, so it
    /// may land before that flush's `finished` or beside it.
    pub(crate) fn insert_candidates(&self, keys: &[Candidate]) -> usize {
        debug_assert!(
            keys.windows(2).all(|w| w[0].p <= w[1].p),
            "candidates must be grouped by partition"
        );
        let mut added = 0usize;
        let mut copied = 0usize;
        #[cfg(test)]
        let mut unsearched = 0usize;
        let mut rest = keys;
        while let Some(&Candidate { p, .. }) = rest.first() {
            let end = rest.partition_point(|c| c.p == p);
            let (group, tail) = rest.split_at(end);
            rest = tail;
            let mut part = self.part_mut(usize::from(p));
            let stands = group.iter().all(|c| c.seen == part.version)
                && group
                    .windows(2)
                    .all(|w| cmp_keys(&w[0].key, &w[1].key).is_lt());
            #[cfg(test)]
            let stands = stands && !self.search_always.load(Ordering::SeqCst);
            let run: Vec<Key> = if stands {
                debug_assert!(
                    group.iter().all(|c| !part.contains(&c.key)),
                    "partition {p} holds a key its version says it does not"
                );
                #[cfg(test)]
                {
                    unsearched = unsearched.saturating_add(group.len());
                }
                group.iter().map(|c| c.key).collect()
            } else {
                let mut run: Vec<Key> = group
                    .iter()
                    .map(|c| c.key)
                    .filter(|key| !part.contains(key))
                    .collect();
                run.sort_unstable_by(cmp_keys);
                run.dedup();
                run
            };
            if run.is_empty() {
                continue;
            }
            added = added.saturating_add(run.len());
            copied = copied.saturating_add(part.add_run(run));
        }
        #[cfg(test)]
        {
            self.copied.fetch_add(copied, Ordering::SeqCst);
            self.unsearched.fetch_add(unsearched, Ordering::SeqCst);
        }
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

    /// Partition `p`'s unjournaled keys that no flush has sealed, sorted.
    pub(crate) fn unjournaled_sorted(&self, p: usize) -> Vec<Key> {
        self.part(p).unjournaled()
    }

    /// Every key of partition `p`, sealed keys included, sorted.
    pub(crate) fn all_sorted(&self, p: usize) -> Vec<Key> {
        self.part(p).all()
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

    /// Seal every unjournaled key: a flush has journaled or merged each
    /// of them in a transaction that has yet to commit.
    ///
    /// The keys stay held and found, apart from the ones later inserts
    /// add, so the flush's `finished` can tell the two apart however
    /// many inserts land before it.  The runs are moved, not copied.
    /// Nothing is counted as unjournaled afterwards: the next flush owes
    /// only what arrives from here on.
    ///
    /// Only for a holder of the database's writer semaphore, as an insert
    /// is, so the count is not zeroed over an insert in progress.
    pub(crate) fn seal(&self) {
        for p in 0..PARTITIONS {
            let mut part = self.part_mut(p);
            if part.fresh_len == 0 {
                continue;
            }
            let part = &mut *part;
            part.sealed.append(&mut part.fresh);
            part.sealed_len = part.sealed_len.saturating_add(part.fresh_len);
            part.fresh_len = 0;
        }
        self.unjournaled.store(0, Ordering::SeqCst);
    }

    /// Apply a committed flush to the keys it sealed: those of a
    /// partition it merged leave memory with the partition's journaled
    /// keys, all of them now in its runs, and those of any other
    /// partition join its journaled keys.
    ///
    /// Keys inserted since the seal are left as they are, held and
    /// counted as unjournaled: no flush has written them.
    ///
    /// Each partition is changed under its own write lock, after the
    /// flush's commit, so a lookup that misses a merged partition's keys
    /// here begins its read transaction afterwards and finds them in the
    /// runs that commit wrote.
    pub(crate) fn fold_sealed(&self, merged: &[bool; PARTITIONS]) {
        let mut removed = 0usize;
        for (p, &was_merged) in merged.iter().enumerate() {
            let mut part = self.part_mut(p);
            if was_merged {
                removed = removed
                    .saturating_add(part.journaled.len())
                    .saturating_add(part.sealed_len);
                part.journaled = Vec::new();
            } else if part.sealed_len > 0 {
                let sealed = merge_runs(&part.sealed);
                part.journaled = merge_sorted(&part.journaled, &sealed);
            }
            // The partition's keys or its journaled ones changed: a
            // candidate filtered before this is searched for again.
            if was_merged || part.sealed_len > 0 {
                part.version = part.version.wrapping_add(1);
            }
            part.sealed = Vec::new();
            part.sealed_len = 0;
        }
        self.len.fetch_sub(removed, Ordering::SeqCst);
    }

    /// Undo [`Self::seal`] for a flush that failed: the sealed keys are
    /// unjournaled again, with whatever was inserted since.
    ///
    /// A partition nothing was inserted into gets its runs back as they
    /// were; in any other the sealed and the newer keys become one run,
    /// which keeps the runs' lengths falling.
    pub(crate) fn unseal(&self) {
        let mut restored = 0usize;
        for p in 0..PARTITIONS {
            let mut part = self.part_mut(p);
            if part.sealed_len == 0 {
                continue;
            }
            let part = &mut *part;
            restored = restored.saturating_add(part.sealed_len);
            if part.fresh.is_empty() {
                part.fresh = std::mem::take(&mut part.sealed);
            } else {
                let sealed = merge_runs(&part.sealed);
                let fresh = merge_runs(&part.fresh);
                part.fresh = vec![merge_sorted(&sealed, &fresh)];
                part.sealed = Vec::new();
            }
            part.fresh_len = part.fresh_len.saturating_add(part.sealed_len);
            part.sealed_len = 0;
        }
        self.unjournaled.fetch_add(restored, Ordering::SeqCst);
    }

    /// A committed flush with nothing inserted between its seal and its
    /// end: every unjournaled key is now journaled, and the partitions it
    /// merged are empty, their keys in runs.  For the tests, which pin
    /// that the two steps together are what one step used to be.
    #[cfg(test)]
    pub(crate) fn commit_flush(&self, merged: &[bool; PARTITIONS]) {
        self.seal();
        self.fold_sealed(merged);
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
            self.part_mut(p).replace(journaled);
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

    /// Partition `p`'s sealed runs' lengths, for tests.
    #[cfg(test)]
    pub(crate) fn sealed_shape(&self, p: usize) -> Vec<usize> {
        self.part(p).sealed.iter().map(Vec::len).collect()
    }

    /// Keys copied by unjournaled-run merges so far, for tests.
    #[cfg(test)]
    pub(crate) fn copied(&self) -> usize {
        self.copied.load(Ordering::SeqCst)
    }

    /// Keys inserted without a search so far, for tests.
    #[cfg(test)]
    pub(crate) fn unsearched(&self) -> usize {
        self.unsearched.load(Ordering::SeqCst)
    }

    /// Partition `p`'s version, for tests.
    #[cfg(test)]
    pub(crate) fn version(&self, p: usize) -> u64 {
        self.part(p).version
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
    use std::collections::BTreeSet;

    use dcroxide_testutil::SplitMix64;

    use super::*;

    fn key(t: u8, p: u8, rest: u8) -> Key {
        let mut k = [rest; 21];
        k[0] = t;
        k[1] = p;
        k
    }

    /// What a connect's filter keeps of `keys`, under the partition the
    /// tests file them under: the key's second byte.
    fn filtered(m: &Memtable, keys: &[Key]) -> Vec<Candidate> {
        m.filter(keys.iter().map(|k| (k[1], *k)))
    }

    /// Filter `keys` and insert what the filter kept, as a connect does
    /// when nothing comes between the two; returns how many were new.
    fn insert(m: &Memtable, keys: &[Key]) -> usize {
        m.insert_candidates(&filtered(m, keys))
    }

    /// `keys` as a filter would hand them had it kept them all at a
    /// version no partition has: the insert searches for every one.
    fn stale(keys: &[Key]) -> Vec<Candidate> {
        let mut c: Vec<Candidate> = keys
            .iter()
            .map(|k| Candidate {
                p: k[1],
                key: *k,
                seen: u64::MAX,
            })
            .collect();
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
        assert_eq!(insert(&m, &keys), 202);
        assert_eq!(m.len(), 202);
        assert_eq!(m.unjournaled(), 202);
        for k in &keys {
            assert!(m.contains(k[1], k));
        }
        assert!(!m.contains(7, &key(0, 7, 255)));
        assert!(!m.contains(7, &key(1, 7, 3)), "same hash, other type");
        assert!(!m.contains(8, &key(0, 7, 3)), "another partition");
        // A second insert of held keys adds nothing, and one of held and
        // new keys adds the new.
        assert_eq!(m.insert_candidates(&stale(&keys[..5])), 0);
        assert_eq!(m.len(), 202);
        let mixed = [keys[0], key(3, 7, 0), keys[1], key(3, 9, 2), keys[201]];
        assert_eq!(m.insert_candidates(&stale(&mixed)), 2);
        assert_eq!(m.len(), 204);
        assert_eq!(m.unjournaled(), 204);
        // One key at a time, then a batch: the runs keep falling, each
        // more than twice the next.
        for r in 0..=255u8 {
            insert(&m, &[key(1, 7, r)]);
            assert!(runs_fall_geometrically(&m, 7), "{:?}", m.shape(7));
        }
        let batch: Vec<Key> = (0..=255u8).map(|r| key(2, 7, r)).collect();
        insert(&m, &batch);
        assert!(runs_fall_geometrically(&m, 7), "{:?}", m.shape(7));
        assert_eq!(m.len(), 204 + 256 + 256);
        let all = m.all_sorted(7);
        assert_eq!(all.len(), 202 + 512);
        assert!(all.windows(2).all(|w| w[0] < w[1]));
    }

    /// A partition's keys need not arrive in order, or each once: the
    /// insert sorts the run they go in as and drops a repeat, and every
    /// later search and merge rests on that.  A connect hands its keys
    /// sorted, so no other test shows the sort.  Each batch here is
    /// filtered just before it is handed, so its versions stand, and it
    /// is the keys' order alone that has the insert sort them.
    #[test]
    fn a_partitions_keys_are_sorted_however_they_are_handed() {
        let m = Memtable::new();
        let ascending: Vec<Key> = (0..4u8)
            .flat_map(|t| (0..60u8).map(move |r| key(t, 9, r)))
            .collect();
        assert!(ascending.windows(2).all(|w| w[0] < w[1]));
        // Every other key, last first; then the rest, last first and the
        // lowest of them twice, which merges with the run the first batch
        // left.
        for batch in [0usize, 1] {
            let keys: Vec<Key> = ascending
                .iter()
                .copied()
                .filter(|k| usize::from(k[2]) % 2 == batch)
                .collect();
            let mut handed = filtered(&m, &keys);
            assert_eq!(handed.len(), keys.len());
            handed.reverse();
            if batch == 1 {
                handed.push(*handed.last().expect("keys"));
            }
            assert_eq!(m.insert_candidates(&handed), keys.len());
        }
        assert_eq!(m.unsearched(), 0, "keys out of order went in unsorted");
        assert_eq!(m.all_sorted(9), ascending);
        assert_eq!(m.len(), ascending.len());
        for k in &ascending {
            assert!(m.contains(9, k));
        }
        assert!(!m.contains(9, &key(0, 9, 60)));
        assert_eq!(m.insert_candidates(&stale(&ascending)), 0);
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
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                m.insert_candidates(&m.filter(keys));
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
            insert(&m, chunk);
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

    /// A seal sets the unjournaled keys apart without losing sight of
    /// them, and a committed flush then changes only what it sealed: keys
    /// inserted between the two stay, counted and found.
    #[test]
    fn a_fold_leaves_keys_inserted_since_the_seal() {
        let m = Memtable::new();
        // Partition 1 will be merged by the flush, partition 2 journaled.
        let first: Vec<Key> = (0..40u8)
            .flat_map(|r| [key(0, 1, r), key(0, 2, r)])
            .collect();
        for chunk in first.chunks(7) {
            insert(&m, chunk);
        }
        // An earlier flush journaled these, in both partitions.
        m.commit_flush(&[false; PARTITIONS]);
        let second: Vec<Key> = (0..30u8)
            .flat_map(|r| [key(1, 1, r), key(1, 2, r)])
            .collect();
        insert(&m, &second);
        assert_eq!((m.len(), m.unjournaled()), (140, 60));

        m.seal();
        // Nothing is owed to the next flush, and nothing left memory.
        assert_eq!((m.len(), m.unjournaled()), (140, 0));
        assert_eq!(m.shape(1), (40, vec![]));
        assert_eq!(m.sealed_shape(1), vec![30]);
        assert!(m.unjournaled_sorted(1).is_empty());
        assert_eq!(m.sizes()[1], 70);
        assert_eq!(m.all_sorted(1).len(), 70);
        assert_eq!(m.snapshot().len(), 140);
        for k in first.iter().chain(&second) {
            assert!(m.contains(k[1], k), "a sealed or journaled key is held");
        }

        // What a hook hands over while the flush's commit is under way:
        // new keys in both partitions, and keys the flush already holds,
        // which are skipped.
        let third: Vec<Key> = (0..10u8)
            .flat_map(|r| [key(2, 1, r), key(2, 2, r)])
            .collect();
        let mut handed = third.clone();
        handed.extend_from_slice(&second[..8]);
        handed.extend_from_slice(&first[..8]);
        assert_eq!(m.insert_candidates(&stale(&handed)), 20);
        assert_eq!((m.len(), m.unjournaled()), (160, 20));
        assert_eq!(m.unjournaled_sorted(1).len(), 10);
        assert_eq!(m.all_sorted(1).len(), 80);
        assert!(m.all_sorted(1).windows(2).all(|w| w[0] < w[1]));

        let mut merged = [false; PARTITIONS];
        merged[1] = true;
        m.fold_sealed(&merged);
        // Partition 1 lost its journaled and sealed keys and kept the
        // ten inserted since; partition 2 journaled its sealed keys and
        // kept its ten.  All twenty are still owed to the next flush.
        assert_eq!((m.len(), m.unjournaled()), (90, 20));
        assert_eq!(m.shape(1), (0, vec![10]));
        assert_eq!(m.shape(2), (70, vec![10]));
        assert!(m.sealed_shape(1).is_empty() && m.sealed_shape(2).is_empty());
        assert_eq!(m.spare_capacity(2), 0);
        for k in &third {
            assert!(m.contains(k[1], k), "a key inserted since the seal");
        }
        assert!(!m.contains(1, &first[0]) && !m.contains(1, &second[0]));
        assert!(m.contains(2, &first[1]) && m.contains(2, &second[1]));
        assert_eq!(
            m.unjournaled_sorted(1),
            third
                .iter()
                .copied()
                .filter(|k| k[1] == 1)
                .collect::<Vec<Key>>()
        );
        let mut want: Vec<Key> = first
            .iter()
            .chain(&second)
            .copied()
            .filter(|k| k[1] == 2)
            .chain(third.iter().copied())
            .collect();
        want.sort_unstable();
        assert_eq!(m.snapshot(), want);

        // The next flush seals and folds those twenty like any others.
        m.commit_flush(&[false; PARTITIONS]);
        assert_eq!((m.len(), m.unjournaled()), (90, 0));
        assert_eq!(m.shape(1), (10, vec![]));
        assert_eq!(m.shape(2), (80, vec![]));
    }

    /// A failed flush unseals: every key is unjournaled again, whether or
    /// not anything was inserted since the seal, and the runs still fall.
    #[test]
    fn an_unseal_puts_the_sealed_keys_back() {
        let m = Memtable::new();
        let journaled: Vec<Key> = (0..20u8).map(|r| key(0, 3, r)).collect();
        insert(&m, &journaled);
        m.commit_flush(&[false; PARTITIONS]);
        let sealed: Vec<Key> = (0..50u8)
            .flat_map(|r| [key(1, 3, r), key(1, 4, r)])
            .collect();
        for chunk in sealed.chunks(6) {
            insert(&m, chunk);
        }
        let before = m.snapshot();
        let runs_before = m.shape(4);
        assert_eq!((m.len(), m.unjournaled()), (120, 100));

        m.seal();
        // Into partition 3 only, so partition 4 gets its runs back as
        // they were.
        let late: Vec<Key> = (0..5u8).map(|r| key(2, 3, r)).collect();
        assert_eq!(insert(&m, &late), 5);
        assert_eq!((m.len(), m.unjournaled()), (125, 5));

        m.unseal();
        assert_eq!((m.len(), m.unjournaled()), (125, 105));
        assert_eq!(m.shape(3), (20, vec![55]), "one run of both");
        assert_eq!(m.shape(4), runs_before);
        assert!(m.sealed_shape(3).is_empty() && m.sealed_shape(4).is_empty());
        assert!(runs_fall_geometrically(&m, 3) && runs_fall_geometrically(&m, 4));
        assert_eq!(m.unjournaled_sorted(3).len(), 55);
        assert!(m.unjournaled_sorted(3).windows(2).all(|w| w[0] < w[1]));
        let mut want = before;
        want.extend_from_slice(&late);
        want.sort_unstable();
        assert_eq!(m.snapshot(), want);
        for k in journaled.iter().chain(&sealed).chain(&late) {
            assert!(m.contains(k[1], k));
        }

        // With nothing sealed it changes nothing.
        m.unseal();
        assert_eq!((m.len(), m.unjournaled()), (125, 105));
        assert_eq!(m.shape(3), (20, vec![55]));
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
        insert(&m, &keys);
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
            insert(&m, &more);
            m.commit_flush(&[false; PARTITIONS]);
        }
        stop.store(true, Ordering::SeqCst);
        for r in readers {
            r.join().expect("reader");
        }
        assert_eq!(m.len(), keys.len() + 50 * 256);
    }

    /// Every change to a partition's vectors moves its version and no
    /// other's, what changes nothing leaves it, and nothing sets it back:
    /// a cleared or reloaded partition counts on from where it was.
    #[test]
    fn a_version_moves_with_every_change_to_its_partition_and_never_back() {
        let m = Memtable::new();
        let versions = |m: &Memtable| [m.version(3), m.version(5)];
        assert_eq!(versions(&m), [0, 0]);
        // An insert that adds keys, and one that adds none.
        assert_eq!(insert(&m, &[key(0, 3, 1), key(0, 3, 2), key(0, 3, 3)]), 3);
        assert_eq!(versions(&m), [1, 0]);
        assert_eq!(m.insert_candidates(&stale(&[key(0, 3, 1)])), 0);
        assert_eq!(versions(&m), [1, 0]);
        // An insert into a partition that has a run already: one whose
        // run stays beside the first, and one whose run merges with both.
        assert_eq!(insert(&m, &[key(0, 3, 4)]), 1);
        assert_eq!((m.shape(3), versions(&m)), ((0, vec![3, 1]), [2, 0]));
        assert_eq!(insert(&m, &[key(0, 3, 5)]), 1);
        assert_eq!((m.shape(3), versions(&m)), ((0, vec![5]), [3, 0]));
        // A flush folds 3's unjournaled keys; the next finds none to fold.
        m.commit_flush(&[false; PARTITIONS]);
        assert_eq!((m.shape(3), versions(&m)), ((5, vec![]), [4, 0]));
        m.commit_flush(&[false; PARTITIONS]);
        assert_eq!(versions(&m), [4, 0]);
        // A flush clears the partition it merged.
        let mut merged = [false; PARTITIONS];
        merged[3] = true;
        m.commit_flush(&merged);
        assert_eq!(m.len(), 0);
        assert_eq!(versions(&m), [5, 0]);
        // A load and a clear replace every partition.
        let mut parts = vec![Vec::new(); PARTITIONS];
        parts[3] = vec![key(0, 3, 1)];
        m.load(parts);
        assert_eq!(versions(&m), [6, 1]);
        m.clear();
        assert_eq!(versions(&m), [7, 2]);
    }

    /// A filter's keys go in without a search while their partition is as
    /// the filter saw it, and are searched for once anything has changed
    /// it.  A change to one partition leaves another's keys unsearched.
    #[test]
    fn an_insert_searches_only_the_partitions_changed_since_its_filter() {
        // Partitions 3 and 5 hold a journaled key each, and the filter
        // keeps two keys for 3 and one for 5.  Returns how many keys the
        // insert added and how many of them it did not search for.
        let kept = [key(0, 3, 7), key(0, 3, 8), key(0, 5, 7)];
        let run = |change: &dyn Fn(&Memtable)| {
            let m = Memtable::new();
            assert_eq!(insert(&m, &[key(0, 3, 1), key(0, 5, 1)]), 2);
            m.commit_flush(&[false; PARTITIONS]);
            let filter = filtered(&m, &kept);
            assert_eq!(filter.len(), 3);
            change(&m);
            let before = m.unsearched();
            let added = m.insert_candidates(&filter);
            let held = m.snapshot();
            assert!(held.windows(2).all(|w| w[0] < w[1]), "a key twice");
            assert!(kept.iter().all(|k| m.contains(k[1], k)));
            (added, m.unsearched() - before)
        };
        // Nothing in between.
        assert_eq!(run(&|_| ()), (3, 3));
        // Another insert hands 3 one of the filter's keys and one more:
        // 3 is searched and the key skipped.
        let theirs = [key(0, 3, 7), key(1, 3, 0)];
        assert_eq!(run(&|m| assert_eq!(insert(m, &theirs), 2)), (2, 1));
        // An insert that adds nothing to 3, and a flush that finds
        // nothing to fold, leave both as the filter saw them.
        let held = stale(&[key(0, 3, 1)]);
        assert_eq!(run(&|m| assert_eq!(m.insert_candidates(&held), 0)), (3, 3));
        assert_eq!(run(&|m| m.commit_flush(&[false; PARTITIONS])), (3, 3));
        // A flush that merged 3 cleared it.
        let mut merged = [false; PARTITIONS];
        merged[3] = true;
        assert_eq!(run(&|m| m.commit_flush(&merged)), (3, 1));
        // A load replaces every partition, and brings 3 one of the keys.
        let mut parts = vec![Vec::new(); PARTITIONS];
        parts[3] = vec![key(0, 3, 8)];
        assert_eq!(run(&|m| m.load(parts.clone())), (2, 0));
    }

    /// A flush's seal moves no version: it sets keys apart and changes
    /// neither which keys are held nor which are journaled, so a filter
    /// made before it still stands after it, and its keys go in without
    /// a search, as a connect's do when its hook runs while that flush's
    /// commit is under way.  Nor does an unseal.  The fold that ends the
    /// flush moves the version of each partition whose sealed keys it
    /// journaled or cleared, and of no other.
    #[test]
    fn a_seal_leaves_a_filter_standing_and_the_fold_after_it_does_not() {
        let m = Memtable::new();
        assert_eq!(insert(&m, &[key(0, 3, 1), key(0, 5, 1)]), 2);
        // An insert of a filter's keys: how many went in, and how many of
        // them without a search.
        let go_in = |m: &Memtable, filter: &[Candidate]| {
            let before = m.unsearched();
            let added = m.insert_candidates(filter);
            (added, m.unsearched() - before)
        };

        let filter = filtered(&m, &[key(1, 3, 1), key(1, 5, 1)]);
        m.seal();
        assert_eq!(go_in(&m, &filter), (2, 2), "the seal moved a version");
        let filter = filtered(&m, &[key(2, 3, 1), key(2, 5, 1)]);
        m.unseal();
        assert_eq!(go_in(&m, &filter), (2, 2), "the unseal moved a version");
        assert_eq!((m.len(), m.unjournaled()), (6, 6));

        // Sealed again, and folded with partition 3 merged and 5 not: a
        // filter made between the two is searched for in both, and in 7,
        // which the flush did not touch, it stands.
        m.seal();
        let filter = filtered(&m, &[key(3, 3, 1), key(3, 5, 1), key(3, 7, 1)]);
        let mut merged = [false; PARTITIONS];
        merged[3] = true;
        m.fold_sealed(&merged);
        assert_eq!(go_in(&m, &filter), (3, 1));
        assert_eq!(m.shape(3), (0, vec![1]));
        assert_eq!(m.shape(5), (3, vec![1]));
        // A filter made after the fold stands.
        let filter = filtered(&m, &[key(4, 3, 1), key(4, 5, 1)]);
        assert_eq!(go_in(&m, &filter), (2, 2));
    }

    /// Connects on several threads filter with no lock held and insert
    /// one at a time, as connects that each hold the database's writer
    /// for their hook do, with flushes among them: no key is ever held
    /// twice.  Their keys overlap, so a key one thread found missing is
    /// often inserted by another before the first hands it over, and the
    /// first must then search for it.  It does, because the version its
    /// filter recorded was read no later than the search was made.  A
    /// filter that read the version under a second hold of the lock,
    /// after its search, hands such a key over with the version that
    /// followed the other thread's insert, and the key goes in again.
    ///
    /// A race, and a one-sided one: correct code passes however the
    /// threads interleave, and that filter is caught only when an insert
    /// falls between its two holds, which it does readily where two
    /// threads run at once.  The mutex stands for the writer.
    #[test]
    fn filters_that_race_inserts_leave_no_key_twice() {
        const THREADS: u64 = 4;
        const ROUNDS: u32 = 30_000;
        let m = std::sync::Arc::new(Memtable::new());
        let writer = std::sync::Arc::new(std::sync::Mutex::new(()));
        let threads: Vec<_> = (0..THREADS)
            .map(|t| {
                let m = std::sync::Arc::clone(&m);
                let writer = std::sync::Arc::clone(&writer);
                std::thread::spawn(move || {
                    let mut rng = SplitMix64(0x6d65_6d74_6162_0002 + t);
                    for round in 0..ROUNDS {
                        let keys: BTreeSet<Key> = (0..1 + rng.below(6))
                            .map(|_| key(0, 0, rng.below(48) as u8))
                            .collect();
                        let keys: Vec<Key> = keys.into_iter().collect();
                        let kept = filtered(&m, &keys);
                        let _writer = writer.lock().expect("writer");
                        m.insert_candidates(&kept);
                        let all = m.all_sorted(0);
                        assert!(
                            all.windows(2).all(|w| w[0] < w[1]),
                            "thread {t}, round {round}: a key twice"
                        );
                        assert_eq!(m.len(), all.len());
                        // A flush now and then, which half the time
                        // merges the partition and so empties it.
                        if rng.below(24) == 0 {
                            let mut merged = [false; PARTITIONS];
                            merged[0] = rng.below(2) == 0;
                            m.commit_flush(&merged);
                        }
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("no key twice");
        }
    }

    /// Two memtables taken through the same random filters, inserts,
    /// flushes and loads hold the same vectors after every step, and both
    /// agree with a model that keeps sets.  One trusts its versions.  The
    /// other searches for every key at every insert, which is what an
    /// insert did when a partition had no version.
    ///
    /// The filters wait, several at a time, and go in in any order, so
    /// inserts, flushes and loads fall between a filter and its insert.
    /// The keys come from four partitions and eighty values each, so the
    /// waiting filters share keys, and what one inserts another must
    /// skip.  Two waiting filters are sometimes handed as one, whose
    /// groups then hold keys filtered at different versions, or a key
    /// twice.
    #[test]
    fn random_interleavings_leave_what_a_search_for_every_key_leaves() {
        const PARTS: [u8; 4] = [0, 1, 7, 255];
        let mut rng = SplitMix64(0x6d65_6d74_6162_0001);
        let trusting = Memtable::new();
        let searching = Memtable::new();
        searching.search_always.store(true, Ordering::SeqCst);
        let tables = [&trusting, &searching];
        // Per partition, the journaled keys and the unjournaled ones.
        let mut model: Vec<[BTreeSet<Key>; 2]> = vec![Default::default(); PARTITIONS];
        // The filters not yet inserted, as each table returned them.
        let mut waiting: Vec<[Vec<Candidate>; 2]> = Vec::new();
        let (mut handed, mut added) = (0usize, 0usize);
        let (mut joined, mut flushes, mut loads) = (0usize, 0usize, 0usize);
        for step in 0..40_000u32 {
            match rng.below(16) {
                0..=5 => {
                    let keys: BTreeSet<Key> = (0..1 + rng.below(8))
                        .map(|_| {
                            let p = PARTS[rng.below(4) as usize];
                            key(rng.below(2) as u8, p, rng.below(40) as u8)
                        })
                        .collect();
                    let keys: Vec<Key> = keys.into_iter().collect();
                    waiting.push(tables.map(|m| filtered(m, &keys)));
                }
                6..=11 if !waiting.is_empty() => {
                    let filter = waiting.swap_remove(rng.below(waiting.len() as u64) as usize);
                    let mut want = 0usize;
                    for c in &filter[0] {
                        let [journaled, unjournaled] = &mut model[usize::from(c.p)];
                        if !journaled.contains(&c.key) && unjournaled.insert(c.key) {
                            want += 1;
                        }
                    }
                    let got = [0, 1].map(|t| tables[t].insert_candidates(&filter[t]));
                    assert_eq!(got, [want, want], "step {step}");
                    handed += filter[0].len();
                    added += want;
                }
                12 if waiting.len() >= 2 => {
                    let [a0, a1] = waiting.swap_remove(rng.below(waiting.len() as u64) as usize);
                    let [b0, b1] = waiting.swap_remove(rng.below(waiting.len() as u64) as usize);
                    let join = |mut a: Vec<Candidate>, b: Vec<Candidate>| {
                        a.extend(b);
                        a.sort_unstable();
                        a
                    };
                    waiting.push([join(a0, b0), join(a1, b1)]);
                    joined += 1;
                }
                13 | 14 => {
                    let mut merged = [false; PARTITIONS];
                    for p in PARTS {
                        merged[usize::from(p)] = rng.below(3) == 0;
                    }
                    for m in tables {
                        m.commit_flush(&merged);
                    }
                    for (p, [journaled, unjournaled]) in model.iter_mut().enumerate() {
                        if merged[p] {
                            journaled.clear();
                            unjournaled.clear();
                        } else {
                            journaled.append(unjournaled);
                        }
                    }
                    flushes += 1;
                }
                15 => {
                    // Most of what each partition held and a few keys it
                    // may not have, all of them journaled.
                    let mut parts = vec![Vec::new(); PARTITIONS];
                    for p in PARTS {
                        let [journaled, unjournaled] = &mut model[usize::from(p)];
                        let mut keys: BTreeSet<Key> = journaled
                            .union(unjournaled)
                            .copied()
                            .filter(|_| rng.below(4) != 0)
                            .collect();
                        for _ in 0..rng.below(4) {
                            keys.insert(key(rng.below(2) as u8, p, rng.below(40) as u8));
                        }
                        parts[usize::from(p)] = keys.iter().copied().collect();
                        *journaled = keys;
                        unjournaled.clear();
                    }
                    for m in tables {
                        m.load(parts.clone());
                    }
                    loads += 1;
                }
                _ => {}
            }
            let mut held = 0usize;
            let mut fresh_held = 0usize;
            for p in PARTS.map(usize::from) {
                let [journaled, unjournaled] = &model[p];
                let all: Vec<Key> = journaled.union(unjournaled).copied().collect();
                let fresh: Vec<Key> = unjournaled.iter().copied().collect();
                for m in tables {
                    assert_eq!(m.all_sorted(p), all, "step {step}, partition {p}");
                    assert_eq!(m.unjournaled_sorted(p), fresh, "step {step}, partition {p}");
                }
                assert_eq!(
                    (trusting.shape(p), trusting.version(p)),
                    (searching.shape(p), searching.version(p)),
                    "step {step}, partition {p}"
                );
                held += all.len();
                fresh_held += fresh.len();
            }
            for m in tables {
                assert_eq!((m.len(), m.unjournaled()), (held, fresh_held));
            }
        }
        // Both ways of inserting ran in the one table and only the search
        // in the other; the search was needed, for the keys handed over
        // that were held by then; and every kind of step ran.
        assert_eq!(searching.unsearched(), 0);
        let unsearched = trusting.unsearched();
        assert!(unsearched > 10_000, "{unsearched} keys went in unsearched");
        assert!(handed - unsearched > 30_000, "{handed} handed");
        assert!(
            handed - added > 2_000,
            "{} held keys handed",
            handed - added
        );
        assert!(joined > 1_000 && flushes > 4_000 && loads > 2_000);
    }

    /// A flush's fold on one thread and inserts on another, as when the
    /// flush's commit ends while later connects hand their keys over:
    /// readers see every key throughout, none is lost and the counts
    /// come out exact.
    #[test]
    fn inserts_beside_a_fold_lose_nothing() {
        let m = std::sync::Arc::new(Memtable::new());
        let mut held: Vec<Key> = Vec::new();
        for round in 0..40u8 {
            let sealed: Vec<Key> = (0..=255u8).map(|p| key(0, p, round)).collect();
            insert(&m, &sealed);
            m.seal();
            held.extend_from_slice(&sealed);
            let late: Vec<Key> = (0..=255u8).map(|p| key(1, p, round)).collect();
            let folder = {
                let m = std::sync::Arc::clone(&m);
                std::thread::spawn(move || m.fold_sealed(&[false; PARTITIONS]))
            };
            // One partition at a time, so the two interleave.
            for k in &late {
                assert_eq!(insert(&m, &[*k]), 1);
                assert!(m.contains(k[1], k));
            }
            folder.join().expect("fold");
            held.extend_from_slice(&late);
            for k in &held[held.len() - 512..] {
                assert!(m.contains(k[1], k));
            }
            assert_eq!(m.len(), held.len());
            assert_eq!(m.unjournaled(), 256, "what was inserted since the seal");
            // The next round's seal takes them.
            m.seal();
            m.fold_sealed(&[false; PARTITIONS]);
            assert_eq!(m.unjournaled(), 0);
        }
        held.sort_unstable();
        assert_eq!(m.snapshot(), held);
    }
}
