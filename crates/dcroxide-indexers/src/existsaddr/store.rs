// SPDX-License-Identifier: ISC
//! The index's flush participant: the memtable, the committed meta row,
//! and the work each flush does under the bucket's prefix.
//!
//! Each flush with keys to journal, inside the metadata flush's own redb
//! write transaction:
//!
//! 1. numbers itself (`jseq += 1`);
//! 2. while the memtable holds more than `k0` keys, merges the largest
//!    partition into its delta run, or into its base run once the delta
//!    would pass its cap, until the page budget is spent (or past it,
//!    while more than `k0_hard` keys are held);
//! 3. journals the keys not yet journaled of every partition it did not
//!    merge, gathered a partition at a time: a merged partition's keys are
//!    in its runs in this same commit, and need no journal row;
//! 4. marks every partition with nothing left in memory as pending from
//!    the next flush;
//! 5. removes the journal rows below the oldest pending flush;
//! 6. writes the meta row.
//!
//! A flush with nothing to journal does nothing here, merges included, so
//! a second flush in a row -- the one `Database::close` makes after the
//! node's own shutdown flush -- commits nothing.
//!
//! Nothing changes in memory until `finished(true)`, after the commit:
//! then the journaled keys are folded and the merged partitions cleared.
//! A failed flush leaves memory as it was; the store is latched by then.
//!
//! **Invariant.**  In every durable state, every key of every connect
//! whose tip row is durable is in a run of its partition, or in a journal
//! row numbered at or after its partition's `pend_from`.  The tip rows and
//! all of these rows share one `Durability::Immediate` commit, and the
//! hook that hands a connect's keys over runs after the commit's own
//! flush and before its tip row is published, so the flush that persists
//! a tip row journals that connect's keys, and no flush journals the keys
//! of a connect whose tip row it does not persist.

use std::sync::{Mutex, RwLock};

use dcroxide_database::{
    Bucket, Database, Error, FlushParticipant, FlushWriter, ParticipantStats, Transaction,
};

use super::journal::{self, JOURNAL_TAG};
use super::memtable::Memtable;
use super::meta::{META_TAG, Meta};
use super::policy::{PARTITIONS, Partitioner, Policy, merge_order, random_partition_key};
use super::runs::{self, BASE, DELTA, Filing, RUN_TAG};
use super::{Key, corrupt};

/// What one contributing flush decided, adopted by `finished(true)`.
struct Plan {
    meta: Meta,
    merged: Box<[bool; PARTITIONS]>,
}

/// The committed meta row and the plan of the flush in progress.
#[derive(Default)]
struct State {
    meta: Meta,
    plan: Option<Plan>,
}

/// Fault switches for the tests' controls, each of which a correct suite
/// must catch.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct Faults {
    /// `contribute` writes no journal rows, but memory still treats the
    /// keys as journaled.
    pub(crate) skip_journal: std::sync::atomic::AtomicBool,
    /// Lookups read the mempool overlay last instead of first.
    pub(crate) overlay_last: std::sync::atomic::AtomicBool,
    /// A connect hands its keys over after its commit has published the
    /// tip row, instead of in the commit hook.
    pub(crate) hook_after_publish: std::sync::atomic::AtomicBool,
    /// The hand-overs deferred by `hook_after_publish`.
    pub(crate) deferred: Mutex<Vec<Box<dyn FnOnce() + Send>>>,
    /// `contribute` fails after writing its rows.
    pub(crate) fail_contribute: std::sync::atomic::AtomicBool,
    /// Every `finished` outcome, in order.
    pub(crate) finished: Mutex<Vec<bool>>,
}

/// The exists-address index's in-memory state and flush participant.
///
/// Holds no database handle: the database holds this by a strong
/// reference once it is registered, and a handle here would make a cycle
/// that keeps the store open for the life of the process.
pub(crate) struct AddrStore {
    pub(crate) mem: Memtable,
    /// The partition hash, keyed by the meta row's key.  Its own lock, so
    /// a lookup never waits on the state a flush holds.
    part: RwLock<Partitioner>,
    state: Mutex<State>,
    policy: Policy,
    #[cfg(test)]
    pub(crate) faults: Faults,
}

/// What a restart reads back: the meta row, if a flush has written one,
/// and per partition the journaled keys not yet in a run, sorted.
pub(crate) struct Loaded {
    meta: Option<Meta>,
    parts: Vec<Vec<Key>>,
}

impl AddrStore {
    /// An empty store merging by `policy`.
    pub(crate) fn new(policy: Policy) -> AddrStore {
        AddrStore {
            mem: Memtable::new(),
            part: RwLock::new(Partitioner::default()),
            state: Mutex::new(State::default()),
            policy,
            #[cfg(test)]
            faults: Faults::default(),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("exists address store poisoned")
    }

    /// The partition hash every key of this store is filed under.
    pub(crate) fn partitioner(&self) -> Partitioner {
        *self.part.read().expect("partitioner lock poisoned")
    }

    /// Adopt what a restart read back.  An index no flush has written to
    /// yet gets its partition key here: the policy's, or a random one.
    pub(crate) fn install(&self, loaded: Loaded) -> Result<(), Error> {
        let meta = match loaded.meta {
            Some(meta) => meta,
            None => Meta::fresh(match self.policy.partition_key {
                Some(key) => key,
                None => random_partition_key()?,
            }),
        };
        *self.part.write().expect("partitioner lock poisoned") =
            Partitioner::new(&meta.partition_key);
        self.mem.load(loaded.parts);
        *self.state() = State { meta, plan: None };
        Ok(())
    }

    /// Forget everything: the index was dropped.
    pub(crate) fn reset(&self) {
        self.mem.clear();
        *self.state() = State::default();
    }

    /// The committed meta row, for tests.
    #[cfg(test)]
    pub(crate) fn meta(&self) -> Meta {
        self.state().meta.clone()
    }

    /// Install a new index's state, as opening one no flush has written
    /// to does, for tests that drive the store directly.
    #[cfg(test)]
    pub(crate) fn install_fresh(&self) -> Result<(), Error> {
        self.install(Loaded {
            meta: None,
            parts: Vec::new(),
        })
    }
}

/// A run-row count as the meta row stores it.
fn count(n: usize) -> Result<u32, Error> {
    u32::try_from(n).map_err(|_| corrupt(format!("a run of {n} keys does not fit the meta row")))
}

/// Check a level read inside a flush against the meta row's count.
fn check_count(level: &runs::Level, want: u32, p: u8, lvl: u8) -> Result<(), Error> {
    if level.keys.len() != want as usize {
        return Err(corrupt(format!(
            "partition {p} level {lvl} holds {} keys where the meta row records {want}",
            level.keys.len()
        )));
    }
    Ok(())
}

/// The meta row's key under `bucket`.
pub(crate) fn meta_key(bucket: &[u8]) -> Vec<u8> {
    let mut key = bucket.to_vec();
    key.push(META_TAG);
    key
}

impl FlushParticipant for AddrStore {
    fn wants_flush(&self) -> bool {
        self.mem.unjournaled() >= self.policy.u_max
    }

    /// Only keys not yet journaled make work: a memtable over `k0` with
    /// nothing new waits for the next flush that journals, so a flush
    /// straight after another, as `Database::close` makes after the
    /// node's own shutdown flush, is not a second durable commit made
    /// only to merge.  Merging is never owed: memory stays bounded by
    /// `k0_hard` plus what arrives before the next flush, and that flush
    /// has keys to journal.
    fn has_work(&self) -> bool {
        self.mem.unjournaled() > 0
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "counts bounded by the memtable's length, and floating point"
    )]
    fn contribute(&self, w: &mut FlushWriter<'_, '_>) -> Result<ParticipantStats, Error> {
        let memtable_keys = self.mem.len();
        let part = self.partitioner();
        let mut state = self.state();
        state.plan = None;
        let mut meta = state.meta.clone();
        // 1. Number this flush.
        meta.jseq = meta
            .jseq
            .checked_add(1)
            .ok_or_else(|| corrupt("the journal sequence is exhausted"))?;
        let jseq = meta.jseq;
        let next = jseq.saturating_add(1);

        // 2. Merge the largest partitions while the memtable is over its
        //    target, within the page budget.
        let sizes = self.mem.sizes();
        let mut remaining: usize = sizes.iter().sum();
        let mut merged = Box::new([false; PARTITIONS]);
        let mut pages = 0usize;
        let mut merges = 0u64;
        let mut base_rewrites = 0u64;
        for p in merge_order(&sizes) {
            if remaining <= self.policy.k0 {
                break;
            }
            if merges > 0 && pages >= self.policy.budget_pages && remaining <= self.policy.k0_hard {
                break;
            }
            let pi = usize::from(p);
            let held = self.mem.all_sorted(pi);
            let delta = runs::read_level(w, &part, p, DELTA)?;
            check_count(&delta, meta.d_keys[pi], p, DELTA)?;
            let grown = (u64::from(meta.d_keys[pi]) + held.len() as u64) as f64;
            if grown <= self.policy.dcap(p, u64::from(meta.b_keys[pi])) {
                let keys = runs::union(&delta.keys, &held);
                drop(held);
                pages += runs::write_level(w, p, DELTA, &delta, &keys)?;
                meta.d_keys[pi] = count(keys.len())?;
            } else {
                let base = runs::read_level(w, &part, p, BASE)?;
                check_count(&base, meta.b_keys[pi], p, BASE)?;
                let keys = runs::union(&runs::union(&base.keys, &delta.keys), &held);
                drop(held);
                pages += runs::write_level(w, p, BASE, &base, &keys)?;
                runs::remove_level(w, &delta)?;
                meta.d_keys[pi] = 0;
                meta.b_keys[pi] = count(keys.len())?;
                base_rewrites += 1;
            }
            merged[pi] = true;
            merges += 1;
            remaining -= sizes[pi];
        }

        // 3. Journal the keys not yet journaled of every partition left
        //    in memory, one partition's copy and one batch at a time.
        #[cfg(test)]
        let skip = self
            .faults
            .skip_journal
            .load(std::sync::atomic::Ordering::SeqCst);
        #[cfg(not(test))]
        let skip = false;
        let mut journal = journal::Appender::new(w.prefix(), jseq);
        if !skip {
            for p in 0..PARTITIONS {
                if !merged[p] && sizes[p] > 0 {
                    journal.add(w, &self.mem.unjournaled_sorted(p))?;
                }
            }
        }
        let keys_journaled = journal.finish(w)?;

        // 4. A partition with nothing left in memory has nothing pending
        //    in the journal either.
        for p in 0..PARTITIONS {
            if sizes[p] == 0 || merged[p] {
                meta.pend_from[p] = next;
            }
        }

        // 5. Every journal row below the oldest pending flush holds only
        //    keys now in runs; the rows below the last watermark are gone
        //    already.
        journal::gc(w, state.meta.min_pend_from(), meta.min_pend_from())?;

        // 6. The meta row, last.
        let bucket = w.prefix().to_vec();
        w.insert(&meta_key(&bucket), &meta.encode())?;

        #[cfg(test)]
        if self
            .faults
            .fail_contribute
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(Error {
                kind: dcroxide_database::ErrorKind::DriverSpecific,
                description: "injected contribute failure".to_string(),
            });
        }
        state.plan = Some(Plan { meta, merged });
        let mut stats = ParticipantStats::default();
        stats.keys_journaled = keys_journaled;
        stats.merges = merges;
        stats.base_rewrites = base_rewrites;
        stats.memtable_keys = memtable_keys as u64;
        Ok(stats)
    }

    fn finished(&self, committed: bool) {
        #[cfg(test)]
        self.faults
            .finished
            .lock()
            .expect("finished log")
            .push(committed);
        let mut state = self.state();
        let plan = state.plan.take();
        if !committed {
            // The store is latched; memory stays as it was, and the next
            // open decides from what is on disk.
            return;
        }
        let Some(plan) = plan else {
            debug_assert!(false, "finished(true) without a contribute");
            return;
        };
        self.mem.commit_flush(&plan.merged);
        state.meta = plan.meta;
    }
}

/// Read the meta row and the journaled keys not yet in a run: what a
/// restart puts back in the memtable.
///
/// A missing meta row means no flush has contributed, and then the bucket
/// must be empty: rows without a meta row are corruption, never an empty
/// index.  So is a row of no layout-3 shape, which is what a build from
/// before layout 3 writes if it runs with the index on over this one: it
/// has no version check, puts a bare 21-byte key row per new address and
/// moves the tip, and this build, which never reads those rows, would
/// otherwise open without them.  Their type byte (0-3) sorts them before
/// every layout-3 tag, so the bucket's first row shows whether any exist.
///
/// The journal is read twice, in one read transaction: once to count each
/// partition's pending keys, then into one vector a partition allocated
/// at that count and sorted in place.  Memory peaks at about the loaded
/// keys.  Gathering them into one vector and splitting it peaked at twice
/// that, and growing each partition's vector as it filled left up to as
/// much again in freed buffers the process heap keeps; the second read
/// costs the decoding and hashing again, and the pages, just read, are
/// in the page cache.
pub(crate) fn load(tx: &Transaction, bucket: &Bucket<'_>) -> Result<Loaded, Error> {
    let id = bucket.raw_id();
    let first = tx.try_scan_after(&id, None, 1)?.into_iter().next();
    if let Some((key, _)) = &first
        && !matches!(key.get(4), Some(&(JOURNAL_TAG | META_TAG | RUN_TAG)))
    {
        return Err(corrupt(format!(
            "the bucket holds a row of no layout-3 shape ({} first), as a build from before \
             layout 3 writes when it runs with the index on",
            runs::hex(key)
        )));
    }
    let Some(raw) = bucket.try_get(&[META_TAG])? else {
        if let Some((key, _)) = first {
            return Err(corrupt(format!(
                "the bucket holds rows ({} first) but no meta row",
                runs::hex(&key)
            )));
        }
        return Ok(Loaded {
            meta: None,
            parts: Vec::new(),
        });
    };
    let meta = Meta::decode(&raw)?;
    let part = Partitioner::new(&meta.partition_key);
    // Each pending key with its partition, for both reads.
    let pending = |each: &mut dyn FnMut(usize, Key)| {
        journal::scan(tx, &id, meta.min_pend_from(), |jseq, row| {
            if jseq > meta.jseq {
                return Err(corrupt(format!(
                    "a journal row of flush {jseq} is past the meta row's {}",
                    meta.jseq
                )));
            }
            for key in row {
                let p = usize::from(part.of(&key));
                if jseq >= meta.pend_from[p] {
                    each(p, key);
                }
            }
            Ok(())
        })
    };
    let mut counts = vec![0usize; PARTITIONS];
    pending(&mut |p, _| counts[p] = counts[p].saturating_add(1))?;
    let mut parts: Vec<Vec<Key>> = counts.iter().map(|&n| Vec::with_capacity(n)).collect();
    pending(&mut |p, key| parts[p].push(key))?;
    for (keys, &n) in parts.iter_mut().zip(&counts) {
        if keys.len() != n {
            return Err(corrupt(
                "the journal changed between two reads of one snapshot",
            ));
        }
        keys.sort_unstable();
        keys.dedup();
        if keys.len() < n {
            keys.shrink_to_fit();
        }
    }
    Ok(Loaded {
        meta: Some(meta),
        parts,
    })
}

/// Rows read per window by the whole-index walks.
const WALK_WINDOW: usize = 512;

/// Every key in the runs under `bucket`, sorted, each once.  Reads every
/// run row; for tests, the digest and the drop's checks, never a lookup.
pub(crate) fn run_keys(
    tx: &Transaction,
    part: &Partitioner,
    bucket: &[u8],
) -> Result<Vec<Key>, Error> {
    let mut prefix = bucket.to_vec();
    prefix.push(RUN_TAG);
    let mut keys = Vec::new();
    let mut after: Option<Vec<u8>> = None;
    loop {
        let rows = tx.try_scan_after(&prefix, after.as_deref(), WALK_WINDOW)?;
        let full = rows.len() == WALK_WINDOW;
        for (row_key, value) in &rows {
            keys.extend(runs::decode_chunk(part, Filing::Every, bucket, row_key, value)?.keys);
        }
        match rows.into_iter().last() {
            Some((last, _)) if full => after = Some(last),
            _ => break,
        }
    }
    keys.sort_unstable();
    keys.dedup();
    Ok(keys)
}

/// What [`check_layout`] found in a layout-3 store.
#[doc(hidden)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LayoutCheck {
    /// The meta row's journal sequence.
    pub jseq: u32,
    /// Journal rows present.
    pub journal_rows: usize,
    /// Keys in those rows, pending or not: what a restart reads.
    pub journal_keys: usize,
    /// Run chunk rows present.
    pub run_rows: usize,
    /// The keys a restart puts in the memtable: those in journal rows
    /// numbered at or after their partition's `pend_from`.  Sorted.
    pub pending: Vec<[u8; super::ADDR_KEY_SIZE]>,
    /// The keys in the runs.  Sorted, each once.
    pub runs: Vec<[u8; super::ADDR_KEY_SIZE]>,
}

/// Walk every row of a layout-3 index and check the format's invariants:
/// the meta row decodes; every row is a meta, journal or run row of the
/// right shape; the journal holds no flush below the oldest pending one
/// or past the newest, and each flush's rows are numbered from 0 without
/// gaps; every chunk decodes and holds keys of its own partition; each
/// level's chunks ascend without overlap
/// and hold the count the meta row records.  `Ok(None)` when the index has
/// no bucket.  For tests and diagnostics: it reads the whole index.
#[doc(hidden)]
pub fn check_layout(db: &Database) -> Result<Option<LayoutCheck>, crate::IdxError> {
    let tx = db.begin(false)?;
    let res = check_layout_tx(&tx);
    tx.rollback()?;
    res
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "row and key counts bounded by the store"
)]
fn check_layout_tx(tx: &Transaction) -> Result<Option<LayoutCheck>, crate::IdxError> {
    let Some(bucket) = tx
        .metadata()
        .bucket(crate::existsaddrindex::EXISTS_ADDR_INDEX_KEY)
    else {
        return Ok(None);
    };
    let id = bucket.raw_id();
    let meta = match bucket.try_get(&[META_TAG])? {
        Some(raw) => Meta::decode(&raw)?,
        None => Meta::default(),
    };
    let part = Partitioner::new(&meta.partition_key);
    let min = meta.min_pend_from();
    let mut check = LayoutCheck {
        jseq: meta.jseq,
        ..LayoutCheck::default()
    };
    let mut journal_at: Option<(u32, u32)> = None;
    let mut level_at: Option<(u8, u8, Key)> = None;
    let mut level_counts = vec![[0u64; 2]; PARTITIONS];
    let mut saw_meta = false;
    let mut after: Option<Vec<u8>> = None;
    loop {
        let rows = tx.try_scan_after(&id, after.as_deref(), WALK_WINDOW)?;
        let full = rows.len() == WALK_WINDOW;
        for (key, value) in &rows {
            match key.get(4) {
                Some(&META_TAG) if key.len() == 5 => saw_meta = true,
                Some(&journal::JOURNAL_TAG) => {
                    let (jseq, i) = journal::parse_row_key(&id, key)?;
                    if jseq < min || jseq > meta.jseq {
                        return Err(corrupt(format!(
                            "a journal row of flush {jseq} lies outside {min}..={}",
                            meta.jseq
                        ))
                        .into());
                    }
                    let want = match journal_at {
                        Some((prev, last)) if prev == jseq => last + 1,
                        _ => 0,
                    };
                    if i != want {
                        return Err(corrupt(format!(
                            "flush {jseq}'s journal rows skip from {want} to {i}"
                        ))
                        .into());
                    }
                    journal_at = Some((jseq, i));
                    check.journal_rows += 1;
                    for k in journal::decode_row(key, value)? {
                        check.journal_keys += 1;
                        if jseq >= meta.pend_from[usize::from(part.of(&k))] {
                            check.pending.push(k);
                        }
                    }
                }
                Some(&RUN_TAG) => {
                    let chunk = runs::decode_chunk(&part, Filing::Every, &id, key, value)?;
                    let first = chunk.keys[0];
                    if let Some((p, lvl, last)) = level_at
                        && p == chunk.p
                        && lvl == chunk.lvl
                        && last >= first
                    {
                        return Err(corrupt(format!(
                            "the chunks of partition {p} level {lvl} overlap"
                        ))
                        .into());
                    }
                    let last = *chunk.keys.last().expect("chunks are never empty");
                    level_at = Some((chunk.p, chunk.lvl, last));
                    level_counts[usize::from(chunk.p)][usize::from(chunk.lvl)] +=
                        chunk.keys.len() as u64;
                    check.run_rows += 1;
                    check.runs.extend(chunk.keys);
                }
                _ => {
                    return Err(
                        corrupt(format!("a row of unknown shape {}", runs::hex(key))).into(),
                    );
                }
            }
        }
        match rows.into_iter().last() {
            Some((last, _)) if full => after = Some(last),
            _ => break,
        }
    }
    if !saw_meta && (check.journal_rows > 0 || check.run_rows > 0) {
        return Err(corrupt("run or journal rows without a meta row").into());
    }
    for (p, counts) in level_counts.iter().enumerate() {
        let want = [u64::from(meta.d_keys[p]), u64::from(meta.b_keys[p])];
        if *counts != want {
            return Err(corrupt(format!(
                "partition {p} holds {counts:?} delta and base keys; the meta row records {want:?}"
            ))
            .into());
        }
    }
    check.pending.sort_unstable();
    check.pending.dedup();
    check.runs.sort_unstable();
    check.runs.dedup();
    Ok(Some(check))
}

/// Every key a stored exists-address index holds, read from the store
/// alone, in either layout: layout 2's bucket keys, or layout 3's run keys
/// plus the journaled keys a restart would load.  Sorted, each once;
/// `Ok(None)` when the index does not exist.  For the benchmark's digest
/// and the tests, which compare the two layouts' key sets; it reads the
/// whole index.
#[doc(hidden)]
pub fn stored_keys(
    db: &Database,
) -> Result<Option<Vec<[u8; super::ADDR_KEY_SIZE]>>, crate::IdxError> {
    let db_tx = db.begin(false)?;
    let version = (|| {
        let has_tip = db_tx
            .metadata()
            .bucket(crate::common::INDEX_TIPS_BUCKET_NAME)
            .is_some_and(|b| {
                b.get(crate::existsaddrindex::EXISTS_ADDR_INDEX_KEY)
                    .is_some()
            });
        if !has_tip {
            return Ok(None);
        }
        crate::common::db_fetch_indexer_version(
            &db_tx,
            crate::existsaddrindex::EXISTS_ADDR_INDEX_KEY,
        )
    })();
    let res = match version {
        Err(err) => Err(err),
        Ok(None) => Ok(None),
        Ok(Some(crate::existsaddrindex::EXISTS_ADDR_INDEX_VERSION)) => {
            check_layout_tx(&db_tx).map(|check| {
                check.map(|check| {
                    let mut keys = runs::union(&check.runs, &check.pending);
                    keys.dedup();
                    keys
                })
            })
        }
        Ok(Some(_)) => {
            let mut keys = Vec::new();
            if let Some(bucket) = db_tx
                .metadata()
                .bucket(crate::existsaddrindex::EXISTS_ADDR_INDEX_KEY)
            {
                bucket
                    .try_for_each(|k, _| {
                        let key: Key = k.try_into().map_err(|_| {
                            corrupt(format!("a layout-2 row has a {}-byte key", k.len()))
                        })?;
                        keys.push(key);
                        Ok(())
                    })
                    .map_err(crate::IdxError::from)
                    .map(|()| {
                        keys.sort_unstable();
                        Some(keys)
                    })
            } else {
                Ok(None)
            }
        }
    };
    db_tx.rollback()?;
    res
}
