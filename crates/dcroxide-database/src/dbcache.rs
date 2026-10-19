// SPDX-License-Identifier: ISC
//! The metadata write cache (dcrd ffldb `dbcache.go`): committed
//! metadata accumulates in memory and reaches the durable key/value
//! store only when the cache flushes — after enough time or size, on
//! an explicit flush, and on close.  The flush syncs the flat block
//! files *before* committing the metadata so the metadata can never
//! describe blocks whose bytes did not survive a crash; between
//! flushes a crash simply loses the cached window (the chain re-syncs
//! it), exactly dcrd's behavior.
//!
//! dcrd snapshots an immutable treap, so a reader's snapshot is O(1)
//! and shares structure with the writer.  This port reaches the same
//! property with layered snapshots instead: the overlay is an ordered
//! stack of immutable [`CacheLayer`] maps, newest first, and a
//! snapshot is a clone of the (short) list of layer handles.  A
//! commit writes into the newest layer in place while this cache is
//! that layer's only owner; the moment a reader holds a snapshot
//! naming it, the layer is frozen and the commit starts a fresh layer
//! on top.  The newest layer folds into the next older one at the
//! first commit that finds no snapshot naming that one any more, so a
//! layer a short reader split off costs about the rows committed while
//! the reader held it, and the stack is back to one layer, above any
//! layers a flush in flight captured, as soon as no reader overlaps a
//! commit.  While readers keep a layer frozen, layers are merged back
//! together geometrically — the newest layer merges into the next older
//! one once it has grown to half that layer's entry count — which keeps
//! the stack shallow (typically one to three layers, never more than
//! [`MAX_LAYERS`]) at an amortized cost proportional to the data
//! committed, never to the size of the whole overlay.
//!
//! Because a sealed layer is immutable, a key rewritten while a reader
//! held a snapshot is stored once per layer it was written into, until
//! a merge collapses the copies.  The size accounting counts those
//! copies — see [`DbCache::total_size`] — so the flush threshold sees
//! the memory the overlay really holds rather than the size of its
//! logical contents.
//!
//! Lookups walk the layers newest to oldest and stop at the first
//! layer holding the key, whether it holds a value or a pending
//! deletion (`None`) — a deletion is an answer, not a miss.  Ordered
//! iteration merges the layers with [`LayerMerge`], where a newer
//! layer's entry shadows every older one for the same key.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::METADATA_TABLE;
use crate::blockfile::BlockStore;
use crate::bucketindex::BucketIndex;
use crate::error::{Error, ErrorKind, db_error};
use crate::participant::{FlushWriter, Registration};
use crate::transaction::BUCKET_INDEX_PREFIX;

/// The default size for the database cache: 300 MiB, three times dcrd's
/// `defaultCacheSize` of 100 MiB (`database/ffldb/dbcache.go:22`).  A
/// UTXO cache flush that only its size limit tripped does not force a
/// flush of this cache, so its rows wait here, and this ceiling is the
/// most they wait for: with the factor in [`DbCache::needs_flush`], a
/// commit flushes once more than 200 MiB is retained.  The flush
/// interval, or a flush participant that asks for one, can come first.
pub(crate) const DEFAULT_CACHE_SIZE: u64 = 300 * 1024 * 1024;

/// The default number of seconds between flushes (dcrd
/// `defaultFlushSecs`, five minutes).
pub(crate) const DEFAULT_FLUSH_SECS: u64 = 300;

/// One immutable layer of the cache overlay: key to live value, or
/// `None` for a pending deletion of a stored key.
pub(crate) type CacheLayer = BTreeMap<Vec<u8>, Option<Vec<u8>>>;

/// The bytes each overlay entry is counted at beyond its key and value
/// (dcrd treap `nodeFieldsSize`,
/// `database/internal/treap/common.go:22`), for live values and pending
/// deletions alike: dcrd's `nodeSize` is this plus the key and value
/// lengths, and `needsFlush` gates on the sum.
///
/// dcrd sizes it from a treap node's fields, but it also fits this
/// port's own per-entry cost: 200,000 random-keyed `CacheLayer`
/// entries hold about 74 bytes each beyond their keys and values
/// (bytes requested from the allocator, before its own overhead), for
/// live values and deletions alike.  Counting key and value bytes alone
/// put the figure 2-4x under the memory held for the small rows that
/// dominated this store then: before ADR-0011, an `existsaddridx` row
/// went through the overlay as a 25-byte key and an empty value.
const NODE_FIELDS_SIZE: u64 = 72;

/// The size one entry is counted at (dcrd treap `nodeSize`).
#[allow(
    clippy::arithmetic_side_effects,
    reason = "72 plus the lengths of a key and value held in memory at once, so the sum is far \
              below u64::MAX"
)]
fn node_size(key_len: usize, value: Option<&[u8]>) -> u64 {
    NODE_FIELDS_SIZE + key_len as u64 + value.map_or(0, |v| v.len() as u64)
}

/// The layers a flush retired, as [`FlushBatch::into_retired`] hands them
/// back: no longer published, and freed when the last handle on each is
/// dropped.
pub(crate) type RetiredLayers = Vec<Arc<CacheLayer>>;

/// An overlay capture handed to [`DbCache::sync_blocks`],
/// [`DbCache::fill`] and [`DbCache::commit`], which persist it with no
/// lock held.
///
/// It owns `Arc`s on the captured layers, which does two things: the
/// contents cannot change under the commit (every `Arc::try_unwrap` in
/// the write path fails while it is held, so writers seal a new layer
/// instead of mutating one of these), and the layers stay alive even
/// though they are still published for readers.
pub(crate) struct FlushBatch {
    layers: Vec<Arc<CacheLayer>>,
    bytes: u64,
    write_log: Option<crate::WriteLogSink>,
    take_stats: bool,
    /// Whether an observer will see this flush, which is what the I/O
    /// and processor time counters of [`crate::FlushPhase`] are read for.
    observed: bool,
    started: Instant,
    /// The waits for the writer semaphore as of this flush, for the
    /// observer; set by the flush's caller, which holds the semaphore.
    pub(crate) writer_waits: crate::WriterWaits,
    /// Whether `Database::flush` or `Database::close` asked for this
    /// flush, rather than a commit's own flush check; set by the flush's
    /// caller.
    pub(crate) explicit: bool,
    /// What the caller spent waiting for the previous flush's commit to
    /// end before it captured this one; set by the flush's caller.
    pub(crate) waited: Duration,
    /// Whether the commit was handed to another thread
    /// ([`Self::hand_off`]).
    background: bool,
    /// The time from the capture to that hand-off; unused for a flush
    /// whose commit ran on the capturing thread.
    foreground: Duration,
    /// What the flush pinned and what the process held around it, for
    /// the observer ([`crate::FlushMemory`]).  The capture fills in the
    /// layers, the flush's caller the readings it takes on the way, and
    /// [`DbCache::retire`] the rest.
    pub(crate) memory: crate::FlushMemory,
    /// Whether the commit is made with a read snapshot of the store held
    /// across it ([`crate::FlushObservation::snapshot`]); set by the
    /// flush's caller.
    pub(crate) snapshot: bool,
    /// A test's probe, run as the batch is dropped.  Fields are dropped
    /// in the order they are declared, so a batch dropped whole has let
    /// go of [`Self::layers`] by then; one taken apart by
    /// [`Self::into_retired`] runs it with those handles still held.
    #[cfg(test)]
    pub(crate) on_drop: DropProbe,
}

/// A closure a test plants for [`FlushBatch::on_drop`].
#[cfg(test)]
pub(crate) type BatchProbe = Arc<dyn Fn() + Send + Sync>;

/// Runs its closure, if it has one, when it is dropped.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct DropProbe(pub(crate) Option<BatchProbe>);

#[cfg(test)]
impl Drop for DropProbe {
    fn drop(&mut self) {
        if let Some(probe) = self.0.take() {
            probe();
        }
    }
}

impl FlushBatch {
    /// Whether an observer will see this flush: the readings of
    /// [`crate::FlushMemory`] are taken only for one.
    pub(crate) fn observed(&self) -> bool {
        self.observed
    }

    /// Record that this flush's commit is leaving the capturing thread:
    /// everything from the capture to here ran on it, with the writer
    /// semaphore held.
    pub(crate) fn hand_off(&mut self) {
        self.background = true;
        self.foreground = self.started.elapsed();
    }

    /// Undo [`Self::hand_off`] for a commit that could not leave after
    /// all, and so runs on the capturing thread like any other.
    pub(crate) fn take_back(&mut self) {
        self.background = false;
        self.foreground = Duration::ZERO;
    }

    /// The batch's handles on the layers it captured, and nothing else of
    /// it: what a flush that [`DbCache::retire`] took out of the overlay
    /// still holds of them, for its caller to drop once that caller holds
    /// no lock another thread waits on.
    pub(crate) fn into_retired(self) -> RetiredLayers {
        self.layers
    }
}

/// A flush's write transaction, filled and not yet committed: what
/// [`DbCache::fill`] hands to [`DbCache::commit`].
pub(crate) struct CommitJob {
    tx: redb::WriteTransaction,
    /// What the flush has measured so far; the commit adds its own phase.
    outcome: FlushOutcome,
    /// [`FlushBatch::observed`], for the commit's timer.
    observed: bool,
}

/// What [`DbCache::fill`] made of a captured batch.
#[allow(
    clippy::large_enum_variant,
    reason = "one is made per flush and handed straight to its caller; boxing the write \
              transaction would add an allocation and save nothing"
)]
pub(crate) enum Filled {
    /// Nothing to commit: an empty overlay and no participant work.  The
    /// block files were still synced.
    Empty(FlushOutcome),
    /// A write transaction holding the overlay's rows and the
    /// participant's, ready for [`DbCache::commit`].
    Tx(CommitJob),
}

/// What a completed commit reports back for the observer.
pub(crate) struct FlushOutcome {
    dirty_entries: usize,
    stats_elapsed: Duration,
    sampled: Option<crate::RawStats>,
    block_sync: crate::FlushPhase,
    insert: crate::FlushPhase,
    commit: crate::FlushPhase,
    /// Set when the flush participant contributed to this flush.
    participant: Option<crate::ParticipantStats>,
}

impl FlushOutcome {
    /// A successful outcome with nothing to report, for tests that drive
    /// retirement without running a real commit.
    #[cfg(test)]
    pub(crate) fn for_test() -> FlushOutcome {
        FlushOutcome {
            dirty_entries: 0,
            stats_elapsed: Duration::ZERO,
            sampled: None,
            block_sync: crate::FlushPhase::default(),
            insert: crate::FlushPhase::default(),
            commit: crate::FlushPhase::default(),
            participant: None,
        }
    }
}

/// The calling thread's storage I/O so far, `(read_bytes, write_bytes)`
/// from Linux's `/proc/thread-self/io`; `None` elsewhere, or where the
/// kernel keeps no task I/O accounting.
///
/// Per thread rather than `/proc/self/io`, because block serving and RPC
/// run beside a flush and their reads would land in its figures.  redb
/// does its I/O on the thread that calls it, which is the flushing one.
fn thread_io() -> Option<(u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        let io = String::from_utf8(read_proc("/proc/thread-self/io")?).ok()?;
        let (mut read, mut write) = (None, None);
        for line in io.lines() {
            if let Some(v) = line.strip_prefix("read_bytes:") {
                read = v.trim().parse().ok();
            } else if let Some(v) = line.strip_prefix("write_bytes:") {
                write = v.trim().parse().ok();
            }
        }
        Some((read?, write?))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// The calling thread's processor time so far, `(utime, stime)` from
/// Linux's `/proc/thread-self/stat`, in clock ticks: the time it has run
/// in user mode and in the kernel.  `None` elsewhere.
///
/// Per thread for [`thread_io`]'s reason.
fn thread_times() -> Option<(u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        parse_stat_times(&read_proc("/proc/thread-self/stat")?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// The calling thread's time on a processor and its time runnable but
/// waiting for one so far, both in nanoseconds, from Linux's
/// `/proc/thread-self/schedstat`; `None` elsewhere, and where the kernel
/// has no such file.  A kernel that has the file but keeps no scheduler
/// accounting writes zeros in it.
///
/// The two do not add up to the wall time between two readings: the
/// rest of it the thread spent asleep, which in a flush is waiting for
/// storage or for a lock.  The kernel brings a running thread's time on
/// a processor up to date at a scheduler tick or a context switch, not
/// when the file is read, so a reading can trail the thread by up to a
/// tick; so can those of [`thread_times`] where, as on x86 and ARM, the
/// kernel reports them as a division of the same figure.
fn thread_sched() -> Option<(u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        parse_schedstat(&read_proc("/proc/thread-self/schedstat")?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// The contents of the `/proc` file at `path`; `None` when it cannot be
/// read.  The counters above all read through here, and so do the
/// readings of the process's memory ([`crate::ProcessMemory`]).
#[cfg(target_os = "linux")]
pub(crate) fn read_proc(path: &str) -> Option<Vec<u8>> {
    #[cfg(test)]
    PROC_READS.with(|reads| reads.set(reads.get().saturating_add(1)));
    std::fs::read(path).ok()
}

#[cfg(test)]
thread_local! {
    /// How many `/proc` files the calling thread has asked for through
    /// `read_proc`, for the tests that an unobserved flush reads none.
    static PROC_READS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// `utime` and `stime`, in clock ticks, from the contents of a
/// `/proc/<pid>/stat` file (`proc_pid_stat(5)`).
///
/// The second field is the thread's name in parentheses, and a name may
/// itself hold spaces, parentheses and bytes that are not UTF-8 (the
/// kernel cuts a name at 15 bytes, wherever that falls), so the fields
/// are counted from the last `)` of the file: everything after the name
/// is a state letter and numbers.  From there `utime` and `stime` are the
/// twelfth and thirteenth fields, the file's fourteenth and fifteenth.
#[cfg(any(target_os = "linux", test))]
fn parse_stat_times(stat: &[u8]) -> Option<(u64, u64)> {
    let name_end = stat.iter().rposition(|&byte| byte == b')')?;
    let rest = std::str::from_utf8(stat.get(name_end.checked_add(1)?..)?).ok()?;
    let mut fields = rest.split_ascii_whitespace();
    let utime = fields.nth(11)?.parse().ok()?;
    let stime = fields.next()?.parse().ok()?;
    Some((utime, stime))
}

/// The first two fields of a `/proc/<pid>/schedstat` file: nanoseconds
/// on a processor, and nanoseconds runnable but waiting for one.
#[cfg(any(target_os = "linux", test))]
fn parse_schedstat(schedstat: &[u8]) -> Option<(u64, u64)> {
    let mut fields = std::str::from_utf8(schedstat)
        .ok()?
        .split_ascii_whitespace();
    let on_cpu = fields.next()?.parse().ok()?;
    let waiting = fields.next()?.parse().ok()?;
    Some((on_cpu, waiting))
}

/// Milliseconds in one clock tick of `/proc/<pid>/stat`.  The kernel
/// writes process times there in units of its `USER_HZ`, which its
/// generic definition, the one x86, ARM and RISC-V take, sets to 100 a
/// second (alpha's is 1024).
const MS_PER_CLOCK_TICK: u64 = 10;

/// What each of a pair of counters grew by since `before`, read again by
/// `read`; `None`, with nothing read, when `before` is.
fn grown(
    before: Option<(u64, u64)>,
    read: impl FnOnce() -> Option<(u64, u64)>,
) -> Option<(u64, u64)> {
    let (first, second) = before?;
    let (first_now, second_now) = read()?;
    Some((
        first_now.saturating_sub(first),
        second_now.saturating_sub(second),
    ))
}

/// Times one phase of a flush, reading the thread's I/O and processor
/// time counters at either end when an observer will see the result.
///
/// The processor time counters are read nearest the phase at both ends,
/// so the reads of the I/O counters are outside what they measure; the
/// wall time is taken inside all of them.
struct PhaseTimer {
    started: Instant,
    io: Option<(u64, u64)>,
    times: Option<(u64, u64)>,
    sched: Option<(u64, u64)>,
}

impl PhaseTimer {
    fn start(observed: bool) -> PhaseTimer {
        PhaseTimer {
            io: if observed { thread_io() } else { None },
            times: if observed { thread_times() } else { None },
            sched: if observed { thread_sched() } else { None },
            started: Instant::now(),
        }
    }

    fn finish(self) -> crate::FlushPhase {
        let elapsed = self.started.elapsed();
        let sched = grown(self.sched, thread_sched);
        let times = grown(self.times, thread_times);
        let io = grown(self.io, thread_io);
        let ms = |ticks: u64| ticks.saturating_mul(MS_PER_CLOCK_TICK);
        crate::FlushPhase {
            elapsed,
            read_bytes: io.map(|(read, _)| read),
            write_bytes: io.map(|(_, write)| write),
            utime_ms: times.map(|(utime, _)| ms(utime)),
            stime_ms: times.map(|(_, stime)| ms(stime)),
            on_cpu_ns: sched.map(|(on_cpu, _)| on_cpu),
            runq_wait_ns: sched.map(|(_, waiting)| waiting),
        }
    }
}

/// The ceiling on how many layers a snapshot may hold.  Every layer a
/// lookup must probe before it can answer "not cached" costs one
/// `BTreeMap` search, so the depth is a direct multiplier on the miss
/// path; eight keeps that within a small constant while still leaving
/// the geometric merge rule room for a 2^8 spread between the newest
/// and oldest layer sizes.  Reaching the ceiling forces a merge of the
/// two newest (and, after the geometric pass, smallest) layers.
const MAX_LAYERS: usize = 8;

/// A point-in-time view of the cache overlay: the layers that were
/// sealed or live when the snapshot was taken, newest first.  Cloning
/// one clones only the layer handles, never the maps.
#[derive(Default)]
pub(crate) struct CacheSnapshot {
    /// The overlay layers, newest first.  Every layer named here is
    /// immutable for as long as this snapshot exists.
    layers: Vec<Arc<CacheLayer>>,
}

/// The name the rest of the crate uses for a snapshot of the overlay.
pub(crate) type CacheMap = CacheSnapshot;

impl CacheSnapshot {
    /// The overlay's entry for the key: `Some(Some(value))` for a
    /// cached value, `Some(None)` for a cached deletion, and `None`
    /// when no layer holds the key at all (the caller must then read
    /// the durable store).  The walk stops at the first layer holding
    /// the key — a deletion in a newer layer hides a value in an older
    /// one.
    pub(crate) fn get(&self, key: &[u8]) -> Option<&Option<Vec<u8>>> {
        for layer in &self.layers {
            if let Some(entry) = layer.get(key) {
                return Some(entry);
            }
        }
        None
    }

    /// How many layers this snapshot names.
    #[cfg(test)]
    pub(crate) fn layer_count(&self) -> usize {
        self.layers.len()
    }

    /// Whether the overlay holds nothing at all.
    fn is_empty(&self) -> bool {
        self.layers.iter().all(|layer| layer.is_empty())
    }

    /// Whether any layer holds an entry, a pending deletion included,
    /// whose key starts with `prefix`: the check that registering a flush
    /// participant over `prefix` would leave no overlay row to shadow its
    /// rows.
    pub(crate) fn holds_prefix(&self, prefix: &[u8]) -> bool {
        self.merged_from(prefix)
            .next()
            .is_some_and(|(key, _)| key.starts_with(prefix))
    }

    /// The merged view of every layer, ascending by key: each key once,
    /// with the entry from the newest layer holding it.
    fn merged(&self) -> LayerMerge<'_> {
        LayerMerge::new(&self.layers, None)
    }

    /// The merged view from `from` onward, ascending by key: each key
    /// once, with the entry from the newest layer holding it, a pending
    /// deletion included as `None` (dcrd's cache snapshot iterator over
    /// its treaps).  A prefix scan merges this with the durable store's
    /// range, the overlay shadowing the store.
    pub(crate) fn merged_from(&self, from: &[u8]) -> LayerMerge<'_> {
        LayerMerge::new(&self.layers, Some(from))
    }
}

/// A merging iterator over a snapshot's layers: ascending by key, each
/// key yielded exactly once with the entry from the newest layer that
/// holds it (a pending deletion included, as `None`).
pub(crate) struct LayerMerge<'a> {
    /// One peekable range per layer, newest first.
    iters: Vec<LayerRange<'a>>,
}

/// An ascending range over one layer, one entry of lookahead deep.
type LayerRange<'a> =
    std::iter::Peekable<std::collections::btree_map::Range<'a, Vec<u8>, Option<Vec<u8>>>>;

impl<'a> LayerMerge<'a> {
    fn new(layers: &'a [Arc<CacheLayer>], from: Option<&[u8]>) -> LayerMerge<'a> {
        // An explicit bound pair: the `RangeFrom<&T>` shorthand cannot
        // carry an unsized `[u8]` bound.
        let start = match from {
            Some(key) => std::ops::Bound::Included(key),
            None => std::ops::Bound::Unbounded,
        };
        let iters = layers
            .iter()
            .map(|layer| {
                layer
                    .range::<[u8], _>((start, std::ops::Bound::Unbounded))
                    .peekable()
            })
            .collect();
        LayerMerge { iters }
    }
}

impl<'a> Iterator for LayerMerge<'a> {
    type Item = (&'a [u8], &'a Option<Vec<u8>>);

    fn next(&mut self) -> Option<Self::Item> {
        // The smallest key across the layer heads.
        let mut min: Option<&'a Vec<u8>> = None;
        for iter in self.iters.iter_mut() {
            if let Some(&(key, _)) = iter.peek() {
                match min {
                    Some(cur) if cur <= key => {}
                    _ => min = Some(key),
                }
            }
        }
        let min = min?;

        // Consume that key from every layer holding it, keeping the
        // newest layer's entry: newer shadows older.
        let mut newest: Option<Self::Item> = None;
        for iter in self.iters.iter_mut() {
            match iter.peek() {
                Some(&(key, _)) if key == min => {}
                _ => continue,
            }
            let Some((key, entry)) = iter.next() else {
                continue;
            };
            if newest.is_none() {
                newest = Some((key.as_slice(), entry));
            }
        }
        newest
    }
}

/// Merge the newest layer into the next older one, newer entries
/// shadowing older ones (pending deletions included), leaving the
/// result as the newest layer and returning the retained bytes the
/// merge reclaimed.
///
/// A key present in both layers occupied space twice while they were
/// separate — the older copy is frozen, so it could not be freed when the
/// newer write shadowed it — and after the merge it occupies space once.
/// The caller subtracts the difference from the running total, which is
/// what keeps that total a measure of memory actually held rather than of
/// the overlay's logical contents.
///
/// The smaller layer is the one walked: its entries go into the larger
/// map, so a merge costs one map insert per entry of the smaller layer
/// whichever of the two is newer.  When that is the older layer, an
/// older entry the newer layer already holds is dropped rather than
/// inserted, which leaves the same map and reclaims the same bytes as
/// walking the newer layer would.
fn merge_newest_pair(layers: &mut Vec<Arc<CacheLayer>>) -> u64 {
    if layers.len() < 2 {
        return 0;
    }
    let newer = layers.remove(0);
    let older = layers.remove(0);
    let mut reclaimed = 0u64;
    let merged = if newer.len() > older.len() {
        // Start from the newer layer, and add each older entry it does
        // not shadow.
        let mut merged = Arc::unwrap_or_clone(newer);
        let mut keep = |key: Vec<u8>, entry: Option<Vec<u8>>| {
            #[cfg(test)]
            count_merge_insert();
            match merged.entry(key) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(entry);
                }
                // The newer copy stays, and this older one is no longer
                // retained.
                std::collections::btree_map::Entry::Occupied(slot) => {
                    reclaimed =
                        reclaimed.saturating_add(node_size(slot.key().len(), entry.as_deref()));
                }
            }
        };
        match Arc::try_unwrap(older) {
            Ok(map) => map.into_iter().for_each(|(key, entry)| keep(key, entry)),
            Err(shared) => shared
                .iter()
                .for_each(|(key, entry)| keep(key.clone(), entry.clone())),
        }
        merged
    } else {
        // Start from the older layer — taking it outright when no
        // snapshot still names it — and let the newer layer overwrite.
        let mut merged = Arc::unwrap_or_clone(older);
        let mut absorb = |key: Vec<u8>, entry: Option<Vec<u8>>| {
            #[cfg(test)]
            count_merge_insert();
            let key_len = key.len();
            if let Some(shadowed) = merged.insert(key, entry) {
                // The older copy of this key is gone: its entry, its key
                // bytes and, when it held one, its value bytes are no
                // longer retained.
                reclaimed = reclaimed.saturating_add(node_size(key_len, shadowed.as_deref()));
            }
        };
        // The newer layer is moved rather than copied when nothing else
        // names it, which inside `compact` is always: it was just built
        // by `commit_pending` or by the previous merge.
        match Arc::try_unwrap(newer) {
            Ok(map) => map.into_iter().for_each(|(key, entry)| absorb(key, entry)),
            Err(shared) => shared
                .iter()
                .for_each(|(key, entry)| absorb(key.clone(), entry.clone())),
        }
        merged
    };
    layers.insert(0, Arc::new(merged));
    reclaimed
}

#[cfg(test)]
thread_local! {
    /// How many entries the calling thread's merges have walked into
    /// another layer, for the tests of what a merge costs.
    static MERGE_INSERTS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Count one entry walked into another layer by a merge.
#[cfg(test)]
fn count_merge_insert() {
    MERGE_INSERTS.with(|n| n.set(n.get().saturating_add(1)));
}

/// Keep the layer stack shallow, returning the retained bytes the
/// merges reclaimed.
///
/// The newest layer folds into the one below it at once whenever no
/// snapshot names that layer any more: the cache then holds the only
/// handle on it, so the merge takes it without a copy, and costs one map
/// insert per entry of the smaller of the two.  The folds go on down the
/// stack for as long as the next layer is unshared too.  A layer that a
/// reader's snapshot forced the commit to seal holds only what was
/// committed while some reader held the layer below, typically one
/// commit's rows, so the stack above any layers a flush in flight
/// captured returns to a single layer at the first commit no reader
/// overlaps, as it never leaves one while no reader overlaps any.  The
/// readers that split the stack in practice are short — a transaction
/// that reads a few rows while another thread commits — and without the
/// fold the layer they split off grew in place until the rule below
/// merged it, re-inserting about half the older layer's entry count at
/// once and leaving every lookup in between to probe one more layer.
///
/// While a snapshot still names the layer below, the newest layer
/// merges down only once it has grown to half that layer's entry count,
/// which copies the entries of the layer below (the snapshot keeps the
/// original), and keeps two properties:
///
/// - a merge costs at most about three times the data that caused it,
///   and cannot recur until that much new data arrives again, so the
///   cost per committed entry stays constant rather than growing with
///   the overlay;
/// - the stack keeps collapsing back toward a single layer instead of
///   settling at the [`MAX_LAYERS`] ceiling, so the lookup path — which
///   probes every layer before it can answer "not cached" — stays one
///   to three searches deep rather than always eight.  Deleting this
///   pass leaves only the ceiling below, and the stack then pins at
///   eight layers permanently; `the_merge_rule_keeps_the_stack_shallow`
///   is the guard.
///
/// [`MAX_LAYERS`] then forces merges of the newest (and, under the rule
/// above, smallest) pair if the stack is ever deeper than the lookup
/// path should walk.
/// `pinned` is the number of layers at the TAIL that an in-flight flush
/// is persisting, which must not be merged.
///
/// A flush captures the stack, releases the cache lock, and retires
/// exactly those layers when its commit lands. `merge_newest_pair` would
/// break that: it removes `layers[0]` and `layers[1]` and inserts one new
/// `Arc` in their place, so a captured layer folded together with a newer
/// one loses its identity. Retiring "the tail" would then either drop the
/// newer layer's uncommitted writes — a whole `Chain::flush` unit, block
/// index rows and UTXO entries and both state markers — or, if retirement
/// went by pointer identity, match nothing and leave the overlay unable
/// to drain.
///
/// The barrier is why `commit_pending`'s Arc back-off is not enough on
/// its own: pinning makes `Arc::try_unwrap` fail, and the merge path
/// *clones* on failure rather than backing off the way the top-layer path
/// does.
fn compact(layers: &mut Vec<Arc<CacheLayer>>, pinned: usize) -> u64 {
    let mut reclaimed = 0u64;
    // `layers.len() - pinned >= 2` keeps both arguments of every merge
    // above the barrier: layers are only ever prepended, so the pinned
    // region stays the tail for as long as it is pinned.  (A pinned
    // layer is never unshared either, since the flush that pinned it
    // holds a handle on it until it retires it.)
    //
    // A strong count of one means `layers` holds the only handle, and a
    // handle is made only from another, so the merge's `try_unwrap`
    // takes the layer without a copy.  Nothing rests on that but the
    // copy: a layer some snapshot still named would be copied, and the
    // snapshot would keep the original.
    while layers.len().saturating_sub(pinned) >= 2
        && (Arc::strong_count(&layers[1]) == 1
            || layers[0].len().saturating_mul(2) >= layers[1].len())
    {
        reclaimed = reclaimed.saturating_add(merge_newest_pair(layers));
    }
    while layers.len().saturating_sub(pinned) > MAX_LAYERS {
        reclaimed = reclaimed.saturating_add(merge_newest_pair(layers));
    }
    reclaimed
}

/// The metadata write cache (dcrd `dbCache`).
pub(crate) struct DbCache {
    /// The published snapshot of the committed-but-unflushed overlay;
    /// transactions snapshot it by cloning the `Arc`, which is O(1) and
    /// never copies a layer.
    pub(crate) cached: Arc<CacheSnapshot>,
    /// The bucket index of the committed state `cached` publishes: the
    /// store's bucket index rows with those of every transaction
    /// committed since applied (see [`BucketIndex`]).  It changes only in
    /// [`Self::commit_pending`], with `cached`, so the two are always of
    /// one commit, and a transaction clones both handles under one hold
    /// of the cache lock.  A flush leaves it alone.  The rows it moves
    /// from the overlay to the store it does not change, and the rows a
    /// flush participant writes with it lie under the participant's
    /// prefix, which `Database::set_flush_participant` refuses inside the
    /// bucket index: the map is the rows only for as long as it does.
    pub(crate) buckets: Arc<BucketIndex>,
    /// The approximate byte size of the entries the overlay RETAINS,
    /// each counted as dcrd's treap counts a node: [`NODE_FIELDS_SIZE`]
    /// plus its key and value bytes, for a pending deletion as for a
    /// live value.  For a single layer this is the figure dcrd's
    /// `needsFlush` sums over its two treaps (`pendingKeys.Size() +
    /// pendingRemove.Size()`, a key being in at most one of them).
    ///
    /// Not the logical size of the overlay's contents: sealed layers are
    /// immutable, so a key rewritten across several of them is held once
    /// per layer and counted once per layer, and the count falls again
    /// when a merge collapses the copies.  `needs_flush` gates the cache
    /// ceiling on this, so it has to measure memory rather than
    /// contents — counting a rewritten key once put the figure ~5x under
    /// the bytes actually held, which let the overlay grow to several
    /// times `max_size` before a flush was triggered.
    ///
    /// One boundary: a reader's snapshot can name a layer this stack has
    /// already merged away, and those bytes stay allocated until the
    /// reader drops.  They are not counted, because they belong to a
    /// transaction's lifetime rather than to the overlay's — the same
    /// place dcrd's accounting draws the line for a treap snapshot an
    /// open transaction still holds.
    total_size: u64,
    /// The last time the cache was flushed.
    last_flush: Instant,
    /// The maximum size threshold before a flush (dcrd `maxSize`).
    max_size: u64,
    /// The time threshold before a flush (dcrd `flushInterval`).
    flush_interval: Duration,
    /// Observer for the storage-measurement work in ADR-0004; `None`
    /// in every ordinary build, in which case flush is unchanged.
    observer: Option<crate::FlushObserver>,
    /// Take full stats every Nth flush; 0 disables.
    stats_every: u64,
    /// Flushes since open, so an observation can be ordered.
    flush_seq: u64,
    /// Records every key/value the engine is handed, in the order it is
    /// handed them; `None` in every ordinary build.
    ///
    /// This exists for ADR-0009's candidate engine benchmark, where the
    /// insertion *order* decides the answer: a sorted bulk load is an
    /// LSM's best case and a copy-on-write B-tree's worst (a sorted
    /// rebuild of this store measured 58.29% fill against 64.86%), and a
    /// random one is the reverse. Neither is what the engine actually
    /// sees. It sees this: one transaction per flush, each a sorted sweep
    /// over a scattered subset, carrying overwrites and deletes. Capturing
    /// it once and replaying it into every candidate eliminates the
    /// confound rather than balancing it.
    write_log: Option<crate::WriteLogSink>,
    /// Layers at the TAIL that an in-flight flush is persisting.
    ///
    /// They stay published for the whole commit, because the durable
    /// store does not hold them yet and a reader must still find them.
    /// Non-zero only between `begin_flush` and `retire`, and the
    /// barrier [`compact`] honours so their identity survives.
    in_flight_layers: usize,
    /// Retained bytes those layers account for, moved out of
    /// `total_size` at capture.
    ///
    /// Kept separate so `needs_flush` disarms the moment a flush is
    /// handed off rather than staying armed for its whole duration —
    /// otherwise every commit inside the window re-triggers a flush of
    /// data already being written. Restored to `total_size` if the
    /// commit fails, since the overlay still holds it.
    in_flight_size: u64,
    /// Whether a flush has been captured and not yet retired.
    ///
    /// The two figures above cannot say so: a flush in which only the
    /// participant has work captures no layer and no byte.  Set by
    /// `begin_flush` and cleared by `retire`, and what `flush_locked`
    /// refuses a second capture on.
    in_flight: bool,
}

impl DbCache {
    pub(crate) fn new() -> DbCache {
        DbCache {
            cached: Arc::new(CacheSnapshot::default()),
            buckets: Arc::new(BucketIndex::default()),
            total_size: 0,
            last_flush: Instant::now(),
            max_size: DEFAULT_CACHE_SIZE,
            flush_interval: Duration::from_secs(DEFAULT_FLUSH_SECS),
            observer: None,
            stats_every: 0,
            flush_seq: 0,
            in_flight_layers: 0,
            in_flight_size: 0,
            in_flight: false,
            write_log: None,
        }
    }

    /// Set the overlay's size ceiling and time-based flush interval.
    pub(crate) fn set_limits(&mut self, max_size: u64, flush_interval_secs: u64) {
        self.max_size = max_size;
        self.flush_interval = Duration::from_secs(flush_interval_secs);
    }

    /// Attach a flush observer and its sampling interval.
    pub(crate) fn set_observer(
        &mut self,
        observer: Option<crate::FlushObserver>,
        stats_every: u64,
    ) {
        self.observer = observer;
        self.stats_every = stats_every;
    }

    /// Attach a write-log sink. See [`Self::write_log`].
    pub(crate) fn set_write_log(&mut self, sink: Option<crate::WriteLogSink>) {
        self.write_log = sink;
    }

    /// Start from the bucket index the store holds.  For the open, while
    /// the overlay is still empty: from then on only
    /// [`Self::commit_pending`] changes it.
    pub(crate) fn set_bucket_index(&mut self, index: BucketIndex) {
        self.buckets = Arc::new(index);
    }

    /// Apply a committed transaction's pending sets to the overlay
    /// with dcrd's size accounting (dcrd `commitTx` onto the cached
    /// treaps).
    ///
    /// The write lands in the newest layer in place whenever this cache
    /// is that layer's only owner — the steady state, where the cost is
    /// one `BTreeMap` insert per key and nothing else.  While a reader
    /// holds a snapshot naming the layer, the layer stays frozen and
    /// this commit seals a fresh layer above it instead, so no
    /// transaction ever copies the overlay to make progress.  The first
    /// commit that finds no snapshot naming the frozen layer folds the
    /// fresh one back into it ([`compact`]), unless a flush in flight
    /// captured that layer.
    ///
    /// The transaction's bucket index rows are applied to
    /// [`Self::buckets`] as well, here and nowhere else, so the map and
    /// the overlay change under one hold of the cache lock.  The map is
    /// copied first when a transaction still holds it, which leaves that
    /// transaction the bucket index it began with.
    pub(crate) fn commit_pending(
        &mut self,
        puts: BTreeMap<Vec<u8>, Vec<u8>>,
        removes: impl Iterator<Item = Vec<u8>>,
    ) {
        // Take the layer list out of the published snapshot when no
        // reader holds it; otherwise clone the (at most `MAX_LAYERS`)
        // handles, which leaves the reader's snapshot untouched.
        let mut layers = match Arc::get_mut(&mut self.cached) {
            Some(snapshot) => std::mem::take(&mut snapshot.layers),
            None => self.cached.layers.clone(),
        };

        // Reclaim the newest layer for in-place mutation if it is
        // unshared; a failed unwrap means a snapshot still names it, so
        // it must stay frozen and this commit starts a new layer.
        let mut top: CacheLayer = if layers.is_empty() {
            CacheLayer::new()
        } else {
            match Arc::try_unwrap(layers.remove(0)) {
                Ok(map) => map,
                Err(shared) => {
                    layers.insert(0, shared);
                    CacheLayer::new()
                }
            }
        };

        // The accounting measures bytes RETAINED, not the overlay's
        // logical size, because that is what the flush threshold has to
        // gate on.  Layers below the top are frozen: shadowing one of
        // their entries does not free it, so overwriting a key that lives
        // in an older layer ADDS a second copy rather than replacing the
        // first.  Only a write landing on an entry already in `top`
        // genuinely frees the bytes it displaces.  Subtracting in the
        // shadowing case is what made this figure under-count real
        // overlay memory by up to ~5x, letting the cache hold several
        // times `max_size`.  The double-counting is settled later, by
        // `compact`, which reports what its merges reclaim.
        //
        // A fresh entry is counted as dcrd's treap counts a new node,
        // [`NODE_FIELDS_SIZE`] plus its key and value; a write onto an
        // entry already in `top` swaps only the value bytes, as dcrd's
        // `Put` onto an existing node does
        // (`database/internal/treap/immutable.go:164`).
        for key in removes {
            if key.starts_with(BUCKET_INDEX_PREFIX) {
                Arc::make_mut(&mut self.buckets).remove_row(&key);
            }
            let key_len = key.len();
            match top.insert(key, None) {
                // Replaced an entry in the mutable layer: the key stays,
                // any value it held is freed.
                Some(displaced) => {
                    self.total_size = self
                        .total_size
                        .saturating_sub(displaced.map_or(0, |v| v.len() as u64));
                }
                // A fresh tombstone, whether or not an older layer has
                // this key: it occupies its own entry and key bytes.
                None => {
                    self.total_size = self.total_size.saturating_add(node_size(key_len, None));
                }
            }
        }
        for (key, value) in puts {
            if key.starts_with(BUCKET_INDEX_PREFIX) {
                Arc::make_mut(&mut self.buckets).put_row(&key, &value);
            }
            let key_len = key.len();
            let added = value.len() as u64;
            match top.insert(key, Some(value)) {
                Some(displaced) => {
                    self.total_size = self
                        .total_size
                        .saturating_sub(displaced.map_or(0, |v| v.len() as u64))
                        .saturating_add(added);
                }
                #[allow(
                    clippy::arithmetic_side_effects,
                    reason = "72 plus a key's length, at most isize::MAX"
                )]
                None => {
                    self.total_size = self
                        .total_size
                        .saturating_add(NODE_FIELDS_SIZE + key_len as u64)
                        .saturating_add(added);
                }
            }
        }

        layers.insert(0, Arc::new(top));
        let reclaimed = compact(&mut layers, self.in_flight_layers);
        self.total_size = self.total_size.saturating_sub(reclaimed);
        self.publish(layers);
    }

    /// Publish a new layer stack, reusing the snapshot allocation when
    /// no reader holds the current one.
    fn publish(&mut self, layers: Vec<Arc<CacheLayer>>) {
        match Arc::get_mut(&mut self.cached) {
            Some(snapshot) => snapshot.layers = layers,
            None => self.cached = Arc::new(CacheSnapshot { layers }),
        }
    }

    /// Whether the cache must flush before accepting more (dcrd
    /// `needsFlush`): the flush interval elapsed, or one and a half
    /// times the overlay size exceeds the maximum.
    pub(crate) fn needs_flush(&self) -> bool {
        if self.last_flush.elapsed() > self.flush_interval {
            return true;
        }
        let total = (self.total_size as f64 * 1.5) as u64;
        total > self.max_size
    }

    /// Whether a flush has been captured and not yet retired.
    pub(crate) fn in_flight(&self) -> bool {
        self.in_flight
    }

    /// Whether the overlay holds more than its maximum while a flush is
    /// in flight: the layers that flush captured, which stay published
    /// until it retires, plus everything committed since.
    ///
    /// `needs_flush` cannot bound this.  It gates on the bytes committed
    /// since the capture alone, so that a flush under way is not asked
    /// for again, and those can reach its trigger with the captured
    /// layers still held beside them.  A commit that finds this true
    /// waits for the flush in flight to retire before it adds more
    /// (`flush_locked`); it does not flush for this reason alone.
    pub(crate) fn over_ceiling(&self) -> bool {
        self.in_flight && self.total_size.saturating_add(self.in_flight_size) > self.max_size
    }

    /// The counted bytes of everything the overlay has published: what a
    /// flush in flight captured and what was committed since.
    pub(crate) fn overlay_bytes(&self) -> u64 {
        self.total_size.saturating_add(self.in_flight_size)
    }

    /// Capture the overlay for a flush, under the cache lock.
    ///
    /// Always returns a batch, an empty one when there is nothing to
    /// write: `sync_blocks` still syncs the block files for it. The captured
    /// layers STAY PUBLISHED: the durable store does not hold them yet,
    /// so a reader must still be able to find them, and they are retired
    /// only once the commit that persisted them succeeds. That is what
    /// lets the caller drop the cache lock across the commit — the
    /// expensive part — instead of holding it through an fsync that
    /// blocks every reader in the process.
    ///
    /// Capture happens BEFORE the block files are synced, which is the
    /// opposite of the order this code used when the whole flush ran
    /// under one lock hold. It has to: syncing first and capturing
    /// second would let a block written in between be described by
    /// metadata this commit persists, while its bytes are not yet on
    /// disk. Capturing first means the sync covers at least everything
    /// the metadata names.
    pub(crate) fn begin_flush(&mut self) -> FlushBatch {
        self.last_flush = Instant::now();
        let layers = self.cached.layers.clone();
        let bytes = self.total_size;
        let memory = crate::FlushMemory {
            pinned_layers: layers.len(),
            pinned_entries: layers
                .iter()
                .fold(0usize, |n, layer| n.saturating_add(layer.len())),
            ..crate::FlushMemory::default()
        };
        // Move the bytes out of the figure `needs_flush` gates on, so
        // the trigger disarms at handoff rather than staying armed for
        // the whole commit and re-firing on every commit inside it.
        self.total_size = 0;
        self.in_flight_size = bytes;
        self.in_flight_layers = layers.len();
        self.in_flight = true;
        // The sequence is assigned in `retire`, so an empty flush --
        // which syncs block files and commits nothing -- does not consume
        // a number the observer would then appear to skip.
        let take_stats = self.stats_every > 0
            && self
                .flush_seq
                .saturating_add(1)
                .is_multiple_of(self.stats_every);
        FlushBatch {
            layers,
            bytes,
            write_log: self.write_log.clone(),
            take_stats: take_stats && self.observer.is_some(),
            observed: self.observer.is_some(),
            started: Instant::now(),
            writer_waits: crate::WriterWaits::default(),
            explicit: false,
            waited: Duration::ZERO,
            background: false,
            foreground: Duration::ZERO,
            memory,
            snapshot: false,
            #[cfg(test)]
            on_drop: DropProbe::default(),
        }
    }

    /// Persist a captured batch: [`Self::sync_blocks`], [`Self::fill`]
    /// and [`Self::commit`] in a row, as `flush_locked` runs them for a
    /// flush whose commit stays on the capturing thread.  For the tests of
    /// this module, which drive a flush without a database around it.
    #[cfg(test)]
    pub(crate) fn run_flush(
        batch: &FlushBatch,
        kv: &redb::Database,
        block_store: &std::sync::Mutex<BlockStore>,
        participant: Option<&Registration>,
        contributed: &mut bool,
    ) -> Result<FlushOutcome, Error> {
        let block_sync = Self::sync_blocks(batch, block_store)?;
        match Self::fill(batch, kv, participant, contributed, block_sync)? {
            Filled::Empty(outcome) => Ok(outcome),
            Filled::Tx(job) => Self::commit(job),
        }
    }

    /// The first step of persisting a captured batch: sync the block
    /// files written since the last flush.  Runs WITHOUT the cache lock
    /// held, as [`Self::fill`] and [`Self::commit`] do, so readers and the
    /// overlay's writers proceed while a flush works.
    pub(crate) fn sync_blocks(
        batch: &FlushBatch,
        block_store: &std::sync::Mutex<BlockStore>,
    ) -> Result<crate::FlushPhase, Error> {
        // Block files before metadata, so the metadata never describes
        // bytes that could vanish in a crash.
        //
        // The store lock is held to capture what is owed and again to
        // discharge it, not across the fsyncs: block reads go on while
        // they run, as dcrd's do beside `syncBlocks`, which takes read
        // locks alone (`blockio.go:603-625`).  The writer semaphore the
        // caller holds keeps every block write out until the discharge.
        let timer = PhaseTimer::start(batch.observed);
        let plan = block_store
            .lock()
            .expect("block store lock poisoned")
            .sync_plan();
        let (synced, sync_result) = plan.run();
        block_store
            .lock()
            .expect("block store lock poisoned")
            .finish_sync(&synced);
        sync_result?;
        Ok(timer.finish())
    }

    /// The second step: open the flush's write transaction and hand it
    /// every row of the batch, leaving it uncommitted.  `block_sync` is
    /// what [`Self::sync_blocks`] returned, carried into the outcome.
    ///
    /// With a registered flush participant (ADR-0011), the participant is
    /// asked `has_work` once, after the block sync.  When it has work, it
    /// contributes its rows inside this flush's write transaction, after
    /// the overlay's rows and before the commit, so both land in the one
    /// durable commit, and the flush commits even an empty overlay.
    /// `contributed` is set just before `contribute` is called, so the
    /// caller knows to call `finished` whether or not this then fails.
    pub(crate) fn fill(
        batch: &FlushBatch,
        kv: &redb::Database,
        participant: Option<&Registration>,
        contributed: &mut bool,
        block_sync: crate::FlushPhase,
    ) -> Result<Filled, Error> {
        let view = CacheSnapshot {
            layers: batch.layers.clone(),
        };
        let contributing = participant.filter(|r| r.participant.has_work());
        if view.is_empty() && contributing.is_none() {
            // Nothing to commit, but the block files still needed their
            // sync -- that is the half of a flush that runs even on an
            // empty overlay.
            return Ok(Filled::Empty(FlushOutcome {
                dirty_entries: 0,
                stats_elapsed: Duration::ZERO,
                sampled: None,
                block_sync,
                insert: crate::FlushPhase::default(),
                commit: crate::FlushPhase::default(),
                participant: None,
            }));
        }
        // The participant's prefix, which no overlay row may lie under.
        let guarded = participant.map(|r| &*r.prefix);

        let mut dirty_entries = 0usize;
        let mut participant_stats = None;
        let mut sampled = None;
        let mut stats_elapsed = Duration::ZERO;
        let timer = PhaseTimer::start(batch.observed);
        let insert;
        let tx = crate::begin_durable_write(kv)?;
        {
            let mut table = tx
                .open_table(METADATA_TABLE)
                .map_err(crate::storage_error)?;
            for (key, entry) in view.merged() {
                // An overlay row under the participant's prefix would
                // shadow the participant's newer rows for every reader.
                // Registration and commit refuse to create one, so this is
                // a backstop: it fails the flush, and with it latches the
                // store, rather than persist a row that should not exist.
                if let Some(prefix) = guarded {
                    debug_assert!(
                        !key.starts_with(prefix),
                        "an overlay row lies under the flush participant's prefix: {key:02x?}"
                    );
                    if key.starts_with(prefix) {
                        return Err(db_error(
                            ErrorKind::IncompatibleValue,
                            format!(
                                "the metadata overlay holds a row under the flush participant's \
                                 prefix ({key:02x?}); refusing to flush it"
                            ),
                        ));
                    }
                }
                dirty_entries = dirty_entries.saturating_add(1);
                if let Some(sink) = &batch.write_log {
                    sink(key, entry.as_ref().map(|v| v.as_slice()));
                }
                match entry {
                    Some(v) => {
                        table
                            .insert(key, v.as_slice())
                            .map_err(crate::storage_error)?;
                    }
                    None => {
                        table.remove(key).map_err(crate::storage_error)?;
                    }
                }
            }
            insert = timer.finish();
            if let Some(registered) = contributing {
                *contributed = true;
                let timer = PhaseTimer::start(batch.observed);
                let mut writer =
                    FlushWriter::new(&mut table, &registered.prefix, batch.write_log.as_ref());
                let mut stats = registered.participant.contribute(&mut writer)?;
                writer.fill(&mut stats);
                stats.contribute = timer.finish();
                participant_stats = Some(stats);
            }
            if batch.take_stats {
                let stats_started = Instant::now();
                let db_stats = tx.stats().map_err(crate::storage_error)?;
                let table_stats =
                    redb::ReadableTableMetadata::stats(&table).map_err(crate::storage_error)?;
                sampled = Some(crate::RawStats {
                    page_size: db_stats.page_size() as u64,
                    allocated_pages: db_stats.allocated_pages(),
                    tree_height: db_stats.tree_height(),
                    database_fragmented_bytes: db_stats.fragmented_bytes(),
                    leaf_pages: table_stats.leaf_pages(),
                    branch_pages: table_stats.branch_pages(),
                    stored_leaf_bytes: table_stats.stored_bytes(),
                    metadata_bytes: table_stats.metadata_bytes(),
                    table_fragmented_bytes: table_stats.fragmented_bytes(),
                });
                stats_elapsed = stats_started.elapsed();
            }
        }
        Ok(Filled::Tx(CommitJob {
            tx,
            outcome: FlushOutcome {
                dirty_entries,
                stats_elapsed,
                sampled,
                block_sync,
                insert,
                commit: crate::FlushPhase::default(),
                participant: participant_stats,
            },
            observed: batch.observed,
        }))
    }

    /// The last step: redb's durable commit of the transaction
    /// [`Self::fill`] left, timed on the thread that makes it.
    pub(crate) fn commit(job: CommitJob) -> Result<FlushOutcome, Error> {
        let CommitJob {
            tx,
            mut outcome,
            observed,
        } = job;
        let timer = PhaseTimer::start(observed);
        tx.commit().map_err(crate::storage_error)?;
        outcome.commit = timer.finish();
        Ok(outcome)
    }

    /// Retire a batch under the cache lock once its commit has landed
    /// (`Some`), or put its bytes back when the flush failed (`None`).
    ///
    /// The batch is borrowed, so the captured layers are freed after this
    /// lock is released, and not under it: by whoever drops the batch, or
    /// the handles taken out of it ([`FlushBatch::into_retired`]).  Once
    /// the snapshots taken before the flush are gone those are the last
    /// handles, and dropping them frees every row the flush wrote.
    ///
    /// A retirement checks that the pinned tail is still the layers the
    /// batch captured, which [`compact`]'s barrier guarantees.  Were it
    /// not, truncating the tail would drop rows no commit holds, so
    /// nothing is truncated: the accounting goes back as for a failed
    /// flush and the error is returned for the caller to latch the store
    /// with.  Putting the bytes back cannot fail.
    pub(crate) fn retire(
        &mut self,
        batch: &FlushBatch,
        outcome: Option<FlushOutcome>,
    ) -> Result<(), Error> {
        let pinned = self.in_flight_layers;
        self.in_flight_layers = 0;
        let bytes = self.in_flight_size;
        self.in_flight_size = 0;
        self.in_flight = false;
        // What the overlay held with the captured layers still in it.
        let overlay_at_retirement = self.total_size.saturating_add(bytes);
        let layers_at_retirement = self.cached.layers.len();

        let Some(outcome) = outcome else {
            // The commit failed: the overlay still holds every captured
            // byte, so the accounting has to go back or the cache grows
            // without ever tripping its own ceiling again.
            self.total_size = self.total_size.saturating_add(bytes);
            return Ok(());
        };

        let mut layers = self.cached.layers.clone();
        let kept = layers.len().checked_sub(pinned);
        let intact = pinned == batch.layers.len()
            && kept.is_some_and(|kept| {
                layers[kept..]
                    .iter()
                    .zip(batch.layers.iter())
                    .all(|(a, b)| Arc::ptr_eq(a, b))
            });
        let Some(kept) = kept.filter(|_| intact) else {
            self.total_size = self.total_size.saturating_add(bytes);
            return Err(db_error(
                ErrorKind::DriverSpecific,
                "the metadata overlay's pinned layers are no longer the ones the flush captured; \
                 refusing to retire them",
            ));
        };
        layers.truncate(kept);
        self.publish(layers);

        // A flush that committed takes a sequence number, including one in
        // which only the participant wrote: without that, the flushes a
        // participant drives on its own (an index catch-up, `wants_flush`)
        // would be invisible to the observer.
        if outcome.dirty_entries == 0 && outcome.participant.is_none() {
            return Ok(());
        }
        self.flush_seq = self.flush_seq.saturating_add(1);
        if let Some(observer) = &self.observer {
            let elapsed = batch.started.elapsed();
            // The stack published above no longer names the captured
            // layers, so a count above one is a snapshot some transaction
            // still holds: that transaction's thread frees the layer, and
            // the flush's own reference goes first.  A flush whose commit
            // ran on the capturing thread hands that reference to its
            // caller, which may then be the one to free the layer: a
            // commit and `Database::flush` let it go once they have
            // released the writer semaphore, and `Database::close` where
            // it flushed, under the semaphore.
            let shared = || {
                batch
                    .layers
                    .iter()
                    .filter(|layer| Arc::strong_count(layer) > 1)
            };
            observer(&crate::FlushObservation {
                sequence: self.flush_seq,
                dirty_entries: outcome.dirty_entries,
                dirty_bytes: batch.bytes,
                elapsed,
                stats_elapsed: outcome.stats_elapsed,
                block_sync: outcome.block_sync,
                insert: outcome.insert,
                commit: outcome.commit,
                stats: outcome.sampled,
                participant: outcome.participant,
                writer_waits: batch.writer_waits,
                explicit: batch.explicit,
                background: batch.background,
                foreground: if batch.background {
                    batch.foreground
                } else {
                    elapsed
                },
                waited: batch.waited,
                snapshot: batch.snapshot,
                memory: crate::FlushMemory {
                    overlay_at_retirement,
                    layers_at_retirement,
                    shared_layers: shared().count(),
                    shared_entries: shared().fold(0usize, |n, layer| n.saturating_add(layer.len())),
                    ..batch.memory
                },
            });
        }
        Ok(())
    }

    /// Weak handles on the layers published now, newest first, for the
    /// tests outside this module that follow a layer to its free.
    #[cfg(test)]
    pub(crate) fn published_layers_for_test(&self) -> Vec<std::sync::Weak<CacheLayer>> {
        self.cached.layers.iter().map(Arc::downgrade).collect()
    }

    /// Replace every published layer by a copy of itself: the same rows
    /// in layers of another identity, which is what a merge across the
    /// pin would leave.  For the tests of a retirement that finds its
    /// layers changed.
    #[cfg(test)]
    pub(crate) fn reidentify_layers_for_test(&mut self) {
        let layers = self
            .cached
            .layers
            .iter()
            .map(|layer| Arc::new((**layer).clone()))
            .collect();
        self.publish(layers);
    }

    /// [`Self::retire`] with the batch taken by value, for the tests of
    /// this module, none of which changes the pinned tail under a flush.
    /// It hands back the batch's handles on the layers it retired, and
    /// none when the commit failed, as `finish` in the crate root does
    /// for a flush whose commit ran on the capturing thread; it is a copy
    /// of that rule and not `finish`, which the tests that drive
    /// `flush_locked` pin.
    #[cfg(test)]
    pub(crate) fn finish_flush(
        &mut self,
        batch: FlushBatch,
        outcome: Option<FlushOutcome>,
    ) -> RetiredLayers {
        let committed = outcome.is_some();
        self.retire(&batch, outcome)
            .expect("the pinned tail is the layers this flush captured");
        if committed {
            batch.into_retired()
        } else {
            RetiredLayers::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use tempfile::TempDir;

    use super::{DEFAULT_FLUSH_SECS, DbCache, MAX_LAYERS, NODE_FIELDS_SIZE, node_size};
    use crate::{Database, Options};

    /// simnet magic, matching the interface battery.
    const NET: u32 = 0x1214_1c16;

    /// An overlay flattened to key/entry pairs in key order, for
    /// comparing a layered view against a single map.
    type FlatView = Vec<(Vec<u8>, Option<Vec<u8>>)>;

    fn new_db() -> (TempDir, Database) {
        let dir = TempDir::new().expect("tempdir");
        let opts = Options::new(dir.path().join("db"), NET);
        let db = Database::create(&opts).expect("create");
        (dir, db)
    }

    /// Commit one small metadata write in its own transaction.
    fn commit_one(db: &Database, key: &[u8], value: &[u8]) {
        let tx = db.begin(true).expect("begin write");
        tx.metadata()
            .bucket(b"cache")
            .expect("bucket")
            .put(key, value)
            .expect("put");
        tx.commit().expect("commit");
    }

    /// The steady state — commits with no reader anywhere — must stay a
    /// single flat layer written in place, so the work per commit is the
    /// same map insert the unlayered overlay did.  A layer count above
    /// one here would mean sealing (and later merging) work that the
    /// sync path never used to pay.
    #[test]
    fn no_reader_commits_keep_a_single_layer() {
        let mut cache = DbCache::new();
        for round in 0..1000u32 {
            let mut puts = BTreeMap::new();
            puts.insert(format!("k{round:06}").into_bytes(), vec![1u8; 32]);
            puts.insert(b"ffldb-writeloc".to_vec(), round.to_be_bytes().to_vec());
            cache.commit_pending(puts, std::iter::empty());
            assert_eq!(cache.cached.layers.len(), 1, "sealed a layer at {round}");
        }
        assert_eq!(cache.cached.layers[0].len(), 1001);
    }

    /// Snapshot-per-commit over the cache directly: the stack must stay
    /// within [`MAX_LAYERS`], every frozen snapshot must keep the view
    /// it was taken with, the merged view must match a flat overlay,
    /// and the size accounting must stay exactly what a single map
    /// would have produced (each overlay key's bytes once, plus the
    /// bytes of every live value).
    #[test]
    fn layer_stack_stays_bounded_and_accounted() {
        const KEYS: usize = 64;
        const ROUNDS: usize = 500;

        let mut cache = DbCache::new();
        // The flat overlay the layered one must agree with.
        let mut expected: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
        let mut pins = Vec::new();
        let mut first_pin_view: Option<FlatView> = None;

        for round in 0..ROUNDS {
            // A reader snapshots the overlay before every commit.
            let pin = Arc::clone(&cache.cached);
            if first_pin_view.is_none() && round == 3 {
                first_pin_view = Some(pin.merged().map(|(k, v)| (k.to_vec(), v.clone())).collect());
            }
            pins.push(pin);

            // Rewrite one key and delete another, so layers overlap and
            // deletions have to shadow older values.
            let put_key = format!("k{:04}", round % KEYS).into_bytes();
            let value = vec![u8::try_from(round % 251).expect("fits"); round % 13 + 1];
            let del_key = format!("k{:04}", (round + 7) % KEYS).into_bytes();
            let mut puts = BTreeMap::new();
            puts.insert(put_key.clone(), value.clone());
            cache.commit_pending(puts, std::iter::once(del_key.clone()));
            expected.insert(del_key, None);
            expected.insert(put_key, Some(value));

            assert!(
                cache.cached.layers.len() <= MAX_LAYERS,
                "layer stack grew to {} at round {round}",
                cache.cached.layers.len()
            );
        }

        // The merged view of the layered overlay equals the flat one.
        let merged: Vec<(Vec<u8>, Option<Vec<u8>>)> = cache
            .cached
            .merged()
            .map(|(k, v)| (k.to_vec(), v.clone()))
            .collect();
        let flat: Vec<(Vec<u8>, Option<Vec<u8>>)> = expected.clone().into_iter().collect();
        assert_eq!(merged, flat);

        // Point lookups agree too, deletions included.
        for (key, entry) in &expected {
            assert_eq!(cache.cached.get(key), Some(entry), "lookup of {key:?}");
        }

        // The accounting measures bytes retained across the layers, so
        // it must equal what the layers actually hold...
        assert_eq!(
            cache.total_size,
            retained_bytes(&cache),
            "the running total drifted from the bytes the {} layers hold",
            cache.cached.layers.len()
        );
        // ...and it may never fall below the overlay's logical size (every
        // key once plus its live value), which is what a single flat map
        // would have held.  Anything above that is a rewritten key held in
        // more than one sealed layer, which is real memory.
        let logical: u64 = expected
            .iter()
            .map(|(k, v)| node_size(k.len(), v.as_deref()))
            .sum();
        assert!(
            cache.total_size >= logical,
            "the total ({}) fell below the overlay's logical size ({logical}), \
             so it is under-counting held memory",
            cache.total_size
        );

        // The early snapshot never changed under the commits that
        // followed it.
        let pinned_now: Vec<(Vec<u8>, Option<Vec<u8>>)> = pins[3]
            .merged()
            .map(|(k, v)| (k.to_vec(), v.clone()))
            .collect();
        assert_eq!(Some(pinned_now), first_pin_view);
    }

    /// Concurrent readers must not make commits cost more.  A copy-on-
    /// write overlay unshares itself once per snapshot, so a *held*
    /// reader costs one full copy and a reader that snapshots again
    /// before each commit — an RPC poll during a sync — costs one full
    /// copy per commit.  Layering makes both O(1): a snapshot freezes
    /// the newest layer and the commit seals a fresh one above it.
    #[test]
    fn commits_stay_flat_under_concurrent_readers() {
        let (_dir, db) = new_db();
        {
            let tx = db.begin(true).expect("begin write");
            tx.metadata().create_bucket(b"cache").expect("create");
            tx.commit().expect("commit");
        }

        // Fill the overlay with roughly 30 MiB of committed metadata,
        // well under the default flush threshold so nothing flushes
        // mid-measurement.
        const FILL_KEYS: usize = 30_000;
        const ROUNDS: usize = 300;
        {
            let tx = db.begin(true).expect("begin write");
            let bucket = tx.metadata().bucket(b"cache").expect("bucket");
            let value = vec![0x5au8; 1024];
            for i in 0..FILL_KEYS {
                bucket
                    .put(format!("fill-{i:08}").as_bytes(), &value)
                    .expect("put");
            }
            tx.commit().expect("commit");
        }

        // Baseline: small commits with no reader open at all.
        let baseline_start = Instant::now();
        for i in 0..ROUNDS {
            commit_one(&db, format!("solo-{i:08}").as_bytes(), b"v");
        }
        let baseline = baseline_start.elapsed();

        // The same commits with one read transaction held open across
        // all of them.
        let reader = db.begin(false).expect("begin read");
        let held_start = Instant::now();
        for i in 0..ROUNDS {
            commit_one(&db, format!("held-{i:08}").as_bytes(), b"v");
        }
        let held = held_start.elapsed();

        // The held reader still sees its own snapshot: the values
        // committed before it began, and none committed after.
        {
            let bucket = reader.metadata().bucket(b"cache").expect("bucket");
            assert_eq!(bucket.get(b"fill-00000000"), Some(vec![0x5au8; 1024]));
            assert_eq!(bucket.get(b"solo-00000000"), Some(b"v".to_vec()));
            assert_eq!(bucket.get(b"held-00000000"), None);
        }
        drop(reader);

        // And with a fresh reader overlapping every single commit,
        // which is what a client polling the database during a sync
        // does.  Every commit here finds the overlay shared.
        let overlapped_start = Instant::now();
        for i in 0..ROUNDS {
            let reader = db.begin(false).expect("begin read");
            commit_one(&db, format!("lapped-{i:08}").as_bytes(), b"v");
            drop(reader);
        }
        let overlapped = overlapped_start.elapsed();

        // A generous multiple of the no-reader baseline: copying the
        // overlay per commit runs orders of magnitude over it, while
        // layering stays within a small factor.
        let budget = baseline.max(Duration::from_millis(20)) * 20;
        assert!(
            held <= budget,
            "commits under a held reader cost {held:?} against a {baseline:?} \
             baseline (budget {budget:?}): the overlay is being copied instead \
             of layered"
        );
        assert!(
            overlapped <= budget,
            "commits overlapped by a reader cost {overlapped:?} against a \
             {baseline:?} baseline (budget {budget:?}): the overlay is being \
             copied per commit instead of layered"
        );
    }

    /// Layered lookups, ranges, and the flush must all agree with a
    /// single flat overlay: newer layers shadow older ones, and a
    /// pending deletion in a newer layer hides an older value instead
    /// of falling through to it.
    #[test]
    fn layers_shadow_older_entries_including_deletions() {
        let (_dir, db) = new_db();
        {
            let tx = db.begin(true).expect("begin write");
            let bucket = tx.metadata().create_bucket(b"cache").expect("create");
            bucket.put(b"a", b"1").expect("put");
            bucket.put(b"b", b"2").expect("put");
            bucket.put(b"c", b"3").expect("put");
            tx.commit().expect("commit");
        }

        // Pin the overlay with a reader so each commit below has to
        // seal its own layer instead of writing in place.
        let pinned = db.begin(false).expect("begin read");
        {
            let tx = db.begin(true).expect("begin write");
            let bucket = tx.metadata().bucket(b"cache").expect("bucket");
            bucket.put(b"b", b"22").expect("put");
            bucket.delete(b"a").expect("delete");
            bucket.put(b"d", b"4").expect("put");
            tx.commit().expect("commit");
        }
        {
            let tx = db.begin(true).expect("begin write");
            let bucket = tx.metadata().bucket(b"cache").expect("bucket");
            bucket.delete(b"c").expect("delete");
            bucket.put(b"a", b"11").expect("put");
            tx.commit().expect("commit");
        }

        // The pinned reader still sees only what was committed before
        // it began.
        {
            let bucket = pinned.metadata().bucket(b"cache").expect("bucket");
            assert_eq!(bucket.get(b"a"), Some(b"1".to_vec()));
            assert_eq!(bucket.get(b"b"), Some(b"2".to_vec()));
            assert_eq!(bucket.get(b"c"), Some(b"3".to_vec()));
            assert_eq!(bucket.get(b"d"), None);
        }

        // A fresh reader sees the merged view: newest layer wins, and
        // the deletion of `c` is not a fall-through to the older value.
        let expected: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (b"a".to_vec(), b"11".to_vec()),
            (b"b".to_vec(), b"22".to_vec()),
            (b"d".to_vec(), b"4".to_vec()),
        ];
        let read_view = |db: &Database| -> Vec<(Vec<u8>, Vec<u8>)> {
            let tx = db.begin(false).expect("begin read");
            let bucket = tx.metadata().bucket(b"cache").expect("bucket");
            assert_eq!(bucket.get(b"a"), Some(b"11".to_vec()));
            assert_eq!(bucket.get(b"b"), Some(b"22".to_vec()));
            assert_eq!(bucket.get(b"c"), None);
            assert_eq!(bucket.get(b"d"), Some(b"4".to_vec()));
            let mut seen = Vec::new();
            bucket
                .for_each(|k, v| {
                    seen.push((k.to_vec(), v.to_vec()));
                    Ok(())
                })
                .expect("for_each");
            let mut cursor_keys = Vec::new();
            let mut cursor = bucket.cursor();
            let mut ok = cursor.first();
            while ok {
                cursor_keys.push(cursor.key().expect("cursor key"));
                ok = cursor.next();
            }
            assert_eq!(
                cursor_keys,
                vec![b"a".to_vec(), b"b".to_vec(), b"d".to_vec()]
            );
            seen
        };
        assert_eq!(read_view(&db), expected);

        // Flushing the layered overlay to the durable store must
        // produce the same view (the merge is what gets written).
        drop(pinned);
        db.flush().expect("flush");
        assert_eq!(read_view(&db), expected);
    }

    /// The bytes actually held across every layer, computed the slow,
    /// obvious way so a test can check the running total against it:
    /// every entry of every layer at dcrd's node size.
    fn retained_bytes(cache: &DbCache) -> u64 {
        cache
            .cached
            .layers
            .iter()
            .flat_map(|layer| layer.iter())
            .map(|(k, v)| node_size(k.len(), v.as_deref()))
            .sum()
    }

    /// The overlay's logical size: every key once, at dcrd's node size
    /// with its live value.  This is what a single flat map would have
    /// held, and the floor the retained figure may never fall below.
    fn logical_bytes(cache: &DbCache) -> u64 {
        cache
            .cached
            .merged()
            .map(|(k, v)| node_size(k.len(), v.as_deref()))
            .sum()
    }

    /// A key rewritten across sealed layers, with the layers sized so the
    /// geometric merge rule leaves the stack three deep.
    ///
    /// The rule merges whenever the newest layer has half the entries of
    /// the one below, so a stack only survives when each layer is more
    /// than twice the one above it: 40, then 8, then 2.  Every layer
    /// rewrites `key`, and `gone` is written in the oldest and deleted in
    /// the newest.  Returns the reader snapshots that keep the lower
    /// layers frozen; dropping them lets the next commit write in place.
    fn three_layer_rewrite(
        cache: &mut DbCache,
        key: &[u8],
        gone: &[u8],
        value_len: usize,
    ) -> Vec<Arc<super::CacheSnapshot>> {
        let mut pins = Vec::new();
        // Oldest layer: 40 entries, including both keys.
        let mut puts = BTreeMap::new();
        puts.insert(key.to_vec(), vec![0u8; value_len]);
        puts.insert(gone.to_vec(), b"present".to_vec());
        for i in 0..38u32 {
            puts.insert(format!("bottom-{i:04}").into_bytes(), vec![0xaa; 4]);
        }
        cache.commit_pending(puts, std::iter::empty());

        // Middle layer: 8 entries, rewriting `key`.
        pins.push(Arc::clone(&cache.cached));
        let mut puts = BTreeMap::new();
        puts.insert(key.to_vec(), vec![1u8; value_len]);
        for i in 0..7u32 {
            puts.insert(format!("middle-{i:04}").into_bytes(), vec![0xbb; 4]);
        }
        cache.commit_pending(puts, std::iter::empty());

        // Newest layer: 2 entries — `key` again, and `gone` deleted.
        pins.push(Arc::clone(&cache.cached));
        let mut puts = BTreeMap::new();
        puts.insert(key.to_vec(), vec![2u8; value_len]);
        cache.commit_pending(puts, std::iter::once(gone.to_vec()));

        assert_eq!(
            cache.cached.layers.len(),
            3,
            "the layer sizes no longer defeat the merge rule, so this test \
             is not exercising a real stack"
        );
        pins
    }

    /// `total_size` must count the bytes the overlay RETAINS, not the size
    /// of its logical contents, because that figure is what `needs_flush`
    /// gates the cache ceiling on.
    ///
    /// Sealed layers are immutable, so shadowing an entry in one does not
    /// free it: rewriting a key while a reader holds a snapshot stores a
    /// copy per layer.  An accounting that subtracts the shadowed value on
    /// every overwrite reports the logical size instead, which measured
    /// ~5x under the bytes actually held on a live sync — and a cache that
    /// believes it holds 100 MiB while holding 500 is not bounded at all.
    #[test]
    fn the_size_total_counts_every_retained_copy() {
        const VALUE_LEN: usize = 4096;
        let key = b"the-rewritten-key".to_vec();
        let gone = b"deleted-in-the-newest-layer".to_vec();

        let mut cache = DbCache::new();
        let pins = three_layer_rewrite(&mut cache, &key, &gone, VALUE_LEN);

        assert_eq!(
            cache.total_size,
            retained_bytes(&cache),
            "the running total must equal what the three layers hold"
        );

        // And exactly which copies those are: `key` is stored in all three
        // layers where the merged view shows it once, so two extra entries
        // with its key and value are held; `gone` is stored in the oldest
        // layer and tombstoned in the newest, so one extra entry with its
        // key and value is held beyond the tombstone the merged view
        // shows.  Both terms vanish under an accounting that subtracts on
        // every overwrite, which is what makes this the regression guard.
        let expected_excess = 2 * node_size(key.len(), Some(&[0u8; VALUE_LEN]))
            + node_size(gone.len(), Some(b"present"));
        assert_eq!(
            cache.total_size - logical_bytes(&cache),
            expected_excess,
            "the shadowed-but-retained copies are not being counted"
        );

        // A merge collapses those copies, and the total must follow it
        // down.  Dropping the readers unfreezes the stack; filling the
        // newest layer to half the middle one's size trips the merge.
        drop(pins);
        let before = cache.total_size;
        let mut puts = BTreeMap::new();
        for i in 0..8u32 {
            puts.insert(format!("trip-{i:04}").into_bytes(), vec![0xcc; 1]);
        }
        cache.commit_pending(puts, std::iter::empty());
        assert!(
            cache.cached.layers.len() < 3,
            "no merge happened, so this half of the test proves nothing"
        );
        assert_eq!(
            cache.total_size,
            retained_bytes(&cache),
            "the total drifted from the layers after a merge"
        );
        assert!(
            cache.total_size < before,
            "the merge collapsed a duplicate 4 KiB value, so the total must \
             have fallen from {before}, got {}",
            cache.total_size
        );
    }

    /// Every entry is counted as dcrd's treap counts a node:
    /// `nodeFieldsSize` plus its key and value, for a pending deletion as
    /// for a live value (dcrd `database/internal/treap/common.go:43-45`),
    /// so the size trigger fires at the entry count dcrd's `needsFlush`
    /// does.
    ///
    /// Counting the key and value alone put an `existsaddridx`-shaped
    /// overlay (a 25-byte key, an empty value) at about a quarter of
    /// dcrd's figure and a UTXO-shaped one at about half, and the overlay
    /// flushed only after 2-4x as many entries as dcrd's would.
    #[test]
    fn entries_are_sized_as_dcrds_treap_nodes() {
        const ROWS: u64 = 100;
        let addr_key = |i: u64| {
            let mut key = vec![0u8; 25];
            key[..8].copy_from_slice(&i.to_be_bytes());
            key
        };

        // dcrd flushes once 1.5 times the treap size exceeds the ceiling.
        // Put the ceiling exactly where ROWS existsaddridx rows land, so
        // they do not trip it and one more row does.
        let mut cache = DbCache::new();
        cache.set_limits(ROWS * (NODE_FIELDS_SIZE + 25) * 3 / 2, DEFAULT_FLUSH_SECS);
        let puts: BTreeMap<Vec<u8>, Vec<u8>> =
            (0..ROWS).map(|i| (addr_key(i), Vec::new())).collect();
        cache.commit_pending(puts, std::iter::empty());
        assert_eq!(
            cache.total_size,
            ROWS * 97,
            "97 bytes a row, as dcrd counts it"
        );
        assert!(
            !cache.needs_flush(),
            "exactly at the ceiling is not over it"
        );
        let mut puts = BTreeMap::new();
        puts.insert(addr_key(ROWS), Vec::new());
        cache.commit_pending(puts, std::iter::empty());
        assert!(
            cache.needs_flush(),
            "one row past the ceiling dcrd would flush at"
        );

        // A UTXO-shaped put and its deletion, each a fresh entry: 145 and
        // 110 bytes, dcrd's figures for the same rows.
        let mut cache = DbCache::new();
        let utxo_key = vec![7u8; 38];
        let mut puts = BTreeMap::new();
        puts.insert(utxo_key.clone(), vec![1u8; 35]);
        cache.commit_pending(puts, std::iter::empty());
        assert_eq!(cache.total_size, 145);
        cache.commit_pending(BTreeMap::new(), std::iter::once(vec![8u8; 38]));
        assert_eq!(cache.total_size, 145 + 110);
        // Deleting the key the mutable layer holds frees only its value,
        // as moving a node between dcrd's two treaps does.
        cache.commit_pending(BTreeMap::new(), std::iter::once(utxo_key));
        assert_eq!(cache.total_size, 110 + 110);
        assert_eq!(cache.total_size, retained_bytes(&cache));
    }

    /// A flush's block-file fsync and every block read run with the block
    /// store's lock released, as dcrd's `syncBlocks` and `readBlock` take
    /// only read locks (`blockio.go:514-625`).  Holding it across the
    /// fsync made every block read -- P2P getdata, RPC getblock -- wait
    /// out the flush's fsync, and holding it across a read queued the
    /// reads behind one another.
    ///
    /// Checked from inside the I/O, through the block store's test hook:
    /// a lock held across it shows as a failed `try_lock`.
    #[test]
    fn block_reads_and_the_block_file_fsync_run_without_the_store_lock() {
        use std::cell::RefCell;
        use std::rc::Rc;

        let (_dir, db) = new_db();
        let raw = vec![0x5au8; 300];
        // The hash is that of the 180-byte header the bytes start with,
        // and the height the one it records.
        let hash = dcroxide_chainhash::hash_h(&raw[..180]);
        let height = crate::transaction::serialized_block_height(&raw).expect("a header");
        {
            let tx = db.begin(true).expect("begin write");
            tx.store_block_raw(&hash, raw.clone()).expect("store block");
            tx.commit().expect("commit");
        }

        let seen: Rc<RefCell<Vec<(&'static str, bool)>>> = Rc::default();
        let log = Rc::clone(&seen);
        let inner = Arc::clone(&db.inner);
        crate::blockfile::IO_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |what| {
                let unlocked = inner.block_store.try_lock().is_ok();
                log.borrow_mut().push((what, unlocked));
            }));
        });

        // The commit wrote the block to its file; the flush syncs it.
        db.flush().expect("flush");
        {
            let tx = db.begin(false).expect("begin read");
            assert_eq!(tx.fetch_block(&hash, height).expect("fetch block"), raw);
            let region = crate::BlockRegion {
                hash,
                offset: 4,
                len: 8,
            };
            assert_eq!(
                tx.fetch_block_region(&region, height)
                    .expect("fetch region"),
                raw[4..12].to_vec()
            );
        }
        crate::blockfile::IO_HOOK.with(|hook| *hook.borrow_mut() = None);

        let seen = seen.borrow();
        let count = |what: &str| seen.iter().filter(|(w, _)| *w == what).count();
        assert_eq!(
            count("fsync"),
            1,
            "the flush synced the block file: {seen:?}"
        );
        assert_eq!(count("read"), 2, "both fetches read the file: {seen:?}");
        assert!(
            seen.iter().all(|&(_, unlocked)| unlocked),
            "block I/O ran with the block store locked: {seen:?}"
        );
    }

    /// The observer is told how a flush's time divides between its three
    /// phases -- the block-file fsync, the insert loop and the commit --
    /// and, on Linux, the storage I/O the flushing thread did in each and
    /// the processor time it used.  A single `elapsed` over all three
    /// cannot say which phase a stall inside a flush window was in.
    ///
    /// It is told as well who asked for the flush, which thread made its
    /// commit, and what the flushing thread spent in it and waiting
    /// before it.
    #[test]
    fn a_flush_observation_splits_the_flush_into_its_phases() {
        let dir = TempDir::new().expect("tempdir");
        let mut opts = Options::new(dir.path().join("db"), NET);
        // Any row is over this ceiling, for the commit-path flush at the
        // end.
        opts.cache_max_size = 1;
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        opts.flush_observer = Some(Arc::new(move |obs: &crate::FlushObservation| {
            sink.lock().expect("observations").push(*obs);
        }));
        let db = Database::create(&opts).expect("create");
        {
            let tx = db.begin(true).expect("begin write");
            let bucket = tx.metadata().create_bucket(b"cache").expect("create");
            for i in 0..100u32 {
                bucket.put(&i.to_be_bytes(), b"value").expect("put");
            }
            tx.commit().expect("commit");
        }
        db.flush().expect("flush");

        let observations = Arc::clone(&seen);
        let seen = seen.lock().expect("observations");
        let obs = seen.last().expect("the flush was observed");
        let phases =
            obs.block_sync.elapsed + obs.insert.elapsed + obs.commit.elapsed + obs.stats_elapsed;
        assert!(
            phases <= obs.elapsed,
            "the phases ({phases:?}) are parts of the flush ({:?})",
            obs.elapsed
        );
        #[cfg(target_os = "linux")]
        if std::path::Path::new("/proc/thread-self/io").exists() {
            for phase in [obs.block_sync, obs.insert, obs.commit] {
                assert!(
                    phase.read_bytes.is_some() && phase.write_bytes.is_some(),
                    "an observed flush reads the thread's I/O counters: {phase:?}"
                );
            }
        }
        // The processor time of each phase, where the kernel has the
        // file it is read from; nothing anywhere else.
        for phase in [obs.block_sync, obs.insert, obs.commit] {
            let has = thread_self_has;
            assert_eq!(
                (phase.utime_ms.is_some(), phase.stime_ms.is_some()),
                (has("stat"), has("stat")),
                "{phase:?}"
            );
            assert_eq!(
                (phase.on_cpu_ns.is_some(), phase.runq_wait_ns.is_some()),
                (has("schedstat"), has("schedstat")),
                "{phase:?}"
            );
            // A phase is inside the flush, so the thread was on a
            // processor in it for no longer than the flush took, give or
            // take the tick the kernel's figure can trail by at each end.
            let flush = obs.elapsed + Duration::from_millis(20);
            assert!(
                phase.on_cpu_ns.unwrap_or(0) <= flush.as_nanos() as u64,
                "{phase:?} in a flush of {:?}",
                obs.elapsed
            );
            assert_eq!(phase.utime_ms.unwrap_or(0) % 10, 0, "whole ticks");
            assert_eq!(phase.stime_ms.unwrap_or(0) % 10, 0, "whole ticks");
        }
        assert!(obs.commit.to_json().starts_with("{\"ms\":"));
        // `Database::flush` asked for it and its commit ran on the
        // flushing thread, which spent the whole flush in it and waited
        // for no earlier commit first.
        assert!(obs.explicit, "an asked-for flush says so");
        assert!(!obs.background);
        assert_eq!(obs.foreground, obs.elapsed);
        assert_eq!(obs.waited, Duration::ZERO);
        // What it pinned: the one layer the commit above wrote, whose
        // every entry it wrote out.  Nothing was committed while it ran,
        // and no transaction was open to hold the layer past it.
        let memory = obs.memory;
        assert!(!obs.snapshot, "a commit made here is given no snapshot");
        assert_eq!(memory.pinned_layers, 1);
        assert_eq!(memory.pinned_entries, obs.dirty_entries);
        assert_eq!(memory.overlay_at_hand_off, obs.dirty_bytes);
        assert_eq!(memory.overlay_at_retirement, obs.dirty_bytes);
        assert_eq!(memory.layers_at_retirement, 1);
        assert_eq!((memory.shared_layers, memory.shared_entries), (0, 0));
        assert_eq!(
            (
                memory.process_after_previous_finished,
                memory.process_after_previous
            ),
            (None, None),
            "no flush ended before the first"
        );
        #[cfg(target_os = "linux")]
        {
            let at_capture = memory.process_at_capture.expect("read at the capture");
            let at_hand_off = memory.process_at_hand_off.expect("read before the commit");
            let at_commit = memory.process_at_commit.expect("read after the commit");
            assert!(at_capture.resident > 0 && at_capture.threads > 0);
            assert!(
                at_capture.arenas.is_some() && at_commit.arenas.is_some(),
                "the heap's mappings are listed at the capture and after the commit"
            );
            assert_eq!(at_hand_off.arenas, None, "and not in between");
            assert!(at_commit.peak_resident >= at_capture.peak_resident);
        }
        let flushes = seen.len();
        drop(seen);

        // A flush a commit's own check trips is not explicit.  The check
        // comes before the commit's rows are published, so the second of
        // two commits is the one that finds the overlay over its ceiling.
        for key in [b"one", b"two"] {
            let tx = db.begin(true).expect("begin write");
            tx.metadata()
                .bucket(b"cache")
                .expect("bucket")
                .put(key, b"value")
                .expect("put");
            tx.commit().expect("commit");
        }
        let seen = observations.lock().expect("observations");
        assert_eq!(seen.len(), flushes + 1, "the second commit flushed");
        let obs = seen.last().expect("the flush was observed");
        assert!(!obs.explicit, "a commit's own flush is not asked for");
        assert!(!obs.background);
        assert_eq!(obs.foreground, obs.elapsed);
        assert_eq!(obs.waited, Duration::ZERO);
        // The commit that tripped it is still open, with the snapshot it
        // began with: that transaction, not the flush, frees the layer.
        let memory = obs.memory;
        assert_eq!(memory.pinned_layers, 1);
        assert_eq!(
            (memory.shared_layers, memory.shared_entries),
            (1, memory.pinned_entries),
            "the open transaction still names the captured layer"
        );
        assert_eq!(memory.overlay_at_retirement, obs.dirty_bytes);
        #[cfg(target_os = "linux")]
        assert!(
            memory.process_after_previous_finished.is_some()
                && memory.process_after_previous.is_some(),
            "the flush before this one left its readings"
        );
        assert!(
            memory.previous_finished <= memory.previous_release,
            "the participant is told before the layers are freed: {memory:?}"
        );
    }

    /// With no observer nothing of the process is read: the readings are
    /// taken for an observation and for nothing else.
    #[test]
    fn an_unobserved_flush_reads_nothing_of_the_process() {
        let mut cache = DbCache::new();
        let mut puts = BTreeMap::new();
        puts.insert(b"key".to_vec(), b"value".to_vec());
        cache.commit_pending(puts, std::iter::empty());
        let batch = cache.begin_flush();
        assert!(!batch.observed());
        assert_eq!(batch.memory.pinned_layers, 1);
        assert_eq!(batch.memory.pinned_entries, 1);
        assert_eq!(batch.memory.process_at_capture, None);
        assert_eq!(cache.overlay_bytes(), batch.bytes);
        cache.finish_flush(batch, Some(super::FlushOutcome::for_test()));
        assert_eq!(cache.overlay_bytes(), 0);
    }

    /// A phase renders as one JSON object: the three fields it always
    /// had, as they were, then the four processor time fields, `null`
    /// for each counter that was not read.
    #[test]
    fn a_flush_phase_renders_its_counters_after_the_fields_it_had() {
        let phase = crate::FlushPhase {
            elapsed: Duration::from_micros(1_500),
            read_bytes: Some(8192),
            write_bytes: Some(4096),
            utime_ms: Some(30),
            stime_ms: Some(10),
            on_cpu_ns: Some(41_234_567),
            runq_wait_ns: Some(89),
        };
        assert_eq!(
            phase.to_json(),
            concat!(
                r#"{"ms":1.500,"read_bytes":8192,"write_bytes":4096,"#,
                r#""utime_ms":30,"stime_ms":10,"on_cpu_ns":41234567,"runq_wait_ns":89}"#,
            )
        );
        assert_eq!(
            crate::FlushPhase::default().to_json(),
            concat!(
                r#"{"ms":0.000,"read_bytes":null,"write_bytes":null,"#,
                r#""utime_ms":null,"stime_ms":null,"on_cpu_ns":null,"runq_wait_ns":null}"#,
            )
        );
        // Each field is rendered from its own counter.
        let only = |set: fn(&mut crate::FlushPhase)| {
            let mut phase = crate::FlushPhase::default();
            set(&mut phase);
            phase.to_json()
        };
        assert!(only(|p| p.utime_ms = Some(7)).contains(r#""utime_ms":7,"stime_ms":null,"#));
        assert!(only(|p| p.stime_ms = Some(7)).contains(r#""stime_ms":7,"on_cpu_ns":null,"#));
        assert!(only(|p| p.on_cpu_ns = Some(7)).contains(r#""on_cpu_ns":7,"runq_wait_ns":null}"#));
        assert!(
            only(|p| p.runq_wait_ns = Some(7)).ends_with(r#""on_cpu_ns":null,"runq_wait_ns":7}"#)
        );
    }

    /// `utime` and `stime` are found by counting fields from the last
    /// `)` of a stat file, because the thread's name, between the first
    /// `(` and that `)`, can hold anything: spaces, parentheses, text
    /// shaped like the fields that follow it, and bytes that are not
    /// UTF-8.
    #[test]
    fn the_stat_parser_counts_fields_from_the_end_of_the_thread_name() {
        use super::parse_stat_times;

        // The fields after the name, `utime` 111 and `stime` 222 among
        // them, then `cutime` and the rest.
        let rest = " S 1 2 3 4 5 6 7 8 9 10 111 222 13 14 20 0 1 0 99 1000 1 1844\n";
        let stat = |name: &[u8]| [b"4242 (", name, b")", rest.as_bytes()].concat();
        for name in [
            &b"index"[..],
            b"peer outbound",
            b"a (b) c",
            b"))) (((",
            b") R 9 9 9 9 9 9 9 9 9 9 77 88 9",
            b"",
            // Cut at its fifteenth byte, inside a two-byte character.
            b"peer-outbound-\xc3",
            b"\xff\xfe",
        ] {
            assert_eq!(
                parse_stat_times(&stat(name)),
                Some((111, 222)),
                "{:?}",
                String::from_utf8_lossy(name)
            );
        }
        // A real one, of a thread whose name is plain.
        assert_eq!(
            parse_stat_times(
                b"1395644 (cat) R 1395643 1395644 1395643 0 -1 4194304 99 0 0 0 3 5 0 0 12 -8 1 \
                  0 3148778 6635520 575 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 15 0 0 0 \
                  0 0 0 0 0 0 0 0 0 0\n"
            ),
            Some((3, 5))
        );

        // Not a stat file: no name, too few fields after it, or a field
        // that is not a count.
        for bad in [
            &b""[..],
            b"4242 index S 1 2 3 4 5 6 7 8 9 10 111 222 13",
            b"4242 (index) S 1 2 3 4 5 6 7 8 9 10 111",
            b"4242 (index) S 1 2 3 4 5 6 7 8 9 10",
            b"4242 (index) S 1 2 3 4 5 6 7 8 9 10 -1 222",
            b"4242 (index) S 1 2 3 4 5 6 7 8 9 10 111 x",
            b"4242 (index)",
            b"4242 (index) S 1 2 3 4 5 6 7 8 9 10 111 222 \xff",
        ] {
            assert_eq!(
                parse_stat_times(bad),
                None,
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    /// The schedstat file's first two fields are the time on a processor
    /// and the time waiting for one; the third, a count of time slices,
    /// is not read.
    #[test]
    fn the_schedstat_parser_takes_the_two_times() {
        use super::parse_schedstat;

        assert_eq!(parse_schedstat(b"381472 2380 2\n"), Some((381_472, 2_380)));
        assert_eq!(parse_schedstat(b"0 0 0\n"), Some((0, 0)));
        assert_eq!(
            parse_schedstat(b"18446744073709551615 7"),
            Some((u64::MAX, 7))
        );
        for bad in [
            &b""[..],
            b"\n",
            b"381472\n",
            b"381472 x 2\n",
            b"-1 2 3\n",
            b"1 \xff 3\n",
        ] {
            assert_eq!(
                parse_schedstat(bad),
                None,
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    /// How many `/proc` files this thread has asked for so far.
    fn proc_reads() -> u64 {
        super::PROC_READS.with(|reads| reads.get())
    }

    /// Whether this thread's `/proc` entry has `file`: false off Linux.
    fn thread_self_has(file: &str) -> bool {
        cfg!(target_os = "linux")
            && std::path::Path::new("/proc/thread-self")
                .join(file)
                .exists()
    }

    /// The `/proc` reads one observed phase makes: each counter file
    /// that exists once at either end, and one that does not once, at the
    /// start, since a counter that could not be read is not read again.
    /// None off Linux.
    fn reads_of_an_observed_phase() -> u64 {
        if !cfg!(target_os = "linux") {
            return 0;
        }
        ["io", "stat", "schedstat"]
            .into_iter()
            .map(|file| if thread_self_has(file) { 2 } else { 1 })
            .sum()
    }

    /// The `/proc` reads an observed flush makes of the process's memory
    /// ([`crate::FlushMemory`]) when its commit runs on the thread that
    /// captured it: `/proc/self/status` at the capture, at the hand-off,
    /// after the commit, once the participant has been told and at the
    /// end, and `/proc/self/maps` beside the first and the third.  None
    /// off Linux.
    fn reads_of_the_process_in_an_observed_flush() -> u64 {
        if cfg!(target_os = "linux") { 5 + 2 } else { 0 }
    }

    /// Commit two rows over an overlay ceiling that any row is over, so
    /// that the second commit's own flush check trips a flush: the first
    /// commit's row is published after its check.  The flush has
    /// committed when this returns, as every flush of a store without
    /// background commits has by the time its commit returns.
    fn trip_a_commits_flush(db: &Database) {
        let flushed = || db.inner.cache.lock().expect("cache").flush_seq;
        let before = flushed();
        db.inner
            .cache
            .lock()
            .expect("cache")
            .set_limits(1, DEFAULT_FLUSH_SECS);
        commit_one(db, b"tripping-1", b"value");
        commit_one(db, b"tripping-2", b"value");
        assert_eq!(
            flushed(),
            before.saturating_add(1),
            "the second commit flushed"
        );
    }

    /// With no observer nothing is read from `/proc`, by a phase's timer
    /// or by a whole flush, whether `Database::flush` asked for it or a
    /// commit's own check tripped it, and a phase has its wall time and
    /// no counter.  With one, each counter file is read once at either
    /// end of a phase, and the process's memory is read around the flush
    /// ([`reads_of_the_process_in_an_observed_flush`]).  A flush runs on
    /// the thread that calls it, which is this one: the stores are opened
    /// without background commits.
    #[test]
    fn the_counters_are_read_only_for_an_observer() {
        use super::PhaseTimer;

        let before = proc_reads();
        let phase = PhaseTimer::start(false).finish();
        assert_eq!(proc_reads(), before, "an unobserved phase read /proc");
        assert_eq!(
            phase,
            crate::FlushPhase {
                elapsed: phase.elapsed,
                ..crate::FlushPhase::default()
            }
        );

        let (_dir, db) = new_db();
        {
            let tx = db.begin(true).expect("begin write");
            tx.metadata().create_bucket(b"cache").expect("create");
            tx.commit().expect("commit");
        }
        commit_one(&db, b"key", b"value");
        db.flush().expect("flush");
        assert_eq!(proc_reads(), before, "an unobserved flush read /proc");
        trip_a_commits_flush(&db);
        assert_eq!(
            proc_reads(),
            before,
            "an unobserved flush a commit tripped read /proc"
        );
        drop(db);

        // Observed: one phase, then a flush of three.
        let phase = PhaseTimer::start(true).finish();
        let per_phase = reads_of_an_observed_phase();
        assert_eq!(proc_reads() - before, per_phase);
        assert_eq!(
            (phase.read_bytes.is_some(), phase.write_bytes.is_some()),
            (thread_self_has("io"), thread_self_has("io"))
        );
        assert_eq!(
            (phase.utime_ms.is_some(), phase.stime_ms.is_some()),
            (thread_self_has("stat"), thread_self_has("stat"))
        );
        assert_eq!(
            (phase.on_cpu_ns.is_some(), phase.runq_wait_ns.is_some()),
            (thread_self_has("schedstat"), thread_self_has("schedstat"))
        );

        let dir = TempDir::new().expect("tempdir");
        let mut opts = Options::new(dir.path().join("db"), NET);
        let flushes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = Arc::clone(&flushes);
        opts.flush_observer = Some(Arc::new(move |_: &crate::FlushObservation| {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));
        let db = Database::create(&opts).expect("create");
        {
            let tx = db.begin(true).expect("begin write");
            tx.metadata().create_bucket(b"cache").expect("create");
            tx.commit().expect("commit");
        }
        let per_flush = 3 * per_phase + reads_of_the_process_in_an_observed_flush();
        let before = proc_reads();
        let flushed = flushes.load(std::sync::atomic::Ordering::SeqCst);
        db.flush().expect("flush");
        assert_eq!(
            flushes.load(std::sync::atomic::Ordering::SeqCst),
            flushed + 1,
            "the flush was observed"
        );
        assert_eq!(
            proc_reads() - before,
            per_flush,
            "the block sync, the insert loop, the commit and the process"
        );

        // A flush a commit's own check tripped reads as much.
        let before = proc_reads();
        trip_a_commits_flush(&db);
        assert_eq!(
            flushes.load(std::sync::atomic::Ordering::SeqCst),
            flushed + 2,
            "the commit's flush was observed"
        );
        assert_eq!(proc_reads() - before, per_flush);
    }

    /// A flush participant that writes one row under its prefix in every
    /// flush and counts the flushes it wrote in.
    struct OneRow {
        prefix: Vec<u8>,
        contributed: std::sync::atomic::AtomicUsize,
    }

    impl crate::FlushParticipant for OneRow {
        fn wants_flush(&self) -> bool {
            false
        }

        fn has_work(&self) -> bool {
            true
        }

        fn contribute(
            &self,
            w: &mut crate::FlushWriter<'_, '_>,
        ) -> Result<crate::ParticipantStats, crate::Error> {
            let mut key = self.prefix.clone();
            key.push(b'r');
            w.insert(&key, b"row")?;
            self.contributed
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(crate::ParticipantStats::default())
        }

        fn finished(&self, _: bool) {}
    }

    /// Register a [`OneRow`] in `db`, under a bucket made for it and
    /// flushed first.
    fn register_one_row(db: &Database) -> Arc<OneRow> {
        let tx = db.begin(true).expect("begin write");
        let prefix = tx
            .metadata()
            .create_bucket(b"journal")
            .expect("create")
            .raw_id()
            .to_vec();
        tx.commit().expect("commit");
        db.flush().expect("flush the bucket");
        let journal = Arc::new(OneRow {
            prefix: prefix.clone(),
            contributed: std::sync::atomic::AtomicUsize::new(0),
        });
        db.set_flush_participant(
            &prefix,
            Arc::clone(&journal) as Arc<dyn crate::FlushParticipant>,
        )
        .expect("register");
        journal
    }

    /// The participant's part of a flush is a fourth phase, counted as
    /// the other three are.  With no observer a flush the participant
    /// writes in reads nothing from `/proc`; with one, that phase has the
    /// counters of a phase and the flush makes four phases' reads, beside
    /// its readings of the process's memory.
    #[test]
    fn the_participants_phase_is_counted_only_for_an_observer() {
        let contributed = |journal: &OneRow| {
            journal
                .contributed
                .load(std::sync::atomic::Ordering::SeqCst)
        };

        let (_dir, db) = new_db();
        let journal = register_one_row(&db);
        let before = proc_reads();
        db.flush().expect("flush");
        assert_eq!(contributed(&journal), 1, "the participant wrote");
        assert_eq!(
            proc_reads(),
            before,
            "an unobserved flush with a participant read /proc"
        );
        drop(db);

        let dir = TempDir::new().expect("tempdir");
        let mut opts = Options::new(dir.path().join("db"), NET);
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        opts.flush_observer = Some(Arc::new(move |obs: &crate::FlushObservation| {
            sink.lock().expect("observations").push(*obs);
        }));
        let db = Database::create(&opts).expect("create");
        let journal = register_one_row(&db);
        let before = proc_reads();
        let observed = seen.lock().expect("observations").len();
        db.flush().expect("flush");
        assert_eq!(contributed(&journal), 1, "the participant wrote");
        assert_eq!(
            proc_reads() - before,
            4 * reads_of_an_observed_phase() + reads_of_the_process_in_an_observed_flush(),
            "the block sync, the insert loop, the participant, the commit and the process"
        );
        let obs = {
            let seen = seen.lock().expect("observations");
            assert_eq!(seen.len(), observed + 1, "the flush was observed");
            *seen.last().expect("the flush was observed")
        };
        let phase = obs.participant.expect("the participant's part").contribute;
        let has = thread_self_has;
        assert_eq!(
            (phase.read_bytes.is_some(), phase.write_bytes.is_some()),
            (has("io"), has("io")),
            "{phase:?}"
        );
        assert_eq!(
            (phase.utime_ms.is_some(), phase.stime_ms.is_some()),
            (has("stat"), has("stat")),
            "{phase:?}"
        );
        assert_eq!(
            (phase.on_cpu_ns.is_some(), phase.runq_wait_ns.is_some()),
            (has("schedstat"), has("schedstat")),
            "{phase:?}"
        );
        assert!(
            phase.elapsed <= obs.elapsed,
            "{phase:?} in {:?}",
            obs.elapsed
        );
    }

    /// A phase's processor time is the flushing thread's own over that
    /// phase and no more.  A phase spent computing shows about as much
    /// time on a processor as it took, nearly all of it in user mode, and
    /// the two files the figures come from agree.  A phase spent asleep
    /// straight after it shows next to none, though the thread's totals
    /// by then hold all of the first and another thread of the process
    /// computes throughout.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_phase_reports_the_processor_time_of_that_phase() {
        use super::PhaseTimer;

        /// Compute for `wall`, never sleeping: the calling thread is on
        /// a processor or waiting for one throughout.
        fn compute_for(wall: Duration) -> u64 {
            let began = Instant::now();
            let mut x = 1u64;
            while began.elapsed() < wall {
                for i in 0..10_000u64 {
                    x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(i);
                    x = std::hint::black_box(x);
                }
            }
            x
        }

        if !thread_self_has("stat") || !thread_self_has("schedstat") {
            return;
        }
        let ms = |nanos: u64| nanos / 1_000_000;

        let timer = PhaseTimer::start(true);
        compute_for(Duration::from_millis(400));
        let busy = timer.finish();
        let elapsed = busy.elapsed.as_millis() as u64;
        let (utime, stime) = (busy.utime_ms.expect("utime"), busy.stime_ms.expect("stime"));
        let on_cpu = ms(busy.on_cpu_ns.expect("on_cpu"));
        let waited = ms(busy.runq_wait_ns.expect("runq_wait"));
        if super::thread_sched() == Some((0, 0)) {
            // A kernel that keeps no scheduler accounting.
            return;
        }
        assert!(on_cpu <= elapsed + 20, "{busy:?}");
        assert!(on_cpu + waited + 20 >= elapsed / 2, "{busy:?}");
        assert!((utime + stime).abs_diff(on_cpu) <= 50, "{busy:?}");
        assert!(utime >= stime, "a loop in user mode: {busy:?}");

        // Asleep, beside a thread that computes from before the phase
        // until after it.  The short sleep ahead of the phase has the
        // kernel bring this thread's times up to date as it is switched
        // out, so the tick they can trail by after the computing above
        // is not counted into the phase, however long the kernel's tick.
        let other = std::thread::spawn(|| compute_for(Duration::from_millis(250)));
        std::thread::sleep(Duration::from_millis(1));
        let timer = PhaseTimer::start(true);
        std::thread::sleep(Duration::from_millis(100));
        let idle = timer.finish();
        other.join().expect("the computing thread");
        assert!(idle.elapsed >= Duration::from_millis(100), "{idle:?}");
        assert!(ms(idle.on_cpu_ns.expect("on_cpu")) <= 25, "{idle:?}");
        assert!(
            idle.utime_ms.expect("utime") + idle.stime_ms.expect("stime") <= 30,
            "{idle:?}"
        );
    }

    /// The flush writes from the merged view, so it has to be exercised
    /// against a real layer stack: with one layer the merge is a no-op and
    /// a flush that resolved duplicates in the wrong direction would still
    /// pass.  This drives a three-deep stack through the public API and
    /// checks that the flush persists the newest value for a key rewritten
    /// in every layer, and honours a deletion that shadows an older value.
    #[test]
    fn a_flush_resolves_duplicates_to_the_newest_layer() {
        let (_dir, db) = new_db();
        {
            let tx = db.begin(true).expect("begin write");
            tx.metadata().create_bucket(b"cache").expect("create");
            tx.commit().expect("commit");
        }

        // Oldest layer: wide, so the merge rule cannot fold the next one
        // into it.  `shadowed` and `gone` both start here.
        {
            let tx = db.begin(true).expect("begin write");
            let bucket = tx.metadata().bucket(b"cache").expect("bucket");
            bucket.put(b"shadowed", b"oldest").expect("put");
            bucket.put(b"gone", b"present").expect("put");
            for i in 0..38u32 {
                bucket
                    .put(format!("bottom-{i:04}").as_bytes(), b"x")
                    .expect("put");
            }
            tx.commit().expect("commit");
        }

        // A held reader freezes that layer, so the next commit seals its
        // own on top of it — and a second reader freezes that one in turn.
        let pin_bottom = db.begin(false).expect("begin read");
        {
            let tx = db.begin(true).expect("begin write");
            let bucket = tx.metadata().bucket(b"cache").expect("bucket");
            bucket.put(b"shadowed", b"middle").expect("put");
            for i in 0..7u32 {
                bucket
                    .put(format!("middle-{i:04}").as_bytes(), b"x")
                    .expect("put");
            }
            tx.commit().expect("commit");
        }
        let pin_middle = db.begin(false).expect("begin read");
        {
            let tx = db.begin(true).expect("begin write");
            let bucket = tx.metadata().bucket(b"cache").expect("bucket");
            bucket.put(b"shadowed", b"newest").expect("put");
            bucket.delete(b"gone").expect("delete");
            tx.commit().expect("commit");
        }

        let depth = db.overlay_layer_count();
        assert!(
            depth > 1,
            "the flush must be exercised against a real layer stack, got \
             {depth} layer(s)"
        );

        // The two pinned readers each still see the overlay they began
        // with, which is what makes the layers below genuinely frozen.
        {
            let bucket = pin_bottom.metadata().bucket(b"cache").expect("bucket");
            assert_eq!(bucket.get(b"shadowed"), Some(b"oldest".to_vec()));
            assert_eq!(bucket.get(b"gone"), Some(b"present".to_vec()));
        }
        {
            let bucket = pin_middle.metadata().bucket(b"cache").expect("bucket");
            assert_eq!(bucket.get(b"shadowed"), Some(b"middle".to_vec()));
            assert_eq!(bucket.get(b"gone"), Some(b"present".to_vec()));
        }
        drop(pin_bottom);
        drop(pin_middle);

        // Flush the stack and read back from the durable store: the
        // newest layer's value must be what landed, and the deletion must
        // have removed the older value rather than falling through to it.
        db.flush().expect("flush");
        assert_eq!(
            db.overlay_layer_count(),
            0,
            "the flush must clear the overlay"
        );
        let tx = db.begin(false).expect("begin read");
        let bucket = tx.metadata().bucket(b"cache").expect("bucket");
        assert_eq!(
            bucket.get(b"shadowed"),
            Some(b"newest".to_vec()),
            "the flush wrote a shadowed older value over the newest one"
        );
        assert_eq!(
            bucket.get(b"gone"),
            None,
            "the flush did not carry the deletion through"
        );
        assert_eq!(bucket.get(b"bottom-0000"), Some(b"x".to_vec()));
        assert_eq!(bucket.get(b"middle-0000"), Some(b"x".to_vec()));
    }

    /// The geometric merge rule must keep the stack collapsing back toward
    /// a single layer.  Every cache miss probes each layer in turn before
    /// it can answer "not cached", so depth is a direct multiplier on that
    /// path — and with only the [`MAX_LAYERS`] ceiling to hold it, a
    /// workload that snapshots before every commit pins the stack at the
    /// ceiling permanently (measured: 493 of 500 commits at eight layers,
    /// against a distribution centred on three with the rule in place).
    /// Deleting the rule leaves every other test in this module green, so
    /// this is the guard that notices.
    #[test]
    fn the_merge_rule_keeps_the_stack_shallow() {
        const KEYS: usize = 64;
        const ROUNDS: usize = 500;

        let mut cache = DbCache::new();
        // A reader snapshots before every commit, so no commit may write
        // in place and every one of them seals a layer.
        let mut pins = Vec::new();
        let mut depths = Vec::with_capacity(ROUNDS);
        for round in 0..ROUNDS {
            pins.push(Arc::clone(&cache.cached));
            let mut puts = BTreeMap::new();
            puts.insert(format!("k{:04}", round % KEYS).into_bytes(), vec![7u8; 8]);
            cache.commit_pending(puts, std::iter::empty());
            depths.push(cache.cached.layers.len());
        }

        let shallow = depths.iter().filter(|&&d| d <= 2).count();
        let total: usize = depths.iter().sum();
        // With the rule: 137 of 500 commits leave two layers or fewer, and
        // the mean depth is 3.0.  Without it: 2 of 500, and 7.97.
        assert!(
            shallow * 10 >= ROUNDS,
            "only {shallow} of {ROUNDS} commits left the stack two layers or \
             fewer, so it is settling at the ceiling instead of collapsing"
        );
        assert!(
            total * 2 < ROUNDS * MAX_LAYERS,
            "the mean layer depth is {:.2} against a ceiling of {MAX_LAYERS}, \
             so the stack is pinned near it",
            total as f64 / ROUNDS as f64
        );
    }

    /// How many entries this thread's merges have walked so far.
    fn merge_inserts() -> u64 {
        super::MERGE_INSERTS.with(|n| n.get())
    }

    /// Commit `rows` puts of an eight-byte value, keyed `<tag>-<i>`.
    fn commit_rows(cache: &mut DbCache, tag: &str, rows: usize) {
        let puts = (0..rows)
            .map(|i| (format!("{tag}-{i:06}").into_bytes(), vec![0x5a; 8]))
            .collect();
        cache.commit_pending(puts, std::iter::empty());
    }

    /// The overlay as one flat map, from the merged view.
    fn flat(cache: &DbCache) -> FlatView {
        cache
            .cached
            .merged()
            .map(|(k, v)| (k.to_vec(), v.clone()))
            .collect()
    }

    /// A layer that a reader's snapshot made a commit seal folds back
    /// into the layer below at the first commit that finds no snapshot
    /// naming that layer, whatever the two layers' sizes, and the fold
    /// walks only the rows the sealed layer took, never the wide layer
    /// below.  While the reader holds its snapshot, its layer stays in
    /// the stack as it is, with no copy taken.
    ///
    /// The geometric rule alone leaves the split for as long as the new
    /// layer is under half the old one, here 498 more rows: this is the
    /// stack the exists-address index's tip read, a snapshot open while
    /// the block thread commits, kept three to four layers deep in the
    /// flushes of a sync, where the index-off syncs kept one.
    #[test]
    fn a_layer_a_reader_split_off_folds_back_once_the_reader_lets_go() {
        let mut cache = DbCache::new();
        commit_rows(&mut cache, "bottom", 1000);
        assert_eq!(cache.cached.layers.len(), 1);

        let reader = Arc::clone(&cache.cached);
        let frozen = flat(&cache);
        commit_rows(&mut cache, "split", 2);
        assert_eq!(cache.cached.layers.len(), 2, "the reader froze the layer");
        assert!(
            Arc::ptr_eq(&cache.cached.layers[1], &reader.layers[0]),
            "the reader's layer is still the one below, not a copy of it"
        );

        // Still held: the commit writes into the new layer in place and
        // merges nothing.
        let before = merge_inserts();
        commit_rows(&mut cache, "held", 1);
        assert_eq!(cache.cached.layers.len(), 2);
        assert!(Arc::ptr_eq(&cache.cached.layers[1], &reader.layers[0]));
        assert_eq!(merge_inserts(), before, "nothing merged under the reader");

        // Let go: the next commit folds the three rows above into the
        // wide layer, and walks only those three and its own one.
        let reader_view: FlatView = reader
            .merged()
            .map(|(k, v)| (k.to_vec(), v.clone()))
            .collect();
        assert_eq!(reader_view, frozen, "the reader saw no commit after it");
        drop(reader);
        commit_rows(&mut cache, "after", 1);
        assert_eq!(
            cache.cached.layers.len(),
            1,
            "the split layer did not fold back once no reader held the layer below"
        );
        assert_eq!(
            merge_inserts() - before,
            4,
            "the fold walked the wide layer"
        );
        assert_eq!(cache.cached.layers[0].len(), 1004);
        assert_eq!(cache.total_size, retained_bytes(&cache));
        assert_eq!(cache.total_size, logical_bytes(&cache));
    }

    /// The fold goes on down the stack: a stack two readers split three
    /// deep, with layers the geometric rule leaves alone (10 rows over
    /// 100 over 1000), is back to one layer at the first commit after
    /// both let go.  Each fold walks the smaller layer, so the cascade
    /// walks the rows above the wide layer and never the wide layer.
    #[test]
    fn a_stack_three_deep_folds_to_one_at_the_first_commit_no_reader_overlaps() {
        let mut cache = DbCache::new();
        commit_rows(&mut cache, "base", 1000);
        let first = Arc::clone(&cache.cached);
        commit_rows(&mut cache, "mid", 100);
        let second = Arc::clone(&cache.cached);
        commit_rows(&mut cache, "top", 10);
        assert_eq!(cache.cached.layers.len(), 3, "each reader froze a layer");
        let mut expected: BTreeMap<Vec<u8>, Option<Vec<u8>>> = flat(&cache).into_iter().collect();

        drop((first, second));
        let before = merge_inserts();
        commit_rows(&mut cache, "after", 1);
        expected.insert(b"after-000000".to_vec(), Some(vec![0x5a; 8]));
        assert_eq!(
            cache.cached.layers.len(),
            1,
            "the folds stopped short of the bottom layer"
        );
        // The top layer, with this commit's row, folds into the middle
        // one (11 entries walked), and that into the base (111 walked).
        assert_eq!(
            merge_inserts() - before,
            11 + 111,
            "a fold walked the wide layer"
        );
        assert_eq!(cache.cached.layers[0].len(), 1111);
        assert_eq!(flat(&cache), expected.into_iter().collect::<FlatView>());
        assert_eq!(cache.total_size, retained_bytes(&cache));
        assert_eq!(cache.total_size, logical_bytes(&cache));
    }

    /// The pattern of a sync with the exists-address index on: once a
    /// block, a reader holds a snapshot across one commit, and the
    /// block's other commits run with no reader.  Every commit with no
    /// reader leaves one layer, and a flush captures one, where the
    /// geometric rule alone left the stack two deep until the split-off
    /// layer reached half the one below.
    ///
    /// A key rewritten in every block, and a key deleted under the
    /// reader and written again after it, keep the folded view equal to
    /// a flat map's, with the size accounting equal to what the one
    /// layer holds.
    #[test]
    fn a_reader_over_one_commit_a_block_leaves_one_layer_to_capture() {
        let mut cache = DbCache::new();
        commit_rows(&mut cache, "bottom", 1000);
        let mut expected: BTreeMap<Vec<u8>, Option<Vec<u8>>> = flat(&cache).into_iter().collect();
        for block in 0..200u32 {
            let reader = Arc::clone(&cache.cached);
            let mut puts = BTreeMap::new();
            puts.insert(b"hot".to_vec(), block.to_be_bytes().to_vec());
            puts.insert(format!("blk-{block:06}").into_bytes(), vec![1; 4]);
            let gone = format!("bottom-{:06}", block % 1000).into_bytes();
            cache.commit_pending(puts.clone(), std::iter::once(gone.clone()));
            assert_eq!(
                cache.cached.layers.len(),
                2,
                "block {block}: the reader froze the layer"
            );
            for (key, value) in puts {
                expected.insert(key, Some(value));
            }
            expected.insert(gone.clone(), None);
            drop(reader);
            for commit in 0..3u32 {
                let mut puts = BTreeMap::new();
                puts.insert(format!("row-{block:06}-{commit}").into_bytes(), vec![2; 6]);
                if commit == 2 {
                    puts.insert(gone.clone(), b"back".to_vec());
                }
                cache.commit_pending(puts.clone(), std::iter::empty());
                assert_eq!(
                    cache.cached.layers.len(),
                    1,
                    "block {block}, commit {commit}: no reader, yet the stack is split"
                );
                for (key, value) in puts {
                    expected.insert(key, Some(value));
                }
            }
        }
        assert_eq!(flat(&cache), expected.into_iter().collect::<FlatView>());
        assert_eq!(cache.total_size, retained_bytes(&cache));
        let batch = cache.begin_flush();
        assert_eq!(batch.memory.pinned_layers, 1);
        cache.finish_flush(batch, Some(super::FlushOutcome::for_test()));
        assert!(cache.cached.layers.is_empty());
    }

    /// A merge walks the smaller of its two layers into the larger, and
    /// leaves the same map and reclaims the same bytes whichever it
    /// walks: the newer entry wins for a key both hold, a pending
    /// deletion included, and the older copy's bytes are reclaimed.
    /// Checked against a merge done the obvious way, for layers of
    /// either size order, either of them still named by a snapshot or
    /// not, and the snapshot's layer left as it was.
    #[test]
    fn a_merge_walks_the_smaller_layer_and_the_newer_entry_wins() {
        /// A layer of `len` entries over keys drawn from a small space,
        /// so the two layers share keys; about one in four a deletion.
        fn layer(len: usize, seed: &mut u64) -> super::CacheLayer {
            let mut map = super::CacheLayer::new();
            while map.len() < len {
                *seed ^= *seed << 13;
                *seed ^= *seed >> 7;
                *seed ^= *seed << 17;
                let key = format!("k{:05}", *seed % 400).into_bytes();
                let entry = (!seed.is_multiple_of(4)).then(|| vec![0xab; (*seed % 37) as usize]);
                map.insert(key, entry);
            }
            map
        }

        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for (newer_len, older_len) in [
            (0, 5),
            (5, 0),
            (3, 100),
            (100, 3),
            (50, 50),
            (51, 50),
            (50, 51),
            (1, 300),
            (300, 1),
            (150, 200),
            (200, 150),
        ] {
            for (newer_shared, older_shared) in
                [(false, false), (true, false), (false, true), (true, true)]
            {
                let newer = layer(newer_len, &mut seed);
                let older = layer(older_len, &mut seed);

                // The obvious merge: the older map, overwritten by the
                // newer, counting each older copy overwritten.
                let mut want = older.clone();
                let mut want_reclaimed = 0u64;
                for (key, entry) in &newer {
                    if let Some(shadowed) = want.insert(key.clone(), entry.clone()) {
                        want_reclaimed += node_size(key.len(), shadowed.as_deref());
                    }
                }

                let (newer_copy, older_copy) = (newer.clone(), older.clone());
                let mut layers = vec![Arc::new(newer), Arc::new(older)];
                let snapshot_newer = newer_shared.then(|| Arc::clone(&layers[0]));
                let snapshot_older = older_shared.then(|| Arc::clone(&layers[1]));
                let before = merge_inserts();
                let reclaimed = super::merge_newest_pair(&mut layers);
                let case = format!(
                    "newer {newer_len} (shared {newer_shared}), older {older_len} (shared \
                     {older_shared})"
                );
                assert_eq!(layers.len(), 1, "{case}");
                assert_eq!(*layers[0], want, "{case}");
                assert_eq!(reclaimed, want_reclaimed, "{case}");
                assert_eq!(
                    merge_inserts() - before,
                    newer_len.min(older_len) as u64,
                    "{case}: the merge did not walk the smaller layer"
                );
                if let Some(snapshot) = snapshot_newer {
                    assert_eq!(*snapshot, newer_copy, "{case}");
                }
                if let Some(snapshot) = snapshot_older {
                    assert_eq!(*snapshot, older_copy, "{case}");
                }
            }
        }
    }

    /// Layers committed beside a flush in flight fold among themselves
    /// and leave the captured layer in place: with a reader over one
    /// commit, the stack above the captured layer is back to one layer
    /// at the next commit with no reader, the captured layer is still
    /// the tail and the same `Arc`, and the retirement leaves exactly the
    /// rows committed beside the flush.
    ///
    /// That no fold reaches into the captured layers this test cannot
    /// show on its own, since the flush's handle keeps them shared
    /// whatever [`compact`]'s barrier says; the barrier is pinned by
    /// `a_commit_during_a_flush_neither_merges_into_it_nor_is_lost_by_it`.
    #[test]
    fn layers_committed_beside_a_flush_fold_among_themselves() {
        let mut cache = DbCache::new();
        commit_rows(&mut cache, "captured", 1000);
        let captured = Arc::clone(&cache.cached.layers[0]);
        let batch = cache.begin_flush();

        commit_rows(&mut cache, "beside", 10);
        assert_eq!(cache.cached.layers.len(), 2, "the flush froze its layer");
        let reader = Arc::clone(&cache.cached);
        commit_rows(&mut cache, "read", 2);
        assert_eq!(
            cache.cached.layers.len(),
            3,
            "the reader froze the layer above"
        );
        drop(reader);
        commit_rows(&mut cache, "after", 1);
        assert_eq!(
            cache.cached.layers.len(),
            2,
            "the layers above the flush did not fold together"
        );
        assert!(
            Arc::ptr_eq(&cache.cached.layers[1], &captured),
            "the captured layer is no longer the tail"
        );
        drop(captured);

        cache.finish_flush(batch, Some(super::FlushOutcome::for_test()));
        assert_eq!(cache.cached.layers.len(), 1);
        let keys: Vec<Vec<u8>> = flat(&cache).into_iter().map(|(k, _)| k).collect();
        let mut want: Vec<Vec<u8>> = (0..10)
            .map(|i| format!("beside-{i:06}"))
            .chain([
                "after-000000".into(),
                "read-000000".into(),
                "read-000001".into(),
            ])
            .map(String::into_bytes)
            .collect();
        want.sort();
        assert_eq!(
            keys, want,
            "the retirement kept other rows than those committed beside it"
        );
        assert_eq!(cache.total_size, retained_bytes(&cache));
    }

    /// Through transactions: readers that began before a commit keep the
    /// view they began with while later commits seal, merge and fold the
    /// layers around them, and once none is left the next commit returns
    /// the overlay to one layer holding the newest value of every key.
    #[test]
    fn readers_keep_their_view_while_the_layers_around_them_fold() {
        let (_dir, db) = new_db();
        {
            let tx = db.begin(true).expect("begin write");
            let bucket = tx.metadata().create_bucket(b"cache").expect("create");
            for i in 0..100u32 {
                bucket
                    .put(format!("row-{i:04}").as_bytes(), b"0")
                    .expect("put");
            }
            tx.commit().expect("commit");
        }
        let write = |puts: &[(&str, &[u8])], deletes: &[&str]| {
            let tx = db.begin(true).expect("begin write");
            let bucket = tx.metadata().bucket(b"cache").expect("bucket");
            for (key, value) in puts {
                bucket.put(key.as_bytes(), value).expect("put");
            }
            for key in deletes {
                bucket.delete(key.as_bytes()).expect("delete");
            }
            tx.commit().expect("commit");
        };
        let read = |tx: &crate::Transaction, key: &str| {
            tx.metadata()
                .bucket(b"cache")
                .expect("bucket")
                .get(key.as_bytes())
        };

        let first = db.begin(false).expect("begin read");
        write(&[("row-0000", b"1"), ("new-a", b"1")], &["row-0001"]);
        let second = db.begin(false).expect("begin read");
        write(&[("row-0000", b"2")], &["new-a"]);
        assert!(db.overlay_layer_count() > 1, "the readers split the stack");
        drop(first);
        write(&[("row-0002", b"3")], &[]);
        let third = db.begin(false).expect("begin read");
        write(&[("row-0000", b"4"), ("new-b", b"4")], &[]);
        drop(second);
        write(&[("row-0003", b"5")], &[]);
        assert!(
            db.overlay_layer_count() > 1,
            "the third reader holds the layer below"
        );

        assert_eq!(read(&third, "row-0000"), Some(b"2".to_vec()));
        assert_eq!(read(&third, "row-0001"), None);
        assert_eq!(read(&third, "row-0002"), Some(b"3".to_vec()));
        assert_eq!(read(&third, "row-0003"), Some(b"0".to_vec()));
        assert_eq!(read(&third, "new-a"), None);
        assert_eq!(read(&third, "new-b"), None);
        drop(third);

        write(&[("row-0004", b"6")], &[]);
        assert_eq!(
            db.overlay_layer_count(),
            1,
            "no reader is left, yet the commit left the stack split"
        );
        let tx = db.begin(false).expect("begin read");
        for (key, want) in [
            ("row-0000", Some(&b"4"[..])),
            ("row-0001", None),
            ("row-0002", Some(b"3")),
            ("row-0003", Some(b"5")),
            ("row-0004", Some(b"6")),
            ("row-0005", Some(b"0")),
            ("new-a", None),
            ("new-b", Some(b"4")),
        ] {
            assert_eq!(read(&tx, key).as_deref(), want, "{key}");
        }
        tx.rollback().expect("rollback");
    }

    /// The layers a flush retired are freed by the thread that flushed,
    /// once it has released the writer semaphore, and so after the cache
    /// lock too, which it let go before that.  `flush_locked` hands them
    /// back alive.  A commit that flushed still holds them when its hooks
    /// run and when it releases the semaphore, as `Database::flush` does
    /// when it releases its own, and they are gone once either has
    /// returned.  So the next writer does not wait for the frees.
    ///
    /// That is every flush of a store opened without background commits,
    /// as this one is, and every flush `Database::flush` asks for, but
    /// the flush of `Database::close`, which drops the layers where it
    /// flushed, under the semaphore: no transaction begins behind a
    /// close.  A flush whose commit is handed to a thread of its own is
    /// retired by that thread, which holds no semaphore and lets go of
    /// the layers itself; `flush_locked` hands back none of them.
    ///
    /// The count at each release is read by the probe the release runs
    /// on this thread, [`crate::RELEASE_HOOK`].
    #[test]
    fn the_layers_a_flush_retired_are_freed_once_the_writer_is_released() {
        use std::cell::RefCell;
        use std::rc::Rc;
        let (_dir, db) = new_db();
        {
            let tx = db.begin(true).expect("begin write");
            tx.metadata().create_bucket(b"cache").expect("create");
            tx.commit().expect("commit");
        }
        // A weak handle on the overlay's one layer.
        let layer = || {
            let cache = db.inner.cache.lock().expect("cache");
            assert_eq!(cache.cached.layers.len(), 1);
            Arc::downgrade(&cache.cached.layers[0])
        };
        let published = || db.inner.cache.lock().expect("cache").cached.layers.len();
        // The handles on `layer` at each release of the writer semaphore
        // that `act` makes.
        let at_each_release = |layer: &std::sync::Weak<super::CacheLayer>, act: &dyn Fn()| {
            let counts = Rc::new(RefCell::new(Vec::new()));
            let (seen, layer) = (Rc::clone(&counts), layer.clone());
            crate::RELEASE_HOOK.with(|hook| {
                let count = move || seen.borrow_mut().push(layer.strong_count());
                *hook.borrow_mut() = Some(Box::new(count));
            });
            act();
            crate::RELEASE_HOOK.with(|hook| *hook.borrow_mut() = None);
            counts.take()
        };

        // The flush itself, under the writer: unpublished, handed back,
        // and freed when the caller drops what it was handed.
        let retiring = layer();
        let writer = db.exclusive_writer();
        let retired = crate::flush_locked(&db.inner, false).expect("flush");
        assert_eq!(published(), 0);
        assert_eq!(retired.len(), 1);
        assert_eq!(retiring.strong_count(), 1, "the flush freed it");
        drop(writer);
        drop(retired);
        assert_eq!(retiring.strong_count(), 0);

        // `Database::flush`: its handle is the only one left when it
        // releases the writer, and is gone when it returns.
        commit_one(&db, b"k1", b"v1");
        let retiring = layer();
        let held = at_each_release(&retiring, &|| db.flush().expect("flush"));
        assert_eq!(held, [1], "freed before the writer was released");
        assert_eq!((published(), retiring.strong_count()), (0, 0));

        // A commit whose own flush retires the layer its snapshot names.
        // In its hook the snapshot and the commit's handle both hold it;
        // at the release the snapshot has gone and the handle has not.
        commit_one(&db, b"k2", b"v2");
        let retiring = layer();
        db.inner
            .cache
            .lock()
            .expect("cache")
            .set_limits(1, DEFAULT_FLUSH_SECS);
        let tx = db.begin(true).expect("begin write");
        let bucket = tx.metadata().bucket(b"cache").expect("bucket");
        bucket.put(b"k3", b"v3").expect("put");
        let in_hook = Arc::new(std::sync::atomic::AtomicUsize::new(usize::MAX));
        let (seen, handles) = (Arc::clone(&in_hook), retiring.clone());
        tx.on_commit(move || {
            seen.store(handles.strong_count(), std::sync::atomic::Ordering::SeqCst);
        })
        .expect("hook");
        let held = at_each_release(&retiring, &|| tx.commit().expect("commit"));
        assert_eq!(in_hook.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(held, [1], "freed before the writer was released");
        assert_eq!(retiring.strong_count(), 0, "it outlived the commit");
        // What is published now is the commit's own row, in a new layer.
        assert_eq!(published(), 1);
        let tx = db.begin(false).expect("begin read");
        let bucket = tx.metadata().bucket(b"cache").expect("bucket");
        for key in [&b"k1"[..], b"k2", b"k3"] {
            assert!(bucket.get(key).is_some(), "{key:?} is missing");
        }
        tx.rollback().expect("rollback");
    }
}

#[cfg(test)]
mod participant_guard_tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use tempfile::TempDir;

    use super::DbCache;
    use crate::participant::Registration;
    use crate::{Database, Error, FlushParticipant, FlushWriter, Options, ParticipantStats};

    /// A participant that always has work and must never be reached.
    struct Unreachable;

    impl FlushParticipant for Unreachable {
        fn wants_flush(&self) -> bool {
            false
        }

        fn has_work(&self) -> bool {
            true
        }

        fn contribute(&self, _: &mut FlushWriter<'_, '_>) -> Result<ParticipantStats, Error> {
            panic!("contribute ran after the overlay guard should have failed the flush");
        }

        fn finished(&self, _: bool) {}
    }

    /// The flush's backstop against an overlay row under the participant's
    /// prefix, which would shadow the participant's rows for every reader.
    ///
    /// Registration and commit both refuse to create such a row, so no
    /// public path reaches this; the row is put into the cache directly.
    /// A debug build stops at the assertion, a release build fails the
    /// flush before the participant is called -- the error `flush_locked`
    /// latches.
    #[test]
    #[cfg_attr(
        debug_assertions,
        should_panic(expected = "an overlay row lies under the flush participant's prefix")
    )]
    fn a_flush_refuses_an_overlay_row_under_the_participant_prefix() {
        let dir = TempDir::new().expect("tempdir");
        let db =
            Database::create(&Options::new(dir.path().join("db"), 0x1214_1c16)).expect("create");
        let prefix: Arc<[u8]> = Arc::from(&[0u8, 0, 0, 9][..]);
        let mut puts = BTreeMap::new();
        puts.insert(vec![0u8, 0, 0, 9, b'x'], b"shadow".to_vec());
        let mut cache = db.inner.cache.lock().expect("cache");
        cache.commit_pending(puts, std::iter::empty());
        let batch = cache.begin_flush();
        let registration = Registration {
            prefix,
            participant: Arc::new(Unreachable),
        };
        let mut contributed = false;
        let result = DbCache::run_flush(
            &batch,
            &db.inner.kv,
            &db.inner.block_store,
            Some(&registration),
            &mut contributed,
        );
        let err = result.err().expect("the flush must fail");
        assert_eq!(err.kind, crate::ErrorKind::IncompatibleValue, "{err}");
        assert!(!contributed, "the participant was not called");
        cache.finish_flush(batch, None);
    }
}

#[cfg(test)]
mod flush_barrier_tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use super::{DbCache, FlushOutcome};

    fn put(cache: &mut DbCache, keys: &[&str]) {
        let mut puts = BTreeMap::new();
        for k in keys {
            puts.insert(k.as_bytes().to_vec(), vec![0xcc; 8]);
        }
        cache.commit_pending(puts, std::iter::empty());
    }

    /// A commit landing WHILE a flush is in flight must not lose either
    /// side, and the captured layers must still be identifiable when the
    /// commit returns.
    ///
    /// This interleaving cannot occur through the public API today —
    /// every flush call site holds the writer semaphore for its whole
    /// duration, so no second writer can reach `commit_pending`. It is
    /// forced here because the barrier that makes it safe would
    /// otherwise be untested code that first runs for real when the
    /// commit moves to a background thread.
    ///
    /// Without the `pinned` argument to `compact`, this fails: the new
    /// layer and the captured one satisfy the geometric merge rule, get
    /// folded into one fresh `Arc`, and retirement then either drops the
    /// new layer's writes or matches nothing at all.
    #[test]
    fn a_commit_during_a_flush_neither_merges_into_it_nor_is_lost_by_it() {
        let mut cache = DbCache::new();
        put(&mut cache, &["captured-a", "captured-b", "captured-c"]);
        let captured = cache.cached.layers.clone();
        assert_eq!(captured.len(), 1, "setup: one layer to capture");

        let batch = cache.begin_flush();
        assert_eq!(
            cache.total_size, 0,
            "captured bytes leave the flush trigger"
        );

        // The concurrent writer. Sized so `compact`'s geometric rule
        // WOULD fire — `layers[0].len() * 2 >= layers[1].len()`, i.e.
        // 2*2 >= 3 — because a smaller layer leaves the merge dormant
        // and the test vacuous. Checked by removing the barrier and
        // watching this fail.
        put(&mut cache, &["fresh-1", "fresh-2"]);
        assert_eq!(
            cache.cached.layers.len(),
            2,
            "the barrier must keep the captured layer out of the merge"
        );
        assert!(
            Arc::ptr_eq(&cache.cached.layers[1], &captured[0]),
            "the captured layer must still be the tail, and the same Arc"
        );

        cache.finish_flush(batch, Some(FlushOutcome::for_test()));

        assert_eq!(cache.cached.layers.len(), 1, "the captured layer retired");
        assert!(
            !Arc::ptr_eq(&cache.cached.layers[0], &captured[0]),
            "what remains is the writer's layer, not the retired one"
        );
        let view = &cache.cached;
        assert!(
            view.get(b"fresh-1").is_some() && view.get(b"fresh-2").is_some(),
            "the concurrent commit's write survived the retirement"
        );
        assert!(
            view.get(b"captured-a").is_none(),
            "the flushed keys left the overlay -- they are in the store now"
        );
    }

    /// A store over storage whose power a test can cut, with a bucket
    /// `rows` holding two rows in the overlay, in one layer; and a weak
    /// handle on that layer.
    fn store_with_a_layer() -> (
        tempfile::TempDir,
        Arc<dcroxide_testutil::powerloss::PowerLossBackend>,
        crate::Database,
        std::sync::Weak<super::CacheLayer>,
    ) {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let db_dir = dir.path().join("db");
        std::fs::create_dir_all(&db_dir).expect("mkdir");
        let power = dcroxide_testutil::powerloss::PowerLossBackend::create(
            &db_dir.join(crate::METADATA_FILE),
            true,
        );
        let mut opts = crate::Options::new(&db_dir, 0x1214_1c16);
        opts.backend = Some(Arc::clone(&power) as crate::SharedBackend);
        let db = crate::Database::create(&opts).expect("create");
        db.update(|tx| {
            let rows = tx.metadata().create_bucket(b"rows")?;
            rows.put(b"a", b"1")?;
            rows.put(b"b", b"2")
        })
        .expect("the rows");
        let layers = db
            .inner
            .cache
            .lock()
            .expect("cache")
            .published_layers_for_test();
        assert_eq!(layers.len(), 1, "one layer");
        let layer = layers[0].clone();
        (dir, power, db, layer)
    }

    /// A flush that committed on the thread that captured it hands back
    /// its handles on the layers it retired, alive, rather than freeing
    /// them under the cache lock: `flush_locked` returns them to its
    /// caller.  They are the last handles unless a reader that began
    /// before the flush still holds its snapshot, and then that reader
    /// goes on reading the layers after the handles are dropped.  A
    /// flush whose commit failed retired nothing: `flush_locked` returns
    /// the error, and the layer is still published, held by the overlay
    /// alone.
    #[test]
    fn a_flush_hands_back_the_layers_it_retired_alive() {
        let published = |db: &crate::Database| {
            db.inner
                .cache
                .lock()
                .expect("cache")
                .published_layers_for_test()
        };
        for held_by_a_reader in [false, true] {
            let (_dir, _power, db, layer) = store_with_a_layer();
            let reader = held_by_a_reader.then(|| db.begin(false).expect("begin a reader"));
            let writer = db.exclusive_writer();
            let retired = crate::flush_locked(&db.inner, false).expect("flush");
            drop(writer);
            assert!(published(&db).is_empty(), "still published");
            assert_eq!(retired.len(), 1);
            assert!(std::ptr::eq(retired[0].as_ref(), layer.as_ptr()));
            let readers = usize::from(held_by_a_reader);
            assert_eq!(
                layer.strong_count(),
                1 + readers,
                "the layer was freed, or is held, where it should not be"
            );
            drop(retired);
            assert_eq!(layer.strong_count(), readers);
            if let Some(reader) = reader {
                let rows = reader.metadata().bucket(b"rows").expect("bucket");
                assert!(rows.get(b"a").is_some() && rows.get(b"b").is_some());
                reader.rollback().expect("end the reader");
            }
        }

        let (_dir, power, db, layer) = store_with_a_layer();
        power.power_fails_after(0);
        let writer = db.exclusive_writer();
        let failed = crate::flush_locked(&db.inner, false);
        drop(writer);
        assert!(failed.is_err() && power.power_failed(), "the commit failed");
        let still = published(&db);
        assert_eq!(still.len(), 1);
        assert!(std::ptr::eq(still[0].as_ptr(), layer.as_ptr()));
        assert_eq!(layer.strong_count(), 1, "held by the overlay alone");
    }

    /// A retirement checks that the pinned tail is still the layers the
    /// batch captured.  Over a tail of another identity, or of another
    /// length, it truncates nothing, puts the captured bytes back as a
    /// failed flush does, and returns the error its caller latches the
    /// store with: the tail may hold rows no commit has.
    #[test]
    fn a_retirement_refuses_a_pinned_tail_it_did_not_capture() {
        let filled = || {
            let mut cache = DbCache::new();
            let mut puts = BTreeMap::new();
            puts.insert(b"key".to_vec(), b"value".to_vec());
            cache.commit_pending(puts, std::iter::empty());
            cache
        };

        // The same rows in a layer that is not the captured one.
        let mut cache = filled();
        let held = cache.total_size;
        let batch = cache.begin_flush();
        cache.reidentify_layers_for_test();
        let err = cache
            .retire(&batch, Some(super::FlushOutcome::for_test()))
            .expect_err("the tail is not the captured layer");
        assert!(
            err.description
                .contains("no longer the ones the flush captured"),
            "{err}"
        );
        assert_eq!(cache.cached.layers.len(), 1, "nothing was truncated");
        assert_eq!(cache.cached.get(b"key"), Some(&Some(b"value".to_vec())));
        assert_eq!(cache.total_size, held, "the bytes went back");
        assert!(!cache.in_flight() && cache.in_flight_layers == 0);

        // A pin that no longer counts the captured layers.
        let mut cache = filled();
        let batch = cache.begin_flush();
        cache.in_flight_layers = 0;
        cache
            .retire(&batch, Some(super::FlushOutcome::for_test()))
            .expect_err("the pin does not cover what was captured");
        assert_eq!(cache.cached.layers.len(), 1, "nothing was truncated");
        assert_eq!(cache.total_size, held);

        // More pinned than the overlay holds.
        let mut cache = filled();
        let batch = cache.begin_flush();
        cache.publish(Vec::new());
        cache
            .retire(&batch, Some(super::FlushOutcome::for_test()))
            .expect_err("the pinned layers are gone");
        assert_eq!(cache.total_size, held);
    }

    /// A failed commit puts the bytes back, or the overlay grows without
    /// ever tripping its own ceiling again.
    #[test]
    fn a_failed_flush_restores_the_accounting_and_keeps_the_layers() {
        let mut cache = DbCache::new();
        put(&mut cache, &["a", "b"]);
        let before = cache.total_size;
        let layers = cache.cached.layers.clone();

        let batch = cache.begin_flush();
        assert_eq!(cache.total_size, 0);
        cache.finish_flush(batch, None);

        assert_eq!(cache.total_size, before, "the bytes came back");
        assert_eq!(cache.cached.layers.len(), layers.len(), "layers kept");
        assert!(Arc::ptr_eq(&cache.cached.layers[0], &layers[0]));
        assert!(
            cache.cached.get(b"a").is_some(),
            "the data is still readable"
        );
    }
}
