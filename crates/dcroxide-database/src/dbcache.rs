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
//! on top.  Layers are merged back together geometrically — the
//! newest layer merges into the next older one once it has grown to
//! half that layer's entry count — which keeps the stack shallow
//! (typically one to three layers, never more than [`MAX_LAYERS`]) at
//! an amortized cost proportional to the data committed, never to the
//! size of the whole overlay.
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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::METADATA_TABLE;
use crate::blockfile::BlockStore;
use crate::error::{Error, ErrorKind, db_error};

/// The default size for the database cache (dcrd `defaultCacheSize`,
/// 100 MiB).
pub(crate) const DEFAULT_CACHE_SIZE: u64 = 100 * 1024 * 1024;

/// The default number of seconds between flushes (dcrd
/// `defaultFlushSecs`, five minutes).
pub(crate) const DEFAULT_FLUSH_SECS: u64 = 300;

/// One immutable layer of the cache overlay: key to live value, or
/// `None` for a pending deletion of a stored key.
pub(crate) type CacheLayer = BTreeMap<Vec<u8>, Option<Vec<u8>>>;

/// An overlay capture handed to [`DbCache::run_flush`], which persists it
/// with no lock held.
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
    started: Instant,
}

/// What a completed commit reports back for the observer.
pub(crate) struct FlushOutcome {
    dirty_entries: usize,
    stats_elapsed: Duration,
    sampled: Option<crate::RawStats>,
}

impl FlushOutcome {
    /// A successful outcome with nothing to report, for tests that drive
    /// retirement without running a real commit.
    #[cfg(test)]
    fn for_test() -> FlushOutcome {
        FlushOutcome {
            dirty_entries: 0,
            stats_elapsed: Duration::ZERO,
            sampled: None,
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

    /// The merged view of every layer, ascending by key: each key once,
    /// with the entry from the newest layer holding it.
    fn merged(&self) -> LayerMerge<'_> {
        LayerMerge::new(&self.layers, None)
    }

    /// Fold the overlay's entries for the prefix into a set of keys
    /// gathered from the durable store: a live entry adds its key and a
    /// pending deletion masks it, with newer layers shadowing older
    /// ones (dcrd's snapshot iterator merged over the store iterator).
    ///
    /// `after` skips keys an earlier window already returned, and
    /// `upto` is the inclusive last key of the span the store scan
    /// covered.  Both `None` folds the whole prefix.
    ///
    /// Overlay keys beyond `upto` are left for the next window rather
    /// than dropped.  `None` for `upto` means the store scan reached the
    /// end of the prefix, so there is no next window and the whole
    /// remaining overlay belongs to this one.
    pub(crate) fn merge_prefix_keys_window(
        &self,
        prefix: &[u8],
        after: Option<&[u8]>,
        upto: Option<&[u8]>,
        merged: &mut BTreeSet<Vec<u8>>,
    ) {
        let from = after.unwrap_or(prefix);
        for (key, entry) in LayerMerge::new(&self.layers, Some(from)) {
            if !key.starts_with(prefix) {
                break;
            }
            if after.is_some_and(|a| key <= a) {
                continue;
            }
            if upto.is_some_and(|u| key > u) {
                break;
            }
            match entry {
                Some(_) => {
                    merged.insert(key.to_vec());
                }
                None => {
                    merged.remove(key);
                }
            }
        }
    }
}

/// A merging iterator over a snapshot's layers: ascending by key, each
/// key yielded exactly once with the entry from the newest layer that
/// holds it (a pending deletion included, as `None`).
struct LayerMerge<'a> {
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
fn merge_newest_pair(layers: &mut Vec<Arc<CacheLayer>>) -> u64 {
    if layers.len() < 2 {
        return 0;
    }
    let newer = layers.remove(0);
    let older = layers.remove(0);
    // Start from the older layer — taking it outright when no snapshot
    // still names it — and let the newer layer overwrite.
    let mut merged = match Arc::try_unwrap(older) {
        Ok(map) => map,
        Err(shared) => (*shared).clone(),
    };
    let mut reclaimed = 0u64;
    for (key, entry) in newer.iter() {
        if let Some(shadowed) = merged.insert(key.clone(), entry.clone()) {
            // The older copy of this key is gone: its key bytes and,
            // when it held one, its value bytes are no longer retained.
            reclaimed = reclaimed
                .saturating_add(key.len() as u64)
                .saturating_add(shadowed.map_or(0, |v| v.len() as u64));
        }
    }
    layers.insert(0, Arc::new(merged));
    reclaimed
}

/// Keep the layer stack shallow, returning the retained bytes the
/// merges reclaimed.  The newest layer merges down as soon as it has
/// grown to half the entry count of the layer below it, which keeps two
/// properties:
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
    // region stays the tail for as long as it is pinned.
    while layers.len().saturating_sub(pinned) >= 2
        && layers[0].len().saturating_mul(2) >= layers[1].len()
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
    /// The approximate byte size of the keys and values the overlay
    /// RETAINS (dcrd tracks its treap sizes, which for a single treap is
    /// the same figure).
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
    /// Non-zero only between `begin_flush` and `finish_flush`, and the
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
}

impl DbCache {
    pub(crate) fn new() -> DbCache {
        DbCache {
            cached: Arc::new(CacheSnapshot::default()),
            total_size: 0,
            last_flush: Instant::now(),
            max_size: DEFAULT_CACHE_SIZE,
            flush_interval: Duration::from_secs(DEFAULT_FLUSH_SECS),
            observer: None,
            stats_every: 0,
            flush_seq: 0,
            in_flight_layers: 0,
            in_flight_size: 0,
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

    /// Apply a committed transaction's pending sets to the overlay
    /// with dcrd's size accounting (dcrd `commitTx` onto the cached
    /// treaps).
    ///
    /// The write lands in the newest layer in place whenever this cache
    /// is that layer's only owner — the steady state, where the cost is
    /// one `BTreeMap` insert per key and nothing else.  While a reader
    /// holds a snapshot naming the layer, the layer stays frozen and
    /// this commit seals a fresh layer above it instead, so no
    /// transaction ever copies the overlay to make progress.
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
        for key in removes {
            match top.insert(key.clone(), None) {
                // Replaced an entry in the mutable layer: the key stays,
                // any value it held is freed.
                Some(displaced) => {
                    self.total_size = self
                        .total_size
                        .saturating_sub(displaced.map_or(0, |v| v.len() as u64));
                }
                // A fresh tombstone, whether or not an older layer has
                // this key: it occupies its own key bytes.
                None => {
                    self.total_size = self.total_size.saturating_add(key.len() as u64);
                }
            }
        }
        for (key, value) in puts {
            let added = value.len() as u64;
            match top.insert(key.clone(), Some(value)) {
                Some(displaced) => {
                    self.total_size = self
                        .total_size
                        .saturating_sub(displaced.map_or(0, |v| v.len() as u64))
                        .saturating_add(added);
                }
                None => {
                    self.total_size = self
                        .total_size
                        .saturating_add(key.len() as u64)
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

    /// Capture the overlay for a flush, under the cache lock.
    ///
    /// Returns `None` when there is nothing to write. The captured
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
        // Move the bytes out of the figure `needs_flush` gates on, so
        // the trigger disarms at handoff rather than staying armed for
        // the whole commit and re-firing on every commit inside it.
        self.total_size = 0;
        self.in_flight_size = bytes;
        self.in_flight_layers = layers.len();
        // The sequence is assigned in `finish_flush`, so an empty flush --
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
            started: Instant::now(),
        }
    }

    /// Persist a captured batch. Runs WITHOUT the cache lock held, so
    /// readers and the overlay's writers proceed while it works.
    pub(crate) fn run_flush(
        batch: &FlushBatch,
        kv: &redb::Database,
        block_store: &std::sync::Mutex<BlockStore>,
    ) -> Result<FlushOutcome, Error> {
        // Block files before metadata, so the metadata never describes
        // bytes that could vanish in a crash.
        block_store
            .lock()
            .expect("block store lock poisoned")
            .sync()?;

        let view = CacheSnapshot {
            layers: batch.layers.clone(),
        };
        if view.is_empty() {
            // Nothing to commit, but the block files above still needed
            // their sync -- that is the half of a flush that runs even on
            // an empty overlay.
            return Ok(FlushOutcome {
                dirty_entries: 0,
                stats_elapsed: Duration::ZERO,
                sampled: None,
            });
        }

        let mut dirty_entries = 0usize;
        let mut sampled = None;
        let mut stats_elapsed = Duration::ZERO;
        let tx = crate::begin_durable_write(kv)?;
        {
            let mut table = tx
                .open_table(METADATA_TABLE)
                .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
            for (key, entry) in view.merged() {
                dirty_entries = dirty_entries.saturating_add(1);
                if let Some(sink) = &batch.write_log {
                    sink(key, entry.as_ref().map(|v| v.as_slice()));
                }
                match entry {
                    Some(v) => {
                        table
                            .insert(key, v.as_slice())
                            .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
                    }
                    None => {
                        table
                            .remove(key)
                            .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
                    }
                }
            }
            if batch.take_stats {
                let stats_started = Instant::now();
                let db_stats = tx
                    .stats()
                    .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
                let table_stats = redb::ReadableTableMetadata::stats(&table)
                    .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
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
        tx.commit()
            .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
        Ok(FlushOutcome {
            dirty_entries,
            stats_elapsed,
            sampled,
        })
    }

    /// Retire a batch under the cache lock once its commit has landed,
    /// or put its bytes back when it failed.
    pub(crate) fn finish_flush(&mut self, batch: FlushBatch, outcome: Option<FlushOutcome>) {
        let pinned = self.in_flight_layers;
        self.in_flight_layers = 0;
        let bytes = self.in_flight_size;
        self.in_flight_size = 0;

        let Some(outcome) = outcome else {
            // The commit failed: the overlay still holds every captured
            // byte, so the accounting has to go back or the cache grows
            // without ever tripping its own ceiling again.
            self.total_size = self.total_size.saturating_add(bytes);
            return;
        };

        let mut layers = self.cached.layers.clone();
        debug_assert!(
            layers.len() >= pinned
                && layers[layers.len() - pinned..]
                    .iter()
                    .zip(batch.layers.iter())
                    .all(|(a, b)| Arc::ptr_eq(a, b)),
            "the pinned tail is no longer the layers this flush captured; \
             `compact`'s barrier is the thing that guarantees it"
        );
        layers.truncate(layers.len().saturating_sub(pinned));
        self.publish(layers);

        if outcome.dirty_entries == 0 {
            return;
        }
        self.flush_seq = self.flush_seq.saturating_add(1);
        if let Some(observer) = &self.observer {
            observer(&crate::FlushObservation {
                sequence: self.flush_seq,
                dirty_entries: outcome.dirty_entries,
                dirty_bytes: batch.bytes,
                elapsed: batch.started.elapsed(),
                stats_elapsed: outcome.stats_elapsed,
                stats: outcome.sampled,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use tempfile::TempDir;

    use super::{DbCache, MAX_LAYERS};
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
            .map(|(k, v)| (k.len() + v.as_ref().map_or(0, Vec::len)) as u64)
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
        // well under the 100 MiB flush threshold so nothing flushes
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
    /// obvious way so a test can check the running total against it.
    fn retained_bytes(cache: &DbCache) -> u64 {
        cache
            .cached
            .layers
            .iter()
            .flat_map(|layer| layer.iter())
            .map(|(k, v)| k.len() as u64 + v.as_ref().map_or(0, |b| b.len() as u64))
            .sum()
    }

    /// The overlay's logical size: every key once, plus its live value.
    /// This is what a single flat map would have held, and the floor the
    /// retained figure may never fall below.
    fn logical_bytes(cache: &DbCache) -> u64 {
        cache
            .cached
            .merged()
            .map(|(k, v)| k.len() as u64 + v.as_ref().map_or(0, |b| b.len() as u64))
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
        // layers where the merged view shows it once, so two extra copies
        // of its key and value are held; `gone` is stored in the oldest
        // layer and tombstoned in the newest, so its value plus one extra
        // copy of its key is held beyond the tombstone the merged view
        // shows.  Both terms vanish under an accounting that subtracts on
        // every overwrite, which is what makes this the regression guard.
        let expected_excess =
            2 * (key.len() + VALUE_LEN) as u64 + (gone.len() + b"present".len()) as u64;
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
