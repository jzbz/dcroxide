// SPDX-License-Identifier: ISC
//! Transactions, buckets, and cursors over the redb-backed metadata
//! store, reproducing the observable semantics of dcrd's ffldb driver
//! (database/ffldb `db.go`).
//!
//! The key layout is ffldb's, with one exception:
//!
//! - key/value rows: `<4-byte bucket ID><key>`; the top-level metadata
//!   bucket has ID `[0, 0, 0, 0]`.
//! - bucket index rows: `bidx<4-byte parent ID><child name>` mapping to
//!   the child's 4-byte ID; the internal block index bucket keeps the
//!   fixed ID `[0, 0, 0, 1]` under the name `ffldb-blockidx`.
//! - the current bucket ID counter lives at the raw key `bidx-cbid`.
//! - the exception: a block's row in the internal block index is keyed
//!   by its big-endian height and then its hash, where ffldb uses the
//!   hash alone, so the block lookups take the height beside the hash.
//!   `block_idx_key` is the one encoder of that key, and
//!   `serialized_block_height` the one reader of a stored block's
//!   height; see ADR-0010.
//!
//! Because bucket IDs are assigned sequentially from 1 and `bidx`
//! begins with 0x62, a full-bucket cursor observes all key/value rows
//! before all nested-bucket rows, exactly as ffldb's merged raw-key
//! iterators do.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use dcroxide_chainhash::Hash;

use crate::blockfile::{BLOCK_LOC_SIZE, BlockLocation, BlockRecord, serialize_write_row};
use crate::bucketindex::BucketIndex;
use crate::dbcache::LayerKey;
use crate::error::{Error, ErrorKind, db_error};
use crate::{DbInner, METADATA_TABLE};

/// The prefix used for all entries in the bucket index (dcrd
/// `bucketIndexPrefix`).
pub(crate) const BUCKET_INDEX_PREFIX: &[u8] = b"bidx";

/// The raw key tracking the current bucket ID counter (dcrd
/// `curBucketIDKeyName`).
pub(crate) const CUR_BUCKET_ID_KEY: &[u8] = b"bidx-cbid";

/// The metadata-bucket key storing the current block file write cursor
/// (dcrd `writeLocKeyName`).
pub(crate) const WRITE_LOC_KEY: &[u8] = b"ffldb-writeloc";

/// The ID of the top-level metadata bucket (dcrd `metadataBucketID`).
pub(crate) const METADATA_BUCKET_ID: [u8; 4] = [0, 0, 0, 0];

/// The ID of the internal block index bucket (dcrd `blockIdxBucketID`).
pub(crate) const BLOCK_IDX_BUCKET_ID: [u8; 4] = [0, 0, 0, 1];

/// The name of the internal block index bucket (dcrd
/// `blockIdxBucketName`; the name is kept for layout familiarity even
/// though this driver is not ffldb).
pub(crate) const BLOCK_IDX_BUCKET_NAME: &[u8] = b"ffldb-blockidx";

/// The size of a block header, which is how many bytes of a stored
/// block the header occupies (dcrd `blockHdrSize`).
pub(crate) const BLOCK_HDR_SIZE: usize = 180;

/// Where a serialized block header keeps its little-endian height: after
/// the version (4 bytes), the previous block, merkle and stake roots (32
/// each), the vote bits (2), final state (6), voters (2), fresh stake
/// (1), revocations (1), pool size (4), bits (4) and stake difficulty
/// (8) (dcrd `wire.BlockHeader`).
const BLOCK_HDR_HEIGHT_OFFSET: usize = 128;

/// The height a serialized block's header records, or `None` when the
/// bytes are too short to hold it.  This is the height
/// [`block_idx_key`] files a block under when only its bytes are at
/// hand ([`Transaction::store_block_raw`]).
pub(crate) fn serialized_block_height(raw: &[u8]) -> Option<u32> {
    let end = BLOCK_HDR_HEIGHT_OFFSET.checked_add(4)?;
    let bytes: [u8; 4] = raw.get(BLOCK_HDR_HEIGHT_OFFSET..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// The raw key of a block's row in the internal block index bucket: the
/// bucket ID, the block's height big-endian, then its hash.
///
/// ffldb keys the row by the hash alone (`ffldb/db.go:1142`, `:1239`,
/// `:1717`), which scatters the blocks of one metadata flush over the
/// whole bucket: redb copies one cold leaf, and its branch path, per
/// block.  Height first files consecutive blocks side by side, so a
/// flush appends at the bucket's right edge instead, as dcrd's own
/// `blockidxv3` key does (`blockIndexKey`).  The hash follows so blocks
/// at one height stay apart.  The cost is that every lookup takes the
/// block's height beside its hash; every caller has it, from the block
/// index node or the block's own header, and a lookup under any other
/// height finds nothing.  The layout is dcroxide's own, and the chain
/// database's version records it
/// (`dcroxide_blockchain::chaindb::CURRENT_DATABASE_VERSION`, ADR-0010).
fn block_idx_key(hash: &Hash, height: u32) -> LayerKey {
    LayerKey::concat(&[&BLOCK_IDX_BUCKET_ID, &height.to_be_bytes(), &hash.0])
}

/// A particular region of a block, identified by hash, offset, and
/// length (dcrd `BlockRegion`).  Reading one also takes the block's
/// height, which keys the block's index row, as a separate argument
/// (see [`Transaction::fetch_block_region`]): a transaction index entry
/// carries a region and no height.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BlockRegion {
    /// The hash of the block the region is part of.
    pub hash: Hash,
    /// The zero-based offset relative to the start of the serialized
    /// block.
    pub offset: u32,
    /// The number of bytes in the region.
    pub len: u32,
}

/// The key for storing and retrieving a child bucket in the bucket
/// index (dcrd `bucketIndexKey`): `bidx<parent ID><name>`.
fn bucket_index_key(parent_id: [u8; 4], key: &[u8]) -> LayerKey {
    LayerKey::concat(&[BUCKET_INDEX_PREFIX, &parent_id, key])
}

/// The actual key for a key within a bucket (dcrd `bucketizedKey`):
/// `<bucket ID><key>`.
///
/// The key is the one the pending sets and the cache overlay hold
/// ([`LayerKey`]): a row's key of up to 46 bytes is built on the stack
/// and moves from there into the set a put or a delete stages it in,
/// and a lookup's is dropped where it was built, so neither allocates.
fn bucketized_key(bucket_id: [u8; 4], key: &[u8]) -> LayerKey {
    LayerKey::concat(&[&bucket_id, key])
}

/// Whether a pending set whose greatest key is `last` can hold `key`:
/// not when it is empty, and not when `key` sorts after `last`, which
/// is to sort after every key the set holds.
///
/// [`Transaction::put_raw`] and [`Transaction::delete_raw`] keep the two
/// pending sets disjoint by taking each key they stage out of the other
/// one, as dcrd's `putKey` and `deleteKey` do (`ffldb/db.go:1061`,
/// `:1098`).  That is a search of the other set for a key that is almost
/// never there, while its greatest key is read without comparing any.
/// A flush of the UTXO cache stages its rows in ascending key order,
/// puts and deletes interleaved, so nearly every one of them sorts after
/// everything staged before it and one comparison shows there is nothing
/// to take out; a row that does not is searched for as before.  The
/// removal of a key the set does not hold changes nothing, so leaving it
/// out leaves both sets as the search would.
#[inline]
fn may_hold(last: Option<&LayerKey>, key: &LayerKey) -> bool {
    last.is_some_and(|last| last >= key)
}

/// Rows per window of a [`Bucket::for_each`] walk.  Small enough that a
/// walk over the UTXO set holds a few hundred kilobytes instead of every
/// key of the bucket, large enough that the per-window B-tree descent is
/// noise beside the rows it returns.
const WALK_WINDOW: usize = 4096;

/// One window of a prefix scan (see `Transaction::scan_prefix_window`).
#[derive(Default)]
struct ScanWindow {
    /// The live rows in raw key order: the raw key and its value, the
    /// value left empty when the scan was not asked for values.
    rows: Vec<(Vec<u8>, Vec<u8>)>,
    /// The read error that ended the store's side of the scan early.
    store_error: Option<Error>,
}

/// A store row as a scan holds it until the merge consumes it.
type StoreRow = (
    redb::AccessGuard<'static, &'static [u8]>,
    redb::AccessGuard<'static, &'static [u8]>,
);

/// Pull the store's next row, ending the stream -- and recording why --
/// at its first read error (see `Transaction::scan_prefix_window`).
fn next_store_row(
    store: &mut Option<redb::Range<'static, &'static [u8], &'static [u8]>>,
    error: &mut Option<Error>,
) -> Option<StoreRow> {
    match store.as_mut()?.next() {
        Some(Ok(row)) => Some(row),
        Some(Err(e)) => {
            *error = Some(crate::storage_error(e));
            *store = None;
            None
        }
        None => {
            *store = None;
            None
        }
    }
}

/// The underlying redb transaction, either read-only or read-write.
// One value exists per transaction, so the size difference between the
// redb read and write transaction types is irrelevant.
#[allow(clippy::large_enum_variant)]
enum KvTx {
    Read(redb::ReadTransaction),
    /// A writable transaction: reads come from a redb read snapshot
    /// (writes buffer in the pending maps and reach redb only when
    /// the metadata cache flushes); the writer semaphore is held.
    Write(redb::ReadTransaction),
}

/// A block a transaction holds until its commit writes it.
enum PendingBlock {
    /// The serialized block.  The commit lays its record out.
    Bytes(Vec<u8>),
    /// The block already laid out as its record
    /// ([`Transaction::store_block_record`]), shared with whoever handed
    /// it in.  The commit writes it as it stands.
    Record(Arc<BlockRecord>),
}

impl PendingBlock {
    /// The serialized block.
    fn bytes(&self) -> &[u8] {
        match self {
            PendingBlock::Bytes(raw) => raw,
            PendingBlock::Record(record) => record.block(),
        }
    }
}

/// The mutable state of a transaction, kept behind a `RefCell` so
/// bucket and cursor handles can share the transaction immutably (like
/// dcrd's interface, a transaction and its derived handles are intended
/// for single-threaded use).
struct TxState {
    /// The underlying key/value transaction; `None` once closed.
    kv: Option<KvTx>,
    /// The redb handle `kv` was begun on, held until `kv` has been let go
    /// of, so that a close made while this transaction is open leaves
    /// redb's file open under it and redb closes the file once the last
    /// such transaction ends (`DbInner::kv`).  `None` once closed.
    kv_handle: Option<Arc<redb::Database>>,
    /// The metadata table, opened once for the transaction's life.
    ///
    /// `ReadTransaction::open_table` resolves the table by name through
    /// redb's master table tree on every call, and it returns an owned
    /// `ReadOnlyTable` rather than a borrow — so opening it per key
    /// lookup, as this used to, paid that walk on every `Bucket::get`
    /// and on every step of a `for_each` or prefix scan.  The read
    /// transaction is a snapshot, so which table it resolves cannot
    /// change while it lives; opening once is the same answer for less
    /// work.  `None` only when the table does not exist, which keeps
    /// "missing table reads as empty".  Any other `open_table` failure
    /// fails the `begin` instead (see [`Transaction::new`]): mapping it
    /// to `None` made every key of the transaction read as missing, and
    /// redb does not stop that at one transaction.  `begin_read` takes
    /// its snapshot from memory and a read-cache hit skips redb's
    /// failure check (redb-4.5.0 `page_manager.rs:1389-1392`,
    /// `cached_file.rs:690-698`), so after an I/O error the master
    /// table root keeps opening from cache while every uncached page
    /// returns `PreviousIo`, for the rest of the process.
    table: Option<redb::ReadOnlyTable<&'static [u8], &'static [u8]>>,
    /// Blocks buffered by `store_block` to be written on commit, each
    /// with the height that keys its index row, plus an index over them
    /// by hash (dcrd `pendingBlocks` / `pendingBlockData`).  A block is
    /// held as its bytes or as the record it arrived laid out as.
    pending_blocks: Vec<(Hash, u32, PendingBlock)>,
    pending_index: HashMap<[u8; 32], usize>,
    /// Metadata puts buffered until commit (dcrd `pendingKeys`).
    pending_keys: std::collections::BTreeMap<LayerKey, Vec<u8>>,
    /// Metadata deletions buffered until commit (dcrd
    /// `pendingRemove`).
    pending_removes: std::collections::BTreeSet<LayerKey>,
    /// The cache overlay as of transaction start (dcrd `dbCacheSnapshot`):
    /// an `Arc` clone of the layer stack.  `None`, read as an overlay
    /// holding no row, once closed, and from the point a commit lets it
    /// go so that the cache's newest layer can be written in place.
    cache_snap: Option<Arc<crate::dbcache::CacheSnapshot>>,
    /// The bucket index beneath this transaction's pending changes: the
    /// one the cache published when `cache_snap` was taken, under the
    /// same hold of the cache lock, so it holds what a read of the bucket
    /// index rows through `cache_snap` and the store returns
    /// ([`BucketIndex`]).  `None` once the transaction is closed, and
    /// from the point a commit publishes its rows, so the cache's map is
    /// unshared when it takes them.
    buckets: Option<Arc<BucketIndex>>,
    /// Whether this transaction has staged a put or a delete of a key
    /// under the bucket index prefix.  Until it has, neither pending set
    /// can hold a bucket's index row, and a bucket lookup is answered by
    /// `buckets` alone ([`Transaction::child_bucket_id`]).
    staged_bucket_index: bool,
    /// How many times [`Transaction::put_raw`] and
    /// [`Transaction::delete_raw`] went on to search the other pending
    /// set for the key they staged, counted where [`may_hold`] lets the
    /// search through.
    #[cfg(test)]
    cross_searches: usize,
    /// Closures to run once a commit's own flush has taken the rows it
    /// will write and before the commit's are published, in registration
    /// order (see
    /// [`Transaction::on_commit`]).  Dropped unrun by `close`, so a
    /// rollback, a drop or a failed commit runs none of them.
    on_commit: Vec<OnCommit>,
}

/// A closure registered with [`Transaction::on_commit`].
type OnCommit = Box<dyn FnOnce() + Send>;

/// A database transaction over the metadata buckets and block storage
/// (dcrd `database.Tx`).  Read-write transactions buffer all changes
/// until commit; read-only transactions observe a consistent snapshot.
pub struct Transaction {
    db: Arc<DbInner>,
    state: RefCell<TxState>,
    writable: bool,
    managed: bool,
}

impl Transaction {
    /// Wrap the seed `begin_seed` acquired, opening the metadata table
    /// once for the transaction's life.
    ///
    /// Fails when the table cannot be opened for any reason but its
    /// absence, the way ffldb's `begin` fails when its cache cannot take
    /// a leveldb snapshot (`ffldb/db.go` `begin`, `dbcache.go`
    /// `Snapshot`).  The writer semaphore a writable seed carries is
    /// released first, as `begin` unlocks its write lock.
    pub(crate) fn new(
        db: Arc<DbInner>,
        kv: KvTxSeed,
        kv_handle: Arc<redb::Database>,
        cache_snap: Arc<crate::dbcache::CacheSnapshot>,
        buckets: Arc<BucketIndex>,
        managed: bool,
    ) -> Result<Transaction, Error> {
        let (kv, writable) = match kv {
            KvTxSeed::Read(t) => (KvTx::Read(t), false),
            KvTxSeed::Write(t) => (KvTx::Write(t), true),
        };
        // Both variants hold a redb read transaction, so this is the
        // owned `ReadOnlyTable` and can outlive the call.
        let opened = match &kv {
            KvTx::Read(t) | KvTx::Write(t) => t.open_table(METADATA_TABLE),
        };
        let tx = Transaction {
            db,
            state: RefCell::new(TxState {
                kv: Some(kv),
                kv_handle: Some(kv_handle),
                table: None,
                pending_blocks: Vec::new(),
                pending_index: HashMap::new(),
                pending_keys: std::collections::BTreeMap::new(),
                pending_removes: std::collections::BTreeSet::new(),
                cache_snap: Some(cache_snap),
                buckets: Some(buckets),
                staged_bucket_index: false,
                #[cfg(test)]
                cross_searches: 0,
                on_commit: Vec::new(),
            }),
            writable,
            managed,
        };
        match opened {
            Ok(table) => tx.state.borrow_mut().table = Some(table),
            Err(redb::TableError::TableDoesNotExist(_)) => {}
            Err(e) => {
                tx.close();
                return Err(crate::storage_error(e));
            }
        }
        Ok(tx)
    }

    /// Error when the transaction has already been closed (dcrd
    /// `checkClosed`).
    fn check_closed(&self) -> Result<(), Error> {
        if self.state.borrow().kv.is_none() {
            return Err(db_error(ErrorKind::TxClosed, "database tx is closed"));
        }
        Ok(())
    }

    fn is_closed(&self) -> bool {
        self.state.borrow().kv.is_none()
    }

    /// Whether the transaction is writable.
    pub fn writable(&self) -> bool {
        self.writable
    }

    // ------------------------------------------------------------------
    // Raw keyspace helpers (dcrd transaction fetchKey/putKey/deleteKey).
    // ------------------------------------------------------------------

    /// The layered view of one raw key, answering `None` for a store
    /// read error as well as for absence -- exactly what ffldb's
    /// `dbCacheSnapshot.Get` does with a leveldb error
    /// (`ffldb/dbcache.go`), so every ffldb-layout read keeps dcrd's
    /// answer.  Reads that port a backend which does keep the two apart
    /// use [`Self::try_fetch_raw`].  The lookup of a nested bucket is
    /// not one of these reads: it makes none ([`Bucket::bucket`]).
    pub(crate) fn fetch_raw(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.try_fetch_raw(key).unwrap_or(None)
    }

    /// [`Self::fetch_raw`] with a store read error returned rather than
    /// read as absence.
    pub(crate) fn try_fetch_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let state = self.state.borrow();
        // The layered view (dcrd `fetchKey`): this transaction's
        // pending changes, then the cache snapshot, then the store.
        if state.pending_removes.contains(key) {
            return Ok(None);
        }
        if let Some(v) = state.pending_keys.get(key) {
            return Ok(Some(v.clone()));
        }
        Self::fetch_committed(&state, key)
    }

    /// The key's value beneath this transaction's pending changes: the
    /// cache snapshot, then the store.
    fn fetch_committed(state: &TxState, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        // A cached entry answers the lookup whether it holds a value or
        // a pending deletion (`None`); a key no layer knows, and every
        // key once the snapshot is let go, falls through to the store.
        if let Some(entry) = state.cache_snap.as_ref().and_then(|snap| snap.get(key)) {
            return Ok(entry.clone());
        }
        // `kv` is still consulted so a closed transaction reads as
        // empty, exactly as before; the table itself is the one opened
        // when the transaction began.
        if state.kv.is_none() {
            return Ok(None);
        }
        let Some(table) = state.table.as_ref() else {
            return Ok(None);
        };
        Ok(table
            .get(key)
            .map_err(crate::storage_error)?
            .map(|g| g.value().to_vec()))
    }

    fn has_raw(&self, key: &[u8]) -> bool {
        self.fetch_raw(key).is_some()
    }

    /// Stage a put.  The key is taken owned, as every caller has just
    /// built it, and so is the value: both reach the pending set -- and
    /// from there the cache overlay -- without another copy.  A caller
    /// that holds a borrowed value copies it once, on the way in.
    pub(crate) fn put_raw(&self, key: LayerKey, value: Vec<u8>) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        if state.kv.is_none() || !self.writable {
            return Err(db_error(ErrorKind::TxNotWritable, "tx not writable"));
        }
        if key.as_bytes().starts_with(BUCKET_INDEX_PREFIX) {
            state.staged_bucket_index = true;
        }
        if may_hold(state.pending_removes.last(), &key) {
            #[cfg(test)]
            {
                state.cross_searches = state.cross_searches.saturating_add(1);
            }
            state.pending_removes.remove(&key);
        }
        state.pending_keys.insert(key, value);
        Ok(())
    }

    /// Stage a delete, taking the key owned as [`Self::put_raw`] does.
    pub(crate) fn delete_raw(&self, key: LayerKey) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        if state.kv.is_none() || !self.writable {
            return Err(db_error(ErrorKind::TxNotWritable, "tx not writable"));
        }
        if key.as_bytes().starts_with(BUCKET_INDEX_PREFIX) {
            state.staged_bucket_index = true;
        }
        if may_hold(
            state.pending_keys.last_key_value().map(|(last, _)| last),
            &key,
        ) {
            #[cfg(test)]
            {
                state.cross_searches = state.cross_searches.saturating_add(1);
            }
            state.pending_keys.remove(&key);
        }
        state.pending_removes.insert(key);
        Ok(())
    }

    /// [`Self::delete_raw`], also reporting what the key read as just
    /// before the delete whenever this transaction's pending changes
    /// alone answer that: `Some(value)`, or `Some(None)` for a key they
    /// had already deleted.  `None` means the answer lies beneath them,
    /// in the cache snapshot or the store, neither of which the delete
    /// changes -- so it can still be read there later, and only if
    /// someone asks.
    fn delete_raw_reporting(&self, key: &[u8]) -> Result<Option<Option<Vec<u8>>>, Error> {
        let mut state = self.state.borrow_mut();
        if state.kv.is_none() || !self.writable {
            return Err(db_error(ErrorKind::TxNotWritable, "tx not writable"));
        }
        if key.starts_with(BUCKET_INDEX_PREFIX) {
            state.staged_bucket_index = true;
        }
        // `put_raw` and `delete_raw` keep the two pending sets disjoint.
        let prior = match state.pending_keys.remove(key) {
            Some(value) => Some(Some(value)),
            None if state.pending_removes.contains(key) => Some(None),
            None => None,
        };
        state.pending_removes.insert(LayerKey::concat(&[key]));
        Ok(prior)
    }

    /// The exclusive upper bound of a prefix scan: the prefix with its
    /// last incrementable byte incremented (goleveldb
    /// `util.BytesPrefix` semantics).  `None` for an all-0xff prefix,
    /// which scans to the end of the keyspace.
    ///
    /// Shared by the whole-prefix and windowed scans, and by the flush
    /// participant's writer, so none of them can drift apart.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "end[i] != 0xff is checked before the increment, and i < end.len()"
    )]
    pub(crate) fn prefix_upper_bound(prefix: &[u8]) -> Option<Vec<u8>> {
        let mut end = prefix.to_vec();
        for i in (0..end.len()).rev() {
            if end[i] != 0xff {
                end[i] += 1;
                end.truncate(i + 1);
                return Some(end);
            }
        }
        None
    }

    /// All raw keys beginning with the prefix, in raw byte order.
    fn scan_prefix_keys(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
        self.scan_prefix_keys_window(prefix, None, None)
    }

    /// [`Self::scan_prefix_keys`] bounded to at most `limit` keys
    /// starting strictly after `after`.
    fn scan_prefix_keys_window(
        &self,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: Option<usize>,
    ) -> Vec<Vec<u8>> {
        self.scan_prefix_window(prefix, after, limit, false, true)
            .rows
            .into_iter()
            .map(|(key, _)| key)
            .collect()
    }

    /// The live rows beginning with the prefix, at most `limit` of them
    /// and strictly after `after`, in raw byte order -- with their
    /// values when `values` is set and with empty ones otherwise.
    ///
    /// A merge join over the sources a key can come from, which is what
    /// ffldb's cursor is: the store's range, the cache snapshot's merged
    /// layers (dcrd's cached treaps), and this transaction's pending
    /// puts, with its pending deletions as a mask.  A newer source
    /// shadows an older one for the same key, and a pending or cached
    /// deletion hides it.  Each source is an ordered stream pulled only
    /// as far as the window reaches, so a window costs O(`limit`)
    /// however much of the prefix lies past it and however its keys are
    /// split between the store and the overlay.
    ///
    /// Two costs this replaced are worth knowing.  Materializing a whole
    /// prefix per batch made dcrd's 2,000,000-key incremental drop
    /// quadratic -- 66,494,886 rows for mainnet's `existsaddridx` --
    /// because dcrd's cursor is lazy and restarting it is free.  And the
    /// store scan kept only keys, so every walk then looked each value
    /// up a second time, through the pending sets, the overlay and a
    /// fresh B-tree descent, where ffldb's `ForEach` reads it from the
    /// iterator.
    ///
    /// The store stream ends at its first read error, which comes back
    /// in [`ScanWindow::store_error`] while the overlay and pending
    /// streams carry on: a goleveldb iterator goes invalid on an error
    /// and ffldb's merged cursor treats that as exhausted, never
    /// checking `Error()`.  redb's range iterator instead repeats
    /// `PreviousIo` forever once it has failed (redb-4.5.0
    /// `btree_cursor_range.rs:208-216`), so a scan that skipped errors
    /// -- as a `flatten()` here once did -- spun forever.
    ///
    /// `read_store` false leaves the store out entirely, for a walk
    /// whose store stream already ended in an earlier window.
    fn scan_prefix_window(
        &self,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: Option<usize>,
        values: bool,
        read_store: bool,
    ) -> ScanWindow {
        use std::ops::Bound;

        let end = Self::prefix_upper_bound(prefix);
        // A resume key from below the prefix would start the walk
        // outside it, where the first key ends it -- so the window would
        // return a neighbouring bucket's rows and none of its own.
        let after = after.filter(|a| *a >= prefix);
        let want = limit.unwrap_or(usize::MAX);
        let mut out = ScanWindow::default();
        // Nothing of the prefix sorts after a resume key at or past its
        // end (a nested-bucket row handed back to the key-row scan), and
        // the inverted range would panic in the `BTreeMap` streams.
        if want == 0 || matches!((after, end.as_deref()), (Some(a), Some(e)) if a >= e) {
            return out;
        }
        let state = self.state.borrow();
        if state.kv.is_none() {
            return out;
        }

        let lower = match after {
            Some(a) => Bound::Excluded(a),
            None => Bound::Included(prefix),
        };
        let upper = match end.as_deref() {
            Some(e) => Bound::Excluded(e),
            None => Bound::Unbounded,
        };

        let mut store = match (read_store, state.table.as_ref()) {
            (true, Some(table)) => match table.range::<&[u8]>((lower, upper)) {
                Ok(range) => Some(range),
                Err(e) => {
                    out.store_error = Some(crate::storage_error(e));
                    None
                }
            },
            _ => None,
        };
        let mut store_head = next_store_row(&mut store, &mut out.store_error);
        let mut overlay = state
            .cache_snap
            .iter()
            .flat_map(|snap| snap.merged_from(after.unwrap_or(prefix)))
            .skip_while(|&(key, _)| after.is_some_and(|a| key <= a))
            .take_while(|&(key, _)| key.starts_with(prefix))
            .peekable();
        let mut pending = state
            .pending_keys
            .range::<[u8], _>((lower, upper))
            .peekable();
        let mut removed = state
            .pending_removes
            .range::<[u8], _>((lower, upper))
            .peekable();
        let keep = |v: &[u8]| if values { v.to_vec() } else { Vec::new() };

        while out.rows.len() < want {
            let store_key = store_head.as_ref().map(|(key, _)| key.value());
            let overlay_key = overlay.peek().map(|&(key, _)| key);
            let pending_key = pending.peek().map(|&(key, _)| key.as_bytes());
            let Some(key) = [store_key, overlay_key, pending_key]
                .into_iter()
                .flatten()
                .min()
                .map(<[u8]>::to_vec)
            else {
                break;
            };
            let in_store = store_key == Some(key.as_slice());
            let in_overlay = overlay_key == Some(key.as_slice());
            let in_pending = pending_key == Some(key.as_slice());

            let from_pending = if in_pending {
                pending.next().map(|(_, v)| v)
            } else {
                None
            };
            let from_overlay = if in_overlay {
                overlay.next().map(|(_, entry)| entry)
            } else {
                None
            };
            let from_store = if in_store {
                let row = store_head.take();
                store_head = next_store_row(&mut store, &mut out.store_error);
                row
            } else {
                None
            };
            while removed.next_if(|k| k.as_bytes() < key.as_slice()).is_some() {}
            let masked = removed.peek().is_some_and(|k| k.as_bytes() == key);

            // Newest first: this transaction's puts, then its deletions,
            // then the overlay (a cached deletion included), then the
            // store.
            let value = if let Some(v) = from_pending {
                Some(keep(v))
            } else if masked {
                None
            } else if let Some(entry) = from_overlay {
                entry.as_deref().map(keep)
            } else {
                from_store.map(|(_, v)| keep(v.value()))
            };
            if let Some(value) = value {
                out.rows.push((key, value));
            }
        }
        out
    }

    /// The first live row whose raw key starts with `prefix` and sorts
    /// strictly after `after`, with its value, or `None`.
    ///
    /// A raw-keyspace read with no ffldb counterpart, for a reader of a
    /// flush participant's rows (ADR-0011): an index whose rows are chunks
    /// keyed by their last entry finds the chunk that may hold `k` as the
    /// first row after `prefix || k`.  It sees what every read of this
    /// transaction sees, the store merged with the overlay and this
    /// transaction's pending changes.  Unlike [`Bucket::get`], a store
    /// read error is returned rather than read as absence, since an index
    /// that read a failing disk as "no row" would answer a lookup wrongly
    /// rather than fail it.  `after` below `prefix` starts at the
    /// prefix's first row.
    pub fn try_first_after(
        &self,
        prefix: &[u8],
        after: &[u8],
    ) -> Result<Option<crate::RawRow>, Error> {
        Ok(self
            .try_scan_after(prefix, Some(after), 1)?
            .into_iter()
            .next())
    }

    /// Up to `limit` live rows whose raw keys start with `prefix`,
    /// strictly after `after` when one is given, in raw key order, with
    /// their values.  [`Self::try_first_after`] for more than one row,
    /// with the same view and the same error rule; resume a walk from the
    /// last key returned.
    pub fn try_scan_after(
        &self,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<crate::RawRow>, Error> {
        self.check_closed()?;
        let window = self.scan_prefix_window(prefix, after, Some(limit), true, true);
        match window.store_error {
            Some(e) => Err(e),
            None => Ok(window.rows),
        }
    }

    /// The ID of the bucket `name` nested in the bucket `parent`, or
    /// `None` when there is none: [`Self::fetch_raw`] of the bucket's
    /// index row, read as an ID, without the read.
    ///
    /// Beneath this transaction's pending changes the row is the entry of
    /// the bucket index taken with its snapshots ([`BucketIndex`]).  The
    /// pending changes can hold the row only once this transaction has
    /// staged a write under the bucket index prefix, which creating or
    /// deleting a bucket does; until then they are not consulted, and the
    /// lookup builds no key.
    fn child_bucket_id(&self, parent: [u8; 4], name: &[u8]) -> Option<[u8; 4]> {
        let state = self.state.borrow();
        if state.staged_bucket_index {
            let key = bucket_index_key(parent, name);
            if state.pending_removes.contains(&key) {
                return None;
            }
            if let Some(value) = state.pending_keys.get(&key) {
                return value.as_slice().try_into().ok();
            }
        }
        state.buckets.as_ref()?.get(parent, name)
    }

    /// The bucket index as a scan of its rows through this transaction's
    /// layered view builds it, pending changes included: what a read-only
    /// transaction's own map must equal.
    #[cfg(test)]
    pub(crate) fn bucket_index_from_rows(&self) -> BucketIndex {
        let mut index = BucketIndex::default();
        let rows = self
            .scan_prefix_window(BUCKET_INDEX_PREFIX, None, None, true, true)
            .rows;
        for (key, value) in rows {
            index.put_row(&key, &value);
        }
        index
    }

    /// The bucket index this transaction took with its snapshots.
    #[cfg(test)]
    pub(crate) fn held_bucket_index(&self) -> Option<Arc<BucketIndex>> {
        self.state.borrow().buckets.clone()
    }

    /// Allocate the next bucket ID (dcrd `nextBucketID`).
    fn next_bucket_id(&self) -> Result<[u8; 4], Error> {
        let cur = self
            .fetch_raw(CUR_BUCKET_ID_KEY)
            .ok_or_else(|| db_error(ErrorKind::Corruption, "missing current bucket ID counter"))?;
        let cur_id = u32::from_be_bytes(
            cur.as_slice()
                .try_into()
                .map_err(|_| db_error(ErrorKind::Corruption, "corrupt bucket ID counter"))?,
        );
        let next = cur_id
            .checked_add(1)
            .ok_or_else(|| db_error(ErrorKind::DriverSpecific, "bucket IDs exhausted"))?;
        let next_bytes = next.to_be_bytes();
        self.put_raw(LayerKey::concat(&[CUR_BUCKET_ID_KEY]), next_bytes.to_vec())?;
        Ok(next_bytes)
    }

    // ------------------------------------------------------------------
    // Metadata bucket access.
    // ------------------------------------------------------------------

    /// The top-most bucket for all metadata storage (dcrd
    /// `Tx.Metadata`).
    pub fn metadata(&self) -> Bucket<'_> {
        Bucket {
            tx: self,
            id: METADATA_BUCKET_ID,
        }
    }

    // ------------------------------------------------------------------
    // Block storage (dcrd Tx block APIs).
    // ------------------------------------------------------------------

    fn has_block_internal(&self, hash: &Hash, height: u32) -> bool {
        if self.pending_block_index(hash, height).is_some() {
            return true;
        }
        self.has_raw(block_idx_key(hash, height).as_bytes())
    }

    /// Store the provided block (dcrd `StoreBlock`).  The block is
    /// buffered and written to the flat files on commit.
    pub fn store_block(&self, block: &dcroxide_wire::MsgBlock) -> Result<(), Error> {
        // A serialization is a whole header by construction and the hash
        // is that header's, so nothing needs checking; the bytes are
        // moved into the pending set rather than copied a second time.
        self.store_block_with(
            &block.header.block_hash(),
            Some(block.header.height),
            || Ok(PendingBlock::Bytes(block.serialize())),
        )
    }

    /// [`Self::store_block`] for a caller that holds the hash of the
    /// block's header, which is then not hashed again here: the same
    /// checks in the same order, the same row and the same bytes (dcrd
    /// `StoreBlock` reads `block.Hash()`, the hash its `dcrutil.Block`
    /// computed as the block was wrapped, `ffldb/db.go:1169`,
    /// `dcrutil/block.go:92-94`, `:288-293`).
    ///
    /// The hash must be that of `block.header`: it keys the block index
    /// row and the pending set, and nothing here can tell another hash
    /// from the right one short of hashing the header, which is what
    /// this entry exists to spare.  [`Self::store_block_raw`] makes that
    /// comparison because its bytes come from outside; a caller of this
    /// one hands in the hash it computed from the very block it lends.
    /// Under debug assertions the pair is checked.
    pub fn store_block_hashed(
        &self,
        hash: &Hash,
        block: &dcroxide_wire::MsgBlock,
    ) -> Result<(), Error> {
        debug_assert_eq!(
            *hash,
            dcroxide_chainhash::hash_h(&block.header.serialize()),
            "the hash handed in with a block is not its header's"
        );
        self.store_block_with(hash, Some(block.header.height), || {
            Ok(PendingBlock::Bytes(block.serialize()))
        })
    }

    /// Store a block given its hash and raw serialized bytes; the raw
    /// entry point used by bulk import.
    ///
    /// dcrd's `StoreBlock` takes a block and asks it for both, so it
    /// cannot be handed a mismatched pair; this can.  The bytes must
    /// hold at least a whole header, because commit and
    /// `fetch_block_header` slice one out of them, and the hash must be
    /// that header's, because it keys the block index row.  Either
    /// mistake fails with [`ErrorKind::DriverSpecific`] -- the kind
    /// `StoreBlock` gives a block whose bytes it cannot get -- rather
    /// than panicking at commit or filing the block under another hash.
    ///
    /// The index row is keyed by the height the header records.  Bytes
    /// too short to record one cannot be looked up, so they skip the
    /// existence check and fail on their length.
    pub fn store_block_raw(&self, hash: &Hash, raw: Vec<u8>) -> Result<(), Error> {
        let height = serialized_block_height(&raw);
        self.store_block_with(hash, height, || {
            if raw.len() < BLOCK_HDR_SIZE {
                return Err(db_error(
                    ErrorKind::DriverSpecific,
                    format!(
                        "block {hash} is {} bytes, shorter than its {BLOCK_HDR_SIZE}-byte header",
                        raw.len()
                    ),
                ));
            }
            let header_hash = dcroxide_chainhash::hash_h(&raw[..BLOCK_HDR_SIZE]);
            if header_hash != *hash {
                return Err(db_error(
                    ErrorKind::DriverSpecific,
                    format!("block {hash} was given bytes whose header hashes to {header_hash}"),
                ));
            }
            Ok(PendingBlock::Bytes(raw))
        })
    }

    /// Store a block that was laid out as its block-file record before
    /// it came here ([`BlockRecord`]), given its hash: what
    /// [`Self::store_block_raw`] does with the block the record holds,
    /// except that the commit writes the record as it stands and does
    /// not copy the block into one and checksum it.  The file bytes, the
    /// index row and everything read back are those of
    /// `store_block_raw`.
    ///
    /// dcrd's `StoreBlock` is handed a block that carries the bytes it
    /// was decoded from (`dcrutil.NewBlockFromBlockAndBytes`,
    /// `dcrutil/block.go:54-58`) and stores those; this is the entry
    /// for a caller that kept them.
    ///
    /// The hash must be that of the header the record's block begins
    /// with, which the record took from its own bytes as it was laid
    /// out; another hash fails with [`ErrorKind::DriverSpecific`], as it
    /// does in `store_block_raw`.  A record always holds a whole header.
    /// The record is shared, not copied: the transaction lets go of it
    /// when it ends.
    pub fn store_block_record(&self, hash: &Hash, record: &Arc<BlockRecord>) -> Result<(), Error> {
        let height = serialized_block_height(record.block());
        self.store_block_with(hash, height, || {
            let header_hash = record.hash();
            if header_hash != hash {
                return Err(db_error(
                    ErrorKind::DriverSpecific,
                    format!("block {hash} was given bytes whose header hashes to {header_hash}"),
                ));
            }
            Ok(PendingBlock::Record(Arc::clone(record)))
        })
    }

    /// The body of [`Self::store_block`], [`Self::store_block_hashed`],
    /// [`Self::store_block_raw`] and [`Self::store_block_record`], in dcrd
    /// `StoreBlock`'s order: the transaction checks and the existence
    /// check, and only then the block's bytes (dcrd `block.Bytes()`,
    /// whose failure is `ErrDriverSpecific`).  `hash` is taken as given:
    /// `store_block` computes it from the block, `store_block_raw` and
    /// `store_block_record` refuse bytes whose header does not hash to
    /// it, and `store_block_hashed` relies on its caller.  `height` is
    /// the one the block's header records, for the existence check; it
    /// is `None` only for bytes that `bytes` refuses as too short to
    /// hold a header.  The row is filed under the height the stored
    /// bytes record.
    fn store_block_with(
        &self,
        hash: &Hash,
        height: Option<u32>,
        bytes: impl FnOnce() -> Result<PendingBlock, Error>,
    ) -> Result<(), Error> {
        self.check_closed()?;
        if !self.writable {
            return Err(db_error(
                ErrorKind::TxNotWritable,
                "store block requires a writable database transaction",
            ));
        }

        // Reject the block if it already exists (pending or stored).
        if let Some(height) = height
            && self.has_block_internal(hash, height)
        {
            return Err(db_error(
                ErrorKind::BlockExists,
                format!("block {hash} already exists"),
            ));
        }
        let raw = bytes()?;
        // `bytes` refuses anything shorter than a header, and a header
        // records its height, so this error is never reached.
        let height = serialized_block_height(raw.bytes()).ok_or_else(|| {
            db_error(
                ErrorKind::DriverSpecific,
                format!("block {hash} is too short to record its height"),
            )
        })?;

        let mut state = self.state.borrow_mut();
        let idx = state.pending_blocks.len();
        state.pending_blocks.push((*hash, height, raw));
        state.pending_index.insert(hash.0, idx);
        Ok(())
    }

    /// Whether a block with the given hash and height exists (dcrd
    /// `HasBlock`).  The height keys the block's index row, so under any
    /// height but its own a stored block answers `false`.
    pub fn has_block(&self, hash: &Hash, height: u32) -> Result<bool, Error> {
        self.check_closed()?;
        Ok(self.has_block_internal(hash, height))
    }

    /// Whether each of the blocks with the provided hashes and heights
    /// exists (dcrd `HasBlocks`).
    pub fn has_blocks(&self, blocks: &[(Hash, u32)]) -> Result<Vec<bool>, Error> {
        self.check_closed()?;
        Ok(blocks
            .iter()
            .map(|(hash, height)| self.has_block_internal(hash, *height))
            .collect())
    }

    fn fetch_block_row(&self, hash: &Hash, height: u32) -> Result<Vec<u8>, Error> {
        self.fetch_raw(block_idx_key(hash, height).as_bytes())
            .ok_or_else(|| {
                db_error(
                    ErrorKind::BlockNotFound,
                    format!("block {hash} does not exist"),
                )
            })
    }

    /// The position in the pending set of the block with the given hash
    /// and height, when this transaction stored it.
    fn pending_block_index(&self, hash: &Hash, height: u32) -> Option<usize> {
        let state = self.state.borrow();
        let idx = *state.pending_index.get(&hash.0)?;
        (state.pending_blocks[idx].1 == height).then_some(idx)
    }

    fn pending_block_bytes(&self, hash: &Hash, height: u32) -> Option<Vec<u8>> {
        let idx = self.pending_block_index(hash, height)?;
        Some(self.state.borrow().pending_blocks[idx].2.bytes().to_vec())
    }

    /// The raw serialized bytes of the block header for the given hash
    /// and height (dcrd `FetchBlockHeader`).  Headers are read from the
    /// block index row, never the flat files.
    pub fn fetch_block_header(&self, hash: &Hash, height: u32) -> Result<Vec<u8>, Error> {
        self.check_closed()?;
        if let Some(bytes) = self.pending_block_bytes(hash, height) {
            return Ok(bytes[..BLOCK_HDR_SIZE].to_vec());
        }
        let row = self.fetch_block_row(hash, height)?;
        if row.len() < BLOCK_LOC_SIZE + BLOCK_HDR_SIZE {
            return Err(db_error(ErrorKind::Corruption, "corrupt block index row"));
        }
        Ok(row[BLOCK_LOC_SIZE..BLOCK_LOC_SIZE + BLOCK_HDR_SIZE].to_vec())
    }

    /// The raw block headers for the given hashes and heights (dcrd
    /// `FetchBlockHeaders`).
    pub fn fetch_block_headers(&self, blocks: &[(Hash, u32)]) -> Result<Vec<Vec<u8>>, Error> {
        blocks
            .iter()
            .map(|(hash, height)| self.fetch_block_header(hash, *height))
            .collect()
    }

    /// The raw serialized bytes for the block with the given hash and
    /// height (dcrd `FetchBlock`).
    pub fn fetch_block(&self, hash: &Hash, height: u32) -> Result<Vec<u8>, Error> {
        self.check_closed()?;
        if let Some(bytes) = self.pending_block_bytes(hash, height) {
            return Ok(bytes);
        }
        let row = self.fetch_block_row(hash, height)?;
        let loc = BlockLocation::deserialize(&row[..BLOCK_LOC_SIZE]);
        // Only the handle is taken under the store lock; the read runs
        // after it is released, as dcrd's `ReadAt` runs under the file's
        // read lock alone.
        let reader = self
            .db
            .block_store
            .lock()
            .expect("store lock")
            .reader(loc.block_file_num)?;
        reader.read_block(loc)
    }

    /// The raw serialized bytes for the blocks with the given hashes and
    /// heights (dcrd `FetchBlocks`).
    pub fn fetch_blocks(&self, blocks: &[(Hash, u32)]) -> Result<Vec<Vec<u8>>, Error> {
        blocks
            .iter()
            .map(|(hash, height)| self.fetch_block(hash, *height))
            .collect()
    }

    /// The raw bytes of the given region of the block at `height` (dcrd
    /// `FetchBlockRegion`).
    pub fn fetch_block_region(&self, region: &BlockRegion, height: u32) -> Result<Vec<u8>, Error> {
        self.check_closed()?;

        // Pending blocks are served straight from the buffered bytes.
        if let Some(bytes) = self.pending_block_bytes(&region.hash, height) {
            let end = region.offset.checked_add(region.len);
            match end {
                #[allow(
                    clippy::arithmetic_side_effects,
                    reason = "region.offset + region.len is end, which checked_add returned"
                )]
                Some(end) if (end as usize) <= bytes.len() => {
                    return Ok(bytes
                        [region.offset as usize..(region.offset + region.len) as usize]
                        .to_vec());
                }
                _ => {
                    return Err(db_error(
                        ErrorKind::BlockRegionInvalid,
                        format!(
                            "block {} region offset {}, length {} exceeds block length of {}",
                            region.hash,
                            region.offset,
                            region.len,
                            bytes.len()
                        ),
                    ));
                }
            }
        }

        let row = self.fetch_block_row(&region.hash, height)?;
        let loc = BlockLocation::deserialize(&row[..BLOCK_LOC_SIZE]);

        // Ensure the region is within the bounds of the block.  dcrd
        // checks against the full record length (which includes the
        // network, length, and checksum overhead), not the raw block
        // length, so a region reaching into the trailing overhead bytes
        // is accepted and served from the file.
        let end = region.offset.checked_add(region.len);
        match end {
            Some(end) if end <= loc.block_len => {}
            _ => {
                return Err(db_error(
                    ErrorKind::BlockRegionInvalid,
                    format!(
                        "block {} region offset {}, length {} exceeds block length of {}",
                        region.hash, region.offset, region.len, loc.block_len
                    ),
                ));
            }
        }

        let reader = self
            .db
            .block_store
            .lock()
            .expect("store lock")
            .reader(loc.block_file_num)?;
        reader.read_block_region(loc, region.offset, region.len)
    }

    /// The raw bytes of the given block regions, each with the height of
    /// its block (dcrd `FetchBlockRegions`).
    pub fn fetch_block_regions(
        &self,
        regions: &[(BlockRegion, u32)],
    ) -> Result<Vec<Vec<u8>>, Error> {
        regions
            .iter()
            .map(|(region, height)| self.fetch_block_region(region, *height))
            .collect()
    }

    // ------------------------------------------------------------------
    // Commit / rollback.
    // ------------------------------------------------------------------

    fn close(&self) {
        let mut state = self.state.borrow_mut();
        // Drop the opened table BEFORE the transaction it came from.
        // `ReadOnlyTable` holds an `Arc<TransactionGuard>`, so leaving
        // it here would keep the redb read transaction alive past
        // close — and redb will not reclaim a freed page past the
        // oldest live read transaction, so a leaked reader makes the
        // allocator grow the file instead of reusing it.
        state.table = None;
        let open = state.kv.take().is_some();
        // Then the redb handle, after the transaction begun on it, and
        // before a writable transaction releases the writer semaphore:
        // the close lets go of the store's own clone only with that
        // semaphore held, so a writer's clone is never the last one, and
        // redb's close is never left to a thread that has already let the
        // close go ahead.  A reader's can be the last, and its drop here
        // then closes redb's file.
        state.kv_handle = None;
        if open && self.writable {
            // Release the writer semaphore (dcrd releases its write
            // lock when a writable transaction ends).
            let mut busy = self.db.writer_busy.lock().expect("writer flag poisoned");
            *busy = false;
            self.db.writer_cv.notify_one();
            #[cfg(test)]
            crate::release_hook();
        }
        state.pending_blocks.clear();
        state.pending_index.clear();
        state.pending_keys.clear();
        state.pending_removes.clear();
        state.cache_snap = None;
        state.buckets = None;
        // Unrun: whatever closed the transaction short of a successful
        // commit -- a rollback, a drop, a failed commit -- must not run
        // them.  Dropped after the state is released, in case dropping
        // what a closure captured reaches back into this transaction.
        let hooks = std::mem::take(&mut state.on_commit);
        drop(state);
        drop(hooks);
    }

    /// Run `hook` when this transaction commits, once any flush its
    /// commit trips has taken the rows it will write and before this
    /// transaction's rows are published to the overlay.  Hooks run in
    /// registration order.  There is no dcrd counterpart (ADR-0011).
    ///
    /// When a hook runs, the writer semaphore is held, so no other commit
    /// can interleave and no flush can start; any flush this commit
    /// triggered has captured the write cache and sealed a
    /// [`crate::FlushParticipant`]'s work (`seal`); and the transaction's
    /// rows are not yet visible to any other transaction.  That is the
    /// placement an index needs to hand in-memory state over atomically
    /// with its tip row: the commit's own flush cannot capture state the
    /// hook adds, and no reader can see the tip before the hook has run.
    ///
    /// That flush has also written its rows, the participant's
    /// `contribute` among them, and committed, and the participant's
    /// `finished` for it has been called, unless the database hands
    /// flushes to a thread of their own
    /// ([`crate::Options::background_commit`]) and the participant allows
    /// its `contribute` and `finished` to be deferred
    /// ([`crate::FlushParticipant::allows_deferred_contribute`]).  Then
    /// the flush's rows, the participant's and the commit may all still be
    /// to come, and may still fail; `contribute` may run beside this hook
    /// and the hooks of later commits, and `finished` after them.
    ///
    /// A hook never runs if the commit fails, the transaction is rolled
    /// back, or it is dropped.  After the hooks the commit cannot fail:
    /// publishing the rows is an in-memory step.
    ///
    /// A hook must not begin a writable transaction, flush, close, or
    /// register or clear a flush participant on this database: each waits
    /// for the writer semaphore the committing thread holds.  A read-only
    /// transaction is allowed, and sees the store without this
    /// transaction's rows.
    ///
    /// Errors with [`ErrorKind::TxClosed`] on a closed transaction and
    /// [`ErrorKind::TxNotWritable`] on a read-only one, which never
    /// commits.
    pub fn on_commit(&self, hook: impl FnOnce() + Send + 'static) -> Result<(), Error> {
        self.check_closed()?;
        if !self.writable {
            return Err(db_error(
                ErrorKind::TxNotWritable,
                "a commit hook requires a writable database transaction",
            ));
        }
        self.state.borrow_mut().on_commit.push(Box::new(hook));
        Ok(())
    }

    /// Refuse a commit that stages a row under the flush participant's
    /// prefix: in the overlay it would shadow the participant's own rows
    /// for every reader.  An index drop clears the participant before it
    /// deletes, so the only writer of those rows left is the participant.
    fn check_participant_prefix(&self) -> Result<(), Error> {
        let Some(prefix) = self.db.participant_prefix() else {
            return Ok(());
        };
        let state = self.state.borrow();
        // An explicit bound pair: `RangeFrom<&T>` cannot carry an unsized
        // `[u8]` bound.
        let from = (
            std::ops::Bound::Included(&*prefix),
            std::ops::Bound::Unbounded,
        );
        let under = |key: Option<&LayerKey>| key.is_some_and(|k| k.as_bytes().starts_with(&prefix));
        let staged = under(
            state
                .pending_keys
                .range::<[u8], _>(from)
                .next()
                .map(|(k, _)| k),
        ) || under(state.pending_removes.range::<[u8], _>(from).next());
        if staged {
            return Err(db_error(
                ErrorKind::IncompatibleValue,
                format!(
                    "this transaction writes under {:02x?}, the prefix a flush participant owns",
                    &*prefix
                ),
            ));
        }
        Ok(())
    }

    /// Commit all changes made to metadata and block storage (dcrd
    /// `Commit`).  Panics on a managed transaction, exactly like dcrd.
    pub fn commit(&self) -> Result<(), Error> {
        if self.managed {
            panic!("managed transaction commit not allowed");
        }
        self.commit_internal()
    }

    pub(crate) fn commit_internal(&self) -> Result<(), Error> {
        self.check_closed()?;

        // Regarding read-only transactions, a commit is a rollback per
        // the dcrd semantics.
        if !self.writable {
            self.close();
            return Err(db_error(
                ErrorKind::TxNotWritable,
                "Commit requires a writable database transaction",
            ));
        }

        // Nothing is written on a latched store -- not the block files,
        // not a flush.  `begin` re-checks the latch once it holds the
        // writer semaphore, and without background commits only a
        // semaphore holder can set it, so this cannot fire then.  With
        // them it is the check that refuses a transaction begun before a
        // commit failed on its own thread and committed after: no block
        // bytes are written and no hook runs.
        if let Err(e) = self.db.check_writable() {
            self.close();
            return Err(e);
        }

        // Before anything is written: a refused commit leaves no block
        // bytes to roll back and does not latch the store.
        if let Err(e) = self.check_participant_prefix() {
            self.close();
            return Err(e);
        }

        // Write the pending blocks to the flat files first, recording
        // their locations, then stage the block index rows and the
        // updated write cursor into the metadata transaction, and only
        // then commit it.  A crash between the file writes and the
        // metadata commit leaves orphaned file bytes which are
        // reconciled away on the next open, matching dcrd's ordering.
        let pending: Vec<(Hash, u32, PendingBlock)> =
            std::mem::take(&mut self.state.borrow_mut().pending_blocks);
        let rollback_pos = {
            let store = self.db.block_store.lock().expect("store lock");
            (store.write_file_num, store.write_offset)
        };

        let result = (|| -> Result<(), Error> {
            let mut locations = Vec::with_capacity(pending.len());
            {
                let mut store = self.db.block_store.lock().expect("store lock");
                for (hash, height, block) in &pending {
                    let loc = match block {
                        PendingBlock::Bytes(raw) => store.write_block(raw)?,
                        PendingBlock::Record(record) => store.write_block_record(record)?,
                    };
                    locations.push((*hash, *height, loc, block.bytes()));
                }
                // The metadata cache flush syncs the files; per-
                // commit syncing is gone with it (dcrd ffldb).

                // Stage the block index rows: location || header, keyed
                // by height || hash.
                for (hash, height, loc, bytes) in &locations {
                    let mut row = Vec::with_capacity(BLOCK_LOC_SIZE + BLOCK_HDR_SIZE);
                    row.extend_from_slice(&loc.serialize());
                    row.extend_from_slice(&bytes[..BLOCK_HDR_SIZE]);
                    self.put_raw(block_idx_key(hash, *height), row)?;
                }

                // Stage the new write cursor position.
                let row = serialize_write_row(store.write_file_num, store.write_offset);
                self.put_raw(
                    bucketized_key(METADATA_BUCKET_ID, WRITE_LOC_KEY),
                    row.to_vec(),
                )?;
            }

            Ok(())
        })();

        if result.is_err() {
            // Roll the flat files back to their pre-transaction state
            // (dcrd's `rollback` closure over `handleRollback`).  Its
            // result is only for tests: like `handleRollback` it logs
            // each failure as a `ROLLBACK:` warning and puts the write
            // cursor back whatever fails.
            let _ = self
                .db
                .block_store
                .lock()
                .expect("store lock")
                .rollback_to(rollback_pos.0, rollback_pos.1);
            self.close();
            return result;
        }

        // dcrd's `commitTx` order: when the thresholds demand it,
        // flush the accumulated window FIRST — a flush failure fails
        // the commit with this transaction unapplied (the files roll
        // back below) — and only then publish this transaction's
        // changes to the cache.  The flush is `Database::flush`'s own
        // helper, so the capture, the unlocked commit and the
        // retirement cannot drift between the two; this transaction
        // holds the writer semaphore throughout, and the helper waits
        // for a flush whose commit is still under way on its own thread
        // before it captures another, which together keep two flushes
        // from overlapping.  With background commits the helper returns
        // once the window is captured, what the block-file sync owes is
        // taken and redb's write transaction is open; a failure in
        // syncing the block files, writing the rows or the redb commit
        // then latches the store from the thread they were handed to
        // instead of failing this commit.  The
        // layers a flush retired here are kept until that semaphore is
        // released, at the end; those of a flush that was handed over
        // are retired and let go of by the thread it was handed to.
        let retired = crate::flush_locked(&self.db, crate::FlushKind::Commit);
        if let Err(e) = retired {
            // Already latched, by `flush_locked` or by the thread an
            // earlier flush's commit failed on: the dirty set is still
            // in the cache, so without the latch the next commit retries
            // it and can report success after this failure (see
            // DbInner::mark_fatal).  It has to be latched BEFORE `close`
            // releases the writer semaphore, which wakes the next queued
            // writer: latching after it let that writer in unlatched, to
            // re-run this flush -- and a block file fsync that failed
            // once can succeed on the retry without the bytes having
            // reached disk.
            let _ = self
                .db
                .block_store
                .lock()
                .expect("store lock")
                .rollback_to(rollback_pos.0, rollback_pos.1);
            self.close();
            return Err(e);
        }

        // The commit's own flush has taken everything it will write and
        // this transaction's rows are not yet published: the one point
        // at which a hook's in-memory change and this transaction's rows
        // become visible together, with no flush able to capture one
        // without the other (see `on_commit`).
        let hooks = std::mem::take(&mut self.state.borrow_mut().on_commit);
        for hook in hooks {
            hook();
        }

        let (puts, removes) = {
            let mut state = self.state.borrow_mut();
            // Release this transaction's snapshot so the cache's newest
            // layer is unshared when it applies the changes below and
            // can take them in place (a snapshot naming that layer
            // forces the commit to seal a fresh layer instead).
            state.cache_snap = None;
            // And its bucket index, so the cache changes its own map in
            // place when this transaction created or deleted a bucket.
            state.buckets = None;
            (
                std::mem::take(&mut state.pending_keys),
                std::mem::take(&mut state.pending_removes),
            )
        };
        self.db
            .cache
            .lock()
            .expect("cache lock poisoned")
            .commit_pending(puts, removes.into_iter());
        self.close();
        // Freed here, with the cache lock and the writer semaphore both
        // released, so no other thread waits for either while this one
        // frees the rows of a whole flush.  Nothing could read them any
        // more: the flush unpublished them, and this transaction's own
        // snapshot, the last to name them unless a reader that began
        // before the flush still does, was let go above.
        drop(retired);
        Ok(())
    }

    /// Undo all changes made to metadata and block storage (dcrd
    /// `Rollback`).  Panics on a managed transaction, exactly like
    /// dcrd.
    pub fn rollback(&self) -> Result<(), Error> {
        if self.managed {
            panic!("managed transaction rollback not allowed");
        }
        self.rollback_internal()
    }

    pub(crate) fn rollback_internal(&self) -> Result<(), Error> {
        self.check_closed()?;
        self.close();
        Ok(())
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if !self.is_closed() {
            self.close();
        }
    }
}

/// Seed for constructing a transaction; keeps redb types out of the
/// public signature.
#[allow(clippy::large_enum_variant)]
pub(crate) enum KvTxSeed {
    Read(redb::ReadTransaction),
    /// A writable transaction's read snapshot; the writer semaphore
    /// is already held by the caller.
    Write(redb::ReadTransaction),
}

// ----------------------------------------------------------------------
// Buckets.
// ----------------------------------------------------------------------

/// A collection of key/value pairs within a transaction (dcrd
/// `database.Bucket`).
#[derive(Copy, Clone)]
pub struct Bucket<'tx> {
    tx: &'tx Transaction,
    id: [u8; 4],
}

impl<'tx> Bucket<'tx> {
    /// Retrieve the nested bucket with the given key, or `None` if it
    /// does not exist (dcrd `Bucket`).
    ///
    /// dcrd reads the bucket's index row for this on every call
    /// (`ffldb/db.go:598-614`).  The answer here is that row's, taken
    /// from the bucket index the transaction holds and from its own
    /// pending changes once it has created or deleted a bucket, without
    /// the read.  The one difference is a store read error: the read
    /// turns it into `None`, and no read is made here to meet it (see
    /// the `bucketindex` module docs).
    pub fn bucket(&self, key: &[u8]) -> Option<Bucket<'tx>> {
        if self.tx.check_closed().is_err() {
            return None;
        }
        let id = self.tx.child_bucket_id(self.id, key)?;
        Some(Bucket { tx: self.tx, id })
    }

    /// [`Self::bucket`] as dcrd makes it, by reading the bucket's index
    /// row through the transaction's layered view: the answer the bucket
    /// index has to give.
    #[cfg(test)]
    pub(crate) fn bucket_from_rows(&self, key: &[u8]) -> Option<Bucket<'tx>> {
        if self.tx.check_closed().is_err() {
            return None;
        }
        let child_id = self
            .tx
            .fetch_raw(bucket_index_key(self.id, key).as_bytes())?;
        let id: [u8; 4] = child_id.as_slice().try_into().ok()?;
        Some(Bucket { tx: self.tx, id })
    }

    /// Create and return a new nested bucket with the given key (dcrd
    /// `CreateBucket`).
    pub fn create_bucket(&self, key: &[u8]) -> Result<Bucket<'tx>, Error> {
        self.tx.check_closed()?;
        if !self.tx.writable {
            return Err(db_error(
                ErrorKind::TxNotWritable,
                "create bucket requires a writable database transaction",
            ));
        }
        if key.is_empty() {
            return Err(db_error(
                ErrorKind::BucketNameRequired,
                "create bucket requires a key",
            ));
        }

        // Ensure the bucket does not already exist.
        let bidx_key = bucket_index_key(self.id, key);
        if self.tx.has_raw(bidx_key.as_bytes()) {
            return Err(db_error(ErrorKind::BucketExists, "bucket already exists"));
        }

        // Find the appropriate next bucket ID to use for the new
        // bucket; the special internal block index keeps its fixed ID.
        let child_id = if self.id == METADATA_BUCKET_ID && key == BLOCK_IDX_BUCKET_NAME {
            BLOCK_IDX_BUCKET_ID
        } else {
            self.tx.next_bucket_id()?
        };

        // Add the new bucket to the bucket index.
        self.tx.put_raw(bidx_key, child_id.to_vec())?;
        Ok(Bucket {
            tx: self.tx,
            id: child_id,
        })
    }

    /// Create and return the nested bucket with the given key, creating
    /// it only if it does not already exist (dcrd
    /// `CreateBucketIfNotExists`).
    pub fn create_bucket_if_not_exists(&self, key: &[u8]) -> Result<Bucket<'tx>, Error> {
        self.tx.check_closed()?;
        if !self.tx.writable {
            return Err(db_error(
                ErrorKind::TxNotWritable,
                "create bucket requires a writable database transaction",
            ));
        }
        if let Some(bucket) = self.bucket(key) {
            return Ok(bucket);
        }
        self.create_bucket(key)
    }

    /// Remove the nested bucket with the given key, including all its
    /// nested buckets and keys (dcrd `DeleteBucket`).
    pub fn delete_bucket(&self, key: &[u8]) -> Result<(), Error> {
        self.tx.check_closed()?;
        if !self.tx.writable {
            return Err(db_error(
                ErrorKind::TxNotWritable,
                "delete bucket requires a writable database transaction",
            ));
        }

        let bidx_key = bucket_index_key(self.id, key);
        let child_id = self.tx.fetch_raw(bidx_key.as_bytes()).ok_or_else(|| {
            db_error(
                ErrorKind::BucketNotFound,
                format!("bucket {:?} does not exist", String::from_utf8_lossy(key)),
            )
        })?;

        // Remove all nested buckets and their keys, iteratively.
        let mut child_ids: Vec<Vec<u8>> = vec![child_id];
        while let Some(child_id) = child_ids.pop() {
            // Delete all keys in the nested bucket.
            for raw_key in self.tx.scan_prefix_keys(&child_id) {
                self.tx.delete_raw(LayerKey::new(raw_key))?;
            }

            // Iterate through all nested buckets, pushing their IDs
            // for the next iteration and removing their index rows.  The
            // ID is the row's value, taken from the scan as dcrd takes
            // it from its cursor (`rawValue`).
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "constant lengths: 4 + 4 = 8"
            )]
            let mut prefix = Vec::with_capacity(BUCKET_INDEX_PREFIX.len() + 4);
            prefix.extend_from_slice(BUCKET_INDEX_PREFIX);
            prefix.extend_from_slice(&child_id);
            let rows = self
                .tx
                .scan_prefix_window(&prefix, None, None, true, true)
                .rows;
            for (raw_key, grandchild) in rows {
                child_ids.push(grandchild);
                self.tx.delete_raw(LayerKey::new(raw_key))?;
            }
        }

        // Remove the nested bucket from the bucket index.
        self.tx.delete_raw(bidx_key)
    }

    /// Invoke the function with every key/value pair in the bucket, not
    /// including nested buckets; the first error from the callback is
    /// returned (dcrd `ForEach`).
    ///
    /// A store read error ends the walk where it happened, as a
    /// goleveldb iterator error ends ffldb's cursor, which `ForEach`
    /// never asks about; see [`Self::try_for_each`] for the walk that
    /// reports it.
    pub fn for_each(
        &self,
        fn_: impl FnMut(&[u8], &[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.walk(false, fn_)
    }

    /// [`Self::for_each`], but a store read error fails the walk instead
    /// of ending it, the way dcrd's UTXO backend checks `iter.Error()`
    /// after its walk (`levelDbUtxoBackend.FetchStats`,
    /// `internal/blockchain/utxobackend.go:577-579`).
    pub fn try_for_each(
        &self,
        fn_: impl FnMut(&[u8], &[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.walk(true, fn_)
    }

    /// The body of [`Self::for_each`] and [`Self::try_for_each`].
    ///
    /// Streamed in windows of [`WALK_WINDOW`] rows: each window is read
    /// with its values in one pass and handed out before the next is
    /// read, so the walk holds one window rather than every key of the
    /// bucket, and reads each value once rather than scanning keys and
    /// then looking every value up again.  No borrow of the transaction
    /// is held while `fn_` runs.
    fn walk(
        &self,
        strict: bool,
        mut fn_: impl FnMut(&[u8], &[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.tx.check_closed()?;
        let mut after: Option<Vec<u8>> = None;
        let mut read_store = true;
        loop {
            let window = self.tx.scan_prefix_window(
                &self.id,
                after.as_deref(),
                Some(WALK_WINDOW),
                true,
                read_store,
            );
            if let Some(e) = window.store_error {
                if strict {
                    return Err(e);
                }
                // The store stream stays ended for the rest of the walk,
                // as the invalidated iterator does; the overlay goes on.
                read_store = false;
            }
            let full = window.rows.len() == WALK_WINDOW;
            for (raw_key, value) in &window.rows {
                fn_(&raw_key[4..], value)?;
            }
            if !full {
                return Ok(());
            }
            after = window.rows.into_iter().next_back().map(|(key, _)| key);
        }
    }

    /// Invoke the function with the key of every nested bucket in the
    /// bucket; the first error from the callback is returned (dcrd
    /// `ForEachBucket`).
    pub fn for_each_bucket(
        &self,
        mut fn_: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.tx.check_closed()?;
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "constant lengths: 4 + 4 = 8"
        )]
        let mut prefix = Vec::with_capacity(BUCKET_INDEX_PREFIX.len() + 4);
        prefix.extend_from_slice(BUCKET_INDEX_PREFIX);
        prefix.extend_from_slice(&self.id);
        let strip = prefix.len();
        for raw_key in self.tx.scan_prefix_keys(&prefix) {
            fn_(&raw_key[strip..])?;
        }
        Ok(())
    }

    /// A new cursor over the bucket's key/value pairs and nested
    /// buckets (dcrd `Cursor`).
    pub fn cursor(&self) -> Cursor<'tx> {
        if self.tx.check_closed().is_err() {
            return Cursor {
                tx: self.tx,
                bucket_id: self.id,
                keys: Vec::new(),
                pos: CursorPos::Exhausted,
                parked: None,
            };
        }

        // Materialize the raw keys of both the key/value range and the
        // nested-bucket index range, merged in raw byte order, exactly
        // matching ffldb's merged iterators (the cursor contract makes
        // the view a snapshot: later bucket changes invalidate it).
        let mut keys = self.tx.scan_prefix_keys(&self.id);
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "constant lengths: 4 + 4 = 8"
        )]
        let mut prefix = Vec::with_capacity(BUCKET_INDEX_PREFIX.len() + 4);
        prefix.extend_from_slice(BUCKET_INDEX_PREFIX);
        prefix.extend_from_slice(&self.id);
        keys.extend(self.tx.scan_prefix_keys(&prefix));
        keys.sort();

        Cursor {
            tx: self.tx,
            bucket_id: self.id,
            keys,
            pos: CursorPos::Unpositioned,
            parked: None,
        }
    }

    /// A cursor over at most `limit` keys starting strictly after
    /// `after` (`None` from the beginning).
    ///
    /// [`Self::cursor`] snapshots the whole bucket, which is fine for a
    /// bucket read once but quadratic for dcrd's batched
    /// `incrementalFlatDrop`: dcrd's cursor is a pair of lazy merged
    /// iterators, so restarting it per batch costs nothing, while
    /// restarting this one re-materializes every remaining key.
    ///
    /// The nested-bucket index rows are appended only when the window
    /// reaches the end of the key range, so a flat drop of a bucket
    /// that wrongly has children still fails with
    /// [`ErrorKind::IncompatibleValue`] -- at the end of the walk
    /// rather than partway through it.
    pub fn cursor_window(&self, after: Option<&[u8]>, limit: usize) -> Cursor<'tx> {
        if self.tx.check_closed().is_err() {
            return Cursor {
                tx: self.tx,
                bucket_id: self.id,
                keys: Vec::new(),
                pos: CursorPos::Exhausted,
                parked: None,
            };
        }

        // The cursor's keys carry the bucket id prefix, so a resume key
        // from a previous window is already in the right space.
        let mut keys = self
            .tx
            .scan_prefix_keys_window(&self.id, after, Some(limit));
        if keys.len() < limit {
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "constant lengths: 4 + 4 = 8"
            )]
            let mut prefix = Vec::with_capacity(BUCKET_INDEX_PREFIX.len() + 4);
            prefix.extend_from_slice(BUCKET_INDEX_PREFIX);
            prefix.extend_from_slice(&self.id);
            // These sort after the key/value rows, so they fill the tail
            // of the walk -- but they have to respect the window like
            // everything else.  Scanning them unbounded overruns
            // `limit`, and re-appending them on every window makes a
            // caller that resumes from the last key walk forever.
            let bidx_after = after.filter(|a| a.starts_with(BUCKET_INDEX_PREFIX));
            keys.extend(self.tx.scan_prefix_keys_window(
                &prefix,
                bidx_after,
                Some(limit.saturating_sub(keys.len())),
            ));
        }
        keys.sort();

        Cursor {
            tx: self.tx,
            bucket_id: self.id,
            keys,
            pos: CursorPos::Unpositioned,
            parked: None,
        }
    }

    /// Whether the bucket is writable (dcrd `Writable`).
    pub fn writable(&self) -> bool {
        self.tx.writable
    }

    /// The bucket's four-byte id, which starts the raw key of every row in
    /// it.  No dcrd counterpart: it is the prefix a flush participant
    /// registers (ADR-0011) and the one [`Transaction::try_first_after`]
    /// scans.  A deleted and re-created bucket gets a fresh id.
    pub fn raw_id(&self) -> [u8; 4] {
        self.id
    }

    /// Save the specified key/value pair to the bucket (dcrd `Put`).
    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        self.check_put(key)?;
        self.tx
            .put_raw(bucketized_key(self.id, key), value.to_vec())
    }

    /// [`Self::put`] of a value the caller built for the row and has no
    /// more use for.  The buffer itself is staged, where `put` stages a
    /// copy of the borrowed bytes; dcrd's `Put` hands the caller's slice
    /// to `putKey`, which keeps it too (`ffldb/db.go:1058-1065`).  The
    /// checks, their order and their errors are `put`'s, and so is what
    /// the row holds.  Capacity past the value's length is given back
    /// first, so the pending set and the cache overlay retain what they
    /// would for the copy.
    pub fn put_owned(&self, key: &[u8], mut value: Vec<u8>) -> Result<(), Error> {
        self.check_put(key)?;
        value.shrink_to_fit();
        self.tx.put_raw(bucketized_key(self.id, key), value)
    }

    /// The checks of dcrd's `Put`, in its order (`ffldb/db.go:877-893`).
    fn check_put(&self, key: &[u8]) -> Result<(), Error> {
        self.tx.check_closed()?;
        if !self.tx.writable {
            return Err(db_error(
                ErrorKind::TxNotWritable,
                "setting a key requires a writable database transaction",
            ));
        }
        if key.is_empty() {
            return Err(db_error(ErrorKind::KeyRequired, "put requires a key"));
        }
        Ok(())
    }

    /// The value for the given key, or `None` if it does not exist;
    /// keys that exist with no value return an empty vector (dcrd
    /// `Get`).
    ///
    /// A store read error also returns `None`, as ffldb's does
    /// (`dbCacheSnapshot.Get` discards the leveldb error); see
    /// [`Self::try_get`] for the read that reports it.
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        if self.tx.check_closed().is_err() || key.is_empty() {
            return None;
        }
        self.tx.fetch_raw(bucketized_key(self.id, key).as_bytes())
    }

    /// [`Self::get`], but a store read error is returned rather than
    /// read as a missing key.
    ///
    /// For the rows dcrd keeps in its UTXO backend, whose `Get` returns
    /// `nil` only for `leveldb.ErrNotFound` and propagates every other
    /// error (`internal/blockchain/utxobackend.go:392-401`).  This port
    /// stores those rows in the ffldb-layout store, where [`Self::get`]
    /// keeps ffldb's error-as-absence answer -- which, on the UTXO set,
    /// turns a failing disk into a missing output and a valid block into
    /// `ErrMissingTxOut`.
    pub fn try_get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.tx.check_closed()?;
        if key.is_empty() {
            return Ok(None);
        }
        self.tx
            .try_fetch_raw(bucketized_key(self.id, key).as_bytes())
    }

    /// Remove the specified key from the bucket; deleting a key that
    /// does not exist does not return an error, and — reproducing
    /// ffldb's behavior exactly — neither does deleting an empty key,
    /// despite the interface contract mentioning `ErrKeyRequired`
    /// (ffldb returns nil for an empty key) (dcrd `Delete`).
    pub fn delete(&self, key: &[u8]) -> Result<(), Error> {
        self.tx.check_closed()?;
        if !self.tx.writable {
            return Err(db_error(
                ErrorKind::TxNotWritable,
                "deleting a value requires a writable database transaction",
            ));
        }
        if key.is_empty() {
            return Ok(());
        }
        self.tx.delete_raw(bucketized_key(self.id, key))
    }
}

// ----------------------------------------------------------------------
// Cursors.
// ----------------------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq)]
enum CursorPos {
    /// Not yet positioned via first/last/seek: movement and accessor
    /// calls behave as exhausted.
    Unpositioned,
    At(usize),
    Exhausted,
}

/// A cursor over the key/value pairs and nested buckets of a bucket
/// (dcrd `database.Cursor`).  The view is a snapshot taken at creation;
/// bucket modifications other than [`Cursor::delete`] invalidate it,
/// per the interface contract.
pub struct Cursor<'tx> {
    tx: &'tx Transaction,
    bucket_id: [u8; 4],
    keys: Vec<Vec<u8>>,
    pos: CursorPos,
    /// The key/value pair parked by `delete` until the next movement
    /// (dcrd's cursor keeps returning the deleted pair from its
    /// parked iterators until it is repositioned).
    parked: Option<(Vec<u8>, ParkedValue)>,
}

/// The value half of a pair [`Cursor::delete`] parked.
enum ParkedValue {
    /// What the transaction's pending changes held for the key: its
    /// pending value, or `None` when they had already deleted it.
    Pending(Option<Vec<u8>>),
    /// The pending changes did not hold the key, so its value is the
    /// one beneath them -- in the cache snapshot or the store, which the
    /// delete leaves alone -- and is read from there only if
    /// [`Cursor::value`] asks.  dcrd's `Cursor.Delete` reads nothing;
    /// reading the value eagerly here cost a B-tree lookup per deleted
    /// row, 66,494,886 of them for a drop of mainnet's `existsaddridx`.
    Committed,
}

impl Cursor<'_> {
    /// Whether the key at the index was deleted in this transaction
    /// after the cursor materialized (dcrd's `skipPendingUpdates`
    /// consults the live pending-remove set on every movement).
    fn removed(&self, i: usize) -> bool {
        self.keys.get(i).is_some_and(|k| {
            self.tx
                .state
                .borrow()
                .pending_removes
                .contains(k.as_slice())
        })
    }

    /// Move forward from a removed key to the next live one.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "i < self.keys.len() before each increment: callers pass a cursor position \
                  and the loop returns once i reaches the length"
    )]
    fn skip_forward(&mut self, mut i: usize) -> bool {
        loop {
            i += 1;
            if i >= self.keys.len() {
                self.pos = CursorPos::Exhausted;
                return false;
            }
            if !self.removed(i) {
                self.pos = CursorPos::At(i);
                return true;
            }
        }
    }

    /// Move backward from a removed key to the previous live one.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "i > 0: the loop returns at i == 0 before decrementing"
    )]
    fn skip_backward(&mut self, mut i: usize) -> bool {
        loop {
            if i == 0 {
                self.pos = CursorPos::Exhausted;
                return false;
            }
            i -= 1;
            if !self.removed(i) {
                self.pos = CursorPos::At(i);
                return true;
            }
        }
    }

    fn current_raw(&self) -> Option<&[u8]> {
        match self.pos {
            CursorPos::At(i) => self.keys.get(i).map(|k| k.as_slice()),
            _ => None,
        }
    }

    /// Delete the current key/value pair without invalidating the
    /// cursor (dcrd `Cursor.Delete`).
    pub fn delete(&mut self) -> Result<(), Error> {
        self.tx.check_closed()?;
        let Some(raw) = self.current_raw() else {
            return Err(db_error(
                ErrorKind::IncompatibleValue,
                "cursor is exhausted",
            ));
        };
        if raw.starts_with(BUCKET_INDEX_PREFIX) {
            return Err(db_error(
                ErrorKind::IncompatibleValue,
                "buckets may not be deleted via a cursor",
            ));
        }
        if !self.tx.writable {
            return Err(db_error(
                ErrorKind::TxNotWritable,
                "deleting a value requires a writable database transaction",
            ));
        }
        let raw = raw.to_vec();
        // Park the deleted pair: dcrd's cursor keeps returning it
        // from its iterators until the cursor moves.
        let parked = match self.tx.delete_raw_reporting(&raw)? {
            Some(pending) => ParkedValue::Pending(pending),
            None => ParkedValue::Committed,
        };
        self.parked = Some((raw, parked));
        Ok(())
    }

    /// Position at the first entry; returns whether it exists (dcrd
    /// `First`).
    pub fn first(&mut self) -> bool {
        self.parked = None;
        if self.tx.check_closed().is_err() || self.keys.is_empty() {
            self.pos = CursorPos::Exhausted;
            return false;
        }
        self.pos = CursorPos::At(0);
        if self.removed(0) {
            return self.skip_forward(0);
        }
        true
    }

    /// Position at the last entry; returns whether it exists (dcrd
    /// `Last`).
    pub fn last(&mut self) -> bool {
        self.parked = None;
        if self.tx.check_closed().is_err() || self.keys.is_empty() {
            self.pos = CursorPos::Exhausted;
            return false;
        }
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "keys is non-empty, checked above"
        )]
        let last = self.keys.len() - 1;
        self.pos = CursorPos::At(last);
        if self.removed(last) {
            return self.skip_backward(last);
        }
        true
    }

    /// Move forward one entry; returns whether it exists (dcrd `Next`).
    /// Deliberately mirrors dcrd's cursor API rather than implementing
    /// `Iterator` (positioning and accessors are separate operations).
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> bool {
        if self.tx.check_closed().is_err() {
            return false;
        }
        self.parked = None;
        match self.pos {
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "i is a cursor position, i < self.keys.len(), so i + 1 <= len"
            )]
            CursorPos::At(i) if i + 1 < self.keys.len() => {
                self.pos = CursorPos::At(i + 1);
                if self.removed(i + 1) {
                    return self.skip_forward(i + 1);
                }
                true
            }
            CursorPos::At(_) => {
                self.pos = CursorPos::Exhausted;
                false
            }
            _ => false,
        }
    }

    /// Move backward one entry; returns whether it exists (dcrd
    /// `Prev`).
    pub fn prev(&mut self) -> bool {
        if self.tx.check_closed().is_err() {
            return false;
        }
        self.parked = None;
        match self.pos {
            #[allow(clippy::arithmetic_side_effects, reason = "i > 0 by the match guard")]
            CursorPos::At(i) if i > 0 => {
                self.pos = CursorPos::At(i - 1);
                if self.removed(i - 1) {
                    return self.skip_backward(i - 1);
                }
                true
            }
            CursorPos::At(_) => {
                self.pos = CursorPos::Exhausted;
                false
            }
            _ => false,
        }
    }

    /// Position at the first entry with key greater than or equal to
    /// the given key; returns whether it exists (dcrd `Seek`).
    pub fn seek(&mut self, seek: &[u8]) -> bool {
        if self.tx.check_closed().is_err() {
            return false;
        }
        self.parked = None;
        let seek_key = bucketized_key(self.bucket_id, seek);
        let idx = self
            .keys
            .partition_point(|k| k.as_slice() < seek_key.as_bytes());
        if idx < self.keys.len() {
            self.pos = CursorPos::At(idx);
            if self.removed(idx) {
                return self.skip_forward(idx);
            }
            true
        } else {
            self.pos = CursorPos::Exhausted;
            false
        }
    }

    /// The current key, with the bucket prefixes stripped (dcrd `Key`);
    /// `None` when exhausted.
    pub fn key(&self) -> Option<Vec<u8>> {
        if self.tx.check_closed().is_err() {
            return None;
        }
        let raw = match &self.parked {
            Some((k, _)) => k.as_slice(),
            None => self.current_raw()?,
        };
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "constant lengths: 4 + 4 = 8"
        )]
        if raw.starts_with(BUCKET_INDEX_PREFIX) {
            return Some(raw[BUCKET_INDEX_PREFIX.len() + 4..].to_vec());
        }
        Some(raw[4..].to_vec())
    }

    /// The current key including its bucket prefix, for resuming a
    /// [`Bucket::cursor_window`] walk where this one stopped.
    ///
    /// [`Self::key`] strips the prefix, which is what callers want to
    /// read but not what the windowed scan ranges over.
    pub fn raw_key(&self) -> Option<Vec<u8>> {
        if self.tx.check_closed().is_err() {
            return None;
        }
        match &self.parked {
            Some((k, _)) => Some(k.clone()),
            None => self.current_raw().map(<[u8]>::to_vec),
        }
    }

    /// The current value; `None` when exhausted or pointing at a nested
    /// bucket (dcrd `Value`).
    pub fn value(&self) -> Option<Vec<u8>> {
        if self.tx.check_closed().is_err() {
            return None;
        }
        if let Some((k, v)) = &self.parked {
            if k.starts_with(BUCKET_INDEX_PREFIX) {
                return None;
            }
            return match v {
                ParkedValue::Pending(v) => v.clone(),
                ParkedValue::Committed => {
                    Transaction::fetch_committed(&self.tx.state.borrow(), k).unwrap_or(None)
                }
            };
        }
        let raw = self.current_raw()?;
        if raw.starts_with(BUCKET_INDEX_PREFIX) {
            return None;
        }
        self.tx.fetch_raw(raw)
    }
}

#[cfg(test)]
mod block_idx_key_tests {
    use dcroxide_chainhash::Hash;
    use dcroxide_wire::BlockHeader;

    use super::{BLOCK_IDX_BUCKET_ID, block_idx_key, serialized_block_height};

    /// The key is the bucket ID, the height big-endian, then the hash,
    /// and it reads back into the same pair.
    #[test]
    fn the_key_is_the_bucket_id_the_big_endian_height_and_the_hash() {
        let hash = Hash(core::array::from_fn(|i| i as u8));
        for height in [0u32, 1, 255, 256, 0x0102_0304, u32::MAX] {
            let key = block_idx_key(&hash, height);
            let key = key.as_bytes();
            assert_eq!(key.len(), 40);
            assert_eq!(key[..4], BLOCK_IDX_BUCKET_ID);
            assert_eq!(key[4..8], height.to_be_bytes());
            assert_eq!(key[8..], hash.0);
            let read = u32::from_be_bytes(key[4..8].try_into().expect("four bytes"));
            assert_eq!(
                (read, Hash(key[8..].try_into().expect("a hash"))),
                (height, hash)
            );
        }
    }

    /// Keys sort by height first and then by hash, whatever order the
    /// heights' little-endian bytes or the hashes would give.
    #[test]
    fn keys_sort_by_height_then_hash() {
        let low = Hash([0x00; 32]);
        let high = Hash([0xff; 32]);
        let mut pairs = vec![
            (65_536u32, low),
            (1, high),
            (256, low),
            (255, high),
            (7, high),
            (7, low),
            (0, high),
            (16_777_216, low),
        ];
        let mut by_key = pairs.clone();
        by_key.sort_by_key(|(height, hash)| block_idx_key(hash, *height).as_bytes().to_vec());
        pairs.sort();
        assert_eq!(by_key, pairs);
    }

    /// The height read from a block's bytes is the one its header
    /// records, at the offset the wire format puts it.
    #[test]
    fn the_stored_height_is_the_one_the_header_records() {
        for height in [0u32, 1, 0x0102_0304, u32::MAX] {
            // Every neighbour of the height set to bytes it is not.
            let header = BlockHeader {
                version: -1,
                prev_block: Hash([0x11; 32]),
                merkle_root: Hash([0x22; 32]),
                stake_root: Hash([0x33; 32]),
                vote_bits: u16::MAX,
                final_state: [0x44; 6],
                voters: u16::MAX,
                fresh_stake: u8::MAX,
                revocations: u8::MAX,
                pool_size: u32::MAX,
                bits: u32::MAX,
                sbits: -1,
                height,
                size: 0x5555_5555,
                timestamp: 0x6666_6666,
                nonce: u32::MAX,
                extra_data: [0x77; 32],
                stake_version: 0x0a0b_0c0d,
            };
            let mut raw = header.serialize().to_vec();
            assert_eq!(serialized_block_height(&raw), Some(height));
            // Trailing transactions change nothing.
            raw.extend_from_slice(&[0xee; 64]);
            assert_eq!(serialized_block_height(&raw), Some(height));
        }
        assert_eq!(serialized_block_height(&[0u8; 131]), None);
        assert_eq!(serialized_block_height(&[]), None);
    }
}

#[cfg(test)]
mod put_owned_tests {
    //! [`Bucket::put_owned`] against [`Bucket::put`]: the same checks in
    //! the same order with the same errors, and the same row in the
    //! pending set, in the cache overlay and in the durable store.

    use std::sync::{Arc, Mutex};

    use tempfile::TempDir;

    use crate::{Database, ErrorKind, Options};

    /// simnet magic, matching the interface battery.
    const NET: u32 = 0x1214_1c16;

    /// Every key and value a flush handed the engine, in order.
    type Written = Arc<Mutex<Vec<(Vec<u8>, Option<Vec<u8>>)>>>;

    /// What one flush reported: its entries and the bytes it counted.
    type Flushed = Arc<Mutex<Vec<(usize, u64)>>>;

    /// A new store that records what its flushes write and report.
    pub(super) fn recording_db() -> (TempDir, Database, Written, Flushed) {
        let dir = TempDir::new().expect("tempdir");
        let written: Written = Arc::default();
        let flushed: Flushed = Arc::default();
        let mut opts = Options::new(dir.path().join("db"), NET);
        let sink = Arc::clone(&written);
        opts.write_log = Some(Arc::new(move |key: &[u8], value: Option<&[u8]>| {
            sink.lock()
                .expect("write log")
                .push((key.to_vec(), value.map(<[u8]>::to_vec)));
        }));
        let sink = Arc::clone(&flushed);
        opts.flush_observer = Some(Arc::new(move |obs: &crate::FlushObservation| {
            sink.lock()
                .expect("observations")
                .push((obs.dirty_entries, obs.dirty_bytes));
        }));
        let db = Database::create(&opts).expect("create");
        (dir, db, written, flushed)
    }

    /// The rows the two stores are given: empty, short and long values,
    /// a key written twice, and a key deleted and written again.
    fn rows() -> Vec<(&'static [u8], Vec<u8>)> {
        vec![
            (b"empty", Vec::new()),
            (b"short", vec![0x01]),
            (b"long", (0..=255u8).cycle().take(5000).collect()),
            (b"twice", vec![0x02; 40]),
            (b"twice", vec![0x03; 7]),
            (b"deleted", vec![0x04; 9]),
        ]
    }

    /// The value in a buffer with room to spare, as a serializer that
    /// reserved more than it wrote would hand it over.
    fn roomy(value: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(value.len().saturating_add(64));
        buf.extend_from_slice(value);
        buf
    }

    /// Write [`rows`] in one transaction, owned or borrowed, and return
    /// what the transaction read back before it committed.
    fn write_rows(db: &Database, owned: bool) -> Vec<Option<Vec<u8>>> {
        let tx = db.begin(true).expect("begin");
        let bucket = tx.metadata().create_bucket(b"rows").expect("bucket");
        bucket.put(b"deleted", b"before").expect("put");
        bucket.delete(b"deleted").expect("delete");
        for (key, value) in rows() {
            if owned {
                bucket.put_owned(key, roomy(&value)).expect("put_owned");
            } else {
                bucket.put(key, &value).expect("put");
            }
        }
        // No pending value holds more than its bytes, whichever way it
        // came in.
        for (key, value) in &tx.state.borrow().pending_keys {
            let key = key.as_bytes();
            assert_eq!(value.capacity(), value.len(), "key {key:02x?}");
        }
        let read = rows().iter().map(|(key, _)| bucket.get(key)).collect();
        tx.commit().expect("commit");
        read
    }

    /// What the store reads for every key of [`rows`].
    fn read_rows(db: &Database) -> Vec<Option<Vec<u8>>> {
        let mut read = Vec::new();
        db.view(|tx| {
            let bucket = tx.metadata().bucket(b"rows").expect("bucket");
            read = rows().iter().map(|(key, _)| bucket.get(key)).collect();
            Ok(())
        })
        .expect("view");
        read
    }

    #[test]
    fn an_owned_put_leaves_what_a_borrowed_put_leaves() {
        let (_borrowed_dir, borrowed, borrowed_written, borrowed_flushed) = recording_db();
        let (_owned_dir, owned, owned_written, owned_flushed) = recording_db();

        // In the pending set.
        let want: Vec<Option<Vec<u8>>> = vec![
            Some(Vec::new()),
            Some(vec![0x01]),
            Some((0..=255u8).cycle().take(5000).collect()),
            Some(vec![0x03; 7]),
            Some(vec![0x03; 7]),
            Some(vec![0x04; 9]),
        ];
        assert_eq!(write_rows(&borrowed, false), want);
        assert_eq!(write_rows(&owned, true), want);

        // In the cache overlay.
        assert_eq!(read_rows(&borrowed), want);
        assert_eq!(read_rows(&owned), want);

        // In what the flush hands the engine and counts.
        borrowed.flush().expect("flush");
        owned.flush().expect("flush");
        let borrowed_written = borrowed_written.lock().expect("write log").clone();
        assert!(borrowed_written.len() >= 5, "{}", borrowed_written.len());
        assert_eq!(*owned_written.lock().expect("write log"), borrowed_written);
        let borrowed_flushed = borrowed_flushed.lock().expect("observations").clone();
        assert_eq!(borrowed_flushed.len(), 1);
        assert_eq!(
            *owned_flushed.lock().expect("observations"),
            borrowed_flushed
        );

        // And in the durable store.
        assert_eq!(read_rows(&borrowed), want);
        assert_eq!(read_rows(&owned), want);
    }

    #[test]
    fn an_owned_put_is_refused_as_a_borrowed_put_is() {
        let (_dir, db, _, _) = recording_db();
        db.update(|tx| tx.metadata().create_bucket(b"rows").map(|_| ()))
            .expect("bucket");

        // No key.
        let tx = db.begin(true).expect("begin");
        let bucket = tx.metadata().bucket(b"rows").expect("bucket");
        let borrowed = bucket.put(b"", b"value").expect_err("put");
        let owned = bucket.put_owned(b"", b"value".to_vec()).expect_err("owned");
        assert_eq!(borrowed.kind, ErrorKind::KeyRequired);
        assert_eq!(
            (owned.kind, &owned.description),
            (borrowed.kind, &borrowed.description)
        );
        tx.rollback().expect("rollback");

        // A read-only transaction, which is refused before the key is
        // looked at.
        let tx = db.begin(false).expect("begin");
        let bucket = tx.metadata().bucket(b"rows").expect("bucket");
        for key in [&b""[..], &b"key"[..]] {
            let borrowed = bucket.put(key, b"value").expect_err("put");
            let owned = bucket.put_owned(key, b"value".to_vec()).expect_err("owned");
            assert_eq!(borrowed.kind, ErrorKind::TxNotWritable);
            assert_eq!(
                (owned.kind, &owned.description),
                (borrowed.kind, &borrowed.description)
            );
        }

        // A closed transaction, which is refused before anything else.
        tx.rollback().expect("rollback");
        for key in [&b""[..], &b"key"[..]] {
            let borrowed = bucket.put(key, b"value").expect_err("put");
            let owned = bucket.put_owned(key, b"value".to_vec()).expect_err("owned");
            assert_eq!(borrowed.kind, ErrorKind::TxClosed);
            assert_eq!(
                (owned.kind, &owned.description),
                (borrowed.kind, &borrowed.description)
            );
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic over small counts"
)]
mod pending_guard_tests {
    //! [`Transaction::put_raw`] and [`Transaction::delete_raw`] search
    //! the other pending set only for a key it can hold ([`may_hold`]):
    //! the two sets hold what they would if every key were searched for,
    //! whatever order the keys come in, and rows staged in ascending key
    //! order are searched for not at all.

    use std::collections::{BTreeMap, BTreeSet};

    use dcroxide_testutil::SplitMix64;

    use super::may_hold;
    use super::put_owned_tests::recording_db;
    use crate::dbcache::LayerKey;
    use crate::{Database, Transaction};

    /// A set with no key holds nothing, and one whose greatest key
    /// sorts before the key asked about does not hold it.  Every other
    /// key may be held: the greatest key itself, a key below it, and a
    /// key that is a prefix of it.  The order is that of the bytes, not
    /// of the lengths, and not of where a key holds its bytes: a key too
    /// long to be held in place is above or below one that is held so
    /// as its bytes are.
    #[test]
    fn may_hold_is_false_only_above_the_last_key() {
        let key_of = |bytes: &[u8]| LayerKey::concat(&[bytes]);
        let last = key_of(&[0x05, 0x80, 0x01]);
        for key in [&[][..], &[0x00], last.as_bytes()] {
            assert!(!may_hold(None, &key_of(key)), "no last key, key {key:02x?}");
        }
        let cases: [(&[u8], bool, &str); 9] = [
            (&[0x05, 0x80, 0x02], false, "above the last key"),
            (&[0x06], false, "shorter than the last key and above it"),
            (&[0x05, 0x80, 0x01, 0x00], false, "the last key and more"),
            (&[0x05, 0x80, 0x01], true, "the last key"),
            (&[0x05, 0x80, 0x00], true, "below the last key"),
            (&[0x05, 0x7f, 0xff, 0xff], true, "longer and below"),
            (&[0x04], true, "shorter and below"),
            (&[0x05, 0x80], true, "a prefix of the last key"),
            (&[], true, "the empty key"),
        ];
        for (key, want, what) in cases {
            assert_eq!(may_hold(Some(&last), &key_of(key)), want, "{what}");
        }
        // The empty key is the least there is.
        assert!(may_hold(Some(&key_of(&[])), &key_of(&[])));
        assert!(!may_hold(Some(&key_of(&[])), &key_of(&[0x00])));
        // A last key of fifty bytes, which is not held in place, and
        // one of forty-six, which is.
        let (long, short) = (key_of(&[0x05; 50]), key_of(&[0x05; 46]));
        assert!(!long.lies_in_place() && short.lies_in_place());
        assert!(may_hold(Some(&long), &short), "a prefix held in place");
        assert!(may_hold(Some(&long), &long), "the last key, not in place");
        assert!(
            !may_hold(Some(&long), &key_of(&[0x06])),
            "above it, in place"
        );
        assert!(!may_hold(Some(&short), &long), "the last key and more");
        assert!(
            may_hold(Some(&key_of(&[0x06])), &long),
            "below one in place"
        );
    }

    /// The raw keys the model test stages, in ascending order: keys of
    /// several lengths, some of them prefixes of others, so that the
    /// longer of two keys is the lesser in some pairs and the greater in
    /// others.  Four of them are alike in their first 45 bytes: one of
    /// 46 bytes, which a pending set holds in place, that key with a
    /// zero after it, and two more too long to be held so.
    fn model_keys() -> Vec<Vec<u8>> {
        let short: [&[u8]; 16] = [
            &[0xf5],
            &[0xf5, 0x00],
            &[0xf5, 0x00, 0x00],
            &[0xf5, 0x00, 0x01],
            &[0xf5, 0x01],
            &[0xf5, 0x7f],
            &[0xf5, 0x7f, 0xff],
            &[0xf5, 0x80],
            &[0xf5, 0x80, 0x00],
            &[0xf5, 0x80, 0x00, 0x00],
            &[0xf5, 0xff],
            &[0xf5, 0xff, 0x7f],
            &[0xf5, 0xff, 0x80, 0x80, 0x00],
            &[0xf5, 0xff, 0xff],
            &[0xf6],
            &[0xf6, 0x00],
        ];
        let mut keys: Vec<Vec<u8>> = short.iter().map(|key| key.to_vec()).collect();
        let long = |tail: &[u8]| [&[0xf5][..], &[0x90; 44], tail].concat();
        let long = [
            long(&[1]),
            long(&[1, 0]),
            long(&[1, 1]),
            long(&[2, 0, 0, 0]),
        ];
        assert_eq!(long.each_ref().map(Vec::len), [46, 47, 47, 49]);
        keys.splice(10..10, long);
        assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
        keys
    }

    /// Random puts, deletes and reporting deletes of a few raw keys,
    /// drawn in ascending order, in descending order and at random, each
    /// compared with a model in which the last operation on a key wins.
    /// After every call the staged puts are the keys last put, with the
    /// values they were put with, the staged deletes are the keys last
    /// deleted, so no key is in both, and every key reads as the model
    /// says, through to the rows committed beneath.  A reporting delete
    /// reports what the model held.
    #[test]
    fn the_pending_sets_match_a_model_under_any_order() {
        let mut rng = SplitMix64::from_entropy("pending sets against a model");
        let (_dir, db, _, _) = recording_db();
        let keys = model_keys();
        // What the committed rows hold: every third key to begin with,
        // then whatever the transactions that commit leave.
        let mut beneath: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        db.update(|tx| {
            for key in keys.iter().step_by(3) {
                tx.put_raw(key.clone().into(), b"beneath".to_vec())?;
                beneath.insert(key.clone(), b"beneath".to_vec());
            }
            Ok(())
        })
        .expect("rows beneath");

        for order in ["ascending", "descending", "random"] {
            for round in 0..40u32 {
                let tx = db.begin(true).expect("begin");
                // The last operation on each key: the value put, or
                // `None` for a delete.
                let mut model: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
                for step in 0..3 * keys.len() {
                    let context = format!("{order}, round {round}, step {step}");
                    let at = match order {
                        "ascending" => step % keys.len(),
                        "descending" => keys.len() - 1 - step % keys.len(),
                        _ => rng.below(keys.len() as u64) as usize,
                    };
                    let key = &keys[at];
                    match rng.below(5) {
                        0 | 1 => {
                            let value = rng.bytes(6);
                            tx.put_raw(key.clone().into(), value.clone()).expect("put");
                            model.insert(key.clone(), Some(value));
                        }
                        2 | 3 => {
                            tx.delete_raw(key.clone().into()).expect("delete");
                            model.insert(key.clone(), None);
                        }
                        _ => {
                            let reported = tx.delete_raw_reporting(key).expect("delete");
                            assert_eq!(reported, model.insert(key.clone(), None), "{context}");
                        }
                    }

                    let puts: BTreeMap<Vec<u8>, Vec<u8>> = model
                        .iter()
                        .filter_map(|(key, staged)| Some((key.clone(), staged.clone()?)))
                        .collect();
                    let deletes: BTreeSet<Vec<u8>> = model
                        .iter()
                        .filter(|(_, staged)| staged.is_none())
                        .map(|(key, _)| key.clone())
                        .collect();
                    {
                        // The sets as they are walked, against the
                        // model's keys in the order of their bytes.
                        let state = tx.state.borrow();
                        let staged = state.pending_keys.iter();
                        let staged: Vec<_> =
                            staged.map(|(key, value)| (key.as_bytes(), value)).collect();
                        let want: Vec<_> =
                            puts.iter().map(|(key, value)| (&key[..], value)).collect();
                        assert_eq!(staged, want, "{context}: puts");
                        let staged = state.pending_removes.iter();
                        let staged: Vec<_> = staged.map(LayerKey::as_bytes).collect();
                        let want: Vec<_> = deletes.iter().map(|key| &key[..]).collect();
                        assert_eq!(staged, want, "{context}: deletes");
                    }
                    for key in &keys {
                        let want = match model.get(key) {
                            Some(staged) => staged.clone(),
                            None => beneath.get(key).cloned(),
                        };
                        assert_eq!(
                            tx.try_fetch_raw(key).expect("read"),
                            want,
                            "{context}: key {key:02x?}"
                        );
                    }
                }
                if round % 2 == 0 {
                    tx.rollback().expect("rollback");
                    continue;
                }
                tx.commit().expect("commit");
                for (key, staged) in model {
                    match staged {
                        Some(value) => beneath.insert(key, value),
                        None => beneath.remove(&key),
                    };
                }
            }
        }
    }

    /// The rows of the content test in ascending key order, each a value
    /// to put or `None` for a delete, two puts to every delete.  The
    /// least key is put and the greatest is deleted.
    fn content_rows() -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        (0..200u16)
            .map(|i| {
                let staged = (i % 3 != 1).then(|| vec![i as u8; usize::from(i % 7) * 9]);
                (i.to_be_bytes().to_vec(), staged)
            })
            .collect()
    }

    /// The least and the greatest key [`content_rows`] puts, and the
    /// least and the greatest it deletes.
    fn ends_put_and_deleted() -> ([Vec<u8>; 2], [Vec<u8>; 2]) {
        let rows = content_rows();
        let ends = |put: bool| {
            let mut keys = rows
                .iter()
                .filter(|(_, staged)| staged.is_some() == put)
                .map(|(key, _)| key.clone());
            let least = keys.next().expect("a row of each kind");
            [least, keys.next_back().expect("two rows of each kind")]
        };
        let (put, deleted) = (ends(true), ends(false));
        assert!(put[0] < deleted[0] && put[1] < deleted[1]);
        (put, deleted)
    }

    /// A key that sorts above every key of [`content_rows`].
    fn key_above_the_rows() -> Vec<u8> {
        200u16.to_be_bytes().to_vec()
    }

    /// The keys the content test reads: those of [`content_rows`] and
    /// then [`key_above_the_rows`].
    fn content_keys() -> Vec<Vec<u8>> {
        let rows = content_rows();
        let keys = rows.into_iter().map(|(key, _)| key);
        keys.chain([key_above_the_rows()]).collect()
    }

    /// What every key of [`content_keys`] holds once [`stage_content`]
    /// has staged its rows.
    fn content_want() -> Vec<Option<Vec<u8>>> {
        let (put, deleted) = ends_put_and_deleted();
        let rows = content_rows().into_iter().map(|(key, staged)| {
            if put.contains(&key) {
                None
            } else if deleted.contains(&key) {
                Some(b"again".to_vec())
            } else {
                staged
            }
        });
        rows.chain([None]).collect()
    }

    /// Over a bucket in which every other key already has a row, stage
    /// [`content_rows`] in one transaction, in ascending or in descending
    /// key order, then delete the least key put and put the least key
    /// deleted, and the same for the greatest of each, which by then is
    /// the greatest key of the set it has to leave.  Last, put
    /// [`key_above_the_rows`] and delete it, which leaves the greatest
    /// key staged as a put above the greatest staged as a delete, where
    /// the rows leave them the other way round.  Returns the transaction
    /// the rows are staged in.
    fn stage_content(db: &Database, ascending: bool) -> Transaction {
        let mut rows = content_rows();
        db.update(|tx| {
            let bucket = tx.metadata().create_bucket(b"rows")?;
            for (key, _) in rows.iter().step_by(2) {
                bucket.put(key, b"beneath")?;
            }
            Ok(())
        })
        .expect("rows beneath");

        let tx = db.begin(true).expect("begin");
        {
            let bucket = tx.metadata().bucket(b"rows").expect("bucket");
            if !ascending {
                rows.reverse();
            }
            for (key, staged) in &rows {
                match staged {
                    Some(value) => bucket.put(key, value).expect("put"),
                    None => bucket.delete(key).expect("delete"),
                }
            }
            let (put, deleted) = ends_put_and_deleted();
            for (put, deleted) in put.iter().zip(&deleted) {
                bucket.delete(put).expect("delete");
                bucket.put(deleted, b"again").expect("put");
            }
            let above = key_above_the_rows();
            bucket.put(&above, b"above").expect("put");
            bucket.delete(&above).expect("delete");
        }
        tx
    }

    /// Commit what [`stage_content`] stages and return what the
    /// transaction read for every key of [`content_keys`] before it
    /// committed.
    fn write_content(db: &Database, ascending: bool) -> Vec<Option<Vec<u8>>> {
        let tx = stage_content(db, ascending);
        let read = {
            let bucket = tx.metadata().bucket(b"rows").expect("bucket");
            content_keys().iter().map(|key| bucket.get(key)).collect()
        };
        tx.commit().expect("commit");
        read
    }

    /// What the store reads for every key of [`content_keys`].
    fn read_content(db: &Database) -> Vec<Option<Vec<u8>>> {
        let mut read = Vec::new();
        db.view(|tx| {
            let bucket = tx.metadata().bucket(b"rows").expect("bucket");
            read = content_keys().iter().map(|key| bucket.get(key)).collect();
            Ok(())
        })
        .expect("view");
        read
    }

    /// Rows staged in ascending key order, none of which is searched
    /// for, leave what the same rows leave staged in descending order,
    /// all but the first of which is: in what the transaction reads
    /// before it commits, in the cache overlay, in the keys and values
    /// the flush hands the engine, in the entries and bytes it counts,
    /// and in the durable store.  Both end with deletes of the least and
    /// the greatest key put, puts of the least and the greatest key
    /// deleted, and a put and then a delete of a key above them all, and
    /// both read as the rows say.
    #[test]
    fn ascending_rows_leave_what_descending_rows_leave() {
        let (_ascending_dir, ascending, ascending_written, ascending_flushed) = recording_db();
        let (_descending_dir, descending, descending_written, descending_flushed) = recording_db();
        let want = content_want();
        assert!(want.iter().filter(|row| row.is_none()).count() >= 60);

        // In the pending sets.
        assert_eq!(write_content(&ascending, true), want);
        assert_eq!(write_content(&descending, false), want);

        // In the cache overlay.
        assert_eq!(read_content(&ascending), want);
        assert_eq!(read_content(&descending), want);

        // In what the flush hands the engine and counts.
        ascending.flush().expect("flush");
        descending.flush().expect("flush");
        let descending_written = descending_written.lock().expect("write log").clone();
        assert!(
            descending_written.len() >= 200,
            "{}",
            descending_written.len()
        );
        assert_eq!(
            *ascending_written.lock().expect("write log"),
            descending_written
        );
        let descending_flushed = descending_flushed.lock().expect("observations").clone();
        assert_eq!(descending_flushed.len(), 1);
        assert_eq!(
            *ascending_flushed.lock().expect("observations"),
            descending_flushed
        );

        // And in the durable store.
        assert_eq!(read_content(&ascending), want);
        assert_eq!(read_content(&descending), want);
    }

    /// Stage a thousand raw keys in the order given, a put of every
    /// even one and a delete of every odd one, and return the
    /// transaction they are staged in.
    fn stage_alternating(db: &Database, order: impl Iterator<Item = u16>) -> Transaction {
        let tx = db.begin(true).expect("begin");
        for i in order {
            let key = LayerKey::concat(&[&[0xf5], &i.to_be_bytes()]);
            if i % 2 == 0 {
                tx.put_raw(key, vec![0x01]).expect("put");
            } else {
                tx.delete_raw(key).expect("delete");
            }
        }
        tx
    }

    /// The saving is taken: a thousand puts and deletes, interleaved and
    /// in ascending key order as a flush of the UTXO cache stages its
    /// rows, search the other pending set not once.  A put of the
    /// greatest key deleted and then a delete of that key are each
    /// searched for, and the same thousand rows in descending order are
    /// searched for at every call but the first, which finds the other
    /// set empty.  The count is kept where the guard lets a search
    /// through, so it shows which calls the guard stops and not that
    /// nothing else searches.
    #[test]
    fn an_ascending_run_makes_no_cross_search() {
        let (_dir, db, _, _) = recording_db();
        let searches = |tx: &Transaction| tx.state.borrow().cross_searches;

        let tx = stage_alternating(&db, 0..1000);
        assert_eq!(searches(&tx), 0, "ascending");
        let greatest = LayerKey::concat(&[&[0xf5], &999u16.to_be_bytes()]);
        tx.put_raw(greatest.clone(), vec![0x02]).expect("put");
        assert_eq!(searches(&tx), 1, "a put of the greatest key deleted");
        tx.delete_raw(greatest).expect("delete");
        assert_eq!(searches(&tx), 2, "a delete of the greatest key put");
        tx.rollback().expect("rollback");

        let tx = stage_alternating(&db, (0..1000).rev());
        assert_eq!(searches(&tx), 999, "descending");
        tx.rollback().expect("rollback");
    }

    /// [`ascending_rows_leave_what_descending_rows_leave`] compares rows
    /// staged without the search with rows staged with it.  Of the
    /// ascending rows none is searched for and of the descending rows
    /// all but the first, and of the six operations that end either,
    /// all but the put of the key above every row.
    #[test]
    fn the_content_rows_are_staged_without_the_search_and_with_it() {
        for (ascending, want) in [(true, 5), (false, 204)] {
            let (_dir, db, _, _) = recording_db();
            let tx = stage_content(&db, ascending);
            let searches = tx.state.borrow().cross_searches;
            assert_eq!(searches, want, "ascending: {ascending}");
            tx.rollback().expect("rollback");
        }
    }
}

#[cfg(test)]
mod released_snapshot_tests {
    //! A transaction holds the cache's snapshot from its start until a
    //! commit lets it go or the transaction is closed, and nothing in
    //! its place from then on.  A transaction with no snapshot reads the
    //! store alone, as one holding a snapshot of no layer does.

    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;

    use tempfile::TempDir;

    use super::{Bucket, bucketized_key};
    use crate::dbcache::CacheSnapshot;
    use crate::{Database, ErrorKind, Options, Transaction};

    /// simnet magic, matching the interface battery.
    const NET: u32 = 0x1214_1c16;

    /// A new store with an empty bucket `rows`.
    fn new_db() -> (TempDir, Database) {
        let dir = TempDir::new().expect("tempdir");
        let opts = Options::new(dir.path().join("db"), NET);
        let db = Database::create(&opts).expect("create");
        let tx = db.begin(true).expect("begin");
        tx.metadata().create_bucket(b"rows").expect("bucket");
        tx.commit().expect("commit");
        (dir, db)
    }

    /// Whether the transaction holds a snapshot of the overlay.
    fn held(tx: &Transaction) -> bool {
        tx.state.borrow().cache_snap.is_some()
    }

    /// The handles on the snapshot the cache has published: the cache's
    /// own, and one for each transaction holding that snapshot.
    fn handles(db: &Database) -> usize {
        Arc::strong_count(&db.inner.cache.lock().expect("cache").cached)
    }

    /// The handles on the published snapshot at each release of the
    /// writer semaphore that `act` makes, read by the probe the release
    /// runs on this thread, [`crate::RELEASE_HOOK`].
    fn handles_at_each_release(db: &Database, act: impl FnOnce()) -> Vec<usize> {
        let snapshot = Arc::downgrade(&db.inner.cache.lock().expect("cache").cached);
        let counts = Rc::new(RefCell::new(Vec::new()));
        let seen = Rc::clone(&counts);
        crate::RELEASE_HOOK.with(|hook| {
            let count = move || seen.borrow_mut().push(snapshot.strong_count());
            *hook.borrow_mut() = Some(Box::new(count));
        });
        act();
        crate::RELEASE_HOOK.with(|hook| *hook.borrow_mut() = None);
        counts.take()
    }

    /// Put one row in the bucket `rows`.
    fn put(tx: &Transaction, key: &[u8], value: &[u8]) {
        let bucket = tx.metadata().bucket(b"rows").expect("bucket");
        bucket.put(key, value).expect("put");
    }

    /// A transaction holds a handle on the published snapshot while it
    /// is open and none once it has ended, whichever way it ended: a
    /// rollback, a commit, the commit a read-only transaction is
    /// refused, or the end of a managed transaction's closure.  The
    /// handle is let go by the end itself, with the transaction still in
    /// scope, and nothing is held in its place: an ended transaction
    /// holds no snapshot at all, not an empty one of its own.  A writer
    /// rolled back still holds its handle as it releases the writer
    /// semaphore and lets it go straight after, so whatever layers that
    /// frees are freed with no other writer kept waiting.
    #[test]
    fn a_transaction_holds_no_snapshot_once_it_has_let_go() {
        let (_dir, db) = new_db();
        // A committed row no flush has written, so the snapshot names a
        // layer.
        db.update(|tx| {
            put(tx, b"beneath", b"1");
            Ok(())
        })
        .expect("update");
        assert_eq!(handles(&db), 1);

        for writable in [false, true] {
            let tx = db.begin(writable).expect("begin");
            assert!(held(&tx), "writable {writable}: open");
            assert_eq!(handles(&db), 2, "writable {writable}: open");
            let at_release = handles_at_each_release(&db, || tx.rollback().expect("rollback"));
            // Only a writer has the semaphore to release.
            let expected = if writable { vec![2] } else { vec![] };
            assert_eq!(at_release, expected, "writable {writable}: at the release");
            assert!(!held(&tx), "writable {writable}: rolled back");
            assert_eq!(handles(&db), 1, "writable {writable}: rolled back");
        }

        let tx = db.begin(true).expect("begin");
        put(&tx, b"committed", b"2");
        assert!(held(&tx));
        assert_eq!(handles(&db), 2);
        tx.commit().expect("commit");
        assert!(!held(&tx), "committed");
        assert_eq!(handles(&db), 1, "committed");

        let tx = db.begin(false).expect("begin");
        assert_eq!(handles(&db), 2);
        let refused = tx.commit().expect_err("a read-only commit");
        assert_eq!(refused.kind, ErrorKind::TxNotWritable);
        assert!(!held(&tx), "refused");
        assert_eq!(handles(&db), 1, "refused");

        db.view(|tx| {
            assert!(held(tx), "in a view");
            assert_eq!(handles(&db), 2, "in a view");
            Ok(())
        })
        .expect("view");
        assert_eq!(handles(&db), 1, "after a view");
        db.update(|tx| {
            put(tx, b"updated", b"3");
            assert!(held(tx), "in an update");
            assert_eq!(handles(&db), 2, "in an update");
            Ok(())
        })
        .expect("update");
        assert_eq!(handles(&db), 1, "after an update");
    }

    /// What a transaction reads beneath its pending changes for the keys
    /// `a`, `b` and `c` of the bucket `rows`, and the rows a walk of the
    /// bucket yields.
    type Read = (Vec<Option<Vec<u8>>>, Vec<(Vec<u8>, Vec<u8>)>);

    /// [`Read`] through the bucket's own `get` and `for_each`.
    fn read(bucket: &Bucket) -> Read {
        let values = [b"a", b"b", b"c"].map(|key| bucket.get(key)).to_vec();
        let mut walked = Vec::new();
        bucket
            .for_each(|key, value| {
                walked.push((key.to_vec(), value.to_vec()));
                Ok(())
            })
            .expect("walk");
        (values, walked)
    }

    /// One row of a walk.
    fn row(key: &[u8], value: &[u8]) -> (Vec<u8>, Vec<u8>) {
        (key.to_vec(), value.to_vec())
    }

    /// Fill the bucket `rows` so that the store and the overlay above it
    /// differ on every key read: the store holds `a` and `b`, and the
    /// overlay rewrites `a`, deletes `b` and adds `c`.
    fn fill_store_and_overlay(db: &Database) {
        db.update(|tx| {
            put(tx, b"a", b"store-a");
            put(tx, b"b", b"store-b");
            Ok(())
        })
        .expect("update");
        db.flush().expect("flush");
        db.update(|tx| {
            put(tx, b"a", b"overlay-a");
            put(tx, b"c", b"overlay-c");
            tx.metadata().bucket(b"rows").expect("bucket").delete(b"b")
        })
        .expect("update");
    }

    /// What [`fill_store_and_overlay`] leaves to read through the
    /// overlay.
    fn through_the_overlay() -> Read {
        (
            vec![
                Some(b"overlay-a".to_vec()),
                None,
                Some(b"overlay-c".to_vec()),
            ],
            vec![row(b"a", b"overlay-a"), row(b"c", b"overlay-c")],
        )
    }

    /// What [`fill_store_and_overlay`] leaves in the store.
    fn the_store_alone() -> Read {
        (
            vec![Some(b"store-a".to_vec()), Some(b"store-b".to_vec()), None],
            vec![row(b"a", b"store-a"), row(b"b", b"store-b")],
        )
    }

    /// A transaction that holds no snapshot reads the store alone, row
    /// by row and in a walk: a key the overlay had rewritten reads as
    /// the store has it, one the overlay had deleted is back, and one
    /// only the overlay held is absent.  That is what a transaction
    /// holding a snapshot of no layer reads, which is what a commit and
    /// a close used to leave in the snapshot's place.  No snapshot is
    /// the state a commit is in between letting its snapshot go and
    /// closing, with the store's read transaction still open; once that
    /// is closed too, every key reads as absent and a scan yields
    /// nothing.
    #[test]
    fn a_transaction_without_a_snapshot_reads_the_store_alone() {
        let (_dir, db) = new_db();
        fill_store_and_overlay(&db);

        let reader = db.begin(false).expect("begin");
        let bucket = reader.metadata().bucket(b"rows").expect("bucket");
        assert_eq!(read(&bucket), through_the_overlay());

        reader.state.borrow_mut().cache_snap = None;
        assert_eq!(read(&bucket), the_store_alone(), "no snapshot");
        reader.state.borrow_mut().cache_snap = Some(Arc::new(CacheSnapshot::default()));
        assert_eq!(read(&bucket), the_store_alone(), "a snapshot of no layer");

        // Closed: the bucket's own reads stop at the closed check, so
        // the raw reads beneath them are asked as well.
        reader.rollback().expect("rollback");
        assert!(!held(&reader));
        for key in [b"a", b"b", b"c"] {
            assert_eq!(bucket.get(key), None, "closed, key {key:?}");
            let raw = bucketized_key(bucket.id, key);
            let read = reader.try_fetch_raw(raw.as_bytes());
            assert_eq!(read, Ok(None), "closed, key {key:?}");
        }
        let closed = bucket.for_each(|key, _| panic!("a closed walk yielded {key:?}"));
        assert_eq!(closed.expect_err("closed").kind, ErrorKind::TxClosed);
        let window = reader.scan_prefix_window(&bucket.id, None, None, true, true);
        assert!(window.rows.is_empty() && window.store_error.is_none());
    }

    /// A commit lets its snapshot go before it hands its rows to the
    /// cache and holds nothing in its place while it does.  The commit
    /// here is stopped at the hand-over: its hook leaves the cache's
    /// lock poisoned, and the hand-over is the commit's first use of
    /// that lock after its hooks, so the commit panics there, after it
    /// has let the snapshot go and before it closes.  The transaction is
    /// then in a state no finished commit shows: open on the store,
    /// holding no snapshot at all, with the cache's handle the only one
    /// on the published snapshot.  It reads the store alone there.
    /// Rolled back, it leaves the overlay as it found it.
    #[test]
    fn a_commit_holds_no_snapshot_as_it_hands_its_rows_to_the_cache() {
        let (_dir, db) = new_db();
        fill_store_and_overlay(&db);

        let tx = db.begin(true).expect("begin");
        put(&tx, b"d", b"never-handed-over");
        let bucket = tx.metadata().bucket(b"rows").expect("bucket");
        let inner = Arc::clone(&db.inner);
        tx.on_commit(move || {
            let holder = std::thread::spawn(move || {
                let _cache = inner.cache.lock().expect("cache");
                panic!("leave the cache's lock poisoned");
            });
            holder.join().expect_err("the lock's holder panics");
        })
        .expect("hook");
        assert!(held(&tx), "open");
        assert_eq!(handles(&db), 2, "open");

        let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| tx.commit()));
        let panic = stopped.expect_err("the commit stops at the poisoned lock");
        let text = panic.downcast_ref::<String>().cloned().unwrap_or_default();
        assert!(text.contains("cache lock poisoned"), "{text}");
        db.inner.cache.clear_poison();

        assert!(!held(&tx), "at the hand-over");
        assert_eq!(handles(&db), 1, "at the hand-over");
        assert_eq!(read(&bucket), the_store_alone(), "at the hand-over");

        tx.rollback().expect("rollback");
        let reader = db.begin(false).expect("begin");
        let bucket = reader.metadata().bucket(b"rows").expect("bucket");
        assert_eq!(read(&bucket), through_the_overlay(), "after the rollback");
    }
}

#[cfg(test)]
mod in_place_key_tests {
    //! A row's key is built once, where the row is staged, and is the
    //! key the pending sets and the cache overlay hold ([`LayerKey`]):
    //! its bytes are in the key itself up to 46 of them, the bucket id
    //! included, and on the heap past that.  Rows on both sides of that
    //! length are staged, read, walked and written as their bytes order.
    //!
    //! Two things are read here.  One is where a key's bytes lie once it
    //! is built, staged or published, which does not show a buffer made
    //! and dropped on the way.  The other is how many keys were built in
    //! place and how many with a buffer ([`KEYS_BUILT`]), which shows a
    //! buffer that went through a key and no other.

    use dcroxide_chainhash::Hash;

    use super::put_owned_tests::recording_db;
    use super::{BUCKET_INDEX_PREFIX, block_idx_key, bucket_index_key, bucketized_key};
    use crate::dbcache::{KEYS_BUILT, KeysBuilt, LayerKey};
    use crate::{ErrorKind, Transaction};

    /// The key each builder of a raw key returns is held in place up to
    /// 46 bytes: a block's index row key, which has 40, a bucket's row
    /// key for a key of up to 42, and a bucket's index key for a name of
    /// up to 38.  One byte more and the key is on the heap.  Either way
    /// its bytes are the parts in their order.
    #[test]
    fn a_key_built_for_a_lookup_is_held_in_place() {
        let id = [0x00, 0x00, 0x00, 0x07];
        assert!(block_idx_key(&Hash([0x9c; 32]), 7).lies_in_place());
        let bytes: [u8; 64] = core::array::from_fn(|i| 0x60 ^ i as u8);
        for len in 0..=bytes.len() {
            let key = &bytes[..len];
            let row = bucketized_key(id, key);
            assert_eq!(row.as_bytes(), [&id[..], key].concat());
            assert_eq!(row.lies_in_place(), len <= 42, "a key of {len} bytes");
            let index = bucket_index_key(id, key);
            assert_eq!(index.as_bytes(), [BUCKET_INDEX_PREFIX, &id, key].concat());
            assert_eq!(index.lies_in_place(), len <= 38, "a name of {len} bytes");
        }
    }

    /// The raw key of `key` in the bucket `rows`.
    fn raw(tx: &Transaction, key: &[u8]) -> Vec<u8> {
        let id = tx.metadata().bucket(b"rows").expect("bucket").raw_id();
        [&id[..], key].concat()
    }

    /// A put, an owned put and a delete each leave their key in a
    /// pending set held in place when the key, bucket id included, has
    /// 46 bytes or fewer, and the commit leaves it so in the overlay's
    /// layer.  A longer key is on the heap, and the layer's entry holds
    /// the very buffer the pending set held, for a put and for a delete:
    /// the commit moves each key into the layer and builds none.
    #[test]
    fn a_staged_key_reaches_the_overlay_without_being_rebuilt() {
        let (_dir, db, _, _) = recording_db();
        db.update(|tx| tx.metadata().create_bucket(b"rows").map(|_| ()))
            .expect("bucket");

        // Raw keys of 36, 37, 46, 60 and 61 bytes.
        let (put, deleted, longest_in_place, long, long_deleted) =
            ([0x11; 32], [0x22; 33], [0x33; 42], [0x44; 56], [0x55; 57]);
        let tx = db.begin(true).expect("begin");
        {
            let bucket = tx.metadata().bucket(b"rows").expect("bucket");
            bucket.put(&put, b"put").expect("put");
            bucket.delete(&deleted).expect("delete");
            bucket
                .put_owned(&longest_in_place, b"owned".to_vec())
                .expect("put");
            bucket.put(&long, b"long").expect("put");
            bucket.delete(&long_deleted).expect("delete");
        }
        let keys = [&put[..], &deleted, &longest_in_place, &long, &long_deleted];
        let keys = keys.map(|key| raw(&tx, key));

        // Where the bytes of each staged key lie: in the key, or at an
        // address on the heap.
        let on_the_heap: Vec<(Vec<u8>, usize)> = {
            let state = tx.state.borrow();
            let puts = state.pending_keys.keys();
            let staged: Vec<&LayerKey> = puts.chain(&state.pending_removes).collect();
            let lengths: Vec<usize> = staged.iter().map(|key| key.as_bytes().len()).collect();
            assert_eq!(lengths, [36, 46, 60, 37, 61]);
            for key in &staged {
                let len = key.as_bytes().len();
                assert_eq!(key.lies_in_place(), len <= 46, "staged, {len} bytes");
            }
            let long = staged.iter().filter(|key| !key.lies_in_place());
            long.map(|key| (key.as_bytes().to_vec(), key.as_bytes().as_ptr().addr()))
                .collect()
        };
        assert_eq!(on_the_heap.len(), 2);
        tx.commit().expect("commit");

        let layers = db
            .inner
            .cache
            .lock()
            .expect("cache")
            .published_layers_for_test();
        assert_eq!(layers.len(), 1);
        let layer = layers[0].upgrade().expect("the published layer");
        for key in &keys {
            let (held, _) = layer.get_key_value(&key[..]).expect("the row's entry");
            let len = key.len();
            assert_eq!(held.as_bytes(), key, "in the layer, {len} bytes");
            assert_eq!(held.lies_in_place(), len <= 46, "in the layer, {len} bytes");
        }
        for (key, staged_at) in &on_the_heap {
            let (held, _) = layer.get_key_value(&key[..]).expect("the row's entry");
            let len = key.len();
            assert_eq!(held.as_bytes().as_ptr().addr(), *staged_at, "{len} bytes");
        }
    }

    /// Staging a row whose key, bucket id included, has 46 bytes or
    /// fewer builds one key, in place, and none with a buffer: by a put,
    /// an owned put, a delete and a cursor's delete.  So does a lookup,
    /// of a bucket's row by `get` and by `try_get` and of a block's
    /// index row, whether or not it finds one.  The commit builds the
    /// key of the write cursor's row and no other: every other key it
    /// publishes is one the transaction staged.  A row whose key is
    /// longer costs the one buffer its key keeps, staged or looked up.
    ///
    /// The count is kept where a key is built, so it shows that neither
    /// a builder nor its caller reached a key by way of a buffer, and
    /// not that nothing else allocates.
    #[test]
    fn a_row_staged_or_looked_up_builds_one_key_in_place_and_none_with_a_buffer() {
        let (_dir, db, _, _) = recording_db();
        db.update(|tx| tx.metadata().create_bucket(b"rows").map(|_| ()))
            .expect("bucket");
        let in_place = KeysBuilt {
            in_place: 1,
            with_a_buffer: 0,
        };
        let with_a_buffer = KeysBuilt {
            in_place: 0,
            with_a_buffer: 1,
        };

        let tx = db.begin(true).expect("begin");
        {
            let bucket = tx.metadata().bucket(b"rows").expect("bucket");
            // Raw keys of 46 bytes, the longest held in place, and of 47.
            let (put, owned, deleted, absent) = ([0x11; 42], [0x22; 42], [0x33; 42], [0x44; 42]);
            let (reported, long) = (raw(&tx, &[0x55; 42]), [0x66; 43]);
            let block = Hash([0x9c; 32]);
            let calls: [(&str, KeysBuilt, &dyn Fn()); 13] = [
                ("a put", in_place, &|| {
                    bucket.put(&put, b"put").expect("put");
                }),
                ("an owned put", in_place, &|| {
                    bucket.put_owned(&owned, b"owned".to_vec()).expect("put");
                }),
                ("a delete", in_place, &|| {
                    bucket.delete(&deleted).expect("delete");
                }),
                ("a cursor's delete", in_place, &|| {
                    assert_eq!(tx.delete_raw_reporting(&reported), Ok(None));
                }),
                ("a get of a row", in_place, &|| {
                    assert_eq!(bucket.get(&put), Some(b"put".to_vec()));
                }),
                ("a get of no row", in_place, &|| {
                    assert_eq!(bucket.get(&absent), None);
                }),
                ("a try_get of a row", in_place, &|| {
                    assert_eq!(bucket.try_get(&owned), Ok(Some(b"owned".to_vec())));
                }),
                ("a try_get of a deleted row", in_place, &|| {
                    assert_eq!(bucket.try_get(&deleted), Ok(None));
                }),
                ("a block looked for", in_place, &|| {
                    assert_eq!(tx.has_block(&block, 7), Ok(false));
                }),
                ("a block's row read", in_place, &|| {
                    let missing = tx.fetch_block_row(&block, 7).expect_err("no such block");
                    assert_eq!(missing.kind, ErrorKind::BlockNotFound);
                }),
                ("a put of a long key", with_a_buffer, &|| {
                    bucket.put(&long, b"long").expect("put");
                }),
                ("a get of a long key", with_a_buffer, &|| {
                    assert_eq!(bucket.get(&long), Some(b"long".to_vec()));
                }),
                ("a delete of a long key", with_a_buffer, &|| {
                    bucket.delete(&long).expect("delete");
                }),
            ];
            for (what, want, call) in calls {
                KEYS_BUILT.set(KeysBuilt::default());
                call();
                assert_eq!(KEYS_BUILT.get(), want, "{what}");
            }
        }
        KEYS_BUILT.set(KeysBuilt::default());
        tx.commit().expect("commit");
        assert_eq!(KEYS_BUILT.get(), in_place, "the commit");
    }

    /// Deleting a bucket stages a delete of every row in it and in a
    /// bucket nested in it, and of both buckets' index rows, on both
    /// sides of the in-place limit: a key the scan handed over in a
    /// buffer is held in place when it has 46 bytes or fewer, and is on
    /// the heap when it has more.  The staged deletes are those keys and
    /// no other, in the order of their bytes, and once they are
    /// committed and flushed the store holds none of the rows.
    #[test]
    fn a_deleted_bucket_loses_its_rows_on_both_sides_of_the_in_place_limit() {
        let (_dir, db, _, _) = recording_db();
        // Keys of 41 to 60 bytes, 45 to 64 with a bucket's id, and a
        // nested bucket whose name makes its index row's key 49 bytes.
        let keys: [&[u8]; 4] = [&[0x11; 41], &[0x22; 42], &[0x33; 43], &[0x44; 60]];
        let nested_name = [0x6e; 41];
        let mut raw_keys: Vec<Vec<u8>> = Vec::new();
        db.update(|tx| {
            let meta = tx.metadata();
            let rows = meta.create_bucket(b"rows")?;
            let nested = rows.create_bucket(&nested_name)?;
            for bucket in [&rows, &nested] {
                for key in keys {
                    bucket.put(key, b"row")?;
                    raw_keys.push([&bucket.raw_id()[..], key].concat());
                }
            }
            raw_keys.push([BUCKET_INDEX_PREFIX, &rows.raw_id(), &nested_name].concat());
            raw_keys.push([BUCKET_INDEX_PREFIX, &meta.raw_id(), b"rows"].concat());
            Ok(())
        })
        .expect("rows");
        db.flush().expect("flush");
        raw_keys.sort();
        let lengths: Vec<usize> = raw_keys.iter().map(Vec::len).collect();
        assert_eq!(lengths.iter().filter(|len| **len > 46).count(), 5);
        assert_eq!(lengths.iter().filter(|len| **len <= 46).count(), 5);

        let tx = db.begin(true).expect("begin");
        for key in &raw_keys {
            let row = tx.try_fetch_raw(key).expect("read");
            assert!(row.is_some(), "before the delete, {key:02x?}");
        }
        tx.metadata().delete_bucket(b"rows").expect("delete");
        {
            let state = tx.state.borrow();
            assert!(state.pending_keys.is_empty());
            let staged = state.pending_removes.iter();
            let staged: Vec<&[u8]> = staged.map(LayerKey::as_bytes).collect();
            assert_eq!(staged, raw_keys);
            for key in &state.pending_removes {
                let len = key.as_bytes().len();
                assert_eq!(key.lies_in_place(), len <= 46, "staged, {len} bytes");
            }
        }
        tx.commit().expect("commit");
        db.flush().expect("flush");
        db.view(|tx| {
            assert!(tx.metadata().bucket(b"rows").is_none());
            for key in &raw_keys {
                assert_eq!(tx.try_fetch_raw(key), Ok(None), "{key:02x?}");
            }
            Ok(())
        })
        .expect("view");
    }

    /// One row of the bucket `rows`: its key and what it holds, `None`
    /// for a row that is deleted.
    type Row = (Vec<u8>, Option<Vec<u8>>);

    /// What a transaction reads of the bucket `rows`: each key of `rows`
    /// through `get`, a walk by `for_each`, and the keys a cursor walks.
    fn read(tx: &Transaction, rows: &[Row]) -> (Vec<Row>, Vec<Row>, Vec<Vec<u8>>) {
        let bucket = tx.metadata().bucket(b"rows").expect("bucket");
        let got = rows.iter().map(|(key, _)| (key.clone(), bucket.get(key)));
        let mut walked = Vec::new();
        bucket
            .for_each(|key, value| {
                walked.push((key.to_vec(), Some(value.to_vec())));
                Ok(())
            })
            .expect("walk");
        let mut cursor = bucket.cursor();
        let mut keys = Vec::new();
        let mut more = cursor.first();
        while more {
            keys.push(cursor.key().expect("a key"));
            more = cursor.next();
        }
        (got.collect(), walked, keys)
    }

    /// Eight keys alike in their first 41 bytes, of 45 to 49 bytes with
    /// the bucket id, so that four are held in place and four are not,
    /// one of those four being the longest key held in place with a zero
    /// after it.
    ///
    /// One transaction stages them out of order over rows the store
    /// already holds for four of them: six puts, two of them of keys it
    /// deleted first, and two deletes of keys it put first, a key held
    /// in place and one on the heap each time.  What it leaves is the
    /// last operation on each key in the order of the keys' bytes,
    /// wherever a key holds them: in the two pending sets, which hold no
    /// key in common, in what the transaction reads and walks before it
    /// commits, in what a reader finds in the overlay after, in the
    /// keys and values the flush hands the engine, deletions among
    /// them, and in the store.
    #[test]
    fn rows_on_both_sides_of_the_in_place_limit_are_staged_read_walked_and_flushed_in_byte_order() {
        let (_dir, db, written, _) = recording_db();
        let key = |tail: &[u8]| [&[0x5a; 41][..], tail].concat();
        let [a, g, b, c, d, e, h, f] = [
            key(&[]),
            key(&[6]),
            key(&[7]),
            key(&[7, 0]),
            key(&[7, 1]),
            key(&[7, 1, 9]),
            key(&[7, 1, 9, 9]),
            key(&[8]),
        ];
        db.update(|tx| {
            let bucket = tx.metadata().create_bucket(b"rows")?;
            for key in [&g, &d, &h, &f] {
                bucket.put(key, b"beneath")?;
            }
            Ok(())
        })
        .expect("rows beneath");
        db.flush().expect("flush");
        written.lock().expect("write log").clear();

        let steps: [(&Vec<u8>, Option<&[u8]>); 12] = [
            (&e, Some(b"e")),
            (&d, None),
            (&g, Some(b"g")),
            (&a, Some(b"a")),
            (&f, None),
            (&h, Some(b"h")),
            (&c, Some(b"c")),
            (&g, None),
            (&f, Some(b"f")),
            (&b, Some(b"b")),
            (&h, None),
            (&d, Some(b"d")),
        ];
        // Every key with what it is left holding, in the order of the
        // keys' bytes, and the rows among them that are left.
        let rows: Vec<Row> = [
            (&a, Some(&b"a"[..])),
            (&g, None),
            (&b, Some(b"b")),
            (&c, Some(b"c")),
            (&d, Some(b"d")),
            (&e, Some(b"e")),
            (&h, None),
            (&f, Some(b"f")),
        ]
        .map(|(key, value)| (key.clone(), value.map(<[u8]>::to_vec)))
        .to_vec();
        assert!(rows.windows(2).all(|pair| pair[0].0 < pair[1].0));
        let live: Vec<Row> = rows.iter().filter(|row| row.1.is_some()).cloned().collect();
        let live_keys: Vec<Vec<u8>> = live.iter().map(|(key, _)| key.clone()).collect();
        let want = (rows.clone(), live, live_keys);

        let tx = db.begin(true).expect("begin");
        {
            let bucket = tx.metadata().bucket(b"rows").expect("bucket");
            for (key, value) in steps {
                match value {
                    Some(value) => bucket.put(key, value).expect("put"),
                    None => bucket.delete(key).expect("delete"),
                }
            }
        }
        let raw_rows: Vec<Row> = rows
            .iter()
            .map(|(key, value)| (raw(&tx, key), value.clone()))
            .collect();
        {
            // The pending sets: the puts and the deletes, each in the
            // order of the keys' bytes, with three keys of the puts held
            // in place and one of the deletes.
            let state = tx.state.borrow();
            let puts = state.pending_keys.iter();
            let puts: Vec<Row> = puts
                .map(|(key, value)| (key.as_bytes().to_vec(), Some(value.clone())))
                .collect();
            let deletes: Vec<Row> = state
                .pending_removes
                .iter()
                .map(|key| (key.as_bytes().to_vec(), None))
                .collect();
            let staged = |put: bool| raw_rows.iter().filter(move |row| row.1.is_some() == put);
            assert_eq!(puts, staged(true).cloned().collect::<Vec<_>>());
            assert_eq!(deletes, staged(false).cloned().collect::<Vec<_>>());
            let keys = state.pending_keys.keys().chain(&state.pending_removes);
            let in_place: Vec<usize> = keys
                .filter(|key| key.lies_in_place())
                .map(|key| key.as_bytes().len())
                .collect();
            assert_eq!(in_place, [45, 46, 46, 46]);
        }
        assert_eq!(read(&tx, &rows), want, "before the commit");
        tx.commit().expect("commit");

        let read_back = |when: &str| {
            db.view(|tx| {
                assert_eq!(read(tx, &rows), want, "{when}");
                Ok(())
            })
            .expect("view");
        };
        read_back("in the overlay");
        db.flush().expect("flush");
        // What the flush wrote under the bucket's id; the commit's
        // write cursor row is in the log beside it.
        let written = written.lock().expect("write log").clone();
        let under_the_bucket = |row: &&Row| row.0.starts_with(&raw_rows[0].0[..4]);
        let flushed: Vec<Row> = written.iter().filter(under_the_bucket).cloned().collect();
        assert_eq!(flushed, raw_rows);
        read_back("in the store");
    }
}
