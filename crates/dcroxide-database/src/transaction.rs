// SPDX-License-Identifier: ISC
//! Transactions, buckets, and cursors over the redb-backed metadata
//! store, reproducing the observable semantics of dcrd's ffldb driver
//! (database/ffldb `db.go`).
//!
//! The key layout is ffldb's exactly:
//!
//! - key/value rows: `<4-byte bucket ID><key>`; the top-level metadata
//!   bucket has ID `[0, 0, 0, 0]`.
//! - bucket index rows: `bidx<4-byte parent ID><child name>` mapping to
//!   the child's 4-byte ID; the internal block index bucket keeps the
//!   fixed ID `[0, 0, 0, 1]` under the name `ffldb-blockidx`.
//! - the current bucket ID counter lives at the raw key `bidx-cbid`.
//!
//! Because bucket IDs are assigned sequentially from 1 and `bidx`
//! begins with 0x62, a full-bucket cursor observes all key/value rows
//! before all nested-bucket rows, exactly as ffldb's merged raw-key
//! iterators do.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use dcroxide_chainhash::Hash;

use crate::blockfile::{BLOCK_LOC_SIZE, BlockLocation, serialize_write_row};
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
const BLOCK_HDR_SIZE: usize = 180;

/// A particular region of a block, identified by hash, offset, and
/// length (dcrd `BlockRegion`).
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
fn bucket_index_key(parent_id: [u8; 4], key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(BUCKET_INDEX_PREFIX.len() + 4 + key.len());
    out.extend_from_slice(BUCKET_INDEX_PREFIX);
    out.extend_from_slice(&parent_id);
    out.extend_from_slice(key);
    out
}

/// The actual key for a key within a bucket (dcrd `bucketizedKey`):
/// `<bucket ID><key>`.
fn bucketized_key(bucket_id: [u8; 4], key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + key.len());
    out.extend_from_slice(&bucket_id);
    out.extend_from_slice(key);
    out
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

/// The mutable state of a transaction, kept behind a `RefCell` so
/// bucket and cursor handles can share the transaction immutably (like
/// dcrd's interface, a transaction and its derived handles are intended
/// for single-threaded use).
struct TxState {
    /// The underlying key/value transaction; `None` once closed.
    kv: Option<KvTx>,
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
    /// failure check (redb-4.3.0 `page_manager.rs:1379-1382`,
    /// `cached_file.rs:651-659`), so after an I/O error the master
    /// table root keeps opening from cache while every uncached page
    /// returns `PreviousIo`, for the rest of the process.
    table: Option<redb::ReadOnlyTable<&'static [u8], &'static [u8]>>,
    /// Blocks buffered by `store_block` to be written on commit, plus
    /// an index over them by hash (dcrd `pendingBlocks` /
    /// `pendingBlockData`).
    pending_blocks: Vec<(Hash, Vec<u8>)>,
    pending_index: HashMap<[u8; 32], usize>,
    /// Metadata puts buffered until commit (dcrd `pendingKeys`).
    pending_keys: std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
    /// Metadata deletions buffered until commit (dcrd
    /// `pendingRemove`).
    pending_removes: std::collections::BTreeSet<Vec<u8>>,
    /// The metadata cache overlay as of transaction start (dcrd's
    /// `dbCacheSnapshot`): a layer stack held by an `Arc` clone, taken
    /// and dropped in O(1).  A writable transaction releases it at
    /// commit, before the cache applies this transaction, so the
    /// cache's newest layer is unshared and takes the write in place.
    cache_snap: Arc<crate::dbcache::CacheSnapshot>,
}

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
        cache_snap: Arc<crate::dbcache::CacheSnapshot>,
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
                table: None,
                pending_blocks: Vec::new(),
                pending_index: HashMap::new(),
                pending_keys: std::collections::BTreeMap::new(),
                pending_removes: std::collections::BTreeSet::new(),
                cache_snap,
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
    /// use [`Self::try_fetch_raw`].
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
        // a pending deletion (`None`); only a key no layer knows falls
        // through to the store.
        if let Some(entry) = state.cache_snap.get(key) {
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
    /// built it, so it reaches the pending set -- and from there the
    /// cache overlay -- without another copy.
    pub(crate) fn put_raw(&self, key: Vec<u8>, value: &[u8]) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        if state.kv.is_none() || !self.writable {
            return Err(db_error(ErrorKind::TxNotWritable, "tx not writable"));
        }
        state.pending_removes.remove(&key);
        state.pending_keys.insert(key, value.to_vec());
        Ok(())
    }

    /// Stage a delete, taking the key owned as [`Self::put_raw`] does.
    pub(crate) fn delete_raw(&self, key: Vec<u8>) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        if state.kv.is_none() || !self.writable {
            return Err(db_error(ErrorKind::TxNotWritable, "tx not writable"));
        }
        state.pending_keys.remove(&key);
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
        // `put_raw` and `delete_raw` keep the two pending sets disjoint.
        let prior = match state.pending_keys.remove(key) {
            Some(value) => Some(Some(value)),
            None if state.pending_removes.contains(key) => Some(None),
            None => None,
        };
        state.pending_removes.insert(key.to_vec());
        Ok(prior)
    }

    /// The exclusive upper bound of a prefix scan: the prefix with its
    /// last incrementable byte incremented (goleveldb
    /// `util.BytesPrefix` semantics).  `None` for an all-0xff prefix,
    /// which scans to the end of the keyspace.
    ///
    /// Shared by the whole-prefix and windowed scans so the two cannot
    /// drift apart.
    fn prefix_upper_bound(prefix: &[u8]) -> Option<Vec<u8>> {
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
    /// `PreviousIo` forever once it has failed (redb-4.3.0
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
            .merged_from(after.unwrap_or(prefix))
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
            let pending_key = pending.peek().map(|&(key, _)| key.as_slice());
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
            while removed.next_if(|k| k.as_slice() < key.as_slice()).is_some() {}
            let masked = removed.peek().is_some_and(|k| k.as_slice() == key);

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
        self.put_raw(CUR_BUCKET_ID_KEY.to_vec(), &next_bytes)?;
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

    fn has_block_internal(&self, hash: &Hash) -> bool {
        if self.state.borrow().pending_index.contains_key(&hash.0) {
            return true;
        }
        self.has_raw(&bucketized_key(BLOCK_IDX_BUCKET_ID, &hash.0))
    }

    /// Store the provided block (dcrd `StoreBlock`).  The block is
    /// buffered and written to the flat files on commit.
    pub fn store_block(&self, block: &dcroxide_wire::MsgBlock) -> Result<(), Error> {
        // A serialization is a whole header by construction and the hash
        // is that header's, so nothing needs checking; the bytes are
        // moved into the pending set rather than copied a second time.
        self.store_block_with(&block.header.block_hash(), || Ok(block.serialize()))
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
    pub fn store_block_raw(&self, hash: &Hash, raw: Vec<u8>) -> Result<(), Error> {
        self.store_block_with(hash, || {
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
            Ok(raw)
        })
    }

    /// The body of [`Self::store_block`] and [`Self::store_block_raw`],
    /// in dcrd `StoreBlock`'s order: the transaction checks and the
    /// existence check, and only then the block's bytes (dcrd
    /// `block.Bytes()`, whose failure is `ErrDriverSpecific`).
    fn store_block_with(
        &self,
        hash: &Hash,
        bytes: impl FnOnce() -> Result<Vec<u8>, Error>,
    ) -> Result<(), Error> {
        self.check_closed()?;
        if !self.writable {
            return Err(db_error(
                ErrorKind::TxNotWritable,
                "store block requires a writable database transaction",
            ));
        }

        // Reject the block if it already exists (pending or stored).
        if self.has_block_internal(hash) {
            return Err(db_error(
                ErrorKind::BlockExists,
                format!("block {hash} already exists"),
            ));
        }
        let raw = bytes()?;

        let mut state = self.state.borrow_mut();
        let idx = state.pending_blocks.len();
        state.pending_blocks.push((*hash, raw));
        state.pending_index.insert(hash.0, idx);
        Ok(())
    }

    /// Whether a block with the given hash exists (dcrd `HasBlock`).
    pub fn has_block(&self, hash: &Hash) -> Result<bool, Error> {
        self.check_closed()?;
        Ok(self.has_block_internal(hash))
    }

    /// Whether each of the blocks with the provided hashes exists (dcrd
    /// `HasBlocks`).
    pub fn has_blocks(&self, hashes: &[Hash]) -> Result<Vec<bool>, Error> {
        self.check_closed()?;
        Ok(hashes.iter().map(|h| self.has_block_internal(h)).collect())
    }

    fn fetch_block_row(&self, hash: &Hash) -> Result<Vec<u8>, Error> {
        self.fetch_raw(&bucketized_key(BLOCK_IDX_BUCKET_ID, &hash.0))
            .ok_or_else(|| {
                db_error(
                    ErrorKind::BlockNotFound,
                    format!("block {hash} does not exist"),
                )
            })
    }

    fn pending_block_bytes(&self, hash: &Hash) -> Option<Vec<u8>> {
        let state = self.state.borrow();
        let idx = *state.pending_index.get(&hash.0)?;
        Some(state.pending_blocks[idx].1.clone())
    }

    /// The raw serialized bytes of the block header for the given hash
    /// (dcrd `FetchBlockHeader`).  Headers are read from the block
    /// index row, never the flat files.
    pub fn fetch_block_header(&self, hash: &Hash) -> Result<Vec<u8>, Error> {
        self.check_closed()?;
        if let Some(bytes) = self.pending_block_bytes(hash) {
            return Ok(bytes[..BLOCK_HDR_SIZE].to_vec());
        }
        let row = self.fetch_block_row(hash)?;
        if row.len() < BLOCK_LOC_SIZE + BLOCK_HDR_SIZE {
            return Err(db_error(ErrorKind::Corruption, "corrupt block index row"));
        }
        Ok(row[BLOCK_LOC_SIZE..BLOCK_LOC_SIZE + BLOCK_HDR_SIZE].to_vec())
    }

    /// The raw block headers for the given hashes (dcrd
    /// `FetchBlockHeaders`).
    pub fn fetch_block_headers(&self, hashes: &[Hash]) -> Result<Vec<Vec<u8>>, Error> {
        hashes.iter().map(|h| self.fetch_block_header(h)).collect()
    }

    /// The raw serialized bytes for the block with the given hash (dcrd
    /// `FetchBlock`).
    pub fn fetch_block(&self, hash: &Hash) -> Result<Vec<u8>, Error> {
        self.check_closed()?;
        if let Some(bytes) = self.pending_block_bytes(hash) {
            return Ok(bytes);
        }
        let row = self.fetch_block_row(hash)?;
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

    /// The raw serialized bytes for the blocks with the given hashes
    /// (dcrd `FetchBlocks`).
    pub fn fetch_blocks(&self, hashes: &[Hash]) -> Result<Vec<Vec<u8>>, Error> {
        hashes.iter().map(|h| self.fetch_block(h)).collect()
    }

    /// The raw bytes of the given block region (dcrd
    /// `FetchBlockRegion`).
    pub fn fetch_block_region(&self, region: &BlockRegion) -> Result<Vec<u8>, Error> {
        self.check_closed()?;

        // Pending blocks are served straight from the buffered bytes.
        if let Some(bytes) = self.pending_block_bytes(&region.hash) {
            let end = region.offset.checked_add(region.len);
            match end {
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

        let row = self.fetch_block_row(&region.hash)?;
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

    /// The raw bytes of the given block regions (dcrd
    /// `FetchBlockRegions`).
    pub fn fetch_block_regions(&self, regions: &[BlockRegion]) -> Result<Vec<Vec<u8>>, Error> {
        regions.iter().map(|r| self.fetch_block_region(r)).collect()
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
        if state.kv.take().is_some() && self.writable {
            // Release the writer semaphore (dcrd releases its write
            // lock when a writable transaction ends).
            let mut busy = self.db.writer_busy.lock().expect("writer flag poisoned");
            *busy = false;
            self.db.writer_cv.notify_one();
        }
        state.pending_blocks.clear();
        state.pending_index.clear();
        state.pending_keys.clear();
        state.pending_removes.clear();
        state.cache_snap = Arc::new(crate::dbcache::CacheSnapshot::default());
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
        // writer semaphore and only a semaphore holder can set it, so
        // this cannot fire today; it is here so the latch does not rest
        // on that ordering alone.
        if let Err(e) = self.db.check_writable() {
            self.close();
            return Err(e);
        }

        // Write the pending blocks to the flat files first, recording
        // their locations, then stage the block index rows and the
        // updated write cursor into the metadata transaction, and only
        // then commit it.  A crash between the file writes and the
        // metadata commit leaves orphaned file bytes which are
        // reconciled away on the next open, matching dcrd's ordering.
        let pending: Vec<(Hash, Vec<u8>)> =
            std::mem::take(&mut self.state.borrow_mut().pending_blocks);
        let rollback_pos = {
            let store = self.db.block_store.lock().expect("store lock");
            (store.write_file_num, store.write_offset)
        };

        let result = (|| -> Result<(), Error> {
            let mut locations = Vec::with_capacity(pending.len());
            {
                let mut store = self.db.block_store.lock().expect("store lock");
                for (hash, bytes) in &pending {
                    let loc = store.write_block(bytes)?;
                    locations.push((*hash, loc, bytes));
                }
                // The metadata cache flush syncs the files; per-
                // commit syncing is gone with it (dcrd ffldb).

                // Stage the block index rows: location || header.
                for (hash, loc, bytes) in &locations {
                    let mut row = Vec::with_capacity(BLOCK_LOC_SIZE + BLOCK_HDR_SIZE);
                    row.extend_from_slice(&loc.serialize());
                    row.extend_from_slice(&bytes[..BLOCK_HDR_SIZE]);
                    self.put_raw(bucketized_key(BLOCK_IDX_BUCKET_ID, &hash.0), &row)?;
                }

                // Stage the new write cursor position.
                let row = serialize_write_row(store.write_file_num, store.write_offset);
                self.put_raw(bucketized_key(METADATA_BUCKET_ID, WRITE_LOC_KEY), &row)?;
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
        // holds the writer semaphore throughout, which is what keeps two
        // flushes from overlapping.
        if let Err(e) = crate::flush_locked(&self.db, true) {
            // Already latched by `flush_locked`: the dirty set is still
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

        let (puts, removes) = {
            let mut state = self.state.borrow_mut();
            // Release this transaction's snapshot so the cache's newest
            // layer is unshared when it applies the changes below and
            // can take them in place (a snapshot naming that layer
            // forces the commit to seal a fresh layer instead).
            state.cache_snap = Arc::new(crate::dbcache::CacheSnapshot::default());
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
    pub fn bucket(&self, key: &[u8]) -> Option<Bucket<'tx>> {
        if self.tx.check_closed().is_err() {
            return None;
        }
        let child_id = self.tx.fetch_raw(&bucket_index_key(self.id, key))?;
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
        if self.tx.has_raw(&bidx_key) {
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
        self.tx.put_raw(bidx_key, &child_id)?;
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
        let child_id = self.tx.fetch_raw(&bidx_key).ok_or_else(|| {
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
                self.tx.delete_raw(raw_key)?;
            }

            // Iterate through all nested buckets, pushing their IDs
            // for the next iteration and removing their index rows.  The
            // ID is the row's value, taken from the scan as dcrd takes
            // it from its cursor (`rawValue`).
            let mut prefix = Vec::with_capacity(BUCKET_INDEX_PREFIX.len() + 4);
            prefix.extend_from_slice(BUCKET_INDEX_PREFIX);
            prefix.extend_from_slice(&child_id);
            let rows = self
                .tx
                .scan_prefix_window(&prefix, None, None, true, true)
                .rows;
            for (raw_key, grandchild) in rows {
                child_ids.push(grandchild);
                self.tx.delete_raw(raw_key)?;
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

    /// Save the specified key/value pair to the bucket (dcrd `Put`).
    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), Error> {
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
        self.tx.put_raw(bucketized_key(self.id, key), value)
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
        self.tx.fetch_raw(&bucketized_key(self.id, key))
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
        self.tx.try_fetch_raw(&bucketized_key(self.id, key))
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
            .partition_point(|k| k.as_slice() < seek_key.as_slice());
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
