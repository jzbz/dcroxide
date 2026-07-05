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
use redb::ReadableTable;

use crate::blockfile::{BLOCK_LOC_SIZE, BLOCK_RECORD_OVERHEAD, BlockLocation, serialize_write_row};
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

/// The underlying redb transaction, either read-only or read-write.
// One value exists per transaction, so the size difference between the
// redb read and write transaction types is irrelevant.
#[allow(clippy::large_enum_variant)]
enum KvTx {
    Read(redb::ReadTransaction),
    Write(redb::WriteTransaction),
}

/// The mutable state of a transaction, kept behind a `RefCell` so
/// bucket and cursor handles can share the transaction immutably (like
/// dcrd's interface, a transaction and its derived handles are intended
/// for single-threaded use).
struct TxState {
    /// The underlying key/value transaction; `None` once closed.
    kv: Option<KvTx>,
    /// Blocks buffered by `store_block` to be written on commit, plus
    /// an index over them by hash (dcrd `pendingBlocks` /
    /// `pendingBlockData`).
    pending_blocks: Vec<(Hash, Vec<u8>)>,
    pending_index: HashMap<[u8; 32], usize>,
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
    pub(crate) fn new(db: Arc<DbInner>, kv: KvTxSeed, managed: bool) -> Transaction {
        let (kv, writable) = match kv {
            KvTxSeed::Read(t) => (KvTx::Read(t), false),
            KvTxSeed::Write(t) => (KvTx::Write(t), true),
        };
        Transaction {
            db,
            state: RefCell::new(TxState {
                kv: Some(kv),
                pending_blocks: Vec::new(),
                pending_index: HashMap::new(),
            }),
            writable,
            managed,
        }
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

    pub(crate) fn fetch_raw(&self, key: &[u8]) -> Option<Vec<u8>> {
        let state = self.state.borrow();
        match state.kv.as_ref()? {
            KvTx::Read(t) => {
                let table = t.open_table(METADATA_TABLE).ok()?;
                table.get(key).ok()?.map(|g| g.value().to_vec())
            }
            KvTx::Write(t) => {
                let table = t.open_table(METADATA_TABLE).ok()?;
                table.get(key).ok()?.map(|g| g.value().to_vec())
            }
        }
    }

    fn has_raw(&self, key: &[u8]) -> bool {
        self.fetch_raw(key).is_some()
    }

    pub(crate) fn put_raw(&self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        let state = self.state.borrow();
        match state.kv.as_ref() {
            Some(KvTx::Write(t)) => {
                let mut table = t
                    .open_table(METADATA_TABLE)
                    .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
                table
                    .insert(key, value)
                    .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
                Ok(())
            }
            _ => Err(db_error(ErrorKind::TxNotWritable, "tx not writable")),
        }
    }

    pub(crate) fn delete_raw(&self, key: &[u8]) -> Result<(), Error> {
        let state = self.state.borrow();
        match state.kv.as_ref() {
            Some(KvTx::Write(t)) => {
                let mut table = t
                    .open_table(METADATA_TABLE)
                    .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
                table
                    .remove(key)
                    .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
                Ok(())
            }
            _ => Err(db_error(ErrorKind::TxNotWritable, "tx not writable")),
        }
    }

    /// All raw keys beginning with the prefix, in raw byte order.
    fn scan_prefix_keys(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
        let mut end = prefix.to_vec();
        // The exclusive upper bound is the prefix with its last byte
        // that can be incremented, incremented (goleveldb
        // util.BytesPrefix semantics); an all-0xff prefix scans to the
        // end of the keyspace.
        let mut bounded = false;
        for i in (0..end.len()).rev() {
            if end[i] != 0xff {
                end[i] += 1;
                end.truncate(i + 1);
                bounded = true;
                break;
            }
        }

        let collect = |iter: redb::Range<'_, &'static [u8], &'static [u8]>| -> Vec<Vec<u8>> {
            iter.flatten().map(|(k, _)| k.value().to_vec()).collect()
        };

        let state = self.state.borrow();
        let Some(kv) = state.kv.as_ref() else {
            return Vec::new();
        };
        let result = match kv {
            KvTx::Read(t) => t.open_table(METADATA_TABLE).ok().and_then(|table| {
                let range = if bounded {
                    table.range(prefix..end.as_slice())
                } else {
                    table.range(prefix..)
                };
                range.ok().map(collect)
            }),
            KvTx::Write(t) => t.open_table(METADATA_TABLE).ok().and_then(|table| {
                let range = if bounded {
                    table.range(prefix..end.as_slice())
                } else {
                    table.range(prefix..)
                };
                range.ok().map(collect)
            }),
        };
        result.unwrap_or_default()
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
        self.put_raw(CUR_BUCKET_ID_KEY, &next_bytes)?;
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
        self.store_block_raw(&block.header.block_hash(), &block.serialize())
    }

    /// Store a block given its hash and raw serialized bytes; the raw
    /// entry point used by bulk import.
    pub fn store_block_raw(&self, hash: &Hash, raw: &[u8]) -> Result<(), Error> {
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

        let mut state = self.state.borrow_mut();
        let idx = state.pending_blocks.len();
        state.pending_blocks.push((*hash, raw.to_vec()));
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
        self.db
            .block_store
            .lock()
            .expect("store lock")
            .read_block(loc)
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
                            "block {} region is invalid: offset {}, length {}",
                            region.hash, region.offset, region.len
                        ),
                    ));
                }
            }
        }

        let row = self.fetch_block_row(&region.hash)?;
        let loc = BlockLocation::deserialize(&row[..BLOCK_LOC_SIZE]);

        // Ensure the region is within the bounds of the block.
        let block_len = loc.block_len - BLOCK_RECORD_OVERHEAD;
        let end = region.offset.checked_add(region.len);
        match end {
            Some(end) if end <= block_len => {}
            _ => {
                return Err(db_error(
                    ErrorKind::BlockRegionInvalid,
                    format!(
                        "block {} region exceeds the block length of {block_len}: offset {}, \
                         length {}",
                        region.hash, region.offset, region.len
                    ),
                ));
            }
        }

        self.db
            .block_store
            .lock()
            .expect("store lock")
            .read_block_region(loc, region.offset, region.len)
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
        if let Some(kv) = state.kv.take() {
            match kv {
                KvTx::Read(_) => {}
                KvTx::Write(t) => {
                    let _ = t.abort();
                }
            }
        }
        state.pending_blocks.clear();
        state.pending_index.clear();
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
                store.sync()?;

                // Stage the block index rows: location || header.
                for (hash, loc, bytes) in &locations {
                    let mut row = Vec::with_capacity(BLOCK_LOC_SIZE + BLOCK_HDR_SIZE);
                    row.extend_from_slice(&loc.serialize());
                    row.extend_from_slice(&bytes[..BLOCK_HDR_SIZE]);
                    self.put_raw(&bucketized_key(BLOCK_IDX_BUCKET_ID, &hash.0), &row)?;
                }

                // Stage the new write cursor position.
                let row = serialize_write_row(store.write_file_num, store.write_offset);
                self.put_raw(&bucketized_key(METADATA_BUCKET_ID, WRITE_LOC_KEY), &row)?;
            }

            // Commit the metadata transaction.
            let kv = self.state.borrow_mut().kv.take();
            match kv {
                Some(KvTx::Write(t)) => t
                    .commit()
                    .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string())),
                _ => unreachable!("writable transaction has a write tx"),
            }
        })();

        if result.is_err() {
            // Roll the flat files back to their pre-transaction state
            // and abort the metadata transaction if it is still open.
            let _ = self
                .db
                .block_store
                .lock()
                .expect("store lock")
                .rollback_to(rollback_pos.0, rollback_pos.1);
            self.close();
        } else {
            self.state.borrow_mut().pending_index.clear();
        }
        result
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
    Write(redb::WriteTransaction),
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
        self.tx.put_raw(&bidx_key, &child_id)?;
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
                self.tx.delete_raw(&raw_key)?;
            }

            // Iterate through all nested buckets, pushing their IDs
            // for the next iteration and removing their index rows.
            let mut prefix = Vec::with_capacity(BUCKET_INDEX_PREFIX.len() + 4);
            prefix.extend_from_slice(BUCKET_INDEX_PREFIX);
            prefix.extend_from_slice(&child_id);
            for raw_key in self.tx.scan_prefix_keys(&prefix) {
                if let Some(grandchild) = self.tx.fetch_raw(&raw_key) {
                    child_ids.push(grandchild);
                }
                self.tx.delete_raw(&raw_key)?;
            }
        }

        // Remove the nested bucket from the bucket index.
        self.tx.delete_raw(&bidx_key)
    }

    /// Invoke the function with every key/value pair in the bucket, not
    /// including nested buckets; the first error from the callback is
    /// returned (dcrd `ForEach`).
    pub fn for_each(
        &self,
        mut fn_: impl FnMut(&[u8], &[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.tx.check_closed()?;
        for raw_key in self.tx.scan_prefix_keys(&self.id) {
            let value = self.tx.fetch_raw(&raw_key).unwrap_or_default();
            fn_(&raw_key[4..], &value)?;
        }
        Ok(())
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
        self.tx.put_raw(&bucketized_key(self.id, key), value)
    }

    /// The value for the given key, or `None` if it does not exist;
    /// keys that exist with no value return an empty vector (dcrd
    /// `Get`).
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        if self.tx.check_closed().is_err() || key.is_empty() {
            return None;
        }
        self.tx.fetch_raw(&bucketized_key(self.id, key))
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
        self.tx.delete_raw(&bucketized_key(self.id, key))
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
}

impl Cursor<'_> {
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
        self.tx.delete_raw(&raw)
    }

    /// Position at the first entry; returns whether it exists (dcrd
    /// `First`).
    pub fn first(&mut self) -> bool {
        if self.tx.check_closed().is_err() || self.keys.is_empty() {
            self.pos = CursorPos::Exhausted;
            return false;
        }
        self.pos = CursorPos::At(0);
        true
    }

    /// Position at the last entry; returns whether it exists (dcrd
    /// `Last`).
    pub fn last(&mut self) -> bool {
        if self.tx.check_closed().is_err() || self.keys.is_empty() {
            self.pos = CursorPos::Exhausted;
            return false;
        }
        self.pos = CursorPos::At(self.keys.len() - 1);
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
        match self.pos {
            CursorPos::At(i) if i + 1 < self.keys.len() => {
                self.pos = CursorPos::At(i + 1);
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
        match self.pos {
            CursorPos::At(i) if i > 0 => {
                self.pos = CursorPos::At(i - 1);
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
        let seek_key = bucketized_key(self.bucket_id, seek);
        let idx = self
            .keys
            .partition_point(|k| k.as_slice() < seek_key.as_slice());
        if idx < self.keys.len() {
            self.pos = CursorPos::At(idx);
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
        let raw = self.current_raw()?;
        if raw.starts_with(BUCKET_INDEX_PREFIX) {
            return Some(raw[BUCKET_INDEX_PREFIX.len() + 4..].to_vec());
        }
        Some(raw[4..].to_vec())
    }

    /// The current value; `None` when exhausted or pointing at a nested
    /// bucket (dcrd `Value`).
    pub fn value(&self) -> Option<Vec<u8>> {
        if self.tx.check_closed().is_err() {
            return None;
        }
        let raw = self.current_raw()?;
        if raw.starts_with(BUCKET_INDEX_PREFIX) {
            return None;
        }
        self.tx.fetch_raw(raw)
    }
}
