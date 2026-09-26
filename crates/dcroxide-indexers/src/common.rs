// SPDX-License-Identifier: ISC
//! The generic indexer machinery (dcrd indexers `common.go`): the
//! chain queryer and indexer interfaces, the index tips bucket with
//! its version and drop-marker keys, index creation and upgrade, and
//! the incremental drop paths shared by every index.

use std::sync::Arc;

use dcroxide_chaincfg::Params;
use dcroxide_chainhash::{HASH_SIZE, Hash};
use dcroxide_database::{Database, Transaction};
use dcroxide_wire::{BlockHeader, MsgBlock};

use crate::error::{ErrorKind, IdxError, indexer_error};
use crate::log::{LogLevel, LogSink, log_line};
use crate::subscriber::IndexNtfn;

/// The name of the db bucket used to house the current tip of each
/// index (dcrd `indexTipsBucketName`).
pub(crate) const INDEX_TIPS_BUCKET_NAME: &[u8] = b"idxtips";

/// The error message for interrupt requested errors (dcrd
/// `interruptMsg`).
pub(crate) const INTERRUPT_MSG: &str = "interrupt requested";

/// A shared interrupt flag standing in for dcrd's context
/// cancellation: the daemon sets it to request an early shutdown of
/// long-running index operations.
pub type Interrupt = Arc<core::sync::atomic::AtomicBool>;

/// Whether an interrupt has been requested (dcrd
/// `interruptRequested`).
pub(crate) fn interrupt_requested(interrupt: &Interrupt) -> bool {
    interrupt.load(core::sync::atomic::Ordering::SeqCst)
}

/// A handle returned by [`Indexer::wait_for_sync`]: it flips to true
/// when the index signals its subscribers that it is synced (the
/// synchronous stand-in for dcrd's closed channel).
pub type SyncWaiter = Arc<core::sync::atomic::AtomicBool>;

/// Signal and clear the provided sync subscribers (dcrd
/// `notifySyncSubscribers`).
pub(crate) fn notify_sync_subscribers(subscribers: &mut Vec<SyncWaiter>) {
    for sub in subscribers.drain(..) {
        sub.store(true, core::sync::atomic::Ordering::SeqCst);
    }
}

/// Access to the chain details required by indexes (dcrd
/// `ChainQueryer`).  The daemon shares one queryer across the index
/// threads, so implementations must be thread-safe.
pub trait ChainQueryer: Send + Sync {
    /// Whether the block with the given hash is in the main chain.
    fn main_chain_has_block(&self, hash: &Hash) -> bool;

    /// The network parameters of the chain.
    fn chain_params(&self) -> &Params;

    /// The height and hash of the current best block.
    fn best(&self) -> (i64, Hash);

    /// The block header identified by the given hash.
    fn block_header_by_hash(&self, hash: &Hash) -> Result<BlockHeader, String>;

    /// The hash of the block at the given height in the main chain.
    fn block_hash_by_height(&self, height: i64) -> Result<Hash, String>;

    /// The height of the block with the given hash in the main chain.
    fn block_height_by_hash(&self, hash: &Hash) -> Result<i64, String>;

    /// The block of the provided hash.
    fn block_by_hash(&self, hash: &Hash) -> Result<Arc<MsgBlock>, String>;

    /// Whether the treasury agenda is active at the provided block.
    fn is_treasury_agenda_active(&self, hash: &Hash) -> Result<bool, String>;
}

/// A generic indexer (dcrd `Indexer`).  dcrd's `Init` is realized by
/// the index constructors together with
/// [`IndexSubscriber::subscribe`](crate::IndexSubscriber::subscribe),
/// and the `DropIndex` method of dcrd's `IndexDropper` is part of
/// this trait since both concrete indexes implement it.  The daemon
/// drives the indexes from its own threads, so implementations must
/// be sendable.
pub trait Indexer: Send {
    /// The key of the index as a byte slice.
    fn key(&self) -> &'static [u8];

    /// The human-readable name of the index.
    fn name(&self) -> &'static str;

    /// The current version of the index.
    fn version(&self) -> u32;

    /// The database of the index.
    fn db(&self) -> Arc<Database>;

    /// The chain queryer.
    fn queryer(&self) -> Arc<dyn ChainQueryer>;

    /// The current index tip.
    fn tip(&self) -> Result<(i64, Hash), IdxError>;

    /// Invoked when the indexer is being created.
    fn create(&self, db_tx: &Transaction) -> Result<(), IdxError>;

    /// Index the provided notification based on its notification
    /// type.
    fn process_notification(
        &mut self,
        db_tx: &Transaction,
        ntfn: &IndexNtfn,
    ) -> Result<(), IdxError>;

    /// Subscribe for the next index sync update.
    fn wait_for_sync(&mut self) -> SyncWaiter;

    /// Signal subscribers of an index sync update.  This should only
    /// be called when the index is synced.
    fn notify_sync_subscribers(&mut self);

    /// Whether any client is waiting for the next sync update.  Without
    /// one, signalling is a no-op, so the update path skips the reads
    /// dcrd's `maybeNotifySubscribers` makes to decide whether to
    /// signal.
    fn has_sync_subscribers(&self) -> bool;

    /// Remove the index from the database (dcrd `IndexDropper`),
    /// logging the drop to `log` as dcrd logs it to the package logger.
    fn drop_index(
        &self,
        interrupt: &Interrupt,
        db: &Database,
        log: Option<&LogSink>,
    ) -> Result<(), IdxError>;
}

/// Construct a database error (dcrd `makeDbErr`).
pub(crate) fn make_db_err(kind: dcroxide_database::ErrorKind, desc: impl Into<String>) -> IdxError {
    IdxError::Db(dcroxide_database::Error {
        kind,
        description: desc.into(),
    })
}

/// Update or add the current tip for the given index (dcrd
/// `dbPutIndexerTip`).
pub(crate) fn db_put_indexer_tip(
    db_tx: &Transaction,
    idx_key: &[u8],
    hash: &Hash,
    height: i32,
) -> Result<(), IdxError> {
    let mut serialized = [0u8; HASH_SIZE + 4];
    serialized[..HASH_SIZE].copy_from_slice(&hash.0);
    serialized[HASH_SIZE..].copy_from_slice(&(height as u32).to_le_bytes());

    let meta = db_tx.metadata();
    let indexes_bucket = meta.bucket(INDEX_TIPS_BUCKET_NAME).ok_or_else(|| {
        make_db_err(
            dcroxide_database::ErrorKind::BucketNotFound,
            format!(
                "{} bucket not found",
                String::from_utf8_lossy(INDEX_TIPS_BUCKET_NAME)
            ),
        )
    })?;
    indexes_bucket.put(idx_key, &serialized)?;
    Ok(())
}

/// Retrieve the hash and height of the current tip for the provided
/// index (dcrd `dbFetchIndexerTip`).
pub(crate) fn db_fetch_indexer_tip(
    db_tx: &Transaction,
    idx_key: &[u8],
) -> Result<(Hash, i32), IdxError> {
    let meta = db_tx.metadata();
    let indexes_bucket = meta.bucket(INDEX_TIPS_BUCKET_NAME).ok_or_else(|| {
        make_db_err(
            dcroxide_database::ErrorKind::BucketNotFound,
            format!(
                "{} bucket not found",
                String::from_utf8_lossy(INDEX_TIPS_BUCKET_NAME)
            ),
        )
    })?;
    let serialized = indexes_bucket.get(idx_key).unwrap_or_default();
    if serialized.is_empty() {
        return Err(make_db_err(
            dcroxide_database::ErrorKind::ValueNotFound,
            format!(
                "no index tip value found for {} ",
                String::from_utf8_lossy(idx_key)
            ),
        ));
    }
    if serialized.len() < HASH_SIZE + 4 {
        return Err(make_db_err(
            dcroxide_database::ErrorKind::Corruption,
            format!(
                "unexpected end of data for index \"{}\" tip",
                String::from_utf8_lossy(idx_key)
            ),
        ));
    }

    let mut hash = Hash::ZERO;
    hash.0.copy_from_slice(&serialized[..HASH_SIZE]);
    let mut height_bytes = [0u8; 4];
    height_bytes.copy_from_slice(&serialized[HASH_SIZE..HASH_SIZE + 4]);
    let height = u32::from_le_bytes(height_bytes) as i32;
    Ok((hash, height))
}

/// The key which houses the current version of an index (dcrd
/// `indexVersionKey`).
pub(crate) fn index_version_key(idx_key: &[u8]) -> Vec<u8> {
    let mut ver_key = Vec::with_capacity(idx_key.len().saturating_add(1));
    ver_key.push(b'v');
    ver_key.extend_from_slice(idx_key);
    ver_key
}

/// Update the version for the given index (dcrd
/// `dbPutIndexerVersion`).
pub(crate) fn db_put_indexer_version(
    db_tx: &Transaction,
    idx_key: &[u8],
    version: u32,
) -> Result<(), IdxError> {
    let serialized = version.to_le_bytes();
    let meta = db_tx.metadata();
    let indexes_bucket = meta.bucket(INDEX_TIPS_BUCKET_NAME).ok_or_else(|| {
        make_db_err(
            dcroxide_database::ErrorKind::BucketNotFound,
            format!(
                "{} bucket not found",
                String::from_utf8_lossy(INDEX_TIPS_BUCKET_NAME)
            ),
        )
    })?;
    indexes_bucket.put(&index_version_key(idx_key), &serialized)?;
    Ok(())
}

/// Whether the index keyed by `idx_key` exists in the database (dcrd
/// `existsIndex`).
pub(crate) fn exists_index(db: &Database, idx_key: &[u8]) -> Result<bool, IdxError> {
    let db_tx = db.begin(false)?;
    let exists = db_tx
        .metadata()
        .bucket(INDEX_TIPS_BUCKET_NAME)
        .is_some_and(|bucket| bucket.get(idx_key).is_some());
    db_tx.rollback()?;
    Ok(exists)
}

/// Deletions per database update, matching the `maxDeletions` constant
/// in dcrd's `incrementalFlatDrop` (`common.go:224`).
pub(crate) const MAX_DELETIONS_PER_BATCH: u64 = 2_000_000;

/// Remove key/value pairs from a flat index over multiple database
/// updates (dcrd `incrementalFlatDrop`), logging each batch that
/// deleted anything as "Deleted N keys (M total) from <index>".
///
/// `max_deletions` is dcrd's fixed 2,000,000 in every caller; it is a
/// parameter so the batching itself can be exercised, which needs a cap
/// small enough to make the walk take more than one round.
pub(crate) fn incremental_flat_drop(
    interrupt: &Interrupt,
    db: &Database,
    idx_key: &[u8],
    idx_name: &str,
    max_deletions: u64,
    log: Option<&LogSink>,
) -> Result<(), IdxError> {
    let mut total_deleted: u64 = 0;
    let mut num_deleted = max_deletions;
    // Where the previous batch stopped.  dcrd's cursor is a pair of lazy
    // merged iterators, so it can restart from the beginning each batch
    // for free; this one materializes the keys it walks, so restarting
    // it re-read the whole bucket every time -- 66,494,886 rows for
    // mainnet's `existsaddridx`, once per 2,000,000-key batch.
    //
    // Deliberately not carried across calls to this function: an
    // interrupted drop must start from whatever is actually left.
    let mut resume: Option<Vec<u8>> = None;
    while num_deleted == max_deletions {
        num_deleted = 0;
        let db_tx = db.begin(true)?;
        let res: Result<(), dcroxide_database::Error> = (|| {
            let meta = db_tx.metadata();
            let Some(bucket) = meta.bucket(idx_key) else {
                return Ok(());
            };
            let mut cursor = bucket.cursor_window(resume.as_deref(), max_deletions as usize);
            let mut ok = cursor.first();
            while ok {
                // Captured before the delete: a nested-bucket row that
                // `delete` refuses must not become the resume point, or
                // the next batch would skip past everything before it.
                let at = cursor.raw_key();
                cursor.delete()?;
                resume = at;
                num_deleted = num_deleted.saturating_add(1);
                ok = cursor.next() && num_deleted < max_deletions;
            }
            Ok(())
        })();
        match res {
            Ok(()) => db_tx.commit()?,
            Err(err) => {
                let _ = db_tx.rollback();
                return Err(IdxError::Db(err));
            }
        }

        if num_deleted > 0 {
            total_deleted = total_deleted.saturating_add(num_deleted);
            log_line(
                log,
                LogLevel::Info,
                &format!("Deleted {num_deleted} keys ({total_deleted} total) from {idx_name}"),
            );
        }

        if interrupt_requested(interrupt) {
            return Err(indexer_error(ErrorKind::InterruptRequested, INTERRUPT_MSG));
        }
    }
    Ok(())
}

/// The key which indicates an index is in the process of being
/// dropped (dcrd `indexDropKey`).
pub(crate) fn index_drop_key(idx_key: &[u8]) -> Vec<u8> {
    let mut drop_key = Vec::with_capacity(idx_key.len().saturating_add(1));
    drop_key.push(b'd');
    drop_key.extend_from_slice(idx_key);
    drop_key
}

/// Drop the index metadata: the top level bucket, the index tip, the
/// version, and any in-progress drop flag (dcrd `dropIndexMetadata`).
pub(crate) fn drop_index_metadata(db: &Database, idx_key: &[u8]) -> Result<(), IdxError> {
    let db_tx = db.begin(true)?;
    let res: Result<(), IdxError> = (|| {
        let meta = db_tx.metadata();
        let indexes_bucket = meta.bucket(INDEX_TIPS_BUCKET_NAME).ok_or_else(|| {
            make_db_err(
                dcroxide_database::ErrorKind::BucketNotFound,
                format!(
                    "{} bucket not found",
                    String::from_utf8_lossy(INDEX_TIPS_BUCKET_NAME)
                ),
            )
        })?;
        indexes_bucket.delete(idx_key)?;

        match meta.delete_bucket(idx_key) {
            Ok(()) => {}
            Err(err) if err.kind == dcroxide_database::ErrorKind::BucketNotFound => {}
            Err(err) => return Err(IdxError::Db(err)),
        }

        indexes_bucket.delete(&index_version_key(idx_key))?;
        indexes_bucket.delete(&index_drop_key(idx_key))?;
        Ok(())
    })();
    match res {
        Ok(()) => {
            db_tx.commit()?;
            Ok(())
        }
        Err(err) => {
            let _ = db_tx.rollback();
            Err(err)
        }
    }
}

/// Incrementally drop the passed flat index from the database (dcrd
/// `dropFlatIndex`).
pub(crate) fn drop_flat_index(
    interrupt: &Interrupt,
    db: &Database,
    idx_key: &[u8],
    idx_name: &str,
    log: Option<&LogSink>,
) -> Result<(), IdxError> {
    // Nothing to do if the index doesn't already exist.
    if !exists_index(db, idx_key)? {
        log_line(
            log,
            LogLevel::Info,
            &format!("Not dropping {idx_name} because it does not exist"),
        );
        return Ok(());
    }

    log_line(
        log,
        LogLevel::Info,
        &format!("Dropping all {idx_name} entries.  This might take a while..."),
    );

    // Mark that the index is in the process of being dropped so that
    // it can be resumed on the next start if interrupted before the
    // process is complete.
    mark_index_deletion(db, idx_key)?;

    incremental_flat_drop(
        interrupt,
        db,
        idx_key,
        idx_name,
        MAX_DELETIONS_PER_BATCH,
        log,
    )?;

    // Remove the index tip, version, bucket, and in-progress drop flag
    // now that all index entries have been removed.
    drop_index_metadata(db, idx_key)?;

    log_line(log, LogLevel::Info, &format!("Dropped {idx_name}"));
    Ok(())
}

/// Mark the index identified by `idx_key` for deletion (dcrd
/// `markIndexDeletion`).
pub(crate) fn mark_index_deletion(db: &Database, idx_key: &[u8]) -> Result<(), IdxError> {
    let db_tx = db.begin(true)?;
    let res: Result<(), IdxError> = (|| {
        let meta = db_tx.metadata();
        let indexes_bucket = meta.bucket(INDEX_TIPS_BUCKET_NAME).ok_or_else(|| {
            make_db_err(
                dcroxide_database::ErrorKind::BucketNotFound,
                format!(
                    "{} bucket not found",
                    String::from_utf8_lossy(INDEX_TIPS_BUCKET_NAME)
                ),
            )
        })?;
        indexes_bucket.put(&index_drop_key(idx_key), idx_key)?;
        Ok(())
    })();
    match res {
        Ok(()) => {
            db_tx.commit()?;
            Ok(())
        }
        Err(err) => {
            let _ = db_tx.rollback();
            Err(err)
        }
    }
}

/// The current tip hash and height of the provided index (dcrd
/// `tip`).
pub(crate) fn tip(db: &Database, key: &[u8]) -> Result<(i64, Hash), IdxError> {
    let db_tx = db.begin(false)?;
    let res = db_fetch_indexer_tip(&db_tx, key);
    db_tx.rollback()?;
    let (hash, height) = res?;
    Ok((i64::from(height), hash))
}

/// Determine if the provided index is in the middle of being dropped
/// and finish dropping it when it is (dcrd `finishDrop`).
pub(crate) fn finish_drop(
    interrupt: &Interrupt,
    indexer: &dyn Indexer,
    log: Option<&LogSink>,
) -> Result<(), IdxError> {
    let db = indexer.db();
    let db_tx = db.begin(false)?;
    let drop = db_tx
        .metadata()
        .bucket(INDEX_TIPS_BUCKET_NAME)
        .is_some_and(|bucket| bucket.get(&index_drop_key(indexer.key())).is_some());
    db_tx.rollback()?;

    // Nothing to do if the index does not need dropping.
    if !drop {
        return Ok(());
    }

    if interrupt_requested(interrupt) {
        return Err(indexer_error(ErrorKind::InterruptRequested, INTERRUPT_MSG));
    }

    log_line(
        log,
        LogLevel::Info,
        &format!("Resuming {} drop", indexer.name()),
    );

    indexer.drop_index(interrupt, &db, log)
}

/// Determine if the provided index has already been created and
/// create it if not (dcrd `createIndex`).
pub(crate) fn create_index(indexer: &dyn Indexer, genesis_hash: &Hash) -> Result<(), IdxError> {
    let db = indexer.db();
    let db_tx = db.begin(true)?;
    let res: Result<(), IdxError> = (|| {
        // Create the bucket for the current tips as needed.
        let meta = db_tx.metadata();
        let indexes_bucket = meta.create_bucket_if_not_exists(INDEX_TIPS_BUCKET_NAME)?;

        // Nothing to do if the index tip already exists.
        let idx_key = indexer.key();
        if indexes_bucket.get(idx_key).is_some() {
            return Ok(());
        }

        // Store the index version.
        db_put_indexer_version(&db_tx, idx_key, indexer.version())?;

        // The tip for the index does not exist, so create it and
        // invoke the create callback for the index so it can perform
        // any one-time initialization it requires.
        indexer.create(&db_tx)?;

        // Set the tip for the index to values which represent an
        // uninitialized index (the genesis block hash and height).
        db_put_indexer_tip(&db_tx, idx_key, genesis_hash, 0)
    })();
    match res {
        Ok(()) => {
            db_tx.commit()?;
            Ok(())
        }
        Err(err) => {
            let _ = db_tx.rollback();
            Err(err)
        }
    }
}

/// Determine if the provided index needs to be upgraded and drop and
/// recreate it when it does (dcrd `upgradeIndex`).
pub(crate) fn upgrade_index(
    interrupt: &Interrupt,
    indexer: &dyn Indexer,
    genesis_hash: &Hash,
    log: Option<&LogSink>,
) -> Result<(), IdxError> {
    finish_drop(interrupt, indexer, log)?;
    create_index(indexer, genesis_hash)
}

/// Update subscribers that the index is synced when its tip is
/// identical to the chain tip (dcrd `maybeNotifySubscribers`).  The
/// caller passes the chain tip (dcrd's `indexer.Queryer().Best()`),
/// read before it took the indexer's lock: the queryer locks the chain,
/// and the index lock must not be held while that waits.
pub(crate) fn maybe_notify_subscribers(
    interrupt: &Interrupt,
    indexer: &mut dyn Indexer,
    (best_height, best_hash): (i64, Hash),
) -> Result<(), IdxError> {
    if interrupt_requested(interrupt) {
        return Err(indexer_error(ErrorKind::InterruptRequested, INTERRUPT_MSG));
    }

    let (tip_height, tip_hash) = indexer.tip().map_err(|err| {
        IdxError::Other(format!(
            "{}: unable to fetch index tip: {err}",
            indexer.name()
        ))
    })?;

    if tip_height == best_height && best_hash == tip_hash {
        indexer.notify_sync_subscribers();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcroxide_database::Options;

    /// The batched walk empties a bucket whose keys straddle a flush.
    ///
    /// This calls [`incremental_flat_drop`] directly rather than
    /// `drop_addr_index`, because that wrapper follows the walk with
    /// `drop_index_metadata`, whose `delete_bucket` removes the bucket
    /// unconditionally — an end-to-end assertion that the bucket is gone
    /// passes even when the walk does nothing at all.
    ///
    /// The cap is small so the walk takes many rounds, which is the
    /// point: a window that under-fills while keys remain ends the loop
    /// early (`num_deleted < max_deletions`), exactly as dcrd's does.
    ///
    /// What this covers is the walk finishing the bucket. It does *not*
    /// pin the window's store/overlay bound: the drop's own commits
    /// flush as it proceeds, so overlay-only keys become store-resident
    /// before a wrong bound can strand them. That bound is pinned where
    /// it can be held still, in `dcroxide-database`'s
    /// `cursor_window.rs`.
    #[test]
    fn the_batched_walk_empties_a_bucket_that_straddles_a_flush() {
        const KEYS: u32 = 200;
        let dir = tempfile::tempdir().expect("tempdir");
        let opts = Options::new(dir.path().join("db"), 0x12141c16);
        let db = Database::create(&opts).expect("create");
        let idx_key: &[u8] = b"flatidx";

        let tx = db.begin(true).expect("begin");
        {
            let bucket = tx.metadata().create_bucket(idx_key).expect("create bucket");
            for i in 0..KEYS / 2 {
                bucket.put(&i.to_be_bytes(), b"v").expect("put");
            }
        }
        tx.commit().expect("commit");
        db.flush().expect("flush the first half to the store");

        let tx = db.begin(true).expect("begin");
        {
            let bucket = tx.metadata().bucket(idx_key).expect("bucket");
            for i in KEYS / 2..KEYS {
                bucket.put(&i.to_be_bytes(), b"v").expect("put");
            }
        }
        tx.commit().expect("commit");

        let interrupt: Interrupt = Arc::new(core::sync::atomic::AtomicBool::new(false));
        incremental_flat_drop(&interrupt, &db, idx_key, "flat index", 7, None)
            .expect("incremental drop");

        // The bucket itself is untouched by the walk; what must be gone
        // is every key in it.
        let tx = db.begin(false).expect("begin");
        let left = {
            let bucket = tx.metadata().bucket(idx_key).expect("bucket still exists");
            let mut cursor = bucket.cursor();
            let mut n = 0usize;
            let mut ok = cursor.first();
            while ok {
                n += 1;
                ok = cursor.next();
            }
            n
        };
        tx.rollback().expect("rollback");
        assert_eq!(left, 0, "{left} of {KEYS} keys survived the batched walk");
    }

    /// Each batch that deleted anything logs its count and the running
    /// total, and the final empty batch that ends a walk over an exact
    /// multiple of the cap logs nothing (dcrd's `numDeleted > 0` guard).
    #[test]
    fn each_batch_logs_its_count_and_the_running_total() {
        let dir = tempfile::tempdir().expect("tempdir");
        let opts = Options::new(dir.path().join("db"), 0x12141c16);
        let db = Database::create(&opts).expect("create");
        let idx_key: &[u8] = b"flatidx";

        let tx = db.begin(true).expect("begin");
        {
            let bucket = tx.metadata().create_bucket(idx_key).expect("create bucket");
            for i in 0u32..21 {
                bucket.put(&i.to_be_bytes(), b"v").expect("put");
            }
        }
        tx.commit().expect("commit");

        let lines = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink_lines = Arc::clone(&lines);
        let sink: LogSink = Arc::new(move |level, msg: &str| {
            sink_lines
                .lock()
                .expect("lines")
                .push((level, msg.to_string()));
        });
        let interrupt: Interrupt = Arc::new(core::sync::atomic::AtomicBool::new(false));
        incremental_flat_drop(&interrupt, &db, idx_key, "flat index", 7, Some(&sink))
            .expect("incremental drop");

        let want: Vec<(LogLevel, String)> =
            ["7 keys (7 total)", "7 keys (14 total)", "7 keys (21 total)"]
                .iter()
                .map(|counts| (LogLevel::Info, format!("Deleted {counts} from flat index")))
                .collect();
        assert_eq!(*lines.lock().expect("lines"), want);
    }
}
