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

    /// Remove the index from the database (dcrd `IndexDropper`).
    fn drop_index(&self, interrupt: &Interrupt, db: &Database) -> Result<(), IdxError>;
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

/// Remove key/value pairs from a flat index over multiple database
/// updates (dcrd `incrementalFlatDrop`).
pub(crate) fn incremental_flat_drop(
    interrupt: &Interrupt,
    db: &Database,
    idx_key: &[u8],
) -> Result<(), IdxError> {
    const MAX_DELETIONS: u64 = 2_000_000;
    let mut num_deleted = MAX_DELETIONS;
    while num_deleted == MAX_DELETIONS {
        num_deleted = 0;
        let db_tx = db.begin(true)?;
        let res: Result<(), dcroxide_database::Error> = (|| {
            let meta = db_tx.metadata();
            let Some(bucket) = meta.bucket(idx_key) else {
                return Ok(());
            };
            let mut cursor = bucket.cursor();
            let mut ok = cursor.first();
            while ok {
                cursor.delete()?;
                num_deleted = num_deleted.saturating_add(1);
                ok = cursor.next() && num_deleted < MAX_DELETIONS;
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
) -> Result<(), IdxError> {
    // Nothing to do if the index doesn't already exist.
    if !exists_index(db, idx_key)? {
        return Ok(());
    }

    // Mark that the index is in the process of being dropped so that
    // it can be resumed on the next start if interrupted before the
    // process is complete.
    mark_index_deletion(db, idx_key)?;

    incremental_flat_drop(interrupt, db, idx_key)?;

    drop_index_metadata(db, idx_key)
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
pub(crate) fn finish_drop(interrupt: &Interrupt, indexer: &dyn Indexer) -> Result<(), IdxError> {
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

    indexer.drop_index(interrupt, &db)
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
) -> Result<(), IdxError> {
    finish_drop(interrupt, indexer)?;
    create_index(indexer, genesis_hash)
}

/// Update subscribers that the index is synced when its tip is
/// identical to the chain tip (dcrd `maybeNotifySubscribers`).
pub(crate) fn maybe_notify_subscribers(
    interrupt: &Interrupt,
    indexer: &mut dyn Indexer,
) -> Result<(), IdxError> {
    if interrupt_requested(interrupt) {
        return Err(indexer_error(ErrorKind::InterruptRequested, INTERRUPT_MSG));
    }

    let (best_height, best_hash) = indexer.queryer().best();
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
