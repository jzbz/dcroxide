// SPDX-License-Identifier: ISC
//! The transaction-by-hash index (dcrd indexers `txindex.go`): every
//! transaction in the main chain keyed by hash, with an internal
//! block ID compaction layer mapping each indexed block to a
//! sequential 4-byte ID.

use std::rc::Rc;

use dcroxide_chainhash::{HASH_SIZE, Hash};
use dcroxide_database::{BlockRegion, Database, Transaction};
use dcroxide_wire::{MsgBlock, var_int_serialize_size};

use crate::common::{
    ChainQueryer, INTERRUPT_MSG, Indexer, Interrupt, SyncWaiter, create_index, db_put_indexer_tip,
    drop_index_metadata, exists_index, finish_drop, incremental_flat_drop, interrupt_requested,
    make_db_err, mark_index_deletion, notify_sync_subscribers, tip, upgrade_index,
};
use crate::error::{ErrorKind, IdxError, indexer_error};
use crate::subscriber::{
    CONNECT_NTFN, DISCONNECT_NTFN, IndexNtfn, IndexSubscriber, IndexerHandle, NO_PREREQS,
    block_height,
};

/// The human-readable name for the index (dcrd `txIndexName`).
pub const TX_INDEX_NAME: &str = "transaction index";

/// The current version of the transaction index (dcrd
/// `txIndexVersion`).
const TX_INDEX_VERSION: u32 = 2;

/// The size of a transaction entry: 4 bytes block id + 4 bytes offset
/// + 4 bytes length + 4 bytes block index (dcrd `txEntrySize`).
const TX_ENTRY_SIZE: usize = 4 + 4 + 4 + 4;

/// The key of the transaction index and the db bucket used to house
/// it (dcrd `txIndexKey`).
pub const TX_INDEX_KEY: &[u8] = b"txbyhashidx";

/// The name of the db bucket used to house the block id -> block
/// hash index (dcrd `idByHashIndexBucketName`).
pub const ID_BY_HASH_INDEX_BUCKET_NAME: &[u8] = b"idbyhashidx";

/// The name of the db bucket used to house the block hash -> block
/// id index (dcrd `hashByIDIndexBucketName`).
pub const HASH_BY_ID_INDEX_BUCKET_NAME: &[u8] = b"hashbyididx";

/// Information about an entry in the transaction index (dcrd
/// `TxIndexEntry`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIndexEntry {
    /// The location of the raw bytes of the transaction.
    pub block_region: BlockRegion,
    /// The index of the transaction within the array of transactions
    /// that comprise a tree of the block.
    pub block_index: u32,
}

/// The start offset and serialized length of a transaction within
/// its block (dcrd `wire.TxLoc`).
pub(crate) type TxLoc = (u32, u32);

/// The offset and length of each transaction within the serialized
/// block, for the regular and stake trees (dcrd
/// `dcrutil.Block.TxLoc`, which derives them from
/// `wire.MsgBlock.DeserializeTxLoc`).
pub(crate) fn tx_loc(block: &MsgBlock) -> (Vec<TxLoc>, Vec<TxLoc>) {
    let mut pos = 180usize.saturating_add(var_int_serialize_size(block.transactions.len() as u64));
    let mut tx_locs = Vec::with_capacity(block.transactions.len());
    for tx in &block.transactions {
        let len = tx.serialize_size();
        tx_locs.push((pos as u32, len as u32));
        pos = pos.saturating_add(len);
    }
    pos = pos.saturating_add(var_int_serialize_size(block.stransactions.len() as u64));
    let mut stx_locs = Vec::with_capacity(block.stransactions.len());
    for tx in &block.stransactions {
        let len = tx.serialize_size();
        stx_locs.push((pos as u32, len as u32));
        pos = pos.saturating_add(len);
    }
    (tx_locs, stx_locs)
}

/// Update or add the hash-to-id and id-to-hash mappings for the
/// provided values (dcrd `dbPutBlockIDIndexEntry`).
fn db_put_block_id_index_entry(db_tx: &Transaction, hash: &Hash, id: u32) -> Result<(), IdxError> {
    let serialized_id = id.to_le_bytes();

    // Add the block hash to ID mapping to the index.
    let meta = db_tx.metadata();
    let hash_index = meta
        .bucket(ID_BY_HASH_INDEX_BUCKET_NAME)
        .ok_or_else(|| bucket_missing(ID_BY_HASH_INDEX_BUCKET_NAME))?;
    hash_index.put(&hash.0, &serialized_id)?;

    // Add the block ID to hash mapping to the index.
    let id_index = meta
        .bucket(HASH_BY_ID_INDEX_BUCKET_NAME)
        .ok_or_else(|| bucket_missing(HASH_BY_ID_INDEX_BUCKET_NAME))?;
    id_index.put(&serialized_id, &hash.0)?;
    Ok(())
}

/// Remove the hash-to-id and id-to-hash mappings for the provided
/// hash (dcrd `dbRemoveBlockIDIndexEntry`).
fn db_remove_block_id_index_entry(db_tx: &Transaction, hash: &Hash) -> Result<(), IdxError> {
    // Remove the block hash to ID mapping.
    let meta = db_tx.metadata();
    let hash_index = meta
        .bucket(ID_BY_HASH_INDEX_BUCKET_NAME)
        .ok_or_else(|| bucket_missing(ID_BY_HASH_INDEX_BUCKET_NAME))?;
    let Some(serialized_id) = hash_index.get(&hash.0) else {
        return Ok(());
    };
    hash_index.delete(&hash.0)?;

    // Remove the block ID to hash mapping.
    let id_index = meta
        .bucket(HASH_BY_ID_INDEX_BUCKET_NAME)
        .ok_or_else(|| bucket_missing(HASH_BY_ID_INDEX_BUCKET_NAME))?;
    id_index.delete(&serialized_id)?;
    Ok(())
}

/// Retrieve the hash for the provided serialized block id (dcrd
/// `dbFetchBlockHashBySerializedID`); a missing entry surfaces dcrd's
/// `errNoBlockIDEntry` message.
fn db_fetch_block_hash_by_serialized_id(
    db_tx: &Transaction,
    serialized_id: &[u8],
) -> Result<Hash, IdxError> {
    let meta = db_tx.metadata();
    let id_index = meta
        .bucket(HASH_BY_ID_INDEX_BUCKET_NAME)
        .ok_or_else(|| bucket_missing(HASH_BY_ID_INDEX_BUCKET_NAME))?;
    let hash_bytes = id_index
        .get(serialized_id)
        .ok_or_else(|| IdxError::Other("no entry in the block ID index".into()))?;

    let mut hash = Hash::ZERO;
    hash.0.copy_from_slice(&hash_bytes[..HASH_SIZE]);
    Ok(hash)
}

/// Retrieve the hash for the provided block id (dcrd
/// `dbFetchBlockHashByID`).
fn db_fetch_block_hash_by_id(db_tx: &Transaction, id: u32) -> Result<Hash, IdxError> {
    db_fetch_block_hash_by_serialized_id(db_tx, &id.to_le_bytes())
}

/// Serialize a transaction index entry (dcrd `putTxIndexEntry`).
fn put_tx_index_entry(target: &mut [u8], block_id: u32, tx_loc: TxLoc, block_index: u32) {
    target[0..4].copy_from_slice(&block_id.to_le_bytes());
    target[4..8].copy_from_slice(&tx_loc.0.to_le_bytes());
    target[8..12].copy_from_slice(&tx_loc.1.to_le_bytes());
    target[12..16].copy_from_slice(&block_index.to_le_bytes());
}

/// Store a serialized transaction index entry (dcrd
/// `dbPutTxIndexEntry`).
fn db_put_tx_index_entry(
    db_tx: &Transaction,
    tx_hash: &Hash,
    serialized_data: &[u8],
) -> Result<(), IdxError> {
    let meta = db_tx.metadata();
    let tx_index = meta
        .bucket(TX_INDEX_KEY)
        .ok_or_else(|| bucket_missing(TX_INDEX_KEY))?;
    tx_index.put(&tx_hash.0, serialized_data)?;
    Ok(())
}

/// Fetch the block region for the provided transaction hash (dcrd
/// `dbFetchTxIndexEntry`).  When there is no entry for the provided
/// hash, `None` is returned.
fn db_fetch_tx_index_entry(
    db_tx: &Transaction,
    tx_hash: &Hash,
) -> Result<Option<TxIndexEntry>, IdxError> {
    // Load the record from the database and return now if it doesn't
    // exist.
    let meta = db_tx.metadata();
    let tx_index = meta
        .bucket(TX_INDEX_KEY)
        .ok_or_else(|| bucket_missing(TX_INDEX_KEY))?;
    let Some(serialized_data) = tx_index.get(&tx_hash.0) else {
        return Ok(None);
    };
    if serialized_data.is_empty() {
        return Ok(None);
    }

    // Ensure the serialized data has enough bytes to properly
    // deserialize.
    if serialized_data.len() < TX_ENTRY_SIZE {
        return Err(make_db_err(
            dcroxide_database::ErrorKind::Corruption,
            format!("corrupt transaction index entry for {tx_hash}"),
        ));
    }

    // Load the block hash associated with the block ID.
    let hash =
        db_fetch_block_hash_by_serialized_id(db_tx, &serialized_data[0..4]).map_err(|err| {
            make_db_err(
                dcroxide_database::ErrorKind::Corruption,
                format!("corrupt transaction index entry for {tx_hash}: {err}"),
            )
        })?;

    // Deserialize the final entry.
    let mut offset_bytes = [0u8; 4];
    offset_bytes.copy_from_slice(&serialized_data[4..8]);
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&serialized_data[8..12]);
    let mut index_bytes = [0u8; 4];
    index_bytes.copy_from_slice(&serialized_data[12..16]);
    Ok(Some(TxIndexEntry {
        block_region: BlockRegion {
            hash,
            offset: u32::from_le_bytes(offset_bytes),
            len: u32::from_le_bytes(len_bytes),
        },
        block_index: u32::from_le_bytes(index_bytes),
    }))
}

/// Add a transaction index entry for every transaction in both trees
/// of the passed block (dcrd `dbAddTxIndexEntries`).
fn db_add_tx_index_entries(
    db_tx: &Transaction,
    block: &MsgBlock,
    block_id: u32,
) -> Result<(), IdxError> {
    // The offset and length of the transactions within the
    // serialized block.
    let (tx_locs, stake_tx_locs) = tx_loc(block);

    let add_entries =
        |txns: &[dcroxide_wire::MsgTx], tx_locs: &[(u32, u32)]| -> Result<(), IdxError> {
            let mut serialized = [0u8; TX_ENTRY_SIZE];
            for (i, tx) in txns.iter().enumerate() {
                put_tx_index_entry(&mut serialized, block_id, tx_locs[i], i as u32);
                db_put_tx_index_entry(db_tx, &tx.tx_hash(), &serialized)?;
            }
            Ok(())
        };

    // Add the regular tree transactions.
    add_entries(&block.transactions, &tx_locs)?;

    // Add the stake tree transactions.
    add_entries(&block.stransactions, &stake_tx_locs)
}

/// Remove the most recent transaction index entry for the given hash
/// (dcrd `dbRemoveTxIndexEntry`).
fn db_remove_tx_index_entry(db_tx: &Transaction, tx_hash: &Hash) -> Result<(), IdxError> {
    let meta = db_tx.metadata();
    let tx_index = meta
        .bucket(TX_INDEX_KEY)
        .ok_or_else(|| bucket_missing(TX_INDEX_KEY))?;
    if tx_index.get(&tx_hash.0).is_none() {
        return Err(IdxError::Other(format!(
            "can't remove non-existent transaction {tx_hash} from the transaction index"
        )));
    }
    tx_index.delete(&tx_hash.0)?;
    Ok(())
}

/// Remove the latest transaction entry for every transaction in both
/// trees of the passed block (dcrd `dbRemoveTxIndexEntries`).
fn db_remove_tx_index_entries(db_tx: &Transaction, block: &MsgBlock) -> Result<(), IdxError> {
    for tx in &block.transactions {
        db_remove_tx_index_entry(db_tx, &tx.tx_hash())?;
    }
    for tx in &block.stransactions {
        db_remove_tx_index_entry(db_tx, &tx.tx_hash())?;
    }
    Ok(())
}

/// A missing-bucket error with dcrd's bucket-not-found shape.
fn bucket_missing(name: &[u8]) -> IdxError {
    make_db_err(
        dcroxide_database::ErrorKind::BucketNotFound,
        format!("{} bucket not found", String::from_utf8_lossy(name)),
    )
}

/// The transaction by hash index (dcrd `TxIndex`).
pub struct TxIndex {
    cur_block_id: u32,
    db: Rc<Database>,
    chain: Rc<dyn ChainQueryer>,
    subscribers: Vec<SyncWaiter>,
}

impl TxIndex {
    /// Create the transaction index, subscribe it for updates, and
    /// initialize it, finding the highest used block ID (dcrd
    /// `NewTxIndex` + `TxIndex.Init`).
    pub fn new(
        subscriber: &mut IndexSubscriber,
        db: Rc<Database>,
        chain: Rc<dyn ChainQueryer>,
    ) -> Result<Rc<core::cell::RefCell<TxIndex>>, IdxError> {
        let idx = Rc::new(core::cell::RefCell::new(TxIndex {
            cur_block_id: 0,
            db,
            chain,
            subscribers: Vec::new(),
        }));

        // The transaction index is an optional index.  It has no
        // prerequisite and is updated asynchronously.
        subscriber
            .subscribe(TX_INDEX_NAME, idx.clone() as IndexerHandle, NO_PREREQS)
            .map_err(IdxError::Other)?;

        // Init.
        let interrupt = subscriber.interrupt();
        if interrupt_requested(&interrupt) {
            return Err(indexer_error(ErrorKind::InterruptRequested, INTERRUPT_MSG));
        }
        {
            let genesis_hash = {
                let borrowed = idx.borrow();
                let params = borrowed.chain.chain_params();
                params.genesis_hash
            };
            let borrowed = idx.borrow();
            // Finish any drops that were previously interrupted.
            finish_drop(&interrupt, &*borrowed)?;
            // Create the initial state for the index as needed.
            create_index(&*borrowed, &genesis_hash)?;
            // Upgrade the index as needed.
            upgrade_index(&interrupt, &*borrowed, &genesis_hash)?;
        }

        // Recover the tx index and its dependents to the main chain
        // if needed.
        subscriber.recover_index(TX_INDEX_NAME)?;

        // Find the latest known block id for the internal block id
        // index and initialize it.
        let cur_block_id = {
            let borrowed = idx.borrow();
            let db_tx = borrowed.db.begin(false)?;
            // Scan forward in large gaps to find a block id that
            // doesn't exist yet to serve as an upper bound for the
            // binary search below.
            let mut highest_known = 0u32;
            let mut next_unknown;
            let mut test_block_id = 1u32;
            const INCREMENT: u32 = 100_000;
            loop {
                if db_fetch_block_hash_by_id(&db_tx, test_block_id).is_err() {
                    next_unknown = test_block_id;
                    break;
                }
                highest_known = test_block_id;
                test_block_id = test_block_id.saturating_add(INCREMENT);
            }

            let found = if next_unknown == 1 {
                // No used block IDs due to new database.
                0
            } else {
                // Use a binary search to find the final highest used
                // block id.
                loop {
                    test_block_id = highest_known.midpoint(next_unknown);
                    if db_fetch_block_hash_by_id(&db_tx, test_block_id).is_err() {
                        next_unknown = test_block_id;
                    } else {
                        highest_known = test_block_id;
                    }
                    if highest_known.saturating_add(1) == next_unknown {
                        break;
                    }
                }
                highest_known
            };
            db_tx.rollback()?;
            found
        };
        idx.borrow_mut().cur_block_id = cur_block_id;

        Ok(idx)
    }

    /// Add a hash-to-transaction mapping for every transaction in the
    /// passed block (dcrd `TxIndex.connectBlock`).
    fn connect_block(&mut self, db_tx: &Transaction, block: &MsgBlock) -> Result<(), IdxError> {
        // NOTE: The fact that the block can disapprove the regular
        // tree of the previous block is ignored for this index
        // because even though the disapproved transactions no longer
        // apply spend semantics, they still exist within the block
        // and thus have to be processed before the next block
        // disapproves them.

        // Increment the internal block ID to use for the block being
        // connected and add all of the transactions in the block to
        // the index.
        let new_block_id = self.cur_block_id.saturating_add(1);
        db_add_tx_index_entries(db_tx, block, new_block_id)?;

        // Add the new block ID index entry for the block being
        // connected and update the current internal block ID
        // accordingly.
        let block_hash = block.header.block_hash();
        db_put_block_id_index_entry(db_tx, &block_hash, new_block_id)?;
        self.cur_block_id = new_block_id;

        // Update the current index tip.
        db_put_indexer_tip(db_tx, TX_INDEX_KEY, &block_hash, block_height(block) as i32)
    }

    /// Remove the hash-to-transaction mapping for every transaction
    /// in the passed block (dcrd `TxIndex.disconnectBlock`).
    fn disconnect_block(&mut self, db_tx: &Transaction, block: &MsgBlock) -> Result<(), IdxError> {
        // Remove all of the transactions in the block from the index.
        db_remove_tx_index_entries(db_tx, block)?;

        // Remove the block ID index entry for the block being
        // disconnected and decrement the current internal block ID to
        // account for it.
        db_remove_block_id_index_entry(db_tx, &block.header.block_hash())?;
        self.cur_block_id = self.cur_block_id.saturating_sub(1);

        // Update the current index tip.
        db_put_indexer_tip(
            db_tx,
            TX_INDEX_KEY,
            &block.header.prev_block,
            (block_height(block).saturating_sub(1)) as i32,
        )
    }

    /// Details for the provided transaction hash from the transaction
    /// index (dcrd `TxIndex.Entry`).  When there is no entry for the
    /// provided hash, `None` is returned.
    pub fn entry(&self, hash: &Hash) -> Result<Option<TxIndexEntry>, IdxError> {
        let db_tx = self.db.begin(false)?;
        let res = db_fetch_tx_index_entry(&db_tx, hash);
        db_tx.rollback()?;
        res
    }
}

impl Indexer for TxIndex {
    fn key(&self) -> &'static [u8] {
        TX_INDEX_KEY
    }

    fn name(&self) -> &'static str {
        TX_INDEX_NAME
    }

    fn version(&self) -> u32 {
        TX_INDEX_VERSION
    }

    fn db(&self) -> Rc<Database> {
        self.db.clone()
    }

    fn queryer(&self) -> Rc<dyn ChainQueryer> {
        self.chain.clone()
    }

    fn tip(&self) -> Result<(i64, Hash), IdxError> {
        tip(&self.db, TX_INDEX_KEY)
    }

    fn create(&self, db_tx: &Transaction) -> Result<(), IdxError> {
        let meta = db_tx.metadata();
        meta.create_bucket(ID_BY_HASH_INDEX_BUCKET_NAME)?;
        meta.create_bucket(HASH_BY_ID_INDEX_BUCKET_NAME)?;
        meta.create_bucket(TX_INDEX_KEY)?;
        Ok(())
    }

    fn process_notification(
        &mut self,
        db_tx: &Transaction,
        ntfn: &IndexNtfn,
    ) -> Result<(), IdxError> {
        match ntfn.ntfn_type {
            CONNECT_NTFN => self.connect_block(db_tx, &ntfn.block).map_err(|err| {
                indexer_error(
                    ErrorKind::ConnectBlock,
                    format!("{}: unable to connect block: {err}", self.name()),
                )
            }),
            DISCONNECT_NTFN => self.disconnect_block(db_tx, &ntfn.block).map_err(|err| {
                indexer_error(
                    ErrorKind::DisconnectBlock,
                    format!("{}: unable to disconnect block: {err}", self.name()),
                )
            }),
            other => Err(indexer_error(
                ErrorKind::InvalidNotificationType,
                format!(
                    "{}: unknown notification type received: {}",
                    self.name(),
                    other.0
                ),
            )),
        }
    }

    fn wait_for_sync(&mut self) -> SyncWaiter {
        let waiter: SyncWaiter = Rc::new(core::cell::Cell::new(false));
        self.subscribers.push(waiter.clone());
        waiter
    }

    fn notify_sync_subscribers(&mut self) {
        notify_sync_subscribers(&mut self.subscribers);
    }

    fn drop_index(&self, interrupt: &Interrupt, db: &Database) -> Result<(), IdxError> {
        drop_tx_index(interrupt, db)
    }
}

/// Drop the internal block id index (dcrd `dropBlockIDIndex`).
fn drop_block_id_index(db: &Database) -> Result<(), IdxError> {
    let db_tx = db.begin(true)?;
    let res: Result<(), dcroxide_database::Error> = (|| {
        let meta = db_tx.metadata();
        meta.delete_bucket(ID_BY_HASH_INDEX_BUCKET_NAME)?;
        meta.delete_bucket(HASH_BY_ID_INDEX_BUCKET_NAME)?;
        Ok(())
    })();
    match res {
        Ok(()) => {
            db_tx.commit()?;
            Ok(())
        }
        Err(err) => {
            let _ = db_tx.rollback();
            Err(IdxError::Db(err))
        }
    }
}

/// Drop the transaction index from the provided database if it
/// exists (dcrd `DropTxIndex`).
pub fn drop_tx_index(interrupt: &Interrupt, db: &Database) -> Result<(), IdxError> {
    // Nothing to do if the index doesn't already exist.
    if !exists_index(db, TX_INDEX_KEY)? {
        return Ok(());
    }

    // Mark that the index is in the process of being dropped so that
    // it can be resumed on the next start if interrupted before the
    // process is complete.
    mark_index_deletion(db, TX_INDEX_KEY)?;

    incremental_flat_drop(interrupt, db, TX_INDEX_KEY)?;

    // Call extra index specific deinitialization for the transaction
    // index.
    drop_block_id_index(db)?;

    // Remove the index tip, version, bucket, and in-progress drop
    // flag now that all index entries have been removed.
    drop_index_metadata(db, TX_INDEX_KEY)
}
