// SPDX-License-Identifier: ISC

//! The chain database rows over the dcroxide database: dcrd's
//! `chainio.go` bucket layout for the database info, deployment
//! version, best chain state, block index, spend journal, GCS
//! filters, and header commitments, plus the UTXO set rows.  dcrd
//! houses the UTXO set in a separate database with its own backend;
//! dcroxide colocates it in a dedicated bucket of the one database
//! using the same pinned row formats (a fresh-sync schema decision).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use dcroxide_chainhash::Hash;
use dcroxide_database::Transaction;
use dcroxide_gcs::FilterV2;
use dcroxide_uint256::Uint256;
use dcroxide_wire::OutPoint;

use crate::chainio::{
    BestChainState, BlockIndexEntry, block_index_key, decode_block_index_entry,
    deserialize_best_chain_state, deserialize_header_commitments, serialize_best_chain_state,
    serialize_block_index_entry, serialize_header_commitments,
};
use crate::utxoentry::UtxoEntry;
use crate::utxoio::{
    UtxoSetState, deserialize_utxo_entry, deserialize_utxo_set_state, outpoint_key,
    serialize_utxo_entry, serialize_utxo_set_state,
};

/// The current chain database version (dcrd
/// `currentDatabaseVersion`).
pub const CURRENT_DATABASE_VERSION: u32 = 14;
/// The current block index version (dcrd
/// `currentBlockIndexVersion`).
pub const CURRENT_BLOCK_INDEX_VERSION: u32 = 3;
/// The current spend journal version (dcrd
/// `currentSpendJournalVersion`).
pub const CURRENT_SPEND_JOURNAL_VERSION: u32 = 3;

/// The database info bucket (dcrd `bcdbInfoBucketName`).
pub const BCDB_INFO_BUCKET_NAME: &[u8] = b"dbinfo";
/// The database version key.
pub const BCDB_INFO_VERSION_KEY_NAME: &[u8] = b"version";
/// The compression version key.
pub const BCDB_INFO_COMPRESSION_VER_KEY_NAME: &[u8] = b"compver";
/// The block index version key.
pub const BCDB_INFO_BLOCK_INDEX_VER_KEY_NAME: &[u8] = b"bidxver";
/// The creation date key.
pub const BCDB_INFO_CREATED_KEY_NAME: &[u8] = b"created";
/// The spend journal version key.
pub const BCDB_INFO_SPEND_JOURNAL_VER_KEY_NAME: &[u8] = b"stxover";
/// The best chain state key (dcrd `chainStateKeyName`).
pub const CHAIN_STATE_KEY_NAME: &[u8] = b"chainstate";
/// The deployment version key (dcrd `deploymentVerKeyName`).
pub const DEPLOYMENT_VER_KEY_NAME: &[u8] = b"deploymentver";
/// The spend journal bucket (dcrd `spendJournalBucketName`).
pub const SPEND_JOURNAL_BUCKET_NAME: &[u8] = b"spendjournalv3";
/// The block index bucket (dcrd `blockIndexBucketName`).
pub const BLOCK_INDEX_BUCKET_NAME: &[u8] = b"blockidxv3";
/// The version 2 GCS filter bucket (dcrd `gcsFilterBucketName`).
pub const GCS_FILTER_BUCKET_NAME: &[u8] = b"gcsfilters";
/// The header commitments bucket (dcrd `headerCmtsBucketName`).
pub const HEADER_CMTS_BUCKET_NAME: &[u8] = b"hdrcmts";
/// The treasury account bucket (dcrd `treasuryBucketName`).
pub const TREASURY_BUCKET_NAME: &[u8] = b"treasury";
/// The treasury spend bucket (dcrd `treasuryTSpendBucketName`).
pub const TREASURY_TSPEND_BUCKET_NAME: &[u8] = b"tspend";
/// The UTXO set bucket (dcroxide's colocated stand-in for dcrd's
/// separate UTXO database).
pub const UTXO_SET_BUCKET_NAME: &[u8] = b"utxosetv3";
/// The UTXO set state key (dcrd `utxoSetStateKeyName`).
pub const UTXO_SET_STATE_KEY_NAME: &[u8] = b"utxosetstate";

/// The chain database persistence errors.
#[derive(Debug)]
pub enum ChainDbError {
    /// An underlying database error.
    Db(dcroxide_database::Error),
    /// A serialization error.
    Serial(crate::Error),
    /// A corruption or consistency failure.
    Corrupt(String),
}

impl From<dcroxide_database::Error> for ChainDbError {
    fn from(err: dcroxide_database::Error) -> ChainDbError {
        ChainDbError::Db(err)
    }
}

impl From<crate::Error> for ChainDbError {
    fn from(err: crate::Error) -> ChainDbError {
        ChainDbError::Serial(err)
    }
}

/// The chain database version information (dcrd `databaseInfo`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatabaseInfo {
    /// The overall database version.
    pub version: u32,
    /// The script compression version.
    pub comp_ver: u32,
    /// The block index version.
    pub bidx_ver: u32,
    /// The creation time as unix seconds.
    pub created_unix: u64,
    /// The spend journal version.
    pub stxo_ver: u32,
}

/// Store the database version information (dcrd
/// `dbPutDatabaseInfo`).
pub fn db_put_database_info(tx: &Transaction, dbi: &DatabaseInfo) -> Result<(), ChainDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(BCDB_INFO_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing database info bucket".into()))?;
    bucket.put(BCDB_INFO_VERSION_KEY_NAME, &dbi.version.to_le_bytes())?;
    bucket.put(
        BCDB_INFO_COMPRESSION_VER_KEY_NAME,
        &dbi.comp_ver.to_le_bytes(),
    )?;
    bucket.put(
        BCDB_INFO_BLOCK_INDEX_VER_KEY_NAME,
        &dbi.bidx_ver.to_le_bytes(),
    )?;
    bucket.put(BCDB_INFO_CREATED_KEY_NAME, &dbi.created_unix.to_le_bytes())?;
    bucket.put(
        BCDB_INFO_SPEND_JOURNAL_VER_KEY_NAME,
        &dbi.stxo_ver.to_le_bytes(),
    )?;
    Ok(())
}

/// Fetch the database version information, or `None` when the bucket
/// or version key does not exist (dcrd `dbFetchDatabaseInfo`).
pub fn db_fetch_database_info(tx: &Transaction) -> Result<Option<DatabaseInfo>, ChainDbError> {
    let meta = tx.metadata();
    let Some(bucket) = meta.bucket(BCDB_INFO_BUCKET_NAME) else {
        return Ok(None);
    };
    let u32_of = |v: Option<Vec<u8>>| -> u32 {
        v.filter(|b| b.len() == 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .unwrap_or(0)
    };
    let Some(version) = bucket.get(BCDB_INFO_VERSION_KEY_NAME) else {
        return Ok(None);
    };
    let version = u32_of(Some(version));
    let comp_ver = u32_of(bucket.get(BCDB_INFO_COMPRESSION_VER_KEY_NAME));
    let bidx_ver = u32_of(bucket.get(BCDB_INFO_BLOCK_INDEX_VER_KEY_NAME));
    let stxo_ver = u32_of(bucket.get(BCDB_INFO_SPEND_JOURNAL_VER_KEY_NAME));
    let created_unix = bucket
        .get(BCDB_INFO_CREATED_KEY_NAME)
        .filter(|b| b.len() == 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
        .unwrap_or(0);
    Ok(Some(DatabaseInfo {
        version,
        comp_ver,
        bidx_ver,
        created_unix,
        stxo_ver,
    }))
}

/// Store the deployment version (dcrd `dbPutDeploymentVer`).
pub fn db_put_deployment_ver(tx: &Transaction, version: u32) -> Result<(), ChainDbError> {
    Ok(tx
        .metadata()
        .put(DEPLOYMENT_VER_KEY_NAME, &version.to_le_bytes())?)
}

/// Fetch the deployment version, zero when unset (dcrd
/// `dbFetchDeploymentVer`).
pub fn db_fetch_deployment_ver(tx: &Transaction) -> u32 {
    tx.metadata()
        .get(DEPLOYMENT_VER_KEY_NAME)
        .filter(|b| b.len() == 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .unwrap_or(0)
}

/// Store the best chain state row (dcrd `dbPutBestState`).
pub fn db_put_best_state(
    tx: &Transaction,
    hash: Hash,
    height: u32,
    total_txns: u64,
    total_subsidy: i64,
    work_sum: Uint256,
) -> Result<(), ChainDbError> {
    let state = BestChainState {
        hash,
        height,
        total_txns,
        total_subsidy,
        work_sum,
    };
    Ok(tx
        .metadata()
        .put(CHAIN_STATE_KEY_NAME, &serialize_best_chain_state(&state))?)
}

/// Fetch the best chain state row (dcrd `dbFetchBestState`).
pub fn db_fetch_best_state(tx: &Transaction) -> Result<BestChainState, ChainDbError> {
    let v = tx
        .metadata()
        .get(CHAIN_STATE_KEY_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing chain state".into()))?;
    Ok(deserialize_best_chain_state(&v)?)
}

/// Store a block index row (dcrd `dbPutBlockNode`).
pub fn db_put_block_index_entry(
    tx: &Transaction,
    block_hash: &Hash,
    block_height: u32,
    entry: &BlockIndexEntry,
) -> Result<(), ChainDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(BLOCK_INDEX_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing block index bucket".into()))?;
    Ok(bucket.put(
        &block_index_key(block_hash, block_height),
        &serialize_block_index_entry(entry),
    )?)
}

/// Load every block index entry in height order (the iteration dcrd
/// `loadBlockIndex` performs; the key sorts by big-endian height).
pub fn db_load_block_index(tx: &Transaction) -> Result<Vec<BlockIndexEntry>, ChainDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(BLOCK_INDEX_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing block index bucket".into()))?;
    let mut rows: Vec<Vec<u8>> = Vec::new();
    bucket.for_each(|_k, v| {
        rows.push(v.to_vec());
        Ok(())
    })?;
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        let (entry, _) = decode_block_index_entry(&row)?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Store the serialized spend journal entry for a block (dcrd
/// `dbPutSpendJournalEntry`).
pub fn db_put_spend_journal_entry(
    tx: &Transaction,
    block_hash: &Hash,
    serialized: &[u8],
) -> Result<(), ChainDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(SPEND_JOURNAL_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing spend journal bucket".into()))?;
    Ok(bucket.put(&block_hash.0, serialized)?)
}

/// Remove the spend journal entry for a block (dcrd
/// `dbRemoveSpendJournalEntry`).
pub fn db_remove_spend_journal_entry(
    tx: &Transaction,
    block_hash: &Hash,
) -> Result<(), ChainDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(SPEND_JOURNAL_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing spend journal bucket".into()))?;
    Ok(bucket.delete(&block_hash.0)?)
}

/// Store the version 2 GCS filter for a block (dcrd
/// `dbPutGCSFilter`; the row is the raw filter bytes).
pub fn db_put_gcs_filter(
    tx: &Transaction,
    block_hash: &Hash,
    filter: &FilterV2,
) -> Result<(), ChainDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(GCS_FILTER_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing gcs filter bucket".into()))?;
    Ok(bucket.put(&block_hash.0, filter.bytes())?)
}

/// Fetch the version 2 GCS filter for a block, `None` when absent
/// (dcrd `dbFetchGCSFilter`).
pub fn db_fetch_gcs_filter(
    tx: &Transaction,
    block_hash: &Hash,
) -> Result<Option<FilterV2>, ChainDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(GCS_FILTER_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing gcs filter bucket".into()))?;
    let Some(serialized) = bucket.get(&block_hash.0) else {
        return Ok(None);
    };
    let filter = FilterV2::from_bytes(
        dcroxide_gcs::blockcf2::B,
        dcroxide_gcs::blockcf2::M,
        &serialized,
    )
    .map_err(|e| ChainDbError::Corrupt(format!("bad gcs filter: {e:?}")))?;
    Ok(Some(filter))
}

/// Store the header commitment leaves for a block; nothing is
/// written when there are none (dcrd `dbPutHeaderCommitments`).
pub fn db_put_header_commitments(
    tx: &Transaction,
    block_hash: &Hash,
    commitments: &[Hash],
) -> Result<(), ChainDbError> {
    if commitments.is_empty() {
        return Ok(());
    }
    let meta = tx.metadata();
    let bucket = meta
        .bucket(HEADER_CMTS_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing header commitments bucket".into()))?;
    Ok(bucket.put(&block_hash.0, &serialize_header_commitments(commitments))?)
}

/// Fetch the header commitment leaves for a block (dcrd
/// `dbFetchHeaderCommitments`).
pub fn db_fetch_header_commitments(
    tx: &Transaction,
    block_hash: &Hash,
) -> Result<Vec<Hash>, ChainDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(HEADER_CMTS_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing header commitments bucket".into()))?;
    match bucket.get(&block_hash.0) {
        None => Ok(Vec::new()),
        Some(v) => Ok(deserialize_header_commitments(&v)?),
    }
}

/// Store or remove a UTXO set row: spent entries delete the row and
/// unspent entries write the pinned serialization.
pub fn db_put_utxo(
    tx: &Transaction,
    outpoint: &OutPoint,
    entry: Option<&UtxoEntry>,
) -> Result<(), ChainDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(UTXO_SET_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing utxo set bucket".into()))?;
    let key = outpoint_key(outpoint);
    match entry {
        None => {
            bucket.delete(&key)?;
        }
        Some(entry) => {
            let serialized = serialize_utxo_entry(entry)
                .ok_or_else(|| ChainDbError::Corrupt("serializing a spent utxo entry".into()))?;
            bucket.put(&key, &serialized)?;
        }
    }
    Ok(())
}

/// Fetch one UTXO set row by outpoint (dcrd
/// `levelDbUtxoBackend.dbFetchUtxoEntry`): a missing row returns
/// `None`, an empty row is an entry for a spent output — which should
/// never exist — and both it and an undecodable row are corruption.
pub fn db_fetch_utxo_entry(
    tx: &Transaction,
    outpoint: &OutPoint,
) -> Result<Option<UtxoEntry>, ChainDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(UTXO_SET_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing utxo set bucket".into()))?;
    let key = outpoint_key(outpoint);
    let Some(serialized) = bucket.get(&key) else {
        return Ok(None);
    };
    if serialized.is_empty() {
        return Err(ChainDbError::Corrupt(format!(
            "database contains entry for spent tx output {}:{}",
            outpoint.hash, outpoint.index
        )));
    }
    Ok(Some(deserialize_utxo_entry(&serialized, outpoint.index)?))
}

/// Store the UTXO set state row.
pub fn db_put_utxo_set_state(tx: &Transaction, state: &UtxoSetState) -> Result<(), ChainDbError> {
    Ok(tx
        .metadata()
        .put(UTXO_SET_STATE_KEY_NAME, &serialize_utxo_set_state(state))?)
}

/// Fetch the UTXO set state row when present.
pub fn db_fetch_utxo_set_state(tx: &Transaction) -> Result<Option<UtxoSetState>, ChainDbError> {
    match tx.metadata().get(UTXO_SET_STATE_KEY_NAME) {
        None => Ok(None),
        Some(v) => Ok(Some(deserialize_utxo_set_state(&v)?)),
    }
}

/// Decode an outpoint row key produced by `outpoint_key`.
pub(crate) fn decode_outpoint_key(key: &[u8]) -> Result<OutPoint, ChainDbError> {
    // The key layout is the [3, 3] prefix, the hash, the VLQ tree,
    // and the VLQ index.
    if key.len() < 2 + 32 + 2 {
        return Err(ChainDbError::Corrupt("short utxo key".into()));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&key[2..34]);
    let (tree, read) = crate::compress::deserialize_vlq(&key[34..]);
    if read == 0 {
        return Err(ChainDbError::Corrupt("bad utxo key tree".into()));
    }
    let (index, read2) = crate::compress::deserialize_vlq(&key[34 + read..]);
    if read2 == 0 {
        return Err(ChainDbError::Corrupt("bad utxo key index".into()));
    }
    Ok(OutPoint {
        hash: Hash(hash),
        index: index as u32,
        tree: tree as i8,
    })
}
