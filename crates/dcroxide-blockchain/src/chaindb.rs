// SPDX-License-Identifier: ISC

//! The chain database rows over the dcroxide database: dcrd's
//! `chainio.go` bucket layout for the database info, deployment
//! version, best chain state, block index, spend journal, GCS
//! filters, and header commitments, plus the UTXO set rows.  dcrd
//! houses the UTXO set in a separate database with its own backend;
//! dcroxide colocates it in a dedicated bucket of the one database
//! using the same pinned row formats (a fresh-sync schema decision).
//!
//! The rows are dcrd's, but four of the per-block buckets are keyed
//! differently.  dcrd keys the spend journal, GCS filter, header
//! commitment and treasury rows by block hash, and the port keys them by
//! big-endian height and then hash, as `blockidxv3` is keyed;
//! [`block_row_key`] is the one encoder of that key, here and in
//! `treasurydb`.  [`CURRENT_DATABASE_VERSION`] is one past dcrd's to
//! record it and the other height-first keys, and a database of any
//! other version is refused (ADR-0010).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

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

/// The current chain database version: dcrd's `currentDatabaseVersion`
/// (14, `chainio.go:29`) plus one, for dcroxide's height-first
/// per-block keys (ADR-0010).
///
/// dcrd keys seven per-block buckets by block hash or little-endian
/// height, and the port keys all seven by big-endian height first: the
/// spend journal, GCS filters, header commitments and treasury state
/// ([`block_row_key`]), the stake undo data and new tickets
/// (`dcroxide_stake::stakedb::height_key`), and the database's internal
/// block index (`dcroxide_database`'s block lookups).  Version 15 is
/// that layout over dcrd's version 14 rows, which are otherwise
/// unchanged.  All seven live in the one store this version describes,
/// and [`crate::process::Chain::open_with_config`] checks it before it
/// reads any of them.
///
/// A database of any other version is refused at open rather than
/// misread: a lookup under the other layout's key misses its row, or,
/// for a per-height stake row, can land on the row of the height whose
/// bytes are this one's reversed.  A newer one gets dcrd's downgrade
/// message.  An older one, version 14 from a dcroxide built before the
/// re-keying, gets [`ChainDbError::OlderVersion`], which tells the
/// operator to delete the block database and sync again: there is no
/// in-place upgrade (ADR-0004's fresh-sync stance).  Bumping this
/// number, rather than recording the layout in a row of its own, is
/// what makes a build from before the change refuse a database written
/// after it, through the downgrade check that build already has.  The
/// cost is the startup line "Blockchain database version info: chain:
/// 15, ...", where dcrd prints 14.
///
/// The number is the port's own from here on.  If dcrd ships a version
/// 15 of its own, port its change and take the next free number here
/// (16), keeping the refusal of every older version.
pub const CURRENT_DATABASE_VERSION: u32 = 15;
/// The current block index version (dcrd
/// `currentBlockIndexVersion`).
pub const CURRENT_BLOCK_INDEX_VERSION: u32 = 3;
/// The current spend journal version (dcrd
/// `currentSpendJournalVersion`).
pub const CURRENT_SPEND_JOURNAL_VERSION: u32 = 3;
/// The UTXO database version (dcrd `currentUtxoDatabaseVersion`,
/// `utxobackend.go:28`).
///
/// dcrd records it in the separate UTXO database's backend info and
/// logs it at startup.  The port keeps the UTXO set in the block
/// database with no backend info record of its own, so the chain open
/// logs this constant: the layout its UTXO rows are in, and the value a
/// fresh dcrd `utxodb` records.
pub const CURRENT_UTXO_DATABASE_VERSION: u32 = 3;

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
    /// A shutdown was requested through the chain's interrupt while a
    /// long-running startup step was under way (dcrd
    /// `errInterruptRequested`, `upgrade.go:34-36`).
    Interrupted,
    /// A consensus rule or context error raised while opening the
    /// chain, which dcrd's `New` returns unchanged: a deployment or
    /// historical agenda that `makeAgendas` refuses (`chain.go:2151`),
    /// or an agenda query failing in the startup state load
    /// (`chainio.go:1749-1752`).
    Rule(crate::RuleError),
    /// The database is at the given version, older than
    /// [`CURRENT_DATABASE_VERSION`]: an older dcroxide wrote it, under
    /// per-block keys this build does not look its rows up by.  dcrd
    /// upgrades an older database in place (`upgradeDB`,
    /// `chainio.go:1676`); the port refuses it, and its text says what
    /// to do (see [`older_version_refusal`]).
    OlderVersion(u32),
}

/// The refusal of a database an older dcroxide wrote
/// ([`ChainDbError::OlderVersion`]): the version found, the one this
/// build reads, that nothing is damaged, and what to do about it.
/// `db_dir` names the block database directory, quoted, when the caller
/// knows its path, as the daemon and addblock do; without it the text
/// says "the block database directory".
pub fn older_version_refusal(version: u32, db_dir: Option<&str>) -> String {
    let (found, remove) = match db_dir {
        Some(dir) => (format!(" in '{dir}'"), format!("'{dir}'")),
        None => (String::new(), String::from("the block database directory")),
    };
    format!(
        "the blockchain database{found} is version {version}, which an older dcroxide \
         wrote, and this version of the software reads only version \
         {CURRENT_DATABASE_VERSION} -- there is no in-place upgrade, and the chain is not \
         damaged: delete {remove} and start again to build a new one from genesis (see \
         docs/operating.md)"
    )
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

impl fmt::Display for ChainDbError {
    /// The analogue of Go's `%v` on the error `flushBlockIndex`
    /// returns: the underlying description, since dcrd's
    /// `database.Error` renders as its own description text.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainDbError::Db(e) => write!(f, "{e}"),
            ChainDbError::Serial(e) => write!(f, "{e}"),
            ChainDbError::Corrupt(s) => f.write_str(s),
            ChainDbError::Interrupted => f.write_str("interrupt requested"),
            ChainDbError::Rule(e) => write!(f, "{e}"),
            ChainDbError::OlderVersion(version) => {
                f.write_str(&older_version_refusal(*version, None))
            }
        }
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

/// Hand every block index entry to `fn_` in height order, decoding
/// each row as it is reached (the cursor walk dcrd `loadBlockIndex`
/// performs; the key sorts by big-endian height).  The first error,
/// from a row that fails to decode or from `fn_`, ends the walk.
///
/// The walk is [`dcroxide_database::Bucket::for_each`], which streams
/// the bucket a window at a time and takes each value from the scan
/// that found its key, as dcrd reads `cursor.Value()` from its
/// iterator: the index (about 1.1M mainnet rows) is never held whole,
/// and no row is looked up a second time.  Like dcrd's cursor walk,
/// which never asks the iterator for an error, a store read fault ends
/// the store's rows rather than failing the load.
pub fn db_load_block_index(
    tx: &Transaction,
    mut fn_: impl FnMut(BlockIndexEntry) -> Result<(), ChainDbError>,
) -> Result<(), ChainDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(BLOCK_INDEX_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing block index bucket".into()))?;
    // `for_each` stops at a database error, so the first chain error is
    // kept here and a stand-in database error ends the walk.
    let mut failed: Option<ChainDbError> = None;
    let walked = bucket.for_each(|_k, row| {
        let res = decode_block_index_entry(row)
            .map_err(ChainDbError::from)
            .and_then(|(entry, _)| fn_(entry));
        res.map_err(|e| {
            failed = Some(e);
            dcroxide_database::Error {
                kind: dcroxide_database::ErrorKind::DriverSpecific,
                description: String::from("block index load stopped"),
            }
        })
    });
    match failed {
        Some(e) => Err(e),
        None => Ok(walked?),
    }
}

/// The key of a block's row in the spend journal, GCS filter, header
/// commitment and treasury buckets: the block's height, big-endian, then
/// its hash -- the key [`block_index_key`] gives `blockidxv3`.
///
/// dcrd keys these rows by the hash alone (`chainio.go:767`, `:814`,
/// `:821`, `:851`, `:877`, `:885`, `:980`, `:997`; `treasury.go:235`,
/// `:244`), which scatters the blocks of one metadata flush across each
/// bucket: the store copies one cold leaf, and its branch path, per
/// block per bucket.  Keyed by height first, consecutive blocks share
/// leaves and a flush appends at each bucket's right edge.  The hash
/// keeps blocks at one height apart.  Every caller has the block's node
/// or the block itself, so the height is always at hand, and a lookup
/// under any other height finds nothing.  See
/// [`CURRENT_DATABASE_VERSION`].
pub fn block_row_key(block_hash: &Hash, block_height: u32) -> Vec<u8> {
    block_index_key(block_hash, block_height)
}

/// Store the serialized spend journal entry for a block (dcrd
/// `dbPutSpendJournalEntry`).
pub fn db_put_spend_journal_entry(
    tx: &Transaction,
    block_hash: &Hash,
    block_height: u32,
    serialized: &[u8],
) -> Result<(), ChainDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(SPEND_JOURNAL_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing spend journal bucket".into()))?;
    Ok(bucket.put(&block_row_key(block_hash, block_height), serialized)?)
}

/// Fetch the serialized spend journal entry for a block, `None` when
/// absent (the row read of dcrd `dbFetchSpendJournalEntry`, which
/// decodes it against the block's spending inputs; the chain does that
/// in `Chain::fetch_spend_journal`).
pub fn db_fetch_spend_journal_entry(
    tx: &Transaction,
    block_hash: &Hash,
    block_height: u32,
) -> Option<Vec<u8>> {
    tx.metadata()
        .bucket(SPEND_JOURNAL_BUCKET_NAME)?
        .get(&block_row_key(block_hash, block_height))
}

/// Remove the spend journal entry for a block (dcrd
/// `dbRemoveSpendJournalEntry`).
pub fn db_remove_spend_journal_entry(
    tx: &Transaction,
    block_hash: &Hash,
    block_height: u32,
) -> Result<(), ChainDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(SPEND_JOURNAL_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing spend journal bucket".into()))?;
    Ok(bucket.delete(&block_row_key(block_hash, block_height))?)
}

/// Store the version 2 GCS filter for a block (dcrd
/// `dbPutGCSFilter`; the row is the raw filter bytes).
pub fn db_put_gcs_filter(
    tx: &Transaction,
    block_hash: &Hash,
    block_height: u32,
    filter: &FilterV2,
) -> Result<(), ChainDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(GCS_FILTER_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing gcs filter bucket".into()))?;
    Ok(bucket.put(&block_row_key(block_hash, block_height), filter.bytes())?)
}

/// Fetch the version 2 GCS filter for a block, `None` when absent
/// (dcrd `dbFetchGCSFilter`).  A row that does not decode is dcrd's
/// `database.ErrCorruption` with its "corrupt filter" text.
pub fn db_fetch_gcs_filter(
    tx: &Transaction,
    block_hash: &Hash,
    block_height: u32,
) -> Result<Option<FilterV2>, ChainDbError> {
    let Some(serialized) = db_fetch_raw_gcs_filter(tx, block_hash, block_height)? else {
        return Ok(None);
    };
    let filter = FilterV2::from_bytes(
        dcroxide_gcs::blockcf2::B,
        dcroxide_gcs::blockcf2::M,
        &serialized,
    )
    .map_err(|e| ChainDbError::Corrupt(format!("corrupt filter for {block_hash}: {e}")))?;
    Ok(Some(filter))
}

/// Fetch the serialized version 2 GCS filter for a block without
/// decoding it, `None` when absent (dcrd `dbFetchRawGCSFilter`, which
/// `LocateCFiltersV2` serves peers from).
pub fn db_fetch_raw_gcs_filter(
    tx: &Transaction,
    block_hash: &Hash,
    block_height: u32,
) -> Result<Option<Vec<u8>>, ChainDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(GCS_FILTER_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing gcs filter bucket".into()))?;
    Ok(bucket.get(&block_row_key(block_hash, block_height)))
}

/// Store the header commitment leaves for a block; nothing is
/// written when there are none (dcrd `dbPutHeaderCommitments`).
pub fn db_put_header_commitments(
    tx: &Transaction,
    block_hash: &Hash,
    block_height: u32,
    commitments: &[Hash],
) -> Result<(), ChainDbError> {
    if commitments.is_empty() {
        return Ok(());
    }
    let meta = tx.metadata();
    let bucket = meta
        .bucket(HEADER_CMTS_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing header commitments bucket".into()))?;
    Ok(bucket.put(
        &block_row_key(block_hash, block_height),
        &serialize_header_commitments(commitments),
    )?)
}

/// Fetch the header commitment leaves for a block (dcrd
/// `dbFetchHeaderCommitments`).
pub fn db_fetch_header_commitments(
    tx: &Transaction,
    block_hash: &Hash,
    block_height: u32,
) -> Result<Vec<Hash>, ChainDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(HEADER_CMTS_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing header commitments bucket".into()))?;
    match bucket.get(&block_row_key(block_hash, block_height)) {
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
    db_put_utxos(tx, core::iter::once((*outpoint, entry)))
}

/// Store or remove a batch of UTXO set rows within one transaction,
/// with exactly [`db_put_utxo`]'s per-row semantics: `None` deletes
/// the row and an entry writes its serialization, which ignores the
/// entry's cache state bits.  The bucket resolves once for the whole
/// batch, as [`db_fetch_utxo_entries`] does on the read side, instead
/// of once per row -- a lookup that walks the transaction's growing
/// pending writes every time.  (dcrd's cache flush writes each row
/// straight into a leveldb batch, which has no bucket to resolve.)
pub fn db_put_utxos<'a>(
    tx: &Transaction,
    rows: impl IntoIterator<Item = (OutPoint, Option<&'a UtxoEntry>)>,
) -> Result<(), ChainDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(UTXO_SET_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing utxo set bucket".into()))?;
    for (outpoint, entry) in rows {
        let key = outpoint_key(&outpoint);
        match entry {
            None => {
                bucket.delete(&key)?;
            }
            Some(entry) => {
                let serialized = serialize_utxo_entry(entry).ok_or_else(|| {
                    ChainDbError::Corrupt("serializing a spent utxo entry".into())
                })?;
                bucket.put(&key, &serialized)?;
            }
        }
    }
    Ok(())
}

/// Fetch one UTXO set row by outpoint (dcrd
/// `levelDbUtxoBackend.dbFetchUtxoEntry`): a missing row returns
/// `None`, an empty row is an entry for a spent output — which should
/// never exist — and both it and an undecodable row are corruption.
/// A store read error is returned, not read as a missing row: the row
/// is read with `Bucket::try_get`, as dcrd's backend `Get` keeps
/// `ErrNotFound` apart from a real error.
pub fn db_fetch_utxo_entry(
    tx: &Transaction,
    outpoint: &OutPoint,
) -> Result<Option<UtxoEntry>, ChainDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(UTXO_SET_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing utxo set bucket".into()))?;
    let key = outpoint_key(outpoint);
    let Some(serialized) = bucket.try_get(&key)? else {
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

/// Fetch a batch of UTXO set rows by outpoint within one database
/// transaction, one result per outpoint in order; per-row semantics
/// are exactly [`db_fetch_utxo_entry`]'s and the bucket resolves once
/// for the whole batch.  (dcrd's `UtxoCache.FetchEntries` loop issues
/// per-outpoint leveldb gets, which need no per-read transaction; the
/// redb-backed store amortizes its read transaction here instead.)
pub fn db_fetch_utxo_entries(
    tx: &Transaction,
    outpoints: &[OutPoint],
) -> Result<Vec<Option<UtxoEntry>>, ChainDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(UTXO_SET_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing utxo set bucket".into()))?;
    let mut entries = Vec::with_capacity(outpoints.len());
    for outpoint in outpoints {
        let key = outpoint_key(outpoint);
        let Some(serialized) = bucket.try_get(&key)? else {
            entries.push(None);
            continue;
        };
        if serialized.is_empty() {
            return Err(ChainDbError::Corrupt(format!(
                "database contains entry for spent tx output {}:{}",
                outpoint.hash, outpoint.index
            )));
        }
        entries.push(Some(deserialize_utxo_entry(&serialized, outpoint.index)?));
    }
    Ok(entries)
}

/// Store the UTXO set state row.
pub fn db_put_utxo_set_state(tx: &Transaction, state: &UtxoSetState) -> Result<(), ChainDbError> {
    Ok(tx
        .metadata()
        .put(UTXO_SET_STATE_KEY_NAME, &serialize_utxo_set_state(state))?)
}

/// Fetch the UTXO set state row when present.
///
/// dcrd's `levelDbUtxoBackend.FetchState` folds a zero-length row into
/// "no state" alongside an absent one
/// (`internal/blockchain/utxobackend.go:517-522`).  That fold is
/// deliberately not matched: the empty row goes to
/// `deserialize_utxo_set_state`, which fails with "unexpected end of
/// data after height", and `Chain::open` returns the error instead of
/// starting.
///
/// An empty row is not a fresh backend, and answering "no state" for
/// one makes `initialize_utxo_state` record the state at the current
/// tip and return early (dcrd's `UtxoCache.Initialize`,
/// `utxocache.go:831-856`), skipping the disconnect/replay a set
/// lagging the chain needs — so the fold would turn a damaged marker
/// into a silently wrong UTXO set that every descendant inherits.  It
/// is a laxity local to `FetchState` rather than a storage limit: the
/// same `Get` returns `nil` only for `leveldb.ErrNotFound`
/// (`:392-402`), and `dbFetchUtxoEntry` treats a non-nil zero-length
/// row as an `AssertError` (`:472-477`) — the rule
/// [`db_fetch_utxo_entry`] above ports.  Neither implementation writes
/// a zero-length row (`serialize_utxo_set_state` is a VLQ height plus
/// a 32-byte hash, 33 bytes minimum), so only corruption or an
/// out-of-band writer produces one.
///
/// Read with `Bucket::try_get` for the same reason as
/// [`db_fetch_utxo_entry`]: dcrd's `FetchState` reads through the
/// backend `Get`, which propagates a read error.
pub fn db_fetch_utxo_set_state(tx: &Transaction) -> Result<Option<UtxoSetState>, ChainDbError> {
    match tx.metadata().try_get(UTXO_SET_STATE_KEY_NAME)? {
        None => Ok(None),
        Some(v) => Ok(Some(deserialize_utxo_set_state(&v)?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcroxide_database::{Database, Options};
    use dcroxide_wire::BlockHeader;

    /// simnet's network magic; the rows are not tied to it.
    const NET: u32 = 0x12141c16;

    /// A block index entry at `height` whose header links to `prev`;
    /// `nonce` tells apart two blocks at one height.
    fn entry(height: u32, prev: Hash, nonce: u32) -> BlockIndexEntry {
        BlockIndexEntry {
            header: BlockHeader {
                version: 1,
                prev_block: prev,
                merkle_root: Hash::ZERO,
                stake_root: Hash::ZERO,
                vote_bits: 1,
                final_state: [0; 6],
                voters: 0,
                fresh_stake: 0,
                revocations: 0,
                pool_size: 0,
                bits: 0x207f_ffff,
                sbits: 0,
                height,
                size: 0,
                timestamp: height,
                nonce,
                extra_data: [0; 32],
                stake_version: 0,
            },
            status: (height % 7) as u8,
            vote_info: vec![(height, height as u16)],
        }
    }

    /// Store a `heights`-block chain with a side block at every third
    /// height, returning the entries in the order their keys sort.
    fn put_rows(tx: &Transaction, heights: u32) -> Vec<BlockIndexEntry> {
        tx.metadata()
            .create_bucket(BLOCK_INDEX_BUCKET_NAME)
            .expect("create block index bucket");
        let mut rows = Vec::new();
        let mut prev = Hash::ZERO;
        for height in 0..heights {
            let main = entry(height, prev, 0);
            if height % 3 == 1 {
                rows.push(entry(height, prev, 1));
            }
            prev = main.header.block_hash();
            rows.push(main);
        }
        for row in &rows {
            let hash = row.header.block_hash();
            db_put_block_index_entry(tx, &hash, row.header.height, row).expect("put row");
        }
        rows.sort_by_key(|e| block_index_key(&e.header.block_hash(), e.header.height));
        rows
    }

    /// The entries the load hands out.
    fn load(tx: &Transaction) -> Vec<BlockIndexEntry> {
        let mut got = Vec::new();
        db_load_block_index(tx, |e| {
            got.push(e);
            Ok(())
        })
        .expect("load block index");
        got
    }

    /// The streaming load hands out every row once, in key order,
    /// whether the rows are this transaction's pending writes, the
    /// cache overlay, or the store, for an index small enough for one
    /// window of `Bucket::for_each` and one that crosses into a second
    /// (review findings B7-c#6 and RG03#1).
    #[test]
    fn block_index_load_streams_every_row() {
        for (heights, rows) in [(12u32, 16usize), (3_100, 4_133)] {
            let dir = tempfile::tempdir().expect("tempdir");
            let opts = Options::new(dir.path().join("db"), NET);
            let db = Database::create(&opts).expect("create database");
            let tx = db.begin(true).expect("begin");
            let want = put_rows(&tx, heights);
            assert_eq!(want.len(), rows);
            assert!(load(&tx) == want, "pending writes, {rows} rows");
            tx.commit().expect("commit");
            drop(tx);

            let tx = db.begin(false).expect("begin");
            assert!(load(&tx) == want, "cache overlay, {rows} rows");
            // Every transaction holds the handle open, so the lock goes
            // with the last of them.
            drop(tx);
            db.close().expect("close");
            drop(db);

            let db = Database::open(&opts).expect("reopen database");
            let tx = db.begin(false).expect("begin");
            assert!(load(&tx) == want, "store, {rows} rows");
        }
    }

    /// The first error from the callback ends the walk and comes back
    /// to the caller, rather than the database error that stops the
    /// bucket walk.
    #[test]
    fn block_index_load_stops_at_the_first_callback_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let opts = Options::new(dir.path().join("db"), NET);
        let db = Database::create(&opts).expect("create database");
        let tx = db.begin(true).expect("begin");
        put_rows(&tx, 12);
        let mut calls = 0;
        let res = db_load_block_index(&tx, |_| {
            calls += 1;
            if calls == 5 {
                return Err(ChainDbError::Corrupt("stop".into()));
            }
            Ok(())
        });
        assert!(matches!(res, Err(ChainDbError::Corrupt(ref s)) if s == "stop"));
        assert_eq!(calls, 5);
    }

    /// A row that fails to decode ends the load with the decode error,
    /// as dcrd's `loadBlockIndex` returns `deserializeBlockIndexEntry`'s.
    #[test]
    fn block_index_load_stops_at_a_row_that_does_not_decode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let opts = Options::new(dir.path().join("db"), NET);
        let db = Database::create(&opts).expect("create database");
        let tx = db.begin(true).expect("begin");
        let rows = put_rows(&tx, 12);
        // A short row sorting between the third and fourth entries.
        let third = &rows[2].header;
        let mut key = block_index_key(&third.block_hash(), third.height);
        key.push(0);
        tx.metadata()
            .bucket(BLOCK_INDEX_BUCKET_NAME)
            .expect("bucket")
            .put(&key, &[0; 10])
            .expect("put short row");
        let mut calls = 0;
        let res = db_load_block_index(&tx, |_| {
            calls += 1;
            Ok(())
        });
        assert!(
            matches!(res, Err(ChainDbError::Serial(ref e))
                if e.to_string() == "unexpected end of data while reading block header"),
            "{res:?}"
        );
        assert_eq!(calls, 3);
    }

    /// A per-block row's key is the block's height big-endian and then
    /// its hash, and it reads back into the same pair.
    #[test]
    fn block_row_key_is_the_big_endian_height_then_the_hash() {
        let hash = Hash(core::array::from_fn(|i| i as u8));
        for height in [0u32, 1, 255, 256, 0x0102_0304, u32::MAX] {
            let key = block_row_key(&hash, height);
            assert_eq!(key.len(), 36);
            assert_eq!(key[..4], height.to_be_bytes());
            assert_eq!(key[4..], hash.0);
            let read = u32::from_be_bytes(key[..4].try_into().expect("four bytes"));
            assert_eq!(
                (read, Hash(key[4..].try_into().expect("a hash"))),
                (height, hash)
            );
        }
    }

    /// Per-block row keys sort by height and then by hash, whatever
    /// order the hashes or the heights' little-endian bytes would give.
    #[test]
    fn block_row_keys_sort_by_height_then_hash() {
        let (low, high) = (Hash([0x00; 32]), Hash([0xff; 32]));
        let mut pairs = alloc::vec![
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
        by_key.sort_by_key(|(height, hash)| block_row_key(hash, *height));
        pairs.sort();
        assert_eq!(by_key, pairs);
    }

    /// The refusal of an older database names the versions, says the
    /// chain is not damaged and what to delete: the directory by its
    /// path when the caller knows it.
    #[test]
    fn the_older_version_refusal_says_what_to_delete() {
        let generic = ChainDbError::OlderVersion(14).to_string();
        assert_eq!(generic, older_version_refusal(14, None));
        assert_eq!(
            generic,
            format!(
                "the blockchain database is version 14, which an older dcroxide wrote, and \
                 this version of the software reads only version {CURRENT_DATABASE_VERSION} \
                 -- there is no in-place upgrade, and the chain is not damaged: delete the \
                 block database directory and start again to build a new one from genesis \
                 (see docs/operating.md)"
            )
        );
        assert_eq!(
            older_version_refusal(14, Some("/data/simnet/blocks_ffldb")),
            format!(
                "the blockchain database in '/data/simnet/blocks_ffldb' is version 14, which \
                 an older dcroxide wrote, and this version of the software reads only version \
                 {CURRENT_DATABASE_VERSION} -- there is no in-place upgrade, and the chain is \
                 not damaged: delete '/data/simnet/blocks_ffldb' and start again to build a \
                 new one from genesis (see docs/operating.md)"
            )
        );
    }
}
