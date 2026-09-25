// SPDX-License-Identifier: ISC
//! Removal of the legacy indexes (dcrd indexers `dropaddrindex.go`
//! and `dropcfindex.go`): dcrd no longer maintains the address index
//! or the version 1 committed filter index, but it still cleans up
//! their leftovers from old databases.

use dcroxide_database::Database;

use crate::common::{
    Interrupt, MAX_DELETIONS_PER_BATCH, drop_index_metadata, exists_index, incremental_flat_drop,
};
use crate::error::IdxError;
use crate::log::{LogLevel, LogSink, log_line};

/// The human-readable name for the legacy address index (dcrd
/// `addrIndexName`).
const ADDR_INDEX_NAME: &str = "address index";

/// The key of the legacy address index and the db bucket used to
/// house it (dcrd `addrIndexKey`).
pub const ADDR_INDEX_KEY: &[u8] = b"txbyaddridx";

/// The human-readable name for the legacy committed filter index (dcrd
/// `cfIndexName`).
const CF_INDEX_NAME: &str = "committed filter index";

/// The name of the parent bucket that housed the legacy committed
/// filter index (dcrd `cfIndexParentBucketKey`).
pub const CF_INDEX_PARENT_BUCKET_KEY: &[u8] = b"cfindexparentbucket";

/// Drop the legacy address index from the provided database if it
/// exists (dcrd `DropAddrIndex`), logging its progress to `log` as dcrd
/// logs it to the package logger (see [`LogSink`]).  A database
/// without the index logs nothing, as in dcrd.
pub fn drop_addr_index(
    interrupt: &Interrupt,
    db: &Database,
    log: Option<&LogSink>,
) -> Result<(), IdxError> {
    // Nothing to do if the index doesn't already exist.
    if !exists_index(db, ADDR_INDEX_KEY)? {
        return Ok(());
    }

    log_line(
        log,
        LogLevel::Info,
        &format!("Dropping all legacy {ADDR_INDEX_NAME} entries.  This might take a while..."),
    );

    // Since the indexes can be so large, use a cursor to delete a
    // maximum number of entries out of the bucket at a time.
    incremental_flat_drop(
        interrupt,
        db,
        ADDR_INDEX_KEY,
        ADDR_INDEX_NAME,
        MAX_DELETIONS_PER_BATCH,
        log,
    )?;

    // Remove the index tip, version, bucket, and in-progress drop
    // flag now that all index entries have been removed.
    drop_index_metadata(db, ADDR_INDEX_KEY)?;

    log_line(log, LogLevel::Info, &format!("Dropped {ADDR_INDEX_NAME}"));
    Ok(())
}

/// Drop the legacy version 1 committed filter index from the
/// provided database if it exists (dcrd `DropCfIndex`), logging its
/// progress to `log` as dcrd logs it to the package logger (see
/// [`LogSink`]).  A database without the index logs nothing, as in
/// dcrd.
pub fn drop_cf_index(db: &Database, log: Option<&LogSink>) -> Result<(), IdxError> {
    // Nothing to do if the index doesn't already exist.
    if !exists_index(db, CF_INDEX_PARENT_BUCKET_KEY)? {
        return Ok(());
    }

    log_line(
        log,
        LogLevel::Info,
        &format!("Dropping all legacy {CF_INDEX_NAME} entries.  This might take a while..."),
    );

    // Remove the index tip, version, bucket, and in-progress drop
    // flag.
    drop_index_metadata(db, CF_INDEX_PARENT_BUCKET_KEY)?;

    log_line(log, LogLevel::Info, &format!("Dropped {CF_INDEX_NAME}"));
    Ok(())
}
