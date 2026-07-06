// SPDX-License-Identifier: ISC
//! Removal of the legacy indexes (dcrd indexers `dropaddrindex.go`
//! and `dropcfindex.go`): dcrd no longer maintains the address index
//! or the version 1 committed filter index, but it still cleans up
//! their leftovers from old databases.

use dcroxide_database::Database;

use crate::common::{Interrupt, drop_index_metadata, exists_index, incremental_flat_drop};
use crate::error::IdxError;

/// The key of the legacy address index and the db bucket used to
/// house it (dcrd `addrIndexKey`).
pub const ADDR_INDEX_KEY: &[u8] = b"txbyaddridx";

/// The name of the parent bucket that housed the legacy committed
/// filter index (dcrd `cfIndexParentBucketKey`).
pub const CF_INDEX_PARENT_BUCKET_KEY: &[u8] = b"cfindexparentbucket";

/// Drop the legacy address index from the provided database if it
/// exists (dcrd `DropAddrIndex`).
pub fn drop_addr_index(interrupt: &Interrupt, db: &Database) -> Result<(), IdxError> {
    // Nothing to do if the index doesn't already exist.
    if !exists_index(db, ADDR_INDEX_KEY)? {
        return Ok(());
    }

    // Since the indexes can be so large, use a cursor to delete a
    // maximum number of entries out of the bucket at a time.
    incremental_flat_drop(interrupt, db, ADDR_INDEX_KEY)?;

    // Remove the index tip, version, bucket, and in-progress drop
    // flag now that all index entries have been removed.
    drop_index_metadata(db, ADDR_INDEX_KEY)
}

/// Drop the legacy version 1 committed filter index from the
/// provided database if it exists (dcrd `DropCfIndex`).
pub fn drop_cf_index(db: &Database) -> Result<(), IdxError> {
    // Nothing to do if the index doesn't already exist.
    if !exists_index(db, CF_INDEX_PARENT_BUCKET_KEY)? {
        return Ok(());
    }

    // Remove the index tip, version, bucket, and in-progress drop
    // flag.
    drop_index_metadata(db, CF_INDEX_PARENT_BUCKET_KEY)
}
