// SPDX-License-Identifier: ISC
//! Opening a chain database refuses every version newer than the
//! binary, as dcrd's `initChainState` does (review finding B7-c#3).
//!
//! dcrd rejects a newer database version, a newer compression version
//! and a newer block index version, each with its own message
//! (`chainio.go:1627-1650`).  The port checked only the first, so a
//! binary opening a directory whose block index or script compression
//! format had been bumped on its own would have decoded the rows in the
//! old format rather than refusing to start.

use dcroxide_blockchain::chaindb::{
    CURRENT_BLOCK_INDEX_VERSION, CURRENT_DATABASE_VERSION, DatabaseInfo, db_fetch_database_info,
    db_put_database_info,
};
use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::regnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};

/// Create a chain database, rewrite its version row with `bump`, and
/// return the error the next open fails with.
fn reopen_error(bump: impl Fn(&mut DatabaseInfo)) -> String {
    let params = regnet_params();
    let dir = tempfile::tempdir().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let chain = Chain::open(
        Database::create(&opts).expect("create database"),
        &params,
        Hash::ZERO,
        false,
        0,
    )
    .expect("create chain");
    let db = chain.db.as_ref().expect("db-backed");
    db.update(|tx| {
        let mut info = db_fetch_database_info(tx)
            .expect("read info")
            .expect("info row");
        bump(&mut info);
        db_put_database_info(tx, &info).map_err(|e| panic!("put info: {e:?}"))
    })
    .expect("rewrite the version row");
    db.close().expect("close");
    drop(chain);

    match Chain::open(
        Database::open(&opts).expect("open database"),
        &params,
        Hash::ZERO,
        false,
        0,
    ) {
        Ok(_) => panic!("a database newer than the binary must not open"),
        Err(err) => err.to_string(),
    }
}

#[test]
fn a_newer_database_version_is_refused() {
    let err = reopen_error(|info| info.version = CURRENT_DATABASE_VERSION + 1);
    assert_eq!(
        err,
        format!(
            "the current blockchain database is no longer compatible with this version of \
             the software ({} > {CURRENT_DATABASE_VERSION})",
            CURRENT_DATABASE_VERSION + 1
        )
    );
}

#[test]
fn a_newer_compression_version_is_refused() {
    let current = dcroxide_blockchain::CURRENT_COMPRESSION_VERSION;
    let err = reopen_error(|info| info.comp_ver = current + 1);
    assert_eq!(
        err,
        format!(
            "the current database compression version is no longer compatible with this \
             version of the software ({} > {current})",
            current + 1
        )
    );
}

#[test]
fn a_newer_block_index_version_is_refused() {
    let err = reopen_error(|info| info.bidx_ver = CURRENT_BLOCK_INDEX_VERSION + 1);
    assert_eq!(
        err,
        format!(
            "the current database block index version is no longer compatible with this \
             version of the software ({} > {CURRENT_BLOCK_INDEX_VERSION})",
            CURRENT_BLOCK_INDEX_VERSION + 1
        )
    );
}
