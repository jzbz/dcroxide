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
//!
//! The port's database version is one past dcrd's, for its height-first
//! per-block keys (`chaindb::CURRENT_DATABASE_VERSION`, ADR-0010), and
//! it refuses an older version too, where dcrd would upgrade: the only
//! older one a dcroxide ever wrote holds its rows under keys this build
//! does not look them up by.  The two refusals are the two directions:
//! this build refuses a version-14 directory, and a build from before
//! the re-keying refuses a version-15 one through the newer-version check
//! it already has, which the first test below drives with this build's
//! constant.

use dcroxide_blockchain::chaindb::{
    CURRENT_BLOCK_INDEX_VERSION, CURRENT_DATABASE_VERSION, ChainDbError, DatabaseInfo,
    db_fetch_database_info, db_put_database_info, older_version_refusal,
};
use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::regnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Bucket, Database, Options};

/// Create a chain database, rewrite its version row with `bump`, and
/// return the error the next open fails with.
fn reopen_error(bump: impl Fn(&mut DatabaseInfo)) -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    bump_info(dir.path(), bump);
    refused_open(dir.path()).to_string()
}

/// Create a chain database in `dir` and rewrite its version row with
/// `bump`.
fn bump_info(dir: &std::path::Path, bump: impl Fn(&mut DatabaseInfo)) {
    let params = regnet_params();
    let opts = Options::new(dir.join("chain"), params.net.0);
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
}

/// The error opening the chain database in `dir` fails with.
fn refused_open(dir: &std::path::Path) -> ChainDbError {
    let params = regnet_params();
    let opts = Options::new(dir.join("chain"), params.net.0);
    match Chain::open(
        Database::open(&opts).expect("open database"),
        &params,
        Hash::ZERO,
        false,
        0,
    ) {
        Ok(_) => panic!("a database at another version than the binary's must not open"),
        Err(err) => err,
    }
}

/// One row: the path of nested buckets it sits in, its key and value.
type Row = (Vec<Vec<u8>>, Vec<u8>, Vec<u8>);

/// Every row of `bucket` and of the buckets nested in it, in walk order.
fn bucket_rows(bucket: &Bucket<'_>, path: &[Vec<u8>], out: &mut Vec<Row>) {
    bucket
        .for_each(|key, value| {
            out.push((path.to_vec(), key.to_vec(), value.to_vec()));
            Ok(())
        })
        .expect("walk the bucket");
    let mut names = Vec::new();
    bucket
        .for_each_bucket(|name| {
            names.push(name.to_vec());
            Ok(())
        })
        .expect("walk the nested buckets");
    for name in names {
        let nested = bucket.bucket(&name).expect("a nested bucket");
        let mut nested_path = path.to_vec();
        nested_path.push(name);
        bucket_rows(&nested, &nested_path, out);
    }
}

/// Every row of `dir`'s chain database, nested buckets included.
fn stored_rows(dir: &std::path::Path) -> Vec<Row> {
    let params = regnet_params();
    let db = Database::open(&Options::new(dir.join("chain"), params.net.0)).expect("open");
    let mut rows = Vec::new();
    db.view(|tx| {
        bucket_rows(&tx.metadata(), &[], &mut rows);
        Ok(())
    })
    .expect("read the rows");
    db.close().expect("close");
    rows
}

/// dcrd's downgrade refusal, and also how a build from before the
/// re-keying, at version 14, refuses a directory this one wrote.
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

/// A fresh database is written at the current version, one past dcrd's
/// 14 for the height-first per-block keys, and opens again.
#[test]
fn a_fresh_database_is_the_current_version_and_reopens() {
    assert_eq!(
        CURRENT_DATABASE_VERSION, 15,
        "dcrd's 14, plus the re-keying"
    );
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
    let mut version = 0;
    db.view(|tx| {
        version = db_fetch_database_info(tx)
            .expect("read info")
            .expect("info row")
            .version;
        Ok(())
    })
    .expect("read the version");
    assert_eq!(version, CURRENT_DATABASE_VERSION);
    db.close().expect("close");
    drop(chain);

    Chain::open(
        Database::open(&opts).expect("open database"),
        &params,
        Hash::ZERO,
        false,
        0,
    )
    .expect("a database at the current version opens");
}

/// A database at dcrd's version 14 -- what a dcroxide from before the
/// re-keying wrote -- or any older one is refused with the one remedy
/// there is, where dcrd would upgrade it in place, and the refusal
/// changes no row: every row of the database, the version row among
/// them, is as it was before.
#[test]
fn an_older_database_version_is_refused_with_the_remedy() {
    for older in [CURRENT_DATABASE_VERSION - 1, 1] {
        let dir = tempfile::tempdir().expect("tempdir");
        bump_info(dir.path(), |info| info.version = older);
        let before = stored_rows(dir.path());
        let nested: std::collections::BTreeSet<&[Vec<u8>]> =
            before.iter().map(|(path, ..)| path.as_slice()).collect();
        assert!(
            nested.len() > 5,
            "the walk reaches the nested buckets: {nested:?}"
        );
        let err = refused_open(dir.path());
        assert!(
            matches!(err, ChainDbError::OlderVersion(v) if v == older),
            "{err:?}"
        );
        assert_eq!(err.to_string(), older_version_refusal(older, None));
        assert_eq!(
            err.to_string(),
            format!(
                "the blockchain database is version {older}, which an older dcroxide wrote, \
                 and this version of the software reads only version \
                 {CURRENT_DATABASE_VERSION} -- there is no in-place upgrade, and the chain is \
                 not damaged: delete the block database directory and start again to build a \
                 new one from genesis (see docs/operating.md)"
            )
        );
        assert_eq!(
            stored_rows(dir.path()),
            before,
            "the refusal changed no row"
        );
    }
}
