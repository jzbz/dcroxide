// SPDX-License-Identifier: ISC
//! The UTXO stats walk decodes its keys with the port of dcrd's
//! `decodeOutpointKey`, the decoder dcrd's vectors pin, so a corrupt key
//! fails with dcrd's text.
//!
//! dcrd's `levelDbUtxoBackend.FetchStats` wraps the decoder's error as
//! `corrupt outpoint for key %x: %v` (`utxobackend.go:539-542`).  The
//! walk used to run a second decoder of its own, whose messages ("short
//! utxo key", "bad utxo key index") were not dcrd's (review finding
//! B8-p#3).

use dcroxide_blockchain::chaindb::{ChainDbError, UTXO_SET_BUCKET_NAME};
use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};
use tempfile::TempDir;

const NET: u32 = 0x12141c16; // simnet magic

/// The stats walk's error over a UTXO bucket holding only `key`.
fn stats_error_for_key(key: &[u8]) -> String {
    let dir = TempDir::new().expect("tempdir");
    let db = Database::create(&Options::new(dir.path().join("db"), NET)).expect("create");
    db.update(|tx| {
        let bucket = tx.metadata().create_bucket(UTXO_SET_BUCKET_NAME)?;
        bucket.put(key, &[1, 2, 3])
    })
    .expect("fill");
    match Chain::utxo_stats_from_backend(&db) {
        Err(ChainDbError::Corrupt(desc)) => desc,
        other => panic!("expected a corrupt outpoint error, got {other:?}"),
    }
}

fn key_hex(key: &[u8]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn a_corrupt_utxo_key_fails_the_stats_with_dcrds_text() {
    // The prefix and hash with nothing after them: dcrd's length check
    // (`utxoio.go:111-113`).
    let mut key = vec![3u8, 3];
    key.extend_from_slice(&[0xab; 32]);
    assert_eq!(
        stats_error_for_key(&key),
        format!(
            "corrupt outpoint for key {}: unexpected length for serialized outpoint key",
            key_hex(&key)
        )
    );

    // A tree with no index after it (`utxoio.go:124-128`).
    key.push(0);
    assert_eq!(
        stats_error_for_key(&key),
        format!(
            "corrupt outpoint for key {}: unexpected end of data after tree",
            key_hex(&key)
        )
    );

    // A tree whose VLQ runs to the end of the key: the same error, where
    // the walk's own decoder had said "bad utxo key index".
    let mut key = vec![3u8, 3];
    key.extend_from_slice(&[0xab; 32]);
    key.extend_from_slice(&[0x80, 0x80]);
    assert_eq!(
        stats_error_for_key(&key),
        format!(
            "corrupt outpoint for key {}: unexpected end of data after tree",
            key_hex(&key)
        )
    );
}
