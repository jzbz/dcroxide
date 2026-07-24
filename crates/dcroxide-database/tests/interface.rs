// SPDX-License-Identifier: ISC
//! The metadata/bucket/cursor/transaction semantics battery, ported
//! from dcrd's database/ffldb `interface_test.go` behaviors at the
//! pinned tag.  Every assertion here mirrors a behavior dcrd's own
//! interface tests enforce against ffldb, including the contract
//! quirks (empty-key `delete` silently succeeding, read-only `commit`
//! closing the transaction with `ErrTxNotWritable`, cursor exhaustion
//! semantics).

use dcroxide_database::{Database, Error, ErrorKind, Options};
use tempfile::TempDir;

const NET: u32 = 0x12141c16; // simnet magic

fn new_db() -> (TempDir, Database) {
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("db"), NET);
    let db = Database::create(&opts).expect("create");
    (dir, db)
}

fn kind_of(err: Error) -> ErrorKind {
    err.kind
}

#[test]
fn create_open_semantics() {
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("db"), NET);

    // Opening a missing database fails.
    assert_eq!(
        Database::open(&opts).err().map(kind_of),
        Some(ErrorKind::DbDoesNotExist)
    );

    // Create succeeds, re-create fails.
    let db = Database::create(&opts).expect("create");
    db.close().expect("close");
    drop(db);
    assert_eq!(
        Database::create(&opts).err().map(kind_of),
        Some(ErrorKind::DbExists)
    );

    // Open now succeeds.
    let db = Database::open(&opts).expect("open");
    assert_eq!(db.db_type(), "redb");

    // Close works once, then everything errors with ErrDbNotOpen.
    db.close().expect("close");
    assert_eq!(db.close().err().map(kind_of), Some(ErrorKind::DbNotOpen));
    assert_eq!(
        db.begin(false).err().map(kind_of),
        Some(ErrorKind::DbNotOpen)
    );
    assert_eq!(db.flush().err().map(kind_of), Some(ErrorKind::DbNotOpen));
    assert_eq!(
        db.view(|_| Ok(())).err().map(kind_of),
        Some(ErrorKind::DbNotOpen)
    );
}

#[test]
fn bucket_crud_and_quirks() {
    let (_dir, db) = new_db();

    db.update(|tx| {
        let meta = tx.metadata();
        assert!(meta.writable());

        // The internal block index bucket is visible under its ffldb
        // name.
        assert!(meta.bucket(b"ffldb-blockidx").is_some());

        // Create a bucket; creating it again fails; empty names fail.
        let b = meta.create_bucket(b"bucket1")?;
        assert!(b.writable());
        assert_eq!(
            meta.create_bucket(b"bucket1").err().map(kind_of),
            Some(ErrorKind::BucketExists)
        );
        assert_eq!(
            meta.create_bucket(b"").err().map(kind_of),
            Some(ErrorKind::BucketNameRequired)
        );
        meta.create_bucket_if_not_exists(b"bucket1")?;
        meta.create_bucket_if_not_exists(b"bucket2")?;

        // Put/get round trip, overwrite, empty values, missing keys.
        b.put(b"key1", b"value1")?;
        assert_eq!(b.get(b"key1"), Some(b"value1".to_vec()));
        b.put(b"key1", b"value1-mod")?;
        assert_eq!(b.get(b"key1"), Some(b"value1-mod".to_vec()));
        b.put(b"empty", b"")?;
        assert_eq!(b.get(b"empty"), Some(Vec::new()));
        assert_eq!(b.get(b"missing"), None);
        // Empty keys: get returns nothing, put errors.
        assert_eq!(b.get(b""), None);
        assert_eq!(
            b.put(b"", b"v").err().map(kind_of),
            Some(ErrorKind::KeyRequired)
        );
        // ffldb quirk: deleting an empty key silently succeeds despite
        // the interface contract naming ErrKeyRequired.
        assert_eq!(b.delete(b""), Ok(()));
        // Deleting a missing key succeeds.
        assert_eq!(b.delete(b"missing"), Ok(()));
        // Deleting an existing key removes it.
        b.delete(b"key1")?;
        assert_eq!(b.get(b"key1"), None);

        // Nested buckets.
        let nested = b.create_bucket(b"nested")?;
        nested.put(b"deep", b"value")?;
        assert_eq!(
            tx.metadata()
                .bucket(b"bucket1")
                .expect("bucket1")
                .bucket(b"nested")
                .expect("nested")
                .get(b"deep"),
            Some(b"value".to_vec())
        );
        // A bucket and a plain key may share a name (they live in
        // separate namespaces in the ffldb layout).
        b.put(b"nested", b"plain-value")?;
        assert_eq!(b.get(b"nested"), Some(b"plain-value".to_vec()));
        assert!(b.bucket(b"nested").is_some());

        // DeleteBucket removes the bucket, all its keys, and nested
        // buckets recursively.
        let sub = nested.create_bucket(b"sub")?;
        sub.put(b"subkey", b"subvalue")?;
        b.delete_bucket(b"nested")?;
        assert!(b.bucket(b"nested").is_none());
        assert_eq!(
            b.delete_bucket(b"nested").err().map(kind_of),
            Some(ErrorKind::BucketNotFound)
        );
        // The plain key with the same name survives.
        assert_eq!(b.get(b"nested"), Some(b"plain-value".to_vec()));
        Ok(())
    })
    .expect("update");

    // Read-only transactions reject mutations with ErrTxNotWritable.
    db.view(|tx| {
        let meta = tx.metadata();
        assert!(!meta.writable());
        let b = meta.bucket(b"bucket1").expect("bucket1");
        assert_eq!(
            b.put(b"k", b"v").err().map(kind_of),
            Some(ErrorKind::TxNotWritable)
        );
        assert_eq!(
            b.delete(b"empty").err().map(kind_of),
            Some(ErrorKind::TxNotWritable)
        );
        assert_eq!(
            meta.create_bucket(b"nope").err().map(kind_of),
            Some(ErrorKind::TxNotWritable)
        );
        assert_eq!(
            meta.create_bucket_if_not_exists(b"nope").err().map(kind_of),
            Some(ErrorKind::TxNotWritable)
        );
        assert_eq!(
            meta.delete_bucket(b"bucket1").err().map(kind_of),
            Some(ErrorKind::TxNotWritable)
        );
        Ok(())
    })
    .expect("view");
}

#[test]
fn for_each_and_cursor_ordering() {
    let (_dir, db) = new_db();

    db.update(|tx| {
        let meta = tx.metadata();
        let b = meta.create_bucket(b"iter")?;
        // Inserted out of order; iteration must be lexicographic.
        for (k, v) in [
            (b"cursor" as &[u8], b"val-cursor" as &[u8]),
            (b"abcd", b"val-abcd"),
            (b"bcd", b"val-bcd"),
            (b"defg", b"val-defg"),
        ] {
            b.put(k, v)?;
        }
        // Nested buckets, also out of order.
        b.create_bucket(b"zzz")?;
        b.create_bucket(b"aaa")?;

        // ForEach sees only key/value pairs, in order.
        let mut seen = Vec::new();
        b.for_each(|k, v| {
            seen.push((k.to_vec(), v.to_vec()));
            Ok(())
        })?;
        assert_eq!(
            seen.iter().map(|(k, _)| k.as_slice()).collect::<Vec<_>>(),
            vec![b"abcd" as &[u8], b"bcd", b"cursor", b"defg"]
        );
        assert_eq!(seen[0].1, b"val-abcd");

        // ForEachBucket sees only nested buckets, in order.
        let mut buckets = Vec::new();
        b.for_each_bucket(|k| {
            buckets.push(k.to_vec());
            Ok(())
        })?;
        assert_eq!(buckets, vec![b"aaa".to_vec(), b"zzz".to_vec()]);

        // A full cursor iterates key/value pairs first (bucket IDs sort
        // below the 'bidx' prefix), then nested buckets, with nil
        // values for the latter.
        let mut c = b.cursor();
        let mut forward = Vec::new();
        let mut ok = c.first();
        while ok {
            forward.push((c.key().expect("key"), c.value()));
            ok = c.next();
        }
        assert_eq!(
            forward
                .iter()
                .map(|(k, _)| k.as_slice())
                .collect::<Vec<_>>(),
            vec![b"abcd" as &[u8], b"bcd", b"cursor", b"defg", b"aaa", b"zzz"]
        );
        assert_eq!(forward[3].1, Some(b"val-defg".to_vec()));
        assert_eq!(forward[4].1, None); // nested bucket => nil value

        // Reverse iteration.
        let mut reverse = Vec::new();
        let mut ok = c.last();
        while ok {
            reverse.push(c.key().expect("key"));
            ok = c.prev();
        }
        let mut expected = forward.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>();
        expected.reverse();
        assert_eq!(reverse, expected);

        // Seek positions at the first entry >= the seek key.
        assert!(c.seek(b"bc"));
        assert_eq!(c.key(), Some(b"bcd".to_vec()));
        assert!(c.seek(b"cursor"));
        assert_eq!(c.key(), Some(b"cursor".to_vec()));
        // Seeking past every key lands on the first nested bucket
        // (exactly what ffldb's merged raw iterators do).
        assert!(c.seek(b"zzzz"));
        assert_eq!(c.key(), Some(b"aaa".to_vec()));

        // Exhaustion state machine: walking off the end leaves the
        // cursor exhausted in both directions until repositioned.
        assert!(c.last());
        assert!(!c.next());
        assert!(!c.prev());
        assert_eq!(c.key(), None);
        assert_eq!(c.value(), None);

        // An unpositioned cursor behaves as exhausted.
        let c2 = b.cursor();
        assert_eq!(c2.key(), None);
        assert_eq!(c2.value(), None);

        // Cursor delete: removes the current pair, errors on nested
        // buckets (which sort after every key/value pair, so seeking
        // beyond all keys positions on one).
        let mut c3 = b.cursor();
        assert!(c3.first());
        c3.delete()?; // deletes "abcd"
        assert_eq!(b.get(b"abcd"), None);
        assert!(c3.seek(b"zzzz"));
        assert_eq!(c3.key(), Some(b"aaa".to_vec()));
        assert_eq!(
            c3.delete().err().map(kind_of),
            Some(ErrorKind::IncompatibleValue)
        );

        // Delete-during-forward-iteration, the pattern the contract
        // guarantees: every key removed, nested buckets untouched.
        let mut c4 = b.cursor();
        let mut ok = c4.first();
        while ok {
            if c4.value().is_some() {
                c4.delete()?;
            }
            ok = c4.next();
        }
        let mut remaining = 0;
        b.for_each(|_, _| {
            remaining += 1;
            Ok(())
        })?;
        assert_eq!(remaining, 0, "all keys deleted via cursor");
        let mut buckets_left = 0;
        b.for_each_bucket(|_| {
            buckets_left += 1;
            Ok(())
        })?;
        assert_eq!(buckets_left, 2, "nested buckets survive cursor deletes");

        // Leave one key for the read-only phase below.
        b.put(b"survivor", b"v")?;
        Ok(())
    })
    .expect("update");

    // Cursor delete on a read-only transaction pointing at a key/value
    // pair.  Deliberate divergence from ffldb: ffldb silently accepts
    // the delete into pending state that a read-only commit then
    // discards; this driver returns the error the interface contract
    // documents.
    db.view(|tx| {
        let b = tx.metadata().bucket(b"iter").expect("iter");
        let mut c = b.cursor();
        assert!(c.first());
        assert_eq!(c.key(), Some(b"survivor".to_vec()));
        assert_eq!(
            c.delete().err().map(kind_of),
            Some(ErrorKind::TxNotWritable)
        );
        Ok(())
    })
    .expect("view");
}

#[test]
fn transaction_semantics() {
    let (_dir, db) = new_db();

    // Unmanaged write transaction: committed data persists.
    let tx = db.begin(true).expect("begin rw");
    tx.metadata().create_bucket(b"txtest").expect("create");
    tx.metadata()
        .bucket(b"txtest")
        .expect("bucket")
        .put(b"k", b"v")
        .expect("put");
    tx.commit().expect("commit");

    // Unmanaged write transaction: rollback discards.
    let tx = db.begin(true).expect("begin rw");
    tx.metadata()
        .bucket(b"txtest")
        .expect("bucket")
        .put(b"discarded", b"v")
        .expect("put");
    tx.rollback().expect("rollback");
    db.view(|tx| {
        let b = tx.metadata().bucket(b"txtest").expect("bucket");
        assert_eq!(b.get(b"k"), Some(b"v".to_vec()));
        assert_eq!(b.get(b"discarded"), None);
        Ok(())
    })
    .expect("view");

    // Snapshot isolation: a read transaction started before a write
    // commits does not observe it.
    let reader = db.begin(false).expect("begin ro");
    db.update(|tx| {
        tx.metadata()
            .bucket(b"txtest")
            .expect("bucket")
            .put(b"later", b"v")
    })
    .expect("update");
    assert_eq!(
        reader
            .metadata()
            .bucket(b"txtest")
            .expect("bucket")
            .get(b"later"),
        None
    );
    reader.rollback().expect("rollback reader");
    db.view(|tx| {
        assert_eq!(
            tx.metadata()
                .bucket(b"txtest")
                .expect("bucket")
                .get(b"later"),
            Some(b"v".to_vec())
        );
        Ok(())
    })
    .expect("view");

    // Read-your-writes within a write transaction.
    let tx = db.begin(true).expect("begin rw");
    let b = tx.metadata().bucket(b"txtest").expect("bucket");
    b.put(b"ryw", b"visible").expect("put");
    assert_eq!(b.get(b"ryw"), Some(b"visible".to_vec()));
    tx.rollback().expect("rollback");

    // Commit on a read-only transaction closes it and errors.
    let tx = db.begin(false).expect("begin ro");
    assert_eq!(
        tx.commit().err().map(kind_of),
        Some(ErrorKind::TxNotWritable)
    );
    // The transaction is now closed.
    assert_eq!(tx.rollback().err().map(kind_of), Some(ErrorKind::TxClosed));

    // All operations on a closed transaction error with ErrTxClosed
    // (or the closed-state sentinel for accessors).
    let tx = db.begin(true).expect("begin rw");
    tx.rollback().expect("rollback");
    assert_eq!(tx.commit().err().map(kind_of), Some(ErrorKind::TxClosed));
    let meta = tx.metadata();
    assert_eq!(
        meta.create_bucket(b"x").err().map(kind_of),
        Some(ErrorKind::TxClosed)
    );
    assert_eq!(
        meta.put(b"k", b"v").err().map(kind_of),
        Some(ErrorKind::TxClosed)
    );
    assert_eq!(meta.get(b"k"), None);
    assert!(meta.bucket(b"txtest").is_none());
    let mut c = meta.cursor();
    assert!(!c.first());
    assert_eq!(c.key(), None);
}

#[test]
#[should_panic(expected = "managed transaction commit not allowed")]
fn managed_commit_panics() {
    let (_dir, db) = new_db();
    let _ = db.update(|tx| {
        tx.commit().expect("panics before here");
        Ok(())
    });
}

#[test]
#[should_panic(expected = "managed transaction rollback not allowed")]
fn managed_rollback_panics() {
    let (_dir, db) = new_db();
    let _ = db.view(|tx| {
        tx.rollback().expect("panics before here");
        Ok(())
    });
}

#[test]
fn update_rolls_back_on_error() {
    let (_dir, db) = new_db();
    let result = db.update(|tx| {
        tx.metadata().create_bucket(b"doomed")?;
        Err(Error {
            kind: ErrorKind::DriverSpecific,
            description: "caller error".into(),
        })
    });
    assert_eq!(result.err().map(kind_of), Some(ErrorKind::DriverSpecific));
    db.view(|tx| {
        assert!(tx.metadata().bucket(b"doomed").is_none());
        Ok(())
    })
    .expect("view");
}
