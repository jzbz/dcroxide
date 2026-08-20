// SPDX-License-Identifier: ISC
//! Windowed bucket cursors (RVW-011).
//!
//! `Bucket::cursor` snapshots every key in the bucket. dcrd's cursor is
//! a pair of lazy merged iterators, so its 2,000,000-key
//! `incrementalFlatDrop` batching genuinely bounds memory; rebuilding
//! this one per batch re-materialized the whole remaining bucket every
//! time — 66,494,886 rows for mainnet's `existsaddridx`.
//!
//! The subtle part is the window's upper bound, and getting it wrong
//! loses data rather than merely being slow. A key can live in the
//! durable store, in the cache overlay, or in the transaction's own
//! pending writes, and the three are merged. Bounding the overlay merge
//! by the last *store* key of the window is right only while more store
//! keys remain: once the store is exhausted, every live key that exists
//! only in the overlay sorts after that bound and would be dropped —
//! and the caller, seeing a short batch, stops. So the tests below
//! deliberately straddle a flush.

// Test-harness arithmetic over bounded key counts.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_database::{Database, Options};
use tempfile::TempDir;

const NET: u32 = 0x12141c16; // simnet magic
const BUCKET: &[u8] = b"windowed";

fn new_db() -> (TempDir, Database) {
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("db"), NET);
    let db = Database::create(&opts).expect("create");
    (dir, db)
}

fn key(i: usize) -> Vec<u8> {
    format!("k{i:06}").into_bytes()
}

/// Put `range` into the bucket in one transaction.
fn put_range(db: &Database, range: std::ops::Range<usize>, create: bool) {
    let tx = db.begin(true).expect("begin");
    {
        let meta = tx.metadata();
        let bucket = if create {
            meta.create_bucket(BUCKET).expect("create bucket")
        } else {
            meta.bucket(BUCKET).expect("bucket")
        };
        for i in range {
            bucket.put(&key(i), b"v").expect("put");
        }
    }
    tx.commit().expect("commit");
}

/// Walk the whole bucket in windows of `limit`, returning the keys seen
/// in order.
///
/// Every window before the last must be *full*.  That is the contract
/// `incremental_flat_drop` relies on: it stops as soon as a batch comes
/// back short, exactly as dcrd's does, so a window that returns fewer
/// than `limit` while keys remain does not merely cost another round
/// trip — it ends the drop early and hands the remainder to the
/// unbounded `delete_bucket` path.
fn walk_windows(db: &Database, limit: usize) -> Vec<Vec<u8>> {
    let mut seen = Vec::new();
    let mut resume: Option<Vec<u8>> = None;
    let mut short_batch: Option<usize> = None;
    // A resume bound that stops excluding its own key makes every
    // window return the same batch forever.  Without a cap that is a CI
    // hang and an unbounded `seen`; with one it is an assertion.
    let mut rounds = 0usize;
    loop {
        rounds += 1;
        assert!(
            rounds < 10_000,
            "the walk did not terminate: {} keys seen in {rounds} rounds of {limit}",
            seen.len(),
        );
        let tx = db.begin(false).expect("begin");
        let mut batch = Vec::new();
        {
            let meta = tx.metadata();
            let bucket = meta.bucket(BUCKET).expect("bucket");
            let mut cursor = bucket.cursor_window(resume.as_deref(), limit);
            let mut ok = cursor.first();
            while ok {
                if let (Some(raw), Some(k)) = (cursor.raw_key(), cursor.key()) {
                    batch.push((raw, k));
                }
                ok = cursor.next();
            }
        }
        tx.rollback().expect("rollback");

        assert!(
            batch.len() <= limit,
            "a window of {limit} returned {} keys",
            batch.len(),
        );
        if batch.is_empty() {
            return seen;
        }
        // A short batch is allowed only as the final one; if the walk
        // continues past it, the window under-filled while keys
        // remained and a real drop would have stopped there.
        if let Some(short) = short_batch {
            panic!(
                "a window of {limit} returned {short} keys and then {} more: a drop \
                 would have stopped at the short batch, leaving the rest behind",
                batch.len(),
            );
        }
        if batch.len() < limit {
            short_batch = Some(batch.len());
        }
        resume = Some(batch.last().expect("non-empty").0.clone());
        seen.extend(batch.into_iter().map(|(_, k)| k));
    }
}

#[test]
fn a_window_bounds_the_view_and_resumes_after_a_key() {
    let (_dir, db) = new_db();
    put_range(&db, 0..50, true);

    let all = walk_windows(&db, 1000);
    assert_eq!(
        all.len(),
        50,
        "a limit above the bucket size returns it all"
    );
    assert_eq!(all, (0..50).map(key).collect::<Vec<_>>(), "and in order");

    let windowed = walk_windows(&db, 7);
    assert_eq!(windowed, all, "windowing must not change what is seen");
}

/// The regression test for the bound. Half the keys are flushed to the
/// store and half are committed after, so they live only in the cache
/// overlay and sort *after* every stored key. A window bounded by the
/// last store key returns the flushed half and then reports empty,
/// silently losing the rest.
#[test]
fn a_window_spanning_store_and_overlay_returns_every_live_key() {
    let (_dir, db) = new_db();
    put_range(&db, 0..40, true);
    db.flush().expect("flush the first half to the store");
    put_range(&db, 40..80, false);

    let expected: Vec<Vec<u8>> = (0..80).map(key).collect();
    for limit in [1, 7, 40, 41, 79, 80, 1000] {
        assert_eq!(
            walk_windows(&db, limit),
            expected,
            "windows of {limit} lost keys across the store/overlay boundary",
        );
    }
}

/// Deletions that have not reached the store must mask the stored key,
/// including when the deletion is the last thing in its window.
#[test]
fn a_window_survives_deletions_that_have_not_reached_the_store() {
    let (_dir, db) = new_db();
    put_range(&db, 0..60, true);
    db.flush().expect("flush");

    let tx = db.begin(true).expect("begin");
    {
        let meta = tx.metadata();
        let bucket = meta.bucket(BUCKET).expect("bucket");
        for i in (0..60).step_by(3) {
            bucket.delete(&key(i)).expect("delete");
        }
    }
    tx.commit().expect("commit");

    let expected: Vec<Vec<u8>> = (0..60).filter(|i| i % 3 != 0).map(key).collect();
    for limit in [1, 5, 13, 40, 1000] {
        assert_eq!(
            walk_windows(&db, limit),
            expected,
            "windows of {limit} disagreed with the masked view",
        );
    }
}

/// An empty bucket and a single-key bucket are the shapes the resume
/// logic is most likely to mishandle.
#[test]
fn degenerate_buckets_walk_cleanly() {
    let (_dir, db) = new_db();
    put_range(&db, 0..0, true);
    assert!(
        walk_windows(&db, 4).is_empty(),
        "an empty bucket yields nothing"
    );

    put_range(&db, 0..1, false);
    assert_eq!(walk_windows(&db, 4), vec![key(0)], "one key, one window");
    assert_eq!(walk_windows(&db, 1), vec![key(0)], "one key, limit one");
}

/// Nested-bucket index rows are part of the walk and must obey the
/// window like everything else.
///
/// They sort after the key/value rows, so they fill the tail. Scanning
/// them unbounded overruns `limit`; re-appending them on every window
/// makes a caller that resumes from the last key walk forever, because
/// the resume key is then a `bidx` key that the data range can never
/// advance past. `Cursor::delete` refuses these rows, so the drop path
/// aborts before either can bite — but `cursor_window` is public API.
#[test]
fn nested_bucket_rows_stay_inside_the_window() {
    let (_dir, db) = new_db();
    put_range(&db, 0..5, true);
    let tx = db.begin(true).expect("begin");
    {
        let bucket = tx.metadata().bucket(BUCKET).expect("bucket");
        bucket.create_bucket(b"childA").expect("child A");
        bucket.create_bucket(b"childB").expect("child B");
    }
    tx.commit().expect("commit");

    // The whole-bucket cursor is the oracle: the windowed walk must see
    // exactly what it sees, in the same order.
    let oracle = {
        let tx = db.begin(false).expect("begin");
        let mut out = Vec::new();
        {
            let bucket = tx.metadata().bucket(BUCKET).expect("bucket");
            let mut cursor = bucket.cursor();
            let mut ok = cursor.first();
            while ok {
                out.push(cursor.key().expect("key"));
                ok = cursor.next();
            }
        }
        tx.rollback().expect("rollback");
        out
    };
    assert_eq!(oracle.len(), 7, "five keys and two child buckets");

    for limit in [1, 2, 3, 6, 7, 100] {
        assert_eq!(
            walk_windows(&db, limit),
            oracle,
            "windows of {limit} disagreed with the whole-bucket cursor",
        );
    }
}

/// A window must see its own transaction's uncommitted writes, the way
/// the whole-prefix scan does: read-your-writes is part of the
/// transaction contract, and the drop path builds its cursor inside the
/// same writable transaction it deletes in.
#[test]
fn a_window_sees_the_transactions_own_pending_writes() {
    let (_dir, db) = new_db();
    put_range(&db, 0..20, true);
    db.flush().expect("flush");

    let tx = db.begin(true).expect("begin");
    {
        let bucket = tx.metadata().bucket(BUCKET).expect("bucket");
        // Uncommitted: five more keys past the stored ones, and every
        // third stored key removed.
        for i in 20..25 {
            bucket.put(&key(i), b"v").expect("put");
        }
        for i in (0..20).step_by(3) {
            bucket.delete(&key(i)).expect("delete");
        }

        let expected: Vec<Vec<u8>> = (0..25)
            .filter(|i| *i >= 20 || i % 3 != 0)
            .map(key)
            .collect();
        for limit in [1, 4, 11, 25, 100] {
            let mut seen = Vec::new();
            let mut resume: Option<Vec<u8>> = None;
            let mut rounds = 0usize;
            loop {
                rounds += 1;
                assert!(rounds < 1000, "the in-transaction walk did not terminate");
                let mut batch = Vec::new();
                let mut cursor = bucket.cursor_window(resume.as_deref(), limit);
                let mut ok = cursor.first();
                while ok {
                    if let (Some(raw), Some(k)) = (cursor.raw_key(), cursor.key()) {
                        batch.push((raw, k));
                    }
                    ok = cursor.next();
                }
                if batch.is_empty() {
                    break;
                }
                resume = Some(batch.last().expect("non-empty").0.clone());
                seen.extend(batch.into_iter().map(|(_, k)| k));
            }
            assert_eq!(
                seen, expected,
                "windows of {limit} ignored the transaction's own pending writes",
            );
        }
    }
    tx.rollback().expect("rollback");
}

/// A resume key from outside the bucket must not drag the walk into a
/// sibling's keys, nor silently return nothing.
#[test]
fn a_resume_key_below_the_prefix_is_ignored() {
    let (_dir, db) = new_db();
    put_range(&db, 0..10, true);

    let tx = db.begin(false).expect("begin");
    {
        let bucket = tx.metadata().bucket(BUCKET).expect("bucket");
        let mut cursor = bucket.cursor_window(Some(&[0u8]), 100);
        let mut seen = Vec::new();
        let mut ok = cursor.first();
        while ok {
            seen.push(cursor.key().expect("key"));
            ok = cursor.next();
        }
        assert_eq!(
            seen,
            (0..10).map(key).collect::<Vec<_>>(),
            "a resume key below the bucket must be ignored, not followed",
        );
    }
    tx.rollback().expect("rollback");
}
