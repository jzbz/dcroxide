// SPDX-License-Identifier: ISC
//! The bucket index held in memory: the ID each nested bucket's name
//! resolves to under each parent, so [`crate::Bucket::bucket`] answers
//! without reading the store.
//!
//! ffldb resolves a nested bucket by reading its bucket index row,
//! `bidx<parent ID><name>`, through the transaction's layered view on
//! every call (`ffldb/db.go:598-614`).  Here that read builds the key,
//! probes the transaction's two pending sets and every overlay layer,
//! descends redb and copies the value out, and a caller that names its
//! bucket for each row it reads or writes pays it per row.  The rows it
//! reads change only when a bucket is created or deleted.
//!
//! [`BucketIndex`] is those rows as a map.  It is read from the store
//! when the database opens, and after that every committed transaction's
//! bucket index rows are applied to it by `DbCache::commit_pending`, under
//! the hold of the cache lock that publishes the transaction's other rows
//! to the overlay.  A transaction takes the map with its overlay and
//! store snapshots, under that same lock, so the three are of one commit:
//! the map a transaction holds is what its own layered read of the bucket
//! index beneath its pending changes returns, for as long as it lives and
//! whatever commits after it began.  A transaction that rolls back, is
//! dropped or fails its commit never reaches `commit_pending`, so neither
//! does anything it staged.
//!
//! A flush leaves the map alone.  It moves rows from the overlay to the
//! store and changes nothing the two hold between them.  The one thing it
//! writes that the overlay never held is a flush participant's rows, and
//! those cannot be bucket index rows: `Database::set_flush_participant`
//! refuses a prefix inside the bucket index and the participant's writer
//! refuses a key outside its prefix.  The map depends on that refusal.
//!
//! The map is kept from the raw rows, not from the calls that create and
//! delete buckets, so it needs no account of what those calls stage: a
//! row put is an entry set, a row deleted is an entry gone, and the
//! bucket ID counter at `bidx-cbid`, which a lookup of the name `d` under
//! a bucket with the ID `-cbi` would read as a bucket index row, is kept
//! as the row it is.
//!
//! One answer differs from a read of the row, and only on a failing
//! disk.  A read of the row answers a store read error as a missing key,
//! as ffldb's `dbCacheSnapshot.Get` answers a leveldb error
//! (`ffldb/dbcache.go:308-311`), so a lookup made that way says "no such
//! bucket" whenever the row's page has to come from a disk that fails, and
//! finds the bucket whenever redb still has the page cached.  The map is
//! not read from the disk after the open, so the lookup always finds the
//! bucket and the error is met by the first read of a row in it.  The open
//! reads the bucket index once and fails on a read error there.
//!
//! That disk need not be failing reads.  From the first read, write or
//! sync of its file that fails, redb refuses every read of a page it does
//! not hold (redb-4.3.0 `cached_file.rs:198-261`), so the difference is
//! there for the rest of a handle's life after a failed flush as well.
//!
//! Creating and deleting a bucket still read its row, and read such an
//! error as a missing row.  Within one transaction they can then
//! disagree with a lookup: `delete_bucket` reports no such bucket where
//! the lookup finds it, while `create_bucket_if_not_exists`, which looks
//! the bucket up first, returns it where a read of the row would send the
//! call on to create the name again.

use std::collections::BTreeMap;
use std::ops::Bound;

use redb::ReadableDatabase as _;

use crate::METADATA_TABLE;
use crate::error::Error;
use crate::transaction::BUCKET_INDEX_PREFIX;

/// The bucket index rows of one committed state of the database: for each
/// parent bucket ID, its nested buckets' names and their IDs.
///
/// Two maps over the same rows are equal, whatever order the rows were
/// applied in: a parent whose last child is removed is removed with it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct BucketIndex {
    children: BTreeMap<[u8; 4], BTreeMap<Vec<u8>, [u8; 4]>>,
}

/// The parent ID and child name a raw key addresses as a bucket index row
/// (dcrd `bucketIndexKey`, `ffldb/db.go:572`), or `None` for a key that is
/// not one.  A key under the prefix but too short to hold a parent ID is
/// not one either: a lookup's key always holds one, so no lookup can ask
/// for such a row.
fn split(raw_key: &[u8]) -> Option<([u8; 4], &[u8])> {
    let rest = raw_key.strip_prefix(BUCKET_INDEX_PREFIX)?;
    let (parent, name) = rest.split_first_chunk::<4>()?;
    Some((*parent, name))
}

impl BucketIndex {
    /// The ID of the bucket `name` nested in the bucket `parent`, or
    /// `None` when the bucket index holds no such bucket.
    pub(crate) fn get(&self, parent: [u8; 4], name: &[u8]) -> Option<[u8; 4]> {
        self.children.get(&parent)?.get(name).copied()
    }

    /// Apply a put of the raw row `raw_key`; a key outside the bucket
    /// index is ignored.
    ///
    /// A value that is not a four-byte ID leaves no entry, and removes
    /// the one the key had: a lookup reads such a row as no bucket.
    pub(crate) fn put_row(&mut self, raw_key: &[u8], value: &[u8]) {
        let Some((parent, name)) = split(raw_key) else {
            return;
        };
        match <[u8; 4]>::try_from(value) {
            Ok(id) => {
                self.children
                    .entry(parent)
                    .or_default()
                    .insert(name.to_vec(), id);
            }
            Err(_) => self.remove(parent, name),
        }
    }

    /// Apply a delete of the raw row `raw_key`; a key outside the bucket
    /// index is ignored.
    pub(crate) fn remove_row(&mut self, raw_key: &[u8]) {
        if let Some((parent, name)) = split(raw_key) {
            self.remove(parent, name);
        }
    }

    fn remove(&mut self, parent: [u8; 4], name: &[u8]) {
        let Some(children) = self.children.get_mut(&parent) else {
            return;
        };
        children.remove(name);
        if children.is_empty() {
            self.children.remove(&parent);
        }
    }

    /// The bucket index as the store holds it.
    ///
    /// For the open, before any transaction has committed: the overlay is
    /// empty then, so the store's rows are the database's.  A read error
    /// is returned and fails the open, as a read error on the write
    /// cursor's row does (`reconcile_db`): a map missing the rows that
    /// could not be read would answer "no such bucket" for buckets the
    /// store holds, for the life of the handle.
    ///
    /// A store with no metadata table gives the empty map, which is what
    /// a transaction reads from one: every key missing.  No open gets
    /// this far with such a store, `reconcile_db` having refused it for
    /// its missing write cursor.
    pub(crate) fn load(kv: &redb::Database) -> Result<BucketIndex, Error> {
        let mut index = BucketIndex::default();
        let rtx = kv.begin_read().map_err(crate::storage_error)?;
        let table = match rtx.open_table(METADATA_TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(index),
            Err(e) => return Err(crate::storage_error(e)),
        };
        let end = crate::Transaction::prefix_upper_bound(BUCKET_INDEX_PREFIX);
        let upper = match end.as_deref() {
            Some(end) => Bound::Excluded(end),
            None => Bound::Unbounded,
        };
        let rows = table
            .range::<&[u8]>((Bound::Included(BUCKET_INDEX_PREFIX), upper))
            .map_err(crate::storage_error)?;
        for row in rows {
            let (key, value) = row.map_err(crate::storage_error)?;
            index.put_row(key.value(), value.value());
        }
        Ok(index)
    }
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic over small counts"
)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path as FsPath;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

    use dcroxide_testutil::SplitMix64;
    use dcroxide_testutil::powerloss::PowerLossBackend;
    use tempfile::TempDir;

    use super::BucketIndex;
    use crate::dbcache::DbCache;
    use crate::transaction::{BLOCK_IDX_BUCKET_NAME, METADATA_BUCKET_ID};
    use crate::{Bucket, Database, ErrorKind, Options, SharedBackend, Transaction};

    /// simnet magic, matching the interface battery.
    const NET: u32 = 0x1214_1c16;

    /// The names the histories create buckets under, at every depth, so
    /// one name lives under several parents and is created again after it
    /// was deleted.
    const NAMES: [&[u8]; 3] = [b"a", b"b", b"c"];

    /// The names every check looks up in every bucket it reaches: the
    /// three above, the empty name, one never created, and the internal
    /// block index bucket's, whose row `Database::create` writes itself.
    const LOOKUPS: [&[u8]; 6] = [b"a", b"b", b"c", b"", b"zz", BLOCK_IDX_BUCKET_NAME];

    /// How deep the histories nest buckets.
    const DEPTH: usize = 3;

    /// The key of the row a history puts in a bucket to tell it from every
    /// other bucket that ever had its name.
    const MARKER: &[u8] = b"marker";

    /// A bucket's names from the metadata bucket down.
    type Path = Vec<&'static [u8]>;

    fn show(path: &[&[u8]]) -> String {
        path.iter()
            .map(|name| String::from_utf8_lossy(name).into_owned())
            .collect::<Vec<_>>()
            .join("/")
    }

    /// What the bucket index must hold, kept without reading it: each
    /// bucket's ID and marker by its path, and the bucket ID counter
    /// (dcrd `curBucketIDKeyName`), from which a new bucket takes the next
    /// ID whatever was deleted before it.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Model {
        buckets: BTreeMap<Path, (u32, Option<u64>)>,
        last_id: u32,
    }

    impl Model {
        /// A created database: the block index bucket under its fixed ID,
        /// which is also where the counter starts.
        fn new() -> Model {
            Model {
                buckets: BTreeMap::from([(vec![BLOCK_IDX_BUCKET_NAME], (1, None))]),
                last_id: 1,
            }
        }

        fn has(&self, path: &[&'static [u8]]) -> bool {
            self.buckets.contains_key(path)
        }

        /// Whether the bucket a create or delete of `path` goes through
        /// exists; the metadata bucket always does.
        fn has_parent(&self, path: &[&'static [u8]]) -> bool {
            path.len() == 1 || self.has(&path[..path.len() - 1])
        }

        fn create(&mut self, path: &[&'static [u8]]) -> u32 {
            self.last_id += 1;
            self.buckets.insert(path.to_vec(), (self.last_id, None));
            self.last_id
        }

        /// Remove the bucket and every bucket nested in it.
        fn delete(&mut self, path: &[&'static [u8]]) {
            self.buckets.retain(|p, _| !p.starts_with(path));
        }
    }

    /// The bucket at `path`, found one lookup at a time.
    fn resolve<'tx>(tx: &'tx Transaction, path: &[&[u8]]) -> Option<Bucket<'tx>> {
        path.iter()
            .try_fold(tx.metadata(), |bucket, name| bucket.bucket(name))
    }

    /// Look every name of [`LOOKUPS`] up in `bucket`, and in each bucket
    /// that finds down to [`DEPTH`], three ways that must agree: through
    /// the bucket index, by reading the bucket's index row as dcrd does,
    /// and in the model.  A bucket found must also hold the model's marker
    /// row, which a lookup that answered with another bucket's ID -- one
    /// deleted under the same name, say -- would not find.
    fn check_under(bucket: Bucket<'_>, path: &mut Path, model: &Model, context: &str) {
        for name in LOOKUPS {
            path.push(name);
            let found = bucket.bucket(name);
            let id = found.map(|b| b.raw_id());
            let read = bucket.bucket_from_rows(name).map(|b| b.raw_id());
            assert_eq!(
                id,
                read,
                "{context}: the lookup of {:?} is not the read of its row",
                show(path)
            );
            let want = model.buckets.get(path.as_slice());
            assert_eq!(
                id,
                want.map(|(id, _)| id.to_be_bytes()),
                "{context}: the lookup of {:?} is not the model's",
                show(path)
            );
            if let (Some(found), Some((_, marker))) = (found, want) {
                assert_eq!(
                    found.get(MARKER),
                    marker.map(|m| m.to_be_bytes().to_vec()),
                    "{context}: the marker row of {:?}",
                    show(path)
                );
                if path.len() < DEPTH {
                    check_under(found, path, model, context);
                }
            }
            path.pop();
        }
    }

    /// [`check_under`] from the metadata bucket.
    fn check(tx: &Transaction, model: &Model, context: &str) {
        check_under(tx.metadata(), &mut Vec::new(), model, context);
    }

    /// [`check`] for a read-only transaction, whose map must also be,
    /// entry for entry, the one a scan of the bucket index rows through
    /// its own snapshots builds.  That covers the rows no lookup from the
    /// metadata bucket reaches, such as those of a deleted bucket's ID.
    fn check_reader(tx: &Transaction, model: &Model, context: &str) {
        check(tx, model, context);
        let held = tx
            .held_bucket_index()
            .expect("an open transaction holds a bucket index");
        assert_eq!(
            *held,
            tx.bucket_index_from_rows(),
            "{context}: the map is not the bucket index rows"
        );
    }

    /// Create the bucket at `path` in the transaction and the model,
    /// requiring the ID the model gives it; where the model says it
    /// cannot be created, require that refusal.  Returns whether a bucket
    /// was created.
    fn create(tx: &Transaction, model: &mut Model, path: &[&'static [u8]], context: &str) -> bool {
        let (name, parent_path) = path.split_last().expect("a path names a bucket");
        let Some(parent) = resolve(tx, parent_path) else {
            assert!(!model.has_parent(path), "{context}: {:?}", show(path));
            return false;
        };
        assert!(model.has_parent(path), "{context}: {:?}", show(path));
        let created = parent.create_bucket(name).map(|b| b.raw_id());
        if model.has(path) {
            assert_eq!(
                created.map_err(|e| e.kind),
                Err(ErrorKind::BucketExists),
                "{context}: creating {:?} again",
                show(path)
            );
            return false;
        }
        let id = model.create(path);
        assert_eq!(
            created,
            Ok(id.to_be_bytes()),
            "{context}: the ID of the new bucket {:?}",
            show(path)
        );
        true
    }

    /// [`create`] through `create_bucket_if_not_exists`, which answers
    /// with the bucket there is when there is one.
    fn create_if_missing(
        tx: &Transaction,
        model: &mut Model,
        path: &[&'static [u8]],
        context: &str,
    ) -> bool {
        let (name, parent_path) = path.split_last().expect("a path names a bucket");
        let Some(parent) = resolve(tx, parent_path) else {
            return false;
        };
        let existing = model.buckets.get(path).map(|(id, _)| *id);
        let id = existing.unwrap_or_else(|| model.create(path));
        assert_eq!(
            parent.create_bucket_if_not_exists(name).map(|b| b.raw_id()),
            Ok(id.to_be_bytes()),
            "{context}: create-if-missing of {:?}",
            show(path)
        );
        existing.is_none()
    }

    /// Delete the bucket at `path` in the transaction and the model, or
    /// require dcrd's refusal where the model has none.  Returns whether a
    /// bucket was deleted.
    fn delete(tx: &Transaction, model: &mut Model, path: &[&'static [u8]], context: &str) -> bool {
        let (name, parent_path) = path.split_last().expect("a path names a bucket");
        let Some(parent) = resolve(tx, parent_path) else {
            return false;
        };
        let deleted = parent.delete_bucket(name).map_err(|e| e.kind);
        if !model.has(path) {
            assert_eq!(
                deleted,
                Err(ErrorKind::BucketNotFound),
                "{context}: deleting {:?}, which does not exist",
                show(path)
            );
            return false;
        }
        assert_eq!(deleted, Ok(()), "{context}: deleting {:?}", show(path));
        model.delete(path);
        true
    }

    /// Put a marker row in the bucket at `path`, when there is one.
    fn mark(tx: &Transaction, model: &mut Model, path: &[&'static [u8]], marker: u64) {
        let Some(bucket) = resolve(tx, path) else {
            return;
        };
        bucket.put(MARKER, &marker.to_be_bytes()).expect("put");
        if let Some(entry) = model.buckets.get_mut(path) {
            entry.1 = Some(marker);
        }
    }

    /// Options for a store in `dir` that flushes only when told to, so a
    /// history knows what an unclean stop keeps.
    fn options(dir: &FsPath) -> Options {
        let mut opts = Options::new(dir.join("db"), NET);
        opts.cache_flush_interval_secs = 365 * 24 * 60 * 60;
        opts
    }

    fn row(parent: [u8; 4], name: &[u8]) -> Vec<u8> {
        let mut key = b"bidx".to_vec();
        key.extend_from_slice(&parent);
        key.extend_from_slice(name);
        key
    }

    /// The map is the bucket index rows and nothing else: keyed by parent
    /// and name together, deaf to keys outside the index, and holding no
    /// entry for a row a lookup reads as no bucket.
    #[test]
    fn the_map_holds_what_the_rows_hold() {
        let meta = METADATA_BUCKET_ID;
        let mut index = BucketIndex::default();
        index.put_row(&row(meta, b"a"), &[0, 0, 0, 2]);
        index.put_row(&row(meta, b"b"), &[0, 0, 0, 3]);
        index.put_row(&row([0, 0, 0, 2], b"a"), &[0, 0, 0, 4]);
        index.put_row(&row([0, 0, 0, 3], b"a"), &[0, 0, 0, 5]);
        assert_eq!(index.get(meta, b"a"), Some([0, 0, 0, 2]));
        assert_eq!(index.get(meta, b"b"), Some([0, 0, 0, 3]));
        assert_eq!(
            index.get([0, 0, 0, 2], b"a"),
            Some([0, 0, 0, 4]),
            "one name under two parents is two buckets"
        );
        assert_eq!(index.get([0, 0, 0, 3], b"a"), Some([0, 0, 0, 5]));
        assert_eq!(index.get([0, 0, 0, 4], b"a"), None);
        assert_eq!(index.get(meta, b""), None);
        assert_eq!(index.get(meta, b"ab"), None, "a name is matched whole");

        // The empty name is a name like any other to a row that has it.
        index.put_row(&row(meta, b""), &[0, 0, 0, 6]);
        assert_eq!(index.get(meta, b""), Some([0, 0, 0, 6]));
        index.remove_row(&row(meta, b""));

        // Keys that are not bucket index rows change nothing: a row of a
        // bucket, and keys under the prefix too short to name a parent.
        let before = index.clone();
        for key in [&b"\0\0\0\x02a"[..], b"bid", b"bidx", b"bidx\0\0\0", b""] {
            index.put_row(key, &[0, 0, 0, 9]);
            assert_eq!(index, before, "a put of {key:02x?}");
            index.remove_row(key);
            assert_eq!(index, before, "a delete of {key:02x?}");
        }

        // The bucket ID counter lies under the prefix, and a lookup of
        // the name `d` in a bucket with the ID `-cbi` reads it as a row.
        index.put_row(b"bidx-cbid", &[0, 0, 0, 7]);
        assert_eq!(index.get(*b"-cbi", b"d"), Some([0, 0, 0, 7]));
        index.remove_row(b"bidx-cbid");
        assert_eq!(index, before);

        // A put replaces, and a value that is not an ID reads as no
        // bucket, whatever the row held before.
        index.put_row(&row(meta, b"a"), &[0, 0, 0, 8]);
        assert_eq!(index.get(meta, b"a"), Some([0, 0, 0, 8]));
        for value in [&[][..], &[0, 0, 8], &[0, 0, 0, 0, 8]] {
            index.put_row(&row(meta, b"b"), &[0, 0, 0, 3]);
            index.put_row(&row(meta, b"b"), value);
            assert_eq!(index.get(meta, b"b"), None, "a {}-byte value", value.len());
        }

        // A delete removes one row, and the last row's parent with it, so
        // equal rows make equal maps.
        index.remove_row(&row(meta, b"a"));
        assert_eq!(index.get(meta, b"a"), None);
        assert_eq!(index.get([0, 0, 0, 2], b"a"), Some([0, 0, 0, 4]));
        index.remove_row(&row([0, 0, 0, 2], b"a"));
        index.remove_row(&row([0, 0, 0, 3], b"a"));
        index.remove_row(&row([0, 0, 0, 3], b"never there"));
        assert_eq!(index, BucketIndex::default());
    }

    /// A commit applies its bucket index rows to the cache's map, a
    /// holder of the map as it was keeps it, and a commit with no such
    /// row leaves the very same map published.
    #[test]
    fn a_commit_applies_its_bucket_index_rows_and_no_holder_sees_them() {
        let meta = METADATA_BUCKET_ID;
        let mut cache = DbCache::new();
        let empty = Arc::clone(&cache.buckets);

        let mut puts = BTreeMap::new();
        puts.insert(row(meta, b"a"), vec![0, 0, 0, 2]);
        puts.insert(row([0, 0, 0, 2], b"a"), vec![0, 0, 0, 3]);
        puts.insert(b"bidx-cbid".to_vec(), vec![0, 0, 0, 3]);
        puts.insert(b"\0\0\0\x02key".to_vec(), b"value".to_vec());
        cache.commit_pending(puts, std::iter::empty());
        assert_eq!(cache.buckets.get(meta, b"a"), Some([0, 0, 0, 2]));
        assert_eq!(cache.buckets.get([0, 0, 0, 2], b"a"), Some([0, 0, 0, 3]));
        assert_eq!(
            *empty,
            BucketIndex::default(),
            "the map held from before the commit"
        );

        // No bucket index row: nothing to copy, nothing to change.
        let created = Arc::clone(&cache.buckets);
        let mut puts = BTreeMap::new();
        puts.insert(b"\0\0\0\x02key".to_vec(), b"other".to_vec());
        cache.commit_pending(puts, std::iter::once(b"\0\0\0\x02gone".to_vec()));
        assert!(
            Arc::ptr_eq(&created, &cache.buckets),
            "a commit with no bucket index row republished the map"
        );

        // A delete and a re-creation under a new ID in one commit, and
        // the nested bucket's row deleted with its parent.
        let mut puts = BTreeMap::new();
        puts.insert(row(meta, b"a"), vec![0, 0, 0, 4]);
        cache.commit_pending(puts, std::iter::once(row([0, 0, 0, 2], b"a")));
        assert_eq!(cache.buckets.get(meta, b"a"), Some([0, 0, 0, 4]));
        assert_eq!(cache.buckets.get([0, 0, 0, 2], b"a"), None);
        assert_eq!(created.get(meta, b"a"), Some([0, 0, 0, 2]));
        assert_eq!(created.get([0, 0, 0, 2], b"a"), Some([0, 0, 0, 3]));

        // A delete alone.
        cache.commit_pending(BTreeMap::new(), std::iter::once(row(meta, b"a")));
        assert_eq!(cache.buckets.get(meta, b"a"), None);
    }

    /// Each state a bucket's index row can be in, one after another, with
    /// every lookup checked at each: created and rolled back, created and
    /// deleted in one transaction, the writer's own uncommitted buckets,
    /// nested buckets and one name under several parents, buckets created
    /// and deleted by a writer dropped while open, a delete that takes
    /// nested buckets with it, a bucket deleted and created again,
    /// readers that began before each of those commits, a flush, and
    /// reopens.
    #[test]
    fn a_lookup_is_the_read_of_its_row_in_every_state() {
        let dir = TempDir::new().expect("tempdir");
        let opts = options(dir.path());
        let db = Database::create(&opts).expect("create");
        let mut model = Model::new();
        db.view(|tx| {
            check_reader(tx, &model, "a created database");
            Ok(())
        })
        .expect("view");

        // Created in a transaction that rolls back: seen inside it, by
        // nobody after it, and its ID is handed out again.
        let before_any = db.begin(false).expect("begin read");
        let tx = db.begin(true).expect("begin write");
        let mut staged = model.clone();
        assert!(create(&tx, &mut staged, &[b"a"], "rolled back"));
        assert!(create(&tx, &mut staged, &[b"a", b"b"], "rolled back"));
        mark(&tx, &mut staged, &[b"a", b"b"], 1);
        check(&tx, &staged, "a writer's own uncommitted buckets");
        check_reader(
            &before_any,
            &model,
            "a reader beside the uncommitted buckets",
        );
        tx.rollback().expect("rollback");
        drop(tx);
        db.view(|tx| {
            check_reader(tx, &model, "after the rollback");
            Ok(())
        })
        .expect("view");

        // Created and deleted in one transaction, which then commits:
        // only the counter moved.
        let tx = db.begin(true).expect("begin write");
        assert!(create(&tx, &mut model, &[b"b"], "created then deleted"));
        assert!(create(
            &tx,
            &mut model,
            &[b"b", b"b"],
            "created then deleted"
        ));
        check(&tx, &model, "created, not yet deleted");
        assert!(delete(&tx, &mut model, &[b"b"], "created then deleted"));
        check(&tx, &model, "created and deleted");
        assert!(!delete(&tx, &mut model, &[b"b"], "deleted twice"));
        tx.commit().expect("commit");
        drop(tx);
        assert_eq!(
            model.buckets.len(),
            1,
            "only the block index bucket is left"
        );
        db.view(|tx| {
            check_reader(tx, &model, "after a create and a delete in one commit");
            Ok(())
        })
        .expect("view");

        // Nested buckets, and the name `a` under four parents.
        let tx = db.begin(true).expect("begin write");
        for path in [
            &[b"a" as &[u8]][..],
            &[b"b"],
            &[b"a", b"a"],
            &[b"b", b"a"],
            &[b"a", b"a", b"a"],
        ] {
            assert!(create(&tx, &mut model, path, "nested"));
            let marker = u64::from(model.last_id);
            mark(&tx, &mut model, path, marker);
            assert!(!create(&tx, &mut model, path, "nested, again"));
            assert!(!create_if_missing(&tx, &mut model, path, "nested, again"));
        }
        check(&tx, &model, "nested, uncommitted");
        tx.commit().expect("commit");
        drop(tx);
        let nested = model.clone();
        let before_delete = db.begin(false).expect("begin read");
        check_reader(&before_delete, &nested, "nested, committed");
        check_reader(
            &before_any,
            &Model::new(),
            "a reader from before any bucket",
        );

        // A writer dropped while open is a rollback without the call:
        // the bucket it deleted, the one it created and the one it
        // created under the deleted name are seen inside it and by nobody
        // after it.
        let tx = db.begin(true).expect("begin write");
        let mut staged = model.clone();
        assert!(delete(&tx, &mut staged, &[b"b"], "dropped open"));
        assert!(create(&tx, &mut staged, &[b"c"], "dropped open"));
        assert!(create(&tx, &mut staged, &[b"b"], "dropped open"));
        check(&tx, &staged, "a writer about to be dropped open");
        drop(tx);
        db.view(|tx| {
            check_reader(tx, &model, "after a writer was dropped open");
            Ok(())
        })
        .expect("view");
        check_reader(
            &before_delete,
            &nested,
            "a reader beside the writer dropped open",
        );

        // A delete takes the nested buckets with it; the name is then
        // created again and is a new, empty bucket under a new ID.
        let old_id = model.buckets[&vec![b"a" as &[u8]]].0;
        let tx = db.begin(true).expect("begin write");
        assert!(delete(&tx, &mut model, &[b"a"], "delete with nested"));
        check(&tx, &model, "deleted, uncommitted");
        assert!(create_if_missing(&tx, &mut model, &[b"a"], "created again"));
        check(&tx, &model, "deleted and created again, uncommitted");
        check_reader(
            &before_delete,
            &nested,
            "a reader beside the uncommitted delete",
        );
        tx.commit().expect("commit");
        drop(tx);
        assert_ne!(model.buckets[&vec![b"a" as &[u8]]].0, old_id);
        let recreated = model.clone();
        db.view(|tx| {
            check_reader(tx, &recreated, "deleted and created again");
            Ok(())
        })
        .expect("view");
        check_reader(
            &before_delete,
            &nested,
            "a reader from before the delete, after its commit",
        );

        // Deleted in one transaction, created again in a later one.
        db.update(|tx| {
            assert!(delete(tx, &mut model, &[b"b"], "delete, then a commit"));
            check(tx, &model, "a writer that has only deleted");
            Ok(())
        })
        .expect("update");
        let before_recreate = db.begin(false).expect("begin read");
        let deleted = model.clone();
        db.update(|tx| {
            assert!(create(tx, &mut model, &[b"b"], "created in a later commit"));
            assert!(create(
                tx,
                &mut model,
                &[b"b", b"c"],
                "created in a later commit"
            ));
            Ok(())
        })
        .expect("update");
        check_reader(
            &before_recreate,
            &deleted,
            "a reader from between the two commits",
        );

        // A flush moves every row to the store and changes no answer.
        db.flush().expect("flush");
        for (reader, then, context) in [
            (
                &before_any,
                &Model::new(),
                "the first reader, after a flush",
            ),
            (&before_delete, &nested, "the second, after a flush"),
            (&before_recreate, &deleted, "the third, after a flush"),
        ] {
            check_reader(reader, then, context);
        }
        db.view(|tx| {
            check_reader(tx, &model, "a new reader after a flush");
            Ok(())
        })
        .expect("view");
        // A closed transaction still holds the database open, and so does
        // a reader: all of them go before the store is opened again.
        drop((before_any, before_delete, before_recreate));

        // An unclean stop keeps the flushed buckets and loses the rest.
        let flushed = model.clone();
        db.update(|tx| {
            assert!(delete(tx, &mut model, &[b"a"], "lost"));
            assert!(create(tx, &mut model, &[b"c"], "lost"));
            Ok(())
        })
        .expect("update");
        drop(db);
        let db = Database::open(&opts).expect("reopen after an unclean stop");
        let mut model = flushed;
        db.view(|tx| {
            check_reader(tx, &model, "reopened after an unclean stop");
            Ok(())
        })
        .expect("view");

        // A clean close keeps everything, and the reopened map takes
        // commits like the one it replaced.
        db.update(|tx| {
            assert!(create(tx, &mut model, &[b"c"], "before a close"));
            assert!(delete(tx, &mut model, &[b"b"], "before a close"));
            Ok(())
        })
        .expect("update");
        db.close().expect("close");
        drop(db);
        let db = Database::open(&opts).expect("reopen after a close");
        db.view(|tx| {
            check_reader(tx, &model, "reopened after a close");
            Ok(())
        })
        .expect("view");
        db.update(|tx| {
            assert!(create(tx, &mut model, &[b"b"], "after the reopen"));
            assert!(create(tx, &mut model, &[b"c", b"b"], "after the reopen"));
            check(tx, &model, "after the reopen, uncommitted");
            Ok(())
        })
        .expect("update");
        db.view(|tx| {
            check_reader(tx, &model, "after the reopen, committed");
            Ok(())
        })
        .expect("view");
    }

    /// What a random history did, so a run that never reached a state it
    /// is there to cover fails instead of passing on what it did reach.
    #[derive(Debug, Default)]
    struct Tally {
        created: u32,
        nested: u32,
        deleted: u32,
        created_again: u32,
        created_and_deleted_in_one: u32,
        rolled_back: u32,
        dropped_open: u32,
        outlived_readers: u32,
        flushes: u32,
        clean_reopens: u32,
        unclean_reopens: u32,
    }

    /// A database under a random history, with the model of what it must
    /// hold: after every commit, after the last flush, and when each open
    /// reader began.
    struct World {
        dir: TempDir,
        db: Option<Database>,
        committed: Model,
        flushed: Model,
        readers: Vec<(Transaction, Model)>,
        ever_deleted: BTreeSet<Path>,
        markers: u64,
        tally: Tally,
    }

    impl World {
        fn new() -> World {
            let dir = TempDir::new().expect("tempdir");
            let db = Database::create(&options(dir.path())).expect("create");
            World {
                dir,
                db: Some(db),
                committed: Model::new(),
                flushed: Model::new(),
                readers: Vec::new(),
                ever_deleted: BTreeSet::new(),
                markers: 0,
                tally: Tally::default(),
            }
        }

        fn db(&self) -> &Database {
            self.db.as_ref().expect("open")
        }

        /// Every open reader against the buckets committed when it began,
        /// and a new one against those committed now.
        fn check_readers(&mut self, context: &str) {
            for (i, (reader, then)) in self.readers.iter().enumerate() {
                if *then != self.committed {
                    self.tally.outlived_readers += 1;
                }
                check_reader(reader, then, &format!("{context}: reader {i}"));
            }
            let reader = self.db().begin(false).expect("begin read");
            check_reader(
                &reader,
                &self.committed,
                &format!("{context}: a new reader"),
            );
        }

        /// A path to act on: more often than not one the model holds, or
        /// a child of one, so that deletes find buckets and creates find
        /// parents.
        fn pick(&self, rng: &mut SplitMix64, model: &Model) -> Path {
            let held: Vec<&Path> = model
                .buckets
                .keys()
                .filter(|path| path[0] != BLOCK_IDX_BUCKET_NAME)
                .collect();
            let mut path = if !held.is_empty() && rng.below(4) > 0 {
                held[rng.below(held.len() as u64) as usize].clone()
            } else {
                Vec::new()
            };
            if path.is_empty() || (path.len() < DEPTH && rng.below(2) == 0) {
                path.push(NAMES[rng.below(NAMES.len() as u64) as usize]);
            }
            path
        }

        /// One writable transaction of a few random steps, checked after
        /// each, then committed, rolled back or dropped while open.
        fn write(&mut self, rng: &mut SplitMix64, context: &str) {
            let tx = self.db().begin(true).expect("begin write");
            let mut model = self.committed.clone();
            let mut created_here: BTreeSet<Path> = BTreeSet::new();
            let mut deleted_here: Vec<Path> = Vec::new();
            let mut changed = false;
            check(&tx, &model, &format!("{context}: a new writer"));
            for _ in 0..=rng.below(5) {
                let path = self.pick(rng, &model);
                match rng.below(10) {
                    0..=3 => {
                        let made = if rng.below(2) == 0 {
                            create(&tx, &mut model, &path, context)
                        } else {
                            create_if_missing(&tx, &mut model, &path, context)
                        };
                        if made {
                            changed = true;
                            self.tally.created += 1;
                            if path.len() > 1 {
                                self.tally.nested += 1;
                            }
                            if self.ever_deleted.contains(&path) || deleted_here.contains(&path) {
                                self.tally.created_again += 1;
                            }
                            self.markers += 1;
                            if rng.below(4) > 0 {
                                mark(&tx, &mut model, &path, self.markers);
                            }
                            created_here.insert(path);
                        }
                    }
                    4..=6 => {
                        if delete(&tx, &mut model, &path, context) {
                            changed = true;
                            self.tally.deleted += 1;
                            if created_here.contains(&path) {
                                self.tally.created_and_deleted_in_one += 1;
                            }
                            deleted_here.push(path);
                        }
                    }
                    _ => {
                        self.markers += 1;
                        mark(&tx, &mut model, &path, self.markers);
                    }
                }
                check(&tx, &model, &format!("{context}: a writer after a step"));
            }
            match rng.below(6) {
                0 => {
                    tx.rollback().expect("rollback");
                    if changed {
                        self.tally.rolled_back += 1;
                    }
                }
                // Dropped while open, which is a rollback without the
                // call.
                1 => {
                    drop(tx);
                    if changed {
                        self.tally.dropped_open += 1;
                    }
                }
                _ => {
                    tx.commit().expect("commit");
                    self.committed = model;
                    self.ever_deleted.extend(deleted_here);
                }
            }
        }

        /// Close every reader and the database, cleanly or as a process
        /// that died would leave it, and open it again.
        fn reopen(&mut self, clean: bool) {
            self.check_readers("before a reopen");
            self.readers.clear();
            let db = self.db.take().expect("open");
            if clean {
                db.close().expect("close");
                self.flushed = self.committed.clone();
                self.tally.clean_reopens += 1;
            } else {
                self.committed = self.flushed.clone();
                self.tally.unclean_reopens += 1;
            }
            drop(db);
            self.db = Some(Database::open(&options(self.dir.path())).expect("reopen"));
        }
    }

    /// The differential test: random histories of creates, nested
    /// creates, deletes, commits, rollbacks, writers dropped while open,
    /// readers held across later commits, flushes, and clean and unclean
    /// reopens, with every lookup from every open transaction compared at
    /// every step with the read of its row and with the model.
    #[test]
    fn a_lookup_is_the_read_of_its_row_over_random_histories() {
        let mut rng = SplitMix64::from_entropy("bucket-index-random-histories");
        let mut world = World::new();
        for step in 0..1500u32 {
            let context = format!("step {step}");
            match rng.below(100) {
                0..=54 => world.write(&mut rng, &context),
                55..=69 => {
                    if world.readers.len() < 4 {
                        let reader = world.db().begin(false).expect("begin read");
                        world.readers.push((reader, world.committed.clone()));
                    }
                }
                70..=79 => {
                    if !world.readers.is_empty() {
                        let i = rng.below(world.readers.len() as u64) as usize;
                        let (reader, then) = world.readers.swap_remove(i);
                        check_reader(&reader, &then, &format!("{context}: a reader let go"));
                    }
                }
                80..=89 => {
                    world.db().flush().expect("flush");
                    world.flushed = world.committed.clone();
                    world.tally.flushes += 1;
                }
                90..=94 => world.reopen(true),
                _ => world.reopen(false),
            }
            world.check_readers(&context);
        }
        let t = &world.tally;
        for (what, count) in [
            ("created", t.created),
            ("nested", t.nested),
            ("deleted", t.deleted),
            ("created again", t.created_again),
            ("created and deleted in one", t.created_and_deleted_in_one),
            ("rolled back", t.rolled_back),
            ("dropped open", t.dropped_open),
            ("outlived readers", t.outlived_readers),
            ("flushes", t.flushes),
            ("clean reopens", t.clean_reopens),
            ("unclean reopens", t.unclean_reopens),
        ] {
            assert!(count > 0, "the history never reached: {what} ({t:?})");
        }
    }

    /// One step of the power-cut script: a commit that creates or deletes
    /// one bucket, or a flush.
    enum Step {
        Create(&'static [&'static [u8]]),
        Delete(&'static [&'static [u8]]),
        Flush,
    }

    /// Buckets created, nested, deleted with what they hold and created
    /// again, across four flushes, the last one closing the script.
    const SCRIPT: &[Step] = &[
        Step::Create(&[b"a"]),
        Step::Create(&[b"b"]),
        Step::Create(&[b"a", b"a"]),
        Step::Flush,
        Step::Create(&[b"b", b"a"]),
        Step::Delete(&[b"a"]),
        Step::Flush,
        Step::Create(&[b"a"]),
        Step::Create(&[b"a", b"b"]),
        Step::Delete(&[b"b"]),
        Step::Create(&[b"b"]),
        Step::Flush,
        Step::Delete(&[b"a"]),
        Step::Create(&[b"a"]),
        Step::Flush,
    ];

    /// What one run of [`SCRIPT`] left behind.
    struct Cut {
        /// Storage operations the script made.
        ops: u64,
        power_failed: bool,
        /// The surviving store's buckets, as [`Model`] numbers them.
        survived: Model,
    }

    /// Run [`SCRIPT`] over a power-loss backend, with the power failing
    /// after `cut_after` storage operations when given; cut the power,
    /// reopen what is left and check every lookup in it.
    fn run_script(cut_after: Option<u64>) -> Cut {
        let dir = TempDir::new().expect("tempdir");
        let db_dir = dir.path().join("db");
        std::fs::create_dir_all(&db_dir).expect("mkdir");
        let backend = PowerLossBackend::create(&db_dir.join("metadata.redb"), true);
        let mut opts = options(dir.path());
        opts.backend = Some(Arc::clone(&backend) as SharedBackend);
        let db = Database::create(&opts).expect("create");

        let start = backend.ops();
        if let Some(n) = cut_after {
            backend.power_fails_after(n);
        }
        let mut model = Model::new();
        // The buckets as of the last flush that returned, and as of the
        // one the power failed in, whose commit may have been synced
        // before the operation that was refused.
        let mut settled = Model::new();
        let mut torn = None;
        for step in SCRIPT {
            let stepped = match step {
                Step::Create(path) => db.update(|tx| {
                    assert!(create(tx, &mut model, path, "the script"));
                    let marker = u64::from(model.last_id);
                    mark(tx, &mut model, path, marker);
                    Ok(())
                }),
                Step::Delete(path) => db.update(|tx| {
                    assert!(delete(tx, &mut model, path, "the script"));
                    Ok(())
                }),
                Step::Flush => {
                    let flushed = db.flush();
                    match flushed {
                        Ok(()) => settled = model.clone(),
                        Err(_) => torn = Some(model.clone()),
                    }
                    flushed
                }
            };
            if stepped.is_err() {
                break;
            }
        }
        let ops = backend.ops() - start;
        // Read before the drop: redb's own drop writes, and a cut placed
        // at the script's last operation refuses those, not the script's.
        let power_failed = backend.power_failed();
        drop(db);
        backend.cut_power();

        // Reopened without the backend: the file holds what was synced.
        let reopened = Database::open(&options(dir.path())).expect("reopen after the cut");
        let context = format!("power cut after {cut_after:?} storage operations");
        let survived = reopened
            .begin(false)
            .map(|tx| {
                let counter = tx
                    .fetch_raw(crate::transaction::CUR_BUCKET_ID_KEY)
                    .expect("a store has its bucket ID counter");
                let last_id = u32::from_be_bytes(counter.try_into().expect("four bytes"));
                [Some(settled), torn]
                    .into_iter()
                    .flatten()
                    .find(|m| m.last_id == last_id)
                    .unwrap_or_else(|| panic!("{context}: no flush left the counter at {last_id}"))
            })
            .expect("begin read");
        reopened
            .view(|tx| {
                check_reader(tx, &survived, &context);
                Ok(())
            })
            .expect("view");

        // The reopened map takes commits like the one that was lost.
        let mut after = survived.clone();
        reopened
            .update(|tx| {
                assert!(create(tx, &mut after, &[b"c"], &context));
                create_if_missing(tx, &mut after, &[b"a"], &context);
                assert!(create(tx, &mut after, &[b"a", b"c"], &context));
                delete(tx, &mut after, &[b"b"], &context);
                check(tx, &after, &context);
                Ok(())
            })
            .expect("update");
        reopened
            .view(|tx| {
                check_reader(tx, &after, &format!("{context}, then a commit"));
                Ok(())
            })
            .expect("view");
        Cut {
            ops,
            power_failed,
            survived,
        }
    }

    /// Cut the power at every storage operation of a run that creates,
    /// nests, deletes and re-creates buckets across four flushes, and
    /// after it; whichever flush survives, the reopened database's map is
    /// that flush's bucket index and every lookup is the read of its row.
    #[test]
    fn the_map_is_the_stores_after_a_power_cut_at_every_storage_operation() {
        let whole = run_script(None);
        assert!(!whole.power_failed);
        let flushes = SCRIPT.iter().filter(|s| matches!(s, Step::Flush)).count();
        assert!(
            whole.ops >= 2 * flushes as u64,
            "{} storage operations cannot be {flushes} flushes",
            whole.ops
        );

        let mut felt = 0u64;
        let mut survivors = BTreeSet::new();
        for n in 0..=whole.ops {
            let cut = run_script(Some(n));
            if cut.power_failed {
                felt += 1;
            }
            survivors.insert(cut.survived.last_id);
        }
        assert_eq!(
            run_script(Some(whole.ops)).survived,
            whole.survived,
            "a cut after the last operation loses nothing"
        );
        assert!(
            felt >= whole.ops,
            "only {felt} of {} cuts were felt",
            whole.ops
        );
        // The created store, and the store after each of the flushes.
        assert_eq!(
            survivors.len(),
            flushes + 1,
            "the cuts must leave every flushed state behind: {survivors:?}"
        );
    }

    /// Readers on other threads begin while a writer creates and deletes
    /// a bucket in commit after commit.  A reader's map and its snapshots
    /// are taken under one hold of the cache lock, so whichever commit a
    /// reader begins after, its lookup is the read of the row.  Each
    /// reader begins both ways a reader can, through `Database::begin`
    /// and through `Database::view`, and has to see the bucket come and
    /// go through each.
    #[test]
    fn a_reader_beginning_beside_commits_holds_the_map_of_its_snapshot() {
        const READERS: usize = 3;
        const IDS_TO_SEE: usize = 40;
        const BEGINS_AT_MOST: u32 = 20_000_000;

        let dir = TempDir::new().expect("tempdir");
        let db = Database::create(&options(dir.path())).expect("create");
        let done = Arc::new(AtomicBool::new(false));
        let writer = {
            let db = db.clone();
            let done = Arc::clone(&done);
            std::thread::spawn(move || {
                let mut commits = 0u64;
                while !done.load(Ordering::SeqCst) {
                    db.update(|tx| {
                        let meta = tx.metadata();
                        match meta.bucket(b"x") {
                            Some(_) => meta.delete_bucket(b"x"),
                            None => meta.create_bucket(b"x").map(|_| ()),
                        }
                    })
                    .expect("update");
                    commits += 1;
                }
                commits
            })
        };
        let readers: Vec<_> = (0..READERS)
            .map(|_| {
                let db = db.clone();
                std::thread::spawn(move || {
                    let look = |tx: &Transaction| {
                        let meta = tx.metadata();
                        let id = meta.bucket(b"x").map(|b| b.raw_id());
                        let read = meta.bucket_from_rows(b"x").map(|b| b.raw_id());
                        assert_eq!(id, read, "a reader's map is of another commit");
                        id
                    };
                    // What the readers begun each way have seen: the IDs
                    // the bucket had, and how often it was not there.
                    let mut ids = [BTreeSet::new(), BTreeSet::new()];
                    let mut absent = [0u32; 2];
                    for n in 0..BEGINS_AT_MOST {
                        let way = (n % 2) as usize;
                        let id = if way == 0 {
                            look(&db.begin(false).expect("begin read"))
                        } else {
                            let mut seen = None;
                            db.view(|tx| {
                                seen = Some(look(tx));
                                Ok(())
                            })
                            .expect("view");
                            seen.expect("the view ran")
                        };
                        match id {
                            Some(id) => {
                                ids[way].insert(id);
                            }
                            None => absent[way] += 1,
                        }
                        if ids.iter().all(|ids| ids.len() >= IDS_TO_SEE)
                            && absent.iter().all(|absent| *absent > 0)
                        {
                            return true;
                        }
                    }
                    false
                })
            })
            .collect();
        let saw_enough: Vec<bool> = readers
            .into_iter()
            .map(|reader| reader.join().expect("reader"))
            .collect();
        done.store(true, Ordering::SeqCst);
        let commits = writer.join().expect("writer");
        assert!(
            saw_enough.iter().all(|saw| *saw),
            "a reader did not see {IDS_TO_SEE} buckets come and go each way over {commits} commits"
        );
    }

    /// A reader that begins while a writer holds uncommitted bucket
    /// changes, and one that begins inside that writer's commit, in an
    /// `on_commit` hook, which runs after the commit's own flush and
    /// before its rows are published, both hold the map of the commits
    /// their snapshots hold: neither sees a bucket the writer has staged.
    #[test]
    fn a_reader_beginning_beside_uncommitted_buckets_holds_the_committed_map() {
        let dir = TempDir::new().expect("tempdir");
        let db = Database::create(&options(dir.path())).expect("create");
        let mut model = Model::new();
        db.update(|tx| {
            assert!(create(tx, &mut model, &[b"a"], "setup"));
            assert!(create(tx, &mut model, &[b"a", b"b"], "setup"));
            mark(tx, &mut model, &[b"a", b"b"], 1);
            Ok(())
        })
        .expect("update");
        let committed = model.clone();

        let tx = db.begin(true).expect("begin write");
        assert!(delete(&tx, &mut model, &[b"a"], "staged"));
        assert!(create(&tx, &mut model, &[b"c"], "staged"));
        assert!(create(&tx, &mut model, &[b"a"], "staged"));
        check(&tx, &model, "the writer's own staged buckets");
        let beside = db.begin(false).expect("begin read");
        check_reader(
            &beside,
            &committed,
            "a reader begun beside uncommitted buckets",
        );
        let ran = Arc::new(AtomicBool::new(false));
        {
            let db = db.clone();
            let committed = committed.clone();
            let ran = Arc::clone(&ran);
            tx.on_commit(move || {
                let inside = db.begin(false).expect("begin read in the hook");
                check_reader(&inside, &committed, "a reader begun inside the commit");
                ran.store(true, Ordering::SeqCst);
            })
            .expect("register the hook");
        }
        tx.commit().expect("commit");
        drop(tx);
        assert!(ran.load(Ordering::SeqCst), "the commit ran its hook");
        check_reader(&beside, &committed, "that reader, after the commit");
        db.view(|tx| {
            check_reader(tx, &model, "a reader begun after the commit");
            Ok(())
        })
        .expect("view");
    }

    /// A flush participant with nothing to write.
    struct Idle;

    impl crate::FlushParticipant for Idle {
        fn wants_flush(&self) -> bool {
            false
        }

        fn has_work(&self) -> bool {
            false
        }

        fn contribute(
            &self,
            _: &mut crate::FlushWriter<'_, '_>,
        ) -> Result<crate::ParticipantStats, crate::Error> {
            Ok(crate::ParticipantStats::default())
        }

        fn finished(&self, _: bool) {}
    }

    /// Buckets to stage in a writable transaction whose commit is then
    /// made to fail: a create, a create nested in it, and the delete of a
    /// committed bucket with one nested in it.  `model` is left as the
    /// transaction then sees it; the model of what is committed is the
    /// caller's to keep.
    fn stage_buckets(tx: &Transaction, model: &mut Model, context: &str) {
        assert!(create(tx, model, &[b"c"], context));
        assert!(create(tx, model, &[b"c", b"a"], context));
        mark(tx, model, &[b"c", b"a"], 99);
        assert!(delete(tx, model, &[b"b"], context));
        check(tx, model, context);
    }

    /// The buckets [`stage_buckets`] needs committed, with markers.
    fn commit_buckets_to_stage_over(db: &Database, model: &mut Model) {
        db.update(|tx| {
            for (marker, path) in [&[b"a" as &[u8]][..], &[b"b"], &[b"b", b"a"]]
                .into_iter()
                .enumerate()
            {
                assert!(create(tx, model, path, "setup"));
                mark(tx, model, path, marker as u64);
            }
            Ok(())
        })
        .expect("update");
    }

    /// After a commit that failed and left the store open for writes: no
    /// reader, old or new, sees a bucket the failed transaction staged,
    /// and the next writer is handed the IDs it had taken.
    fn check_after_a_failed_commit(
        db: &Database,
        before: &Transaction,
        model: &mut Model,
        context: &str,
    ) {
        assert!(!db.is_fatal(), "{context}: the store takes writes");
        check_reader(before, model, &format!("{context}: a reader from before"));
        db.view(|tx| {
            check_reader(tx, model, &format!("{context}: a new reader"));
            Ok(())
        })
        .expect("view");
        db.update(|tx| {
            check(tx, model, &format!("{context}: the next writer"));
            // `create` requires the ID the model gives, and the model
            // never saw the failed transaction's buckets.
            stage_buckets(tx, model, &format!("{context}: the next writer"));
            Ok(())
        })
        .expect("update");
        db.view(|tx| {
            check_reader(tx, model, &format!("{context}: after the next commit"));
            Ok(())
        })
        .expect("view");
    }

    /// A commit refused for staging a row under a flush participant's
    /// prefix is a rollback that leaves the store open for writes, so a
    /// map it had changed would be served to every later transaction: no
    /// bucket the refused transaction created or deleted is in any.
    #[test]
    fn a_commit_refused_for_a_participants_prefix_changes_no_lookup() {
        let dir = TempDir::new().expect("tempdir");
        let db = Database::create(&options(dir.path())).expect("create");
        let mut model = Model::new();
        commit_buckets_to_stage_over(&db, &mut model);
        // Registration refuses a prefix with rows waiting in the overlay.
        db.flush().expect("flush");
        let prefix = model.buckets[&vec![b"a" as &[u8]]].0.to_be_bytes();
        db.set_flush_participant(&prefix, Arc::new(Idle))
            .expect("register");

        let before = db.begin(false).expect("begin read");
        let tx = db.begin(true).expect("begin write");
        stage_buckets(&tx, &mut model.clone(), "staged for a refused commit");
        resolve(&tx, &[b"a"])
            .expect("the participant's bucket")
            .put(b"row", b"under the participant's prefix")
            .expect("put");
        let refused = tx.commit().expect_err("the commit must be refused");
        assert_eq!(refused.kind, ErrorKind::IncompatibleValue, "{refused}");
        drop(tx);
        check_after_a_failed_commit(&db, &before, &mut model, "a refused commit");
    }

    /// Whether the process can create files in a directory it has made
    /// read-only, as root can: a test that needs the create to fail has
    /// nothing to run there.
    #[cfg(unix)]
    fn mode_bits_are_ignored(dir: &FsPath) -> bool {
        use std::os::unix::fs::PermissionsExt;
        let probe = dir.join("probe");
        std::fs::create_dir(&probe).expect("mkdir probe");
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o555)).expect("chmod");
        let ignored = std::fs::write(probe.join("x"), b"x").is_ok();
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        ignored
    }

    /// A commit whose block write fails rolls the block files back and
    /// leaves the store open for writes, like a refused one: no bucket
    /// the failed transaction created or deleted is in any map.
    #[cfg(unix)]
    #[test]
    fn a_commit_whose_block_write_fails_changes_no_lookup() {
        use std::os::unix::fs::PermissionsExt;

        const BLOCK_LEN: usize = 400;
        /// A raw block whose header is unique to `seed`, and its hash.
        fn raw_block(seed: u8) -> (dcroxide_chainhash::Hash, Vec<u8>) {
            let mut raw = vec![seed; BLOCK_LEN];
            raw[1] = seed.wrapping_mul(31);
            (dcroxide_chainhash::hash_h(&raw[..180]), raw)
        }

        let dir = TempDir::new().expect("tempdir");
        if mode_bits_are_ignored(dir.path()) {
            eprintln!("skipping: running as a user that ignores directory modes");
            return;
        }
        let mut opts = options(dir.path());
        // Two records to a block file: each is the block and twelve bytes
        // of network, length and checksum.
        opts.max_block_file_size = (2 * (BLOCK_LEN + 12)) as u32;
        let db = Database::create(&opts).expect("create");
        let mut model = Model::new();
        commit_buckets_to_stage_over(&db, &mut model);
        for seed in [1, 2] {
            let (hash, raw) = raw_block(seed);
            db.update(|tx| tx.store_block_raw(&hash, raw.clone()))
                .expect("store a block");
        }

        // The third block goes to a second file, which cannot be created.
        let before = db.begin(false).expect("begin read");
        let tx = db.begin(true).expect("begin write");
        stage_buckets(&tx, &mut model.clone(), "staged beside a block");
        let (hash, raw) = raw_block(3);
        tx.store_block_raw(&hash, raw).expect("stage the block");
        let path = dir.path().join("db");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o555)).expect("chmod");
        let failed = tx.commit();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        drop(tx);
        assert!(failed.is_err(), "creating the second block file must fail");
        check_after_a_failed_commit(&db, &before, &mut model, "a failed block write");
    }

    /// A commit whose own flush fails latches the store and publishes
    /// nothing.  Readers still begin on a latched store, and each holds
    /// the map of the last commit that succeeded.
    #[test]
    fn a_commit_whose_flush_fails_changes_no_lookup() {
        let dir = TempDir::new().expect("tempdir");
        let db_dir = dir.path().join("db");
        std::fs::create_dir_all(&db_dir).expect("mkdir");
        let backend = PowerLossBackend::create(&db_dir.join("metadata.redb"), true);
        let mut opts = options(dir.path());
        // Every commit flushes what the commits before it left in the
        // overlay, so the commit below makes a durable write.
        opts.cache_flush_interval_secs = 0;
        opts.backend = Some(Arc::clone(&backend) as SharedBackend);
        let db = Database::create(&opts).expect("create");
        let mut model = Model::new();
        commit_buckets_to_stage_over(&db, &mut model);
        let before = db.begin(false).expect("begin read");
        check_reader(&before, &model, "before the failed flush");
        let held_before = before
            .held_bucket_index()
            .expect("an open transaction holds a bucket index");

        backend.power_fails_after(0);
        let tx = db.begin(true).expect("begin write");
        stage_buckets(&tx, &mut model.clone(), "staged for a commit that fails");
        tx.commit().expect_err("the commit's flush must fail");
        drop(tx);
        assert!(backend.power_failed(), "the flush was refused a write");
        assert!(db.is_fatal(), "a failed flush latches the store");

        // The store's rows cannot be the oracle from here on: redb fails
        // every read of a page it does not hold once a write has failed.
        // The map checked against them before the failure is.
        let after = db
            .begin(false)
            .expect("a latched store still begins readers");
        for (reader, context) in [(&before, "a reader from before"), (&after, "a new reader")] {
            let held = reader
                .held_bucket_index()
                .expect("an open transaction holds a bucket index");
            assert_eq!(
                *held, *held_before,
                "{context}: a commit whose flush failed changed the map"
            );
            for (path, (id, _)) in &model.buckets {
                assert_eq!(
                    resolve(reader, path).map(|b| b.raw_id()),
                    Some(id.to_be_bytes()),
                    "{context}: the lookup of {:?}",
                    show(path)
                );
            }
            assert!(resolve(reader, &[b"c"]).is_none(), "{context}");
        }
    }

    /// A writable transaction that waited for the writer takes its map
    /// once it holds the writer, with its snapshots.  The commit it
    /// waited for deleted a bucket and created it again and created or
    /// deleted another: the waiter resolves each name as that commit left
    /// it, and a row it puts through the lookup lands in the live bucket,
    /// not under the deleted bucket's ID.
    #[test]
    fn a_writer_that_waited_for_a_commit_holds_the_map_that_commit_left() {
        /// Rounds in which the second writer has to have waited.
        const ROUNDS: u32 = 3;
        const ATTEMPTS_AT_MOST: u32 = 40;
        /// How long the first writer waits for the second to queue behind
        /// it before it commits.
        const HOLD: std::time::Duration = std::time::Duration::from_millis(300);
        const ROW: &[u8] = b"from the waiter";

        let dir = TempDir::new().expect("tempdir");
        let db = Database::create(&options(dir.path())).expect("create");
        let mut model = Model::new();
        db.update(|tx| {
            assert!(create(tx, &mut model, &[b"a"], "setup"));
            Ok(())
        })
        .expect("update");

        let mut waited = 0;
        for attempt in 0.. {
            if waited == ROUNDS {
                break;
            }
            assert!(
                attempt < ATTEMPTS_AT_MOST,
                "the second writer queued behind the first in only {waited} of {attempt} attempts"
            );
            let context = format!("attempt {attempt}");
            let waits_before = db.inner.writer_waits().other.count;
            let holder = db.begin(true).expect("begin write");
            let (started, waiter_started) = std::sync::mpsc::channel();
            let waiter = {
                let db = db.clone();
                std::thread::spawn(move || {
                    started.send(()).expect("signal");
                    let tx = db.begin(true).expect("begin write, after the wait");
                    let meta = tx.metadata();
                    let found = [b"a", b"b"].map(|name| {
                        (
                            meta.bucket(name).map(|b| b.raw_id()),
                            meta.bucket_from_rows(name).map(|b| b.raw_id()),
                        )
                    });
                    meta.bucket(b"a")
                        .expect("the bucket the first writer created again")
                        .put(ROW, &attempt.to_be_bytes())
                        .expect("put");
                    tx.commit().expect("commit");
                    found
                })
            };
            // The waiter is running and about to ask for the writer.
            waiter_started.recv().expect("waiter started");
            std::thread::sleep(HOLD);
            assert!(delete(&holder, &mut model, &[b"a"], &context));
            assert!(create(&holder, &mut model, &[b"a"], &context));
            if model.has(&[b"b"]) {
                assert!(delete(&holder, &mut model, &[b"b"], &context));
            } else {
                assert!(create(&holder, &mut model, &[b"b"], &context));
            }
            holder.commit().expect("commit");
            drop(holder);
            let found = waiter.join().expect("waiter");
            if db.inner.writer_waits().other.count > waits_before {
                waited += 1;
            }

            // Whether or not it had to wait, the second writer began
            // after the first one's commit.
            for (name, (id, read)) in [b"a", b"b"].into_iter().zip(found) {
                assert_eq!(
                    id,
                    read,
                    "{context}: the second writer's lookup of {:?} is not the read of its row",
                    show(&[name])
                );
                assert_eq!(
                    id,
                    model
                        .buckets
                        .get(&vec![name as &[u8]])
                        .map(|(id, _)| id.to_be_bytes()),
                    "{context}: the second writer's lookup of {:?} is not the model's",
                    show(&[name])
                );
            }
            // A flush retires the overlay, so the row is read from the
            // store under the live bucket's ID.
            db.flush().expect("flush");
            db.view(|tx| {
                check_reader(tx, &model, &context);
                assert_eq!(
                    resolve(tx, &[b"a"]).expect("a").get(ROW),
                    Some(attempt.to_be_bytes().to_vec()),
                    "{context}: the second writer's row is not in the bucket"
                );
                Ok(())
            })
            .expect("view");
        }
    }

    /// redb storage over a power-loss backend's file that counts the reads
    /// it serves and can be told to serve only so many more.
    #[derive(Debug)]
    struct ReadFaults {
        inner: Arc<PowerLossBackend>,
        reads: AtomicU64,
        /// Reads to serve before failing every later one; negative for no
        /// limit.
        reads_left: AtomicI64,
        refused: AtomicBool,
    }

    impl ReadFaults {
        fn over(path: &FsPath) -> Arc<ReadFaults> {
            Arc::new(ReadFaults {
                inner: PowerLossBackend::create(path, true),
                reads: AtomicU64::new(0),
                reads_left: AtomicI64::new(-1),
                refused: AtomicBool::new(false),
            })
        }

        /// Serve `n` more reads, then fail every later one; negative for
        /// no limit.
        fn allow_reads(&self, n: i64) {
            self.refused.store(false, Ordering::SeqCst);
            self.reads_left.store(n, Ordering::SeqCst);
        }

        fn reads(&self) -> u64 {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl redb::StorageBackend for ReadFaults {
        fn len(&self) -> Result<u64, std::io::Error> {
            redb::StorageBackend::len(&*self.inner)
        }

        fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), std::io::Error> {
            let admitted = self
                .reads_left
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| match left {
                    0 => None,
                    n if n > 0 => Some(n - 1),
                    n => Some(n),
                });
            if admitted.is_err() {
                self.refused.store(true, Ordering::SeqCst);
                return Err(std::io::Error::other("injected read failure"));
            }
            self.reads.fetch_add(1, Ordering::SeqCst);
            redb::StorageBackend::read(&*self.inner, offset, out)
        }

        fn set_len(&self, len: u64) -> Result<(), std::io::Error> {
            redb::StorageBackend::set_len(&*self.inner, len)
        }

        fn sync_data(&self) -> Result<(), std::io::Error> {
            redb::StorageBackend::sync_data(&*self.inner)
        }

        fn write(&self, offset: u64, data: &[u8]) -> Result<(), std::io::Error> {
            redb::StorageBackend::write(&*self.inner, offset, data)
        }
    }

    /// A store over [`ReadFaults`] with no page cache, so that every page
    /// a lookup needs beneath a tree's root is read from the backend, and
    /// with enough rows that the metadata table's root is a branch: redb
    /// keeps a tree's root for the transaction's life.  The buckets and
    /// rows are flushed, so no lookup is answered by the overlay.
    fn faulty_store(dir: &FsPath) -> (Options, Arc<ReadFaults>, Database) {
        let db_dir = dir.join("db");
        std::fs::create_dir_all(&db_dir).expect("mkdir");
        let backend = ReadFaults::over(&db_dir.join("metadata.redb"));
        let mut opts = options(dir);
        opts.db_cache_bytes = 0;
        opts.backend = Some(Arc::clone(&backend) as SharedBackend);
        let db = Database::create(&opts).expect("create");
        db.update(|tx| {
            let rows = tx.metadata().create_bucket(b"rows")?;
            for i in 0..2000u32 {
                rows.put(&i.to_be_bytes(), &[0x5a; 64])?;
            }
            let nested = rows.create_bucket(b"nested")?;
            nested.put(b"key", b"value")?;
            tx.metadata().create_bucket(b"other")?;
            Ok(())
        })
        .expect("fill");
        db.flush().expect("flush to the store");
        (opts, backend, db)
    }

    /// A lookup reads nothing from the store, where the read of the row
    /// reads it every time; and so a store read error, which the read of
    /// the row turns into "no such bucket", is met by the first read of a
    /// row in the bucket instead.  That holds for a writable transaction
    /// as for a read-only one: before it has staged anything, which is
    /// how a block's connect makes its lookups, with rows staged, and
    /// with buckets of its own created and deleted, when its pending
    /// changes are asked before the map.
    #[test]
    fn a_lookup_reads_nothing_from_the_store() {
        const LOOKUPS: u32 = 500;
        let dir = TempDir::new().expect("tempdir");
        let (_opts, backend, db) = faulty_store(dir.path());

        let tx = db.begin(true).expect("begin write");
        let meta = tx.metadata();
        // The reads `LOOKUPS` rounds of lookups make, with the buckets
        // `new` and `other` there or not.
        let lookup_reads = |new: bool, other: bool| {
            let before = backend.reads();
            for _ in 0..LOOKUPS {
                let rows = meta.bucket(b"rows").expect("rows");
                assert!(rows.bucket(b"nested").is_some());
                assert_eq!(meta.bucket(b"other").is_some(), other);
                assert_eq!(meta.bucket(b"new").is_some(), new);
                assert!(meta.bucket(b"none").is_none());
                assert!(rows.bucket(b"none").is_none());
            }
            backend.reads() - before
        };
        assert_eq!(
            lookup_reads(false, true),
            0,
            "a writer with nothing staged read the store for its lookups"
        );
        meta.bucket(b"rows")
            .expect("rows")
            .put(b"staged", b"row")
            .expect("put");
        assert_eq!(
            lookup_reads(false, true),
            0,
            "a writer with rows staged read the store for its lookups"
        );
        meta.create_bucket(b"new").expect("create");
        meta.delete_bucket(b"other").expect("delete");
        assert_eq!(
            lookup_reads(true, false),
            0,
            "a writer with buckets staged read the store for its lookups"
        );
        // The rig counts a writer's reads: those of the rows the same
        // lookups were.
        let before = backend.reads();
        for _ in 0..LOOKUPS {
            let rows = meta.bucket_from_rows(b"rows").expect("rows");
            assert!(rows.bucket_from_rows(b"nested").is_some());
        }
        let row_reads = backend.reads() - before;
        assert!(
            row_reads >= u64::from(LOOKUPS),
            "{LOOKUPS} reads of two bucket index rows by a writer read the store {row_reads} times"
        );
        tx.rollback().expect("rollback");
        drop(tx);

        db.view(|tx| {
            let meta = tx.metadata();
            let before = backend.reads();
            for _ in 0..LOOKUPS {
                let rows = meta.bucket(b"rows").expect("rows");
                assert!(rows.bucket(b"nested").is_some());
                assert!(meta.bucket(b"other").is_some());
                assert!(meta.bucket(b"none").is_none());
                assert!(rows.bucket(b"none").is_none());
            }
            assert_eq!(backend.reads() - before, 0, "bucket lookups read the store");

            // The rig does count the read each of those lookups was.
            let before = backend.reads();
            for _ in 0..LOOKUPS {
                let rows = meta.bucket_from_rows(b"rows").expect("rows");
                assert!(rows.bucket_from_rows(b"nested").is_some());
            }
            let row_reads = backend.reads() - before;
            assert!(
                row_reads >= u64::from(LOOKUPS),
                "{LOOKUPS} reads of two bucket index rows each read the store {row_reads} times"
            );

            backend.allow_reads(0);
            assert_eq!(
                meta.bucket_from_rows(b"rows").map(|b| b.raw_id()),
                None,
                "the read of the row answers a read error as ffldb does: no such bucket"
            );
            let rows = meta
                .bucket(b"rows")
                .expect("the lookup makes no read to fail");
            let nested = rows.bucket(b"nested").expect("nested");
            assert_eq!(
                nested.get(b"key"),
                None,
                "the read of a row in the bucket meets the error: absence, as ffldb reads it"
            );
            assert!(
                nested.try_get(b"key").is_err(),
                "and an error where the read reports one"
            );
            backend.allow_reads(-1);
            Ok(())
        })
        .expect("view");
    }

    /// Creating and deleting a bucket still read its index row, and read
    /// a store read error as a missing row, as ffldb's do.  Beside a
    /// lookup that finds the bucket, the delete then reports no such
    /// bucket and the create does not find it there, while a
    /// create-if-missing, which looks the bucket up first, returns it.
    #[test]
    fn a_read_error_is_a_missing_row_to_a_create_and_a_delete_and_not_to_the_lookup() {
        let dir = TempDir::new().expect("tempdir");
        let (_opts, backend, db) = faulty_store(dir.path());
        let tx = db.begin(true).expect("begin write");
        let meta = tx.metadata();

        backend.allow_reads(0);
        assert_eq!(
            meta.bucket_from_rows(b"rows").map(|b| b.raw_id()),
            None,
            "the bucket's index row cannot be read"
        );
        assert!(backend.refused.load(Ordering::SeqCst));
        let found = meta
            .bucket(b"rows")
            .expect("the lookup makes no read to fail");
        assert_eq!(found.raw_id(), [0, 0, 0, 2]);
        assert_eq!(
            meta.delete_bucket(b"rows").map_err(|e| e.kind),
            Err(ErrorKind::BucketNotFound),
            "the delete reads the row"
        );
        // The create reads the row as missing too and goes on to the
        // bucket ID counter, which cannot be read either.
        assert_eq!(
            meta.create_bucket(b"rows")
                .map(|b| b.raw_id())
                .map_err(|e| e.kind),
            Err(ErrorKind::Corruption),
            "the create reads the row"
        );
        assert_eq!(
            meta.create_bucket_if_not_exists(b"rows")
                .map(|b| b.raw_id())
                .map_err(|e| e.kind),
            Ok([0, 0, 0, 2]),
            "the create-if-missing looks the bucket up"
        );
        assert_eq!(
            meta.bucket(b"rows").map(|b| b.raw_id()),
            Some([0, 0, 0, 2]),
            "nothing was staged for the bucket"
        );
        tx.rollback().expect("rollback");
    }

    /// The difference a store read error makes is met after a failed
    /// write as well.  A flush that fails leaves redb refusing every read
    /// of a page it does not hold, so from then on the read of a bucket's
    /// index row answers "no such bucket" without asking the storage,
    /// where the lookup finds the bucket.
    #[test]
    fn after_a_failed_flush_the_lookup_finds_a_bucket_whose_row_is_refused() {
        let dir = TempDir::new().expect("tempdir");
        let (_opts, backend, db) = faulty_store(dir.path());
        db.update(|tx| tx.metadata().put(b"key", b"waiting in the overlay"))
            .expect("update");
        let reader = db.begin(false).expect("begin read");
        let meta = reader.metadata();
        assert_eq!(
            meta.bucket_from_rows(b"rows").map(|b| b.raw_id()),
            Some([0, 0, 0, 2]),
            "the row is read while the storage works"
        );

        backend.inner.power_fails_after(0);
        db.flush().expect_err("the flush must fail");
        assert!(db.is_fatal(), "a failed flush latches the store");
        let reads = backend.reads();
        assert_eq!(
            meta.bucket_from_rows(b"rows").map(|b| b.raw_id()),
            None,
            "redb refuses the read of the row's page"
        );
        assert_eq!(backend.reads(), reads, "and asks the storage for nothing");
        assert_eq!(
            meta.bucket(b"rows").map(|b| b.raw_id()),
            Some([0, 0, 0, 2]),
            "the lookup makes no read to refuse"
        );
    }

    /// The open reads the bucket index, and an open that cannot read all
    /// of it fails: whatever number of reads the storage serves before it
    /// starts failing them, the open either fails or holds the whole map.
    #[test]
    fn an_open_that_cannot_read_the_bucket_index_fails() {
        const ATTEMPTS_AT_MOST: i64 = 20_000;
        let dir = TempDir::new().expect("tempdir");
        let (opts, backend, db) = faulty_store(dir.path());
        let whole = db
            .begin(false)
            .expect("begin read")
            .held_bucket_index()
            .expect("an open transaction holds a bucket index");
        assert_eq!(
            whole.get(METADATA_BUCKET_ID, b"rows"),
            Some([0, 0, 0, 2]),
            "the store's bucket index is not empty"
        );
        db.close().expect("close");
        drop(db);

        let mut failed = 0u32;
        let mut reads_served = None;
        for n in 0..ATTEMPTS_AT_MOST {
            backend.allow_reads(n);
            let opened = Database::open(&opts);
            let refused = backend.refused.load(Ordering::SeqCst);
            backend.allow_reads(-1);
            match opened {
                Err(_) => {
                    assert!(refused, "an open failed with every read served");
                    failed += 1;
                }
                Ok(db) => {
                    let held = db
                        .begin(false)
                        .expect("begin read")
                        .held_bucket_index()
                        .expect("an open transaction holds a bucket index");
                    assert_eq!(
                        held, whole,
                        "an open served {n} reads returned without the whole bucket index"
                    );
                    drop(db);
                    if !refused {
                        reads_served = Some(n);
                        break;
                    }
                }
            }
        }
        assert!(
            reads_served.is_some(),
            "no open succeeded within {ATTEMPTS_AT_MOST} reads"
        );
        assert!(failed > 0, "no open was refused a read it needed");
    }

    /// A store with no metadata table loads as the empty map, which is
    /// what a transaction reads from one.  No open gets that far: the
    /// reconciliation refuses such a store for its missing write cursor.
    #[test]
    fn a_store_without_its_metadata_table_loads_as_no_buckets() {
        let dir = TempDir::new().expect("tempdir");
        let kv = redb::Database::create(dir.path().join("bare.redb")).expect("bare redb file");
        assert_eq!(
            BucketIndex::load(&kv).expect("load"),
            BucketIndex::default()
        );
    }

    /// The load reads the bucket index and not the rows that sort before
    /// it, which are every bucket's: what an open reads for the map does
    /// not grow with the table.
    #[test]
    fn the_load_reads_the_bucket_index_and_not_the_rows_before_it() {
        /// The store reads of one load, over a table holding `rows` rows
        /// in a bucket.
        fn load_reads(rows: u32) -> u64 {
            let dir = TempDir::new().expect("tempdir");
            let db_dir = dir.path().join("db");
            std::fs::create_dir_all(&db_dir).expect("mkdir");
            let backend = ReadFaults::over(&db_dir.join("metadata.redb"));
            let mut opts = options(dir.path());
            opts.db_cache_bytes = 0;
            opts.backend = Some(Arc::clone(&backend) as SharedBackend);
            let db = Database::create(&opts).expect("create");
            db.update(|tx| {
                let bucket = tx.metadata().create_bucket(b"rows")?;
                for i in 0..rows {
                    bucket.put(&i.to_be_bytes(), &[0x5a; 64])?;
                }
                Ok(())
            })
            .expect("fill");
            db.flush().expect("flush to the store");
            let before = backend.reads();
            let index = BucketIndex::load(&db.inner.kv).expect("load");
            let reads = backend.reads() - before;
            assert_eq!(index.get(METADATA_BUCKET_ID, b"rows"), Some([0, 0, 0, 2]));
            reads
        }
        let few = load_reads(2_000);
        let many = load_reads(40_000);
        assert!(few > 0, "the rig counted no read of the bucket index");
        // A deeper tree costs a load a page or two more; walking the
        // bucket's rows would cost it hundreds.
        assert!(
            many <= few + 8,
            "the load over a table twenty times the size read the store {many} times, against {few}"
        );
    }
}
