// SPDX-License-Identifier: ISC
//! Flush participants: rows written inside the metadata flush's own redb
//! transaction instead of through the overlay ([ADR-0011]).
//!
//! Every row a transaction commits normally waits in the overlay (dcrd
//! ffldb's `dbCache`) and reaches redb when the overlay flushes.  A
//! participant skips the overlay: it keeps its own state in memory and,
//! once per flush, writes rows straight into the flush's write
//! transaction, after the overlay's rows and before the commit.  Its rows
//! and the chain's therefore land in one `Durability::Immediate` commit,
//! and a power cut keeps both or neither.  The participant never opens a
//! transaction of its own: the database calls it, inside a transaction
//! `begin_durable_write` opened.
//!
//! A participant owns one key prefix.  Its rows live under it and nothing
//! else may: the overlay never holds a row there while the participant is
//! registered, because a stale overlay entry would shadow the
//! participant's newer row for every reader.  Three checks hold that line.
//! [`crate::Database::set_flush_participant`] refuses a prefix the overlay
//! already holds a row under, a commit that stages a row under it is
//! refused, and a flush whose capture holds one fails and latches the
//! store.  [`FlushWriter`] in turn refuses every key outside the prefix,
//! so a participant cannot write over the chain's rows.
//!
//! [ADR-0011]: ../../../docs/adr/0011-exists-address-layout-3-and-the-flush-participant.md

use std::ops::Bound;
use std::sync::Arc;

use redb::ReadableTable as _;

use crate::error::{Error, ErrorKind, db_error};
use crate::{FlushPhase, Transaction, WriteLogSink};

/// A writer whose rows ride inside every metadata flush that has work for
/// it, in the same redb transaction as the overlay's rows.
///
/// Registered with [`crate::Database::set_flush_participant`]; at most one
/// at a time.
///
/// **Calling context.**  Every method is called on the thread running the
/// flush, which holds the database's writer semaphore and no other lock of
/// this crate: not the cache lock, not the block-store lock.  The
/// semaphore serializes the calls against each other, against every
/// writable transaction and its [`crate::Transaction::on_commit`] hooks,
/// and against registration.  So none of them may begin a writable
/// transaction, flush, close, or register or clear a participant on the
/// same database: each of those waits for the semaphore the caller holds,
/// and the thread deadlocks.  A read-only transaction would not deadlock,
/// but it reads the store as it stood before this flush; read through the
/// [`FlushWriter`] instead.
///
/// **No database handle inside.**  The database holds its participant by
/// a strong reference, so that its last flush on [`crate::Database::close`]
/// still reaches a participant whose owner has gone.  A participant that
/// held a `Database` clone would make a cycle: the store's file would stay
/// open, and locked, for the life of the process.
///
/// **Failure.**  An error from [`Self::contribute`] fails the flush, which
/// latches the store fatal exactly as a failed redb commit does
/// (`DbInner::mark_fatal`).  No later write on the handle succeeds, so a
/// participant never has to undo a half-written flush: what it wrote is
/// discarded with the transaction.
pub trait FlushParticipant: Send + Sync {
    /// Whether the next commit should flush even though the overlay's own
    /// thresholds (dcrd's `needsFlush`) have not tripped.
    ///
    /// Asked by every writable commit before its flush check, so it must
    /// be cheap.  Not asked by [`crate::Database::flush`] or
    /// [`crate::Database::close`], which flush regardless.
    fn wants_flush(&self) -> bool;

    /// Whether this flush should call [`Self::contribute`].
    ///
    /// Asked once per flush, after the block files are synced.  When it is
    /// false, the flush runs exactly as it would with no participant: an
    /// empty overlay commits nothing, a non-empty one commits its rows
    /// alone.  When it is true, the flush commits even an empty overlay,
    /// so a participant with work never waits for the chain to write.
    fn has_work(&self) -> bool;

    /// Write this flush's rows through `w`, inside the flush's write
    /// transaction, after the overlay's rows and before the commit.
    ///
    /// The participant reports what only it knows (`keys_journaled`,
    /// `merges`, `base_rewrites`, `memtable_keys`); the database fills in
    /// the row counts from `w` and the time from its own timer, over
    /// whatever was set there.  An error fails the flush and latches the
    /// store; see the trait docs.
    fn contribute(&self, w: &mut FlushWriter<'_, '_>) -> Result<ParticipantStats, Error>;

    /// Called exactly once after each [`Self::contribute`], and never
    /// without one, with whether the flush's commit landed.
    ///
    /// `true` means the rows `contribute` wrote are durable and visible to
    /// every transaction that begins from now on: the flush has committed
    /// and retired the overlay layers it captured.  `false` means the
    /// flush failed and the store is already latched fatal, so no later
    /// flush will run.  Its rows are normally discarded with the
    /// transaction, but an engine that fails after its sync can leave them
    /// durable, so a participant should leave its memory as it was and
    /// let the next open decide from what is on disk.  Either way the call
    /// is made before the writer semaphore is released, so no commit,
    /// flush or [`crate::Transaction::on_commit`] hook runs between the
    /// flush and this call.
    fn finished(&self, committed: bool);
}

/// What a participant's part of one flush did, carried in
/// [`crate::FlushObservation::participant`].
///
/// `#[non_exhaustive]` so fields can be added without breaking a
/// participant: build one from [`Default::default`] and set the fields it
/// knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ParticipantStats {
    /// Rows inserted through the [`FlushWriter`].  Filled by the database.
    pub rows_put: u64,
    /// Rows removed through the [`FlushWriter`] that existed.  Filled by
    /// the database.
    pub rows_removed: u64,
    /// Key plus value bytes of the rows inserted.  Filled by the database.
    pub bytes_put: u64,
    /// Rows read back through the [`FlushWriter`], by `get` or a range.
    /// Filled by the database.
    pub rows_read: u64,
    /// Keys the participant journaled in this flush.
    pub keys_journaled: u64,
    /// Merges the participant ran in this flush.
    pub merges: u64,
    /// Of those, merges that rewrote a base run.
    pub base_rewrites: u64,
    /// Keys the participant held in memory when the flush began.
    pub memtable_keys: u64,
    /// The call to [`FlushParticipant::contribute`]: its wall time and the
    /// flushing thread's storage I/O during it, a fourth phase beside
    /// [`crate::FlushObservation`]'s three.  Filled by the database.
    pub contribute: FlushPhase,
}

impl ParticipantStats {
    /// Render as one JSON object, for the flush log.
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\"rows_put\":{},\"rows_removed\":{},\"bytes_put\":{},\"rows_read\":{},",
                "\"keys_journaled\":{},\"merges\":{},\"base_rewrites\":{},",
                "\"memtable_keys\":{},\"contribute\":{}}}"
            ),
            self.rows_put,
            self.rows_removed,
            self.bytes_put,
            self.rows_read,
            self.keys_journaled,
            self.merges,
            self.base_rewrites,
            self.memtable_keys,
            self.contribute.to_json(),
        )
    }
}

/// A registered participant and the key prefix it owns.
#[derive(Clone)]
pub(crate) struct Registration {
    /// Every row the participant writes starts with this, and no overlay
    /// row may.
    pub(crate) prefix: Arc<[u8]>,
    pub(crate) participant: Arc<dyn FlushParticipant>,
}

/// The rows a participant may read and write in one flush: the flush's
/// redb write transaction, confined to the participant's prefix.
///
/// Reads see the store as the flush has left it so far: the durable rows,
/// the overlay rows this flush has already inserted, and the
/// participant's own writes in this flush.  The overlay never holds a row
/// under the prefix, so for the participant's own keys that is its durable
/// rows plus its writes.
///
/// Every key, and both ends of every range, must lie under the prefix; a
/// key must also be longer than it, as a bucket row's key is never empty.
/// Anything else is refused with [`ErrorKind::IncompatibleValue`] and
/// nothing is read or written.
pub struct FlushWriter<'a, 'txn> {
    table: &'a mut redb::Table<'txn, &'static [u8], &'static [u8]>,
    prefix: &'a [u8],
    write_log: Option<&'a WriteLogSink>,
    rows_put: u64,
    rows_removed: u64,
    bytes_put: u64,
    rows_read: u64,
}

impl<'a, 'txn> FlushWriter<'a, 'txn> {
    pub(crate) fn new(
        table: &'a mut redb::Table<'txn, &'static [u8], &'static [u8]>,
        prefix: &'a [u8],
        write_log: Option<&'a WriteLogSink>,
    ) -> FlushWriter<'a, 'txn> {
        FlushWriter {
            table,
            prefix,
            write_log,
            rows_put: 0,
            rows_removed: 0,
            bytes_put: 0,
            rows_read: 0,
        }
    }

    /// The prefix this writer is confined to.
    pub fn prefix(&self) -> &[u8] {
        self.prefix
    }

    /// The value stored under `key`, or `None`.
    pub fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.check_key(key, "get")?;
        let value = self
            .table
            .get(key)
            .map_err(crate::storage_error)?
            .map(|v| v.value().to_vec());
        if value.is_some() {
            self.rows_read = self.rows_read.saturating_add(1);
        }
        Ok(value)
    }

    /// Every row with `from <= key < to`, in key order.
    ///
    /// `from` must lie under the prefix (the prefix itself included), and
    /// `to` at or below the first key past it.  An empty or inverted range
    /// returns no rows.
    pub fn range(&mut self, from: &[u8], to: &[u8]) -> Result<Vec<crate::RawRow>, Error> {
        if !from.starts_with(self.prefix) {
            return Err(self.outside("range from", from));
        }
        let past = Transaction::prefix_upper_bound(self.prefix);
        if past.as_deref().is_some_and(|past| to > past) {
            return Err(self.outside("range to", to));
        }
        if from >= to {
            return Ok(Vec::new());
        }
        self.collect((Bound::Included(from), Bound::Excluded(to)))
    }

    /// Every row whose key starts with `sub`, in key order.  `sub` must
    /// start with the prefix.
    pub fn range_prefix(&mut self, sub: &[u8]) -> Result<Vec<crate::RawRow>, Error> {
        if !sub.starts_with(self.prefix) {
            return Err(self.outside("range over", sub));
        }
        let past = Transaction::prefix_upper_bound(sub);
        let upper = match past.as_deref() {
            Some(past) => Bound::Excluded(past),
            None => Bound::Unbounded,
        };
        self.collect((Bound::Included(sub), upper))
    }

    /// Insert or replace the row under `key`.
    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        self.check_key(key, "insert")?;
        if let Some(sink) = self.write_log {
            sink(key, Some(value));
        }
        self.table
            .insert(key, value)
            .map_err(crate::storage_error)?;
        self.rows_put = self.rows_put.saturating_add(1);
        self.bytes_put = self
            .bytes_put
            .saturating_add(key.len() as u64)
            .saturating_add(value.len() as u64);
        Ok(())
    }

    /// Remove the row under `key`, returning whether there was one.
    pub fn remove(&mut self, key: &[u8]) -> Result<bool, Error> {
        self.check_key(key, "remove")?;
        if let Some(sink) = self.write_log {
            sink(key, None);
        }
        let existed = self
            .table
            .remove(key)
            .map_err(crate::storage_error)?
            .is_some();
        if existed {
            self.rows_removed = self.rows_removed.saturating_add(1);
        }
        Ok(existed)
    }

    /// Copy the counts this writer kept into `stats`.
    pub(crate) fn fill(&self, stats: &mut ParticipantStats) {
        stats.rows_put = self.rows_put;
        stats.rows_removed = self.rows_removed;
        stats.bytes_put = self.bytes_put;
        stats.rows_read = self.rows_read;
    }

    fn collect(
        &mut self,
        bounds: (Bound<&[u8]>, Bound<&[u8]>),
    ) -> Result<Vec<crate::RawRow>, Error> {
        let mut rows = Vec::new();
        for entry in self
            .table
            .range::<&[u8]>(bounds)
            .map_err(crate::storage_error)?
        {
            let (key, value) = entry.map_err(crate::storage_error)?;
            rows.push((key.value().to_vec(), value.value().to_vec()));
        }
        self.rows_read = self.rows_read.saturating_add(rows.len() as u64);
        Ok(rows)
    }

    fn check_key(&self, key: &[u8], what: &str) -> Result<(), Error> {
        if key.len() > self.prefix.len() && key.starts_with(self.prefix) {
            Ok(())
        } else {
            Err(self.outside(what, key))
        }
    }

    fn outside(&self, what: &str, key: &[u8]) -> Error {
        db_error(
            ErrorKind::IncompatibleValue,
            format!(
                "flush participant {what} of key {} outside its prefix {}",
                hex(key),
                hex(self.prefix)
            ),
        )
    }
}

/// Lowercase hex, for error text.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
