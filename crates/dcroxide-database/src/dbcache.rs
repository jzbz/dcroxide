// SPDX-License-Identifier: ISC
//! The metadata write cache (dcrd ffldb `dbcache.go`): committed
//! metadata accumulates in memory and reaches the durable key/value
//! store only when the cache flushes — after enough time or size, on
//! an explicit flush, and on close.  The flush syncs the flat block
//! files *before* committing the metadata so the metadata can never
//! describe blocks whose bytes did not survive a crash; between
//! flushes a crash simply loses the cached window (the chain re-syncs
//! it), exactly dcrd's behavior.
//!
//! dcrd snapshots immutable treaps; this port keeps the overlay in a
//! `BTreeMap` behind an `Arc`, cloned copy-on-write when a snapshot is
//! still referenced by an open transaction (a documented adaptation —
//! the observable transaction semantics are identical).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::METADATA_TABLE;
use crate::blockfile::BlockStore;
use crate::error::{Error, ErrorKind, db_error};

/// The default size for the database cache (dcrd `defaultCacheSize`,
/// 100 MiB).
pub(crate) const DEFAULT_CACHE_SIZE: u64 = 100 * 1024 * 1024;

/// The default number of seconds between flushes (dcrd
/// `defaultFlushSecs`, five minutes).
pub(crate) const DEFAULT_FLUSH_SECS: u64 = 300;

/// The cache overlay: key to live value, or `None` for a pending
/// deletion of a stored key.
pub(crate) type CacheMap = BTreeMap<Vec<u8>, Option<Vec<u8>>>;

/// The metadata write cache (dcrd `dbCache`).
pub(crate) struct DbCache {
    /// The overlay of committed-but-unflushed metadata; transactions
    /// snapshot it by cloning the `Arc`.
    pub(crate) cached: Arc<CacheMap>,
    /// The approximate byte size of the overlay's keys and values
    /// (dcrd tracks the treap sizes).
    total_size: u64,
    /// The last time the cache was flushed.
    last_flush: Instant,
    /// The maximum size threshold before a flush (dcrd `maxSize`).
    max_size: u64,
    /// The time threshold before a flush (dcrd `flushInterval`).
    flush_interval: Duration,
}

impl DbCache {
    pub(crate) fn new() -> DbCache {
        DbCache {
            cached: Arc::new(BTreeMap::new()),
            total_size: 0,
            last_flush: Instant::now(),
            max_size: DEFAULT_CACHE_SIZE,
            flush_interval: Duration::from_secs(DEFAULT_FLUSH_SECS),
        }
    }

    /// Apply a committed transaction's pending sets to the overlay
    /// with dcrd's size accounting (dcrd `commitTx` onto the cached
    /// treaps).
    pub(crate) fn commit_pending(
        &mut self,
        puts: BTreeMap<Vec<u8>, Vec<u8>>,
        removes: impl Iterator<Item = Vec<u8>>,
    ) {
        let cached = Arc::make_mut(&mut self.cached);
        for key in removes {
            match cached.get(&key) {
                Some(Some(old)) => {
                    self.total_size = self.total_size.saturating_sub(old.len() as u64);
                }
                Some(None) => {}
                None => {
                    self.total_size = self.total_size.saturating_add(key.len() as u64);
                }
            }
            cached.insert(key, None);
        }
        for (key, value) in puts {
            match cached.get(&key) {
                Some(Some(old)) => {
                    self.total_size = self
                        .total_size
                        .saturating_sub(old.len() as u64)
                        .saturating_add(value.len() as u64);
                }
                Some(None) => {
                    self.total_size = self.total_size.saturating_add(value.len() as u64);
                }
                None => {
                    self.total_size = self
                        .total_size
                        .saturating_add(key.len() as u64)
                        .saturating_add(value.len() as u64);
                }
            }
            cached.insert(key, Some(value));
        }
    }

    /// Whether the cache must flush before accepting more (dcrd
    /// `needsFlush`): the flush interval elapsed, or one and a half
    /// times the overlay size exceeds the maximum.
    pub(crate) fn needs_flush(&self) -> bool {
        if self.last_flush.elapsed() > self.flush_interval {
            return true;
        }
        let total = (self.total_size as f64 * 1.5) as u64;
        total > self.max_size
    }

    /// Flush the overlay: sync the flat block files first so the
    /// metadata never describes bytes that could vanish in a crash,
    /// then write everything in one durable transaction and clear
    /// (dcrd `dbCache.flush`).
    pub(crate) fn flush(
        &mut self,
        kv: &redb::Database,
        block_store: &std::sync::Mutex<BlockStore>,
    ) -> Result<(), Error> {
        self.last_flush = Instant::now();

        block_store
            .lock()
            .expect("block store lock poisoned")
            .sync()?;

        if self.cached.is_empty() {
            return Ok(());
        }

        let tx = kv
            .begin_write()
            .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
        {
            let mut table = tx
                .open_table(METADATA_TABLE)
                .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
            for (key, value) in self.cached.iter() {
                match value {
                    Some(v) => {
                        table
                            .insert(key.as_slice(), v.as_slice())
                            .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
                    }
                    None => {
                        table
                            .remove(key.as_slice())
                            .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;
                    }
                }
            }
        }
        tx.commit()
            .map_err(|e| db_error(ErrorKind::DriverSpecific, e.to_string()))?;

        self.cached = Arc::new(BTreeMap::new());
        self.total_size = 0;
        Ok(())
    }
}
