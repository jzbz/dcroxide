// SPDX-License-Identifier: ISC
//! Storage that models power loss under the metadata store, shared by
//! every crate whose crash tests need it.
//!
//! It lived in `dcroxide-database`'s `tests/crash.rs` until the index
//! crates needed the same rig: a crash test of rows that ride inside the
//! metadata flush has to cut power under the same backend the database's
//! own suite trusts, or the two suites prove different things.
//!
//! The crash suites have two primitives, and the difference between them
//! is the point.  `drop` without `close` discards the write cache exactly
//! as process death would, but the page cache survives it, so every byte
//! written and never `fsync`ed is still readable after the reopen; a store
//! that skipped its durability step passes anyway.  This backend discards
//! what was never synced, which is the one thing that tells a durable
//! commit from a merely written one.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// No cut scheduled: [`PowerLossBackend::power_fails_after`] not called.
const NEVER: u64 = u64::MAX;

/// Storage that models power loss.
///
/// Every write is forwarded to a real file, but the bytes it overwrote
/// are kept first, so [`Self::cut_power`] can put the file back exactly as
/// it stood at the last successful `sync_data`.  An extending write is
/// undone by the recorded durable length rather than by its old bytes,
/// since it had none.
///
/// `honest_sync` is what gives the rig teeth: with it false the backend
/// acknowledges `sync_data` without doing anything, which is precisely the
/// mistake a deferred-fsync design can make, and a suite run against it
/// must notice.
///
/// [`Self::power_fails_after`] places the cut inside a flush rather than
/// between two of them: the backend accepts a given number of further
/// writes, length changes and syncs, then fails every later one, so
/// nothing after the cut reaches the file and no sync after it succeeds.
/// Sweeping that number over a scripted run puts the cut at every storage
/// operation the run makes.
#[derive(Debug)]
pub struct PowerLossBackend {
    file: Mutex<File>,
    /// `(offset, previous bytes)` for each write since the last sync,
    /// oldest first; replayed in reverse to undo them.
    undo: Mutex<Vec<(u64, Vec<u8>)>>,
    /// File length as of the last sync, so extensions are truncated away.
    durable_len: Mutex<u64>,
    honest_sync: bool,
    /// Writes, length changes and syncs accepted so far.
    ops: AtomicU64,
    /// Syncs that succeeded so far.
    syncs: AtomicU64,
    /// The operation count at which the power fails; [`NEVER`] when no
    /// cut is scheduled.
    fail_at: AtomicU64,
    /// Set once an operation has been refused for want of power.
    refused: AtomicBool,
}

impl PowerLossBackend {
    /// A backend over the file at `path`, created if it does not exist.
    /// Its current length counts as durable.
    pub fn create(path: &Path, honest_sync: bool) -> Arc<PowerLossBackend> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .expect("open backing file");
        let len = file.metadata().expect("metadata").len();
        Arc::new(PowerLossBackend {
            file: Mutex::new(file),
            undo: Mutex::new(Vec::new()),
            durable_len: Mutex::new(len),
            honest_sync,
            ops: AtomicU64::new(0),
            syncs: AtomicU64::new(0),
            fail_at: AtomicU64::new(NEVER),
            refused: AtomicBool::new(false),
        })
    }

    /// Discard every write since the last successful sync, as a power
    /// cut would.
    pub fn cut_power(&self) {
        let mut file = self.file.lock().expect("file lock");
        let mut undo = self.undo.lock().expect("undo lock");
        let durable = *self.durable_len.lock().expect("len lock");
        // Reverse order: a region written twice must end up holding what
        // it held before the FIRST of those writes.
        for (offset, previous) in undo.drain(..).rev() {
            if offset < durable {
                let keep =
                    std::cmp::min(previous.len() as u64, durable.saturating_sub(offset)) as usize;
                file.seek(SeekFrom::Start(offset)).expect("seek");
                file.write_all(&previous[..keep]).expect("undo write");
            }
        }
        file.set_len(durable).expect("truncate to durable length");
        file.sync_all().expect("sync after power cut");
    }

    /// Let `n` more writes, length changes and syncs through, then fail
    /// every later one with an I/O error: the power goes out after the
    /// `n`th.  `n = 0` fails the very next one.  Call [`Self::cut_power`]
    /// afterwards to discard what the cut left unsynced.
    pub fn power_fails_after(&self, n: u64) {
        let at = self.ops.load(Ordering::SeqCst).saturating_add(n);
        self.fail_at.store(at, Ordering::SeqCst);
    }

    /// Whether a cut scheduled by [`Self::power_fails_after`] has refused
    /// an operation.  A run that made exactly `n` operations reached the
    /// cut without feeling it, and reads `false` here.
    pub fn power_failed(&self) -> bool {
        self.refused.load(Ordering::SeqCst)
    }

    /// Writes, length changes and syncs accepted so far.  The difference
    /// across a scripted run is how many places
    /// [`Self::power_fails_after`] can cut it.
    pub fn ops(&self) -> u64 {
        self.ops.load(Ordering::SeqCst)
    }

    /// Syncs that succeeded so far.
    pub fn syncs(&self) -> u64 {
        self.syncs.load(Ordering::SeqCst)
    }

    /// Admit one mutating operation, or refuse it once the power is out.
    fn admit(&self) -> Result<(), std::io::Error> {
        let fail_at = self.fail_at.load(Ordering::SeqCst);
        let admitted = self
            .ops
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |ops| {
                (ops < fail_at).then(|| ops.saturating_add(1))
            });
        match admitted {
            Ok(_) => Ok(()),
            Err(_) => {
                self.refused.store(true, Ordering::SeqCst);
                Err(std::io::Error::other("power cut (PowerLossBackend)"))
            }
        }
    }
}

impl redb::StorageBackend for PowerLossBackend {
    fn len(&self) -> Result<u64, std::io::Error> {
        Ok(self.file.lock().expect("file lock").metadata()?.len())
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), std::io::Error> {
        let mut file = self.file.lock().expect("file lock");
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(out)
    }

    fn set_len(&self, len: u64) -> Result<(), std::io::Error> {
        self.admit()?;
        self.file.lock().expect("file lock").set_len(len)
    }

    fn sync_data(&self) -> Result<(), std::io::Error> {
        self.admit()?;
        if !self.honest_sync {
            // Acknowledge without persisting: the failure mode under test.
            return Ok(());
        }
        let file = self.file.lock().expect("file lock");
        file.sync_data()?;
        let len = file.metadata()?.len();
        drop(file);
        self.undo.lock().expect("undo lock").clear();
        *self.durable_len.lock().expect("len lock") = len;
        self.syncs.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn write(&self, offset: u64, data: &[u8]) -> Result<(), std::io::Error> {
        self.admit()?;
        let mut file = self.file.lock().expect("file lock");
        let len = file.metadata()?.len();
        // Keep whatever this write is about to destroy, but only the part
        // that exists: past EOF there is nothing to restore and the
        // truncate in `cut_power` removes it instead.
        if offset < len {
            let keep = std::cmp::min(data.len() as u64, len.saturating_sub(offset)) as usize;
            let mut previous = vec![0u8; keep];
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(&mut previous)?;
            self.undo
                .lock()
                .expect("undo lock")
                .push((offset, previous));
        }
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(data)
    }
}
