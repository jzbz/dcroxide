// SPDX-License-Identifier: ISC
//! Flat-file block storage (dcrd database/ffldb `blockio.go`).
//!
//! Blocks are appended to numbered `*.fdb` files using dcrd's exact
//! record format so the on-disk block data is byte-identical to what an
//! ffldb store would write for the same sequence of blocks:
//!
//! ```text
//! <network (4 bytes, LE)><block length (4, LE)><serialized block><crc32c (4, BE)>
//! ```
//!
//! The checksum is CRC-32 with the Castagnoli polynomial over all
//! preceding record bytes.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::{Error, ErrorKind, db_error};
use crate::{LogLevel, LogSink, log_line};

/// CRC-32 with the Castagnoli polynomial (dcrd's `castagnoli` table).
const CASTAGNOLI: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);

/// The number of overhead bytes in a block record: 4 network + 4 length
/// + 4 checksum.
pub(crate) const BLOCK_RECORD_OVERHEAD: u32 = 12;

/// The number of bytes in a serialized block location (dcrd
/// `blockLocSize`).
pub(crate) const BLOCK_LOC_SIZE: usize = 12;

/// The default maximum size for each flat block file (dcrd
/// `maxBlockFileSize`: 512 MiB).
pub(crate) const DEFAULT_MAX_BLOCK_FILE_SIZE: u32 = 512 * 1024 * 1024;

/// Identifies a particular block record within the flat files (dcrd
/// `blockLocation`).  `block_len` is the full record length including
/// the 12 bytes of overhead.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct BlockLocation {
    pub block_file_num: u32,
    pub file_offset: u32,
    pub block_len: u32,
}

impl BlockLocation {
    /// Serialize per dcrd `serializeBlockLoc`: file(4 LE) || offset(4 LE)
    /// || length(4 LE).
    pub(crate) fn serialize(&self) -> [u8; BLOCK_LOC_SIZE] {
        let mut out = [0u8; BLOCK_LOC_SIZE];
        out[0..4].copy_from_slice(&self.block_file_num.to_le_bytes());
        out[4..8].copy_from_slice(&self.file_offset.to_le_bytes());
        out[8..12].copy_from_slice(&self.block_len.to_le_bytes());
        out
    }

    /// Deserialize per dcrd `deserializeBlockLoc`.
    pub(crate) fn deserialize(b: &[u8]) -> BlockLocation {
        BlockLocation {
            block_file_num: u32::from_le_bytes(b[0..4].try_into().expect("4 bytes")),
            file_offset: u32::from_le_bytes(b[4..8].try_into().expect("4 bytes")),
            block_len: u32::from_le_bytes(b[8..12].try_into().expect("4 bytes")),
        }
    }
}

/// Serialize the current write cursor position (dcrd
/// `serializeWriteRow`): file(4 LE) || offset(4 LE) || crc32c(4 LE) of
/// the first eight bytes.
pub(crate) fn serialize_write_row(file_num: u32, offset: u32) -> [u8; 12] {
    let mut row = [0u8; 12];
    row[0..4].copy_from_slice(&file_num.to_le_bytes());
    row[4..8].copy_from_slice(&offset.to_le_bytes());
    let checksum = CASTAGNOLI.checksum(&row[0..8]);
    row[8..12].copy_from_slice(&checksum.to_le_bytes());
    row
}

/// Deserialize and verify a write cursor row (dcrd
/// `deserializeWriteRow`); a checksum mismatch is `ErrCorruption`.
pub(crate) fn deserialize_write_row(row: &[u8]) -> Result<(u32, u32), Error> {
    if row.len() != 12 {
        return Err(db_error(
            ErrorKind::Corruption,
            format!("corrupt write cursor row: unexpected length {}", row.len()),
        ));
    }
    let want = u32::from_le_bytes(row[8..12].try_into().expect("4 bytes"));
    let got = CASTAGNOLI.checksum(&row[0..8]);
    if got != want {
        return Err(db_error(
            ErrorKind::Corruption,
            format!(
                "metadata for write cursor does not match the expected checksum - got {got}, want {want}"
            ),
        ));
    }
    Ok((
        u32::from_le_bytes(row[0..4].try_into().expect("4 bytes")),
        u32::from_le_bytes(row[4..8].try_into().expect("4 bytes")),
    ))
}

/// The file path for the provided block file number (dcrd
/// `blockFilePath`; `%09d.fdb`).
fn block_file_path(db_path: &Path, file_num: u32) -> PathBuf {
    db_path.join(format!("{file_num:09}.fdb"))
}

/// Flat-file block store (dcrd `blockStore`), sans the LRU open-file
/// cache: read handles are simply kept open per file (block file counts
/// stay small at Decred's chain size; revisit if profiling ever says
/// otherwise).
///
/// The store sits behind one mutex, where dcrd has a lock per file and
/// one on the write cursor.  What keeps that from serializing block
/// reads is that neither a read nor the flush's fsync does its I/O under
/// the mutex: a read takes a shared handle ([`Self::reader`]) and reads
/// positionally after releasing it, as dcrd's `ReadAt` under a per-file
/// read lock does, and a sync captures what it owes ([`Self::sync_plan`])
/// and fsyncs without it, as dcrd's `syncBlocks` does under read locks
/// alone.
pub(crate) struct BlockStore {
    db_path: PathBuf,
    network: u32,
    max_block_file_size: u32,
    /// Current write position.
    pub(crate) write_file_num: u32,
    pub(crate) write_offset: u32,
    /// Open read handles keyed by file number, shared with the readers
    /// using them.
    open_files: HashMap<u32, Arc<File>>,
    /// The current write handle, shared with a sync in progress.
    write_file: Option<Arc<File>>,
    /// Files written to since the last sync, for commit-time fsync.
    dirty_files: Vec<u32>,
    /// The driver's log sink (see [`crate::LogSink`]), for the
    /// `ROLLBACK:` lines dcrd's `handleRollback` logs.
    log: Option<LogSink>,
}

fn io_err(err: &std::io::Error, what: &str) -> Error {
    db_error(ErrorKind::DriverSpecific, format!("{what}: {err}"))
}

impl BlockStore {
    /// Open the store rooted at the database directory, scanning the
    /// existing block files to find the current write position (dcrd
    /// `scanBlockFiles`).
    pub(crate) fn open(
        db_path: &Path,
        network: u32,
        max_block_file_size: u32,
        log: Option<LogSink>,
    ) -> Result<BlockStore, Error> {
        let mut write_file_num = 0u32;
        let mut write_offset = 0u32;
        let mut num = 0u32;
        loop {
            let path = block_file_path(db_path, num);
            match fs::metadata(&path) {
                Ok(md) => {
                    write_file_num = num;
                    write_offset = md.len() as u32;
                    num += 1;
                }
                Err(_) => break,
            }
        }

        Ok(BlockStore {
            db_path: db_path.to_path_buf(),
            network,
            max_block_file_size,
            write_file_num,
            write_offset,
            open_files: HashMap::new(),
            write_file: None,
            dirty_files: Vec::new(),
            log,
        })
    }

    /// Write the data at the write cursor and advance the cursor by the
    /// bytes actually written -- also when the write fails part way
    /// (dcrd `writeData`, `blockio.go:373-396`).  The field name is only
    /// for the error.
    ///
    /// Advancing on failure is what lets a rollback find a torn record.
    /// A cursor left on the rollback point makes the rollback a no-op,
    /// and the partial bytes stay in the file past it; one that moved
    /// sends the rollback to truncate them.
    fn write_data(&mut self, data: &[u8], field_name: &str) -> Result<(), Error> {
        let mut file: &File = self.write_file.as_deref().expect("write file open");
        // `write` until done, counting what lands, as Go's `WriteAt`
        // does; `write_all` would hide how much of a failed write did.
        let mut written = 0usize;
        let mut failure = None;
        while written < data.len() {
            match file.write(&data[written..]) {
                Ok(0) => {
                    failure = Some(std::io::Error::from(std::io::ErrorKind::WriteZero));
                    break;
                }
                Ok(n) => written += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    failure = Some(e);
                    break;
                }
            }
        }
        // At most one record, which `write_block` has checked fits the
        // u32 cursor.
        let written = written as u32;
        self.write_offset += written;
        match failure {
            None => Ok(()),
            Some(e) => Err(db_error(
                ErrorKind::DriverSpecific,
                format!(
                    "failed to write {field_name} to file {} at offset {}: {e}",
                    self.write_file_num,
                    self.write_offset - written
                ),
            )),
        }
    }

    /// Append the raw block to the store per dcrd `writeBlock`,
    /// returning its location.  Data is not synced until the next flush:
    /// [`crate::dbcache::DbCache::run_flush`] takes a [`Self::sync_plan`],
    /// runs it ([`SyncPlan::run`]) and discharges it with
    /// [`Self::finish_sync`].
    pub(crate) fn write_block(&mut self, raw_block: &[u8]) -> Result<BlockLocation, Error> {
        let block_len = raw_block.len() as u32;
        let full_len = block_len + BLOCK_RECORD_OVERHEAD;

        // Move to the next block file if adding the new block would
        // exceed the max allowed size for the current block file.
        let final_offset = self.write_offset.checked_add(full_len);
        if final_offset.is_none() || final_offset.expect("checked") > self.max_block_file_size {
            self.write_file = None;
            self.write_file_num += 1;
            self.write_offset = 0;
        }

        if self.write_file.is_none() {
            let path = block_file_path(&self.db_path, self.write_file_num);
            let file = OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&path)
                .map_err(|e| io_err(&e, "failed to open write file"))?;
            self.write_file = Some(Arc::new(file));
        }
        let mut file: &File = self.write_file.as_deref().expect("write file open");
        file.seek(SeekFrom::Start(u64::from(self.write_offset)))
            .map_err(|e| io_err(&e, "failed to seek write file"))?;

        // Record: network || length || block || checksum-of-preceding,
        // each advancing the cursor by what it wrote, as dcrd's do.
        let orig_offset = self.write_offset;
        let mut digest = CASTAGNOLI.digest();
        let net = self.network.to_le_bytes();
        self.write_data(&net, "network")?;
        digest.update(&net);
        let len_bytes = block_len.to_le_bytes();
        self.write_data(&len_bytes, "block length")?;
        digest.update(&len_bytes);
        self.write_data(raw_block, "block")?;
        digest.update(raw_block);
        self.write_data(&digest.finalize().to_be_bytes(), "checksum")?;

        let loc = BlockLocation {
            block_file_num: self.write_file_num,
            file_offset: orig_offset,
            block_len: full_len,
        };
        if !self.dirty_files.contains(&self.write_file_num) {
            self.dirty_files.push(self.write_file_num);
        }
        Ok(loc)
    }

    /// Sync all files written to since the last sync, with the store
    /// held throughout.  [`crate::dbcache::DbCache::run_flush`] splits
    /// this into its three steps so the fsyncs run without the store
    /// lock.
    #[cfg(test)]
    pub(crate) fn sync(&mut self) -> Result<(), Error> {
        let plan = self.sync_plan();
        let (synced, result) = plan.run();
        self.finish_sync(&synced);
        result
    }

    /// What a sync owes: every file written to since the last sync, in
    /// the order written, with the write handle for the current one.
    /// Taken under the store lock; [`SyncPlan::run`] then does the
    /// fsyncs without it, and [`Self::finish_sync`] discharges them.
    ///
    /// Nothing may write between the plan and its discharge, or a file
    /// dirtied again after its fsync would be discharged with the new
    /// bytes unsynced.  Every sync runs inside a flush, and every flush
    /// holds the writer semaphore, which is what excludes the writes.
    pub(crate) fn sync_plan(&self) -> SyncPlan {
        let files = self
            .dirty_files
            .iter()
            .map(|&num| {
                let handle = if num == self.write_file_num {
                    self.write_file.clone()
                } else {
                    None
                };
                (num, block_file_path(&self.db_path, num), handle)
            })
            .collect();
        SyncPlan { files }
    }

    /// Discharge the files a [`SyncPlan::run`] synced.  Entries leave the
    /// dirty list only after their fsync succeeds, so a transient failure
    /// keeps the files-before-metadata invariant armed for the next
    /// attempt.
    pub(crate) fn finish_sync(&mut self, synced: &[u32]) {
        self.dirty_files.retain(|num| !synced.contains(num));
    }

    /// A shared handle for reading the given file, opened on first use
    /// (dcrd `blockFile`).  The store lock is needed only for this; the
    /// read itself runs on the returned [`BlockReader`] after the lock is
    /// released, so block reads neither wait on each other nor on a
    /// flush's fsync, as dcrd's do not.
    pub(crate) fn reader(&mut self, file_num: u32) -> Result<BlockReader, Error> {
        let file = match self.open_files.get(&file_num) {
            Some(file) => Arc::clone(file),
            None => {
                let path = block_file_path(&self.db_path, file_num);
                let file = Arc::new(
                    File::open(&path).map_err(|e| io_err(&e, "failed to open block file"))?,
                );
                self.open_files.insert(file_num, Arc::clone(&file));
                file
            }
        };
        Ok(BlockReader {
            file,
            network: self.network,
        })
    }

    /// Roll the store back to the given write position, removing any
    /// later files and truncating the target file (dcrd
    /// `handleRollback`).  Used both for commit failures and for
    /// reconciliation after an unclean shutdown.
    ///
    /// As in dcrd, the write cursor is repositioned to the target
    /// whatever fails (`blockio.go:662-667`), and the first failure ends
    /// the rollback with a `ROLLBACK:` warning (`:683-718`).  Leaving the
    /// cursor where it was is not an option: after a failed rotation it
    /// names a file that was never created, every later commit stages
    /// it as the durable write cursor, and the next open refuses the
    /// store as corrupt.  Whatever could not be undone lies past the
    /// repositioned cursor, where the next write overwrites it or the
    /// next open's reconciliation truncates it.  The failure is also
    /// returned, though dcrd's returns nothing; callers log nothing more.
    pub(crate) fn rollback_to(&mut self, file_num: u32, offset: u32) -> Result<(), Error> {
        if self.write_file_num == file_num && self.write_offset == offset {
            return Ok(());
        }

        log_line(
            self.log.as_ref(),
            LogLevel::Debug,
            &format!("ROLLBACK: Rolling back to file {file_num}, offset {offset}"),
        );
        let result = self.undo_writes(file_num, offset);
        // Regardless of any failure above, reposition the write cursor to
        // the old block file and offset.
        self.write_file_num = file_num;
        self.write_offset = offset;
        if let Err(e) = &result {
            log_line(self.log.as_ref(), LogLevel::Warn, &format!("ROLLBACK: {e}"));
        }
        result
    }

    /// The file work of [`Self::rollback_to`], stopping at the first
    /// failure.  Each error's text is what dcrd's warning says after
    /// `ROLLBACK: ` for the same step.
    fn undo_writes(&mut self, file_num: u32, offset: u32) -> Result<(), Error> {
        self.write_file = None;
        self.open_files.clear();
        // Only the files this rollback discards leave the dirty list:
        // everything *above* `file_num` is deleted below.  Files below
        // it keep bytes that survive the rollback, so dropping them here
        // would lose the pending fsync and let the metadata that
        // describes them be committed first — the exact ordering the
        // dirty list exists to prevent.
        //
        // `file_num` itself stays until its truncation has been synced.
        // The truncate is what discharges its fsync, so dropping it up
        // front would leave an unsynced prefix owed to nobody on every
        // path where the truncate does not happen: an unwritable file,
        // a full disk, an `EIO` out of `sync_all`.  Each returns an
        // error, and the store keeps running — the next `sync` has to
        // still know about it.
        self.dirty_files.retain(|&num| num <= file_num);

        // Remove any files that are entirely after the target.  A file
        // that cannot be removed ends the rollback, as in dcrd -- a
        // rotation whose new file was never created included.
        let mut num = self.write_file_num;
        while num > file_num {
            let path = block_file_path(&self.db_path, num);
            if let Err(e) = fs::remove_file(&path) {
                return Err(db_error(
                    ErrorKind::DriverSpecific,
                    format!(
                        "Failed to delete block file number {num}: failed to delete file {path:?}: {e}"
                    ),
                ));
            }
            num -= 1;
        }

        // Truncate the target file to the target offset.
        let path = block_file_path(&self.db_path, file_num);
        if offset == 0 && !path.exists() {
            // Rolling back to the very start of a file that was never
            // created: there are no bytes to truncate and none to sync.
            self.dirty_files.retain(|&num| num != file_num);
            return Ok(());
        }
        let file = OpenOptions::new()
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| {
                db_error(
                    ErrorKind::DriverSpecific,
                    format!("failed to open file {path:?}: {e}"),
                )
            })?;
        file.set_len(u64::from(offset)).map_err(|e| {
            db_error(
                ErrorKind::DriverSpecific,
                format!("Failed to truncate file {file_num}: {e}"),
            )
        })?;
        file.sync_all().map_err(|e| {
            db_error(
                ErrorKind::DriverSpecific,
                format!("Failed to sync file {file_num}: {e}"),
            )
        })?;
        // The truncation is on the platter, so the target file owes
        // nothing further.
        self.dirty_files.retain(|&num| num != file_num);
        Ok(())
    }
}

/// A test's probe into block I/O, called with `"read"` or `"fsync"`.
#[cfg(test)]
pub(crate) type IoHook = Box<dyn Fn(&'static str)>;

#[cfg(test)]
thread_local! {
    /// Run on the calling thread just before each block read and each
    /// fsync, so a test can see what is locked while the I/O runs.
    pub(crate) static IO_HOOK: std::cell::RefCell<Option<IoHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Run [`IO_HOOK`], if a test set one.
#[cfg(test)]
fn io_hook(what: &'static str) {
    IO_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow().as_ref() {
            hook(what);
        }
    });
}

/// Fill `buf` from the file at `offset` without moving the handle's
/// cursor (Go's `ReadAt`), so reads through one shared handle cannot
/// disturb each other.
fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    #[cfg(test)]
    io_hook("read");
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::read_exact_at(file, buf, offset)
    }
    #[cfg(windows)]
    {
        // `seek_read` may return short, as `read` may.
        let mut filled = 0usize;
        while filled < buf.len() {
            match std::os::windows::fs::FileExt::seek_read(
                file,
                &mut buf[filled..],
                offset + filled as u64,
            ) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "failed to fill whole buffer",
                    ));
                }
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// A read handle on one block file, taken from [`BlockStore::reader`]
/// under the store lock and used after it is released (dcrd reads with
/// `ReadAt` under the file's read lock, `blockio.go:514-596`).
pub(crate) struct BlockReader {
    file: Arc<File>,
    network: u32,
}

impl BlockReader {
    /// Read the block record at the location per dcrd `readBlock`:
    /// verifies the checksum (`ErrCorruption` on mismatch) and the
    /// network, returning the raw serialized block.
    pub(crate) fn read_block(&self, loc: BlockLocation) -> Result<Vec<u8>, Error> {
        let network = self.network;
        let mut data = vec![0u8; loc.block_len as usize];
        read_exact_at(&self.file, &mut data, u64::from(loc.file_offset)).map_err(|e| {
            io_err(
                &e,
                &format!(
                    "failed to read block from file {}, offset {}",
                    loc.block_file_num, loc.file_offset
                ),
            )
        })?;

        let n = data.len();
        let serialized_checksum = u32::from_be_bytes(data[n - 4..].try_into().expect("4 bytes"));
        let calculated_checksum = CASTAGNOLI.checksum(&data[..n - 4]);
        if serialized_checksum != calculated_checksum {
            return Err(db_error(
                ErrorKind::Corruption,
                format!(
                    "block data checksum does not match - got {calculated_checksum:x}, \
                     want {serialized_checksum:x}"
                ),
            ));
        }

        let serialized_net = u32::from_le_bytes(data[0..4].try_into().expect("4 bytes"));
        if serialized_net != network {
            return Err(db_error(
                ErrorKind::DriverSpecific,
                format!(
                    "block data is for the wrong network - got {serialized_net}, want {network}"
                ),
            ));
        }

        // The raw block excludes the network, length, and checksum.
        data.truncate(n - 4);
        data.drain(0..8);
        Ok(data)
    }

    /// Read a region of the block at the location per dcrd
    /// `readBlockRegion`.  The caller is responsible for bounds
    /// checking against the block length; region reads skip the
    /// checksum for performance, exactly like dcrd.
    pub(crate) fn read_block_region(
        &self,
        loc: BlockLocation,
        offset: u32,
        len: u32,
    ) -> Result<Vec<u8>, Error> {
        // Regions are offsets into the raw block, so skip the network
        // and length bytes of the record.
        let read_offset = u64::from(loc.file_offset) + 8 + u64::from(offset);
        let mut data = vec![0u8; len as usize];
        read_exact_at(&self.file, &mut data, read_offset)
            .map_err(|e| io_err(&e, "failed to read block region"))?;
        Ok(data)
    }
}

/// The fsyncs a sync owes, captured by [`BlockStore::sync_plan`] under
/// the store lock and run without it.
pub(crate) struct SyncPlan {
    /// File number, path, and the write handle when the file is the
    /// current write file, in the order the files were written.
    files: Vec<(u32, PathBuf, Option<Arc<File>>)>,
}

impl SyncPlan {
    /// Fsync each owed file in order, stopping at the first failure.
    /// Returns the files synced, for [`BlockStore::finish_sync`], and the
    /// failure if there was one.
    pub(crate) fn run(&self) -> (Vec<u32>, Result<(), Error>) {
        let mut synced = Vec::with_capacity(self.files.len());
        for (num, path, handle) in &self.files {
            #[cfg(test)]
            io_hook("fsync");
            let result = match handle {
                Some(f) => f.sync_all().map_err(|e| io_err(&e, "failed to sync file")),
                None => {
                    // Opened for WRITING even though nothing is written
                    // here.  `fsync(2)` is happy with a read-only
                    // descriptor, but Windows' `FlushFileBuffers` — which
                    // is what `sync_all` becomes there — requires write
                    // access on the handle and fails the whole flush with
                    // `ERROR_ACCESS_DENIED` (os error 5) without it.
                    // `create` is deliberately absent: a dirty file that
                    // has gone missing must surface as an error, not be
                    // conjured up empty and reported synced.
                    OpenOptions::new()
                        .write(true)
                        .open(path)
                        .map_err(|e| io_err(&e, "failed to open file to sync"))
                        .and_then(|f| f.sync_all().map_err(|e| io_err(&e, "failed to sync file")))
                }
            };
            if let Err(e) = result {
                return (synced, Err(e));
            }
            synced.push(*num);
        }
        (synced, Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small store whose files roll over after two blocks, so a test
    /// can spread writes across several block files.
    fn small_store(dir: &Path) -> BlockStore {
        // Two records of eight payload bytes each fit in one file.
        BlockStore::open(dir, 0x1234_5678, 2 * (8 + BLOCK_RECORD_OVERHEAD), None)
            .expect("open store")
    }

    /// Rolling back must not discard the pending fsync for files that
    /// survive the rollback.  Those files still hold bytes the metadata
    /// will refer to, and the dirty list is what guarantees they reach
    /// the platter before the metadata that describes them; clearing it
    /// wholesale silently drops that ordering.
    #[test]
    fn rollback_keeps_the_pending_sync_for_files_it_does_not_discard() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut store = small_store(dir.path());

        // Fill file 0 and roll into file 1.
        for i in 0..3u8 {
            store.write_block(&[i; 8]).expect("write block");
        }
        assert_eq!(store.write_file_num, 1, "the writes must span two files");
        assert_eq!(store.dirty_files, vec![0, 1]);

        // Roll back to the start of file 1: file 0 is untouched and its
        // bytes remain live, so its fsync is still owed.
        store.rollback_to(1, 0).expect("rollback");
        assert_eq!(
            store.dirty_files,
            vec![0],
            "file 0 survived the rollback and still needs its fsync"
        );

        // The sync must then actually reach it, leaving nothing owed.
        store.sync().expect("sync");
        assert!(store.dirty_files.is_empty());
    }

    /// A rollback whose truncation fails still owes the target file its
    /// fsync.
    ///
    /// The dirty list is the barrier between the block bytes and the
    /// metadata that names them, and the truncation is what discharges
    /// the target's entry.  Dropping the entry before the truncation
    /// runs means an unwritable file, a full disk, or an `EIO` out of
    /// `sync_all` leaves an unsynced prefix that no later `sync` knows
    /// about -- and `rollback_to` returning an error does not stop the
    /// store, so there is a later `sync`.
    #[cfg(unix)]
    #[test]
    fn a_failed_rollback_truncation_keeps_the_target_file_dirty() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir");

        // Root ignores the mode bits, so skip rather than fail there.
        let canary = dir.path().join("canary");
        fs::write(&canary, b"x").expect("write canary");
        fs::set_permissions(&canary, fs::Permissions::from_mode(0o444)).expect("chmod canary");
        if OpenOptions::new().write(true).open(&canary).is_ok() {
            return;
        }

        let mut store = small_store(dir.path());
        for i in 0..2u8 {
            store.write_block(&[i; 8]).expect("write block");
        }
        assert_eq!(store.dirty_files, vec![0]);

        // Make file 0 unwritable, so the rollback cannot open it to
        // truncate.
        let path = block_file_path(dir.path(), 0);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).expect("chmod block file");

        let err = store
            .rollback_to(0, 8 + BLOCK_RECORD_OVERHEAD)
            .expect_err("the truncation cannot open a read-only file");
        assert!(
            format!("{err}").contains("failed to open file"),
            "the failure is the truncating open: {err}"
        );
        assert_eq!(
            store.dirty_files,
            vec![0],
            "the fsync the truncation would have discharged is still owed"
        );

        // Restore the mode so the temp dir can be cleaned up.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("restore mode");
    }

    /// The reopen a sync performs on a rolled-past file must ask for
    /// WRITE access, even though it writes nothing.
    ///
    /// `fsync(2)` accepts a read-only descriptor, so a read-only reopen
    /// works on Unix and this looks fine there.  Windows turns
    /// `sync_all` into `FlushFileBuffers`, which requires write access
    /// and fails with `ERROR_ACCESS_DENIED` without it — and because a
    /// failed sync deliberately keeps its entry on the dirty list, every
    /// later sync fails too.  The flush is the barrier `ProcessBlock`
    /// runs before the metadata commit, so on Windows the node stopped
    /// making progress permanently at the first block-file roll.
    ///
    /// The property is only directly observable on Windows, so this
    /// reaches it from the other side: a file the process may read but
    /// not write must make the sync FAIL.  A read-only reopen would
    /// succeed here and this test is what notices.  The cost of that is
    /// real but contrived — a block file an operator has chmod'ed to
    /// read-only can no longer be synced — and it is strictly less
    /// surprising than reporting a barrier that never ran.
    #[cfg(unix)]
    #[test]
    fn syncing_a_rolled_past_file_needs_a_writable_handle() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir");

        // Root ignores the mode bits, so there the premise cannot be set
        // up at all; skip rather than fail on somebody's CI container.
        let canary = dir.path().join("canary");
        fs::write(&canary, b"x").expect("write canary");
        fs::set_permissions(&canary, fs::Permissions::from_mode(0o444)).expect("chmod canary");
        if OpenOptions::new().write(true).open(&canary).is_ok() {
            return;
        }

        let mut store = small_store(dir.path());
        for i in 0..3u8 {
            store.write_block(&[i; 8]).expect("write block");
        }
        assert_eq!(store.write_file_num, 1, "the writes must span two files");
        assert_eq!(store.dirty_files, vec![0, 1]);

        // File 0 has been rolled past: its handle is closed and the sync
        // has to reopen it by path.  Make it unwritable.
        let rolled_past = block_file_path(dir.path(), 0);
        fs::set_permissions(&rolled_past, fs::Permissions::from_mode(0o444))
            .expect("chmod the rolled-past file");

        let err = store
            .sync()
            .expect_err("a sync that cannot open the file for writing must report it");
        assert!(
            err.to_string().contains("failed to open file to sync"),
            "the failure must name the reopen, got: {err}"
        );
        assert_eq!(
            store.dirty_files,
            vec![0, 1],
            "a failed sync must keep the whole dirty list so the barrier stays armed"
        );

        // And once it is writable again the sync completes, which is what
        // proves the reopen was the only obstacle.
        fs::set_permissions(&rolled_past, fs::Permissions::from_mode(0o644))
            .expect("restore the mode");
        store.sync().expect("sync");
        assert!(store.dirty_files.is_empty());
    }

    /// A rollback that fails still puts the write cursor back, as dcrd's
    /// `handleRollback` does in a deferred reposition.
    ///
    /// The case that matters is a rotation whose new file was never
    /// created: removing it fails, and a cursor left on it is staged by
    /// every later commit as the durable write cursor, which the next
    /// open then refuses as corrupt.
    #[test]
    fn a_failed_rollback_still_repositions_the_write_cursor() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut store = small_store(dir.path());
        for i in 0..2u8 {
            store.write_block(&[i; 8]).expect("write block");
        }
        let good = (store.write_file_num, store.write_offset);
        // Where `write_block` leaves the cursor when it has rotated but
        // could not create the next file.
        store.write_file = None;
        store.write_file_num = 1;
        store.write_offset = 0;
        assert!(!block_file_path(dir.path(), 1).exists());

        let err = store
            .rollback_to(good.0, good.1)
            .expect_err("the never-created file cannot be removed");
        assert!(
            err.to_string()
                .starts_with("Failed to delete block file number 1"),
            "dcrd's ROLLBACK text: {err}"
        );
        assert_eq!(
            (store.write_file_num, store.write_offset),
            good,
            "the cursor goes back whatever failed"
        );
    }

    /// The files a rollback does discard leave the list: they are either
    /// removed or truncated and synced by the rollback itself, so
    /// syncing them again would fail on a path that no longer exists.
    #[test]
    fn rollback_drops_the_files_it_discards() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut store = small_store(dir.path());
        for i in 0..3u8 {
            store.write_block(&[i; 8]).expect("write block");
        }
        assert_eq!(store.dirty_files, vec![0, 1]);

        // Back to the very start: file 1 is removed, file 0 truncated.
        store.rollback_to(0, 0).expect("rollback");
        assert!(
            store.dirty_files.is_empty(),
            "discarded files must not be left owing a sync: {:?}",
            store.dirty_files
        );
        assert!(!block_file_path(dir.path(), 1).exists());
        store.sync().expect("sync must not fail on a removed file");
    }
}
