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
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::{Error, ErrorKind, db_error};
use crate::{LogLevel, LogSink, log_line};

/// CRC-32 with the Castagnoli polynomial (dcrd's `castagnoli` table).
///
/// The sixteen-table form of the same checksum: it consumes sixteen
/// bytes a step where the crate's default takes one, and every block is
/// checksummed whole when it is written and again when it is read.  The
/// values are identical; `tests/blockstore.rs` checks a record against
/// the one-table form.
const CASTAGNOLI: crc::Crc<u32, crc::Table<16>> =
    crc::Crc::<u32, crc::Table<16>>::new(&crc::CRC_32_ISCSI);

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
                #[allow(
                    clippy::arithmetic_side_effects,
                    reason = "num counts contiguous block files that exist on disk, far below u32::MAX"
                )]
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

    /// Write a whole block record at the write cursor and advance the
    /// cursor by the bytes actually written -- also when the write
    /// fails part way (dcrd `writeData`, `blockio.go:373-396`, called
    /// once per field of the record).
    ///
    /// Advancing on failure is what lets a rollback find a torn record.
    /// A cursor left on the rollback point makes the rollback a no-op,
    /// and the partial bytes stay in the file past it; one that moved
    /// sends the rollback to truncate them.
    ///
    /// The bytes the failing write itself landed count too.  dcrd's
    /// cursor moves by what Go's `WriteAt` returns, which is nothing
    /// for a call that failed, whatever it had written by then, so it
    /// stops at the start of the field that failed; the cursor here
    /// moves by every byte that landed, so any torn record moves it.
    ///
    /// The error is the one dcrd's call for the field the write stopped
    /// in returns: it names that field and gives the offset the field
    /// starts at, which is where that call began.
    fn write_record(&mut self, record: &[u8], block_len: u32) -> Result<(), Error> {
        let file: &File = self.write_file.as_deref().expect("write file open");
        let record_offset = self.write_offset;
        let (written, failure) = write_at(file, record, u64::from(record_offset));
        // At most one record, which `write_block` has checked fits the
        // u32 cursor.
        let written = written as u32;
        self.write_offset = record_offset.wrapping_add(written);
        match failure {
            None => Ok(()),
            Some(e) => {
                let (field_name, field_offset) = record_field_at(written, block_len);
                Err(db_error(
                    ErrorKind::DriverSpecific,
                    format!(
                        "failed to write {field_name} to file {} at offset {}: {e}",
                        self.write_file_num,
                        record_offset.wrapping_add(field_offset)
                    ),
                ))
            }
        }
    }

    /// Append the raw block to the store per dcrd `writeBlock`,
    /// returning its location.  Data is not synced until the next flush:
    /// [`crate::dbcache::DbCache::run_flush`] takes a [`Self::sync_plan`],
    /// runs it ([`SyncPlan::run`]) and discharges it with
    /// [`Self::finish_sync`].
    pub(crate) fn write_block(&mut self, raw_block: &[u8]) -> Result<BlockLocation, Error> {
        let block_len = raw_block.len() as u32;
        let full_len = block_len.wrapping_add(BLOCK_RECORD_OVERHEAD);

        // Move to the next block file if adding the new block would
        // exceed the max allowed size for the current block file.
        let final_offset = self.write_offset.checked_add(full_len);
        if final_offset.is_none() || final_offset.expect("checked") > self.max_block_file_size {
            self.write_file = None;
            self.write_file_num = self.write_file_num.wrapping_add(1);
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

        // Record: network || length || block || checksum-of-preceding.
        // dcrd writes the four fields with a `WriteAt` each
        // (`blockio.go:466-489`); the same bytes go out here in one
        // call, three of the four being four bytes long.
        let mut record = Vec::with_capacity(full_len as usize);
        record.extend_from_slice(&self.network.to_le_bytes());
        record.extend_from_slice(&block_len.to_le_bytes());
        record.extend_from_slice(raw_block);
        let checksum = CASTAGNOLI.checksum(&record);
        record.extend_from_slice(&checksum.to_be_bytes());
        let orig_offset = self.write_offset;
        self.write_record(&record, block_len)?;

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
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "num > file_num by the loop condition, so num >= 1"
        )]
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

/// A test's probe into block I/O, called with `"read"`, `"write"` or
/// `"fsync"`.
#[cfg(test)]
pub(crate) type IoHook = Box<dyn Fn(&'static str)>;

#[cfg(test)]
thread_local! {
    /// Run on the calling thread just before each block read, each
    /// write call for a block record and each fsync, so a test can see
    /// what is locked while the I/O runs and how many calls it takes.
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

/// The field of a block record that holds the byte at `offset` into
/// it, and the offset that field starts at.  A write that stopped
/// `offset` bytes into the record stopped in that field, in the call
/// dcrd's `writeBlock` makes for it (`blockio.go:466-489`); an empty
/// block is no field at all, as dcrd's zero-length write of one cannot
/// fail.
fn record_field_at(offset: u32, block_len: u32) -> (&'static str, u32) {
    match offset {
        0..4 => ("network", 0),
        4..8 => ("block length", 4),
        _ if offset.wrapping_sub(8) < block_len => ("block", 8),
        _ => ("checksum", block_len.wrapping_add(8)),
    }
}

/// Write `buf` to the file at `offset` without using the handle's
/// cursor, as the `WriteAt` dcrd's `writeData` calls does
/// (`blockio.go:386`), returning how many bytes landed and the error
/// that stopped it short, if one did ([`write_all_at`]).
fn write_at(file: &File, buf: &[u8], offset: u64) -> (usize, Option<std::io::Error>) {
    write_all_at(
        |rest, at| {
            #[cfg(test)]
            io_hook("write");
            #[cfg(unix)]
            {
                std::os::unix::fs::FileExt::write_at(file, rest, at)
            }
            #[cfg(windows)]
            {
                std::os::windows::fs::FileExt::seek_write(file, rest, at)
            }
        },
        buf,
        offset,
    )
}

/// Hand `buf` to `write`, a positioned write that may take fewer bytes
/// than it is given, until all of it is taken or a call fails.  Each
/// call gets the bytes not yet taken and the offset they belong at.
/// Returns how many bytes were taken and the error that stopped it
/// short, if one did.
///
/// A short count is not a failure and an interrupted call is made
/// again, as Go's `WriteAt` has it.  The count after a failure is not
/// Go's: `WriteAt` reports none of the bytes of the call that failed,
/// and this is every byte that landed, which is where the write
/// cursor has to be for a rollback to find a torn record.
fn write_all_at(
    mut write: impl FnMut(&[u8], u64) -> std::io::Result<usize>,
    buf: &[u8],
    offset: u64,
) -> (usize, Option<std::io::Error>) {
    let mut written = 0usize;
    while written < buf.len() {
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "offset is a u32 file offset and written < buf.len(), one record's length, so the sum is far below u64::MAX"
        )]
        let at = offset + written as u64;
        match write(&buf[written..], at) {
            Ok(0) => {
                return (
                    written,
                    Some(std::io::Error::from(std::io::ErrorKind::WriteZero)),
                );
            }
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "written + n <= buf.len(): a write returns at most the remaining buffer's length"
            )]
            Ok(n) => written += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return (written, Some(e)),
        }
    }
    (written, None)
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
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "offset is a u32 file offset and filled < buf.len() <= u32::MAX, so \
                  offset + filled < 2^33; seek_read returns n <= buf.len() - filled"
    )]
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
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "n = block_len >= 12 for every record write_block stores; a corrupt shorter \
                  length panics in the slicing, as dcrd's readBlock slice expressions do"
    )]
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
        let read_offset = u64::from(loc.file_offset.wrapping_add(8).wrapping_add(offset));
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
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic over small fixed values"
)]
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

    /// A region read computes its file offset at u32, as dcrd's
    /// `readBlockRegion` does (`loc.fileOffset + 8 + offset`,
    /// `blockio.go:582`), so an offset past `u32::MAX` wraps to the
    /// start of the file instead of reading past 4 GiB.
    ///
    /// Computed in u64, the read lands at 2^32 and fails with an EOF
    /// where dcrd returns the bytes at the wrapped offset.
    #[test]
    fn a_region_read_offset_wraps_at_u32_as_dcrd_computes_it() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut store = small_store(dir.path());
        store.write_block(&[7; 8]).expect("write block");
        let reader = store.reader(0).expect("reader");

        // file_offset + 8 wraps to 0: the region is the record's first
        // bytes, the network in little-endian order.
        let loc = BlockLocation {
            block_file_num: 0,
            file_offset: u32::MAX - 7,
            block_len: 8 + BLOCK_RECORD_OVERHEAD,
        };
        let region = reader
            .read_block_region(loc, 0, 4)
            .expect("the wrapped offset reads from the start of the file");
        assert_eq!(region, 0x1234_5678u32.to_le_bytes());

        // And the region offset wraps with it: 2^32 - 8 + 8 + 8 is 8,
        // the first byte of the block.
        let region = reader
            .read_block_region(loc, 8, 8)
            .expect("the wrapped offset reads the block");
        assert_eq!(region, [7u8; 8]);
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

    /// The bytes dcrd's `writeBlock` puts in a block file for one block
    /// (`blockio.go:466-489`), field by field: the network, the block's
    /// length, the block, and the Castagnoli checksum of those three,
    /// taken with the one-table form and not the store's own.
    fn record_of(network: u32, raw_block: &[u8]) -> Vec<u8> {
        let mut record = Vec::new();
        record.extend_from_slice(&network.to_le_bytes());
        record.extend_from_slice(&(raw_block.len() as u32).to_le_bytes());
        record.extend_from_slice(raw_block);
        let checksum = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI).checksum(&record);
        record.extend_from_slice(&checksum.to_be_bytes());
        record
    }

    /// What dcrd's `writeBlock` leaves in the block files for a
    /// sequence of blocks: each record appended whole to the current
    /// file, or to the next one from its start when it would pass the
    /// size cap (`blockio.go:425-446`).
    struct FileModel {
        max_file_size: usize,
        files: Vec<Vec<u8>>,
    }

    impl FileModel {
        /// Append the block's record, returning where it went.
        fn write(&mut self, network: u32, raw_block: &[u8]) -> BlockLocation {
            let record = record_of(network, raw_block);
            if self.files.last().expect("a file").len() + record.len() > self.max_file_size {
                self.files.push(Vec::new());
            }
            let (block_file_num, _) = self.cursor();
            let file = self.files.last_mut().expect("a file");
            let loc = BlockLocation {
                block_file_num,
                file_offset: file.len() as u32,
                block_len: record.len() as u32,
            };
            file.extend_from_slice(&record);
            loc
        }

        /// The write cursor after the writes so far.
        fn cursor(&self) -> (u32, u32) {
            (
                (self.files.len() - 1) as u32,
                self.files.last().expect("a file").len() as u32,
            )
        }

        /// Check the block files on disk hold exactly the model's bytes.
        fn check(&self, dir: &Path, what: &str) {
            for (num, want) in self.files.iter().enumerate() {
                let path = block_file_path(dir, num as u32);
                // A file whose first record was never written does not
                // exist yet.
                let got = fs::read(&path).unwrap_or_default();
                assert_eq!(&got, want, "{what}: the bytes of file {num}");
            }
            assert!(
                !block_file_path(dir, self.files.len() as u32).exists(),
                "{what}: a file past the write cursor"
            );
        }
    }

    /// The store writes each record with one call where dcrd makes
    /// four, and the files must come out the same: every block file
    /// holds the records dcrd's `writeBlock` would have put there, each
    /// at the offset the store reports and with the cursor moved past
    /// it, across file rollovers, a reopen and a rollback.
    #[test]
    fn the_block_files_hold_the_records_dcrd_writes() {
        const NET: u32 = 0x1234_5678;
        const MAX: u32 = 4096;
        let dir = tempfile::tempdir().expect("temp dir");
        let mut rng = dcroxide_testutil::SplitMix64::from_entropy("block records");
        let mut model = FileModel {
            max_file_size: MAX as usize,
            files: vec![Vec::new()],
        };
        let mut store = BlockStore::open(dir.path(), NET, MAX, None).expect("open store");
        let mut written: Vec<(BlockLocation, Vec<u8>)> = Vec::new();
        for step in 0..400usize {
            let room = MAX as usize - model.cursor().1 as usize;
            let len = match step % 8 {
                // An empty block, the shortest record there is.
                0 => 0,
                // A record that ends exactly on the size cap, and the
                // one after it, which cannot fit.
                1 if room >= BLOCK_RECORD_OVERHEAD as usize => {
                    room - BLOCK_RECORD_OVERHEAD as usize
                }
                // A record one byte too long for the room left.
                3 if room >= BLOCK_RECORD_OVERHEAD as usize => {
                    room - BLOCK_RECORD_OVERHEAD as usize + 1
                }
                _ => rng.below(700) as usize,
            };
            let mut block = vec![0u8; len];
            rng.fill(&mut block);

            let want = model.write(NET, &block);
            let got = store.write_block(&block).expect("write block");
            assert_eq!(got, want, "step {step}: where the record went");
            assert_eq!(
                (store.write_file_num, store.write_offset),
                model.cursor(),
                "step {step}: the write cursor"
            );
            written.push((got, block));

            match step % 50 {
                // A restart: the cursor comes from the files and the
                // write handle is a fresh one.
                17 => {
                    drop(store);
                    store = BlockStore::open(dir.path(), NET, MAX, None).expect("reopen store");
                    assert_eq!(
                        (store.write_file_num, store.write_offset),
                        model.cursor(),
                        "step {step}: the cursor after a reopen"
                    );
                }
                // A rollback of the last few records, as a failed commit
                // makes, and the next record lands where they were.
                33 => {
                    let keep = written.len() - 1 - rng.below(4) as usize;
                    let (first_gone, _) = written[keep];
                    written.truncate(keep);
                    model.files.truncate(first_gone.block_file_num as usize + 1);
                    model
                        .files
                        .last_mut()
                        .expect("a file")
                        .truncate(first_gone.file_offset as usize);
                    store
                        .rollback_to(first_gone.block_file_num, first_gone.file_offset)
                        .expect("rollback");
                }
                _ => {}
            }
        }
        model.check(dir.path(), "at the end");
        assert!(model.files.len() > 20, "the writes rolled over many times");

        // And every record reads back as the block it was written from.
        for (loc, block) in &written {
            let reader = store.reader(loc.block_file_num).expect("reader");
            assert_eq!(&reader.read_block(*loc).expect("read block"), block);
        }
    }

    /// A record is never split between two files: one that ends exactly
    /// on the size cap stays in the current file, and one a single byte
    /// longer goes whole to the start of the next, leaving the current
    /// file as it was (dcrd `writeBlock`, `blockio.go:425-446`, which
    /// rolls over when `finalOffset > maxBlockFileSize`).
    #[test]
    fn a_record_that_does_not_fit_starts_the_next_file_whole() {
        const NET: u32 = 0x1234_5678;
        const MAX: u32 = 100;
        let dir = tempfile::tempdir().expect("temp dir");
        let mut store = BlockStore::open(dir.path(), NET, MAX, None).expect("open store");
        let file = |num| fs::read(block_file_path(dir.path(), num)).expect("read block file");

        // 50 bytes, then 50 more: the second ends on the cap and stays.
        let (a, b) = ([0xa1u8; 38], [0xb2u8; 38]);
        store.write_block(&a).expect("first record");
        let loc = store.write_block(&b).expect("a record ending on the cap");
        assert_eq!(
            (loc.block_file_num, loc.file_offset, loc.block_len),
            (0, 50, 50)
        );
        assert_eq!((store.write_file_num, store.write_offset), (0, 100));
        let full = [record_of(NET, &a), record_of(NET, &b)].concat();
        assert_eq!(file(0), full);

        // The file is full, so even an empty block starts the next one.
        let loc = store.write_block(&[]).expect("an empty block");
        assert_eq!(
            (loc.block_file_num, loc.file_offset, loc.block_len),
            (1, 0, 12)
        );
        assert_eq!(file(0), full, "the full file is left as it was");
        assert_eq!(file(1), record_of(NET, &[]));

        // 12 bytes are in file 1; a record of 89 would end one byte past
        // the cap, so all of it goes to file 2 and none of it to file 1.
        let c = [0xc3u8; 77];
        let loc = store.write_block(&c).expect("a record one byte too long");
        assert_eq!(
            (loc.block_file_num, loc.file_offset, loc.block_len),
            (2, 0, 89)
        );
        assert_eq!((store.write_file_num, store.write_offset), (2, 89));
        assert_eq!(file(1), record_of(NET, &[]), "nothing of it in file 1");
        assert_eq!(file(2), record_of(NET, &c));
        assert_eq!(store.dirty_files, vec![0, 1, 2]);
    }

    /// Set in the child that runs under a file-size limit.
    #[cfg(target_os = "linux")]
    const TORN_RECORD_CHILD: &str = "DCROXIDE_TORN_RECORD_CHILD";

    /// A record write that fails part way names the field it stopped
    /// in, with that field's offset, as the one of dcrd's four
    /// `writeData` calls that fails does (`blockio.go:384-392`): the
    /// failing call is the one for the field holding the first byte
    /// that did not land, and its error gives the offset that call
    /// started at.  The write cursor moves by every byte that landed,
    /// those of the field the write stopped in included, where Go's
    /// `WriteAt` reports none of a failed call's and dcrd's cursor
    /// stops at that field's start.  What landed stays in the file
    /// past the old cursor until the rollback truncates it.
    ///
    /// The partial writes come from `RLIMIT_FSIZE`: the test re-runs
    /// itself under `ulimit -f 1` with `SIGXFSZ` ignored, where a write
    /// that crosses the limit stores what fits and the next one fails
    /// with `EFBIG`.  The child starts each case from a block file that
    /// ends a chosen number of bytes short of the limit.  Linux only:
    /// storing the part that fits, to the byte, is what its kernel does
    /// with such a write, and the cases are counted in those bytes.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_record_write_that_fails_part_way_names_the_field_it_stopped_in() {
        if std::env::var_os(TORN_RECORD_CHILD).is_some() {
            torn_record_child();
            return;
        }
        let exe = std::env::current_exe().expect("test binary path");
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(
                "ulimit -f 1 && trap '' XFSZ && exec \"$0\" --exact \
                 blockfile::tests::a_record_write_that_fails_part_way_names_the_field_it_stopped_in \
                 --nocapture",
            )
            .arg(&exe)
            .env(TORN_RECORD_CHILD, "1")
            .output()
            .expect("run the limited child");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "the child failed:\n{stdout}\n{stderr}"
        );
        assert!(
            stdout.contains("torn-record child ran") || stderr.contains("torn-record child ran"),
            "the child must have run the check, not skipped it:\n{stdout}\n{stderr}"
        );
    }

    #[cfg(target_os = "linux")]
    fn torn_record_child() {
        use std::io::Write;

        const NET: u32 = 0x1234_5678;

        // The limit in bytes: one block of the shell's `ulimit -f`,
        // 512 bytes in a POSIX sh and 1024 in bash.  A write across it
        // stores what fits.
        let probe_dir = tempfile::tempdir().expect("temp dir");
        let mut probe = File::create(probe_dir.path().join("probe")).expect("create probe");
        let limit = probe.write(&[0u8; 4096]).expect("a write across the limit");
        assert!(
            limit == 512 || limit == 1024,
            "the file-size limit: {limit}"
        );
        let limit = limit as u32;

        let block: Vec<u8> = (0..100u8).collect();
        assert_eq!(record_of(NET, &block).len(), 112);
        // The block, how many bytes of its record fit under the limit,
        // the field the write then stops in, and that field's offset in
        // the record.
        let cases: [(&[u8], u32, &str, u32); 15] = [
            (&block, 0, "network", 0),
            (&block, 1, "network", 0),
            (&block, 2, "network", 0),
            (&block, 3, "network", 0),
            (&block, 4, "block length", 4),
            (&block, 7, "block length", 4),
            (&block, 8, "block", 8),
            (&block, 57, "block", 8),
            (&block, 107, "block", 8),
            (&block, 108, "checksum", 108),
            (&block, 111, "checksum", 108),
            // An empty block is never the field: dcrd's zero-length
            // write of one cannot fail, so a write that stops after the
            // length stopped in the checksum.
            (&[], 3, "network", 0),
            (&[], 7, "block length", 4),
            (&[], 8, "checksum", 8),
            (&[], 11, "checksum", 8),
        ];
        for (block, fits, field, field_offset) in cases {
            let record = record_of(NET, block);
            let what = format!(
                "{fits} bytes of the record of a {}-byte block fit",
                block.len()
            );
            let dir = tempfile::tempdir().expect("temp dir");
            let path = block_file_path(dir.path(), 0);
            // The file the store finds: records of earlier commits, up
            // to `fits` bytes short of the limit.
            let start = limit - fits;
            let earlier = vec![0x5au8; start as usize];
            fs::write(&path, &earlier).expect("write the earlier bytes");
            let mut store = BlockStore::open(dir.path(), NET, DEFAULT_MAX_BLOCK_FILE_SIZE, None)
                .expect("open store");
            assert_eq!((store.write_file_num, store.write_offset), (0, start));

            let err = store
                .write_block(block)
                .expect_err("the write must cross the file-size limit");
            assert_eq!(err.kind, ErrorKind::DriverSpecific, "{what}");
            let want = format!(
                "failed to write {field} to file 0 at offset {}: ",
                start + field_offset
            );
            assert!(
                err.description.starts_with(&want) && err.description.len() > want.len(),
                "{what}: want {want:?} and the cause, got {:?}",
                err.description
            );
            assert_eq!(
                (store.write_file_num, store.write_offset),
                (0, start + fits),
                "{what}: the cursor moves by what landed"
            );
            assert!(
                store.dirty_files.is_empty(),
                "{what}: a failed write owes no sync"
            );
            let left = fs::read(&path).expect("read block file");
            assert_eq!(
                left,
                [earlier.as_slice(), &record[..fits as usize]].concat(),
                "{what}: what the failed write left in the file"
            );

            // The commit's rollback then removes what landed.
            store.rollback_to(0, start).expect("rollback");
            assert_eq!((store.write_file_num, store.write_offset), (0, start));
            assert_eq!(fs::read(&path).expect("read block file"), earlier);
        }

        // A record that ends exactly on the limit is written whole.
        let record = record_of(NET, &block);
        let dir = tempfile::tempdir().expect("temp dir");
        let path = block_file_path(dir.path(), 0);
        let earlier = vec![0x5au8; (limit - 112) as usize];
        fs::write(&path, &earlier).expect("write the earlier bytes");
        let mut store = BlockStore::open(dir.path(), NET, DEFAULT_MAX_BLOCK_FILE_SIZE, None)
            .expect("open store");
        store.write_block(&block).expect("the record fits");
        assert_eq!((store.write_file_num, store.write_offset), (0, limit));
        assert_eq!(
            fs::read(&path).expect("read block file"),
            [earlier.as_slice(), record.as_slice()].concat()
        );
        eprintln!("torn-record child ran");
    }

    /// The field a stopped write is blamed on, for every count of
    /// bytes that can have landed: the one holding the next byte, with
    /// its offset in the record.  An empty block is never that field,
    /// so a write that stops once the length is down stopped in the
    /// checksum, which then starts where the block would have.
    #[test]
    fn a_stopped_write_is_blamed_on_the_field_holding_the_next_byte() {
        let expect = |block_len: u32, landed: std::ops::RangeInclusive<u32>, field, at: u32| {
            for landed in landed {
                assert_eq!(
                    record_field_at(landed, block_len),
                    (field, at),
                    "{landed} bytes of the record of a {block_len}-byte block landed"
                );
            }
        };
        expect(100, 0..=3, "network", 0);
        expect(100, 4..=7, "block length", 4);
        expect(100, 8..=107, "block", 8);
        expect(100, 108..=111, "checksum", 108);
        expect(1, 4..=7, "block length", 4);
        expect(1, 8..=8, "block", 8);
        expect(1, 9..=12, "checksum", 9);
        expect(0, 0..=3, "network", 0);
        expect(0, 4..=7, "block length", 4);
        expect(0, 8..=11, "checksum", 8);
    }

    /// What [`write_all_at`] returned, each call it made of the write
    /// as the offset and the bytes it passed, and the file a write
    /// that stores what it says it took leaves.
    type Scripted = (
        (usize, Option<std::io::Error>),
        Vec<(u64, Vec<u8>)>,
        Vec<u8>,
    );

    /// Run [`write_all_at`] over `buf` at `offset` against a write that
    /// answers each call with the next step of `script`, taking the
    /// leading bytes it is given when the step is a count.  The file
    /// starts as zeroes and ends eight bytes past the write.
    fn run_scripted(script: Vec<std::io::Result<usize>>, buf: &[u8], offset: u64) -> Scripted {
        let mut calls = Vec::new();
        let mut file = vec![0u8; offset as usize + buf.len() + 8];
        let mut script = script.into_iter();
        let result = write_all_at(
            |rest, at| {
                calls.push((at, rest.to_vec()));
                let step = script.next().expect("a call past the script's end");
                if let Ok(n) = step {
                    file[at as usize..at as usize + n].copy_from_slice(&rest[..n]);
                }
                step
            },
            buf,
            offset,
        );
        assert!(script.next().is_none(), "a step of the script was not used");
        (result, calls, file)
    }

    /// A positioned write that takes less than it was given is made
    /// again with the rest at the offset the rest belongs at, and one
    /// that was interrupted is made again as it was, until the whole
    /// buffer is down; each byte reaches the file once, at its place.
    /// A write that takes everything is the only call made, which is
    /// how a block record reaches its file.
    #[test]
    fn a_short_or_interrupted_write_is_continued_where_it_stopped() {
        let buf: Vec<u8> = (1..=20u8).collect();
        let interrupted = || std::io::Error::from(std::io::ErrorKind::Interrupted);
        let in_place = |offset: usize, landed: &[u8]| {
            let mut file = vec![0u8; offset + buf.len() + 8];
            file[offset..offset + landed.len()].copy_from_slice(landed);
            file
        };

        let ((written, failure), calls, file) = run_scripted(
            vec![Ok(3), Err(interrupted()), Ok(5), Err(interrupted()), Ok(12)],
            &buf,
            1000,
        );
        assert_eq!((written, failure.map(|e| e.kind())), (20, None));
        assert_eq!(
            calls,
            vec![
                (1000, buf.clone()),
                (1003, buf[3..].to_vec()),
                (1003, buf[3..].to_vec()),
                (1008, buf[8..].to_vec()),
                (1008, buf[8..].to_vec()),
            ]
        );
        assert_eq!(file, in_place(1000, &buf));

        // Interrupted before anything landed.
        let ((written, failure), calls, file) =
            run_scripted(vec![Err(interrupted()), Ok(20)], &buf, 7);
        assert_eq!((written, failure.map(|e| e.kind())), (20, None));
        assert_eq!(calls, vec![(7, buf.clone()), (7, buf.clone())]);
        assert_eq!(file, in_place(7, &buf));

        // The whole buffer in one call.
        let ((written, failure), calls, file) = run_scripted(vec![Ok(20)], &buf, 4096);
        assert_eq!((written, failure.map(|e| e.kind())), (20, None));
        assert_eq!(calls, vec![(4096, buf.clone())]);
        assert_eq!(file, in_place(4096, &buf));

        // Nothing to write is no call at all, as in Go's `WriteAt`.
        let ((written, failure), calls, _) = run_scripted(Vec::new(), &[], 5);
        assert_eq!((written, failure.map(|e| e.kind())), (0, None));
        assert!(calls.is_empty());
    }

    /// A write that fails after part of the buffer landed reports the
    /// bytes that landed, those of earlier short counts included, with
    /// the error of the call that failed; a write that takes nothing
    /// is such a failure and not the end of the buffer.
    #[test]
    fn a_failed_write_reports_what_landed_before_it() {
        let buf: Vec<u8> = (1..=20u8).collect();

        let ((written, failure), calls, file) = run_scripted(
            vec![Ok(3), Ok(4), Err(std::io::Error::other("no room"))],
            &buf,
            100,
        );
        assert_eq!(written, 7);
        let failure = failure.expect("the write failed");
        assert_eq!(
            (failure.kind(), failure.to_string()),
            (std::io::ErrorKind::Other, "no room".to_string()),
            "the error is the failing call's own"
        );
        assert_eq!(
            calls,
            vec![
                (100, buf.clone()),
                (103, buf[3..].to_vec()),
                (107, buf[7..].to_vec()),
            ]
        );
        assert_eq!(&file[100..107], &buf[..7]);
        assert!(file[107..].iter().all(|&b| b == 0), "nothing past it");

        // The first call fails: nothing landed.
        let ((written, failure), calls, _) =
            run_scripted(vec![Err(std::io::Error::other("no room"))], &buf, 100);
        assert_eq!(written, 0);
        assert_eq!(failure.expect("the write failed").to_string(), "no room");
        assert_eq!(calls.len(), 1);

        // A call that takes nothing.
        let ((written, failure), calls, _) = run_scripted(vec![Ok(3), Ok(0)], &buf, 100);
        assert_eq!(
            (written, failure.map(|e| e.kind())),
            (3, Some(std::io::ErrorKind::WriteZero))
        );
        assert_eq!(calls, vec![(100, buf.clone()), (103, buf[3..].to_vec())]);
        let ((written, failure), ..) = run_scripted(vec![Ok(0)], &buf, 100);
        assert_eq!(
            (written, failure.map(|e| e.kind())),
            (0, Some(std::io::ErrorKind::WriteZero))
        );
    }

    /// Each block record reaches its file in one write call, where
    /// dcrd makes one for each of its four fields
    /// (`blockio.go:466-489`): counted through the store's I/O probe
    /// over empty and full blocks, a rollover and a reopened store.
    #[test]
    fn a_block_record_is_written_with_one_call() {
        use std::cell::Cell;
        use std::rc::Rc;

        let dir = tempfile::tempdir().expect("temp dir");
        let mut store = BlockStore::open(dir.path(), 0x1234_5678, 100, None).expect("open store");
        let writes = Rc::new(Cell::new(0usize));
        let counter = Rc::clone(&writes);
        IO_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |what| {
                if what == "write" {
                    counter.set(counter.get() + 1);
                }
            }));
        });
        let blocks: [&[u8]; 6] = [&[], &[7; 38], &[8; 38], &[9; 88], &[], &[1; 30]];
        for (i, block) in blocks.into_iter().enumerate() {
            if i == 3 {
                drop(store);
                store = BlockStore::open(dir.path(), 0x1234_5678, 100, None).expect("reopen");
            }
            store.write_block(block).expect("write block");
            assert_eq!(writes.get(), i + 1, "write calls after record {i}");
        }
        IO_HOOK.with(|hook| *hook.borrow_mut() = None);
        assert_eq!(store.write_file_num, 3, "the records rolled over");
    }

    /// The sixteen-table checksum is the one-table checksum: at every
    /// length around its sixteen-byte step, in one call and fed in the
    /// three pieces a block record is written in.  A record's bytes on
    /// disk depend on it.
    #[test]
    fn the_wide_table_checksum_matches_the_one_table_form() {
        let reference = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);
        let data: Vec<u8> = (0..4096u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
        for len in (0..=100).chain([255, 256, 257, 1023, 1024, 1025, 4095, 4096]) {
            let bytes = &data[..len];
            assert_eq!(
                CASTAGNOLI.checksum(bytes),
                reference.checksum(bytes),
                "one call, {len} bytes"
            );
            if len >= 8 {
                let mut digest = CASTAGNOLI.digest();
                digest.update(&bytes[0..4]);
                digest.update(&bytes[4..8]);
                digest.update(&bytes[8..]);
                assert_eq!(
                    digest.finalize(),
                    reference.checksum(bytes),
                    "three pieces, {len} bytes"
                );
            }
        }
        // Anchored absolutely as well: the check value, and thirty-two
        // zero bytes (RFC 3720, B.4), which take two sixteen-byte steps.
        assert_eq!(CASTAGNOLI.checksum(b"123456789"), 0xe306_9283);
        assert_eq!(CASTAGNOLI.checksum(&[0u8; 32]), 0x8a91_36aa);
    }
}
