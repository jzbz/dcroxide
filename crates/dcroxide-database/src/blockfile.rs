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
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::{Error, ErrorKind, db_error};

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
pub(crate) struct BlockStore {
    db_path: PathBuf,
    network: u32,
    max_block_file_size: u32,
    /// Current write position.
    pub(crate) write_file_num: u32,
    pub(crate) write_offset: u32,
    /// Open read handles keyed by file number.
    open_files: HashMap<u32, File>,
    /// The current write handle.
    write_file: Option<File>,
    /// Files written to since the last sync, for commit-time fsync.
    dirty_files: Vec<u32>,
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
        })
    }

    /// Append the raw block to the store per dcrd `writeBlock`,
    /// returning its location.  Data is not synced until
    /// [`Self::sync`].
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
            self.write_file = Some(file);
        }
        let file = self.write_file.as_mut().expect("write file open");
        file.seek(SeekFrom::Start(u64::from(self.write_offset)))
            .map_err(|e| io_err(&e, "failed to seek write file"))?;

        // Record: network || length || block || checksum-of-preceding.
        let mut digest = CASTAGNOLI.digest();
        let net = self.network.to_le_bytes();
        file.write_all(&net)
            .map_err(|e| io_err(&e, "failed to write network"))?;
        digest.update(&net);
        let len_bytes = block_len.to_le_bytes();
        file.write_all(&len_bytes)
            .map_err(|e| io_err(&e, "failed to write block length"))?;
        digest.update(&len_bytes);
        file.write_all(raw_block)
            .map_err(|e| io_err(&e, "failed to write block"))?;
        digest.update(raw_block);
        file.write_all(&digest.finalize().to_be_bytes())
            .map_err(|e| io_err(&e, "failed to write checksum"))?;

        let loc = BlockLocation {
            block_file_num: self.write_file_num,
            file_offset: self.write_offset,
            block_len: full_len,
        };
        self.write_offset += full_len;
        if !self.dirty_files.contains(&self.write_file_num) {
            self.dirty_files.push(self.write_file_num);
        }
        Ok(loc)
    }

    /// Sync all files written to since the last sync.
    pub(crate) fn sync(&mut self) -> Result<(), Error> {
        for num in std::mem::take(&mut self.dirty_files) {
            let via_write_handle = num == self.write_file_num && self.write_file.is_some();
            if via_write_handle {
                let f = self.write_file.as_ref().expect("checked above");
                f.sync_all()
                    .map_err(|e| io_err(&e, "failed to sync file"))?;
            } else {
                let path = block_file_path(&self.db_path, num);
                let f = File::open(&path).map_err(|e| io_err(&e, "failed to open file to sync"))?;
                f.sync_all()
                    .map_err(|e| io_err(&e, "failed to sync file"))?;
            }
        }
        Ok(())
    }

    fn read_handle(&mut self, file_num: u32) -> Result<&mut File, Error> {
        if !self.open_files.contains_key(&file_num) {
            let path = block_file_path(&self.db_path, file_num);
            let file = File::open(&path).map_err(|e| io_err(&e, "failed to open block file"))?;
            self.open_files.insert(file_num, file);
        }
        Ok(self.open_files.get_mut(&file_num).expect("just inserted"))
    }

    /// Read the block record at the location per dcrd `readBlock`:
    /// verifies the checksum (`ErrCorruption` on mismatch) and the
    /// network, returning the raw serialized block.
    pub(crate) fn read_block(&mut self, loc: BlockLocation) -> Result<Vec<u8>, Error> {
        let network = self.network;
        let file = self.read_handle(loc.block_file_num)?;
        let mut data = vec![0u8; loc.block_len as usize];
        file.seek(SeekFrom::Start(u64::from(loc.file_offset)))
            .map_err(|e| io_err(&e, "failed to seek block file"))?;
        file.read_exact(&mut data).map_err(|e| {
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
        &mut self,
        loc: BlockLocation,
        offset: u32,
        len: u32,
    ) -> Result<Vec<u8>, Error> {
        let file = self.read_handle(loc.block_file_num)?;
        // Regions are offsets into the raw block, so skip the network
        // and length bytes of the record.
        let read_offset = u64::from(loc.file_offset) + 8 + u64::from(offset);
        let mut data = vec![0u8; len as usize];
        file.seek(SeekFrom::Start(read_offset))
            .map_err(|e| io_err(&e, "failed to seek block file"))?;
        file.read_exact(&mut data)
            .map_err(|e| io_err(&e, "failed to read block region"))?;
        Ok(data)
    }

    /// Roll the store back to the given write position, removing any
    /// later files and truncating the target file (dcrd
    /// `handleRollback`).  Used both for commit failures and for
    /// reconciliation after an unclean shutdown.
    pub(crate) fn rollback_to(&mut self, file_num: u32, offset: u32) -> Result<(), Error> {
        if self.write_file_num == file_num && self.write_offset == offset {
            return Ok(());
        }

        self.write_file = None;
        self.open_files.clear();
        self.dirty_files.clear();

        // Remove any files that are entirely after the target.
        let mut num = self.write_file_num;
        while num > file_num {
            let path = block_file_path(&self.db_path, num);
            if let Err(e) = fs::remove_file(&path) {
                return Err(io_err(&e, "failed to remove block file"));
            }
            num -= 1;
        }

        // Truncate the target file to the target offset.
        let path = block_file_path(&self.db_path, file_num);
        if offset == 0 && !path.exists() {
            // Rolling back to the very start of a file that was never
            // created.
            self.write_file_num = file_num;
            self.write_offset = 0;
            return Ok(());
        }
        let file = OpenOptions::new()
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| io_err(&e, "failed to open block file for truncation"))?;
        file.set_len(u64::from(offset))
            .map_err(|e| io_err(&e, "failed to truncate block file"))?;
        file.sync_all()
            .map_err(|e| io_err(&e, "failed to sync truncated block file"))?;

        self.write_file_num = file_num;
        self.write_offset = offset;
        Ok(())
    }
}
