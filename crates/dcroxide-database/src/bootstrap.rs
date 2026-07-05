// SPDX-License-Identifier: ISC
//! Bulk block import/export in dcrd's `addblock` bootstrap file format
//! (dcrd cmd/addblock `import.go`):
//!
//! ```text
//! <network (4 bytes, LE)><block length (4, LE)><serialized block> ...
//! ```
//!
//! A clean end-of-file at a record boundary terminates the stream; a
//! network mismatch or a block length beyond `wire.MaxBlockPayload` is
//! an error, exactly like dcrd's reader.
//!
//! The import here is storage-level only: blocks are checked for
//! well-formedness by deserializing them and already-known blocks are
//! skipped, but no consensus validation occurs (dcrd's importer runs
//! blocks through the chain engine, which arrives with the blockchain
//! phase and will layer on top of this).

use std::io::{ErrorKind as IoErrorKind, Read, Write};

use dcroxide_wire::{MAX_BLOCK_PAYLOAD, MsgBlock};

use crate::Database;
use crate::error::{Error, ErrorKind, db_error};

/// Statistics from a bulk import.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ImportStats {
    /// Blocks read from the input stream.
    pub read: u64,
    /// Blocks stored (read minus already-known duplicates).
    pub imported: u64,
    /// Blocks skipped because they were already present.
    pub skipped: u64,
}

/// Read the next block record from the reader (dcrd `readBlock`).
/// Returns `Ok(None)` on a clean end of file at a record boundary.
pub fn read_block(r: &mut impl Read, network: u32) -> Result<Option<Vec<u8>>, Error> {
    // The block file format is:
    //  <network> <block length> <serialized block>
    let mut net_bytes = [0u8; 4];
    match r.read_exact(&mut net_bytes) {
        Ok(()) => {}
        Err(e) if e.kind() == IoErrorKind::UnexpectedEof => {
            // No block and no error means there are no more blocks to
            // read.
            return Ok(None);
        }
        Err(e) => {
            return Err(db_error(
                ErrorKind::DriverSpecific,
                format!("failed to read network: {e}"),
            ));
        }
    }
    let net = u32::from_le_bytes(net_bytes);
    if net != network {
        return Err(db_error(
            ErrorKind::DriverSpecific,
            format!("network mismatch -- got {net:x}, want {network:x}"),
        ));
    }

    // Read the block length and ensure it is sane.
    let mut len_bytes = [0u8; 4];
    r.read_exact(&mut len_bytes).map_err(|e| {
        db_error(
            ErrorKind::DriverSpecific,
            format!("failed to read block length: {e}"),
        )
    })?;
    let block_len = u32::from_le_bytes(len_bytes);
    if block_len > MAX_BLOCK_PAYLOAD {
        return Err(db_error(
            ErrorKind::DriverSpecific,
            format!(
                "block payload of {block_len} bytes is larger than the max allowed \
                 {MAX_BLOCK_PAYLOAD} bytes"
            ),
        ));
    }

    let mut block = vec![0u8; block_len as usize];
    r.read_exact(&mut block).map_err(|e| {
        db_error(
            ErrorKind::DriverSpecific,
            format!("failed to read block: {e}"),
        )
    })?;
    Ok(Some(block))
}

/// Append one block record to the writer in the bootstrap format.
pub fn write_block(w: &mut impl Write, network: u32, raw_block: &[u8]) -> Result<(), Error> {
    let io = |e: std::io::Error| {
        db_error(
            ErrorKind::DriverSpecific,
            format!("failed to write block record: {e}"),
        )
    };
    w.write_all(&network.to_le_bytes()).map_err(io)?;
    w.write_all(&(raw_block.len() as u32).to_le_bytes())
        .map_err(io)?;
    w.write_all(raw_block).map_err(io)?;
    Ok(())
}

/// How many blocks to store per database transaction during import.
const IMPORT_BATCH_SIZE: usize = 256;

impl Database {
    /// Bulk-import blocks from a bootstrap-format stream into block
    /// storage.  Malformed blocks are rejected; blocks that are already
    /// present are skipped, mirroring dcrd's importer behavior at the
    /// storage layer.  Blocks are stored in batches of a few hundred
    /// per transaction.
    ///
    /// This performs NO consensus validation; it is the storage half of
    /// dcrd's `addblock` and the chain-engine half arrives with the
    /// blockchain phase.
    pub fn import_blocks(&self, r: &mut impl Read, network: u32) -> Result<ImportStats, Error> {
        let mut stats = ImportStats::default();
        let mut batch: Vec<(dcroxide_chainhash::Hash, Vec<u8>)> = Vec::new();

        let flush = |batch: &mut Vec<(dcroxide_chainhash::Hash, Vec<u8>)>,
                     stats: &mut ImportStats|
         -> Result<(), Error> {
            if batch.is_empty() {
                return Ok(());
            }
            self.update(|tx| {
                for (hash, raw) in batch.iter() {
                    if tx.has_block(hash)? {
                        stats.skipped += 1;
                        continue;
                    }
                    tx.store_block_raw(hash, raw)?;
                    stats.imported += 1;
                }
                Ok(())
            })?;
            batch.clear();
            Ok(())
        };

        while let Some(raw) = read_block(r, network)? {
            stats.read += 1;

            // Deserialize to check for malformed blocks and to compute
            // the block hash.
            let (block, _) = MsgBlock::from_bytes(&raw).map_err(|e| {
                db_error(
                    ErrorKind::DriverSpecific,
                    format!("failed to deserialize imported block: {e:?}"),
                )
            })?;
            batch.push((block.header.block_hash(), raw));

            if batch.len() >= IMPORT_BATCH_SIZE {
                flush(&mut batch, &mut stats)?;
            }
        }
        flush(&mut batch, &mut stats)?;
        Ok(stats)
    }

    /// Export the blocks with the given hashes, in order, to a
    /// bootstrap-format stream readable by [`Database::import_blocks`]
    /// and by dcrd's `addblock`.
    pub fn export_blocks(
        &self,
        w: &mut impl Write,
        network: u32,
        hashes: &[dcroxide_chainhash::Hash],
    ) -> Result<u64, Error> {
        let mut exported = 0u64;
        self.view(|tx| {
            for hash in hashes {
                let raw = tx.fetch_block(hash)?;
                write_block(w, network, &raw)?;
                exported += 1;
            }
            Ok(())
        })?;
        Ok(exported)
    }
}
