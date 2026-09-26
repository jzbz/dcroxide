// SPDX-License-Identifier: ISC
//! Bulk block import/export in dcrd's `addblock` bootstrap file format
//! (dcrd cmd/addblock `import.go`):
//!
//! ```text
//! <network (4 bytes, LE)><block length (4, LE)><serialized block> ...
//! ```
//!
//! A clean end-of-file at a record boundary terminates the stream, and
//! anything short of a whole record does not: a trailing fragment is an
//! error, as it is for dcrd's reader, which distinguishes `io.EOF` from
//! `io.ErrUnexpectedEOF`.  A network mismatch or a block length beyond
//! `wire.MaxBlockPayload` is an error too.
//!
//! [`read_block`] is the one port of dcrd's `readBlock`: the daemon's
//! `addblock` (`dcroxide-node`'s `addblock.rs`) reads its records with
//! it and runs every block through the chain, as dcrd's importer does,
//! and the bench replays corpora with it.
//!
//! [`Database::import_blocks`] is not that importer.  It stores blocks
//! straight into block storage with no block index, UTXO or consensus
//! work at all, and nothing but this crate's own tests calls it; it
//! exists to exercise block storage and [`Database::export_blocks`] in
//! bulk, and must not be wired in as a way to load a chain.

use std::io::{Read, Write};

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

/// Read the next block record from the reader (dcrd `readBlock`,
/// `cmd/addblock/import.go:60-94`).  Returns `Ok(None)` on a clean end
/// of file at a record boundary; every other outcome is an error whose
/// description is the text dcrd's reader returns: Go's `EOF` or
/// `unexpected EOF` for a short read, the network mismatch, or the
/// payload cap.
pub fn read_block(r: &mut impl Read, network: u32) -> Result<Option<Vec<u8>>, Error> {
    let fail = |description: String| db_error(ErrorKind::DriverSpecific, description);

    // The block file format is:
    //  <network> <block length> <serialized block>
    //
    // Go's `binary.Read` returns `io.EOF` only when it read nothing at
    // all and `io.ErrUnexpectedEOF` for a partial fill, and dcrd tests
    // for the former alone (`import.go:66-74`), so a trailing fragment
    // is an error there.
    let mut net_bytes = [0u8; 4];
    match read_full(r, &mut net_bytes) {
        ReadFull::Eof => return Ok(None),
        ReadFull::Short => return Err(fail("unexpected EOF".to_string())),
        ReadFull::Err(e) => return Err(fail(e)),
        ReadFull::Ok => {}
    }
    let net = u32::from_le_bytes(net_bytes);
    if net != network {
        return Err(fail(format!(
            "network mismatch -- got {net:x}, want {network:x}"
        )));
    }

    // Read the block length and ensure it is sane.
    let mut len_bytes = [0u8; 4];
    read_full(r, &mut len_bytes).into_result()?;
    let block_len = u32::from_le_bytes(len_bytes);
    if block_len > MAX_BLOCK_PAYLOAD {
        return Err(fail(format!(
            "block payload of {block_len} bytes is larger than the max allowed \
             {MAX_BLOCK_PAYLOAD} bytes"
        )));
    }

    let mut block = vec![0u8; block_len as usize];
    read_full(r, &mut block).into_result()?;
    Ok(Some(block))
}

/// How a full read of a buffer ended: Go `io.ReadFull`'s outcomes of a
/// filled buffer, `io.EOF` when nothing was read, `io.ErrUnexpectedEOF`
/// on a partial fill, or an underlying error.
enum ReadFull {
    Ok,
    Eof,
    Short,
    Err(String),
}

impl ReadFull {
    /// The outcome of a read that has no clean end, as dcrd's reader
    /// returns it: `EOF` and `unexpected EOF` are Go's error texts.
    fn into_result(self) -> Result<(), Error> {
        let description = match self {
            ReadFull::Ok => return Ok(()),
            ReadFull::Eof => "EOF".to_string(),
            ReadFull::Short => "unexpected EOF".to_string(),
            ReadFull::Err(e) => e,
        };
        Err(db_error(ErrorKind::DriverSpecific, description))
    }
}

/// Fill the buffer (Go `io.ReadFull`).  An interrupted read is retried,
/// as Go's runtime retries `EINTR` beneath `Read`; an empty buffer is
/// filled by definition.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> ReadFull {
    let mut filled = 0usize;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return ReadFull::Eof,
            Ok(0) => return ReadFull::Short,
            Ok(n) => filled = filled.saturating_add(n),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return ReadFull::Err(e.to_string()),
        }
    }
    ReadFull::Ok
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
    /// Bulk-store blocks from a bootstrap-format stream into block
    /// storage.  Malformed blocks are rejected and blocks that are
    /// already present are skipped.  Blocks are stored in batches of a
    /// few hundred per transaction.
    ///
    /// This is a storage-test helper, not an importer: it writes no
    /// block index or UTXO state and performs NO consensus validation,
    /// so a chain loaded through it is not a chain.  dcrd's `addblock`
    /// counterpart runs every block through the chain engine; that is
    /// `dcroxide-node`'s `addblock`, which only shares [`read_block`]
    /// with this module.
    pub fn import_blocks(&self, r: &mut impl Read, network: u32) -> Result<ImportStats, Error> {
        let mut stats = ImportStats::default();
        let mut batch: Vec<(dcroxide_chainhash::Hash, Vec<u8>)> = Vec::new();

        #[allow(
            clippy::arithmetic_side_effects,
            reason = "one increment per block in the batch: a u64 count of blocks read cannot overflow"
        )]
        let flush = |batch: &mut Vec<(dcroxide_chainhash::Hash, Vec<u8>)>,
                     stats: &mut ImportStats|
         -> Result<(), Error> {
            if batch.is_empty() {
                return Ok(());
            }
            self.update(|tx| {
                for (hash, raw) in batch.drain(..) {
                    if tx.has_block(&hash)? {
                        stats.skipped += 1;
                        continue;
                    }
                    tx.store_block_raw(&hash, raw)?;
                    stats.imported += 1;
                }
                Ok(())
            })?;
            Ok(())
        };

        #[allow(
            clippy::arithmetic_side_effects,
            reason = "one increment per block read: a u64 count of blocks cannot overflow"
        )]
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
    /// bootstrap-format stream readable by [`read_block`] (and so by the
    /// daemon's `addblock`) and by dcrd's `addblock`.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "one increment per hash in a slice: at most hashes.len()"
    )]
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A reader that fails its first `read` call with `Interrupted`,
    /// then serves the wrapped bytes a few at a time.
    struct Eintr<'a> {
        interrupted: bool,
        rest: &'a [u8],
    }

    impl Read for Eintr<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            let n = buf.len().min(self.rest.len()).min(3);
            buf[..n].copy_from_slice(&self.rest[..n]);
            self.rest = &self.rest[n..];
            Ok(n)
        }
    }

    fn description(res: Result<Option<Vec<u8>>, Error>) -> String {
        res.expect_err("an error").description
    }

    /// An interrupted read is retried rather than aborting the stream,
    /// as Go's runtime retries `EINTR` beneath the `io.ReadFull` dcrd's
    /// `readBlock` makes.  The earlier bare `read` of the first byte
    /// turned it into "failed to read network: ...".
    #[test]
    fn an_interrupted_read_is_retried() {
        let net = 0x1234_5678u32;
        let mut record = net.to_le_bytes().to_vec();
        record.extend_from_slice(&3u32.to_le_bytes());
        record.extend_from_slice(&[9, 8, 7]);

        let mut r = Eintr {
            interrupted: false,
            rest: &record,
        };
        assert_eq!(read_block(&mut r, net).expect("read"), Some(vec![9, 8, 7]));

        // An interrupt at a clean end is still a clean end.
        let mut r = Eintr {
            interrupted: false,
            rest: &[],
        };
        assert_eq!(read_block(&mut r, net).expect("clean end"), None);
    }

    /// The errors carry the text dcrd's `readBlock` returns, the same
    /// text the daemon's `addblock` prints.
    #[test]
    fn errors_carry_dcrds_text() {
        let net = 0x1234_5678u32;

        let mut partial: &[u8] = &[0x78, 0x56];
        assert_eq!(description(read_block(&mut partial, net)), "unexpected EOF");

        let mut mismatched: &[u8] = &0xdead_beefu32.to_le_bytes();
        assert_eq!(
            description(read_block(&mut mismatched, net)),
            "network mismatch -- got deadbeef, want 12345678"
        );

        let no_len = net.to_le_bytes();
        assert_eq!(description(read_block(&mut &no_len[..], net)), "EOF");

        let mut short_len = net.to_le_bytes().to_vec();
        short_len.push(1);
        assert_eq!(
            description(read_block(&mut short_len.as_slice(), net)),
            "unexpected EOF"
        );

        let mut oversized = net.to_le_bytes().to_vec();
        oversized.extend_from_slice(&(MAX_BLOCK_PAYLOAD + 1).to_le_bytes());
        assert_eq!(
            description(read_block(&mut oversized.as_slice(), net)),
            format!(
                "block payload of {} bytes is larger than the max allowed {} bytes",
                MAX_BLOCK_PAYLOAD + 1,
                MAX_BLOCK_PAYLOAD
            )
        );

        let mut no_block = net.to_le_bytes().to_vec();
        no_block.extend_from_slice(&8u32.to_le_bytes());
        assert_eq!(
            description(read_block(&mut no_block.as_slice(), net)),
            "EOF"
        );

        let mut truncated = no_block.clone();
        truncated.extend_from_slice(&[1, 2, 3]);
        assert_eq!(
            description(read_block(&mut truncated.as_slice(), net)),
            "unexpected EOF"
        );

        // A zero-length payload is a whole record (Go's `io.ReadFull`
        // of an empty buffer reads nothing and succeeds).
        let mut empty_block = net.to_le_bytes().to_vec();
        empty_block.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            read_block(&mut empty_block.as_slice(), net).expect("read"),
            Some(Vec::new())
        );
    }
}
