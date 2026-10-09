// SPDX-License-Identifier: ISC
//! The journal: the keys each flush made durable, so a restart can rebuild
//! the memtable.
//!
//! Rows are `B || 'J' || jseq || i`, both big-endian u32s, each holding up
//! to [`CHUNK`] strictly ascending keys: the keys flush number `jseq`
//! journaled.  A flush gathers them a partition at a time into a batch of
//! at most [`BATCH`] keys plus one partition, and writes each batch sorted
//! as full rows, so it never holds a second copy of more than that, and a
//! flush at the chain tip, with a block's hundred keys, writes one row.

use dcroxide_database::{Error, FlushWriter, Transaction};

use super::policy::{CHUNK, PARTITIONS};
use super::runs::{decode_keys, encode_chunk, hex};
use super::{Key, corrupt};

/// Keys a flush gathers before it sorts and writes them: 256 full rows,
/// about 1 MB.
pub(crate) const BATCH: usize = CHUNK * PARTITIONS;

/// The journal rows' suffix under the bucket id.
pub(crate) const JOURNAL_TAG: u8 = b'J';

/// Bytes of a journal row's key.
pub(crate) const JOURNAL_KEY_LEN: usize = 4 + 1 + 4 + 4;

/// `B || 'J'`: every journal row.
pub(crate) fn journal_prefix(bucket: &[u8]) -> Vec<u8> {
    let mut prefix = bucket.to_vec();
    prefix.push(JOURNAL_TAG);
    prefix
}

/// `B || 'J' || jseq`: the rows of one flush, and the point a restart
/// scans from.
pub(crate) fn jseq_prefix(bucket: &[u8], jseq: u32) -> Vec<u8> {
    let mut prefix = journal_prefix(bucket);
    prefix.extend_from_slice(&jseq.to_be_bytes());
    prefix
}

/// The key of row `i` of flush `jseq`.
pub(crate) fn row_key(bucket: &[u8], jseq: u32, i: u32) -> Vec<u8> {
    let mut key = jseq_prefix(bucket, jseq);
    key.extend_from_slice(&i.to_be_bytes());
    key
}

/// The flush number and row index of a journal row key under `bucket`.
pub(crate) fn parse_row_key(bucket: &[u8], key: &[u8]) -> Result<(u32, u32), Error> {
    if key.len() != JOURNAL_KEY_LEN || !key.starts_with(bucket) || key[4] != JOURNAL_TAG {
        return Err(corrupt(format!(
            "a journal row has a malformed key {}",
            hex(key)
        )));
    }
    let mut jseq = [0u8; 4];
    jseq.copy_from_slice(&key[5..9]);
    let mut i = [0u8; 4];
    i.copy_from_slice(&key[9..13]);
    Ok((u32::from_be_bytes(jseq), u32::from_be_bytes(i)))
}

/// Decode and check a journal row's keys.
pub(crate) fn decode_row(key: &[u8], value: &[u8]) -> Result<Vec<Key>, Error> {
    decode_keys(value, CHUNK, &format!("the journal row {}", hex(key)))
}

/// One flush's journal rows, gathered a partition at a time and numbered
/// from 0.
pub(crate) struct Appender {
    bucket: Vec<u8>,
    jseq: u32,
    rows: u32,
    keys: u64,
    batch: Vec<Key>,
}

impl Appender {
    /// The rows of flush `jseq` under `bucket`, none written yet.
    pub(crate) fn new(bucket: &[u8], jseq: u32) -> Appender {
        Appender {
            bucket: bucket.to_vec(),
            jseq,
            rows: 0,
            keys: 0,
            batch: Vec::new(),
        }
    }

    /// Journal one partition's keys, each once and none journaled before:
    /// into the batch, which is written once it holds [`BATCH`] keys.
    pub(crate) fn add(&mut self, w: &mut FlushWriter<'_, '_>, keys: &[Key]) -> Result<(), Error> {
        self.batch.extend_from_slice(keys);
        if self.batch.len() >= BATCH {
            self.write_batch(w)?;
        }
        Ok(())
    }

    /// Write what the batch still holds; returns the keys journaled.
    pub(crate) fn finish(mut self, w: &mut FlushWriter<'_, '_>) -> Result<u64, Error> {
        self.write_batch(w)?;
        Ok(self.keys)
    }

    /// Sort the batch and write it as rows of [`CHUNK`] keys.
    fn write_batch(&mut self, w: &mut FlushWriter<'_, '_>) -> Result<(), Error> {
        self.batch.sort_unstable();
        debug_assert!(self.batch.windows(2).all(|pair| pair[0] < pair[1]));
        for row in self.batch.chunks(CHUNK) {
            w.insert(
                &row_key(&self.bucket, self.jseq, self.rows),
                &encode_chunk(row),
            )?;
            self.rows = self
                .rows
                .checked_add(1)
                .ok_or_else(|| corrupt("a flush journaled more than 2^32 rows"))?;
            self.keys = self.keys.saturating_add(row.len() as u64);
        }
        self.batch.clear();
        Ok(())
    }
}

/// Remove the rows of every flush numbered `from..below`.  Each flush's
/// rows are numbered from 0 without gaps, so a flush's rows end at the
/// first index not found.  Returns the rows removed.
pub(crate) fn gc(w: &mut FlushWriter<'_, '_>, from: u32, below: u32) -> Result<u64, Error> {
    let bucket = w.prefix().to_vec();
    let mut removed = 0u64;
    for jseq in from..below {
        let mut i = 0u32;
        while w.remove(&row_key(&bucket, jseq, i))? {
            removed = removed.saturating_add(1);
            i = i.saturating_add(1);
        }
    }
    Ok(removed)
}

/// Rows a restart reads per window.
const LOAD_WINDOW: usize = 512;

/// Call `each(jseq, keys)` for every journal row from flush `from` on, in
/// key order, each row checked.
pub(crate) fn scan(
    tx: &Transaction,
    bucket: &[u8],
    from: u32,
    mut each: impl FnMut(u32, Vec<Key>) -> Result<(), Error>,
) -> Result<(), Error> {
    let prefix = journal_prefix(bucket);
    let mut after = jseq_prefix(bucket, from);
    // `after` itself is shorter than every row of flush `from`, so a
    // strictly-after scan starts at that flush's first row.
    loop {
        let rows = tx.try_scan_after(&prefix, Some(&after), LOAD_WINDOW)?;
        let Some((last, _)) = rows.last() else {
            return Ok(());
        };
        let next = last.clone();
        let full = rows.len() == LOAD_WINDOW;
        for (key, value) in rows {
            let (jseq, _) = parse_row_key(bucket, &key)?;
            let keys = decode_row(&key, &value)?;
            each(jseq, keys)?;
        }
        if !full {
            return Ok(());
        }
        after = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const B: [u8; 4] = [0, 0, 0, 42];

    /// Row keys round-trip, sort by flush then row, and a malformed one
    /// is corruption.
    #[test]
    fn journal_row_keys_round_trip_and_sort_by_flush_then_row() {
        let key = row_key(&B, 0x0102_0304, 7);
        assert_eq!(key.len(), JOURNAL_KEY_LEN);
        assert_eq!(parse_row_key(&B, &key).expect("parse"), (0x0102_0304, 7));
        assert!(row_key(&B, 1, u32::MAX) < row_key(&B, 2, 0));
        assert!(row_key(&B, 2, 0) < row_key(&B, 2, 1));
        // A restart's scan starts strictly after `B || 'J' || jseq`, which
        // every row of that flush sorts after.
        assert!(jseq_prefix(&B, 2) < row_key(&B, 2, 0));
        assert!(row_key(&B, 1, u32::MAX) < jseq_prefix(&B, 2));
        for bad in [
            &key[..12],
            &row_key(&[0, 0, 0, 43], 1, 0)[..],
            &[&B[..], b"R", &[0; 8]].concat()[..],
        ] {
            let err = parse_row_key(&B, bad).expect_err("malformed");
            assert_eq!(err.kind, dcroxide_database::ErrorKind::Corruption);
        }
    }

    /// A journal row holds 1..=192 strictly ascending keys.
    #[test]
    fn journal_rows_decode_and_check_their_keys() {
        let keys: Vec<Key> = (0..192u8).map(|n| [n; 21]).collect();
        let key = row_key(&B, 1, 0);
        assert_eq!(
            decode_row(&key, &encode_chunk(&keys)).expect("decode"),
            keys
        );
        let many: Vec<Key> = (0..193u16).map(|n| [(n / 2) as u8; 21]).collect();
        assert!(decode_row(&key, &encode_chunk(&many)).is_err(), "193 keys");
        assert!(decode_row(&key, &[]).is_err(), "empty");
        assert!(decode_row(&key, &encode_chunk(&[[2; 21], [1; 21]])).is_err());
    }
}
