// SPDX-License-Identifier: ISC
//! The sorted runs: per partition a delta run and a base run, each stored
//! as near-equal chunks of at most [`CHUNK`] keys, one chunk per row.
//!
//! A chunk row's key is `B || 'R' || p || lvl || last_key || 0xFF`, so the
//! chunk that may hold a key `k` is the first row after `B || 'R' || p ||
//! lvl || k`: its last key is the first at or above `k`, the trailing
//! `0xFF` making a chunk whose last key *is* `k` sort after that probe.

use dcroxide_database::{Error, FlushWriter, Transaction};

use super::policy::{CHUNK, Partitioner};
use super::{ADDR_KEY_SIZE, Key, corrupt};

/// The run rows' suffix under the bucket id.
pub(crate) const RUN_TAG: u8 = b'R';
/// The delta run's level byte.
pub(crate) const DELTA: u8 = 0;
/// The base run's level byte.
pub(crate) const BASE: u8 = 1;
/// The last byte of every chunk row's key.
const ROW_END: u8 = 0xFF;

/// Bytes of a chunk row's key: bucket id, tag, partition, level, last key
/// and the end byte.
pub(crate) const CHUNK_KEY_LEN: usize = 4 + 1 + 1 + 1 + ADDR_KEY_SIZE + 1;

/// `B || 'R' || p || lvl`: every chunk of one level of one partition.
pub(crate) fn level_prefix(bucket: &[u8], p: u8, lvl: u8) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(CHUNK_KEY_LEN);
    prefix.extend_from_slice(bucket);
    prefix.extend_from_slice(&[RUN_TAG, p, lvl]);
    prefix
}

/// The row key of the chunk ending in `last`.
pub(crate) fn chunk_key(bucket: &[u8], p: u8, lvl: u8, last: &Key) -> Vec<u8> {
    let mut key = level_prefix(bucket, p, lvl);
    key.extend_from_slice(last);
    key.push(ROW_END);
    key
}

/// A chunk row's value: its keys, concatenated.
pub(crate) fn encode_chunk(keys: &[Key]) -> Vec<u8> {
    let mut value = Vec::with_capacity(keys.len().saturating_mul(ADDR_KEY_SIZE));
    for key in keys {
        value.extend_from_slice(key);
    }
    value
}

/// Split concatenated 21-byte keys, checking they are 1..=`max` strictly
/// ascending keys.  Shared by chunk and journal rows.
pub(crate) fn decode_keys(value: &[u8], max: usize, what: &str) -> Result<Vec<Key>, Error> {
    if value.is_empty() || !value.len().is_multiple_of(ADDR_KEY_SIZE) {
        return Err(corrupt(format!(
            "{what} holds {} bytes, not a whole number of keys",
            value.len()
        )));
    }
    let n = value.len() / ADDR_KEY_SIZE;
    if n > max {
        return Err(corrupt(format!("{what} holds {n} keys, more than {max}")));
    }
    let mut keys: Vec<Key> = Vec::with_capacity(n);
    for key in value.as_chunks::<ADDR_KEY_SIZE>().0 {
        if keys.last().is_some_and(|prev| prev >= key) {
            return Err(corrupt(format!("{what} holds keys out of order")));
        }
        keys.push(*key);
    }
    Ok(keys)
}

/// A decoded, checked chunk row.
pub(crate) struct Chunk {
    pub(crate) p: u8,
    pub(crate) lvl: u8,
    pub(crate) keys: Vec<Key>,
}

/// How much of a chunk's partition filing [`decode_chunk`] checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Filing {
    /// Every key hashes to the row's partition: merges, walks and the
    /// layout check.
    Every,
    /// Only the last key, the one the row is filed under: a lookup's
    /// probe, which needs the order and the row's own filing, and not a
    /// hash of every key it does not look for.
    Last,
}

/// Decode and check a chunk row under `bucket`: the key's shape, 1..=192
/// strictly ascending keys, the last one equal to the key the row is filed
/// under, and the keys in the row's partition as `filing` says.
pub(crate) fn decode_chunk(
    part: &Partitioner,
    filing: Filing,
    bucket: &[u8],
    row_key: &[u8],
    value: &[u8],
) -> Result<Chunk, Error> {
    let shaped = row_key.len() == CHUNK_KEY_LEN
        && row_key.starts_with(bucket)
        && row_key[4] == RUN_TAG
        && row_key[6] <= BASE
        && row_key[CHUNK_KEY_LEN - 1] == ROW_END;
    if !shaped {
        return Err(corrupt(format!(
            "a run row has a malformed key {}",
            hex(row_key)
        )));
    }
    let (p, lvl) = (row_key[5], row_key[6]);
    let what = format!("the run chunk {}", hex(row_key));
    let keys = decode_keys(value, CHUNK, &what)?;
    let last = keys.last().expect("decode_keys returns at least one key");
    if last[..] != row_key[7..CHUNK_KEY_LEN - 1] {
        return Err(corrupt(format!(
            "{what} does not end with the key it is filed under"
        )));
    }
    let misfiled = match filing {
        Filing::Every => keys.iter().any(|k| part.of(k) != p),
        Filing::Last => part.of(last) != p,
    };
    if misfiled {
        return Err(corrupt(format!("{what} holds a key outside partition {p}")));
    }
    Ok(Chunk { p, lvl, keys })
}

/// The sizes of the near-equal chunks a level of `n` keys is written as:
/// `ceil(n / 192)` chunks whose sizes differ by at most one.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "chunks >= 1 once n >= 1, so neither division can trap"
)]
pub(crate) fn chunk_sizes(n: usize) -> Vec<usize> {
    if n == 0 {
        return Vec::new();
    }
    let chunks = n.div_ceil(CHUNK);
    let base = n / chunks;
    let extra = n % chunks;
    (0..chunks)
        .map(|i| {
            if i < extra {
                base.saturating_add(1)
            } else {
                base
            }
        })
        .collect()
}

/// Whether level `lvl` of partition `p` holds `key`: one row read and a
/// binary search inside its chunk.  A store read error is an error, not
/// absence, and so is a damaged chunk.
pub(crate) fn probe(
    tx: &Transaction,
    part: &Partitioner,
    bucket: &[u8],
    p: u8,
    key: &Key,
    lvl: u8,
) -> Result<bool, Error> {
    let prefix = level_prefix(bucket, p, lvl);
    let mut after = prefix.clone();
    after.extend_from_slice(key);
    let Some((row_key, value)) = tx.try_first_after(&prefix, &after)? else {
        return Ok(false);
    };
    let chunk = decode_chunk(part, Filing::Last, bucket, &row_key, &value)?;
    Ok(chunk.keys.binary_search(key).is_ok())
}

/// The sorted union of two sorted lists, each key once.
pub(crate) fn union(a: &[Key], b: &[Key]) -> Vec<Key> {
    let mut out = Vec::with_capacity(a.len().saturating_add(b.len()));
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            core::cmp::Ordering::Less => {
                out.push(a[i]);
                i = i.saturating_add(1);
            }
            core::cmp::Ordering::Greater => {
                out.push(b[j]);
                j = j.saturating_add(1);
            }
            core::cmp::Ordering::Equal => {
                out.push(a[i]);
                i = i.saturating_add(1);
                j = j.saturating_add(1);
            }
        }
    }
    out.extend_from_slice(&a[i..]);
    out.extend_from_slice(&b[j..]);
    out
}

/// One level of one partition as read inside a flush: the row keys, for
/// removal, and the keys, checked.
#[derive(Default)]
pub(crate) struct Level {
    pub(crate) rows: Vec<Vec<u8>>,
    pub(crate) keys: Vec<Key>,
}

/// Read and check a level: every chunk decodes, every key is filed in
/// `p`, and the chunks ascend without overlap.
pub(crate) fn read_level(
    w: &mut FlushWriter<'_, '_>,
    part: &Partitioner,
    p: u8,
    lvl: u8,
) -> Result<Level, Error> {
    let bucket = w.prefix().to_vec();
    let rows = w.range_prefix(&level_prefix(&bucket, p, lvl))?;
    let mut level = Level::default();
    for (row_key, value) in rows {
        let chunk = decode_chunk(part, Filing::Every, &bucket, &row_key, &value)?;
        if chunk.p != p || chunk.lvl != lvl {
            return Err(corrupt(format!(
                "the run row {} is filed under the wrong level",
                hex(&row_key)
            )));
        }
        if let (Some(prev), Some(first)) = (level.keys.last(), chunk.keys.first())
            && prev >= first
        {
            return Err(corrupt(format!(
                "the run chunks of partition {p} level {lvl} overlap at {}",
                hex(&row_key)
            )));
        }
        level.keys.extend_from_slice(&chunk.keys);
        level.rows.push(row_key);
    }
    Ok(level)
}

/// Remove a level's rows.
pub(crate) fn remove_level(w: &mut FlushWriter<'_, '_>, old: &Level) -> Result<(), Error> {
    for row in &old.rows {
        w.remove(row)?;
    }
    Ok(())
}

/// Replace a level's rows with `keys`, written as near-equal chunks in
/// ascending order.  Returns the rows written, each one 4 KiB leaf.
pub(crate) fn write_level(
    w: &mut FlushWriter<'_, '_>,
    p: u8,
    lvl: u8,
    old: &Level,
    keys: &[Key],
) -> Result<usize, Error> {
    remove_level(w, old)?;
    let bucket = w.prefix().to_vec();
    let mut at = 0usize;
    let sizes = chunk_sizes(keys.len());
    for &size in &sizes {
        let end = at.saturating_add(size);
        let chunk = &keys[at..end];
        let last = chunk.last().expect("chunk sizes are positive");
        w.insert(&chunk_key(&bucket, p, lvl, last), &encode_chunk(chunk))?;
        at = end;
    }
    Ok(sizes.len())
}

/// Lowercase hex, for error text.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const B: [u8; 4] = [0, 0, 0, 42];

    fn part() -> Partitioner {
        Partitioner::new(&[0x42; 16])
    }

    /// The `n`th key of type `t` in partition `p`: ascending in `n`, the
    /// bytes after `n` searched until the key hashes into `p`.
    fn key(t: u8, p: u8, n: u16) -> Key {
        let part = part();
        (0u32..)
            .map(|c| {
                let mut k = [0u8; 21];
                k[0] = t;
                k[1..3].copy_from_slice(&n.to_be_bytes());
                k[3..7].copy_from_slice(&c.to_be_bytes());
                k
            })
            .find(|k| part.of(k) == p)
            .expect("some key hashes into every partition")
    }

    fn decode(row: &[u8], value: &[u8]) -> Result<Chunk, Error> {
        decode_chunk(&part(), Filing::Every, &B, row, value)
    }

    /// Near-equal splitting at and around the chunk size.
    #[test]
    fn levels_split_into_near_equal_chunks() {
        assert!(chunk_sizes(0).is_empty());
        assert_eq!(chunk_sizes(1), vec![1]);
        assert_eq!(chunk_sizes(191), vec![191]);
        assert_eq!(chunk_sizes(192), vec![192]);
        assert_eq!(chunk_sizes(193), vec![97, 96]);
        assert_eq!(chunk_sizes(385), vec![129, 128, 128]);
        for n in 1..2000 {
            let sizes = chunk_sizes(n);
            assert_eq!(sizes.iter().sum::<usize>(), n);
            assert_eq!(sizes.len(), n.div_ceil(CHUNK));
            let (lo, hi) = (sizes.iter().min().unwrap(), sizes.iter().max().unwrap());
            assert!(*hi <= CHUNK && hi - lo <= 1, "{n}: {sizes:?}");
        }
    }

    /// A chunk round-trips, and the row key ends with its last key.
    #[test]
    fn a_chunk_round_trips() {
        let keys: Vec<Key> = (0..192).map(|n| key(0, 9, n)).collect();
        let row = chunk_key(&B, 9, BASE, keys.last().unwrap());
        assert_eq!(row.len(), CHUNK_KEY_LEN);
        let value = encode_chunk(&keys);
        assert_eq!(value.len(), 4032);
        let chunk = decode(&row, &value).expect("decode");
        assert_eq!((chunk.p, chunk.lvl), (9, BASE));
        assert_eq!(chunk.keys, keys);
    }

    /// Every way a chunk row can be wrong is corruption.
    #[test]
    fn bad_chunks_are_corruption() {
        let keys: Vec<Key> = (0..3).map(|n| key(0, 9, n)).collect();
        let row = chunk_key(&B, 9, DELTA, &keys[2]);
        let value = encode_chunk(&keys);
        let bad = |row: &[u8], value: &[u8]| {
            let err = decode(row, value).err().expect("must fail");
            assert_eq!(err.kind, dcroxide_database::ErrorKind::Corruption);
            assert!(err.description.contains("--dropexistsaddrindex"), "{err}");
        };
        // Bad length.
        bad(&row, &value[..62]);
        bad(&row, &[]);
        // Too many keys.
        let many: Vec<Key> = (0..193).map(|n| key(0, 9, n)).collect();
        bad(&chunk_key(&B, 9, DELTA, &many[192]), &encode_chunk(&many));
        // Unsorted and duplicated keys.
        bad(&row, &encode_chunk(&[keys[1], keys[0], keys[2]]));
        bad(&row, &encode_chunk(&[keys[0], keys[0], keys[2]]));
        // A key from another partition, which a probe's check of the
        // filing alone lets through, and one filed under the wrong
        // partition, which it does not.
        let stray = encode_chunk(&[keys[0], key(0, 8, 1), keys[2]]);
        bad(&row, &stray);
        assert!(decode_chunk(&part(), Filing::Last, &B, &row, &stray).is_ok());
        let mut misfiled = row.clone();
        misfiled[5] = 8;
        bad(&misfiled, &value);
        assert!(decode_chunk(&part(), Filing::Last, &B, &misfiled, &value).is_err());
        // The last key not the row's.
        bad(&row, &encode_chunk(&keys[..2]));
        // Malformed row keys: wrong bucket, level, end byte, length.
        bad(&chunk_key(&[0, 0, 0, 43], 9, DELTA, &keys[2]), &value);
        let mut lvl = row.clone();
        lvl[6] = 2;
        bad(&lvl, &value);
        let mut end = row.clone();
        end[CHUNK_KEY_LEN - 1] = 0;
        bad(&end, &value);
        bad(&row[..CHUNK_KEY_LEN - 1], &value);
    }

    /// Script-hash keys (type 3) sort after pubkey-hash keys (type 0) of
    /// the same partition, so they land in later chunks.
    #[test]
    fn type_3_keys_sort_after_type_0() {
        let a = key(0, 5, 999);
        let b = key(3, 5, 0);
        assert!(a < b);
        assert_eq!(union(&[b], &[a]), vec![a, b]);
    }

    /// The union is sorted, each key once.
    #[test]
    fn the_union_drops_duplicates() {
        let a: Vec<Key> = [1, 3, 5, 7].iter().map(|&n| key(0, 1, n)).collect();
        let b: Vec<Key> = [2, 3, 7, 9].iter().map(|&n| key(0, 1, n)).collect();
        let want: Vec<Key> = [1, 2, 3, 5, 7, 9].iter().map(|&n| key(0, 1, n)).collect();
        assert_eq!(union(&a, &b), want);
        assert_eq!(union(&a, &[]), a);
        assert_eq!(union(&[], &b), b);
    }
}
