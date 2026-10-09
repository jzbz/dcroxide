// SPDX-License-Identifier: ISC
//! The meta row: the journal sequence, the partition hash's key and, per
//! partition, where its unmerged keys start in the journal and how many
//! keys its runs hold.

use dcroxide_database::Error;

use super::corrupt;
use super::policy::{PARTITION_KEY_LEN, PARTITIONS};

/// The meta row's suffix under the bucket id.
pub(crate) const META_TAG: u8 = b'M';

/// The row format's own version, separate from the index version.  1 was
/// the format before the partition key, which filed keys by their first
/// hash160 byte; no released build wrote it.
const LAYOUT: u8 = 2;

/// Encoded size: layout byte, journal sequence, partition key, and three
/// u32s per partition.
pub(crate) const META_LEN: usize = 1 + 4 + PARTITION_KEY_LEN + PARTITIONS * 12;

/// Where the per-partition fields start.
const PER_PARTITION_AT: usize = 1 + 4 + PARTITION_KEY_LEN;

/// What the meta row records.  Absent, it is all zeros but the partition
/// key, which the index draws when it is created: no flush has
/// contributed yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Meta {
    /// The number of the newest flush that contributed.
    pub(crate) jseq: u32,
    /// The key of the partition hash every run and journal row is filed
    /// under ([`super::policy::Partitioner`]).
    pub(crate) partition_key: [u8; PARTITION_KEY_LEN],
    /// Per partition, the oldest journal number that may still hold its
    /// keys not yet in a run.
    pub(crate) pend_from: [u32; PARTITIONS],
    /// Per partition, the keys in its delta run.
    pub(crate) d_keys: [u32; PARTITIONS],
    /// Per partition, the keys in its base run.
    pub(crate) b_keys: [u32; PARTITIONS],
}

impl Default for Meta {
    fn default() -> Meta {
        Meta {
            jseq: 0,
            partition_key: [0; PARTITION_KEY_LEN],
            pend_from: [0; PARTITIONS],
            d_keys: [0; PARTITIONS],
            b_keys: [0; PARTITIONS],
        }
    }
}

impl Meta {
    /// The meta of an index no flush has contributed to, whose keys the
    /// partition hash keyed by `partition_key` files.
    pub(crate) fn fresh(partition_key: [u8; PARTITION_KEY_LEN]) -> Meta {
        Meta {
            partition_key,
            ..Meta::default()
        }
    }

    /// The journal number below which no row holds a key outside a run.
    pub(crate) fn min_pend_from(&self) -> u32 {
        self.pend_from.iter().copied().min().unwrap_or(0)
    }

    /// The 3,093-byte row value.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(META_LEN);
        out.push(LAYOUT);
        out.extend_from_slice(&self.jseq.to_be_bytes());
        out.extend_from_slice(&self.partition_key);
        for p in 0..PARTITIONS {
            out.extend_from_slice(&self.pend_from[p].to_be_bytes());
            out.extend_from_slice(&self.d_keys[p].to_be_bytes());
            out.extend_from_slice(&self.b_keys[p].to_be_bytes());
        }
        out
    }

    /// Decode and check a row value.
    pub(crate) fn decode(value: &[u8]) -> Result<Meta, Error> {
        if value.len() != META_LEN {
            return Err(corrupt(format!(
                "the meta row is {} bytes, not {META_LEN}",
                value.len()
            )));
        }
        if value[0] != LAYOUT {
            return Err(corrupt(format!(
                "the meta row has layout {}, not {LAYOUT}",
                value[0]
            )));
        }
        let u32_at = |at: usize| {
            let mut b = [0u8; 4];
            b.copy_from_slice(&value[at..at.saturating_add(4)]);
            u32::from_be_bytes(b)
        };
        let mut meta = Meta {
            jseq: u32_at(1),
            ..Meta::default()
        };
        meta.partition_key
            .copy_from_slice(&value[5..PER_PARTITION_AT]);
        for p in 0..PARTITIONS {
            let at = p.saturating_mul(12).saturating_add(PER_PARTITION_AT);
            meta.pend_from[p] = u32_at(at);
            meta.d_keys[p] = u32_at(at.saturating_add(4));
            meta.b_keys[p] = u32_at(at.saturating_add(8));
            if meta.pend_from[p] > meta.jseq.saturating_add(1) {
                return Err(corrupt(format!(
                    "the meta row has partition {p} pending from journal {}, past the newest, {}",
                    meta.pend_from[p], meta.jseq
                )));
            }
        }
        Ok(meta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_meta_row_round_trips_and_is_3093_bytes() {
        let mut meta = Meta {
            jseq: 0x0102_0304,
            partition_key: core::array::from_fn(|i| 0xA0 + i as u8),
            ..Meta::default()
        };
        for p in 0..PARTITIONS {
            meta.pend_from[p] = (p as u32) % 7;
            meta.d_keys[p] = p as u32 * 3;
            meta.b_keys[p] = u32::MAX - p as u32;
        }
        let row = meta.encode();
        assert_eq!(row.len(), 3093);
        assert_eq!(&row[..6], &[2, 1, 2, 3, 4, 0xA0]);
        assert_eq!(&row[21..25], &0u32.to_be_bytes(), "partition 0's pend_from");
        assert_eq!(Meta::decode(&row).expect("decode"), meta);
        assert_eq!(meta.min_pend_from(), 0);
        assert_eq!(
            Meta::fresh(meta.partition_key).partition_key,
            meta.partition_key
        );
    }

    #[test]
    fn a_bad_meta_row_is_corruption() {
        let row = Meta::default().encode();
        for bad in [&row[..3092], &[&row[..], &[0][..]].concat()[..]] {
            let err = Meta::decode(bad).expect_err("bad length");
            assert_eq!(err.kind, dcroxide_database::ErrorKind::Corruption);
        }
        // Layout 1, the format before the partition key, is refused.
        let mut layout = row.clone();
        layout[0] = 1;
        assert!(Meta::decode(&layout).is_err());
        let mut ahead = row;
        ahead[PER_PARTITION_AT..PER_PARTITION_AT + 4].copy_from_slice(&2u32.to_be_bytes());
        let err = Meta::decode(&ahead).expect_err("pending past the newest journal");
        assert!(err.description.contains("--dropexistsaddrindex"), "{err}");
    }
}
