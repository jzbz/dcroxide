// SPDX-License-Identifier: ISC
//! The fixed shape of layout 3 and the tuning of its merges.
//!
//! The shape constants and the partition hash are part of the on-disk
//! format; the [`Policy`] values only decide when the participant merges,
//! so changing them changes the pages a flush writes but never what a
//! lookup answers.

use core::hash::Hasher as _;

use siphasher::sip::SipHasher24;

use super::Key;

/// Partitions: one per value of a key's partition hash ([`Partitioner`]).
pub(crate) const PARTITIONS: usize = 256;

/// Bytes of the key the partition hash is keyed with, which the meta row
/// records.
pub(crate) const PARTITION_KEY_LEN: usize = 16;

/// Keys per chunk row and per journal row: 192 x 21 = 4,032 value bytes,
/// which with a chunk row's 29-byte key and redb's per-entry overhead fills
/// exactly one 4 KiB leaf (redb 4.3.0 `btree_base.rs` `required_bytes`,
/// `leaf_fits_one_page`).
pub(crate) const CHUNK: usize = 192;

/// When the exists-address index's flush participant merges its memtable
/// into the sorted runs, and when it asks for a flush.
///
/// The defaults are the plan's model knee; [`Policy::tiny`] is for tests,
/// which need every merge and journal path to run within a handful of
/// blocks.  No setting changes an answer, only the pages a flush writes and
/// the memory the memtable holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Merge while the memtable holds more keys than this.  About 42 MB of
    /// keys at the default.
    pub k0: usize,
    /// Keep merging past the page budget while the memtable holds more
    /// keys than this, so a deferred merge cannot grow memory without
    /// bound.
    pub k0_hard: usize,
    /// Run-chunk rows (4 KiB leaves) one flush may write before it stops
    /// merging.  The first merge of a flush always runs.
    pub budget_pages: usize,
    /// Ask for a flush once this many keys are in memory and not yet
    /// journaled.  Drives the flushes of a catch-up, where the overlay
    /// barely grows.
    pub u_max: usize,
    /// The key of the partition hash for an index created under this
    /// policy; `None`, the default, draws one from the operating system's
    /// randomness.  An index that exists keeps the key its meta row
    /// records, whatever this says.  Tests fix it so their layouts repeat;
    /// a node must not, or anyone who knows the key can choose which
    /// partition their addresses land in, and crowd one.
    pub partition_key: Option<[u8; PARTITION_KEY_LEN]>,
}

impl Default for Policy {
    fn default() -> Policy {
        Policy {
            k0: 2_000_000,
            k0_hard: 3_000_000,
            budget_pages: 12_000,
            u_max: 1_500_000,
            partition_key: None,
        }
    }
}

impl Policy {
    /// Limits small enough that journaling, both run rewrites and journal
    /// garbage collection all happen within a few blocks: `k0` 4, `k0_hard`
    /// 6, a one-page budget and `u_max` 8; and a fixed partition key, so a
    /// test's layout, and the paths it runs, repeat with its seed.
    pub fn tiny() -> Policy {
        Policy {
            k0: 4,
            k0_hard: 6,
            budget_pages: 1,
            u_max: 8,
            partition_key: Some(*b"Policy::tiny key"),
        }
    }

    /// The defaults with the memtable target set to `k0` keys and the hard
    /// bound to one and a half times that, as the developer-only
    /// `DCROXIDE_EXISTSADDR_MEMTABLE_KEYS` sets them.
    pub fn with_memtable_keys(k0: usize) -> Policy {
        Policy {
            k0,
            k0_hard: k0.saturating_add(k0 / 2),
            ..Policy::default()
        }
    }

    /// The memtable share one partition holds at the target, `m* = 2 k0 /
    /// (P + 1)`, and at least one key.
    ///
    /// The floor only matters below `k0` = 129, which only a test policy
    /// sets: without it every merge of a partition holding a key or two
    /// would rewrite its base, and the delta path would never run.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "floating point: no overflow trap, and k0 is a key count"
    )]
    pub(crate) fn m_star(&self) -> f64 {
        (2.0 * self.k0 as f64 / (PARTITIONS as f64 + 1.0)).max(1.0)
    }

    /// The size a partition's delta run may reach before a merge rewrites
    /// its base instead: `max(m*, phi_p sqrt(2 b m*))`, the optimum of
    /// `(n + 1) / 2 + b / (n m*)` rewrites per key, staggered by
    /// [`phi`] so the partitions' base rewrites do not fall in one flush.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "floating point: no overflow trap"
    )]
    pub(crate) fn dcap(&self, p: u8, b_keys: u64) -> f64 {
        let m = self.m_star();
        let staggered = phi(p) * (2.0 * b_keys as f64 * m).sqrt();
        m.max(staggered)
    }
}

/// The stagger factor of partition `p`, in `[0.5, 1.5)`: `0.5 + ((97 p)
/// mod 256) / 256`.  97 is odd, so the factors are a permutation of the
/// 256 steps.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "97 * 255 fits a u32, and the rest is floating point"
)]
pub(crate) fn phi(p: u8) -> f64 {
    0.5 + f64::from((97 * u32::from(p)) % 256) / 256.0
}

/// Where a key goes: the top byte of SipHash-2-4 of its 21 bytes, keyed
/// by the index's partition key.
///
/// Not the key's own bytes.  A key's hash160 is uniform for addresses
/// nobody chose, but whoever pays to an address chooses it, and a key
/// whose first hash160 byte is a given value takes about 256 tries to
/// find.  Partitioned by that byte, an adversary could put every address
/// of a run of blocks in one partition: one merge would then rewrite a
/// base run of any size, whatever the page budget, hold several copies of
/// it in memory, and leave the other partitions unmerged, so the journal
/// every restart reads would grow without bound.  Keyed by a secret drawn
/// when the index is created, the hash leaves nothing to grind, and every
/// partition's share stays near 1/256 of whatever arrives.
///
/// The hash and the byte taken from it are part of the on-disk format: a
/// store records its key in the meta row, and its runs and journal rows
/// are filed under this function's answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Partitioner {
    k0: u64,
    k1: u64,
}

impl Partitioner {
    /// The partitioner keyed by `key`, split into two little-endian
    /// words as SipHash's reference code splits its 128-bit key.
    pub(crate) fn new(key: &[u8; PARTITION_KEY_LEN]) -> Partitioner {
        let mut k0 = [0u8; 8];
        let mut k1 = [0u8; 8];
        k0.copy_from_slice(&key[..8]);
        k1.copy_from_slice(&key[8..]);
        Partitioner {
            k0: u64::from_le_bytes(k0),
            k1: u64::from_le_bytes(k1),
        }
    }

    /// SipHash-2-4 of `data` under this key.
    fn sip(&self, data: &[u8]) -> u64 {
        let mut hasher = SipHasher24::new_with_keys(self.k0, self.k1);
        hasher.write(data);
        hasher.finish()
    }

    /// The partition `key` belongs to.
    pub(crate) fn of(&self, key: &Key) -> u8 {
        self.sip(key).to_be_bytes()[0]
    }
}

/// A fresh partition key from the operating system's randomness.
pub(crate) fn random_partition_key() -> Result<[u8; PARTITION_KEY_LEN], dcroxide_database::Error> {
    let mut key = [0u8; PARTITION_KEY_LEN];
    getrandom::fill(&mut key).map_err(|e| dcroxide_database::Error {
        kind: dcroxide_database::ErrorKind::DriverSpecific,
        description: format!(
            "exists address index: no system randomness for a new partition key: {e}"
        ),
    })?;
    Ok(key)
}

/// The partition of `key` under the partition key `partition_key`, for
/// tests that need keys in chosen partitions of an index whose policy
/// fixed its key.
#[doc(hidden)]
pub fn partition_of(partition_key: &[u8; PARTITION_KEY_LEN], key: &Key) -> u8 {
    Partitioner::new(partition_key).of(key)
}

/// The order a flush considers partitions for merging: largest first, ties
/// to the lowest partition, empty partitions left out.
pub(crate) fn merge_order(sizes: &[usize; PARTITIONS]) -> Vec<u8> {
    let mut order: Vec<u8> = (0..=u8::MAX)
        .filter(|&p| sizes[usize::from(p)] > 0)
        .collect();
    order.sort_by(|&a, &b| {
        sizes[usize::from(b)]
            .cmp(&sizes[usize::from(a)])
            .then(a.cmp(&b))
    });
    order
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stagger factors are 256 distinct steps of 1/256 from 0.5.
    #[test]
    fn phi_is_a_permutation_of_the_steps() {
        let mut steps: Vec<u32> = (0..=u8::MAX)
            .map(|p| ((phi(p) - 0.5) * 256.0) as u32)
            .collect();
        steps.sort_unstable();
        assert_eq!(steps, (0..256).collect::<Vec<u32>>());
        assert_eq!(phi(0), 0.5);
        assert_eq!(phi(1), 0.5 + 97.0 / 256.0);
        assert_eq!(phi(3), 0.5 + 35.0 / 256.0, "291 mod 256 = 35");
    }

    /// dcap is m* for an empty base and grows with the square root of the
    /// base, scaled by the partition's stagger.
    #[test]
    fn dcap_follows_the_formula() {
        let p = Policy::default();
        let m = 4_000_000.0 / 257.0;
        assert!((p.m_star() - m).abs() < 1e-9);
        assert_eq!(p.dcap(0, 0), m);
        let b = 260_000u64;
        let want = (0.5 * (2.0 * b as f64 * m).sqrt()).max(m);
        assert!((p.dcap(0, b) - want).abs() < 1e-6);
        // Staggering: the same base gives different caps per partition.
        assert!(p.dcap(1, b) > p.dcap(0, b));
        // A large base lifts the cap above m*.
        assert!(p.dcap(128, 66_000_000 / 256) > m);
        // A test policy's cap is never below one key.
        assert_eq!(Policy::tiny().m_star(), 1.0);
        assert_eq!(Policy::tiny().dcap(0, 0), 1.0);
        assert!((Policy::tiny().dcap(1, 200) - phi(1) * 20.0).abs() < 1e-9);
    }

    /// Largest first, the lowest partition winning ties, empties skipped.
    #[test]
    fn merge_order_is_largest_first_with_lowest_p_ties() {
        let mut sizes = [0usize; PARTITIONS];
        sizes[5] = 10;
        sizes[2] = 10;
        sizes[200] = 30;
        sizes[7] = 1;
        assert_eq!(merge_order(&sizes), vec![200, 2, 5, 7]);
        assert!(merge_order(&[0usize; PARTITIONS]).is_empty());
    }

    /// The developer knob sets the target and one and a half times it.
    #[test]
    fn the_memtable_knob_sets_the_target_and_the_hard_bound() {
        let p = Policy::with_memtable_keys(1_000_000);
        assert_eq!(p.k0, 1_000_000);
        assert_eq!(p.k0_hard, 1_500_000);
        assert_eq!(p.budget_pages, Policy::default().budget_pages);
        assert_eq!(p.u_max, Policy::default().u_max);
        assert_eq!(p.partition_key, None);
    }

    /// The hash is SipHash-2-4: the reference implementation's vector for
    /// the 15-byte message 00..0e under the key 00..0f (the SipHash
    /// paper, appendix A).
    #[test]
    fn the_partition_hash_is_siphash_2_4() {
        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        let message: Vec<u8> = (0..15u8).collect();
        assert_eq!(Partitioner::new(&key).sip(&message), 0xa129_ca61_49be_45e5);
    }

    /// The on-disk mapping, pinned: these answers file existing rows, so
    /// a change of hash, key split or output byte must fail here first.
    #[test]
    fn the_partition_of_a_key_is_pinned() {
        let pkey: [u8; 16] = core::array::from_fn(|i| i as u8);
        let part = Partitioner::new(&pkey);
        let key: Key = core::array::from_fn(|i| i as u8);
        let zero = [0u8; 21];
        let mut ones = [0xFFu8; 21];
        ones[0] = 3;
        let got = [part.of(&key), part.of(&zero), part.of(&ones)];
        assert_eq!(got, PINNED, "{got:?}");
        assert_eq!(partition_of(&pkey, &key), part.of(&key));
        // Another key places the same address elsewhere.
        let other = Partitioner::new(&[7u8; 16]);
        assert_ne!([other.of(&key), other.of(&zero), other.of(&ones)], PINNED);
    }
    const PINNED: [u8; 3] = [208, 21, 254];

    /// Keys an adversary grinds to share a first hash160 byte, as they
    /// would to crowd a partition placed by that byte, spread over every
    /// partition, none holding much more than its 1/256 share.
    #[test]
    fn keys_sharing_a_hash160_byte_spread_over_every_partition() {
        let part = Partitioner::new(&[0x5Au8; 16]);
        let mut counts = [0usize; PARTITIONS];
        let n = 256 * 400;
        for i in 0..n as u32 {
            let mut key = [0u8; 21];
            key[1] = 0; // the byte the adversary fixes
            key[2..6].copy_from_slice(&i.to_be_bytes());
            counts[usize::from(part.of(&key))] += 1;
        }
        let (min, max) = (*counts.iter().min().unwrap(), *counts.iter().max().unwrap());
        // 400 expected per partition, standard deviation 20.
        assert!(min > 300 && max < 500, "{min}..{max}");
    }
}
