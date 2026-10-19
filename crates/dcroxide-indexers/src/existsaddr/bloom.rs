// SPDX-License-Identifier: ISC
//! A memtable partition's Bloom filter: a test that rules out most keys
//! the partition does not hold before any of its sorted vectors is
//! searched.
//!
//! A filter answers "no" or "maybe".  "No" is exact: every key the
//! partition holds has had its bits set, so a key the filter rules out
//! is not held, and a lookup's answer is the search's whenever the filter
//! lets a key through.  The filter only spares the searches that would
//! have missed.
//!
//! A filter is an array of 64-byte blocks, one cache line each.  A key
//! sets one bit in each of its block's eight words, so a probe reads one
//! line, where a binary search of a partition's vectors reads a dozen or
//! more.  The block comes from the high half of the key's hash and the
//! eight bits from the low half, each by its own odd multiplier: the
//! split-block filter of Apache Parquet's format, there with 32-bit words
//! and here with 64-bit ones.
//!
//! A filter is built at sixteen bits a key held, and built again, larger,
//! before its keys would leave it fewer than eight, so a partition's
//! filter takes at most two bytes a key it holds plus one block.  At
//! eight bits a key about one key in 34 that the partition does not hold
//! passes the filter, at sixteen about one in 1,100 (a test below holds
//! the two shares to 2-4% and under 0.2%).
//!
//! The hash is not keyed.  A key's hash160 is uniform for addresses
//! nobody chose; whoever pays to addresses can grind ones whose bits are
//! set, or that crowd one block.  That buys no more than the filter
//! would have saved: a key it lets through is searched for as every key
//! was before it, so no answer depends on the hash, and a lookup costs
//! at most one probe more than a search alone.  Nothing of a filter is
//! on disk: a load builds it from the keys it reads back.

use super::Key;

/// Words in a block, and bits a key sets: one in each word.
const WORDS: usize = 8;

/// Keys a block stands for when a filter is built: sixteen bits each.
const KEYS_A_BLOCK_BUILT: usize = 32;

/// The most keys a block may stand for before the filter must be built
/// again, larger: eight bits each.
const KEYS_A_BLOCK_MOST: usize = 64;

/// The odd multipliers that spread a key's 32-bit tag over its block's
/// words, one a word: Apache Parquet's split-block filter's salts.
const SALT: [u32; WORDS] = [
    0x47b6_137b,
    0x4497_4d91,
    0x8824_ad5b,
    0xa2b7_289d,
    0x7054_95c7,
    0x2df1_424b,
    0x9efc_4947,
    0x5c6b_fb31,
];

/// One block: 512 bits, as eight words, on a cache line of its own.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(align(64))]
struct Block([u64; WORDS]);

/// A Bloom filter of a set of keys.  The default has no blocks and holds
/// nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Bloom {
    blocks: Vec<Block>,
}

impl Bloom {
    /// The filter of `len` keys, sized for them: every key of every
    /// vector of `keys`, which hold `len` keys in all.  No blocks when
    /// `len` is zero.
    pub(crate) fn of<'a>(len: usize, keys: impl IntoIterator<Item = &'a [Key]>) -> Bloom {
        let mut bloom = Bloom {
            blocks: vec![Block::default(); len.div_ceil(KEYS_A_BLOCK_BUILT)],
        };
        let mut added = 0usize;
        for vector in keys {
            for key in vector {
                bloom.add(key);
            }
            added = added.saturating_add(vector.len());
        }
        debug_assert_eq!(added, len, "a filter sized for other keys than it holds");
        bloom
    }

    /// Whether the filter can stand for `keys` keys without being built
    /// again: eight bits a key or more.
    pub(crate) fn fits(&self, keys: usize) -> bool {
        keys <= self.blocks.len().saturating_mul(KEYS_A_BLOCK_MOST)
    }

    /// Set `key`'s bits.  Only for a filter that [`fits`](Self::fits) the
    /// keys it will stand for, which a filter with no blocks never does.
    pub(crate) fn add(&mut self, key: &Key) {
        let (i, tag) = self.place(key);
        let block = &mut self
            .blocks
            .get_mut(i)
            .expect("a key added to a filter with no blocks")
            .0;
        for (word, mask) in block.iter_mut().zip(masks(tag)) {
            *word |= mask;
        }
    }

    /// False when the filter's set holds no `key`; true when it may.
    pub(crate) fn may_hold(&self, key: &Key) -> bool {
        let (i, tag) = self.place(key);
        let Some(block) = self.blocks.get(i) else {
            // No blocks: the filter of no keys.
            return false;
        };
        block
            .0
            .iter()
            .zip(masks(tag))
            .all(|(word, mask)| word & mask == mask)
    }

    /// Blocks, for tests.
    #[cfg(test)]
    pub(crate) fn blocks(&self) -> usize {
        self.blocks.len()
    }

    /// The filter of the keys of `keys` with as many blocks as this one,
    /// for the tests that check a filter holds the bits of its keys and
    /// of no others.
    #[cfg(test)]
    pub(crate) fn same_size_of<'a>(&self, keys: impl IntoIterator<Item = &'a [Key]>) -> Bloom {
        let mut bloom = Bloom {
            blocks: vec![Block::default(); self.blocks.len()],
        };
        for vector in keys {
            for key in vector {
                bloom.add(key);
            }
        }
        bloom
    }

    /// `key`'s block and its tag, the hash's low half.  With no blocks
    /// the block is 0, which does not exist.
    fn place(&self, key: &Key) -> (usize, u32) {
        let h = hash(key);
        let n = self.blocks.len() as u64;
        // The high half scaled to the block count, as a multiply and a
        // shift: below 2^32 times n, then divided by 2^32, so below n.
        let i = ((h >> 32).wrapping_mul(n) >> 32) as usize;
        (i, h as u32)
    }
}

/// The bit each word of a block takes for `tag`: the top six bits of the
/// tag times the word's salt.
fn masks(tag: u32) -> [u64; WORDS] {
    core::array::from_fn(|w| 1u64 << (tag.wrapping_mul(SALT[w]) >> 26))
}

/// The filter's hash of `key`: its 21 bytes as three little-endian words,
/// the third overlapping the second by three bytes, folded together by
/// two full 64-by-64-bit multiplications.  The constants are digits of
/// pi, keeping a key of zeros from hashing to zero.
fn hash(key: &Key) -> u64 {
    let word = |bytes: &[u8]| {
        let mut w = [0u8; 8];
        w.copy_from_slice(bytes);
        u64::from_le_bytes(w)
    };
    let h = fold(
        word(&key[..8]) ^ 0x243f_6a88_85a3_08d3,
        word(&key[8..16]) ^ 0x1319_8a2e_0370_7344,
    );
    fold(h ^ word(&key[13..]), 0xa409_3822_299f_31d0)
}

/// The 128-bit product of `a` and `b`, its two halves xored.
fn fold(a: u64, b: u64) -> u64 {
    let wide = u128::from(a).wrapping_mul(u128::from(b));
    (wide as u64) ^ ((wide >> 64) as u64)
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic over small counts"
)]
mod tests {
    use dcroxide_testutil::SplitMix64;

    use super::*;

    fn random_keys(rng: &mut SplitMix64, n: usize) -> Vec<Key> {
        (0..n)
            .map(|_| {
                let mut k = [0u8; 21];
                rng.fill(&mut k);
                k[0] %= 4;
                k
            })
            .collect()
    }

    /// The filter of no keys has no blocks and rules everything out; a
    /// filter is sized at sixteen bits a key and stands for up to eight.
    #[test]
    fn a_filter_is_sized_by_the_keys_it_stands_for() {
        let empty = Bloom::of(0, []);
        assert_eq!(empty, Bloom::default());
        assert_eq!(empty.blocks(), 0);
        assert!(!empty.may_hold(&[0u8; 21]));
        assert!(empty.fits(0) && !empty.fits(1));
        let keys = random_keys(&mut SplitMix64(1), 100);
        let bloom = Bloom::of(100, [keys.as_slice()]);
        assert_eq!(bloom.blocks(), 4, "100 keys at 32 a block");
        assert!(bloom.fits(256) && !bloom.fits(257));
        let one = Bloom::of(1, [&keys[..1]]);
        assert_eq!(one.blocks(), 1);
        assert!(one.fits(64) && !one.fits(65));
    }

    /// Every key added is let through, from whichever vector it came and
    /// however many share a block; a key added later by `add` too.
    #[test]
    fn a_filter_lets_every_key_it_holds_through() {
        let mut rng = SplitMix64(0x626c_6f6f_6d00_0001);
        for n in [1usize, 2, 31, 32, 33, 64, 500, 20_000] {
            let keys = random_keys(&mut rng, n);
            let (a, b) = keys.split_at(n / 3);
            let mut bloom = Bloom::of(n, [a, b]);
            assert!(keys.iter().all(|k| bloom.may_hold(k)), "{n} keys");
            let more = random_keys(&mut rng, n);
            assert!(bloom.fits(2 * n));
            for k in &more {
                bloom.add(k);
            }
            assert!(keys.iter().chain(&more).all(|k| bloom.may_hold(k)));
        }
    }

    /// Of keys not held, the share a filter lets through is near what
    /// its bits a key promise: about 2.9% at eight, the most a partition
    /// lets it fall to, and 0.09% at sixteen, where it is built.  Random
    /// keys and keys of the tests' shape, a type byte and one byte
    /// repeated, alike.
    #[test]
    fn a_filter_lets_few_keys_it_does_not_hold_through() {
        let mut rng = SplitMix64(0x626c_6f6f_6d00_0002);
        let n = 64 * 1024;
        let held = random_keys(&mut rng, n);
        let probes = random_keys(&mut rng, 400_000);
        let share = |bloom: &Bloom| {
            probes.iter().filter(|k| bloom.may_hold(k)).count() as f64 / probes.len() as f64
        };
        // Built for the keys: sixteen bits each.
        let built = Bloom::of(n, [held.as_slice()]);
        let at_16 = share(&built);
        assert!(at_16 < 0.002, "{at_16} at sixteen bits a key");
        // Built for half of them, then given the rest: eight bits each.
        let (first, second) = held.split_at(n / 2);
        let mut grown = Bloom::of(n / 2, [first]);
        assert!(grown.fits(n) && !grown.fits(n + 1));
        for k in second {
            grown.add(k);
        }
        let at_8 = share(&grown);
        assert!(at_8 > 0.02 && at_8 < 0.04, "{at_8} at eight bits a key");

        // The tests' keys: type t, partition byte p, the rest one byte.
        let shaped = |t: u8, p: u8, r: u8| {
            let mut k = [r; 21];
            k[0] = t;
            k[1] = p;
            k
        };
        let held: Vec<Key> = (0..4u8)
            .flat_map(|t| (0..=255u8).flat_map(move |p| (0..32u8).map(move |r| shaped(t, p, r))))
            .collect();
        let bloom = Bloom::of(held.len(), [held.as_slice()]);
        let missing = (0..4u8)
            .flat_map(|t| (0..=255u8).flat_map(move |p| (32..=255u8).map(move |r| shaped(t, p, r))))
            .filter(|k| bloom.may_hold(k))
            .count();
        assert!(missing < 4 * 256 * 224 / 200, "{missing} let through");
    }

    /// The hash spreads keys that differ in any one byte, and a block's
    /// eight bits fall on different positions for different tags.
    #[test]
    fn the_hash_reads_every_byte() {
        let base = [0x5au8; 21];
        let h = hash(&base);
        for i in 0..21 {
            let mut k = base;
            k[i] ^= 1;
            assert_ne!(hash(&k), h, "byte {i}");
        }
        assert_ne!(hash(&[0u8; 21]), 0);
        let m = masks(0x1234_5678);
        assert!(m.iter().all(|w| w.count_ones() == 1));
        assert_ne!(m, masks(0x1234_5679));
    }
}
