// SPDX-License-Identifier: ISC
//! The entropy a generator draws from.
//!
//! Generators take `&mut dyn Entropy` rather than a concrete PRNG so that
//! the soak (SplitMix64, seeded per case) and a fuzz target (the fuzzer's
//! bytes, [`ByteEntropy`]) drive the same code.  The provided methods
//! reproduce SplitMix64's inherent ones exactly, so a generator draws the
//! same values whichever it calls.

use dcroxide_testutil::SplitMix64;

/// A source of 64-bit words, with the derived draws every generator uses.
pub trait Entropy {
    /// The next 64 bits.
    fn next_u64(&mut self) -> u64;

    /// Fills `buf` with the little-endian bytes of successive
    /// [`next_u64`](Entropy::next_u64) values, the last one truncated:
    /// `SplitMix64::fill`'s layout.
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let word = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }

    /// `next_u64() % n`, `SplitMix64::below`'s rule (the modulo bias is
    /// at most `n / 2^64`, nothing a generator's strata can see).  `n` must
    /// be nonzero.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "callers pass n > 0, and u64 % n cannot overflow"
    )]
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    /// A fair coin: the low bit of the next word.
    fn coin(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    /// 32 bytes, as [`fill`](Entropy::fill) lays them out.
    fn bytes32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.fill(&mut out);
        out
    }
}

impl Entropy for SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        SplitMix64::next_u64(self)
    }
}

/// Entropy read from a byte string, as a fuzz target hands it over: eight
/// bytes little-endian per word, zero-padded, and zeros once the input is
/// exhausted, so a generator always terminates (its retry loops are bounded
/// and fall back to fixed values on a zero stream).
pub struct ByteEntropy<'a> {
    rest: &'a [u8],
}

impl<'a> ByteEntropy<'a> {
    /// Entropy drawn from `data`, front to back.
    pub fn new(data: &'a [u8]) -> Self {
        ByteEntropy { rest: data }
    }

    /// Whether every input byte has been consumed.
    pub fn is_exhausted(&self) -> bool {
        self.rest.is_empty()
    }
}

impl Entropy for ByteEntropy<'_> {
    fn next_u64(&mut self) -> u64 {
        let take = self.rest.len().min(8);
        let (head, tail) = self.rest.split_at(take);
        let mut word = [0u8; 8];
        word[..take].copy_from_slice(head);
        self.rest = tail;
        u64::from_le_bytes(word)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The trait's provided draws are SplitMix64's inherent ones, value for
    /// value, whichever a generator calls.
    #[test]
    fn provided_draws_match_splitmix64() {
        let mut inherent = SplitMix64(0x0123_4567_89ab_cdef);
        let mut through_trait = SplitMix64(0x0123_4567_89ab_cdef);
        let e: &mut dyn Entropy = &mut through_trait;
        for i in 0..1_000u64 {
            match i % 4 {
                0 => assert_eq!(e.next_u64(), inherent.next_u64()),
                1 => {
                    let n = i.wrapping_mul(7919).wrapping_add(1);
                    assert_eq!(e.below(n), inherent.below(n));
                }
                2 => {
                    let len = usize::try_from(i % 41).expect("small");
                    let mut a = vec![0u8; len];
                    let mut b = vec![0u8; len];
                    e.fill(&mut a);
                    inherent.fill(&mut b);
                    assert_eq!(a, b);
                }
                _ => {
                    let mut b = [0u8; 32];
                    inherent.fill(&mut b);
                    assert_eq!(e.bytes32(), b);
                }
            }
        }
        assert_eq!(
            SplitMix64(7).coin(),
            SplitMix64(7).next_u64() & 1 == 1,
            "coin is the low bit"
        );
    }

    /// `ByteEntropy` reads eight bytes little-endian per word, pads the last
    /// short word with zeros and then yields zeros for ever.
    #[test]
    fn byte_entropy_reads_little_endian_then_zeros() {
        let data: Vec<u8> = (1..=11).collect();
        let mut e = ByteEntropy::new(&data);
        assert!(!e.is_exhausted());
        assert_eq!(e.next_u64(), 0x0807_0605_0403_0201);
        assert_eq!(e.next_u64(), 0x0000_0000_000b_0a09);
        assert!(e.is_exhausted());
        for _ in 0..3 {
            assert_eq!(e.next_u64(), 0);
        }
        let mut buf = [0xffu8; 5];
        e.fill(&mut buf);
        assert_eq!(buf, [0; 5]);
        assert_eq!(ByteEntropy::new(&[]).bytes32(), [0; 32]);
        assert_eq!(ByteEntropy::new(&[3]).below(2), 1);
    }
}
