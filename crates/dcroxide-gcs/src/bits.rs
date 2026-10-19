// SPDX-License-Identifier: ISC
//! Bit-granularity writer and reader for the Golomb-coded bitstreams
//! (dcrd gcs `bits.go`).

use alloc::vec::Vec;

/// Writes bits MSB-first into a growing byte vector (dcrd `bitWriter`).
///
/// dcrd writes a bit at a time into the stream's last byte, and whole
/// bytes only once an n-bit write has reached a byte boundary.  This
/// writer gathers the bits in a 64-bit word instead, appends the word
/// as eight big-endian bytes each time it fills, and appends the bytes
/// of the last, partly filled word in [`BitWriter::finish`].  The
/// stream is dcrd's: the bits in the order written, the most
/// significant bit of each byte first, and the final byte padded with
/// zero bits.
pub(crate) struct BitWriter {
    bytes: Vec<u8>,
    /// The bits written and not yet appended, left-aligned: the top
    /// `used` bits of the word, every bit below them zero.
    word: u64,
    /// How many bits of `word` are written, below 64 between calls.
    used: u32,
}

impl BitWriter {
    /// A writer that appends its bitstream after `bytes`, which it never
    /// modifies: the first bit written starts a new byte.  The filter
    /// build passes its entry count serialization, sized for the whole
    /// filter, so the bitstream needs no second buffer.
    pub(crate) fn after(bytes: Vec<u8>) -> BitWriter {
        BitWriter {
            bytes,
            word: 0,
            used: 0,
        }
    }

    /// Append the n low bits of the data, most significant first, for
    /// n in 1..=64.  Every bit of the data above those n must be zero.
    #[inline]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "used < 64 between calls, so free is in 1..=64; n < free in the first arm makes free - n 1..=63 and used + n < 64; n >= free in the second makes rest = n - free 0..=63 (n <= 64), so 64 - rest is 1..=64 and is shifted by only when rest > 0"
    )]
    fn put(&mut self, data: u64, n: u32) {
        debug_assert!((1..=64).contains(&n), "gcs: put of {n} bits");
        debug_assert!(n == 64 || data >> n == 0, "gcs: data above its {n} bits");
        let free = 64 - self.used;
        if n < free {
            self.word |= data << (free - n);
            self.used += n;
            return;
        }
        // The word fills: its last `free` bits are the top bits of the
        // data, and the `rest` bits below them start the next word.
        let rest = n - free;
        self.word |= data >> rest;
        self.bytes.extend_from_slice(&self.word.to_be_bytes());
        self.word = if rest == 0 { 0 } else { data << (64 - rest) };
        self.used = rest;
    }

    /// Append a unary-coded quantity: q one bits, then a zero bit (the
    /// run of dcrd `writeOne` calls the coding loop makes, and the
    /// `writeZero` after it).
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "q >= 64 guards the decrement; after the loop q <= 63, so 1 << q does not overflow, (1 << q) - 1 >= 0, the shifted ones fit in 64 bits, and q + 1 <= 64"
    )]
    pub(crate) fn write_unary(&mut self, mut q: u64) {
        while q >= 64 {
            self.put(u64::MAX, 64);
            q -= 64;
        }
        let ones = (1u64 << q) - 1;
        self.put(ones << 1, q as u32 + 1);
    }

    /// Append the n least significant bits of the data, most
    /// significant bit first (dcrd `writeNBits`).
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "n is in 1..=64 at the shift (asserted, zero returned early), so 64 - n is in 0..=63"
    )]
    pub(crate) fn write_n_bits(&mut self, data: u64, n: u32) {
        assert!(n <= 64, "gcs: cannot write more than 64 bits of a uint64");
        // Writing zero bits is a no-op (Go's shift by 64 zeroes the
        // data and the loops never run).
        if n == 0 {
            return;
        }
        // dcrd shifts the bits above n out of the data; mask them off.
        self.put(data & (u64::MAX >> (64 - n)), n);
    }

    /// The bytes the writer was made with followed by the bitstream,
    /// its final byte padded with zero bits.
    pub(crate) fn finish(mut self) -> Vec<u8> {
        let word = self.word.to_be_bytes();
        let tail = self.used.div_ceil(8) as usize;
        self.bytes.extend_from_slice(&word[..tail]);
        self.bytes
    }
}

/// Reads bits MSB-first from a byte slice (dcrd `bitReader`).  Reads
/// past the end return `Err(())`, mirroring dcrd's io.EOF (dcrd allows
/// partial reads to mutate state; so does this).
pub(crate) struct BitReader<'a> {
    bytes: &'a [u8],
    /// Mask of the next bit to read in `bytes[0]`.
    next: u8,
}

impl<'a> BitReader<'a> {
    /// A reader positioned at the start of the bitstream (dcrd
    /// `newBitReader`).
    pub(crate) fn new(bitstream: &'a [u8]) -> BitReader<'a> {
        BitReader {
            bytes: bitstream,
            next: 1 << 7,
        }
    }

    /// Read a unary-encoded quantity: the count of one bits before the
    /// terminating zero bit (dcrd `readUnary`).
    pub(crate) fn read_unary(&mut self) -> Result<u64, ()> {
        let mut value: u64 = 0;
        loop {
            if self.bytes.is_empty() {
                return Err(());
            }
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "value counts one bits of an in-memory byte slice: reaching u64::MAX would take 2^61 bytes (2 EiB), beyond any address space"
            )]
            while self.next != 0 {
                let bit = self.bytes[0] & self.next;
                self.next >>= 1;
                if bit == 0 {
                    return Ok(value);
                }
                value += 1;
            }
            self.bytes = &self.bytes[1..];
            self.next = 1 << 7;
        }
    }

    /// Read n bits as an unsigned integer, most significant bit first
    /// (dcrd `readNBits`).
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "each decrement of n is guarded by its loop condition (n > 0 or n >= 8)"
    )]
    pub(crate) fn read_n_bits(&mut self, n: u32) -> Result<u64, ()> {
        assert!(n <= 64, "gcs: cannot read more than 64 bits as a uint64");
        if n == 0 {
            return Ok(0);
        }
        if self.bytes.is_empty() {
            return Err(());
        }

        let mut n = n;
        let mut value: u64 = 0;

        // Read any leading bits of a partially-consumed byte.
        if self.next != 1 << 7 {
            while n > 0 {
                if self.next == 0 {
                    self.next = 1 << 7;
                    self.bytes = &self.bytes[1..];
                    break;
                }
                value <<= 1;
                if self.bytes[0] & self.next != 0 {
                    value |= 1;
                }
                self.next >>= 1;
                n -= 1;
            }
            if n == 0 {
                return Ok(value);
            }
        }

        // Read whole bytes.
        while n >= 8 {
            if self.bytes.is_empty() {
                return Err(());
            }
            value = value << 8 | u64::from(self.bytes[0]);
            self.bytes = &self.bytes[1..];
            n -= 8;
        }

        // Read any trailing bits.
        while n > 0 {
            if self.bytes.is_empty() {
                return Err(());
            }
            value <<= 1;
            if self.bytes[0] & self.next != 0 {
                value |= 1;
            }
            self.next >>= 1;
            if self.next == 0 {
                self.next = 1 << 7;
                self.bytes = &self.bytes[1..];
            }
            n -= 1;
        }

        Ok(value)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use dcroxide_testutil::{SplitMix64, unhex};

    /// dcrd's `bitWriter` as the port wrote it before the word at a
    /// time writer: a bit at a time into the last byte.  The reference
    /// the writer above is compared against, here and by the filter
    /// build's test in the crate root.
    pub(crate) struct SingleBitWriter {
        pub(crate) bytes: Vec<u8>,
        /// Mask of the next bit to write in the final byte; zero when
        /// a new byte must be appended.
        next: u8,
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "n is in 1..=64 at the shift (asserted, zero returned early), and each decrement is guarded by its loop condition (n > 0 or n >= 8)"
    )]
    impl SingleBitWriter {
        pub(crate) fn after(bytes: Vec<u8>) -> SingleBitWriter {
            SingleBitWriter { bytes, next: 0 }
        }

        /// dcrd `writeOne`.
        pub(crate) fn write_one(&mut self) {
            if self.next == 0 {
                self.bytes.push(1 << 7);
                self.next = 1 << 6;
                return;
            }
            *self.bytes.last_mut().expect("next!=0 implies a byte") |= self.next;
            self.next >>= 1;
        }

        /// dcrd `writeZero`.
        pub(crate) fn write_zero(&mut self) {
            if self.next == 0 {
                self.bytes.push(0);
                self.next = 1 << 6;
                return;
            }
            self.next >>= 1;
        }

        /// dcrd `writeNBits`.
        pub(crate) fn write_n_bits(&mut self, mut data: u64, mut n: u32) {
            assert!(n <= 64, "gcs: cannot write more than 64 bits of a uint64");
            if n == 0 {
                return;
            }
            data <<= 64 - n;
            while n > 0 {
                if self.next == 0 {
                    break;
                }
                if data & (1 << 63) != 0 {
                    self.write_one();
                } else {
                    self.write_zero();
                }
                n -= 1;
                data <<= 1;
            }
            if n == 0 {
                return;
            }
            while n >= 8 {
                self.bytes.push((data >> 56) as u8);
                n -= 8;
                data <<= 8;
            }
            while n > 0 {
                if data & (1 << 63) != 0 {
                    self.write_one();
                } else {
                    self.write_zero();
                }
                n -= 1;
                data <<= 1;
            }
        }

        /// The coding loop's unary quotient: q one bits, then a zero.
        pub(crate) fn write_unary(&mut self, q: u64) {
            for _ in 0..q {
                self.write_one();
            }
            self.write_zero();
        }
    }

    /// One write, made on both writers.
    #[derive(Clone, Copy, Debug)]
    enum Op {
        Unary(u64),
        Bits(u64, u32),
    }

    /// The stream both writers make of the same writes after the same
    /// leading bytes: the word at a time writer's and the reference's.
    fn both(prefix: &[u8], ops: &[Op]) -> (Vec<u8>, Vec<u8>) {
        let mut w = BitWriter::after(prefix.to_vec());
        let mut r = SingleBitWriter::after(prefix.to_vec());
        for op in ops {
            match *op {
                Op::Unary(q) => {
                    w.write_unary(q);
                    r.write_unary(q);
                }
                Op::Bits(data, n) => {
                    w.write_n_bits(data, n);
                    r.write_n_bits(data, n);
                }
            }
        }
        (w.finish(), r.bytes)
    }

    /// dcrd's `TestBitWriter` vectors (gcs/v4 `bits_test.go` at the
    /// parity pin).  Each case is a run of steps on one writer: some
    /// single bits, then some bits of a uint64, then the bytes expected
    /// so far.  The reference writer takes the single bits as dcrd's
    /// test does, a `writeOne` or `writeZero` each, and its bytes are
    /// checked after every step.  The word at a time writer has
    /// neither, so it takes each as a one-bit write, and since only
    /// finishing it gives its bytes, a fresh one replays every step up
    /// to the one checked.
    #[test]
    fn dcrds_bit_writer_vectors() {
        /// The single bits and how many, the uint64 and how many of
        /// its bits, and the bytes after the step.
        type Step = (u64, u32, u64, u32, &'static str);
        let cases: [(&str, &[Step]); 10] = [
            ("1 bit - 0", &[(0x0, 1, 0, 0, "00")]),
            ("1 bit - 1", &[(0x1, 1, 0, 0, "80")]),
            ("2 bits - 00", &[(0x0, 2, 0, 0, "00")]),
            ("2 bits - 01", &[(0x1, 2, 0, 0, "40")]),
            ("9 bits - 010101010", &[(0x0aa, 9, 0, 0, "5500")]),
            ("9 bits - 010101011", &[(0x0ab, 9, 0, 0, "5580")]),
            (
                "2 bits, 3 bits of uint64 - 01 110",
                &[(0x1, 2, 0, 0, "40"), (0, 0, 6, 3, "70")],
            ),
            (
                "7 bits, 2 bits of uint64 - 1111111 00",
                &[(0x7f, 7, 0, 0, "fe"), (0, 0, 0, 2, "fe00")],
            ),
            (
                "7 bits, 11 bits of uint64 - 1111111 00100000101",
                &[(0x7f, 7, 0, 0, "fe"), (0, 0, 261, 11, "fe4140")],
            ),
            (
                "7 bits of uint64, 2 bits  - 1010101 11",
                &[(0, 0, 85, 7, "aa"), (0x3, 2, 0, 0, "ab80")],
            ),
        ];
        for (name, steps) in cases {
            let mut reference = SingleBitWriter::after(Vec::new());
            for (s, &(bits, n_bits, val, n_val_bits, want)) in steps.iter().enumerate() {
                let want = unhex(want);
                for i in (0..n_bits).rev() {
                    match (bits >> i) & 1 {
                        0 => reference.write_zero(),
                        _ => reference.write_one(),
                    }
                }
                reference.write_n_bits(val, n_val_bits);
                assert_eq!(reference.bytes, want, "{name}, step {s}: reference writer");

                let mut w = BitWriter::after(Vec::new());
                for &(bits, n_bits, val, n_val_bits, _) in &steps[..=s] {
                    for i in (0..n_bits).rev() {
                        w.write_n_bits((bits >> i) & 1, 1);
                    }
                    w.write_n_bits(val, n_val_bits);
                }
                assert_eq!(w.finish(), want, "{name}, step {s}");
            }
        }
    }

    /// Every write lands on every alignment of the word: after each
    /// count of bits from 0 to 64 already written, a write of each
    /// width from 0 to 64 bits and unary quotients across one and two
    /// word boundaries make dcrd's bytes, and the leading bytes stay
    /// as they were.  The bits already written come from each of four
    /// patterns and a width write's data from the next one, so a write
    /// that lands on bits already written, or that appends its bits
    /// ahead of them, changes the stream.
    #[test]
    fn every_alignment_matches_dcrds_writer() {
        let prefix = [0xa5u8, 0x00, 0xff];
        let patterns = [
            u64::MAX,
            0x8000_0000_0000_0001,
            0xaaaa_aaaa_aaaa_aaaa,
            0x0123_4567_89ab_cdef,
        ];
        let quotients = [0u64, 1, 2, 7, 8, 62, 63, 64, 65, 127, 128, 129, 200];
        for lead in 0..=64u32 {
            for (&pattern, &next) in patterns.iter().zip(patterns.iter().cycle().skip(1)) {
                for n in 0..=64u32 {
                    let data = next.rotate_left(n);
                    let ops = [Op::Bits(pattern, lead), Op::Bits(data, n)];
                    let (got, want) = both(&prefix, &ops);
                    assert_eq!(got, want, "{lead} bits of {pattern:#x}, {n} of {data:#x}");
                    assert_eq!(got[..prefix.len()], prefix);
                }
                for &q in &quotients {
                    let ops = [Op::Bits(pattern, lead), Op::Unary(q), Op::Bits(1, 1)];
                    let (got, want) = both(&prefix, &ops);
                    assert_eq!(got, want, "{lead} bits of {pattern:#x}, quotient {q}");
                }
            }
        }
        // No writes at all: the leading bytes alone.
        assert_eq!(both(&prefix, &[]), (prefix.to_vec(), prefix.to_vec()));
        assert_eq!(both(&[], &[Op::Bits(7, 0)]), (Vec::new(), Vec::new()));
    }

    /// Random runs of writes, with the quotients and remainder widths
    /// the filters use and wider ones, data with bits set above the
    /// width written, and leading bytes of random length: the word at
    /// a time writer makes dcrd's bytes, and the reader reads every
    /// write back.
    #[test]
    fn random_writes_match_dcrds_writer() {
        let mut rng = SplitMix64::from_entropy("gcs-bit-writer");
        for round in 0..3000 {
            let prefix = rng.bytes(9);
            let n_ops = rng.below(300) as usize;
            let mut ops = Vec::with_capacity(n_ops);
            for _ in 0..n_ops {
                let op = match rng.below(8) {
                    0..=2 => Op::Unary(match rng.below(10) {
                        0 => rng.below(300),
                        _ => rng.below(4),
                    }),
                    3 => Op::Bits(rng.next_u64(), rng.below(65) as u32),
                    _ => Op::Bits(rng.next_u64(), [19, 20, 10, 32][rng.below(4) as usize]),
                };
                ops.push(op);
            }
            let (got, want) = both(&prefix, &ops);
            assert_eq!(got, want, "round {round}: {} writes", ops.len());

            let mut r = BitReader::new(&got[prefix.len()..]);
            for (i, op) in ops.iter().enumerate() {
                match *op {
                    Op::Unary(q) => assert_eq!(r.read_unary(), Ok(q), "round {round}, write {i}"),
                    Op::Bits(data, n) => {
                        let mask = u64::MAX.checked_shr(64 - n).unwrap_or(0);
                        assert_eq!(
                            r.read_n_bits(n),
                            Ok(data & mask),
                            "round {round}, write {i}"
                        );
                    }
                }
            }
        }
    }
}
