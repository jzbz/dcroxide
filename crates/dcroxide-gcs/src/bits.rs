// SPDX-License-Identifier: ISC
//! Bit-granularity writer and reader for the Golomb-coded bitstreams
//! (dcrd gcs `bits.go`).

use alloc::vec::Vec;

/// Writes bits MSB-first into a growing byte vector (dcrd `bitWriter`).
#[derive(Default)]
pub(crate) struct BitWriter {
    pub(crate) bytes: Vec<u8>,
    /// Mask of the next bit to write in the final byte; zero when a new
    /// byte must be appended.
    next: u8,
}

impl BitWriter {
    /// Append a one bit (dcrd `writeOne`).
    pub(crate) fn write_one(&mut self) {
        if self.next == 0 {
            self.bytes.push(1 << 7);
            self.next = 1 << 6;
            return;
        }
        *self.bytes.last_mut().expect("next!=0 implies a byte") |= self.next;
        self.next >>= 1;
    }

    /// Append a zero bit (dcrd `writeZero`).
    pub(crate) fn write_zero(&mut self) {
        if self.next == 0 {
            self.bytes.push(0);
            self.next = 1 << 6;
            return;
        }
        self.next >>= 1;
    }

    /// Append the n least significant bits of the data, most
    /// significant bit first (dcrd `writeNBits`).
    pub(crate) fn write_n_bits(&mut self, mut data: u64, mut n: u32) {
        assert!(n <= 64, "gcs: cannot write more than 64 bits of a uint64");
        // Writing zero bits is a no-op (Go's shift by 64 zeroes the
        // data and the loops never run).
        if n == 0 {
            return;
        }

        data <<= 64 - n;

        // Fill any partial byte first.
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

        // Write out any whole bytes.
        while n >= 8 {
            self.bytes.push((data >> 56) as u8);
            n -= 8;
            data <<= 8;
        }

        // Write any remaining bits.
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
