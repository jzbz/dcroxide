// SPDX-License-Identifier: ISC
//! A byte-slice cursor providing the primitive little-endian reads the wire
//! codecs are built from (dcrd's `readElement` fast paths, minus `io.Reader`).

use crate::error::WireError;

/// A forward-only cursor over a byte slice.
#[derive(Debug, Clone)]
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// A cursor at the start of `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    /// Bytes consumed so far.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Bytes remaining.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Take `n` bytes as a slice.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.remaining() < n {
            return Err(WireError::UnexpectedEof);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Take a fixed-size byte array.
    pub fn take_array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    /// Read a `u8`.
    pub fn read_u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take_array::<1>()?[0])
    }

    /// Read a little-endian `u16`.
    pub fn read_u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_le_bytes(self.take_array()?))
    }

    /// Read a little-endian `u32`.
    pub fn read_u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_le_bytes(self.take_array()?))
    }

    /// Read a little-endian `u64`.
    pub fn read_u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_le_bytes(self.take_array()?))
    }
}
