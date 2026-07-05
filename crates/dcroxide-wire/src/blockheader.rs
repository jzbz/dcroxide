// SPDX-License-Identifier: ISC
//! The 180-byte Decred block header and its BLAKE-256 block hash.

use alloc::vec::Vec;

use dcroxide_chainhash::{HASH_SIZE, Hash, hash_h};

use crate::cursor::Cursor;
use crate::error::WireError;

/// The number of bytes a serialized block header occupies (180): dcrd
/// `MaxBlockHeaderPayload` — for Decred headers the maximum is also the only
/// size.
pub const MAX_BLOCK_HEADER_PAYLOAD: usize = 84 + HASH_SIZE * 3;

/// A Decred block header, byte-compatible with dcrd's `BlockHeader`.
///
/// The timestamp is a `u32` of unix seconds: that is the wire format (dcrd
/// holds a `time.Time` in memory and truncates on write; this type cannot
/// represent anything the wire cannot).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeader {
    /// Block version (not the protocol version).
    pub version: i32,
    /// Hash of the previous block.
    pub prev_block: Hash,
    /// Merkle root of the regular transaction tree (or the combined tree
    /// post-DCP0005).
    pub merkle_root: Hash,
    /// Merkle root of the stake transaction tree.
    pub stake_root: Hash,
    /// Votes on the previous block and undecided parameters.
    pub vote_bits: u16,
    /// Final state of the ticket-lottery PRNG.
    pub final_state: [u8; 6],
    /// Number of participating voters.
    pub voters: u16,
    /// Number of new tickets (SStx).
    pub fresh_stake: u8,
    /// Number of revocations (SSRtx).
    pub revocations: u8,
    /// Size of the live ticket pool.
    pub pool_size: u32,
    /// Compact difficulty target.
    pub bits: u32,
    /// Stake difficulty target in atoms.
    pub sbits: i64,
    /// Block height.
    pub height: u32,
    /// Serialized size of the entire block.
    pub size: u32,
    /// Block time as unix seconds (u32 on the wire; good through 2106).
    pub timestamp: u32,
    /// Classic 4-byte nonce (technically part of the extra data).
    pub nonce: u32,
    /// Extra consensus data / extended nonce space.
    pub extra_data: [u8; 32],
    /// Stake version used for voting.
    pub stake_version: u32,
}

impl BlockHeader {
    /// Decode a header from the cursor (dcrd `readBlockHeader`).
    pub fn decode(r: &mut Cursor<'_>) -> Result<BlockHeader, WireError> {
        Ok(BlockHeader {
            version: r.read_u32()? as i32,
            prev_block: Hash(r.take_array()?),
            merkle_root: Hash(r.take_array()?),
            stake_root: Hash(r.take_array()?),
            vote_bits: r.read_u16()?,
            final_state: r.take_array()?,
            voters: r.read_u16()?,
            fresh_stake: r.read_u8()?,
            revocations: r.read_u8()?,
            pool_size: r.read_u32()?,
            bits: r.read_u32()?,
            sbits: r.read_u64()? as i64,
            height: r.read_u32()?,
            size: r.read_u32()?,
            timestamp: r.read_u32()?,
            nonce: r.read_u32()?,
            extra_data: r.take_array()?,
            stake_version: r.read_u32()?,
        })
    }

    /// Decode from a byte slice, returning the header and bytes consumed
    /// (always 180 on success; trailing bytes are not an error, as in dcrd).
    pub fn from_bytes(b: &[u8]) -> Result<(BlockHeader, usize), WireError> {
        let mut r = Cursor::new(b);
        let h = Self::decode(&mut r)?;
        Ok((h, r.position()))
    }

    /// The 180-byte serialization (dcrd `writeBlockHeader` / `Serialize`).
    pub fn serialize(&self) -> [u8; MAX_BLOCK_HEADER_PAYLOAD] {
        let mut out = [0u8; MAX_BLOCK_HEADER_PAYLOAD];
        let mut w = Vec::with_capacity(MAX_BLOCK_HEADER_PAYLOAD);
        w.extend_from_slice(&(self.version as u32).to_le_bytes());
        w.extend_from_slice(self.prev_block.as_bytes());
        w.extend_from_slice(self.merkle_root.as_bytes());
        w.extend_from_slice(self.stake_root.as_bytes());
        w.extend_from_slice(&self.vote_bits.to_le_bytes());
        w.extend_from_slice(&self.final_state);
        w.extend_from_slice(&self.voters.to_le_bytes());
        w.push(self.fresh_stake);
        w.push(self.revocations);
        w.extend_from_slice(&self.pool_size.to_le_bytes());
        w.extend_from_slice(&self.bits.to_le_bytes());
        w.extend_from_slice(&(self.sbits as u64).to_le_bytes());
        w.extend_from_slice(&self.height.to_le_bytes());
        w.extend_from_slice(&self.size.to_le_bytes());
        w.extend_from_slice(&self.timestamp.to_le_bytes());
        w.extend_from_slice(&self.nonce.to_le_bytes());
        w.extend_from_slice(&self.extra_data);
        w.extend_from_slice(&self.stake_version.to_le_bytes());
        out.copy_from_slice(&w);
        out
    }

    /// The BLAKE-256 block identifier hash (dcrd `BlockHash`).
    pub fn block_hash(&self) -> Hash {
        hash_h(&self.serialize())
    }

    /// The version 1 proof-of-work hash: identical to [`Self::block_hash`]
    /// (dcrd `PowHashV1`; applies to all blocks before DCP0011 activation).
    pub fn pow_hash_v1(&self) -> Hash {
        self.block_hash()
    }

    /// The version 2 proof-of-work hash defined in DCP0011: BLAKE3 over the
    /// serialized header (dcrd `PowHashV2`).
    pub fn pow_hash_v2(&self) -> Hash {
        Hash(*blake3::hash(&self.serialize()).as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> BlockHeader {
        BlockHeader {
            version: 6,
            prev_block: dcroxide_chainhash::hash_h(b"prev"),
            merkle_root: dcroxide_chainhash::hash_h(b"merkle"),
            stake_root: dcroxide_chainhash::hash_h(b"stake"),
            vote_bits: 0x0001,
            final_state: [1, 2, 3, 4, 5, 6],
            voters: 5,
            fresh_stake: 2,
            revocations: 1,
            pool_size: 40960,
            bits: 0x1a2b3c4d,
            sbits: 123_456_789_012,
            height: 654_321,
            size: 987_654,
            timestamp: 1_700_000_000,
            nonce: 0xdeadbeef,
            extra_data: [0xEE; 32],
            stake_version: 9,
        }
    }

    #[test]
    fn round_trip() {
        let h = sample_header();
        let bytes = h.serialize();
        assert_eq!(bytes.len(), MAX_BLOCK_HEADER_PAYLOAD);
        let (decoded, consumed) = BlockHeader::from_bytes(&bytes).expect("decode header");
        assert_eq!(consumed, MAX_BLOCK_HEADER_PAYLOAD);
        assert_eq!(decoded, h);
    }

    #[test]
    fn truncated_is_eof() {
        let bytes = sample_header().serialize();
        for len in [0, 1, 90, 179] {
            assert_eq!(
                BlockHeader::from_bytes(&bytes[..len]),
                Err(WireError::UnexpectedEof),
                "len {len}"
            );
        }
    }

    #[test]
    fn trailing_bytes_ignored() {
        let h = sample_header();
        let mut bytes = h.serialize().to_vec();
        bytes.extend_from_slice(&[0xAA; 7]);
        let (decoded, consumed) = BlockHeader::from_bytes(&bytes).expect("decode header");
        assert_eq!(consumed, MAX_BLOCK_HEADER_PAYLOAD);
        assert_eq!(decoded, h);
    }
}
