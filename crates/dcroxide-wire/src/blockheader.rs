// SPDX-License-Identifier: ISC
//! The 180-byte Decred block header and its BLAKE-256 block hash.

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
    ///
    /// Each field is written straight into the array at its fixed offset.
    /// dcrd's `BlockHash` streams the same fields into the hasher, so no
    /// header hash goes through a heap buffer there either.
    pub fn serialize(&self) -> [u8; MAX_BLOCK_HEADER_PAYLOAD] {
        let mut out = [0u8; MAX_BLOCK_HEADER_PAYLOAD];
        let mut off = 0;
        let mut put = |field: &[u8]| {
            out[off..off + field.len()].copy_from_slice(field);
            off += field.len();
        };
        put(&(self.version as u32).to_le_bytes());
        put(self.prev_block.as_bytes());
        put(self.merkle_root.as_bytes());
        put(self.stake_root.as_bytes());
        put(&self.vote_bits.to_le_bytes());
        put(&self.final_state);
        put(&self.voters.to_le_bytes());
        put(&[self.fresh_stake, self.revocations]);
        put(&self.pool_size.to_le_bytes());
        put(&self.bits.to_le_bytes());
        put(&(self.sbits as u64).to_le_bytes());
        put(&self.height.to_le_bytes());
        put(&self.size.to_le_bytes());
        put(&self.timestamp.to_le_bytes());
        put(&self.nonce.to_le_bytes());
        put(&self.extra_data);
        put(&self.stake_version.to_le_bytes());
        debug_assert_eq!(off, MAX_BLOCK_HEADER_PAYLOAD);
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
        Self::pow_hash_v2_of(&self.serialize())
    }

    /// The version 2 proof-of-work hash of an already serialized header
    /// (dcrd `blake3.Sum256` over the header bytes), for a solver that
    /// serializes once and patches the nonce fields in place.
    pub fn pow_hash_v2_of(serialized: &[u8; MAX_BLOCK_HEADER_PAYLOAD]) -> Hash {
        Hash(*blake3::hash(serialized).as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BLAKE3 known answers for the empty input and for "abc", plus one
    /// the length of a serialized header: 180 bytes of the official test
    /// vectors' `i % 251` input pattern, as dcrd's own BLAKE3
    /// (`lukechampine.com/blake3` v1.3.0) answers it.  The first two fit
    /// one compression block; the header length takes three, which is
    /// the path `pow_hash_v2` runs.
    ///
    /// `pow_hash_v2` is the DCP0011 proof-of-work hash, so a change in
    /// what `blake3` returns is a consensus change. The dependency
    /// ledger records the crate as reviewed at a version and notes the
    /// KATs were checked by hand then; that check was not held anywhere,
    /// so a bump could alter the output with nothing to catch it. This
    /// is that check, kept.
    #[test]
    fn blake3_still_answers_the_known_vectors() {
        let empty = blake3::hash(b"");
        assert_eq!(
            empty.to_hex().as_str(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            "BLAKE3 of the empty input"
        );
        let abc = blake3::hash(b"abc");
        assert_eq!(
            abc.to_hex().as_str(),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
            "BLAKE3 of \"abc\""
        );
        let header_len: Vec<u8> = (0..180u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(
            blake3::hash(&header_len).to_hex().as_str(),
            "0147415f175cc3336f70466c43558133769c06815ddcaf30a55d11158efe90b9",
            "BLAKE3 of a header-length input"
        );
    }

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

    /// dcrd's `TestBlockHeaderSerialize` vector: the header serializes
    /// to exactly dcrd's bytes, each field at its offset, and decodes
    /// back.
    #[test]
    fn serialize_matches_dcrd_vector() {
        // dcrd's `mainNetGenesisHash` and `mainNetGenesisMerkleRoot`.
        let prev_block = [
            0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63,
            0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let merkle_root = [
            0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76,
            0x8f, 0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa,
            0x4b, 0x1e, 0x5e, 0x4a,
        ];
        let header = BlockHeader {
            version: 1,
            prev_block: Hash(prev_block),
            merkle_root: Hash(merkle_root),
            stake_root: Hash(merkle_root),
            vote_bits: 0x0000,
            final_state: [0; 6],
            voters: 0,
            fresh_stake: 0,
            revocations: 0,
            pool_size: 0,
            bits: 0x1d00ffff,
            sbits: 0,
            height: 0,
            size: 0,
            timestamp: 0x495fab29,
            nonce: 123123,
            extra_data: [0; 32],
            stake_version: 0x0ddba110,
        };
        let mut want = Vec::new();
        want.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Version 1
        want.extend_from_slice(&prev_block); // PrevBlock
        want.extend_from_slice(&merkle_root); // MerkleRoot
        want.extend_from_slice(&merkle_root); // StakeRoot
        want.extend_from_slice(&[0x00, 0x00]); // VoteBits
        want.extend_from_slice(&[0x00; 6]); // FinalState
        want.extend_from_slice(&[0x00, 0x00]); // Voters
        want.push(0x00); // FreshStake
        want.push(0x00); // Revocations
        want.extend_from_slice(&[0x00; 4]); // PoolSize
        want.extend_from_slice(&[0xff, 0xff, 0x00, 0x1d]); // Bits
        want.extend_from_slice(&[0x00; 8]); // SBits
        want.extend_from_slice(&[0x00; 4]); // Height
        want.extend_from_slice(&[0x00; 4]); // Size
        want.extend_from_slice(&[0x29, 0xab, 0x5f, 0x49]); // Timestamp
        want.extend_from_slice(&[0xf3, 0xe0, 0x01, 0x00]); // Nonce
        want.extend_from_slice(&[0x00; 32]); // ExtraData
        want.extend_from_slice(&[0x10, 0xa1, 0xdb, 0x0d]); // StakeVersion
        assert_eq!(header.serialize().as_slice(), want.as_slice());
        let (decoded, _) = BlockHeader::from_bytes(&want).expect("decode header");
        assert_eq!(decoded, header);
    }

    /// dcrd's `TestBlockHeaderHashing` known answer.
    #[test]
    fn block_hash_matches_dcrd_vector() {
        let encoded = dcroxide_testutil::unhex(concat!(
            "0000000049e0b48ade043f729d60095ed92642d96096fe6aba42f2eda",
            "632d461591a152267dc840ff27602ce1968a81eb30a43423517207617a0150b56c4f72",
            "b803e497f00000000000000000000000000000000000000000000000000000000000000",
            "00010000000000000000000000b7000000ffff7f20204e0000000000005800000060010",
            "0008b990956000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000ABCD",
        ));
        // In byte order, as dcrd's test passes it to `chainhash.NewHash`.
        let want = dcroxide_testutil::unhex(
            "0d40d58703482d81d711be0ffc1b313788d3c3937e1617e4876661d33a8c4c41",
        );
        let (header, _) = BlockHeader::from_bytes(&encoded).expect("decode header");
        assert_eq!(header.serialize().as_slice(), encoded.as_slice());
        assert_eq!(header.block_hash().as_bytes().as_slice(), want.as_slice());
        assert_eq!(header.pow_hash_v1(), header.block_hash());
    }

    #[test]
    fn truncated_is_eof() {
        let bytes = sample_header().serialize();
        // dcrd reads the header field by field, so a cut at a field
        // boundary reads nothing (io.EOF) and one inside a field reads
        // part of it (io.ErrUnexpectedEOF).
        for (len, want) in [
            (0, WireError::Eof),
            (1, WireError::UnexpectedEof),
            (36, WireError::Eof),
            (90, WireError::UnexpectedEof),
            (179, WireError::UnexpectedEof),
        ] {
            assert_eq!(
                BlockHeader::from_bytes(&bytes[..len]),
                Err(want),
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
