// SPDX-License-Identifier: ISC
//! Decred transactions (`MsgTx`) with byte-exact dcrd serialization across
//! all three serialization types, and the BLAKE-256 transaction hashes.

use alloc::vec::Vec;

use dcroxide_chainhash::{Hash, hash_h};

use crate::MAX_MESSAGE_PAYLOAD;
use crate::cursor::Cursor;
use crate::error::WireError;
use crate::varint::{
    read_var_bytes, read_var_int, var_int_serialize_size, write_var_bytes, write_var_int,
};

/// The initial transaction version (dcrd `TxVersion`).
pub const TX_VERSION: u16 = 1;

/// The maximum sequence number a transaction input can have.
pub const MAX_TX_IN_SEQUENCE_NUM: u32 = 0xffff_ffff;

/// The maximum index of a previous outpoint.
pub const MAX_PREV_OUT_INDEX: u32 = 0xffff_ffff;

/// The expiry value indicating no expiry.
pub const NO_EXPIRY_VALUE: u32 = 0;

/// The null input-witness value.
pub const NULL_VALUE_IN: i64 = -1;

/// The null input-witness block height.
pub const NULL_BLOCK_HEIGHT: u32 = 0;

/// The null input-witness block index.
pub const NULL_BLOCK_INDEX: u32 = 0xffff_ffff;

/// The default public key script version.
pub const DEFAULT_PK_SCRIPT_VERSION: u16 = 0;

/// Regular transaction tree (dcrd `TxTreeRegular`).
pub const TX_TREE_REGULAR: i8 = 0;

/// Stake transaction tree (dcrd `TxTreeStake`).
pub const TX_TREE_STAKE: i8 = 1;

/// Unknown transaction tree (dcrd `TxTreeUnknown`).
pub const TX_TREE_UNKNOWN: i8 = -1;

/// Minimum serialized size of a transaction input in the prefix, per dcrd's
/// `minTxInPayload` (used only to derive the input-count DoS limit).
const MIN_TX_IN_PAYLOAD: u64 = 11 + dcroxide_chainhash::HASH_SIZE as u64;

/// The maximum number of transaction inputs that could possibly fit into a
/// max-size message (dcrd `maxTxInPerMessage`).
pub const MAX_TX_IN_PER_MESSAGE: u64 = MAX_MESSAGE_PAYLOAD / MIN_TX_IN_PAYLOAD + 1;

/// Minimum serialized size of a transaction output, per dcrd's
/// `minTxOutPayload` (used only to derive the output-count DoS limit).
const MIN_TX_OUT_PAYLOAD: u64 = 9;

/// Minimum serialized size of any full transaction, per dcrd's
/// `minTxPayload` (used to derive the per-tree transaction count limit).
pub(crate) const MIN_TX_PAYLOAD: u64 = 4 + 1 + 1 + 1 + 4 + 4;

/// The maximum number of transaction outputs that could possibly fit into a
/// max-size message (dcrd `maxTxOutPerMessage`).
pub const MAX_TX_OUT_PER_MESSAGE: u64 = MAX_MESSAGE_PAYLOAD / MIN_TX_OUT_PAYLOAD + 1;

/// The serialization type of a transaction, encoded in the upper 16 bits of
/// the on-wire version field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TxSerializeType {
    /// Prefix and all witness data (`TxSerializeFull`).
    #[default]
    Full,
    /// Prefix only (`TxSerializeNoWitness`).
    NoWitness,
    /// Witness data only (`TxSerializeOnlyWitness`).
    OnlyWitness,
}

impl TxSerializeType {
    /// The on-wire value.
    pub fn to_u16(self) -> u16 {
        match self {
            TxSerializeType::Full => 0,
            TxSerializeType::NoWitness => 1,
            TxSerializeType::OnlyWitness => 2,
        }
    }

    /// Parse an on-wire value; unknown values error like dcrd's
    /// `ErrUnknownTxType` (dcrd defers the check until after the version
    /// field is stored, but the observable decode verdict is identical).
    pub fn from_u16(v: u16) -> Result<Self, WireError> {
        match v {
            0 => Ok(TxSerializeType::Full),
            1 => Ok(TxSerializeType::NoWitness),
            2 => Ok(TxSerializeType::OnlyWitness),
            other => Err(WireError::UnknownTxType(other)),
        }
    }
}

/// A reference to a previous transaction output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OutPoint {
    /// The hash of the referenced transaction.
    pub hash: Hash,
    /// The output index within that transaction.
    pub index: u32,
    /// The transaction tree the referenced output lives in.
    pub tree: i8,
}

/// A Decred transaction input: prefix fields plus witness fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TxIn {
    /// (prefix) The previous output being spent.
    pub previous_out_point: OutPoint,
    /// (prefix) The input sequence number.
    pub sequence: u32,
    /// (witness) The value of the previous output in atoms.
    pub value_in: i64,
    /// (witness) The height of the block containing the previous output.
    pub block_height: u32,
    /// (witness) The index within that block of the transaction containing
    /// the previous output.
    pub block_index: u32,
    /// (witness) The signature script.
    pub signature_script: Vec<u8>,
}

impl TxIn {
    /// Serialized size of the prefix portion (dcrd `SerializeSizePrefix`).
    pub fn serialize_size_prefix(&self) -> usize {
        // Outpoint hash 32 + index 4 + tree 1 + sequence 4.
        41
    }

    /// Serialized size of the witness portion (dcrd `SerializeSizeWitness`).
    pub fn serialize_size_witness(&self) -> usize {
        8 + 4
            + 4
            + var_int_serialize_size(self.signature_script.len() as u64)
            + self.signature_script.len()
    }
}

/// A Decred transaction output.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TxOut {
    /// The value of the output in atoms.
    pub value: i64,
    /// The public key script version.
    pub version: u16,
    /// The public key script.
    pub pk_script: Vec<u8>,
}

impl TxOut {
    /// Serialized size (dcrd `TxOut.SerializeSize`).
    pub fn serialize_size(&self) -> usize {
        8 + 2 + var_int_serialize_size(self.pk_script.len() as u64) + self.pk_script.len()
    }
}

/// A Decred transaction, byte-compatible with dcrd's `MsgTx`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgTx {
    /// The serialization type used when encoding this transaction.
    pub ser_type: TxSerializeType,
    /// The transaction version (lower 16 bits of the on-wire version field).
    pub version: u16,
    /// The transaction inputs.
    pub tx_in: Vec<TxIn>,
    /// The transaction outputs.
    pub tx_out: Vec<TxOut>,
    /// The lock time.
    pub lock_time: u32,
    /// The expiry height (0 = no expiry).
    pub expiry: u32,
}

impl Default for MsgTx {
    /// Equivalent to dcrd's `NewMsgTx`: full serialization, version 1, empty
    /// inputs/outputs.
    fn default() -> Self {
        MsgTx {
            ser_type: TxSerializeType::Full,
            version: TX_VERSION,
            tx_in: Vec::new(),
            tx_out: Vec::new(),
            lock_time: 0,
            expiry: 0,
        }
    }
}

impl MsgTx {
    /// Decode a transaction from the cursor (dcrd `MsgTx.BtcDecode` /
    /// `Deserialize`). Trailing bytes are not an error; the cursor position
    /// reflects what was consumed.
    pub fn decode(r: &mut Cursor<'_>) -> Result<MsgTx, WireError> {
        // The on-wire version: real version in the lower 16 bits, the
        // serialization type in the upper 16 bits.
        let version_field = r.read_u32()?;
        let version = (version_field & 0xffff) as u16;
        let ser_type = TxSerializeType::from_u16((version_field >> 16) as u16)?;

        let mut msg = MsgTx {
            ser_type,
            version,
            tx_in: Vec::new(),
            tx_out: Vec::new(),
            lock_time: 0,
            expiry: 0,
        };

        match ser_type {
            TxSerializeType::NoWitness => {
                msg.decode_prefix(r)?;
            }
            TxSerializeType::OnlyWitness => {
                msg.decode_witness(r, false)?;
            }
            TxSerializeType::Full => {
                msg.decode_prefix(r)?;
                msg.decode_witness(r, true)?;
            }
        }
        Ok(msg)
    }

    /// Decode from a byte slice, returning the transaction and the number of
    /// bytes consumed (dcrd `FromBytes`; trailing bytes are ignored there
    /// too, hence the explicit consumed count).
    pub fn from_bytes(b: &[u8]) -> Result<(MsgTx, usize), WireError> {
        let mut r = Cursor::new(b);
        let msg = Self::decode(&mut r)?;
        Ok((msg, r.position()))
    }

    /// dcrd `MsgTx.decodePrefix`.
    fn decode_prefix(&mut self, r: &mut Cursor<'_>) -> Result<(), WireError> {
        let count = read_var_int(r)?;
        // Prevent more input transactions than could possibly fit into a
        // message (memory-exhaustion hardening, same limit as dcrd).
        if count > MAX_TX_IN_PER_MESSAGE {
            return Err(WireError::TooManyTxs {
                count,
                max: MAX_TX_IN_PER_MESSAGE,
            });
        }

        self.tx_in.clear();
        for _ in 0..count {
            let hash = Hash(r.take_array()?);
            let index = r.read_u32()?;
            let tree = r.read_u8()? as i8;
            let sequence = r.read_u32()?;
            self.tx_in.push(TxIn {
                previous_out_point: OutPoint { hash, index, tree },
                sequence,
                ..TxIn::default()
            });
        }

        let count = read_var_int(r)?;
        if count > MAX_TX_OUT_PER_MESSAGE {
            return Err(WireError::TooManyTxs {
                count,
                max: MAX_TX_OUT_PER_MESSAGE,
            });
        }

        self.tx_out.clear();
        for _ in 0..count {
            let value = r.read_u64()? as i64;
            let version = r.read_u16()?;
            let pk_script = read_var_bytes(r, MAX_MESSAGE_PAYLOAD)?;
            self.tx_out.push(TxOut {
                value,
                version,
                pk_script,
            });
        }

        self.lock_time = r.read_u32()?;
        self.expiry = r.read_u32()?;
        Ok(())
    }

    /// dcrd `MsgTx.decodeWitness`. With `is_full`, fills witness fields of
    /// the already-decoded prefix inputs; otherwise builds witness-only
    /// inputs (and an empty output list, as dcrd does).
    fn decode_witness(&mut self, r: &mut Cursor<'_>, is_full: bool) -> Result<(), WireError> {
        let count = read_var_int(r)?;
        if is_full {
            // The witness input count must match the prefix input count;
            // dcrd checks this before the size limit.
            if count != self.tx_in.len() as u64 {
                return Err(WireError::MismatchedWitnessCount {
                    witness: count,
                    prefix: self.tx_in.len() as u64,
                });
            }
        }
        if count > MAX_TX_IN_PER_MESSAGE {
            return Err(WireError::TooManyTxs {
                count,
                max: MAX_TX_IN_PER_MESSAGE,
            });
        }

        if !is_full {
            self.tx_in.clear();
            self.tx_out.clear();
        }
        for i in 0..count as usize {
            let value_in = r.read_u64()? as i64;
            let block_height = r.read_u32()?;
            let block_index = r.read_u32()?;
            let signature_script = read_var_bytes(r, MAX_MESSAGE_PAYLOAD)?;
            if is_full {
                let ti = &mut self.tx_in[i];
                ti.value_in = value_in;
                ti.block_height = block_height;
                ti.block_index = block_index;
                ti.signature_script = signature_script;
            } else {
                self.tx_in.push(TxIn {
                    value_in,
                    block_height,
                    block_index,
                    signature_script,
                    ..TxIn::default()
                });
            }
        }
        Ok(())
    }

    /// Append the prefix serialization (dcrd `encodePrefix`).
    fn encode_prefix(&self, w: &mut Vec<u8>) {
        write_var_int(w, self.tx_in.len() as u64);
        for ti in &self.tx_in {
            w.extend_from_slice(ti.previous_out_point.hash.as_bytes());
            w.extend_from_slice(&ti.previous_out_point.index.to_le_bytes());
            w.push(ti.previous_out_point.tree as u8);
            w.extend_from_slice(&ti.sequence.to_le_bytes());
        }
        write_var_int(w, self.tx_out.len() as u64);
        for to in &self.tx_out {
            w.extend_from_slice(&(to.value as u64).to_le_bytes());
            w.extend_from_slice(&to.version.to_le_bytes());
            write_var_bytes(w, &to.pk_script);
        }
        w.extend_from_slice(&self.lock_time.to_le_bytes());
        w.extend_from_slice(&self.expiry.to_le_bytes());
    }

    /// Append the witness serialization (dcrd `encodeWitness`).
    fn encode_witness(&self, w: &mut Vec<u8>) {
        write_var_int(w, self.tx_in.len() as u64);
        for ti in &self.tx_in {
            w.extend_from_slice(&(ti.value_in as u64).to_le_bytes());
            w.extend_from_slice(&ti.block_height.to_le_bytes());
            w.extend_from_slice(&ti.block_index.to_le_bytes());
            write_var_bytes(w, &ti.signature_script);
        }
    }

    /// Append the serialization for an explicit serialization type.
    fn encode_with_type(&self, ser_type: TxSerializeType, w: &mut Vec<u8>) {
        let version_field = u32::from(self.version) | (u32::from(ser_type.to_u16()) << 16);
        w.extend_from_slice(&version_field.to_le_bytes());
        match ser_type {
            TxSerializeType::NoWitness => self.encode_prefix(w),
            TxSerializeType::OnlyWitness => self.encode_witness(w),
            TxSerializeType::Full => {
                self.encode_prefix(w);
                self.encode_witness(w);
            }
        }
    }

    /// Append the serialization using [`Self::ser_type`] (dcrd
    /// `MsgTx.BtcEncode` / `Serialize`).
    pub fn encode_into(&self, w: &mut Vec<u8>) {
        self.encode_with_type(self.ser_type, w);
    }

    /// The serialization using [`Self::ser_type`] (dcrd `Bytes`).
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(self.serialize_size());
        self.encode_into(&mut w);
        w
    }

    /// The serialized size in bytes for [`Self::ser_type`] (dcrd
    /// `SerializeSize`).
    pub fn serialize_size(&self) -> usize {
        let prefix = || {
            12 + var_int_serialize_size(self.tx_in.len() as u64)
                + var_int_serialize_size(self.tx_out.len() as u64)
                + self
                    .tx_in
                    .iter()
                    .map(TxIn::serialize_size_prefix)
                    .sum::<usize>()
                + self.tx_out.iter().map(TxOut::serialize_size).sum::<usize>()
        };
        let witness = || {
            var_int_serialize_size(self.tx_in.len() as u64)
                + self
                    .tx_in
                    .iter()
                    .map(TxIn::serialize_size_witness)
                    .sum::<usize>()
        };
        match self.ser_type {
            TxSerializeType::NoWitness => prefix(),
            TxSerializeType::OnlyWitness => 4 + witness(),
            TxSerializeType::Full => prefix() + witness(),
        }
    }

    /// The transaction hash: BLAKE-256 over the prefix (no-witness)
    /// serialization (dcrd `TxHash`).
    pub fn tx_hash(&self) -> Hash {
        let mut w = Vec::new();
        self.encode_with_type(TxSerializeType::NoWitness, &mut w);
        hash_h(&w)
    }

    /// The witness hash: BLAKE-256 over the witness-only serialization
    /// (dcrd `TxHashWitness`).
    pub fn tx_hash_witness(&self) -> Hash {
        let mut w = Vec::new();
        self.encode_with_type(TxSerializeType::OnlyWitness, &mut w);
        hash_h(&w)
    }

    /// The full hash: BLAKE-256 over the concatenated prefix and witness
    /// hashes — not over the full serialization (dcrd `TxHashFull`).
    pub fn tx_hash_full(&self) -> Hash {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(self.tx_hash().as_bytes());
        buf[32..].copy_from_slice(self.tx_hash_witness().as_bytes());
        hash_h(&buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// dcrd's `multiTx` reference transaction.
    fn multi_tx() -> MsgTx {
        MsgTx {
            ser_type: TxSerializeType::Full,
            version: 1,
            tx_in: alloc::vec![TxIn {
                previous_out_point: OutPoint {
                    hash: Hash::ZERO,
                    index: 0xffffffff,
                    tree: 0,
                },
                sequence: 0xffffffff,
                value_in: 0x1212121212121212,
                block_height: 0x15151515,
                block_index: 0x34343434,
                signature_script: alloc::vec![0x04, 0x31, 0xdc, 0x00, 0x1b, 0x01, 0x62],
            }],
            tx_out: alloc::vec![
                TxOut {
                    value: 0x12a05f200,
                    version: 0xabab,
                    pk_script: pk_script_65(),
                },
                TxOut {
                    value: 0x5f5e100,
                    version: 0xbcbc,
                    pk_script: pk_script_65(),
                },
            ],
            lock_time: 0,
            expiry: 0,
        }
    }

    fn pk_script_65() -> Vec<u8> {
        let mut s = alloc::vec![0x41];
        s.extend_from_slice(&[
            0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5, 0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d,
            0xca, 0x42, 0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1, 0xc6, 0xa5, 0x9d, 0xc2,
            0x26, 0xc2, 0x86, 0x24, 0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97, 0x3d, 0x81,
            0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78, 0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
            0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63, 0xa6,
        ]);
        s.push(0xac);
        s
    }

    /// dcrd's `multiTxEncoded` reference bytes.
    fn multi_tx_encoded() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // version
        v.push(0x01); // txin count
        v.extend_from_slice(&[0u8; 32]); // prev hash
        v.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]); // prev index
        v.push(0x00); // prev tree
        v.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]); // sequence
        v.push(0x02); // txout count
        v.extend_from_slice(&[0x00, 0xf2, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00]); // amount
        v.extend_from_slice(&[0xab, 0xab]); // script version
        v.push(0x43); // script len
        v.extend_from_slice(&pk_script_65());
        v.extend_from_slice(&[0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00]); // amount
        v.extend_from_slice(&[0xbc, 0xbc]); // script version
        v.push(0x43); // script len
        v.extend_from_slice(&pk_script_65());
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // lock time
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // expiry
        v.push(0x01); // witness count
        v.extend_from_slice(&[0x12; 8]); // value in
        v.extend_from_slice(&[0x15; 4]); // block height
        v.extend_from_slice(&[0x34; 4]); // block index
        v.push(0x07); // sig script len
        v.extend_from_slice(&[0x04, 0x31, 0xdc, 0x00, 0x1b, 0x01, 0x62]);
        v
    }

    #[test]
    fn multi_tx_encode() {
        let tx = multi_tx();
        assert_eq!(tx.serialize(), multi_tx_encoded());
        assert_eq!(tx.serialize_size(), multi_tx_encoded().len());
    }

    #[test]
    fn multi_tx_decode() {
        let bytes = multi_tx_encoded();
        let (tx, consumed) = MsgTx::from_bytes(&bytes).expect("decode multiTx");
        assert_eq!(consumed, bytes.len());
        assert_eq!(tx, multi_tx());
    }

    #[test]
    fn no_tx_round_trip() {
        // dcrd's `noTx` reference: empty version-1 transaction.
        let no_tx = MsgTx::default();
        let encoded = [
            0x01, 0x00, 0x00, 0x00, // version
            0x00, // txin count
            0x00, // txout count
            0x00, 0x00, 0x00, 0x00, // lock time
            0x00, 0x00, 0x00, 0x00, // expiry
            0x00, // witness count
        ];
        assert_eq!(no_tx.serialize(), encoded);
        let (tx, consumed) = MsgTx::from_bytes(&encoded).expect("decode noTx");
        assert_eq!(consumed, encoded.len());
        assert_eq!(tx, no_tx);
    }

    #[test]
    fn tx_hash_matches_dcrd_vector() {
        // Ported from dcrd's TestTxHash (hash of the first transaction from
        // block 113875).
        let want: Hash = "4538fc1618badd058ee88fd020984451024858796be0a1ed111877f887e1bd53"
            .parse()
            .expect("parse want hash");

        let tx = MsgTx {
            tx_in: alloc::vec![TxIn {
                previous_out_point: OutPoint {
                    hash: Hash::ZERO,
                    index: 0xffffffff,
                    tree: TX_TREE_REGULAR,
                },
                sequence: 0xffffffff,
                value_in: 5_000_000_000,
                block_height: 0x3F3F3F3F,
                block_index: 0x2E2E2E2E,
                signature_script: alloc::vec![0x04, 0x31, 0xdc, 0x00, 0x1b, 0x01, 0x62],
            }],
            tx_out: alloc::vec![TxOut {
                value: 5_000_000_000,
                version: 0xf0f0,
                pk_script: {
                    let mut s = alloc::vec![0x41];
                    s.extend_from_slice(&[
                        0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5, 0xfe, 0x29, 0x5a, 0xbd,
                        0xeb, 0x1d, 0xca, 0x42, 0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
                        0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24, 0xe1, 0x81, 0x75, 0xe8,
                        0x51, 0xc9, 0x6b, 0x97, 0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
                        0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20, 0xd1, 0x84, 0x24, 0x1a,
                        0x6a, 0xed, 0x8b, 0x63, 0xa6,
                    ]);
                    s.push(0xac);
                    s
                },
            }],
            ..MsgTx::default()
        };

        assert_eq!(tx.tx_hash(), want);
    }

    #[test]
    fn witness_count_mismatch_rejected() {
        // Full serialization with 0 prefix inputs but 1 witness input.
        let bytes = [
            0x01, 0x00, 0x00, 0x00, // version, full
            0x00, // txin count
            0x00, // txout count
            0x00, 0x00, 0x00, 0x00, // lock time
            0x00, 0x00, 0x00, 0x00, // expiry
            0x01, // witness count (mismatch)
        ];
        assert_eq!(
            MsgTx::from_bytes(&bytes),
            Err(WireError::MismatchedWitnessCount {
                witness: 1,
                prefix: 0
            })
        );
    }

    #[test]
    fn unknown_ser_type_rejected() {
        // Serialization type 3 in the upper 16 bits.
        let bytes = [0x01, 0x00, 0x03, 0x00];
        assert_eq!(MsgTx::from_bytes(&bytes), Err(WireError::UnknownTxType(3)));
    }

    #[test]
    fn only_witness_round_trip() {
        let mut tx = multi_tx();
        tx.ser_type = TxSerializeType::OnlyWitness;
        let bytes = tx.serialize();
        let (decoded, consumed) = MsgTx::from_bytes(&bytes).expect("decode witness-only");
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded.ser_type, TxSerializeType::OnlyWitness);
        assert_eq!(decoded.tx_in.len(), 1);
        assert_eq!(
            decoded.tx_in[0].signature_script,
            tx.tx_in[0].signature_script
        );
        assert!(decoded.tx_out.is_empty());
        // Canonical re-encode.
        assert_eq!(decoded.serialize(), bytes);
    }

    #[test]
    fn no_witness_round_trip() {
        let mut tx = multi_tx();
        tx.ser_type = TxSerializeType::NoWitness;
        let bytes = tx.serialize();
        let (decoded, consumed) = MsgTx::from_bytes(&bytes).expect("decode no-witness");
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded.tx_out, tx.tx_out);
        // Witness fields are zero-valued after a prefix-only decode.
        assert_eq!(decoded.tx_in[0].value_in, 0);
        assert!(decoded.tx_in[0].signature_script.is_empty());
        assert_eq!(decoded.serialize(), bytes);
    }
}
