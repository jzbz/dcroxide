// SPDX-License-Identifier: ISC
//! Decred transactions (`MsgTx`) with byte-exact dcrd serialization across
//! all three serialization types, and the BLAKE-256 transaction hashes.

use alloc::vec::Vec;
use core::fmt;

use dcroxide_chainhash::{Hash, hash_h};

use crate::MAX_MESSAGE_PAYLOAD;
use crate::cursor::Cursor;
use crate::error::WireError;
use crate::varint::{
    read_var_bytes_as, read_var_int, var_int_serialize_size, write_var_bytes, write_var_int,
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

/// Flag on an input sequence number disabling its interpretation as a
/// relative locktime (dcrd `SequenceLockTimeDisabled`).
pub const SEQUENCE_LOCK_TIME_DISABLED: u32 = 1 << 31;

/// Flag on an input sequence number giving the relative locktime units of
/// 512 seconds (dcrd `SequenceLockTimeIsSeconds`).
pub const SEQUENCE_LOCK_TIME_IS_SECONDS: u32 = 1 << 22;

/// Mask extracting the relative locktime from an input sequence number
/// (dcrd `SequenceLockTimeMask`).
pub const SEQUENCE_LOCK_TIME_MASK: u32 = 0x0000_ffff;

/// The right-shift converting seconds to a seconds-based relative lock
/// (dcrd `SequenceLockTimeGranularity`); enforced locks are multiples of
/// 512 seconds.
pub const SEQUENCE_LOCK_TIME_GRANULARITY: u32 = 9;

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

/// The encoded size of a prefix input: outpoint hash 32, index 4 and
/// tree 1, then sequence 4.
const PREFIX_TX_IN_SIZE: usize = 41;

/// The fewest bytes an output can encode to: value 8 and script version
/// 2, then an empty script's one-byte length.
const MIN_TX_OUT_SIZE: usize = 11;

/// The fewest bytes a witness input can encode to: value 8, block height
/// 4 and block index 4, then an empty script's one-byte length.
const MIN_TX_IN_WITNESS_SIZE: usize = 17;

/// The fewest bytes any transaction can encode to: version 4, then the
/// one-byte zero input count of a witness-only serialization.
pub(crate) const MIN_TX_SIZE: usize = 5;

/// The capacity to reserve for `count` decoded elements of at least
/// `min_size` bytes each, when `remaining` bytes are left to decode.
///
/// dcrd sizes these slices from the declared count alone, bounded only
/// by limits derived from payload caps (for a transaction's inputs and
/// outputs, the 32 MiB global one), so a ten-byte `tx` payload declaring
/// 3,728,271 outputs reserves ~149 MB before failing on the first one.
/// The error is the same either way.  Capping by what the bytes could
/// hold keeps the reservation to the payload's own scale, and with
/// `min_size` the true minimum it never under-reserves input that
/// decodes.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "min_size is a positive constant at every call site and the division is unsigned"
)]
pub(crate) fn capped_capacity(count: u64, remaining: usize, min_size: usize) -> usize {
    (count as usize).min(remaining / min_size)
}

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

impl fmt::Display for OutPoint {
    /// The `hash:index` form of dcrd's `OutPoint.String` (the tree is
    /// not part of the rendering).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.hash, self.index)
    }
}

/// Read an outpoint (dcrd `ReadOutPoint`, `wire/msgtx.go:1174-1197`):
/// the hash, index and tree, then the tree check.
///
/// A negative tree fails with [`WireError::NegativeTxTree`] once its
/// byte is read, before anything after the outpoint; a read cut short
/// at an earlier field fails with that read's own io error, as dcrd's
/// does.
pub fn read_out_point(r: &mut Cursor<'_>) -> Result<OutPoint, WireError> {
    let hash = Hash(r.take_array()?);
    let index = r.read_u32()?;
    let tree = r.read_u8()? as i8;
    if tree < 0 {
        return Err(WireError::NegativeTxTree {
            op: "ReadOutPoint",
            tree,
        });
    }
    Ok(OutPoint { hash, index, tree })
}

/// Append an outpoint (dcrd `WriteOutPoint`, `wire/msgtx.go:1201-1218`).
///
/// A negative tree fails with [`WireError::NegativeTxTree`] before
/// anything is written, as dcrd's check precedes its first write.
pub fn write_out_point(w: &mut Vec<u8>, op: &OutPoint) -> Result<(), WireError> {
    if op.tree < 0 {
        return Err(WireError::NegativeTxTree {
            op: "WriteOutPoint",
            tree: op.tree,
        });
    }
    put_out_point(w, op);
    Ok(())
}

/// Append an outpoint's 37 bytes whatever its tree, for the infallible
/// encoders ([`MsgTx::serialize`] and the hashes).
fn put_out_point(w: &mut Vec<u8>, op: &OutPoint) {
    w.extend_from_slice(op.hash.as_bytes());
    w.extend_from_slice(&op.index.to_le_bytes());
    w.push(op.tree as u8);
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
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "constants 16 and a varint size (at most 9) plus an in-memory script length"
    )]
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
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "constants 10 and a varint size (at most 9) plus an in-memory script length"
    )]
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

/// Read a transaction script bounded by the maximum message payload
/// (dcrd `readScript`): the var-bytes read, with the limit error naming
/// the script as dcrd's description does.
pub(crate) fn read_script(
    r: &mut Cursor<'_>,
    field_name: &'static str,
) -> Result<Vec<u8>, WireError> {
    read_var_bytes_as(r, MAX_MESSAGE_PAYLOAD, "readScript", field_name)
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
                op: "MsgTx.decodePrefix",
                what: "input transactions to fit into max message size",
            });
        }

        // dcrd's `make([]TxIn, count)`, capped by the bytes left.
        self.tx_in = Vec::with_capacity(capped_capacity(count, r.remaining(), PREFIX_TX_IN_SIZE));
        for _ in 0..count {
            // dcrd `readTxInPrefix`: the outpoint, then the sequence.
            let previous_out_point = read_out_point(r)?;
            let sequence = r.read_u32()?;
            self.tx_in.push(TxIn {
                previous_out_point,
                sequence,
                ..TxIn::default()
            });
        }

        let count = read_var_int(r)?;
        if count > MAX_TX_OUT_PER_MESSAGE {
            return Err(WireError::TooManyTxs {
                count,
                max: MAX_TX_OUT_PER_MESSAGE,
                op: "MsgTx.decodePrefix",
                what: "output transactions to fit into max message size",
            });
        }

        // dcrd's `make([]TxOut, count)`, capped by the bytes left.
        self.tx_out = Vec::with_capacity(capped_capacity(count, r.remaining(), MIN_TX_OUT_SIZE));
        for _ in 0..count {
            let value = r.read_u64()? as i64;
            let version = r.read_u16()?;
            let pk_script = read_script(r, "transaction output public key script")?;
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
                op: "MsgTx.decodeWitness",
                what: "input transactions to fit into max message size",
            });
        }

        if !is_full {
            // dcrd's `make([]TxIn, count)` in the witness-only decode
            // path, capped by the bytes left (outputs stay empty, as in
            // dcrd).
            self.tx_in = Vec::with_capacity(capped_capacity(
                count,
                r.remaining(),
                MIN_TX_IN_WITNESS_SIZE,
            ));
            self.tx_out = Vec::new();
        }
        for i in 0..count as usize {
            let value_in = r.read_u64()? as i64;
            let block_height = r.read_u32()?;
            let block_index = r.read_u32()?;
            let signature_script = read_script(r, "transaction input signature script")?;
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

    /// Append the prefix serialization (dcrd `encodePrefix`), each input
    /// as dcrd's `writeTxInPrefix` writes it: the outpoint through
    /// [`write_out_point`], then the sequence.  An input with a negative
    /// tree fails there, after the input count and the inputs before it
    /// are written.
    fn encode_prefix(&self, w: &mut Vec<u8>) -> Result<(), WireError> {
        write_var_int(w, self.tx_in.len() as u64);
        for ti in &self.tx_in {
            write_out_point(w, &ti.previous_out_point)?;
            w.extend_from_slice(&ti.sequence.to_le_bytes());
        }
        self.encode_prefix_outputs(w);
        Ok(())
    }

    /// The prefix serialization with every tree written as its byte, for
    /// the infallible forms.
    fn encode_prefix_unchecked(&self, w: &mut Vec<u8>) {
        write_var_int(w, self.tx_in.len() as u64);
        for ti in &self.tx_in {
            put_out_point(w, &ti.previous_out_point);
            w.extend_from_slice(&ti.sequence.to_le_bytes());
        }
        self.encode_prefix_outputs(w);
    }

    /// The rest of the prefix after its inputs: the outputs, lock time
    /// and expiry.
    fn encode_prefix_outputs(&self, w: &mut Vec<u8>) {
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

    /// The on-wire version field: the version in the lower 16 bits, the
    /// serialization type in the upper 16.
    fn version_field(&self, ser_type: TxSerializeType) -> [u8; 4] {
        (u32::from(self.version) | (u32::from(ser_type.to_u16()) << 16)).to_le_bytes()
    }

    /// Append the serialization using [`Self::ser_type`] (dcrd
    /// `MsgTx.BtcEncode` / `Serialize`).
    ///
    /// Fails as dcrd's does on a prefix input whose outpoint names a
    /// negative tree ([`WireError::NegativeTxTree`] from
    /// [`write_out_point`]), with the version field, the input count and
    /// the inputs before it already appended.  A witness-only
    /// serialization writes no outpoints and cannot fail.
    pub fn encode_into(&self, w: &mut Vec<u8>) -> Result<(), WireError> {
        w.extend_from_slice(&self.version_field(self.ser_type));
        match self.ser_type {
            TxSerializeType::NoWitness => self.encode_prefix(w)?,
            TxSerializeType::OnlyWitness => self.encode_witness(w),
            TxSerializeType::Full => {
                self.encode_prefix(w)?;
                self.encode_witness(w);
            }
        }
        Ok(())
    }

    /// Append the serialization for an explicit serialization type, every
    /// outpoint tree written as its byte.
    ///
    /// This is the encoding behind the infallible [`Self::serialize`] and
    /// the hashes.  It differs from [`Self::encode_into`] only for a
    /// transaction with a negative input tree, which dcrd's `Bytes`
    /// refuses with `ErrNegativeTxTree` and its `TxHash` and `TxHashFull`
    /// panic on (`mustHash`, `wire/msgtx.go:418-429`).  No decoder
    /// produces one ([`read_out_point`] refuses it), and every RPC that
    /// builds an input checks its tree first, so only a transaction
    /// assembled in memory can tell the two apart.
    pub(crate) fn encode_unchecked(&self, ser_type: TxSerializeType, w: &mut Vec<u8>) {
        w.extend_from_slice(&self.version_field(ser_type));
        match ser_type {
            TxSerializeType::NoWitness => self.encode_prefix_unchecked(w),
            TxSerializeType::OnlyWitness => self.encode_witness(w),
            TxSerializeType::Full => {
                self.encode_prefix_unchecked(w);
                self.encode_witness(w);
            }
        }
    }

    /// The serialization using [`Self::ser_type`] (dcrd `Bytes`).
    ///
    /// Infallible: a negative input tree, which dcrd's `Bytes` refuses,
    /// is written as its byte (see [`Self::encode_into`] for the checked
    /// form, which [`crate::write_message`] uses).
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(self.serialize_size());
        self.encode_unchecked(self.ser_type, &mut w);
        w
    }

    /// The serialized size in bytes for [`Self::ser_type`] (dcrd
    /// `SerializeSize`).
    pub fn serialize_size(&self) -> usize {
        self.serialize_size_with_type(self.ser_type)
    }

    /// The serialized size in bytes for an explicit serialization type
    /// (dcrd computes this by shallow-copying the transaction with the
    /// desired `SerType` and calling `SerializeSize`).
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "constants, varint sizes (at most 9) and sums of in-memory input and output sizes, bounded by the transaction's allocation"
    )]
    fn serialize_size_with_type(&self, ser_type: TxSerializeType) -> usize {
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
        match ser_type {
            TxSerializeType::NoWitness => prefix(),
            TxSerializeType::OnlyWitness => 4 + witness(),
            TxSerializeType::Full => prefix() + witness(),
        }
    }

    /// The transaction hash: BLAKE-256 over the prefix (no-witness)
    /// serialization (dcrd `TxHash`, which preallocates via
    /// `SerializeSize` in `serialize`).
    ///
    /// Total: an input with a negative tree, on which dcrd's `TxHash`
    /// panics, is hashed with the tree's byte, as [`Self::serialize`]
    /// writes it.
    pub fn tx_hash(&self) -> Hash {
        let ser_type = TxSerializeType::NoWitness;
        let mut w = Vec::with_capacity(self.serialize_size_with_type(ser_type));
        self.encode_unchecked(ser_type, &mut w);
        hash_h(&w)
    }

    /// The witness hash: BLAKE-256 over the witness-only serialization
    /// (dcrd `TxHashWitness`).
    pub fn tx_hash_witness(&self) -> Hash {
        let ser_type = TxSerializeType::OnlyWitness;
        let mut w = Vec::with_capacity(self.serialize_size_with_type(ser_type));
        self.encode_unchecked(ser_type, &mut w);
        hash_h(&w)
    }

    /// The full hash: BLAKE-256 over the concatenated prefix and witness
    /// hashes — not over the full serialization (dcrd `TxHashFull`).
    /// Total, as [`Self::tx_hash`] is.
    pub fn tx_hash_full(&self) -> Hash {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(self.tx_hash().as_bytes());
        buf[32..].copy_from_slice(self.tx_hash_witness().as_bytes());
        hash_h(&buf)
    }

    /// The byte offset of each output's public key script within the
    /// serialized transaction, one per output in order (dcrd
    /// `MsgTx.PkScriptLocs`, `wire/msgtx.go:1119-1157`).
    ///
    /// Output `i`'s script occupies
    /// `bytes[locs[i]..locs[i] + tx.tx_out[i].pk_script.len()]` of the
    /// transaction's serialization `bytes`, so a store that keeps the
    /// serialized transaction can record where each script lies without
    /// serializing it again.  The prefix leads both serializations that
    /// carry outputs, so the offsets are the same for
    /// [`TxSerializeType::Full`] and [`TxSerializeType::NoWitness`], and a
    /// transaction decoded by [`Self::from_bytes`] from either finds its
    /// scripts at these offsets in the very bytes it was decoded from:
    /// decoding is canonical, so those bytes are its serialization.
    ///
    /// A transaction without outputs gets an empty list, where dcrd
    /// returns a nil slice.  A witness-only decode leaves the outputs
    /// empty, so it gets one too.
    ///
    /// As in dcrd, [`Self::ser_type`] is not consulted: the offsets are
    /// always those of the serialization with a prefix.  A transaction
    /// that holds outputs but has [`TxSerializeType::OnlyWitness`] set,
    /// which only one assembled or modified in memory can be, gets the
    /// offsets its outputs would have in the full serialization, and they
    /// do not locate its scripts in its own witness-only serialization,
    /// which carries none (QUIRKS QK-0038).
    ///
    /// This allocates the list once, at its exact length, and not at all
    /// for a transaction without outputs; [`Self::pk_script_locs_iter`]
    /// yields the same offsets without allocating.
    pub fn pk_script_locs(&self) -> Vec<usize> {
        // `collect` would round a short list's capacity up to four.
        let mut locs = Vec::with_capacity(self.tx_out.len());
        locs.extend(self.pk_script_locs_iter());
        locs
    }

    /// [`Self::pk_script_locs`] as an iterator, which allocates nothing:
    /// the same offsets, in output order, computed as they are taken.
    /// `pk_script_locs_iter().nth(i)` is output `i`'s offset alone, in
    /// time linear in `i`.
    pub fn pk_script_locs_iter(&self) -> PkScriptLocs<'_> {
        PkScriptLocs::new(self)
    }
}

/// The offsets of a transaction's output scripts within its serialization,
/// from [`MsgTx::pk_script_locs_iter`]: one `usize` per output, in output
/// order, each the offset [`MsgTx::pk_script_locs`] lists at that index.
#[derive(Debug, Clone)]
pub struct PkScriptLocs<'a> {
    /// The outputs not yet visited.
    outputs: core::slice::Iter<'a, TxOut>,
    /// The offset at which the next output's encoding begins.
    next_output_at: usize,
}

impl<'a> PkScriptLocs<'a> {
    /// The first output's encoding begins after the version field, the
    /// input count, the output count and every prefix input, as dcrd's
    /// `PkScriptLocs` computes it; the witness, which follows the prefix,
    /// does not move it.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "a constant, two varint sizes (at most 9 each) and 41 bytes per in-memory input, bounded by the transaction's allocation"
    )]
    fn new(tx: &'a MsgTx) -> Self {
        let next_output_at = 4
            + var_int_serialize_size(tx.tx_in.len() as u64)
            + var_int_serialize_size(tx.tx_out.len() as u64)
            + PREFIX_TX_IN_SIZE * tx.tx_in.len();
        PkScriptLocs {
            outputs: tx.tx_out.iter(),
            next_output_at,
        }
    }
}

impl Iterator for PkScriptLocs<'_> {
    type Item = usize;

    /// The next output's script begins after its value (8 bytes), its
    /// script version (2) and its script length's varint.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "offsets within the serialization of an in-memory transaction, whose size its allocation bounds"
    )]
    fn next(&mut self) -> Option<usize> {
        let out = self.outputs.next()?;
        let len = out.pk_script.len();
        let loc = self.next_output_at + 8 + 2 + var_int_serialize_size(len as u64);
        self.next_output_at = loc + len;
        Some(loc)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.outputs.size_hint()
    }
}

impl ExactSizeIterator for PkScriptLocs<'_> {}

impl core::iter::FusedIterator for PkScriptLocs<'_> {}

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

    /// dcrd's `multiTxPkScriptLocs` (`wire/msgtx_test.go:1233-1235`).
    const MULTI_TX_PK_SCRIPT_LOCS: [usize; 2] = [58, 136];

    /// dcrd's check after each `PkScriptLocs` comparison: output `j`'s
    /// script is `buf[loc : loc+len(PkScript)]` of the serialization.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "test arithmetic over offsets and lengths within in-memory serializations"
    )]
    fn assert_scripts_at_locs(tx: &MsgTx, buf: &[u8], locs: &[usize], ctx: &str) {
        assert_eq!(locs.len(), tx.tx_out.len(), "{ctx}: one offset per output");
        for (j, (&loc, out)) in locs.iter().zip(&tx.tx_out).enumerate() {
            let end = loc + out.pk_script.len();
            assert_eq!(buf[loc..end], out.pk_script[..], "{ctx}: output {j}");
        }
    }

    /// The `PkScriptLocs` checks of dcrd's `TestTxSerialize`,
    /// `TestTxSerializePrefix` and `TestTxSerializeWitness`
    /// (`wire/msgtx_test.go:348-624`): no offsets for the empty
    /// transaction in each serialization type, `multiTxPkScriptLocs` for
    /// `multiTx` and `multiTxPrefix`, and none for `multiTxWitness`,
    /// whose outputs are empty, with each script found at its offset in
    /// the reference bytes.  dcrd's nil slices are empty lists here.
    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "test arithmetic over offsets and lengths within in-memory serializations"
    )]
    fn pk_script_locs_match_dcrd_tests() {
        for ser_type in [
            TxSerializeType::Full,
            TxSerializeType::NoWitness,
            TxSerializeType::OnlyWitness,
        ] {
            let no_tx = MsgTx {
                ser_type,
                ..MsgTx::default()
            };
            assert_eq!(no_tx.pk_script_locs(), [0usize; 0], "noTx {ser_type:?}");
            assert_eq!(no_tx.pk_script_locs_iter().len(), 0);
        }

        // TestTxSerialize: multiTx and multiTxEncoded.
        let tx = multi_tx();
        let locs = tx.pk_script_locs();
        assert_eq!(locs, MULTI_TX_PK_SCRIPT_LOCS);
        assert_scripts_at_locs(&tx, &multi_tx_encoded(), &locs, "multiTx");

        // TestTxSerializePrefix: multiTxPrefix, whose witness fields are
        // zero, and multiTxPrefixEncoded, which is multiTxEncoded with
        // serialization type 1 and without the witness.
        let mut prefix = multi_tx();
        prefix.ser_type = TxSerializeType::NoWitness;
        prefix.tx_in[0] = TxIn {
            previous_out_point: prefix.tx_in[0].previous_out_point,
            sequence: prefix.tx_in[0].sequence,
            ..TxIn::default()
        };
        let mut prefix_encoded = multi_tx_encoded();
        prefix_encoded[2] = 0x01;
        prefix_encoded.truncate(prefix_encoded.len() - (1 + 8 + 4 + 4 + 1 + 7));
        assert_eq!(prefix.serialize(), prefix_encoded);
        let locs = prefix.pk_script_locs();
        assert_eq!(locs, MULTI_TX_PK_SCRIPT_LOCS);
        assert_scripts_at_locs(&prefix, &prefix_encoded, &locs, "multiTxPrefix");

        // TestTxSerializeWitness: multiTxWitness has no outputs.
        let witness = MsgTx {
            ser_type: TxSerializeType::OnlyWitness,
            tx_in: alloc::vec![TxIn {
                value_in: 0x1212121212121212,
                block_height: 0x15151515,
                block_index: 0x34343434,
                signature_script: alloc::vec![0x04, 0x31, 0xdc, 0x00, 0x1b, 0x01, 0x62],
                ..TxIn::default()
            }],
            ..MsgTx::default()
        };
        assert_eq!(witness.pk_script_locs(), [0usize; 0]);
        let (decoded, _) = MsgTx::from_bytes(&witness.serialize()).expect("decode");
        assert_eq!(decoded.pk_script_locs(), [0usize; 0]);
    }

    /// As in dcrd, the serialization type is not consulted: every type
    /// gets the full serialization's offsets.  For a witness-only
    /// transaction that holds outputs, which only memory can produce,
    /// those offsets lie in a serialization it does not have (QK-0038).
    #[test]
    fn pk_script_locs_ignore_the_serialization_type() {
        let mut tx = multi_tx();
        for ser_type in [TxSerializeType::NoWitness, TxSerializeType::OnlyWitness] {
            tx.ser_type = ser_type;
            assert_eq!(tx.pk_script_locs(), MULTI_TX_PK_SCRIPT_LOCS, "{ser_type:?}");
        }
        // Its own witness-only serialization is 29 bytes, short of the
        // first offset, and the full one holds the scripts there.
        assert_eq!(tx.serialize().len(), 29);
        assert_scripts_at_locs(&tx, &multi_tx_encoded(), &tx.pk_script_locs(), "full");
    }

    /// The iterator yields the list's offsets, reports its exact length as
    /// it goes, stays exhausted, and `nth` reaches an offset alone.
    #[test]
    fn pk_script_locs_iter_is_the_list() {
        let tx = multi_tx();
        let mut it = tx.pk_script_locs_iter();
        assert_eq!(it.len(), 2);
        assert_eq!(it.next(), Some(58));
        assert_eq!(it.size_hint(), (1, Some(1)));
        assert_eq!(it.next(), Some(136));
        assert_eq!(it.len(), 0);
        assert_eq!(it.next(), None);
        assert_eq!(it.next(), None);
        assert_eq!(tx.pk_script_locs_iter().nth(1), Some(136));
        assert_eq!(tx.pk_script_locs_iter().nth(2), None);
        let locs = tx.pk_script_locs();
        assert_eq!(locs.capacity(), locs.len());
    }

    /// Every width of varint that a decodable transaction can carry moves
    /// the offsets as the encoding does: input and output counts and
    /// script lengths at 0xfc, the last one-byte value, at 0xfd and
    /// 0xffff, the first and last three-byte values, and at 0x10000, the
    /// first five-byte value.  Each script is found at its offset in both
    /// serializations that carry it.  The nine-byte width starts at 2^32,
    /// past what a 32 MiB message can hold of either and past what a test
    /// can allocate, and is not exercised.
    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "test arithmetic over offsets and lengths within in-memory serializations"
    )]
    fn pk_script_locs_cross_every_varint_width() {
        const EDGES: [usize; 5] = [0xfc, 0xfd, 0xfe, 0xffff, 0x10000];
        let script =
            |len: usize, tag: u8| -> Vec<u8> { (0..len).map(|i| (i as u8) ^ tag).collect() };
        let output = |len: usize, tag: u8| TxOut {
            value: 1,
            version: 0,
            pk_script: script(len, tag),
        };
        let mut cases = Vec::new();
        for n in EDGES {
            // n inputs before two outputs.
            cases.push(MsgTx {
                tx_in: alloc::vec![TxIn::default(); n],
                tx_out: alloc::vec![output(3, 1), output(0, 2)],
                ..MsgTx::default()
            });
            // n outputs, the scripts of varied short lengths.
            cases.push(MsgTx {
                tx_in: alloc::vec![TxIn::default()],
                tx_out: (0..n).map(|i| output(i % 3, i as u8)).collect(),
                ..MsgTx::default()
            });
            // A script of n bytes between two short ones.
            cases.push(MsgTx {
                tx_out: alloc::vec![output(1, 3), output(n, 4), output(2, 5)],
                ..MsgTx::default()
            });
        }
        for mut tx in cases {
            for ser_type in [TxSerializeType::Full, TxSerializeType::NoWitness] {
                tx.ser_type = ser_type;
                let bytes = tx.serialize();
                let locs = tx.pk_script_locs();
                let ctx = alloc::format!(
                    "{ser_type:?}, {} inputs, {} outputs",
                    tx.tx_in.len(),
                    tx.tx_out.len()
                );
                assert_scripts_at_locs(&tx, &bytes, &locs, &ctx);
                // The last script ends where the lock time begins.
                let last = tx.tx_out.last().expect("outputs");
                let prefix_end = tx.serialize_size_with_type(TxSerializeType::NoWitness);
                assert_eq!(
                    locs.last().expect("offsets") + last.pk_script.len(),
                    prefix_end - 8,
                    "{ctx}"
                );
            }
        }
    }

    /// The largest script the decoder accepts, `MAX_MESSAGE_PAYLOAD`
    /// bytes, is found at its offset in the bytes it was decoded from.
    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "test arithmetic over offsets and lengths within in-memory serializations"
    )]
    fn pk_script_locs_locate_the_largest_decodable_script() {
        let len = MAX_MESSAGE_PAYLOAD as usize;
        let tx = MsgTx {
            ser_type: TxSerializeType::NoWitness,
            tx_out: alloc::vec![TxOut {
                value: 0,
                version: 0,
                pk_script: alloc::vec![0xa5; len],
            }],
            ..MsgTx::default()
        };
        let bytes = tx.serialize();
        let (decoded, consumed) = MsgTx::from_bytes(&bytes).expect("decode");
        assert_eq!(consumed, bytes.len());
        let locs = decoded.pk_script_locs();
        // Version 4, counts 1 and 1, value 8, script version 2, and the
        // script length's five-byte varint.
        assert_eq!(locs, [4 + 1 + 1 + 8 + 2 + 5]);
        assert_eq!(locs[0] + len, bytes.len() - 8);
        assert!(bytes[locs[0]..locs[0] + len].iter().all(|&b| b == 0xa5));
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

    /// A payload that declares the most inputs or outputs dcrd's limits
    /// allow, then runs out, reserves no more than its bytes could hold
    /// and fails exactly as before.  The declared counts used to be
    /// reserved whole: ~149 MB of outputs for a ten-byte `tx` payload.
    #[test]
    fn declared_counts_reserve_only_what_the_bytes_can_hold() {
        // No inputs, the maximum output count, and no outputs.
        let mut bytes = alloc::vec![0x00];
        write_var_int(&mut bytes, MAX_TX_OUT_PER_MESSAGE);
        let mut tx = MsgTx::default();
        assert_eq!(
            tx.decode_prefix(&mut Cursor::new(&bytes)),
            Err(WireError::Eof)
        );
        assert_eq!(tx.tx_out.capacity(), 0);

        // The maximum input count with room for two inputs and a half.
        let mut bytes = Vec::new();
        write_var_int(&mut bytes, MAX_TX_IN_PER_MESSAGE);
        bytes.extend_from_slice(&[0u8; 100]);
        let mut tx = MsgTx::default();
        assert_eq!(
            tx.decode_prefix(&mut Cursor::new(&bytes)),
            Err(WireError::UnexpectedEof)
        );
        assert_eq!(tx.tx_in.len(), 2);
        assert!(tx.tx_in.capacity() <= 100 / PREFIX_TX_IN_SIZE);

        // The witness-only form reserves its inputs the same way.
        let mut bytes = Vec::new();
        write_var_int(&mut bytes, MAX_TX_IN_PER_MESSAGE);
        let mut tx = MsgTx::default();
        assert_eq!(
            tx.decode_witness(&mut Cursor::new(&bytes), false),
            Err(WireError::Eof)
        );
        assert_eq!(tx.tx_in.capacity(), 0);
    }

    /// The cap never under-reserves a transaction that decodes: each
    /// list is sized once, to its length.
    #[test]
    fn decoded_lists_are_reserved_exactly() {
        let bytes = multi_tx_encoded();
        let (tx, _) = MsgTx::from_bytes(&bytes).expect("decode multiTx");
        assert_eq!(tx.tx_in.capacity(), tx.tx_in.len());
        assert_eq!(tx.tx_out.capacity(), tx.tx_out.len());

        let mut witness_only = multi_tx();
        witness_only.ser_type = TxSerializeType::OnlyWitness;
        let (tx, _) = MsgTx::from_bytes(&witness_only.serialize()).expect("decode");
        assert_eq!(tx.tx_in.capacity(), tx.tx_in.len());
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

    /// The raw bytes, not the byte-reversed string form, of the hash
    /// dcrd's `TestOutPointSerialize` uses.
    const OUT_POINT_HASH_HEX: &str =
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    fn out_point_hash() -> Hash {
        let bytes = dcroxide_testutil::unhex(OUT_POINT_HASH_HEX);
        Hash(bytes.try_into().expect("32 bytes"))
    }

    /// The bytes of `OUT_POINT_HASH_HEX` followed by `rest`.
    fn after_hash(rest: &str) -> Vec<u8> {
        dcroxide_testutil::unhex(&alloc::format!("{OUT_POINT_HASH_HEX}{rest}"))
    }

    /// dcrd's `TestOutPointSerialize` read cases
    /// (`wire/msgtx_test.go:717-776`): both valid trees, a negative one,
    /// and a cut at and inside each field, which fails with Go's
    /// `io.EOF` or `io.ErrUnexpectedEOF` for the field it reached.  Only
    /// a complete tree byte reaches the tree check.  The last three rows
    /// are the port's: the negative tree nearest zero, the largest valid
    /// tree, and a negative tree with more bytes behind it, which are not
    /// read.
    #[test]
    fn read_out_point_matches_dcrd() {
        let hash = out_point_hash();
        let negative = |tree| {
            Err(WireError::NegativeTxTree {
                op: "ReadOutPoint",
                tree,
            })
        };
        let cases = [
            (
                "normal regular tree",
                after_hash("0a00000000"),
                Ok(OutPoint {
                    hash,
                    index: 10,
                    tree: TX_TREE_REGULAR,
                }),
            ),
            (
                "normal stake tree",
                after_hash("0800000001"),
                Ok(OutPoint {
                    hash,
                    index: 8,
                    tree: TX_TREE_STAKE,
                }),
            ),
            ("negative tree", after_hash("0800000080"), negative(-128)),
            ("no data", Vec::new(), Err(WireError::Eof)),
            (
                // dcrd slices the hex string, so this is 15 bytes.
                "partial hash",
                dcroxide_testutil::unhex(&OUT_POINT_HASH_HEX[..dcroxide_chainhash::HASH_SIZE - 2]),
                Err(WireError::UnexpectedEof),
            ),
            ("missing index", after_hash(""), Err(WireError::Eof)),
            (
                "partial index",
                after_hash("080000"),
                Err(WireError::UnexpectedEof),
            ),
            ("missing tree", after_hash("08000000"), Err(WireError::Eof)),
            ("tree -1", after_hash("08000000ff"), negative(-1)),
            (
                "tree 127",
                after_hash("080000007f"),
                Ok(OutPoint {
                    hash,
                    index: 8,
                    tree: 127,
                }),
            ),
            (
                "negative tree, then a sequence",
                after_hash("0800000080ffffffff"),
                negative(-128),
            ),
        ];
        for (name, buf, want) in cases {
            let mut r = Cursor::new(&buf);
            assert_eq!(read_out_point(&mut r), want, "{name}");
            if want.is_ok() || matches!(want, Err(WireError::NegativeTxTree { .. })) {
                assert_eq!(r.position(), 37, "{name}: consumed");
            }
        }
        let err = WireError::NegativeTxTree {
            op: "ReadOutPoint",
            tree: -128,
        };
        assert_eq!(err.kind_name(), "ErrNegativeTxTree");
        assert_eq!(
            err.to_string(),
            "ReadOutPoint: negative transaction tree: -128"
        );
    }

    /// dcrd's `TestOutPointSerialize` write cases
    /// (`wire/msgtx_test.go:778-836`).  A negative tree is refused
    /// before anything is written, so a buffer that already holds bytes
    /// keeps exactly those.
    ///
    /// dcrd's three short-write rows cap a `fixedWriter` at 31, 35 and
    /// 36 bytes, so the write fails at the hash, the index and the tree,
    /// and check what the writer holds: nothing, the hash, then the hash
    /// and index (`fixedIO_test.go`'s `Bytes` returns only what was
    /// written as of `6f6cf21b`).  The port writes into a `Vec<u8>`,
    /// which cannot fail short, so the rows reduce to those field
    /// boundaries of the complete encoding.
    #[test]
    fn write_out_point_matches_dcrd() {
        let hash = out_point_hash();
        for (index, tree, want) in [
            (1, TX_TREE_REGULAR, after_hash("0100000000")),
            (2, TX_TREE_STAKE, after_hash("0200000001")),
        ] {
            let mut w = Vec::new();
            assert_eq!(
                write_out_point(&mut w, &OutPoint { hash, index, tree }),
                Ok(())
            );
            assert_eq!(w, want, "tree {tree}");
        }

        for tree in [-1, i8::MIN] {
            let mut w = alloc::vec![0xaa];
            let err = write_out_point(
                &mut w,
                &OutPoint {
                    hash,
                    index: 3,
                    tree,
                },
            )
            .expect_err("negative tree");
            assert_eq!(
                err,
                WireError::NegativeTxTree {
                    op: "WriteOutPoint",
                    tree
                }
            );
            assert_eq!(err.kind_name(), "ErrNegativeTxTree");
            assert_eq!(w, [0xaa], "tree {tree}: nothing written");
            assert_eq!(
                err.to_string(),
                alloc::format!("WriteOutPoint: negative transaction tree: {tree}")
            );
        }

        for (index, written, want) in [
            (4, 0, Vec::new()),
            (5, 32, after_hash("")),
            (6, 36, after_hash("06000000")),
        ] {
            let mut w = Vec::new();
            write_out_point(
                &mut w,
                &OutPoint {
                    hash,
                    index,
                    tree: TX_TREE_REGULAR,
                },
            )
            .expect("valid tree");
            assert_eq!(w[..written], want[..], "index {index}");
        }
    }

    /// A transaction with two inputs, the second one's tree replaced.
    fn two_input_tx(ser_type: TxSerializeType, second_tree: i8) -> MsgTx {
        let mut tx = multi_tx();
        tx.ser_type = ser_type;
        let mut second = tx.tx_in[0].clone();
        second.previous_out_point.tree = second_tree;
        tx.tx_in.push(second);
        tx
    }

    /// Where the second input's tree byte sits: the version field, the
    /// input count and the first input, then the second outpoint's hash
    /// and index.
    const SECOND_TREE_AT: usize = 4 + 1 + PREFIX_TX_IN_SIZE + 32 + 4;

    /// A prefix input naming a negative tree fails the decode in dcrd's
    /// `ReadOutPoint` as soon as its tree byte is read, before the
    /// sequence, in both serializations that carry a prefix.  Every cut
    /// up to that byte still fails with the short read's own error.
    #[test]
    fn negative_input_tree_fails_decode_at_the_tree() {
        for ser_type in [TxSerializeType::Full, TxSerializeType::NoWitness] {
            let mut bytes = two_input_tx(ser_type, TX_TREE_REGULAR).serialize();
            for (byte, tree) in [(0x80, -128), (0xff, -1)] {
                bytes[SECOND_TREE_AT] = byte;
                let want = WireError::NegativeTxTree {
                    op: "ReadOutPoint",
                    tree,
                };
                let mut r = Cursor::new(&bytes);
                assert_eq!(MsgTx::decode(&mut r).err(), Some(want), "{ser_type:?}");
                assert_eq!(r.position(), SECOND_TREE_AT + 1, "{ser_type:?}");
                assert_eq!(
                    MsgTx::from_bytes(&bytes[..=SECOND_TREE_AT]).err(),
                    Some(want),
                    "{ser_type:?}: nothing after the tree is needed"
                );
                for cut in 0..=SECOND_TREE_AT {
                    let err = MsgTx::from_bytes(&bytes[..cut]).expect_err("short");
                    assert!(
                        matches!(err, WireError::Eof | WireError::UnexpectedEof),
                        "{ser_type:?} cut at {cut}: {err:?}"
                    );
                }
            }

            // The largest positive tree is valid and round-trips.
            bytes[SECOND_TREE_AT] = 0x7f;
            let (tx, consumed) = MsgTx::from_bytes(&bytes).expect("tree 127 decodes");
            assert_eq!(consumed, bytes.len());
            assert_eq!(tx.tx_in[1].previous_out_point.tree, 127);
            assert_eq!(tx.serialize(), bytes);
        }
    }

    /// [`MsgTx::encode_into`], dcrd's `BtcEncode`, refuses a negative
    /// input tree in `WriteOutPoint`, holding what dcrd's writer would:
    /// the version field, the input count and the inputs before it.  A
    /// witness-only serialization writes no outpoints and succeeds.  The
    /// infallible forms write the tree's byte, and the hashes stay total.
    #[test]
    fn encode_into_refuses_a_negative_input_tree() {
        for ser_type in [TxSerializeType::Full, TxSerializeType::NoWitness] {
            let tx = two_input_tx(ser_type, -1);
            let mut w = Vec::new();
            assert_eq!(
                tx.encode_into(&mut w),
                Err(WireError::NegativeTxTree {
                    op: "WriteOutPoint",
                    tree: -1
                }),
                "{ser_type:?}"
            );
            let unchecked = tx.serialize();
            assert_eq!(w, unchecked[..4 + 1 + PREFIX_TX_IN_SIZE], "{ser_type:?}");
            assert_eq!(unchecked[SECOND_TREE_AT], 0xff, "{ser_type:?}");

            let mut prefix = Vec::new();
            tx.encode_unchecked(TxSerializeType::NoWitness, &mut prefix);
            assert_eq!(tx.tx_hash(), hash_h(&prefix), "{ser_type:?}");
        }

        let tx = two_input_tx(TxSerializeType::OnlyWitness, -1);
        let mut w = Vec::new();
        assert_eq!(tx.encode_into(&mut w), Ok(()));
        assert_eq!(w, tx.serialize());

        // A valid transaction encodes the same either way.
        let tx = two_input_tx(TxSerializeType::Full, TX_TREE_STAKE);
        let mut w = Vec::new();
        assert_eq!(tx.encode_into(&mut w), Ok(()));
        assert_eq!(w, tx.serialize());
    }
}
