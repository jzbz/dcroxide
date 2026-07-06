// SPDX-License-Identifier: ISC

//! The treasury account and treasury spend records from dcrd's
//! `treasury.go`: the per-block treasury state (the balance as of
//! the block plus its yet-to-mature balance-changing values) and the
//! treasury-spend-to-blocks mapping, with dcrd's exact
//! serializations over the treasury buckets.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use dcroxide_chainhash::Hash;
use dcroxide_database::Transaction;
use dcroxide_wire::MsgBlock;

use crate::chaindb::{ChainDbError, TREASURY_BUCKET_NAME, TREASURY_TSPEND_BUCKET_NAME};
use crate::compress::{deserialize_vlq, put_vlq, serialize_size_vlq};

/// The known types of values that modify the treasury balance (dcrd
/// `treasuryValueType`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TreasuryValueType {
    /// A treasurybase subsidy credit.
    TBase,
    /// A treasury add credit.
    TAdd,
    /// A treasury spend fee debit.
    Fee,
    /// A treasury spend debit.
    TSpend,
}

impl TreasuryValueType {
    /// Whether the type debits the treasury account.
    pub fn is_debit(self) -> bool {
        matches!(self, TreasuryValueType::Fee | TreasuryValueType::TSpend)
    }

    fn to_flag(self) -> u64 {
        match self {
            TreasuryValueType::TBase => 0x01,
            TreasuryValueType::TAdd => 0x02,
            TreasuryValueType::Fee => 0x03,
            TreasuryValueType::TSpend => 0x04,
        }
    }

    fn from_flag(flag: u8) -> Option<TreasuryValueType> {
        match flag & 0x07 {
            0x01 => Some(TreasuryValueType::TBase),
            0x02 => Some(TreasuryValueType::TAdd),
            0x03 => Some(TreasuryValueType::Fee),
            0x04 => Some(TreasuryValueType::TSpend),
            _ => None,
        }
    }
}

/// A single balance-changing value; debits carry negative amounts
/// (dcrd `treasuryValue`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TreasuryValue {
    /// The value type.
    pub typ: TreasuryValueType,
    /// The amount; negative for treasury spends and their fees.
    pub amount: i64,
}

/// The treasury balance as of a block along with the yet-to-mature
/// values included in the block itself (dcrd `treasuryState`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TreasuryState {
    /// The treasury balance as of this block.
    pub balance: i64,
    /// The balance-changing values in block order.
    pub values: Vec<TreasuryValue>,
}

fn abs_i64(v: i64) -> u64 {
    v.unsigned_abs()
}

/// Serialize a treasury state row (dcrd `serializeTreasuryState`).
pub fn serialize_treasury_state(ts: &TreasuryState) -> Result<Vec<u8>, String> {
    if ts.balance < 0 {
        return Err(format!("invalid treasury balance: {}", ts.balance));
    }

    let mut size =
        serialize_size_vlq(ts.balance as u64) + serialize_size_vlq(ts.values.len() as u64);
    for value in &ts.values {
        // Prevent serialization of a wrongly-signed value; zero is
        // allowed even in debit types.
        let want_negative = value.typ.is_debit();
        let got_negative = value.amount < 0;
        if value.amount != 0 && want_negative != got_negative {
            return Err(format!(
                "incorrect negative value for type {:?}: {}",
                value.typ, value.amount
            ));
        }
        size += 1; // The flag is currently a one byte VLQ.
        size += serialize_size_vlq(abs_i64(value.amount));
    }

    let mut serialized = alloc::vec![0u8; size];
    let mut offset = put_vlq(&mut serialized, ts.balance as u64);
    offset += put_vlq(&mut serialized[offset..], ts.values.len() as u64);
    for value in &ts.values {
        offset += put_vlq(&mut serialized[offset..], value.typ.to_flag());
        offset += put_vlq(&mut serialized[offset..], abs_i64(value.amount));
    }
    debug_assert_eq!(offset, serialized.len());
    Ok(serialized)
}

/// Deserialize a treasury state row (dcrd
/// `deserializeTreasuryState`).
pub fn deserialize_treasury_state(data: &[u8]) -> Result<TreasuryState, String> {
    let (balance, mut offset) = deserialize_vlq(data);
    if offset == 0 {
        return Err("unexpected end of data while reading treasury balance".into());
    }
    let (num_values, bytes_read) = deserialize_vlq(&data[offset..]);
    if bytes_read == 0 {
        return Err("unexpected end of data while reading number of value entries".into());
    }
    offset += bytes_read;

    let mut values = Vec::with_capacity(num_values as usize);
    for i in 0..num_values {
        let (flag, bytes_read) = deserialize_vlq(&data[offset..]);
        offset += bytes_read;
        if bytes_read == 0 {
            return Err(format!(
                "unexpected end of data while reading value flag #{i}"
            ));
        }
        let (value, bytes_read) = deserialize_vlq(&data[offset..]);
        offset += bytes_read;
        if bytes_read == 0 {
            return Err(format!(
                "unexpected end of data while reading value amount #{i}"
            ));
        }
        let typ = TreasuryValueType::from_flag(flag as u8)
            .ok_or_else(|| format!("unknown treasury value type flag {flag}"))?;
        let mut amount = value as i64;
        if typ.is_debit() {
            amount = -amount;
        }
        values.push(TreasuryValue { typ, amount });
    }
    Ok(TreasuryState {
        balance: balance as i64,
        values,
    })
}

/// Serialize a treasury spend blocks row (dcrd `serializeTSpend`):
/// a little-endian count followed by the block hashes.
pub fn serialize_tspend(blocks: &[Hash]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + blocks.len() * 32);
    out.extend_from_slice(&(blocks.len() as i64).to_le_bytes());
    for hash in blocks {
        out.extend_from_slice(&hash.0);
    }
    out
}

/// Deserialize a treasury spend blocks row (dcrd
/// `deserializeTSpend`).
pub fn deserialize_tspend(data: &[u8]) -> Result<Vec<Hash>, String> {
    if data.len() < 8 {
        return Err("failed to read count".into());
    }
    let count = i64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    let mut hashes = Vec::with_capacity(count as usize);
    let mut offset = 8usize;
    for i in 0..count {
        if offset + 32 > data.len() {
            return Err(format!("failed to read idx {i}"));
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&data[offset..offset + 32]);
        hashes.push(Hash(h));
        offset += 32;
    }
    Ok(hashes)
}

/// Store a treasury state row (dcrd `dbPutTreasuryBalance`).
pub fn db_put_treasury_balance(
    tx: &Transaction,
    hash: &Hash,
    ts: &TreasuryState,
) -> Result<(), ChainDbError> {
    let serialized = serialize_treasury_state(ts).map_err(ChainDbError::Corrupt)?;
    let meta = tx.metadata();
    let bucket = meta
        .bucket(TREASURY_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing treasury bucket".into()))?;
    Ok(bucket.put(&hash.0, &serialized)?)
}

/// Fetch a treasury state row when present (dcrd
/// `dbFetchTreasuryBalance`; a missing row is `None` rather than
/// dcrd's typed error).
pub fn db_fetch_treasury_balance(
    tx: &Transaction,
    hash: &Hash,
) -> Result<Option<TreasuryState>, ChainDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(TREASURY_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing treasury bucket".into()))?;
    match bucket.get(&hash.0) {
        None => Ok(None),
        Some(v) => Ok(Some(
            deserialize_treasury_state(&v).map_err(ChainDbError::Corrupt)?,
        )),
    }
}

/// Store a treasury spend blocks row (dcrd `dbPutTSpend`).
pub fn db_put_tspend(
    tx: &Transaction,
    tx_hash: &Hash,
    blocks: &[Hash],
) -> Result<(), ChainDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(TREASURY_TSPEND_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing tspend bucket".into()))?;
    Ok(bucket.put(&tx_hash.0, &serialize_tspend(blocks))?)
}

/// Fetch a treasury spend blocks row when present (dcrd
/// `dbFetchTSpend`; a missing row is `None`).
pub fn db_fetch_tspend(
    tx: &Transaction,
    tx_hash: &Hash,
) -> Result<Option<Vec<Hash>>, ChainDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(TREASURY_TSPEND_BUCKET_NAME)
        .ok_or_else(|| ChainDbError::Corrupt("missing tspend bucket".into()))?;
    match bucket.get(&tx_hash.0) {
        None => Ok(None),
        Some(v) => Ok(Some(deserialize_tspend(&v).map_err(ChainDbError::Corrupt)?)),
    }
}

/// Build the treasury state for a block: the given balance plus the
/// block's treasurybase, add, spend, and spend fee values in block
/// order (the scan inside dcrd's method form of
/// `dbPutTreasuryBalance`).
pub fn treasury_state_for_block(block: &MsgBlock, balance: i64) -> TreasuryState {
    let mut ts = TreasuryState {
        balance,
        values: Vec::new(),
    };
    for stx in &block.stransactions {
        if dcroxide_stake::is_tadd(stx) {
            // The amount lives in the first output; the second, when
            // present, is change and is ignored.
            ts.values.push(TreasuryValue {
                typ: TreasuryValueType::TAdd,
                amount: stx.tx_out[0].value,
            });
        } else if dcroxide_standalone::is_treasury_base(stx) {
            ts.values.push(TreasuryValue {
                typ: TreasuryValueType::TBase,
                amount: stx.tx_out[0].value,
            });
        } else if dcroxide_stake::is_tspend(stx) {
            // Skip the first output since it is the OP_RETURN.
            let mut total_out = 0i64;
            for out in &stx.tx_out[1..] {
                ts.values.push(TreasuryValue {
                    typ: TreasuryValueType::TSpend,
                    amount: -out.value,
                });
                total_out += out.value;
            }
            // Fees are stored as negative amounts, so calculate
            // backwards from the usual in minus out.
            ts.values.push(TreasuryValue {
                typ: TreasuryValueType::Fee,
                amount: total_out - stx.tx_in[0].value_in,
            });
        }
    }
    ts
}
