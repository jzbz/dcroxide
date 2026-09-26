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
#[allow(
    clippy::arithmetic_side_effects,
    reason = "size is at most 20 + 11 bytes per value, and a Vec of 16-byte TreasuryValue holds at most isize::MAX / 16 of them; offset counts bytes written into serialized, so offset <= serialized.len()"
)]
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
#[allow(
    clippy::arithmetic_side_effects,
    reason = "offset counts bytes read from data, so offset <= data.len()"
)]
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

    // dcrd sizes the slice from the count outright; the reservation here
    // is bounded by the bytes left (each value takes at least a flag
    // and an amount byte), so a corrupt count reaches the end-of-data
    // error below rather than aborting on the allocation.
    let max_values = (data.len() - offset) / 2;
    let mut values =
        Vec::with_capacity(usize::try_from(num_values).map_or(max_values, |n| n.min(max_values)));
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
            // Go's int64 negation wraps; only a corrupt amount reaches it.
            amount = amount.wrapping_neg();
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
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "a slice of 32-byte hashes spans at most isize::MAX bytes, so 8 + blocks.len() * 32 fits usize"
    )]
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
    // dcrd's `make` panics on a negative count; report the corrupt row
    // instead.
    if count < 0 {
        return Err(format!("negative count {count}"));
    }
    // Bound the reservation by the hashes the row can hold, so a
    // corrupt count reaches the per-index error below rather than
    // aborting on the allocation.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "data.len() >= 8 was checked above"
    )]
    let max_hashes = (data.len() - 8) / 32;
    let mut hashes =
        Vec::with_capacity(usize::try_from(count).map_or(max_hashes, |n| n.min(max_hashes)));
    let mut offset = 8usize;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "offset starts at 8 <= data.len() and advances by 32 only after offset + 32 <= data.len(), so offset + 32 cannot overflow"
    )]
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
        } else if dcroxide_stake::is_treasury_base(stx) {
            // dcrd uses the strict stake.IsTreasuryBase here
            // (treasury.go:424), not the minimal standalone check.
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
                    amount: out.value.wrapping_neg(),
                });
                total_out = total_out.wrapping_add(out.value);
            }
            // Fees are stored as negative amounts, so calculate
            // backwards from the usual in minus out.
            ts.values.push(TreasuryValue {
                typ: TreasuryValueType::Fee,
                amount: total_out.wrapping_sub(stx.tx_in[0].value_in),
            });
        }
    }
    ts
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A corrupt treasury state row whose value count far exceeds its
    /// bytes is reported as corrupt rather than aborting on the
    /// reservation.
    #[test]
    fn huge_treasury_value_count_is_a_decode_error() {
        let num_values = 1u64 << 60;
        let mut row = alloc::vec![0u8; 1 + serialize_size_vlq(num_values)];
        let offset = put_vlq(&mut row, 0);
        put_vlq(&mut row[offset..], num_values);
        assert_eq!(
            deserialize_treasury_state(&row),
            Err("unexpected end of data while reading value flag #0".into())
        );

        // A well-formed row still decodes.
        let ts = TreasuryState {
            balance: 5,
            values: alloc::vec![
                TreasuryValue {
                    typ: TreasuryValueType::TAdd,
                    amount: 7,
                },
                TreasuryValue {
                    typ: TreasuryValueType::TSpend,
                    amount: -3,
                },
            ],
        };
        let row = serialize_treasury_state(&ts).expect("serializes");
        assert_eq!(deserialize_treasury_state(&row), Ok(ts));
    }

    /// Corrupt treasury spend rows with a negative or oversized count
    /// are reported rather than aborting on the reservation.
    #[test]
    fn corrupt_tspend_count_is_a_decode_error() {
        let row = (-1i64).to_le_bytes();
        assert!(deserialize_tspend(&row).is_err());

        let mut row = i64::MAX.to_le_bytes().to_vec();
        row.extend_from_slice(&[0x22; 32]);
        assert_eq!(deserialize_tspend(&row), Err("failed to read idx 1".into()));

        let hashes = [Hash([1; 32]), Hash([2; 32])];
        assert_eq!(
            deserialize_tspend(&serialize_tspend(&hashes)),
            Ok(hashes.to_vec())
        );
    }
}
