// SPDX-License-Identifier: ISC
//! UTXO set serialization: outpoint keys, entry bytes, and the set
//! state (dcrd internal/blockchain `utxoio.go`, plus
//! `readDeserializeSizeOfMinimalOutputs` from `chainio.go`).
//!
//! The serialized entry format is:
//!
//! ```text
//! <block height><block index><flags><compressed txout>[<ticket min outs>]
//! ```
//!
//! where the height, index, and flags are VLQs and the ticket minimal
//! outputs tail is present exactly when the entry is the submission
//! output of a ticket purchase.

use alloc::vec;
use alloc::vec::Vec;

use dcroxide_chainhash::{HASH_SIZE, Hash};
use dcroxide_wire::OutPoint;

use crate::compress::{
    compressed_tx_out_size, decode_compressed_tx_out, deserialize_vlq, put_compressed_tx_out,
    put_vlq, serialize_size_vlq,
};
use crate::error::{Error, deserialize_error};
use crate::utxoentry::{UtxoEntry, is_ticket_submission_output};

/// The key prefix for the UTXO set key space: key set ID 3, version 3
/// (dcrd `utxoPrefixUtxoSet`).
pub const UTXO_PREFIX_UTXO_SET: [u8; 2] = [3, 3];

/// The key prefix for the UTXO state key space: key set ID 2, version 1
/// (dcrd `utxoPrefixUtxoState`).
pub const UTXO_PREFIX_UTXO_STATE: [u8; 2] = [2, 1];

/// The key prefix for the database info key space: key set ID 1,
/// unversioned (dcrd `utxoPrefixDbInfo`).
pub const UTXO_PREFIX_DB_INFO: [u8; 2] = [1, 0];

/// The key for an outpoint in the UTXO set (dcrd `outpointKey`):
/// prefix || hash || VLQ(tree) || VLQ(index).
pub fn outpoint_key(outpoint: &OutPoint) -> Vec<u8> {
    let tree = outpoint.tree as u64;
    let idx = u64::from(outpoint.index);
    let mut key = vec![
        0u8;
        UTXO_PREFIX_UTXO_SET.len()
            + HASH_SIZE
            + serialize_size_vlq(tree)
            + serialize_size_vlq(idx)
    ];
    key[..2].copy_from_slice(&UTXO_PREFIX_UTXO_SET);
    let mut offset = UTXO_PREFIX_UTXO_SET.len();
    key[offset..offset + HASH_SIZE].copy_from_slice(&outpoint.hash.0);
    offset += HASH_SIZE;
    offset += put_vlq(&mut key[offset..], tree);
    put_vlq(&mut key[offset..], idx);
    key
}

/// Decode an outpoint key back into an outpoint (dcrd
/// `decodeOutpointKey`).
pub fn decode_outpoint_key(serialized: &[u8]) -> Result<OutPoint, Error> {
    if UTXO_PREFIX_UTXO_SET.len() + HASH_SIZE >= serialized.len() {
        return Err(deserialize_error(
            "unexpected length for serialized outpoint key",
        ));
    }

    // Deserialize the hash.
    let mut offset = UTXO_PREFIX_UTXO_SET.len();
    let mut hash = [0u8; HASH_SIZE];
    hash.copy_from_slice(&serialized[offset..offset + HASH_SIZE]);
    offset += HASH_SIZE;

    // Deserialize the tree.
    let (tree, bytes_read) = deserialize_vlq(&serialized[offset..]);
    offset += bytes_read;
    if offset >= serialized.len() {
        return Err(deserialize_error("unexpected end of data after tree"));
    }

    // Deserialize the index.
    let (idx, _) = deserialize_vlq(&serialized[offset..]);

    Ok(OutPoint {
        hash: Hash(hash),
        index: idx as u32,
        tree: tree as i8,
    })
}

/// Serialize a UTXO entry for storage; a spent entry serializes to
/// `None` (dcrd `serializeUtxoEntry`, which returns nil).
pub fn serialize_utxo_entry(entry: &UtxoEntry) -> Option<Vec<u8>> {
    // Spent outputs have no serialization.
    if entry.is_spent() {
        return None;
    }

    const HAS_AMOUNT: bool = true;
    // dcrd re-encodes the serialized flags from the entry components
    // via encodeFlags; the packed entry layout is identical, so this
    // reconstructs the same byte.
    let mut flags = entry.transaction_type() << 2;
    if entry.is_coin_base() {
        flags |= 1 << 0;
    }
    if entry.has_expiry() {
        flags |= 1 << 1;
    }

    // Calculate the size needed to serialize the entry.
    let mut size = serialize_size_vlq(u64::from(entry.block_height))
        + serialize_size_vlq(u64::from(entry.block_index))
        + serialize_size_vlq(u64::from(flags))
        + compressed_tx_out_size(
            entry.amount as u64,
            entry.script_version,
            &entry.pk_script,
            HAS_AMOUNT,
        );
    if let Some(min_outs) = &entry.ticket_min_outs {
        size += min_outs.len();
    }

    // Serialize the entry.
    let mut serialized = vec![0u8; size];
    let mut offset = put_vlq(&mut serialized, u64::from(entry.block_height));
    offset += put_vlq(&mut serialized[offset..], u64::from(entry.block_index));
    offset += put_vlq(&mut serialized[offset..], u64::from(flags));
    offset += put_compressed_tx_out(
        &mut serialized[offset..],
        entry.amount as u64,
        entry.script_version,
        &entry.pk_script,
        HAS_AMOUNT,
    );
    if let Some(min_outs) = &entry.ticket_min_outs {
        serialized[offset..].copy_from_slice(min_outs);
    }
    Some(serialized)
}

/// The number of bytes the serialized minimal outputs at the front of
/// the data occupy (dcrd chainio.go
/// `readDeserializeSizeOfMinimalOutputs`).
pub fn read_deserialize_size_of_minimal_outputs(serialized: &[u8]) -> Result<usize, Error> {
    let (num_outputs, mut offset) = deserialize_vlq(serialized);
    if offset == 0 {
        return Err(deserialize_error(
            "unexpected end of data during decoding (num outputs)",
        ));
    }

    for _ in 0..num_outputs {
        // Amount.
        let (_, bytes_read) = deserialize_vlq(&serialized[offset..]);
        if bytes_read == 0 {
            return Err(deserialize_error(
                "unexpected end of data during decoding (output amount)",
            ));
        }
        offset += bytes_read;

        // Script version.
        let (_, bytes_read) = deserialize_vlq(&serialized[offset..]);
        if bytes_read == 0 {
            return Err(deserialize_error(
                "unexpected end of data during decoding (output script version)",
            ));
        }
        offset += bytes_read;

        // Script size and script.
        let (script_size, bytes_read) = deserialize_vlq(&serialized[offset..]);
        if bytes_read == 0 {
            return Err(deserialize_error(
                "unexpected end of data during decoding (output script size)",
            ));
        }
        offset += bytes_read;
        if (serialized[offset..].len() as u64) < script_size {
            return Err(deserialize_error(
                "unexpected end of data during decoding (output script)",
            ));
        }
        offset += script_size as usize;
    }

    Ok(offset)
}

/// Decode a UTXO entry from its serialized form; the output index of
/// the outpoint the entry belongs to determines whether a ticket
/// minimal outputs tail is expected (dcrd `deserializeUtxoEntry`).
pub fn deserialize_utxo_entry(serialized: &[u8], tx_out_index: u32) -> Result<UtxoEntry, Error> {
    // Deserialize the block height.
    let (block_height, bytes_read) = deserialize_vlq(serialized);
    let mut offset = bytes_read;
    if offset >= serialized.len() {
        return Err(deserialize_error("unexpected end of data after height"));
    }

    // Deserialize the block index.
    let (block_index, bytes_read) = deserialize_vlq(&serialized[offset..]);
    offset += bytes_read;
    if offset >= serialized.len() {
        return Err(deserialize_error("unexpected end of data after index"));
    }

    // Deserialize the flags.
    let (flags, bytes_read) = deserialize_vlq(&serialized[offset..]);
    offset += bytes_read;
    if offset >= serialized.len() {
        return Err(deserialize_error("unexpected end of data after flags"));
    }
    let (is_coin_base, has_expiry, tx_type_bits) = crate::compress::decode_flags(flags as u8);

    // Decode the compressed unspent transaction output.
    let (amount, script_version, script, bytes_read) =
        decode_compressed_tx_out(&serialized[offset..], true)
            .map_err(|e| deserialize_error(alloc::format!("unable to decode utxo: {e}")))?;
    offset += bytes_read;

    let mut entry = UtxoEntry {
        amount,
        pk_script: script,
        ticket_min_outs: None,
        block_height: block_height as u32,
        block_index: block_index as u32,
        script_version,
        state: 0,
        packed_flags: {
            // Same layout as the serialized flags; re-encode via the
            // entry flag encoder to mirror dcrd.
            let mut b = tx_type_bits << 2;
            if is_coin_base {
                b |= 1 << 0;
            }
            if has_expiry {
                b |= 1 << 1;
            }
            b
        },
    };

    // Copy the minimal outputs tail when this is a ticket submission
    // output.
    if is_ticket_submission_output(tx_type_bits, tx_out_index) {
        let sz = read_deserialize_size_of_minimal_outputs(&serialized[offset..]).map_err(|e| {
            deserialize_error(alloc::format!("unable to decode ticket outputs: {e}"))
        })?;
        entry.ticket_min_outs = Some(serialized[offset..offset + sz].to_vec());
    }

    Ok(entry)
}

/// The UTXO set state: the block through which the set has been fully
/// flushed (dcrd `UtxoSetState`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoSetState {
    /// The height of the last fully-flushed block.
    pub last_flush_height: u32,
    /// The hash of the last fully-flushed block.
    pub last_flush_hash: Hash,
}

/// Serialize the UTXO set state (dcrd `serializeUtxoSetState`):
/// VLQ(height) || hash.
pub fn serialize_utxo_set_state(state: &UtxoSetState) -> Vec<u8> {
    let size = serialize_size_vlq(u64::from(state.last_flush_height)) + HASH_SIZE;
    let mut serialized = vec![0u8; size];
    let offset = put_vlq(&mut serialized, u64::from(state.last_flush_height));
    serialized[offset..].copy_from_slice(&state.last_flush_hash.0);
    serialized
}

/// Deserialize the UTXO set state (dcrd `deserializeUtxoSetState`).
pub fn deserialize_utxo_set_state(serialized: &[u8]) -> Result<UtxoSetState, Error> {
    // Deserialize the block height.
    let (block_height, bytes_read) = deserialize_vlq(serialized);
    let offset = bytes_read;
    if offset >= serialized.len() {
        return Err(deserialize_error("unexpected end of data after height"));
    }

    // Deserialize the hash.
    if serialized[offset..].len() != HASH_SIZE {
        return Err(deserialize_error("unexpected length for serialized hash"));
    }
    let mut hash = [0u8; HASH_SIZE];
    hash.copy_from_slice(&serialized[offset..offset + HASH_SIZE]);

    Ok(UtxoSetState {
        last_flush_height: block_height as u32,
        last_flush_hash: Hash(hash),
    })
}
