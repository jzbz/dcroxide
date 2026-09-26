// SPDX-License-Identifier: ISC
//! Chain persistence serialization formats (dcrd internal/blockchain
//! `chainio.go`): ticket minimal outputs, block index entries, the
//! spend journal, header commitments, and the best chain state.
//!
//! Only the byte formats live here; the database plumbing that reads
//! and writes them belongs to the chain engine.

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use dcroxide_chainhash::{HASH_SIZE, Hash};
use dcroxide_stake::MinimalOutput;
use dcroxide_uint256::Uint256;
use dcroxide_wire::{BlockHeader, MAX_BLOCK_HEADER_PAYLOAD, MsgTx};

use crate::compress::{
    compress_tx_out_amount, compressed_tx_out_size, decode_compressed_tx_out, decode_flags,
    decompress_tx_out_amount, deserialize_vlq, put_compressed_tx_out, put_vlq, serialize_size_vlq,
};
use crate::error::{Error, deserialize_error};
use crate::utxoio::read_deserialize_size_of_minimal_outputs;

/// The size of a serialized block header (dcrd `blockHdrSize`).
const BLOCK_HDR_SIZE: usize = MAX_BLOCK_HEADER_PAYLOAD;

// ----------------------------------------------------------------------
// Ticket minimal outputs.
// ----------------------------------------------------------------------

/// The number of bytes the transaction's outputs take when serialized
/// as minimal outputs (dcrd `serializeSizeForMinimalOutputs`).
#[allow(
    clippy::arithmetic_side_effects,
    reason = "each output adds at most 30 VLQ bytes, less than its own in-memory size, plus \
              its script's allocated length, so the sum stays far below usize::MAX"
)]
pub fn serialize_size_for_minimal_outputs(tx: &MsgTx) -> usize {
    let mut sz = serialize_size_vlq(tx.tx_out.len() as u64);
    for out in &tx.tx_out {
        sz += serialize_size_vlq(compress_tx_out_amount(out.value as u64));
        sz += serialize_size_vlq(u64::from(out.version));
        sz += serialize_size_vlq(out.pk_script.len() as u64);
        sz += out.pk_script.len();
    }
    sz
}

/// Serialize the transaction's outputs as minimal outputs into the
/// target, which must be large enough per
/// [`serialize_size_for_minimal_outputs`]; returns the bytes written
/// (dcrd `putTxToMinimalOutputs`).
#[allow(
    clippy::arithmetic_side_effects,
    reason = "offset <= target.len() after every step, since each put_vlq and copy writes \
              inside target[offset..], and adding an in-memory script length to it cannot \
              overflow usize"
)]
pub fn put_tx_to_minimal_outputs(target: &mut [u8], tx: &MsgTx) -> usize {
    let mut offset = put_vlq(target, tx.tx_out.len() as u64);
    for out in &tx.tx_out {
        offset += put_vlq(
            &mut target[offset..],
            compress_tx_out_amount(out.value as u64),
        );
        offset += put_vlq(&mut target[offset..], u64::from(out.version));
        offset += put_vlq(&mut target[offset..], out.pk_script.len() as u64);
        target[offset..offset + out.pk_script.len()].copy_from_slice(&out.pk_script);
        offset += out.pk_script.len();
    }
    offset
}

/// Deserialize minimal outputs from the front of the data, returning
/// them along with the bytes consumed (dcrd
/// `deserializeToMinimalOutputs`).  Like dcrd, the input must be well
/// formed.  Validating it first with
/// [`read_deserialize_size_of_minimal_outputs`] does not make every
/// input safe: that check, like dcrd's
/// `readDeserializeSizeOfMinimalOutputs`, reads an output count of 2^63
/// or more as no outputs, so such a count passes it and this function
/// then panics allocating the vector (capacity overflow).  dcrd panics
/// at the same point, in `make` with a negative length, so the panic is
/// kept for parity.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "offset <= serialized.len(): it grows only by the bytes just consumed from \
              serialized[offset..]"
)]
pub fn deserialize_to_minimal_outputs(serialized: &[u8]) -> (Vec<MinimalOutput>, usize) {
    let (num_outputs, mut offset) = deserialize_vlq(serialized);
    let mut min_outs = Vec::with_capacity(num_outputs as usize);
    for _ in 0..num_outputs {
        let (amount_comp, bytes_read) = deserialize_vlq(&serialized[offset..]);
        let amount = decompress_tx_out_amount(amount_comp);
        offset += bytes_read;
        let (version, bytes_read) = deserialize_vlq(&serialized[offset..]);
        offset += bytes_read;
        let (script_size, bytes_read) = deserialize_vlq(&serialized[offset..]);
        offset += bytes_read;
        let pk_script = serialized[offset..offset.wrapping_add(script_size as usize)].to_vec();
        offset += script_size as usize;
        min_outs.push(MinimalOutput {
            value: amount as i64,
            version: version as u16,
            pk_script,
        });
    }
    (min_outs, offset)
}

// ----------------------------------------------------------------------
// Block index entries.
// ----------------------------------------------------------------------

/// A block index entry: the header plus status and vote metadata (dcrd
/// `blockIndexEntry`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockIndexEntry {
    /// The block header.
    pub header: BlockHeader,
    /// The block status byte (dcrd `blockStatus`; the chain engine
    /// defines the flag values).
    pub status: u8,
    /// The (vote version, vote bits) pairs for the votes in the block.
    pub vote_info: Vec<(u32, u16)>,
}

/// The key for an entry in the block index bucket: big-endian height
/// followed by the block hash, so entries iterate by height (dcrd
/// `blockIndexKey`).
pub fn block_index_key(block_hash: &Hash, block_height: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(HASH_SIZE + 4);
    key.extend_from_slice(&block_height.to_be_bytes());
    key.extend_from_slice(&block_hash.0);
    key
}

/// The serialized size of the block index entry (dcrd
/// `blockIndexEntrySerializeSize`).
#[allow(
    clippy::arithmetic_side_effects,
    reason = "each (u32, u16) vote adds at most 5 + 3 VLQ bytes, no more than the 8 bytes it \
              occupies in memory, and the rest is BLOCK_HDR_SIZE + 1 + a VLQ of at most 10 \
              bytes, so the sum stays far below usize::MAX"
)]
pub fn block_index_entry_serialize_size(entry: &BlockIndexEntry) -> usize {
    let mut vote_info_size = 0;
    for (version, bits) in &entry.vote_info {
        vote_info_size +=
            serialize_size_vlq(u64::from(*version)) + serialize_size_vlq(u64::from(*bits));
    }
    BLOCK_HDR_SIZE + 1 + serialize_size_vlq(entry.vote_info.len() as u64) + vote_info_size
}

/// Serialize the block index entry (dcrd `serializeBlockIndexEntry`):
/// header || status || VLQ vote count || VLQ (version, bits) pairs.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "offset <= serialized.len(): it starts at BLOCK_HDR_SIZE and grows only by the \
              status byte and the bytes each put_vlq writes inside serialized[offset..]"
)]
pub fn serialize_block_index_entry(entry: &BlockIndexEntry) -> Vec<u8> {
    let mut serialized = vec![0u8; block_index_entry_serialize_size(entry)];
    serialized[..BLOCK_HDR_SIZE].copy_from_slice(&entry.header.serialize());
    let mut offset = BLOCK_HDR_SIZE;
    serialized[offset] = entry.status;
    offset += 1;
    offset += put_vlq(&mut serialized[offset..], entry.vote_info.len() as u64);
    for (version, bits) in &entry.vote_info {
        offset += put_vlq(&mut serialized[offset..], u64::from(*version));
        offset += put_vlq(&mut serialized[offset..], u64::from(*bits));
    }
    debug_assert_eq!(offset, serialized.len());
    serialized
}

/// Decode a block index entry, returning it and the bytes consumed
/// (dcrd `decodeBlockIndexEntry`).
#[allow(
    clippy::arithmetic_side_effects,
    reason = "offset <= serialized.len(): it starts at BLOCK_HDR_SIZE, checked against the \
              length above, and grows only by the bytes consumed from serialized[offset..]"
)]
pub fn decode_block_index_entry(serialized: &[u8]) -> Result<(BlockIndexEntry, usize), Error> {
    if serialized.len() < BLOCK_HDR_SIZE {
        return Err(deserialize_error(
            "unexpected end of data while reading block header",
        ));
    }
    let (header, _) = BlockHeader::from_bytes(&serialized[..BLOCK_HDR_SIZE])
        .map_err(|e| deserialize_error(format!("bad block header: {e:?}")))?;
    let mut offset = BLOCK_HDR_SIZE;

    if offset + 1 > serialized.len() {
        return Err(deserialize_error(
            "unexpected end of data while reading status",
        ));
    }
    let status = serialized[offset];
    offset += 1;

    let (num_votes, bytes_read) = deserialize_vlq(&serialized[offset..]);
    if bytes_read == 0 {
        return Err(deserialize_error(
            "unexpected end of data while reading num votes",
        ));
    }
    offset += bytes_read;
    let mut votes = Vec::with_capacity(num_votes as usize);
    for i in 0..num_votes {
        let (version, bytes_read) = deserialize_vlq(&serialized[offset..]);
        if bytes_read == 0 {
            return Err(deserialize_error(format!(
                "unexpected end of data while reading vote #{i} version"
            )));
        }
        offset += bytes_read;
        let (vote_bits, bytes_read) = deserialize_vlq(&serialized[offset..]);
        if bytes_read == 0 {
            return Err(deserialize_error(format!(
                "unexpected end of data while reading vote #{i} bits"
            )));
        }
        offset += bytes_read;
        votes.push((version as u32, vote_bits as u16));
    }

    Ok((
        BlockIndexEntry {
            header,
            status,
            vote_info: votes,
        },
        offset,
    ))
}

// ----------------------------------------------------------------------
// Spend journal.
// ----------------------------------------------------------------------

/// A spent transaction output as stored in the spend journal (dcrd
/// `spentTxOut`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpentTxOut {
    /// The amount of the output (carried by the spending input on
    /// disk, not the journal entry itself).
    pub amount: i64,
    /// The public key script of the output.
    pub pk_script: Vec<u8>,
    /// The serialized ticket minimal outputs, present only for ticket
    /// submission outputs.
    pub ticket_min_outs: Option<Vec<u8>>,
    /// The height of the block containing the creating transaction.
    pub block_height: u32,
    /// The index of the creating transaction within its block.
    pub block_index: u32,
    /// The script version of the output.
    pub script_version: u16,
    /// The packed txout flags (same layout as the UTXO flags byte).
    pub packed_flags: u8,
}

impl SpentTxOut {
    /// Whether the output was from a coinbase (dcrd `IsCoinBase`).
    pub fn is_coin_base(&self) -> bool {
        self.packed_flags & 0x01 != 0
    }

    /// Whether the containing transaction has an expiry.
    pub fn has_expiry(&self) -> bool {
        self.packed_flags & 0x02 != 0
    }

    /// The raw stake transaction type bits of the containing
    /// transaction.
    pub fn transaction_type(&self) -> u8 {
        (self.packed_flags & 0x3c) >> 2
    }
}

/// The flags byte dcrd writes for a spent output: `encodeFlags` fed
/// from the accessors, which reassembles exactly the low six bits of
/// the packed byte.
///
/// `TransactionType` casts the extracted bits to `stake.TxType`
/// unchecked (`chainio.go:562-565`), so an undefined type value keeps
/// its bit pattern, and `encodeFlags` shifts inside a `uint8`
/// (`compress.go:670,690-692`), so bits 6-7 are dropped rather than
/// preserved.  With the bitmask at 0x3c and the two flag bits at 0x01
/// and 0x02, the round trip is `packed & 0x3f` for all 256 inputs.
fn encoded_flags(stxo: &SpentTxOut) -> u8 {
    stxo.packed_flags & 0x3f
}

/// The serialized size of the spent output (dcrd
/// `spentTxOutSerializeSize`).
#[allow(
    clippy::arithmetic_side_effects,
    reason = "a one-byte flags VLQ, a compressed txout of at most 13 bytes plus the in-memory \
              script length, and the in-memory min_outs length, so the sum stays far below \
              usize::MAX"
)]
pub fn spent_tx_out_serialize_size(stxo: &SpentTxOut) -> usize {
    let flags = encoded_flags(stxo);
    let mut size = serialize_size_vlq(u64::from(flags));
    const HAS_AMOUNT: bool = false;
    size += compressed_tx_out_size(
        stxo.amount as u64,
        stxo.script_version,
        &stxo.pk_script,
        HAS_AMOUNT,
    );
    if let Some(min_outs) = &stxo.ticket_min_outs {
        size += min_outs.len();
    }
    size
}

/// Serialize the spent output into the target (dcrd `putSpentTxOut`);
/// returns the bytes written.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "offset <= target.len(): each put writes inside target[offset..], and adding the \
              in-memory min_outs length to it cannot overflow usize"
)]
pub fn put_spent_tx_out(target: &mut [u8], stxo: &SpentTxOut) -> usize {
    let flags = encoded_flags(stxo);
    let mut offset = put_vlq(target, u64::from(flags));
    const HAS_AMOUNT: bool = false;
    offset += put_compressed_tx_out(
        &mut target[offset..],
        0,
        stxo.script_version,
        &stxo.pk_script,
        HAS_AMOUNT,
    );
    if let Some(min_outs) = &stxo.ticket_min_outs {
        target[offset..offset + min_outs.len()].copy_from_slice(min_outs);
        offset += min_outs.len();
    }
    offset
}

/// Decode a spent output from the front of the serialized data (dcrd
/// `decodeSpentTxOut`); the amount, height, index, and spent output
/// index come from the spending input, exactly as dcrd populates them.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "offset <= serialized.len(): it grows only by the bytes decode_compressed_tx_out \
              and read_deserialize_size_of_minimal_outputs report consuming from \
              serialized[offset..]"
)]
pub fn decode_spent_tx_out(
    serialized: &[u8],
    amount: i64,
    height: u32,
    index: u32,
    tx_out_index: u32,
) -> Result<(SpentTxOut, usize), Error> {
    // Deserialize the flags.
    let (flags, bytes_read) = deserialize_vlq(serialized);
    let mut offset = bytes_read;
    if offset >= serialized.len() {
        return Err(deserialize_error("unexpected end of data after flags"));
    }

    // Decode the compressed txout (no amount is serialized).
    let (_, script_version, script, bytes_read) =
        decode_compressed_tx_out(&serialized[offset..], false)
            .map_err(|e| deserialize_error(format!("unable to decode txout: {e}")))?;
    offset += bytes_read;

    let (_, _, tx_type_bits) = decode_flags(flags as u8);
    let mut stxo = SpentTxOut {
        amount,
        pk_script: script,
        ticket_min_outs: None,
        block_height: height,
        block_index: index,
        script_version,
        packed_flags: flags as u8,
    };

    // Copy the minimal outputs tail for ticket submission outputs.
    if crate::utxoentry::is_ticket_submission_output(tx_type_bits, tx_out_index) {
        let sz = read_deserialize_size_of_minimal_outputs(&serialized[offset..])
            .map_err(|e| deserialize_error(format!("unable to decode ticket outputs: {e}")))?;
        stxo.ticket_min_outs = Some(serialized[offset..offset + sz].to_vec());
        offset += sz;
    }

    Ok((stxo, offset))
}

/// Serialize a spend journal entry: all stxos serialized in reverse
/// order (dcrd `serializeSpendJournalEntry`); empty input yields
/// `None` (dcrd returns nil).
pub fn serialize_spend_journal_entry(stxos: &[SpentTxOut]) -> Option<Vec<u8>> {
    if stxos.is_empty() {
        return None;
    }

    let size: usize = stxos.iter().map(spent_tx_out_serialize_size).sum();
    let mut serialized = vec![0u8; size];
    let mut offset = 0;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "offset <= size: each put_spent_tx_out writes inside serialized[offset..]"
    )]
    for stxo in stxos.iter().rev() {
        offset += put_spent_tx_out(&mut serialized[offset..], stxo);
    }
    debug_assert_eq!(offset, size);
    Some(serialized)
}

/// Decode a spend journal entry against the transactions it spends for
/// (dcrd `deserializeSpendJournalEntry`): every input of every
/// non-vote transaction gets an stxo; votes get exactly one (the
/// ticket input; the stakebase carries no stxo).  The transactions may
/// be owned or borrowed, so a caller can lend a block's own.
pub fn deserialize_spend_journal_entry<T: core::borrow::Borrow<MsgTx>>(
    serialized: &[u8],
    txns: &[T],
) -> Result<Vec<SpentTxOut>, Error> {
    // Calculate the total number of stxos.
    let mut num_stxos = 0usize;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "one per input (or per vote) of the passed in-memory transactions, so at most \
                  the sum of their tx_in lengths, far below usize::MAX"
    )]
    for tx in txns {
        let tx = tx.borrow();
        if dcroxide_stake::is_ssgen(tx) {
            num_stxos += 1;
            continue;
        }
        num_stxos += tx.tx_in.len();
    }

    // An empty serialization is only valid when there are no stxos.
    if serialized.is_empty() {
        if num_stxos != 0 {
            return Err(deserialize_error(format!(
                "mismatched spend journal serialization - no serialization for \
                 expected {num_stxos} stxos"
            )));
        }
        return Ok(Vec::new());
    }

    // Loop backwards through all transactions so everything is read in
    // reverse order to match the serialization order.
    let mut stxos: Vec<SpentTxOut> = vec![SpentTxOut::default(); num_stxos];
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "vec! just allocated num_stxos elements, so 0 <= num_stxos <= isize::MAX and \
                  the difference is at least -1"
    )]
    let mut stxo_idx = num_stxos as isize - 1;
    let mut offset = 0usize;
    for tx in txns.iter().rev() {
        let tx = tx.borrow();
        let is_vote = dcroxide_stake::is_ssgen(tx);
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "the stxos index just before the decrement succeeded, so stxo_idx >= 0 \
                      there; offset <= serialized.len() since n is the bytes \
                      decode_spent_tx_out consumed from serialized[offset..]"
        )]
        for (tx_in_idx, tx_in) in tx.tx_in.iter().enumerate().rev() {
            if tx_in_idx == 0 && is_vote {
                continue;
            }
            let (stxo, n) = decode_spent_tx_out(
                &serialized[offset..],
                tx_in.value_in,
                tx_in.block_height,
                tx_in.block_index,
                tx_in.previous_out_point.index,
            )
            .map_err(|e| {
                deserialize_error(format!(
                    "unable to decode stxo for {}:{}: {e}",
                    tx_in.previous_out_point.hash, tx_in.previous_out_point.index
                ))
            })?;
            stxos[stxo_idx as usize] = stxo;
            stxo_idx -= 1;
            offset += n;
        }
    }
    Ok(stxos)
}

// ----------------------------------------------------------------------
// Header commitments.
// ----------------------------------------------------------------------

/// Serialize the header commitment hashes (dcrd
/// `serializeHeaderCommitments`); an empty list serializes to nothing.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "commitments is an in-memory slice of HASH_SIZE-byte hashes, so len * HASH_SIZE \
              <= isize::MAX leaves room for the VLQ, and offset walks one hash per commitment \
              up to exactly serialized_len"
)]
pub fn serialize_header_commitments(commitments: &[Hash]) -> Vec<u8> {
    if commitments.is_empty() {
        return Vec::new();
    }

    let serialized_len =
        serialize_size_vlq(commitments.len() as u64) + commitments.len() * HASH_SIZE;
    let mut serialized = vec![0u8; serialized_len];
    let mut offset = put_vlq(&mut serialized, commitments.len() as u64);
    for commitment in commitments {
        serialized[offset..offset + HASH_SIZE].copy_from_slice(&commitment.0);
        offset += HASH_SIZE;
    }
    serialized
}

/// Deserialize the header commitment hashes (dcrd
/// `deserializeHeaderCommitments`).
pub fn deserialize_header_commitments(serialized: &[u8]) -> Result<Vec<Hash>, Error> {
    if serialized.is_empty() {
        return Ok(Vec::new());
    }

    let (num_commitments, offset) = deserialize_vlq(serialized);
    if offset >= serialized.len() {
        return Err(deserialize_error(
            "unexpected end of data after num commitments",
        ));
    }
    // dcrd sizes the check with a wrapping int64 conversion and
    // multiply, so a corrupt count large enough to wrap skips the
    // length check and crashes at the allocation below exactly like
    // Go's makeslice; a moderately corrupt count reports the same
    // (possibly negative) needed size.
    let total = (num_commitments as i64).wrapping_mul(HASH_SIZE as i64);
    if (serialized[offset..].len() as i64) < total {
        return Err(deserialize_error(format!(
            "unexpected end of data after number of commitments (got {}, need {total})",
            serialized[offset..].len()
        )));
    }
    let mut commitments = Vec::with_capacity(num_commitments as usize);
    let mut offset = offset;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "Vec::with_capacity above rejects any count whose byte size overflows isize, so \
                  the length check compared the exact num_commitments * HASH_SIZE and offset + \
                  HASH_SIZE <= serialized.len() on every pass"
    )]
    for _ in 0..num_commitments {
        let mut hash = [0u8; HASH_SIZE];
        hash.copy_from_slice(&serialized[offset..offset + HASH_SIZE]);
        commitments.push(Hash(hash));
        offset += HASH_SIZE;
    }
    Ok(commitments)
}

// ----------------------------------------------------------------------
// Best chain state.
// ----------------------------------------------------------------------

/// The best chain state stored in the chain state bucket (dcrd
/// `bestChainState`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BestChainState {
    /// The hash of the best block.
    pub hash: Hash,
    /// The height of the best block.
    pub height: u32,
    /// The total number of transactions up to and including the best
    /// block.
    pub total_txns: u64,
    /// The total subsidy issued up to and including the best block.
    pub total_subsidy: i64,
    /// The cumulative work of the best chain.
    pub work_sum: Uint256,
}

/// Serialize the best chain state (dcrd `serializeBestChainState`):
/// hash || LE height || LE total txns || LE total subsidy || LE work
/// byte length || big-endian work bytes with leading zeros stripped
/// (an all-zero work sum keeps all 32 zero bytes, matching dcrd's
/// first-nonzero scan).
pub fn serialize_best_chain_state(state: &BestChainState) -> Vec<u8> {
    let work_sum_bytes_array = state.work_sum.to_be_bytes();
    let mut first_nonzero = 0usize;
    for (i, b) in work_sum_bytes_array.iter().enumerate() {
        if *b != 0 {
            first_nonzero = i;
            break;
        }
    }
    let work_sum_bytes = &work_sum_bytes_array[first_nonzero..];

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "HASH_SIZE + 24 fixed bytes plus at most the 32 work sum bytes"
    )]
    let mut serialized = Vec::with_capacity(HASH_SIZE + 4 + 8 + 8 + 4 + work_sum_bytes.len());
    serialized.extend_from_slice(&state.hash.0);
    serialized.extend_from_slice(&state.height.to_le_bytes());
    serialized.extend_from_slice(&state.total_txns.to_le_bytes());
    serialized.extend_from_slice(&(state.total_subsidy as u64).to_le_bytes());
    serialized.extend_from_slice(&(work_sum_bytes.len() as u32).to_le_bytes());
    serialized.extend_from_slice(work_sum_bytes);
    serialized
}

/// Deserialize the best chain state (dcrd
/// `deserializeBestChainState`).
#[allow(
    clippy::arithmetic_side_effects,
    reason = "offset only walks the fixed-width fields, up to HASH_SIZE + 24 = \
              expected_min_len, which the length check bounds by serialized.len()"
)]
pub fn deserialize_best_chain_state(serialized: &[u8]) -> Result<BestChainState, Error> {
    let expected_min_len = HASH_SIZE + 4 + 8 + 8 + 4;
    if serialized.len() < expected_min_len {
        return Err(deserialize_error(format!(
            "corrupt best chain state size; min {expected_min_len} got {}",
            serialized.len()
        )));
    }

    let mut hash = [0u8; HASH_SIZE];
    hash.copy_from_slice(&serialized[..HASH_SIZE]);
    let mut offset = HASH_SIZE;
    let height = u32::from_le_bytes(serialized[offset..offset + 4].try_into().expect("4"));
    offset += 4;
    let total_txns = u64::from_le_bytes(serialized[offset..offset + 8].try_into().expect("8"));
    offset += 8;
    let total_subsidy =
        u64::from_le_bytes(serialized[offset..offset + 8].try_into().expect("8")) as i64;
    offset += 8;
    let work_sum_bytes_len =
        u32::from_le_bytes(serialized[offset..offset + 4].try_into().expect("4"));
    offset += 4;
    // dcrd's offset and lengths here are uint32: it compares the
    // remaining length truncated to uint32 and ends the work slice at
    // the wrapping uint32 sum (chainio.go:1220,1235-1240).
    let remaining = serialized[offset..].len() as u32;
    if remaining < work_sum_bytes_len {
        return Err(deserialize_error(format!(
            "corrupt work sum size; want {work_sum_bytes_len} got {remaining}"
        )));
    }
    // dcrd loads the work bytes with SetByteSlice, which truncates to
    // the trailing 32 bytes (modulo 2^256).
    let work_bytes = &serialized[offset..(offset as u32).wrapping_add(work_sum_bytes_len) as usize];

    Ok(BestChainState {
        hash: Hash(hash),
        height,
        total_txns,
        total_subsidy,
        work_sum: Uint256::from_be_slice(work_bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// dcrd measures the bytes left for the work sum as a uint32
    /// (`chainio.go:1235`), so a record with exactly 2^32 bytes after
    /// the fixed fields reads as 0 remaining and is rejected as
    /// corrupt, where a usize comparison would accept it and load the
    /// work sum.  The buffer comes from a zeroed allocation, so only
    /// the pages written or read are ever touched.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn best_chain_state_work_sum_length_check_is_uint32() {
        const FIXED_LEN: usize = HASH_SIZE + 4 + 8 + 8 + 4;
        let mut serialized = vec![0u8; FIXED_LEN + (1 << 32)];
        serialized[FIXED_LEN - 4..FIXED_LEN].copy_from_slice(&32u32.to_le_bytes());
        let err = deserialize_best_chain_state(&serialized).unwrap_err();
        assert_eq!(err.to_string(), "corrupt work sum size; want 32 got 0");
    }

    /// dcrd ends the work sum slice at the uint32 sum `offset +
    /// workSumBytesLen` (`chainio.go:1240`), which wraps: with 2^32 - 1
    /// bytes after the 56 fixed bytes and a work sum length of
    /// u32::MAX, the length check passes and the end wraps to 55, so
    /// `serializedData[56:55]` panics.  A usize end would reach exactly
    /// the buffer length and load the work sum instead.  The buffer
    /// comes from a zeroed allocation, and the work sum load reads only
    /// the trailing 32 bytes.
    #[cfg(target_pointer_width = "64")]
    #[test]
    #[should_panic(expected = "slice index starts at 56 but ends at 55")]
    fn best_chain_state_work_sum_slice_end_is_uint32() {
        const FIXED_LEN: usize = HASH_SIZE + 4 + 8 + 8 + 4;
        let mut serialized = vec![0u8; FIXED_LEN + (1 << 32) - 1];
        serialized[FIXED_LEN - 4..FIXED_LEN].copy_from_slice(&u32::MAX.to_le_bytes());
        let _ = deserialize_best_chain_state(&serialized);
    }
}
