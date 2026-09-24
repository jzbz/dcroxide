// SPDX-License-Identifier: ISC
//! Chain database record fuzz target: every decoder the chain runs over a
//! stored row must return an error on a malformed one, never panic.
//!
//! The rows are the node's own, but a torn write, a bit flip or a store
//! from another build is exactly what they may turn out to be, and a
//! decoder that indexes past a short row aborts the node on startup where
//! dcrd reports corruption.  The first byte picks the decoder (dcrd's
//! `chainio.go`, `utxoio.go`, `compress.go` and `treasury.go` readers);
//! the spend journal takes the transaction it is a journal for from the
//! front of the rest, since its layout depends on the inputs it covers.
//!
//! Left out: a row whose element count is more than its bytes could hold,
//! for the two decoders that allocate that count before reading an
//! element, the block index entry's votes and the header commitments.
//! dcrd sizes those slices with `make` up front and dies on such a count
//! (`makeslice: len out of range`, or out of memory), and the port
//! reproduces that, so an abort there is parity rather than a finding.
//! dcrd's treasury state and tspend readers do the same, but the port
//! bounds those two reservations by the bytes the row has left and
//! reports a negative tspend count, so every count reaches them here.

#![no_main]

use libfuzzer_sys::fuzz_target;

use dcroxide_blockchain::{chainio, compress, treasurydb};
use dcroxide_wire::{MAX_BLOCK_HEADER_PAYLOAD, MsgTx};

fn le32(b: &[u8]) -> u32 {
    let mut word = [0u8; 4];
    let n = b.len().min(4);
    word[..n].copy_from_slice(&b[..n]);
    u32::from_le_bytes(word)
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    match selector % 12 {
        0 => {
            let (index, row) = rest.split_at(rest.len().min(4));
            let _ = dcroxide_blockchain::deserialize_utxo_entry(row, le32(index));
        }
        1 => {
            let _ = dcroxide_blockchain::decode_outpoint_key(rest);
        }
        2 => {
            let _ = dcroxide_blockchain::deserialize_utxo_set_state(rest);
        }
        3 => {
            // `make([]stake.VoteVersionTuple, numVotes)` in dcrd, read
            // after the header and the status byte.
            let at = MAX_BLOCK_HEADER_PAYLOAD + 1;
            let (count, _) = compress::deserialize_vlq(rest.get(at..).unwrap_or_default());
            if count <= rest.len() as u64 {
                let _ = chainio::decode_block_index_entry(rest);
            }
        }
        4 => {
            // `make([]chainhash.Hash, numCommitments)` in dcrd, behind a
            // length check a wrapping count can pass.
            let (count, _) = compress::deserialize_vlq(rest);
            if count <= rest.len() as u64 / 32 {
                let _ = chainio::deserialize_header_commitments(rest);
            }
        }
        5 => {
            let _ = chainio::deserialize_best_chain_state(rest);
        }
        6 => {
            let (index, row) = rest.split_at(rest.len().min(4));
            let _ = chainio::decode_spent_tx_out(row, 0, 0, 0, le32(index));
        }
        7 => {
            let _ = treasurydb::deserialize_treasury_state(rest);
        }
        8 => {
            let _ = treasurydb::deserialize_tspend(rest);
        }
        9 => {
            let has_amount = rest.first().is_some_and(|b| b & 1 != 0);
            let _ =
                compress::decode_compressed_tx_out(rest.get(1..).unwrap_or_default(), has_amount);
        }
        10 => {
            // The reader dcrd guards the decoder with; the decoder itself
            // assumes a well-formed run, so only a validated one reaches it.
            if let Ok(size) = dcroxide_blockchain::read_deserialize_size_of_minimal_outputs(rest) {
                let (_, consumed) = chainio::deserialize_to_minimal_outputs(&rest[..size]);
                assert_eq!(consumed, size, "minimal outputs size disagrees with decode");
            }
        }
        _ => {
            if let Ok((tx, consumed)) = MsgTx::from_bytes(rest) {
                let _ = chainio::deserialize_spend_journal_entry(&rest[consumed..], &[tx]);
            }
        }
    }
});
