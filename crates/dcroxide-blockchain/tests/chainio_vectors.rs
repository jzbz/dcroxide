// SPDX-License-Identifier: ISC
//! Replay of dcrd's chain persistence serialization formats generated
//! inside dcrd's internal/blockchain package
//! (`data/chainio_vectors.txt`): ticket minimal outputs, block index
//! entries, spend journal entries with their source transactions,
//! header commitments, and the best chain state.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::chainio::{
    BestChainState, BlockIndexEntry, SpentTxOut, block_index_entry_serialize_size,
    decode_block_index_entry, deserialize_best_chain_state, deserialize_header_commitments,
    deserialize_spend_journal_entry, deserialize_to_minimal_outputs, put_tx_to_minimal_outputs,
    serialize_best_chain_state, serialize_block_index_entry, serialize_header_commitments,
    serialize_size_for_minimal_outputs, serialize_spend_journal_entry,
};
use dcroxide_chainhash::Hash;
use dcroxide_testutil::{hex, unhex};
use dcroxide_uint256::Uint256;
use dcroxide_wire::{BlockHeader, MsgTx};

fn parse_hash_hex(s: &str) -> Hash {
    // The dump emits raw byte order (%x of the array), not the
    // display order.
    let bytes = unhex(s);
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Hash(h)
}

#[test]
fn chainio_vectors() {
    let data = include_str!("data/chainio_vectors.txt");

    let mut counts = [0usize; 5];
    let mut pending_stxos: Vec<SpentTxOut> = Vec::new();
    let mut pending_decoded: Vec<SpentTxOut> = Vec::new();

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "minouts" => {
                let (tx, _) = MsgTx::from_bytes(&unhex(f[1])).expect("tx");
                let serialized = unhex(f[2]);
                assert_eq!(
                    serialize_size_for_minimal_outputs(&tx),
                    serialized.len(),
                    "{line}: size"
                );
                let mut buf = vec![0u8; serialized.len()];
                assert_eq!(put_tx_to_minimal_outputs(&mut buf, &tx), buf.len());
                assert_eq!(buf, serialized, "{line}: serialize");
                let (min_outs, consumed) = deserialize_to_minimal_outputs(&serialized);
                assert_eq!(consumed, serialized.len(), "{line}: consumed");
                assert_eq!(min_outs.len(), tx.tx_out.len(), "{line}: count");
                for (got, want) in min_outs.iter().zip(&tx.tx_out) {
                    assert_eq!(got.value, want.value, "{line}: value");
                    assert_eq!(got.version, want.version, "{line}: version");
                    assert_eq!(got.pk_script, want.pk_script, "{line}: script");
                }
                counts[0] += 1;
            }
            "bindex" => {
                let (header, _) = BlockHeader::from_bytes(&unhex(f[1])).expect("header");
                let status: u8 = f[2].parse().expect("status");
                let vote_info: Vec<(u32, u16)> = f[3]
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| {
                        let (v, b) = s.split_once(':').expect("v:b");
                        (v.parse().expect("version"), b.parse().expect("bits"))
                    })
                    .collect();
                let serialized = unhex(f[4]);
                let entry = BlockIndexEntry {
                    header,
                    status,
                    vote_info,
                };
                assert_eq!(
                    block_index_entry_serialize_size(&entry),
                    serialized.len(),
                    "{line}: size"
                );
                assert_eq!(
                    serialize_block_index_entry(&entry),
                    serialized,
                    "{line}: serialize"
                );
                let (decoded, consumed) = decode_block_index_entry(&serialized).expect("decode");
                assert_eq!(consumed, serialized.len(), "{line}: consumed");
                assert_eq!(decoded, entry, "{line}: decode");
                counts[1] += 1;
            }
            "journal" => {
                // Flush any previous journal's collected stxos first.
                assert_eq!(pending_stxos, pending_decoded, "stxo mismatch");
                pending_stxos.clear();
                pending_decoded.clear();

                let txns: Vec<MsgTx> = f[1]
                    .split(',')
                    .map(|s| MsgTx::from_bytes(&unhex(s)).expect("tx").0)
                    .collect();
                let serialized = unhex(f[2]);
                let decoded = deserialize_spend_journal_entry(&serialized, &txns)
                    .expect("deserialize journal");
                // Re-serialization must reproduce the exact bytes.
                assert_eq!(
                    serialize_spend_journal_entry(&decoded).unwrap_or_default(),
                    serialized,
                    "{line}: reserialize"
                );
                pending_decoded = decoded;
                counts[2] += 1;
            }
            "stxo" => {
                // stxo <amount> <pk|""> <minouts|-> <h> <i> <sv> <flags>
                pending_stxos.push(SpentTxOut {
                    amount: f[1].parse().expect("amount"),
                    pk_script: unhex(f[2]),
                    ticket_min_outs: if f[3] == "-" { None } else { Some(unhex(f[3])) },
                    block_height: f[4].parse().expect("height"),
                    block_index: f[5].parse().expect("index"),
                    script_version: f[6].parse().expect("sv"),
                    packed_flags: f[7].parse().expect("flags"),
                });
            }
            "commitments" => {
                let commitments: Vec<Hash> = if f[1] == "-" {
                    Vec::new()
                } else {
                    f[1].split(',').map(parse_hash_hex).collect()
                };
                let serialized = unhex(f[2]);
                assert_eq!(
                    serialize_header_commitments(&commitments),
                    serialized,
                    "{line}: serialize"
                );
                assert_eq!(
                    deserialize_header_commitments(&serialized).expect("deserialize"),
                    commitments,
                    "{line}: deserialize"
                );
                counts[3] += 1;
            }
            "beststate" => {
                let state = BestChainState {
                    hash: parse_hash_hex(f[1]),
                    height: f[2].parse().expect("height"),
                    total_txns: f[3].parse().expect("txns"),
                    total_subsidy: f[4].parse().expect("subsidy"),
                    work_sum: {
                        let be = unhex(f[5]);
                        let mut b = [0u8; 32];
                        b.copy_from_slice(&be);
                        Uint256::from_be_bytes(&b)
                    },
                };
                let serialized = unhex(f[6]);
                assert_eq!(
                    hex(&serialize_best_chain_state(&state)),
                    hex(&serialized),
                    "{line}: serialize"
                );
                assert_eq!(
                    deserialize_best_chain_state(&serialized).expect("deserialize"),
                    state,
                    "{line}: deserialize"
                );
                counts[4] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    // The final journal's stxos.
    assert_eq!(pending_stxos, pending_decoded, "final stxo mismatch");

    assert_eq!(counts, [40, 40, 30, 20, 20], "row counts");
}
