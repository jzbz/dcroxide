// SPDX-License-Identifier: ISC
//! Replay of dcrd's stake node attachment generated inside dcrd's
//! internal/blockchain package (`data/stakenode_vectors.txt`): a
//! 154-block simnet chain with real skeleton blocks (ticket
//! purchases, votes with misses, and revocations) advanced through
//! `fetchStakeNode`'s parent connect path with the ticket database
//! rows recorded at every height, plus a side chain forking below the
//! tip; stake nodes are then pruned and re-fetched to force the
//! tip-to-fork disconnect walk over the undo rows and the side chain
//! replay — comparing pool sizes, final states, winners, and missed
//! tickets.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::simnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;

fn parse_hash(s: &str) -> Hash {
    let bytes = unhex(s);
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Hash(h)
}

fn raw_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hash_csv(hashes: &[Hash]) -> String {
    if hashes.is_empty() {
        return "-".to_string();
    }
    hashes
        .iter()
        .map(|h| raw_hex(&h.0))
        .collect::<Vec<_>>()
        .join(",")
}

#[test]
fn stakenode_vectors() {
    let params = simnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    let data = include_str!("data/stakenode_vectors.txt");
    let mut counts = [0usize; 3];

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "blk" => {
                // blk <hex> <main01>
                let (block, _) = MsgBlock::from_bytes(&unhex(f[1])).expect("block");
                let main = f[2] == "1";
                let prev = chain
                    .index
                    .lookup_node(&block.header.prev_block)
                    .expect("previous node");
                let id = chain.store.new_node(&block.header, Some(prev));
                chain.index.add_node(&chain.store, id);
                chain
                    .blocks
                    .insert(block.header.block_hash().0, block.clone());
                if main {
                    chain
                        .fetch_stake_node(id, &params)
                        .unwrap_or_else(|e| panic!("{line}: fetch failed: {e:?}"));
                    chain.write_stake_db_rows(id);
                    chain.best_chain.set_tip(&chain.store, Some(id));
                }
                counts[0] += 1;
            }
            "prune" => {
                let id = chain
                    .index
                    .lookup_node(&parse_hash(f[1]))
                    .expect("pruned node");
                let node = chain.store.node_mut(id);
                node.stake_node = None;
                node.new_tickets = None;
                node.tickets_voted = Vec::new();
                node.tickets_revoked = Vec::new();
                node.votes = Vec::new();
                node.ticket_info_populated = false;
                counts[1] += 1;
            }
            "fetch" => {
                // fetch <hash> <poolsize> <finalstate> <winners> <missed>
                let id = chain
                    .index
                    .lookup_node(&parse_hash(f[1]))
                    .expect("fetched node");
                let stake_node = chain
                    .fetch_stake_node(id, &params)
                    .unwrap_or_else(|e| panic!("{line}: fetch failed: {e:?}"));
                assert_eq!(
                    stake_node.pool_size().to_string(),
                    f[2],
                    "{line}: pool size"
                );
                assert_eq!(
                    raw_hex(&stake_node.final_state()),
                    f[3],
                    "{line}: final state"
                );
                assert_eq!(hash_csv(stake_node.winners()), f[4], "{line}: winners");
                assert_eq!(
                    hash_csv(&stake_node.missed_tickets()),
                    f[5],
                    "{line}: missed"
                );
                counts[2] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [156, 55, 4], "row counts");
}
