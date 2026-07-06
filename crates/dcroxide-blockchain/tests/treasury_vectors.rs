// SPDX-License-Identifier: ISC
//! Replay of dcrd's treasury account, spend tracking, and treasury
//! spend checks generated against a complete real `BlockChain`
//! inside dcrd's internal/blockchain package
//! (`data/treasury_vectors.txt`): a 240-block simnet chain with
//! treasurybases, treasury adds, treasury-vote-carrying votes across
//! a full voting window, and a treasury spend mined mid-window —
//! comparing treasury balances, duplicate-mine checks, vote tallies
//! and pass verdicts, maximum expenditures under the active DCP0013
//! policy, the complete `tspendChecks` verdict kinds, and the raw
//! treasury state and spend rows byte for byte.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::HashMap;

use dcroxide_blockchain::blockindex::BlockStatus;
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::treasurydb::{serialize_treasury_state, serialize_tspend};
use dcroxide_chaincfg::simnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_testutil::unhex;
use dcroxide_wire::{MsgBlock, MsgTx};

fn parse_hash(s: &str) -> Hash {
    let bytes = unhex(s);
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Hash(h)
}

fn raw_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn treasury_vectors() {
    let params = simnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    let data = include_str!("data/treasury_vectors.txt");
    let mut tspends: HashMap<String, MsgTx> = HashMap::new();
    let mut counts = [0usize; 8];

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "tspend" => {
                let (tx, _) = MsgTx::from_bytes(&unhex(f[2])).expect("tspend");
                tspends.insert(f[1].to_string(), tx);
                counts[0] += 1;
            }
            "blk" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[1])).expect("block");
                let prev = chain
                    .index
                    .lookup_node(&block.header.prev_block)
                    .expect("previous node");
                let id = chain.store.new_node(&block.header, Some(prev));
                {
                    let node = chain.store.node_mut(id);
                    node.status =
                        BlockStatus(BlockStatus::DATA_STORED.0 | BlockStatus::VALIDATED.0);
                    node.is_fully_linked = true;
                }
                chain.index.add_node(&chain.store, id);
                chain
                    .blocks
                    .insert(block.header.block_hash().0, block.clone());
                chain
                    .fetch_stake_node(id, &params)
                    .unwrap_or_else(|e| panic!("{line}: stake node: {e:?}"));
                chain
                    .put_treasury_records(id, &block, &params)
                    .unwrap_or_else(|e| panic!("{line}: treasury records: {e:?}"));
                chain.best_chain.set_tip(&chain.store, Some(id));
                counts[1] += 1;
            }
            "tbal" => {
                // tbal <prevhash> <balance>
                let node = chain
                    .index
                    .lookup_node(&parse_hash(f[1]))
                    .expect("balance node");
                assert_eq!(
                    chain.calculate_treasury_balance(node, &params).to_string(),
                    f[2],
                    "{line}"
                );
                counts[2] += 1;
            }
            "tsx" => {
                // tsx <prevhash> <tspendhash> <exists>
                let node = chain
                    .index
                    .lookup_node(&parse_hash(f[1]))
                    .expect("prev node");
                let exists = chain.check_tspend_exists(node, &parse_hash(f[2])).is_err();
                assert_eq!(exists.to_string(), f[3], "{line}");
                counts[3] += 1;
            }
            "tcv" => {
                // tcv <prevhash> <label> <yes> <no> | err
                let node = chain
                    .index
                    .lookup_node(&parse_hash(f[1]))
                    .expect("prev node");
                let tspend = &tspends[f[2]];
                match chain.tspend_count_votes(node, tspend, &params) {
                    Ok((_, _, yes, no)) => {
                        assert_eq!(yes.to_string(), f[3], "{line}: yes");
                        assert_eq!(no.to_string(), f[4], "{line}: no");
                    }
                    Err(e) => {
                        assert_eq!("err", f[3], "{line}: unexpected error {e}");
                    }
                }
                counts[4] += 1;
            }
            "thv" => {
                // thv <prevhash> <label> <failed>
                let node = chain
                    .index
                    .lookup_node(&parse_hash(f[1]))
                    .expect("prev node");
                let tspend = &tspends[f[2]];
                let failed = chain.check_tspend_has_votes(node, tspend, &params).is_err();
                assert_eq!(failed.to_string(), f[3], "{line}");
                counts[5] += 1;
            }
            "mte" => {
                // mte <prevhash> <amount>
                let node = chain
                    .index
                    .lookup_node(&parse_hash(f[1]))
                    .expect("prev node");
                let amount = chain
                    .max_treasury_expenditure(node, &params)
                    .expect("max expenditure");
                assert_eq!(amount.to_string(), f[2], "{line}");
                counts[6] += 1;
            }
            "tsc" => {
                // tsc <prevhash> <blockhex> <kind>
                let node = chain
                    .index
                    .lookup_node(&parse_hash(f[1]))
                    .expect("prev node");
                let (block, _) = MsgBlock::from_bytes(&unhex(f[2])).expect("block");
                let kind = match chain.tspend_checks(node, &block, &params) {
                    Ok(()) => "ok".to_string(),
                    Err(e) => e.kind.kind_name().to_string(),
                };
                assert_eq!(kind, f[3], "{line}");
                counts[7] += 1;
            }
            "trow" => {
                // trow <blockhash> <rowhex>
                let ts = chain
                    .treasury_state
                    .get(&parse_hash(f[1]).0)
                    .expect("treasury state");
                let raw = serialize_treasury_state(ts).expect("serialize");
                assert_eq!(raw_hex(&raw), f[2], "{line}");
            }
            "srow" => {
                // srow <txhash> <rowhex>
                let blocks = chain
                    .tspend_blocks
                    .get(&parse_hash(f[1]).0)
                    .expect("tspend blocks");
                assert_eq!(raw_hex(&serialize_tspend(blocks)), f[2], "{line}");
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [4, 240, 5, 3, 5, 5, 2, 5], "row counts");
}
