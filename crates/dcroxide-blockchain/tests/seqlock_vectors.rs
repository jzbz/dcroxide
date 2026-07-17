// SPDX-License-Identifier: ISC
//! Replay of dcrd's sequence lock calculations generated inside dcrd's
//! internal/blockchain package (`data/seqlock_vectors.txt`):
//! `calcSequenceLock` over random transactions against synthetic
//! chains and an in-package `UtxoViewpoint` (simnet chains exercise
//! the forced-active treasury agenda; mainnet chains the inactive
//! branch), plus `LockTimeToSequence` samples across the representable
//! boundaries.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use dcroxide_blockchain::agendas::is_treasury_agenda_active;
use dcroxide_blockchain::sequencelock::{SequenceLock, calc_sequence_lock, lock_time_to_sequence};
use dcroxide_blockchain::stakever::VersionNode;
use dcroxide_blockchain::thresholdstate::{VoteChainView, VoteNode};
use dcroxide_chaincfg::{Params, mainnet_params, simnet_params};
use dcroxide_testutil::unhex;
use dcroxide_wire::{MsgTx, OutPoint};

struct VecChain(Vec<VoteNode>);

// The vote view is also a version view (the supertrait the cached
// stake version calculations require); the cache hooks stay at their
// disabled defaults so the vectors replay the uncached path.
impl dcroxide_blockchain::stakever::VersionChainView for VecChain {
    fn node(&self, height: i64) -> Option<dcroxide_blockchain::stakever::VersionNode> {
        self.vote_node(height).map(|n| n.node)
    }
}

impl VoteChainView for VecChain {
    fn vote_node(&self, height: i64) -> Option<VoteNode> {
        if height < 0 {
            return None;
        }
        self.0.get(height as usize).cloned()
    }
}

type UtxoKey = ([u8; 32], u32, i8);

fn utxo_key(op: &OutPoint) -> UtxoKey {
    (op.hash.0, op.index, op.tree)
}

#[test]
fn seqlock_vectors() {
    let data = include_str!("data/seqlock_vectors.txt");

    let mut params: Params = simnet_params();
    let mut chain = VecChain(Vec::new());
    let mut utxos: BTreeMap<UtxoKey, i64> = BTreeMap::new();
    let mut counts = [0usize; 4];

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "scenario" => {
                params = match f[2] {
                    "simnet" => simnet_params(),
                    "mainnet" => mainnet_params(),
                    other => panic!("unknown network {other}"),
                };
                chain = VecChain(Vec::new());
                utxos.clear();
                counts[0] += 1;
            }
            "n" => {
                // n <h> <ts> <bits> <sbits> <pool> <fresh> <blockver>
                //   <stakever> ,v:b...
                let height: i64 = f[1].parse().expect("height");
                let votes: Vec<(u32, u16)> = f[9]
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| {
                        let (v, b) = s.split_once(':').expect("v:b");
                        (v.parse().expect("version"), b.parse().expect("bits"))
                    })
                    .collect();
                chain.0.push(VoteNode {
                    node: VersionNode {
                        height,
                        timestamp: f[2].parse().expect("ts"),
                        block_version: f[7].parse().expect("blockver"),
                        stake_version: f[8].parse().expect("stakever"),
                        vote_versions: votes.iter().map(|&(v, _)| v).collect(),
                    },
                    votes,
                });
            }
            "treasury" => {
                let want: bool = f[1].parse().expect("bool");
                let tip_height = chain.0.len() as i64 - 1;
                assert_eq!(
                    is_treasury_agenda_active(&chain, Some(tip_height), &params),
                    Ok(want),
                    "{line}"
                );
                counts[1] += 1;
            }
            "utxo" => {
                // utxo <hash-raw-hex> <index> <tree> <height>
                let bytes = unhex(f[1]);
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes);
                let key = (
                    hash,
                    f[2].parse().expect("index"),
                    f[3].parse().expect("tree"),
                );
                utxos.insert(key, f[4].parse().expect("height"));
            }
            "seq" => {
                let is_active: bool = f[1].parse().expect("active");
                let (tx, _) = MsgTx::from_bytes(&unhex(f[2])).expect("tx");
                let tip_height = chain.0.len() as i64 - 1;
                let result = calc_sequence_lock(
                    &chain,
                    tip_height,
                    &tx,
                    |op| utxos.get(&utxo_key(op)).copied(),
                    is_active,
                    &params,
                );
                match f[3] {
                    "ok" => {
                        let want = SequenceLock {
                            min_height: f[4].parse().expect("minh"),
                            min_time: f[5].parse().expect("mint"),
                        };
                        assert_eq!(result, Ok(want), "{line}");
                    }
                    "err" => {
                        let got = result.expect_err(line).kind.kind_name().to_string();
                        assert_eq!(got, f[4], "{line}");
                    }
                    other => panic!("unknown verdict {other}"),
                }
                counts[2] += 1;
            }
            "lts" => {
                let is_seconds: bool = f[1].parse().expect("seconds");
                let lock_time: u32 = f[2].parse().expect("locktime");
                let result = lock_time_to_sequence(is_seconds, lock_time);
                match f[3] {
                    "ok" => {
                        let want: u32 = f[4].parse().expect("seq");
                        assert_eq!(result, Ok(want), "{line}");
                    }
                    "err" => assert!(result.is_err(), "{line}"),
                    other => panic!("unknown verdict {other}"),
                }
                counts[3] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [4, 4, 200, 60], "row counts");
}
