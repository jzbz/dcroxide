// SPDX-License-Identifier: ISC
//! Replay of dcrd's contextual validation verdicts generated inside
//! dcrd's internal/blockchain package
//! (`data/contextual_vectors.txt`): `checkProofOfWorkContext` with the
//! agenda-selected hash algorithm over ground headers,
//! `checkBlockHeaderContext` (excluding the parent-stake-node
//! commitments, which the dump avoids by construction since they
//! require the ticket database), `checkMerkleRoots` under both header
//! commitment regimes, and the coinbase/treasurybase unique-height
//! checks over crafted null-data scripts.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::RuleError;
use dcroxide_blockchain::agendas::{
    is_blake3_pow_agenda_active, is_header_commitments_agenda_active,
};
use dcroxide_blockchain::difficulty::{ChainView, DiffNode};
use dcroxide_blockchain::stakever::VersionNode;
use dcroxide_blockchain::thresholdstate::{VoteChainView, VoteNode};
use dcroxide_blockchain::validate::{
    check_block_header_context, check_coinbase_unique_height, check_merkle_roots,
    check_proof_of_work_context, check_treasurybase_unique_height,
};
use dcroxide_chaincfg::{Params, mainnet_params, regnet_params, simnet_params};
use dcroxide_testutil::unhex;
use dcroxide_wire::{BlockHeader, MsgBlock};

/// One synthetic node carrying both difficulty and vote data.
#[derive(Clone)]
struct FullNode {
    diff: DiffNode,
    vote: VoteNode,
}

struct VecChain(Vec<FullNode>);

impl ChainView for VecChain {
    fn node(&self, height: i64) -> Option<DiffNode> {
        if height < 0 {
            return None;
        }
        self.0.get(height as usize).map(|n| n.diff)
    }
}

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
        self.0.get(height as usize).map(|n| n.vote.clone())
    }
}

fn kind_of(result: Result<(), RuleError>) -> String {
    match result {
        Ok(()) => "ok".to_string(),
        Err(e) => e.kind.kind_name().to_string(),
    }
}

#[test]
fn contextual_vectors() {
    let data = include_str!("data/contextual_vectors.txt");

    let mut params: Params = simnet_params();
    let mut chain = VecChain(Vec::new());
    let mut counts = [0usize; 6];

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "scenario" => {
                params = match f[2] {
                    "simnet" => simnet_params(),
                    "mainnet" => mainnet_params(),
                    "regnet" => regnet_params(),
                    other => panic!("unknown scenario {other}"),
                };
                chain = VecChain(Vec::new());
                counts[0] += 1;
            }
            "n" => {
                let height: i64 = f[1].parse().expect("height");
                chain.0.push(FullNode {
                    diff: DiffNode {
                        height,
                        timestamp: f[2].parse().expect("ts"),
                        bits: f[3].parse().expect("bits"),
                        sbits: f[4].parse().expect("sbits"),
                        pool_size: f[5].parse().expect("pool"),
                        fresh_stake: f[6].parse().expect("fresh"),
                    },
                    vote: VoteNode {
                        node: VersionNode {
                            height,
                            timestamp: f[2].parse().expect("ts"),
                            block_version: f[7].parse().expect("blockver"),
                            stake_version: f[8].parse().expect("stakever"),
                            vote_versions: Vec::new(),
                        },
                        votes: Vec::new(),
                    },
                });
            }
            "agendas" => {
                let tip_height = chain.0.last().expect("tip").diff.height;
                let want_blake3: bool = f[1].parse().expect("blake3");
                let want_commitments: bool = f[2].parse().expect("commitments");
                assert_eq!(
                    is_blake3_pow_agenda_active(&chain, Some(tip_height), &params),
                    Ok(want_blake3),
                    "{line}"
                );
                assert_eq!(
                    is_header_commitments_agenda_active(&chain, Some(tip_height), &params),
                    Ok(want_commitments),
                    "{line}"
                );
            }
            "powctx" => {
                let no_pow: bool = f[1].parse().expect("nopow");
                let (header, _) = BlockHeader::from_bytes(&unhex(f[2])).expect("header");
                let tip_height = chain.0.last().expect("tip").diff.height;
                assert_eq!(
                    kind_of(check_proof_of_work_context(
                        &chain, &header, tip_height, no_pow, &params
                    )),
                    f[3],
                    "{line}"
                );
                counts[1] += 1;
            }
            "hbc" => {
                let fast_add: bool = f[1].parse().expect("fastadd");
                let no_pow: bool = f[2].parse().expect("nopow");
                let (header, _) = BlockHeader::from_bytes(&unhex(f[3])).expect("header");
                let tip_height = chain.0.last().expect("tip").diff.height;
                assert_eq!(
                    kind_of(check_block_header_context(
                        &chain,
                        &header,
                        Some(tip_height),
                        fast_add,
                        no_pow,
                        0,
                        [0u8; 6],
                        &params
                    )),
                    f[4],
                    "{line}"
                );
                counts[2] += 1;
            }
            "mroots" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[1])).expect("block");
                let tip_height = chain.0.last().expect("tip").diff.height;
                assert_eq!(
                    kind_of(check_merkle_roots(&chain, &block, tip_height, &params)),
                    f[2],
                    "{line}"
                );
                counts[3] += 1;
            }
            "cuh" => {
                let treasury: bool = f[1].parse().expect("treasury");
                let height: i64 = f[2].parse().expect("height");
                let (block, _) = MsgBlock::from_bytes(&unhex(f[3])).expect("block");
                assert_eq!(
                    kind_of(check_coinbase_unique_height(height, &block, treasury)),
                    f[4],
                    "{line}"
                );
                counts[4] += 1;
            }
            "tuh" => {
                let height: i64 = f[1].parse().expect("height");
                let (block, _) = MsgBlock::from_bytes(&unhex(f[2])).expect("block");
                assert_eq!(
                    kind_of(check_treasurybase_unique_height(height, &block)),
                    f[3],
                    "{line}"
                );
                counts[5] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [3, 30, 42, 30, 40, 30], "row counts");
}
