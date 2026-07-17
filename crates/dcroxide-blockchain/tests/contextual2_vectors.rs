// SPDX-License-Identifier: ISC
//! Replay of dcrd's ticket redeemer and stake commitment verdicts
//! generated inside dcrd's internal/blockchain package
//! (`data/contextual2_vectors.txt`): `checkTicketRedeemers` over
//! crafted vote/revocation/winner/expiring sets under both automatic
//! revocation regimes, and `checkBlockHeaderContext`'s pool size and
//! lottery final state commitments against a real parent stake node
//! built through the ported ticket state machine's dcrd counterpart.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::RuleError;
use dcroxide_blockchain::difficulty::{ChainView, DiffNode};
use dcroxide_blockchain::stakever::VersionNode;
use dcroxide_blockchain::thresholdstate::{VoteChainView, VoteNode};
use dcroxide_blockchain::validate::{check_block_header_context, check_ticket_redeemers};
use dcroxide_chaincfg::simnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_testutil::unhex;
use dcroxide_wire::BlockHeader;

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

fn parse_hashes(s: &str) -> Vec<Hash> {
    if s == "-" {
        return Vec::new();
    }
    s.split(',')
        .map(|h| {
            let bytes = unhex(h);
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes);
            Hash(hash)
        })
        .collect()
}

#[test]
fn contextual2_vectors() {
    let params = simnet_params();
    let data = include_str!("data/contextual2_vectors.txt");

    let mut chain = VecChain(Vec::new());
    let mut parent_pool_size: u32 = 0;
    let mut parent_final_state = [0u8; 6];
    let mut counts = [0usize; 2];

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "ctr" => {
                let autorev: bool = f[1].parse().expect("autorev");
                let votes = parse_hashes(f[2]);
                let revocations = parse_hashes(f[3]);
                let winners = parse_hashes(f[4]);
                let expiring = parse_hashes(f[5]);
                let missed = parse_hashes(f[6]);
                assert_eq!(
                    kind_of(check_ticket_redeemers(
                        &votes,
                        &revocations,
                        &winners,
                        &expiring,
                        |h| missed.contains(h),
                        autorev,
                    )),
                    f[7],
                    "{line}"
                );
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
            "parentstake" => {
                parent_pool_size = f[1].parse().expect("poolsize");
                parent_final_state.copy_from_slice(&unhex(f[2]));
            }
            "hbc2" => {
                let (header, _) = BlockHeader::from_bytes(&unhex(f[1])).expect("header");
                let tip_height = chain.0.last().expect("tip").diff.height;
                assert_eq!(
                    kind_of(check_block_header_context(
                        &chain,
                        &header,
                        Some(tip_height),
                        false,
                        true,
                        parent_pool_size,
                        parent_final_state,
                        &params,
                    )),
                    f[2],
                    "{line}"
                );
                counts[1] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [40, 16], "row counts");
}
