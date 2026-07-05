// SPDX-License-Identifier: ISC
//! Replay of dcrd's full contextual block verdicts generated inside
//! dcrd's internal/blockchain package
//! (`data/blockcontext_vectors.txt`): `checkBlockContext` over crafted
//! simnet blocks with coinbases, treasurybases, votes, tickets,
//! revocations, and treasury adds, against a parent stake node
//! reconstructed step-for-step through the ported ticket pool state
//! machine from the dump's recorded connect inputs.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::RuleError;
use dcroxide_blockchain::difficulty::{ChainView, DiffNode};
use dcroxide_blockchain::stakever::VersionNode;
use dcroxide_blockchain::thresholdstate::{VoteChainView, VoteNode};
use dcroxide_blockchain::validate::check_block_context;
use dcroxide_chaincfg::simnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_stake::ticketnode::{Node, StakeNodeParams};
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;

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

fn parse_hash(s: &str) -> Hash {
    let bytes = unhex(s);
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Hash(h)
}

fn parse_hashes(s: &str) -> Vec<Hash> {
    if s == "-" {
        return Vec::new();
    }
    s.split(',').map(parse_hash).collect()
}

#[test]
fn blockcontext_vectors() {
    let params = simnet_params();
    let data = include_str!("data/blockcontext_vectors.txt");

    // The stake node is rebuilt through the ported state machine from
    // the dump's recorded per-block connect inputs.
    let stake_params = StakeNodeParams {
        votes_per_block: params.tickets_per_block,
        stake_validation_begin_height: params.stake_validation_height,
        stake_enable_height: params.stake_enabled_height,
        ticket_expiry_blocks: params.ticket_expiry,
    };
    let mut stake_node = Node::genesis(stake_params);

    let mut chain = VecChain(Vec::new());
    let mut parent_pool_size: u32 = 0;
    let mut parent_final_state = [0u8; 6];
    let mut counts = [0usize; 2];

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "sblk" => {
                let iv = parse_hash(f[1]);
                let voted = parse_hashes(f[2]);
                let news = parse_hashes(f[3]);
                stake_node = stake_node
                    .connect(iv, &voted, &[], &news)
                    .unwrap_or_else(|e| panic!("{line}: stake connect failed: {e:?}"));
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
                // The rebuilt stake node must agree with the dump.
                assert_eq!(
                    stake_node.pool_size() as u32,
                    parent_pool_size,
                    "rebuilt stake node pool size"
                );
                assert_eq!(
                    stake_node.final_state(),
                    parent_final_state,
                    "rebuilt stake node final state"
                );
            }
            "cbc" => {
                let fast_add: bool = f[1].parse().expect("fastadd");
                let (block, _) = MsgBlock::from_bytes(&unhex(f[2])).expect("block");
                let tip_height = chain.0.last().expect("tip").diff.height;
                assert_eq!(
                    kind_of(check_block_context(
                        &chain,
                        &block,
                        Some(tip_height),
                        fast_add,
                        true,
                        parent_pool_size,
                        parent_final_state,
                        Some(&stake_node),
                        &params,
                    )),
                    f[3],
                    "{line}"
                );
                counts[1] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [154, 36], "row counts");
}
