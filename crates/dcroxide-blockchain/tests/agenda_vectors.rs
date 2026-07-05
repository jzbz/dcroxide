// SPDX-License-Identifier: ISC
//! Replay of dcrd's agenda activation checks and difficulty algorithm
//! selectors over synthetic chains generated inside dcrd's
//! internal/blockchain package (`data/agenda_vectors.txt`): full
//! per-node data plus dcrd's is-active verdicts for every vote ID, the
//! selected proof-of-work difficulty, and the selected stake
//! difficulty at each scenario tip.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::agendas::{
    VOTE_ID_TREASURY, calc_next_required_difficulty, calc_next_required_stake_difficulty,
    is_agenda_active, is_treasury_agenda_active,
};
use dcroxide_blockchain::difficulty::{ChainView, DiffNode};
use dcroxide_blockchain::stakever::VersionNode;
use dcroxide_blockchain::thresholdstate::{VoteChainView, VoteNode};
use dcroxide_chaincfg::simnet_params;

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

impl VoteChainView for VecChain {
    fn vote_node(&self, height: i64) -> Option<VoteNode> {
        if height < 0 {
            return None;
        }
        self.0.get(height as usize).map(|n| n.vote.clone())
    }
}

#[test]
fn agenda_vectors() {
    let params = simnet_params();
    let data = include_str!("data/agenda_vectors.txt");

    let mut scenarios = 0usize;
    let mut verdicts = 0usize;
    let mut chain = VecChain(Vec::new());
    let tip = |chain: &VecChain| chain.0.last().expect("tip").diff;

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "scenario" => {
                let length: usize = f[2].parse().expect("length");
                chain = VecChain(Vec::with_capacity(length));
                scenarios += 1;
            }
            "n" => {
                // n <h> <ts> <bits> <sbits> <pool> <fresh> <blockver>
                //   <stakever> ,v:b...
                let height: i64 = f[1].parse().expect("height");
                let timestamp: i64 = f[2].parse().expect("ts");
                let votes: Vec<(u32, u16)> = f[9]
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| {
                        let (v, b) = s.split_once(':').expect("v:b");
                        (v.parse().expect("version"), b.parse().expect("bits"))
                    })
                    .collect();
                chain.0.push(FullNode {
                    diff: DiffNode {
                        height,
                        timestamp,
                        bits: f[3].parse().expect("bits"),
                        sbits: f[4].parse().expect("sbits"),
                        pool_size: f[5].parse().expect("pool"),
                        fresh_stake: f[6].parse().expect("fresh"),
                    },
                    vote: VoteNode {
                        node: VersionNode {
                            height,
                            timestamp,
                            block_version: f[7].parse().expect("blockver"),
                            stake_version: f[8].parse().expect("stakever"),
                            vote_versions: votes.iter().map(|(v, _)| *v).collect(),
                        },
                        votes,
                    },
                });
            }
            "active" => {
                let vote_id = f[1];
                let prev = Some(tip(&chain).height);
                let got = if f[2] == "unknown" {
                    assert!(
                        is_agenda_active(&chain, prev, vote_id, &params).is_err(),
                        "{line}"
                    );
                    verdicts += 1;
                    continue;
                } else if vote_id == VOTE_ID_TREASURY {
                    is_treasury_agenda_active(&chain, prev, &params).expect("known")
                } else {
                    is_agenda_active(&chain, prev, vote_id, &params).expect("known")
                };
                let want: bool = f[2].parse().expect("want");
                assert_eq!(got, want, "{line} (scenario {scenarios})");
                verdicts += 1;
            }
            "powdiff" => {
                let delta: i64 = f[1].parse().expect("delta");
                let want: u32 = f[2].parse().expect("want");
                let t = tip(&chain);
                let got = calc_next_required_difficulty(&chain, &t, t.timestamp + delta, &params)
                    .expect("known deployment");
                assert_eq!(got, want, "{line} (scenario {scenarios})");
                verdicts += 1;
            }
            "sdiff" => {
                let want: i64 = f[1].parse().expect("want");
                let t = tip(&chain);
                let got = calc_next_required_stake_difficulty(&chain, Some(&t), &params);
                assert_eq!(got, want, "{line} (scenario {scenarios})");
                verdicts += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }

    assert_eq!(scenarios, 12, "chain scenarios");
    assert_eq!(verdicts, 156, "verdicts");
}
