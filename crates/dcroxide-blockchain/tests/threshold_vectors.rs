// SPDX-License-Identifier: ISC
//! Replay of dcrd's threshold state machine over synthetic chains
//! generated inside dcrd's internal/blockchain package at the pinned
//! tag (`data/threshold_vectors.txt`): per-node versions and full
//! (version, bits) votes plus dcrd's state-and-choice verdict for every
//! simnet deployment at every scenario tip.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::stakever::VersionNode;
use dcroxide_blockchain::thresholdstate::{VoteChainView, VoteNode, next_threshold_state};
use dcroxide_chaincfg::simnet_params;

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

#[test]
fn threshold_vectors() {
    let params = simnet_params();
    let data = include_str!("data/threshold_vectors.txt");

    let mut scenarios = 0usize;
    let mut thresholds = 0usize;
    let mut chain = VecChain(Vec::new());

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "scenario" => {
                let length: usize = f[2].parse().expect("length");
                chain = VecChain(Vec::with_capacity(length));
                scenarios += 1;
            }
            "n" => {
                // Format: n <h> <ts> <blockver> <stakever> ,v:b,v:b...
                let votes: Vec<(u32, u16)> = f[5]
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| {
                        let (v, b) = s.split_once(':').expect("v:b");
                        (v.parse().expect("version"), b.parse().expect("bits"))
                    })
                    .collect();
                chain.0.push(VoteNode {
                    node: VersionNode {
                        height: f[1].parse().expect("height"),
                        timestamp: f[2].parse().expect("ts"),
                        block_version: f[3].parse().expect("blockver"),
                        stake_version: f[4].parse().expect("stakever"),
                        vote_versions: votes.iter().map(|(v, _)| *v).collect(),
                    },
                    votes,
                });
            }
            "threshold" => {
                let version: u32 = f[1].parse().expect("version");
                let vote_id = f[2];
                let want_state = f[3];
                let want_choice = f[4];

                let deployment = params
                    .deployments
                    .iter()
                    .find(|(v, _)| *v == version)
                    .and_then(|(_, ds)| ds.iter().find(|d| d.vote.id == vote_id))
                    .expect("deployment exists");

                let tip = chain.0.last().expect("tip").node.height;
                let got = next_threshold_state(&chain, Some(tip), version, deployment, &params);
                assert_eq!(
                    got.state.go_name(),
                    want_state,
                    "{line} (scenario {scenarios})"
                );
                let got_choice = got.choice.as_ref().map_or("-", |c| c.id);
                assert_eq!(got_choice, want_choice, "{line} (scenario {scenarios})");
                thresholds += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }

    assert_eq!(scenarios, 15, "chain scenarios");
    assert_eq!(thresholds, 195, "threshold verdicts");
}
