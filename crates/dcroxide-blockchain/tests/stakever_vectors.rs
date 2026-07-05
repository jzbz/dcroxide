// SPDX-License-Identifier: ISC
//! Replay of dcrd's stake version machinery over synthetic chains
//! generated inside dcrd's internal/blockchain package at the pinned
//! tag (`data/stakever_vectors.txt`): per-node block/stake/vote
//! versions plus dcrd's own outputs for the past median time, the
//! stake/voter version majorities, and the final stake version
//! calculation, alongside pure `calcWantHeight` samples.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::stakever::{
    VersionChainView, VersionNode, calc_past_median_time, calc_prior_stake_version,
    calc_stake_version, calc_voter_version, calc_want_height, is_majority_version,
    is_stake_majority_version,
};
use dcroxide_chaincfg::simnet_params;

struct VecChain(Vec<VersionNode>);

impl VersionChainView for VecChain {
    fn node(&self, height: i64) -> Option<VersionNode> {
        if height < 0 {
            return None;
        }
        self.0.get(height as usize).cloned()
    }
}

#[test]
fn stakever_vectors() {
    let params = simnet_params();
    let data = include_str!("data/stakever_vectors.txt");

    let mut want_heights = 0usize;
    let mut scenarios = 0usize;
    let mut chain = VecChain(Vec::new());
    let tip = |chain: &VecChain| chain.0.last().expect("tip").height;

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "wantheight" => {
                let (svh, interval, height, want): (i64, i64, i64, i64) = (
                    f[1].parse().expect("svh"),
                    f[2].parse().expect("interval"),
                    f[3].parse().expect("height"),
                    f[4].parse().expect("want"),
                );
                assert_eq!(calc_want_height(svh, interval, height), want, "{line}");
                want_heights += 1;
            }
            "scenario" => {
                let length: usize = f[2].parse().expect("length");
                chain = VecChain(Vec::with_capacity(length));
                scenarios += 1;
            }
            "n" => {
                // Format: n <h> <ts> <blockver> <stakever> ,v1,v2...
                let votes = f[5]
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.parse().expect("vote version"))
                    .collect();
                chain.0.push(VersionNode {
                    height: f[1].parse().expect("height"),
                    timestamp: f[2].parse().expect("ts"),
                    block_version: f[3].parse().expect("blockver"),
                    stake_version: f[4].parse().expect("stakever"),
                    vote_versions: votes,
                });
            }
            "median" => {
                let want: i64 = f[1].parse().expect("want");
                assert_eq!(calc_past_median_time(&chain, tip(&chain)), want, "{line}");
            }
            "stakemaj" => {
                let min_ver: u32 = f[1].parse().expect("minver");
                let want: bool = f[2].parse().expect("want");
                assert_eq!(
                    is_stake_majority_version(&chain, min_ver, tip(&chain), &params),
                    want,
                    "{line} (scenario {scenarios})"
                );
            }
            "prior" => {
                let want: Option<u32> = if f[1] == "none" {
                    None
                } else {
                    Some(f[1].parse().expect("prior"))
                };
                assert_eq!(
                    calc_prior_stake_version(&chain, tip(&chain), &params),
                    want,
                    "{line} (scenario {scenarios})"
                );
            }
            "voter" => {
                let want_ver: u32 = f[1].parse().expect("ver");
                let want_height: i64 = f[2].parse().expect("height");
                let (got_ver, got_height) = calc_voter_version(&chain, tip(&chain), &params);
                assert_eq!(got_ver, want_ver, "{line} (scenario {scenarios})");
                assert_eq!(
                    got_height.unwrap_or(-1),
                    want_height,
                    "{line} (scenario {scenarios})"
                );
            }
            "stakever" => {
                let want: u32 = f[1].parse().expect("want");
                assert_eq!(
                    calc_stake_version(&chain, tip(&chain), &params),
                    want,
                    "{line} (scenario {scenarios})"
                );
            }
            "blockmaj" => {
                let min_ver: i32 = f[1].parse().expect("minver");
                let want: bool = f[2].parse().expect("want");
                assert_eq!(
                    is_majority_version(
                        &chain,
                        min_ver,
                        Some(tip(&chain)),
                        params.block_reject_num_required,
                        &params,
                    ),
                    want,
                    "{line} (scenario {scenarios})"
                );
            }
            other => panic!("unknown row tag {other}"),
        }
    }

    assert_eq!(want_heights, 60, "want height samples");
    assert_eq!(scenarios, 18, "chain scenarios");
}
