// SPDX-License-Identifier: ISC
//! Replay of dcrd's legacy difficulty algorithms over synthetic chains
//! generated inside dcrd's internal/blockchain package at the pinned
//! tag (`data/difficulty_vectors.txt`): each scenario carries the exact
//! per-node data (height, timestamp, bits, sbits, pool size, fresh
//! stake) plus dcrd's own outputs for the BLAKE-256 EMA retarget, the
//! testnet minimum-difficulty search, both stake difficulty algorithms,
//! and the BLAKE3 anchor calculation, alongside pure-function samples
//! for the difficulty merge and supply estimate.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::difficulty::{
    ChainView, DiffNode, calc_next_blake3_diff_from_anchor, calc_next_blake256_diff,
    calc_next_required_stake_difficulty_v1, calc_next_required_stake_difficulty_v2,
    estimate_supply, find_prev_testnet_difficulty, merge_difficulty,
};
use dcroxide_chaincfg::{Params, mainnet_params, simnet_params, testnet3_params};

struct VecChain(Vec<DiffNode>);

impl ChainView for VecChain {
    fn node(&self, height: i64) -> Option<DiffNode> {
        if height < 0 {
            return None;
        }
        self.0.get(height as usize).copied()
    }
}

fn params_for(name: &str) -> Params {
    match name {
        "mainnet" => mainnet_params(),
        "testnet3" => testnet3_params(),
        "simnet" => simnet_params(),
        other => panic!("unknown network {other}"),
    }
}

#[test]
fn difficulty_vectors() {
    let data = include_str!("data/difficulty_vectors.txt");
    let lines = data.lines();

    let mut merges = 0usize;
    let mut supplies = 0usize;
    let mut scenarios = 0usize;

    let mut params = mainnet_params();
    let mut chain = VecChain(Vec::new());

    for line in lines {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "merge" => {
                let (old, d1, d2, want): (i64, i64, i64, i64) = (
                    f[1].parse().expect("old"),
                    f[2].parse().expect("d1"),
                    f[3].parse().expect("d2"),
                    f[4].parse().expect("want"),
                );
                assert_eq!(merge_difficulty(old, d1, d2), want, "{line}");
                merges += 1;
            }
            "supply" => {
                let p = params_for(f[1]);
                let height: i64 = f[2].parse().expect("height");
                let want: i64 = f[3].parse().expect("want");
                assert_eq!(estimate_supply(&p, height), want, "{line}");
                supplies += 1;
            }
            "scenario" => {
                params = params_for(f[2]);
                let length: usize = f[3].parse().expect("length");
                chain = VecChain(Vec::with_capacity(length));
                scenarios += 1;
            }
            "n" => {
                chain.0.push(DiffNode {
                    height: f[1].parse().expect("height"),
                    timestamp: f[2].parse().expect("ts"),
                    bits: f[3].parse().expect("bits"),
                    sbits: f[4].parse().expect("sbits"),
                    pool_size: f[5].parse().expect("pool"),
                    fresh_stake: f[6].parse().expect("fresh"),
                });
            }
            "blake256" => {
                let delta: i64 = f[1].parse().expect("delta");
                let want: u32 = f[2].parse().expect("want");
                let tip = *chain.0.last().expect("tip");
                let got = calc_next_blake256_diff(&chain, &tip, tip.timestamp + delta, &params);
                assert_eq!(got, want, "{line} (net {})", params.name);
            }
            "findprev" => {
                let want: u32 = f[1].parse().expect("want");
                let tip = *chain.0.last().expect("tip");
                let got = find_prev_testnet_difficulty(&chain, tip.height, &params);
                assert_eq!(got, want, "{line} (net {})", params.name);
            }
            "stakev1" => {
                let want: i64 = f[1].parse().expect("want");
                let tip = *chain.0.last().expect("tip");
                let got = calc_next_required_stake_difficulty_v1(&chain, Some(&tip), &params);
                assert_eq!(got, want, "{line} (net {})", params.name);
            }
            "stakev2" => {
                let want: i64 = f[1].parse().expect("want");
                let tip = *chain.0.last().expect("tip");
                let got = calc_next_required_stake_difficulty_v2(&chain, Some(&tip), &params);
                assert_eq!(got, want, "{line} (net {})", params.name);
            }
            "blake3" => {
                let anchor_height: i64 = f[1].parse().expect("anchor");
                let want: u32 = f[2].parse().expect("want");
                let tip = *chain.0.last().expect("tip");
                let anchor = chain.node(anchor_height).expect("anchor node");
                let got = calc_next_blake3_diff_from_anchor(&tip, &anchor, &params);
                assert_eq!(got, want, "{line} (net {})", params.name);
            }
            other => panic!("unknown row tag {other}"),
        }
    }

    assert_eq!(merges, 40, "merge samples");
    assert_eq!(supplies, 36, "supply samples");
    assert_eq!(scenarios, 35, "chain scenarios");
}

/// The stake difficulty functions return the minimum before any tickets
/// can exist, including for the missing-node case.
#[test]
fn stake_difficulty_empty_chain() {
    let params = mainnet_params();
    let chain = VecChain(Vec::new());
    assert_eq!(
        calc_next_required_stake_difficulty_v1(&chain, None, &params),
        params.minimum_stake_diff
    );
    assert_eq!(
        calc_next_required_stake_difficulty_v2(&chain, None, &params),
        params.minimum_stake_diff
    );
}
