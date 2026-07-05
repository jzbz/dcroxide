// SPDX-License-Identifier: ISC
//! Replay of dcrd's positional validation verdicts generated inside
//! dcrd's internal/blockchain package (`data/positional_vectors.txt`):
//! `checkDifficultyPositional` (EMA, forced-BLAKE3, and the
//! candidate-anchor walk over solved regnet headers),
//! `checkBlockHeaderPositional` (median time, the testnet3
//! minimum-time rule and max-diff checkpoint on a base-offset chain
//! around height 962928, height commitments, and old-version-majority
//! rejection), `checkBlockPositional` with expired transactions, the
//! DCP0005 violation classifier, and the small pure helpers.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::RuleError;
use dcroxide_blockchain::difficulty::{ChainView, DiffNode};
use dcroxide_blockchain::sequencelock::SequenceLock;
use dcroxide_blockchain::stakever::VersionNode;
use dcroxide_blockchain::thresholdstate::{VoteChainView, VoteNode};
use dcroxide_blockchain::validate::{
    check_block_header_positional, check_block_positional, check_difficulty_positional,
    dcp0005_constants, is_dcp0005_violation, is_expired_tx, is_finalized_transaction,
    sequence_lock_active, vote_bits_approve_parent,
};
use dcroxide_chaincfg::{Params, mainnet_params, regnet_params, simnet_params, testnet3_params};
use dcroxide_testutil::{hex, unhex};
use dcroxide_wire::{BlockHeader, CurrencyNet, MsgBlock, MsgTx};

/// One synthetic node carrying both difficulty and vote data.
#[derive(Clone)]
struct FullNode {
    diff: DiffNode,
    vote: VoteNode,
}

/// A single-branch chain whose lowest node sits at `base`, mirroring
/// the dump's truncated parent chains (walks park at the base exactly
/// like dcrd walks park on a nil parent).
struct OffsetChain {
    base: i64,
    nodes: Vec<FullNode>,
}

impl ChainView for OffsetChain {
    fn node(&self, height: i64) -> Option<DiffNode> {
        if height < self.base {
            return None;
        }
        self.nodes
            .get((height - self.base) as usize)
            .map(|n| n.diff)
    }
}

impl VoteChainView for OffsetChain {
    fn vote_node(&self, height: i64) -> Option<VoteNode> {
        if height < self.base {
            return None;
        }
        self.nodes
            .get((height - self.base) as usize)
            .map(|n| n.vote.clone())
    }
}

fn kind_of(result: Result<(), RuleError>) -> String {
    match result {
        Ok(()) => "ok".to_string(),
        Err(e) => e.kind.kind_name().to_string(),
    }
}

#[test]
fn positional_vectors() {
    let data = include_str!("data/positional_vectors.txt");

    let mut params: Params = mainnet_params();
    let mut chain = OffsetChain {
        base: 0,
        nodes: Vec::new(),
    };
    let mut counts = [0usize; 10];

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "hash" => {
                let want = dcp0005_constants()
                    .iter()
                    .find(|(name, _)| format!("block{}", &f[1][5..]) == *name || *name == f[1])
                    .map(|(_, h)| *h)
                    .unwrap_or_else(|| panic!("unknown hash constant {}", f[1]));
                assert_eq!(hex(&want.0), f[2], "{line}");
                counts[0] += 1;
            }
            "scenario" => {
                params = match f[2] {
                    "mainnet-major" | "mainnet-mixed" => mainnet_params(),
                    "simnet" => simnet_params(),
                    "regnet" => regnet_params(),
                    "tall-testnet3" | "testnet3" => testnet3_params(),
                    other => panic!("unknown scenario {other}"),
                };
                chain = OffsetChain {
                    base: f[4].parse().expect("base"),
                    nodes: Vec::new(),
                };
                counts[1] += 1;
            }
            "n" => {
                let height: i64 = f[1].parse().expect("height");
                chain.nodes.push(FullNode {
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
            "dpos" => {
                let (header, _) = BlockHeader::from_bytes(&unhex(f[1])).expect("header");
                let tip = chain.nodes.last().expect("tip").diff;
                assert_eq!(
                    kind_of(check_difficulty_positional(&chain, &header, &tip, &params)),
                    f[2],
                    "{line}"
                );
                counts[2] += 1;
            }
            "hpos" => {
                let fast_add: bool = f[1].parse().expect("fastadd");
                let (header, _) = BlockHeader::from_bytes(&unhex(f[2])).expect("header");
                let tip_height = chain.nodes.last().expect("tip").diff.height;
                assert_eq!(
                    kind_of(check_block_header_positional(
                        &chain,
                        &header,
                        Some(tip_height),
                        fast_add,
                        &params
                    )),
                    f[3],
                    "{line}"
                );
                counts[3] += 1;
            }
            "bpos" => {
                let fast_add: bool = f[1].parse().expect("fastadd");
                let (block, _) = MsgBlock::from_bytes(&unhex(f[2])).expect("block");
                let tip_height = chain.nodes.last().expect("tip").diff.height;
                assert_eq!(
                    kind_of(check_block_positional(
                        &chain,
                        &block,
                        Some(tip_height),
                        fast_add,
                        &params
                    )),
                    f[3],
                    "{line}"
                );
                counts[4] += 1;
            }
            "dcp5" => {
                let net = CurrencyNet(f[1].parse().expect("net"));
                let (header, _) = BlockHeader::from_bytes(&unhex(f[2])).expect("header");
                let want: bool = f[3].parse().expect("bool");
                let block_hash = header.block_hash();
                assert_eq!(
                    is_dcp0005_violation(net, &header, &block_hash),
                    want,
                    "{line}"
                );
                counts[5] += 1;
            }
            "vba" => {
                let bits: u16 = f[1].parse().expect("bits");
                let want: bool = f[2].parse().expect("bool");
                assert_eq!(vote_bits_approve_parent(bits), want, "{line}");
                counts[6] += 1;
            }
            "exp" => {
                let tx = MsgTx {
                    expiry: f[1].parse().expect("expiry"),
                    ..Default::default()
                };
                let height: i64 = f[2].parse().expect("height");
                let want: bool = f[3].parse().expect("bool");
                assert_eq!(is_expired_tx(&tx, height), want, "{line}");
                counts[7] += 1;
            }
            "sla" => {
                let lock = SequenceLock {
                    min_height: f[1].parse().expect("minh"),
                    min_time: f[2].parse().expect("mint"),
                };
                let height: i64 = f[3].parse().expect("height");
                let time: i64 = f[4].parse().expect("time");
                let want: bool = f[5].parse().expect("bool");
                assert_eq!(sequence_lock_active(&lock, height, time), want, "{line}");
                counts[8] += 1;
            }
            "fin" => {
                let (tx, _) = MsgTx::from_bytes(&unhex(f[1])).expect("tx");
                let height: i64 = f[2].parse().expect("height");
                let time: i64 = f[3].parse().expect("time");
                let want: bool = f[4].parse().expect("bool");
                assert_eq!(is_finalized_transaction(&tx, height, time), want, "{line}");
                counts[9] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [6, 6, 72, 96, 40, 16, 8, 10, 10, 12], "row counts");
}
