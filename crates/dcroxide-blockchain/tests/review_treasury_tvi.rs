// SPDX-License-Identifier: ISC
//! The treasury rejections in `checkBlockContext` that no vector
//! reached: a second treasurybase in the stake tree
//! (`ErrMultipleTreasurybases`), a treasury spend off a treasury vote
//! interval (`ErrNotTVI`), and a treasury spend on one before a full
//! voting window is possible (`ErrInvalidTVoteWindow`), dcrd
//! validate.go:2140-2146 and 2313-2336, exercised in dcrd by
//! treasury_test.go's `twotb0`, `bnottvi0` and `boink1` blocks.
//!
//! The chain, the parent stake node and the block come from the
//! replay in `blockcontext_vectors.rs`: its first `ok` block at height
//! 154 on simnet (treasury agenda active) is mutated here, with the
//! merkle commitment recomputed so each case reaches its rule.  The
//! verdicts follow from dcrd's source rather than from a dcrd run.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::RuleErrorKind;
use dcroxide_blockchain::difficulty::{ChainView, DiffNode};
use dcroxide_blockchain::stakever::VersionNode;
use dcroxide_blockchain::thresholdstate::{VoteChainView, VoteNode};
use dcroxide_blockchain::validate::{check_block_context, determine_check_tx_flags};
use dcroxide_chaincfg::{Params, simnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_stake::ticketnode::{Node, StakeNodeParams};
use dcroxide_testutil::unhex;
use dcroxide_txscript::{OP_DATA_32, OP_DATA_33, OP_DATA_64, OP_RETURN, OP_TGEN, OP_TSPEND};
use dcroxide_wire::{MsgBlock, MsgTx, OutPoint, TxIn, TxOut};

struct VecChain(Vec<(DiffNode, VoteNode)>);

impl ChainView for VecChain {
    fn node(&self, height: i64) -> Option<DiffNode> {
        usize::try_from(height)
            .ok()
            .and_then(|h| self.0.get(h))
            .map(|n| n.0)
    }
}

impl dcroxide_blockchain::stakever::VersionChainView for VecChain {
    fn node(&self, height: i64) -> Option<VersionNode> {
        self.vote_node(height).map(|n| n.node)
    }
}

impl VoteChainView for VecChain {
    fn vote_node(&self, height: i64) -> Option<VoteNode> {
        usize::try_from(height)
            .ok()
            .and_then(|h| self.0.get(h))
            .map(|n| n.1.clone())
    }
}

fn parse_hash(s: &str) -> Hash {
    Hash(unhex(s).try_into().expect("32 bytes"))
}

fn parse_hashes(s: &str) -> Vec<Hash> {
    if s == "-" {
        return Vec::new();
    }
    s.split(',').map(parse_hash).collect()
}

/// The replayed chain, parent stake state, and first accepted
/// full-validation block with a treasurybase.
struct Fixture {
    chain: VecChain,
    stake_node: Node,
    parent_pool_size: u32,
    parent_final_state: [u8; 6],
    block: MsgBlock,
}

fn fixture(params: &Params) -> Fixture {
    let stake_params = StakeNodeParams {
        votes_per_block: params.tickets_per_block,
        stake_validation_begin_height: params.stake_validation_height,
        stake_enable_height: params.stake_enabled_height,
        ticket_expiry_blocks: params.ticket_expiry,
    };
    let mut stake_node = Node::genesis(stake_params);
    let mut chain = VecChain(Vec::new());
    let mut parent_pool_size = 0;
    let mut parent_final_state = [0u8; 6];
    for line in include_str!("data/blockcontext_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "sblk" => {
                stake_node = stake_node
                    .connect(
                        parse_hash(f[1]),
                        &parse_hashes(f[2]),
                        &[],
                        &parse_hashes(f[3]),
                    )
                    .expect("stake connect");
            }
            "n" => {
                let height: i64 = f[1].parse().expect("height");
                let timestamp: i64 = f[2].parse().expect("ts");
                chain.0.push((
                    DiffNode {
                        height,
                        timestamp,
                        bits: f[3].parse().expect("bits"),
                        sbits: f[4].parse().expect("sbits"),
                        pool_size: f[5].parse().expect("pool"),
                        fresh_stake: f[6].parse().expect("fresh"),
                    },
                    VoteNode {
                        node: VersionNode {
                            height,
                            timestamp,
                            block_version: f[7].parse().expect("blockver"),
                            stake_version: f[8].parse().expect("stakever"),
                            vote_versions: Vec::new(),
                        },
                        votes: Vec::new(),
                    },
                ));
            }
            "parentstake" => {
                parent_pool_size = f[1].parse().expect("poolsize");
                parent_final_state.copy_from_slice(&unhex(f[2]));
            }
            "cbc" if f[1] == "false" && f[3] == "ok" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[2])).expect("block");
                if !block.stransactions.is_empty()
                    && dcroxide_standalone::is_treasury_base(&block.stransactions[0])
                {
                    return Fixture {
                        chain,
                        stake_node,
                        parent_pool_size,
                        parent_final_state,
                        block,
                    };
                }
            }
            _ => {}
        }
    }
    panic!("no accepted block with a treasurybase in the vectors");
}

impl Fixture {
    fn tip_height(&self) -> i64 {
        self.chain.0.last().expect("tip").0.height
    }

    fn check(
        &self,
        block: &MsgBlock,
        fast_add: bool,
        params: &Params,
    ) -> Result<(), RuleErrorKind> {
        check_block_context(
            &self.chain,
            block,
            Some(self.tip_height()),
            fast_add,
            true,
            self.parent_pool_size,
            self.parent_final_state,
            Some(&self.stake_node),
            params,
        )
        .map_err(|e| e.kind)
    }

    /// The block with extra stake transactions appended and its merkle
    /// commitment recomputed in whichever form the original used.
    fn with_stake_txs(&self, extra: &[MsgTx]) -> MsgBlock {
        let mut block = self.block.clone();
        let combined = dcroxide_standalone::calc_combined_tx_tree_merkle_root(
            &block.transactions,
            &block.stransactions,
        ) == block.header.merkle_root;
        block.stransactions.extend_from_slice(extra);
        if combined {
            block.header.merkle_root = dcroxide_standalone::calc_combined_tx_tree_merkle_root(
                &block.transactions,
                &block.stransactions,
            );
        } else {
            block.header.stake_root =
                dcroxide_standalone::calc_tx_tree_merkle_root(&block.stransactions);
        }
        block
    }
}

/// A structurally valid treasury spend (dcrd `stake.CheckTSpend`); the
/// signature is not verified by the contextual checks.
fn tspend(expiry: u32) -> MsgTx {
    let amount: i64 = 100_000_000;
    let mut sig_script = vec![OP_DATA_64];
    sig_script.extend_from_slice(&[0x01; 64]);
    sig_script.push(OP_DATA_33);
    sig_script.extend_from_slice(&unhex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    ));
    sig_script.push(OP_TSPEND);
    let mut commitment = vec![OP_RETURN, OP_DATA_32];
    commitment.extend_from_slice(&amount.to_le_bytes());
    commitment.extend_from_slice(&[0x5a; 24]);
    let mut payout = vec![OP_TGEN, 0x76, 0xa9, 0x14];
    payout.extend_from_slice(&[0x42; 20]);
    payout.extend_from_slice(&[0x88, 0xac]);
    MsgTx {
        version: 3,
        tx_in: vec![TxIn {
            previous_out_point: OutPoint {
                hash: Hash([0; 32]),
                index: u32::MAX,
                tree: 0,
            },
            sequence: u32::MAX,
            value_in: amount,
            block_height: 0,
            block_index: u32::MAX,
            signature_script: sig_script,
        }],
        tx_out: vec![
            TxOut {
                value: 0,
                version: 0,
                pk_script: commitment,
            },
            TxOut {
                value: amount,
                version: 0,
                pk_script: payout,
            },
        ],
        lock_time: 0,
        expiry,
        ..MsgTx::default()
    }
}

#[test]
fn treasury_context_rejections() {
    let params = simnet_params();
    let fx = fixture(&params);
    let height = fx.tip_height() + 1;
    assert!(
        determine_check_tx_flags(&fx.chain, Some(fx.tip_height()), &params)
            .expect("flags")
            .is_treasury_enabled()
    );
    assert!(dcroxide_stake::is_tspend(&tspend(1000)));
    assert_eq!(fx.check(&fx.block, false, &params), Ok(()));

    // A second treasurybase anywhere after the first (dcrd `twotb0`),
    // on both paths since the rule sits above the fast-add gate.
    let second_tb = fx.with_stake_txs(&[fx.block.stransactions[0].clone()]);
    for fast_add in [false, true] {
        assert_eq!(
            fx.check(&second_tb, fast_add, &params),
            Err(RuleErrorKind::MultipleTreasurybases),
            "fast add {fast_add}"
        );
    }

    // A treasury spend off a treasury vote interval (dcrd `bnottvi0`):
    // simnet's interval of 48 does not divide 154.  The TVI rules are
    // skipped under fast add, like dcrd's BFFastAdd.
    let tvi = params.treasury_vote_interval;
    assert_ne!(height as u64 % tvi, 0);
    let off_tvi = fx.with_stake_txs(&[tspend(10_000)]);
    assert_eq!(
        fx.check(&off_tvi, false, &params),
        Err(RuleErrorKind::NotTVI)
    );
    assert_eq!(fx.check(&off_tvi, true, &params), Ok(()));

    // On a treasury vote interval, the spend's expiry must leave a full
    // voting window (dcrd `boink1`).  An interval of 77 makes height
    // 154 one.
    let mut tvi_params = params.clone();
    tvi_params.treasury_vote_interval = 77;
    assert_eq!(height % 77, 0);
    let min_expiry = 2
        + tvi_params.stake_validation_height as u64
        + tvi_params.treasury_vote_interval * tvi_params.treasury_vote_interval_multiplier;
    let min_expiry = u32::try_from(min_expiry).expect("small");
    let early = fx.with_stake_txs(&[tspend(min_expiry - 1)]);
    assert_eq!(
        fx.check(&early, false, &tvi_params),
        Err(RuleErrorKind::InvalidTVoteWindow)
    );
    assert_eq!(fx.check(&early, true, &tvi_params), Ok(()));
    let in_window = fx.with_stake_txs(&[tspend(min_expiry)]);
    assert_eq!(fx.check(&in_window, false, &tvi_params), Ok(()));
}
