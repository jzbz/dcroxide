// SPDX-License-Identifier: ISC
//! Replay of dcrd's `checkConnectBlock` verdicts generated inside
//! dcrd's internal/blockchain package
//! (`data/connectblock_vectors.txt`): the full connect battery over a
//! real 154-node simnet chain — treasurybase and commitment root
//! checks, both tree connects with the stake fee carry-forward,
//! sequence lock enforcement, and the version 2 filter hash — plus
//! the stateless treasury spend checks, the pre-treasury coinbase
//! payout, the block one ledger, the added subsidy calculation, and
//! `checkBlockScripts` over both trees.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::RuleError;
use dcroxide_blockchain::UtxoEntry;
use dcroxide_blockchain::chainio::SpentTxOut;
use dcroxide_blockchain::difficulty::{ChainView, DiffNode};
use dcroxide_blockchain::stakever::VersionNode;
use dcroxide_blockchain::thresholdstate::{VoteChainView, VoteNode};
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_blockchain::validate::{
    ChainSubsidyParams, block_one_coinbase_pays_tokens, calculate_added_subsidy,
    check_block_scripts, check_connect_block, coinbase_pays_treasury_address,
    tspend_checks_stateless,
};
use dcroxide_chaincfg::simnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_stake::TxType;
use dcroxide_standalone::SubsidyCache;
use dcroxide_testutil::unhex;
use dcroxide_txscript::ScriptFlags;
use dcroxide_wire::{MsgBlock, MsgTx, OutPoint};

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

fn parse_hash(s: &str) -> Hash {
    let bytes = unhex(s);
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Hash(h)
}

fn kind_of<T>(result: &Result<T, RuleError>) -> String {
    match result {
        Ok(_) => "ok".to_string(),
        Err(e) => e.kind.kind_name().to_string(),
    }
}

fn parse_entry(f: &[&str]) -> (OutPoint, UtxoEntry) {
    let outpoint = OutPoint {
        hash: parse_hash(f[1]),
        index: f[2].parse().expect("idx"),
        tree: f[3].parse().expect("tree"),
    };
    let mut entry = UtxoEntry::new(
        f[4].parse().expect("amt"),
        unhex(f[10]),
        f[5].parse().expect("h"),
        f[6].parse().expect("bi"),
        f[7].parse().expect("sv"),
        false,
        false,
        TxType::Regular,
        if f[11] == "-" {
            None
        } else {
            Some(unhex(f[11]))
        },
    );
    entry.set_state_bits(f[8].parse().expect("st"));
    entry.set_packed_flags_bits(f[9].parse().expect("fl"));
    (outpoint, entry)
}

#[test]
fn connectblock_vectors() {
    let params = simnet_params();
    let mut subsidy_cache = SubsidyCache::new(ChainSubsidyParams(&params));
    let data = include_str!("data/connectblock_vectors.txt");

    let mut chain = VecChain(Vec::new());
    let mut parent: Option<MsgBlock> = None;
    let mut base_view = UtxoView::new();
    let mut cbs_view = UtxoView::new();
    let none_resolver = |_: &OutPoint| -> Option<UtxoEntry> { None };
    let mut counts = [0usize; 6];

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
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
            "parentblk" => {
                let (blk, _) = MsgBlock::from_bytes(&unhex(f[1])).expect("parent");
                base_view.set_best_hash(blk.header.block_hash());
                parent = Some(blk);
            }
            "u" => {
                let (outpoint, entry) = parse_entry(&f);
                base_view.insert_entry(&outpoint, entry);
            }
            "cbsu" => {
                let (outpoint, entry) = parse_entry(&f);
                cbs_view.insert_entry(&outpoint, entry);
            }
            "ccb" => {
                // ccb <block> <verdict> <filterhash|-> <stxos>
                let (block, _) = MsgBlock::from_bytes(&unhex(f[1])).expect("block");
                let parent = parent.as_ref().expect("parent first");
                let mut view = base_view.clone();
                let mut stxos: Vec<SpentTxOut> = Vec::new();
                let result = check_connect_block(
                    &chain,
                    &mut subsidy_cache,
                    block.header.height as i64,
                    block.header.block_hash(),
                    block.header.voters,
                    block.header.vote_bits,
                    &block,
                    parent,
                    &[],
                    &mut view,
                    &none_resolver,
                    Some(&mut stxos),
                    false,
                    &params,
                );
                assert_eq!(kind_of(&result), f[2], "{line}");
                if let Ok(filter_hash) = result {
                    assert_eq!(filter_hash, parse_hash(f[3]), "{line}: filter hash");
                    assert_eq!(view.best_hash(), block.header.block_hash(), "{line}");
                }
                assert_eq!(
                    stxos.len(),
                    f[4].parse::<usize>().expect("stxos"),
                    "{line}: stxo count"
                );
                counts[0] += 1;
            }
            "tsc" => {
                // tsc <prevheight> <block> <verdict>
                let prev_height: i64 = f[1].parse().expect("prevh");
                let (block, _) = MsgBlock::from_bytes(&unhex(f[2])).expect("block");
                let result = tspend_checks_stateless(prev_height, &block, &params);
                assert_eq!(kind_of(&result), f[3], "{line}");
                counts[1] += 1;
            }
            "cpta" => {
                // cpta <tx> <height> <voters> <verdict>
                let (tx, _) = MsgTx::from_bytes(&unhex(f[1])).expect("tx");
                let height: i64 = f[2].parse().expect("height");
                let voters: u16 = f[3].parse().expect("voters");
                let result = coinbase_pays_treasury_address(
                    &mut subsidy_cache,
                    &tx,
                    height,
                    voters,
                    &params,
                );
                assert_eq!(kind_of(&result), f[4], "{line}");
                counts[2] += 1;
            }
            "bocpt" => {
                // bocpt <tx> <verdict>
                let (tx, _) = MsgTx::from_bytes(&unhex(f[1])).expect("tx");
                let result = block_one_coinbase_pays_tokens(&tx, &params);
                assert_eq!(kind_of(&result), f[2], "{line}");
                counts[3] += 1;
            }
            "cas" => {
                // cas <block> <parent> <total>
                let (block, _) = MsgBlock::from_bytes(&unhex(f[1])).expect("block");
                let (cas_parent, _) = MsgBlock::from_bytes(&unhex(f[2])).expect("parent");
                assert_eq!(
                    calculate_added_subsidy(&block, &cas_parent),
                    f[3].parse::<i64>().expect("total"),
                    "{line}"
                );
                counts[4] += 1;
            }
            "cbs" => {
                // cbs <r|s> <flags> <autorev> <block> <verdict>
                let regular = f[1] == "r";
                let flags = ScriptFlags(f[2].parse().expect("flags"));
                let autorev: bool = f[3].parse().expect("autorev");
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                let result = check_block_scripts(&block, &cbs_view, regular, flags, autorev);
                assert_eq!(kind_of(&result), f[5], "{line}");
                counts[5] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [9, 4, 6, 8, 4, 5], "row counts");
}
