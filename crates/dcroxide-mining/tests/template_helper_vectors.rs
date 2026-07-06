// SPDX-License-Identifier: ISC
//! Replay of dcrd's block template building block behavior generated
//! inside dcrd's internal/mining package
//! (`data/template_helper_vectors.txt`): coinbase construction across
//! networks, heights, agenda states, subsidy split variants, and
//! payment addresses (byte for byte, with dcrd's random extra nonce
//! extracted from its own output), treasurybase construction, parent
//! sorting by votes including the top-block tie handling, the fee per
//! kilobyte calculation, and the template merkle and commitment
//! roots.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::HashMap;

use dcroxide_blockchain::validate::ChainSubsidyParams;
use dcroxide_chaincfg::{Params, mainnet_params, simnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_gcs::blockcf2::PrevScripter;
use dcroxide_mining::{
    TxAncestorStats, TxDesc, VoteDesc, calc_block_commitment_root_v1, calc_block_merkle_root,
    calc_fee_per_kb, create_coinbase_tx, create_treasury_base_tx, sort_parents_by_votes,
    standard_coinbase_op_return,
};
use dcroxide_stake::TxType;
use dcroxide_standalone::{SubsidyCache, SubsidySplitVariant};
use dcroxide_testutil::unhex;
use dcroxide_txscript::stdaddr::decode_address;
use dcroxide_wire::{MsgBlock, MsgTx, OutPoint, TX_TREE_REGULAR};

fn raw_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn ssv(v: &str) -> SubsidySplitVariant {
    match v {
        "0" => SubsidySplitVariant::Original,
        "1" => SubsidySplitVariant::Dcp0010,
        "2" => SubsidySplitVariant::Dcp0012,
        other => panic!("unknown split variant {other}"),
    }
}

/// Extract the extra nonce from a standard 12-byte height+nonce
/// OP_RETURN script emitted by dcrd.
fn extract_nonce(script: &[u8]) -> u64 {
    // OP_RETURN OP_DATA_12 <4-byte height> <8-byte nonce>.
    assert_eq!(script[0], 0x6a, "not an op return");
    assert_eq!(script[1], 12, "unexpected push length");
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&script[6..14]);
    u64::from_le_bytes(nonce)
}

struct MapPrevScripter {
    scripts: HashMap<([u8; 32], u32, i8), Vec<u8>>,
}

impl PrevScripter for MapPrevScripter {
    fn prev_script(&self, prev_out: &OutPoint) -> Option<(u16, &[u8])> {
        self.scripts
            .get(&(prev_out.hash.0, prev_out.index, prev_out.tree))
            .map(|s| (0, s.as_slice()))
    }
}

#[test]
fn template_helper_vectors() {
    let main_params = mainnet_params();
    let sim_params = simnet_params();
    let params_for = |net: &str| -> &Params {
        match net {
            "mainnet" => &main_params,
            "simnet" => &sim_params,
            other => panic!("unknown network {other}"),
        }
    };
    let data = include_str!("data/template_helper_vectors.txt");
    let mut addr_str = String::new();
    let mut counts = [0usize; 6];

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "addr" => addr_str = f[1].to_string(),
            "cbtx" => {
                // cbtx <net> <height> <voters> <useaddr> <treasury>
                //      <ssv> <txhex>
                let params = params_for(f[1]);
                let height: i64 = f[2].parse().expect("height");
                let voters: u16 = f[3].parse().expect("voters");
                let use_addr = f[4] == "true";
                let treasury = f[5] == "true";
                let variant = ssv(f[6]);
                let (want_tx, _) = MsgTx::from_bytes(&unhex(f[7])).expect("tx");

                // Recover dcrd's random extra nonce from its own
                // op-return output (absent for the block-one ledger
                // case).
                let op_return = want_tx
                    .tx_out
                    .iter()
                    .find(|out| out.value == 0 && out.pk_script.first() == Some(&0x6a))
                    .map(|out| out.pk_script.clone())
                    .unwrap_or_else(|| {
                        standard_coinbase_op_return(height as u32, 0).expect("op return")
                    });

                let addr = if use_addr {
                    Some(decode_address(&addr_str, params).expect("address"))
                } else {
                    None
                };
                let mut cache = SubsidyCache::new(ChainSubsidyParams(params));
                let tx = create_coinbase_tx(
                    &mut cache,
                    &[0x00, 0x00],
                    &op_return,
                    height,
                    addr.as_ref(),
                    voters,
                    params,
                    treasury,
                    variant,
                );
                assert_eq!(raw_hex(&tx.serialize()), f[7], "{line}");
                counts[0] += 1;
            }
            "tbtx" => {
                // tbtx <net> <height> <voters> <txhex>
                let params = params_for(f[1]);
                let height: i64 = f[2].parse().expect("height");
                let voters: u16 = f[3].parse().expect("voters");
                let (want_tx, _) = MsgTx::from_bytes(&unhex(f[4])).expect("tx");
                let nonce = extract_nonce(&want_tx.tx_out[1].pk_script);
                let mut cache = SubsidyCache::new(ChainSubsidyParams(params));
                let tx = create_treasury_base_tx(&mut cache, height, voters, nonce)
                    .expect("treasurybase");
                assert_eq!(raw_hex(&tx.serialize()), f[4], "{line}");
                counts[1] += 1;
            }
            "spv" => {
                // spv <name> <topbyte:votes> <blocks byte:votes csv|->
                //     <result byte csv|->
                let (top_byte, top_votes) = f[2].split_once(':').expect("top");
                let mut top = Hash::ZERO;
                top.0[0] = u8::from_str_radix(top_byte, 16).expect("byte");
                let mut votes: HashMap<[u8; 32], usize> = HashMap::new();
                votes.insert(top.0, top_votes.parse().expect("votes"));
                let mut blocks: Vec<Hash> = Vec::new();
                if f[3] != "-" {
                    for entry in f[3].split(',') {
                        let (byte, n) = entry.split_once(':').expect("entry");
                        let mut h = Hash::ZERO;
                        h.0[0] = u8::from_str_radix(byte, 16).expect("byte");
                        votes.insert(h.0, n.parse().expect("votes"));
                        blocks.push(h);
                    }
                }
                let dummy_vote = VoteDesc {
                    vote_hash: Hash::ZERO,
                    ticket_hash: Hash::ZERO,
                    approves_parent: false,
                };
                let sorted = sort_parents_by_votes(
                    |hashes| {
                        hashes
                            .iter()
                            .map(|h| vec![dummy_vote; votes.get(&h.0).copied().unwrap_or_default()])
                            .collect()
                    },
                    top,
                    &blocks,
                    &main_params,
                );
                let result = if sorted.is_empty() {
                    "-".to_string()
                } else {
                    sorted
                        .iter()
                        .map(|h| format!("{:02x}", h.0[0]))
                        .collect::<Vec<_>>()
                        .join(",")
                };
                assert_eq!(result, f[4], "{line}");
                counts[2] += 1;
            }
            "fkb" => {
                // fkb <txhex> <fee> <ancfees> <ancsize> <ratebits>
                let (tx, _) = MsgTx::from_bytes(&unhex(f[1])).expect("tx");
                let tx_hash = tx.tx_hash();
                let tx_size = tx.serialize_size() as i64;
                let desc = TxDesc {
                    tx,
                    tx_hash,
                    tree: TX_TREE_REGULAR,
                    tx_type: TxType::Regular,
                    added_unix: 0,
                    height: 0,
                    fee: f[2].parse().expect("fee"),
                    total_sig_ops: 0,
                    tx_size,
                };
                let stats = TxAncestorStats {
                    fees: f[3].parse().expect("fees"),
                    size_bytes: f[4].parse().expect("size"),
                    ..TxAncestorStats::default()
                };
                let rate = calc_fee_per_kb(&desc, &stats);
                assert_eq!(format!("{:016x}", rate.to_bits()), f[5], "{line}");
                counts[3] += 1;
            }
            "mrk" => {
                // mrk <active> <regular csv> <stake csv> <root>
                let parse_list = |s: &str| -> Vec<MsgTx> {
                    s.split(',')
                        .map(|h| MsgTx::from_bytes(&unhex(h)).expect("tx").0)
                        .collect()
                };
                let regular = parse_list(f[2]);
                let stakes = parse_list(f[3]);
                let root = calc_block_merkle_root(&regular, &stakes, f[1] == "true");
                assert_eq!(raw_hex(&root.0), f[4], "{line}");
                counts[4] += 1;
            }
            "ccr" => {
                // ccr <blockhex> <prevscript> <root>
                let (block, _) = MsgBlock::from_bytes(&unhex(f[1])).expect("block");
                let prev_script = unhex(f[2]);
                let spend_in = &block.transactions[1].tx_in[0].previous_out_point;
                let mut scripts = HashMap::new();
                scripts.insert(
                    (spend_in.hash.0, spend_in.index, spend_in.tree),
                    prev_script,
                );
                let prev = MapPrevScripter { scripts };
                let root = calc_block_commitment_root_v1(&block, &prev).expect("root");
                assert_eq!(raw_hex(&root.0), f[3], "{line}");
                counts[5] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [11, 4, 6, 4, 2, 1], "row counts");
}
