// SPDX-License-Identifier: ISC
//! Replay of dcrd's `checkTransactionsAndConnect` verdicts generated
//! inside dcrd's internal/blockchain package (`data/ctac_vectors.txt`):
//! regular and stake tree connect loops over a prepared view on
//! simnet, covering the coinbase and treasurybase subsidy
//! commitments, overpayment rules, empty stake trees, and input-check
//! propagation, with the spend journal lengths compared as well.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::RuleError;
use dcroxide_blockchain::UtxoEntry;
use dcroxide_blockchain::chainio::SpentTxOut;
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_blockchain::validate::{ChainSubsidyParams, check_transactions_and_connect};
use dcroxide_chaincfg::simnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_stake::TxType;
use dcroxide_standalone::{SubsidyCache, SubsidySplitVariant};
use dcroxide_testutil::unhex;
use dcroxide_wire::{BlockHeader, MsgTx, OutPoint};

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

#[test]
fn ctac_vectors() {
    let params = simnet_params();
    let mut subsidy_cache = SubsidyCache::new(ChainSubsidyParams(&params));
    // The dump uses a zero header with only the height set as the
    // previous header.
    let (mut prev_header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header");
    prev_header.height = 153;

    let data = include_str!("data/ctac_vectors.txt");
    let mut base_view = UtxoView::new();
    let mut counts = [0usize; 1];

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "u" => {
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
                base_view.insert_entry(&outpoint, entry);
            }
            "ctac" => {
                // ctac <staketree> <inputfees> <height> <voters>
                //   <txs|-> <verdict> <stxos>
                let stake_tree: bool = f[1].parse().expect("staketree");
                let input_fees: i64 = f[2].parse().expect("fees");
                let height: i64 = f[3].parse().expect("height");
                let voters: u16 = f[4].parse().expect("voters");
                let txs: Vec<MsgTx> = if f[5] == "-" {
                    Vec::new()
                } else {
                    f[5].split(',')
                        .map(|h| MsgTx::from_bytes(&unhex(h)).expect("tx").0)
                        .collect()
                };
                let want_stxos: usize = f[7].parse().expect("stxos");

                let mut view = base_view.clone();
                let mut stxos: Vec<SpentTxOut> = Vec::new();
                let tx_hashes = dcroxide_blockchain::utxoview::collect_tx_hashes(&txs);
                let result = check_transactions_and_connect(
                    &mut subsidy_cache,
                    input_fees,
                    height,
                    Hash::default(),
                    voters,
                    &prev_header,
                    &txs,
                    &tx_hashes,
                    &mut view,
                    Some(&mut stxos),
                    stake_tree,
                    true,
                    true,
                    SubsidySplitVariant::Original,
                    &params,
                );
                assert_eq!(kind_of(&result), f[6], "{line}");
                assert_eq!(stxos.len(), want_stxos, "{line}: stxo count");
                counts[0] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [9], "row counts");
}
