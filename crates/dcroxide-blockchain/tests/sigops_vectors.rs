// SPDX-License-Identifier: ISC
//! Replay of dcrd's signature operation counting and stakebase amount
//! verdicts generated inside dcrd's internal/blockchain package
//! (`data/sigops_vectors.txt`): `CountSigOps`/`CountP2SHSigOps` over
//! P2SH redeem scripts bearing checksig operations, `checkNumSigOps`
//! accumulation against the block limit, and
//! `checkStakeBaseAmounts`/`getStakeBaseAmounts`/`getStakeTreeFees`
//! over vote sets against a fabricated utxo view.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use dcroxide_blockchain::validate::{
    ChainSubsidyParams, check_num_sig_ops, check_stake_base_amounts, count_p2sh_sig_ops,
    count_sig_ops, get_stake_base_amounts, get_stake_tree_fees,
};
use dcroxide_blockchain::{RuleError, UtxoEntry};
use dcroxide_chaincfg::simnet_params;
use dcroxide_stake::TxType;
use dcroxide_standalone::{SubsidyCache, SubsidySplitVariant};
use dcroxide_testutil::unhex;
use dcroxide_wire::{MsgTx, OutPoint};

type UtxoKey = ([u8; 32], u32, i8);

fn utxo_key(op: &OutPoint) -> UtxoKey {
    (op.hash.0, op.index, op.tree)
}

fn kind_of<T>(result: &Result<T, RuleError>) -> String {
    match result {
        Ok(_) => "ok".to_string(),
        Err(e) => e.kind.kind_name().to_string(),
    }
}

fn parse_variant(s: &str) -> SubsidySplitVariant {
    match s {
        "0" => SubsidySplitVariant::Original,
        "1" => SubsidySplitVariant::Dcp0010,
        "2" => SubsidySplitVariant::Dcp0012,
        other => panic!("unknown variant {other}"),
    }
}

fn parse_txs(s: &str) -> Vec<MsgTx> {
    s.split(',')
        .map(|h| MsgTx::from_bytes(&unhex(h)).expect("tx").0)
        .collect()
}

#[test]
fn sigops_vectors() {
    let params = simnet_params();
    let mut subsidy_cache = SubsidyCache::new(ChainSubsidyParams(&params));
    let data = include_str!("data/sigops_vectors.txt");

    let mut utxos: BTreeMap<UtxoKey, UtxoEntry> = BTreeMap::new();
    let mut counts = [0usize; 6];

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "utxo2" => {
                let bytes = unhex(f[1]);
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes);
                let key = (
                    hash,
                    f[2].parse().expect("index"),
                    f[3].parse().expect("tree"),
                );
                let entry = UtxoEntry::new(
                    f[4].parse().expect("amount"),
                    unhex(f[12]),
                    f[6].parse().expect("height"),
                    f[7].parse().expect("blockindex"),
                    f[5].parse().expect("sver"),
                    false,
                    false,
                    TxType::Regular,
                    None,
                );
                utxos.insert(key, entry);
            }
            "cso" => {
                let coinbase: bool = f[1].parse().expect("coinbase");
                let ssgen: bool = f[2].parse().expect("ssgen");
                let treasury: bool = f[3].parse().expect("treasury");
                let (tx, _) = MsgTx::from_bytes(&unhex(f[4])).expect("tx");
                let want: i64 = f[5].parse().expect("count");
                assert_eq!(
                    count_sig_ops(&tx, coinbase, ssgen, treasury),
                    want,
                    "{line}"
                );
                counts[0] += 1;
            }
            "cpso" => {
                let coinbase: bool = f[1].parse().expect("coinbase");
                let stakebase: bool = f[2].parse().expect("stakebase");
                let treasury: bool = f[3].parse().expect("treasury");
                let (tx, _) = MsgTx::from_bytes(&unhex(f[4])).expect("tx");
                let result = count_p2sh_sig_ops(
                    &tx,
                    coinbase,
                    stakebase,
                    |op| utxos.get(&utxo_key(op)).cloned(),
                    treasury,
                );
                assert_eq!(kind_of(&result), f[6], "{line}");
                if f[5] != "-" {
                    let want: i64 = f[5].parse().expect("count");
                    assert_eq!(result.expect(line), want, "{line}: count");
                }
                counts[1] += 1;
            }
            "cnso" => {
                let index: usize = f[1].parse().expect("index");
                let stake_tree: bool = f[2].parse().expect("staketree");
                let cum: i64 = f[3].parse().expect("cum");
                let treasury: bool = f[4].parse().expect("treasury");
                let (tx, _) = MsgTx::from_bytes(&unhex(f[5])).expect("tx");
                let result = check_num_sig_ops(
                    &tx,
                    |op| utxos.get(&utxo_key(op)).cloned(),
                    index,
                    stake_tree,
                    cum,
                    treasury,
                );
                assert_eq!(kind_of(&result), f[7], "{line}");
                if f[6] != "-" {
                    let want: i64 = f[6].parse().expect("count");
                    assert_eq!(result.expect(line), want, "{line}: count");
                }
                counts[2] += 1;
            }
            "sba" => {
                let height: i64 = f[1].parse().expect("height");
                let variant = parse_variant(f[2]);
                let txs = parse_txs(f[3]);
                let result = check_stake_base_amounts(
                    &mut subsidy_cache,
                    height,
                    &txs,
                    |op| utxos.get(&utxo_key(op)).cloned(),
                    variant,
                );
                assert_eq!(kind_of(&result), f[4], "{line}");
                counts[3] += 1;
            }
            "gsba" => {
                let txs = parse_txs(f[1]);
                let result = get_stake_base_amounts(&txs, |op| utxos.get(&utxo_key(op)).cloned());
                assert_eq!(kind_of(&result), f[3], "{line}");
                if f[2] != "-" {
                    let want: i64 = f[2].parse().expect("amount");
                    assert_eq!(result.expect(line), want, "{line}: amount");
                }
                counts[4] += 1;
            }
            "gstf" => {
                let height: i64 = f[1].parse().expect("height");
                let treasury: bool = f[2].parse().expect("treasury");
                let variant = parse_variant(f[3]);
                let txs = parse_txs(f[4]);
                let result = get_stake_tree_fees(
                    &mut subsidy_cache,
                    height,
                    &txs,
                    |op| utxos.get(&utxo_key(op)).cloned(),
                    treasury,
                    variant,
                );
                assert_eq!(kind_of(&result), f[6], "{line}");
                if f[5] != "-" {
                    let want: i64 = f[5].parse().expect("fee");
                    assert_eq!(result.expect(line), want, "{line}: fee");
                }
                counts[5] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [40, 40, 40, 25, 25, 25], "row counts");
}
