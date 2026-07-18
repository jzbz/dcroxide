// SPDX-License-Identifier: ISC
//! Replay of dcrd's `CheckTransactionInputs` verdicts and fees
//! generated inside dcrd's internal/blockchain package
//! (`data/txinputs_vectors.txt`): regular spends across every utxo
//! flavor (coinbase/expiry maturities, treasury-gen and stake-tagged
//! scripts, fraud proofs, amount ranges), coinbase early-outs and the
//! dcrd 2.2 treasurybase flow-through, treasury spends signed with
//! the published simnet Pi test key (incl. the spend amount
//! commitment check), votes summing their stakebase value-in, and
//! direct `verifyTSpendSignature` rows.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use dcroxide_blockchain::validate::{
    ChainSubsidyParams, check_transaction_inputs, verify_tspend_signature,
};
use dcroxide_blockchain::{RuleError, UtxoEntry};
use dcroxide_chaincfg::simnet_params;
use dcroxide_stake::TxType;
use dcroxide_standalone::{SubsidyCache, SubsidySplitVariant};
use dcroxide_testutil::unhex;
use dcroxide_wire::{BlockHeader, MsgTx, OutPoint};

type UtxoKey = ([u8; 32], u32, i8);

fn utxo_key(op: &OutPoint) -> UtxoKey {
    (op.hash.0, op.index, op.tree)
}

fn tx_type_from_u8(v: u8) -> TxType {
    match v {
        0 => TxType::Regular,
        1 => TxType::SStx,
        2 => TxType::SSGen,
        3 => TxType::SSRtx,
        4 => TxType::TAdd,
        5 => TxType::TSpend,
        6 => TxType::TreasuryBase,
        other => panic!("unknown tx type {other}"),
    }
}

fn kind_of(result: &Result<i64, RuleError>) -> String {
    match result {
        Ok(_) => "ok".to_string(),
        Err(e) => e.kind.kind_name().to_string(),
    }
}

#[test]
fn txinputs_vectors() {
    let params = simnet_params();
    let mut subsidy_cache = SubsidyCache::new(ChainSubsidyParams(&params));
    // The dump uses a fixed header with only the height set.
    let (mut prev_header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header");
    prev_header.height = 5000;
    let data = include_str!("data/txinputs_vectors.txt");

    let mut utxos: BTreeMap<UtxoKey, UtxoEntry> = BTreeMap::new();
    let mut counts = [0usize; 2];

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "utxo2" => {
                // utxo2 <hash> <idx> <tree> <amount> <sver> <height>
                //   <blockindex> <cb> <exp> <txtype> <spent> <pk>
                //   <minouts|->
                let bytes = unhex(f[1]);
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes);
                let key = (
                    hash,
                    f[2].parse().expect("index"),
                    f[3].parse().expect("tree"),
                );
                let mut entry = UtxoEntry::new(
                    f[4].parse().expect("amount"),
                    unhex(f[12]),
                    f[6].parse().expect("height"),
                    f[7].parse().expect("blockindex"),
                    f[5].parse().expect("sver"),
                    f[8] == "1",
                    f[9] == "1",
                    tx_type_from_u8(f[10].parse().expect("txtype")),
                    if f[13] == "-" {
                        None
                    } else {
                        Some(unhex(f[13]))
                    },
                );
                if f[11] == "1" {
                    entry.spend();
                }
                utxos.insert(key, entry);
            }
            "cti" => {
                // cti <height> <fraud> <treasury> <autorev> <txhex>
                //   <fee|-> <verdict>
                let tx_height: i64 = f[1].parse().expect("height");
                let fraud: bool = f[2].parse().expect("fraud");
                let treasury: bool = f[3].parse().expect("treasury");
                let auto_rev: bool = f[4].parse().expect("autorev");
                let (tx, _) = MsgTx::from_bytes(&unhex(f[5])).expect("tx");
                let result = check_transaction_inputs(
                    &mut subsidy_cache,
                    &tx,
                    tx_height,
                    |op| utxos.get(&utxo_key(op)).cloned(),
                    fraud,
                    &params,
                    &prev_header,
                    treasury,
                    auto_rev,
                    SubsidySplitVariant::Original,
                );
                assert_eq!(kind_of(&result), f[7], "{line}");
                if f[6] != "-" {
                    let want_fee: i64 = f[6].parse().expect("fee");
                    assert_eq!(result.expect(line), want_fee, "{line}: fee");
                }
                counts[0] += 1;
            }
            "vts" => {
                // vts <txhex> <sighex> <pubhex> <ok>
                let (tx, _) = MsgTx::from_bytes(&unhex(f[1])).expect("tx");
                let sig = unhex(f[2]);
                let pub_key = unhex(f[3]);
                let want: bool = f[4].parse().expect("ok");
                assert_eq!(
                    verify_tspend_signature(&tx, &sig, &pub_key).is_ok(),
                    want,
                    "{line}"
                );
                counts[1] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [78, 10], "row counts");
}
