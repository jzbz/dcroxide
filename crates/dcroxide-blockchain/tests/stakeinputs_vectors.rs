// SPDX-License-Identifier: ISC
//! Replay of dcrd's stake transaction input validation verdicts
//! generated inside dcrd's internal/blockchain package
//! (`data/stakeinputs_vectors.txt`): `checkTicketPurchaseInputs` over
//! tickets referencing a fabricated utxo view,
//! `checkVoteInputs`/`checkRevocationInputs` over crafted votes and
//! revocations straddling the maturity rules and commitment payment
//! corruptions, direct `calcTicketReturnAmounts` pinning (including
//! the auto-revocation PRNG remainder distribution), and the allowed
//! ticket input script form classifier.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use dcroxide_blockchain::chainio::deserialize_to_minimal_outputs;
use dcroxide_blockchain::validate::{
    ChainSubsidyParams, calc_ticket_return_amounts, check_revocation_inputs,
    check_ticket_purchase_inputs, check_vote_inputs, is_allowed_ticket_input_script_form,
    is_stake_submission,
};
use dcroxide_blockchain::{RuleError, UtxoEntry};
use dcroxide_chaincfg::mainnet_params;
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

fn kind_of(result: Result<(), RuleError>) -> String {
    match result {
        Ok(()) => "ok".to_string(),
        Err(e) => e.kind.kind_name().to_string(),
    }
}

#[test]
fn stakeinputs_vectors() {
    let params = mainnet_params();
    let mut subsidy_cache = SubsidyCache::new(ChainSubsidyParams(&params));
    let data = include_str!("data/stakeinputs_vectors.txt");

    let mut utxos: BTreeMap<UtxoKey, UtxoEntry> = BTreeMap::new();
    let mut counts = [0usize; 5];

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "utxo" => {
                // utxo <hash> <idx> <tree> <amount> <sver> <height>
                //   <txtype> <spent> <pkhex> <minouts|->
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
                    unhex(f[9]),
                    f[6].parse().expect("height"),
                    0,
                    f[5].parse().expect("sver"),
                    false,
                    false,
                    tx_type_from_u8(f[7].parse().expect("txtype")),
                    if f[10] == "-" {
                        None
                    } else {
                        Some(unhex(f[10]))
                    },
                );
                if f[8] == "1" {
                    entry.spend();
                }
                utxos.insert(key, entry);
            }
            "tpi" => {
                let (tx, _) = MsgTx::from_bytes(&unhex(f[1])).expect("tx");
                assert_eq!(
                    kind_of(check_ticket_purchase_inputs(&tx, |op| {
                        utxos.get(&utxo_key(op)).cloned()
                    })),
                    f[2],
                    "{line}"
                );
                counts[0] += 1;
            }
            "vote" => {
                // vote <height> <treasury> <autorev> <variant> <prevhdr>
                //   <txhex> <verdict>
                let tx_height: i64 = f[1].parse().expect("height");
                let treasury: bool = f[2].parse().expect("treasury");
                let auto_rev: bool = f[3].parse().expect("autorev");
                let variant = match f[4] {
                    "0" => SubsidySplitVariant::Original,
                    "1" => SubsidySplitVariant::Dcp0010,
                    "2" => SubsidySplitVariant::Dcp0012,
                    other => panic!("unknown variant {other}"),
                };
                let (prev_header, _) = BlockHeader::from_bytes(&unhex(f[5])).expect("header");
                let (tx, _) = MsgTx::from_bytes(&unhex(f[6])).expect("tx");
                assert_eq!(
                    kind_of(check_vote_inputs(
                        &mut subsidy_cache,
                        &tx,
                        tx_height,
                        |op| utxos.get(&utxo_key(op)).cloned(),
                        &params,
                        &prev_header,
                        treasury,
                        auto_rev,
                        variant,
                    )),
                    f[7],
                    "{line}"
                );
                counts[1] += 1;
            }
            "revoke" => {
                // revoke <height> <treasury> <autorev> <prevhdr> <txhex>
                //   <verdict>
                let tx_height: i64 = f[1].parse().expect("height");
                let treasury: bool = f[2].parse().expect("treasury");
                let auto_rev: bool = f[3].parse().expect("autorev");
                let (prev_header, _) = BlockHeader::from_bytes(&unhex(f[4])).expect("header");
                let (tx, _) = MsgTx::from_bytes(&unhex(f[5])).expect("tx");
                assert_eq!(
                    kind_of(check_revocation_inputs(
                        &tx,
                        tx_height,
                        |op| utxos.get(&utxo_key(op)).cloned(),
                        &params,
                        &prev_header,
                        treasury,
                        auto_rev,
                    )),
                    f[6],
                    "{line}"
                );
                counts[2] += 1;
            }
            "ctra" => {
                // ctra <isvote> <autorev> <price> <subsidy> <prevhdr>
                //   <minoutshex> <,amounts>
                let is_vote: bool = f[1].parse().expect("isvote");
                let auto_rev: bool = f[2].parse().expect("autorev");
                let price: i64 = f[3].parse().expect("price");
                let subsidy: i64 = f[4].parse().expect("subsidy");
                let prev_header_bytes = unhex(f[5]);
                let (outs, _) = deserialize_to_minimal_outputs(&unhex(f[6]));
                let want: Vec<i64> = f[7]
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.parse().expect("amount"))
                    .collect();
                assert_eq!(
                    calc_ticket_return_amounts(
                        &outs,
                        price,
                        subsidy,
                        &prev_header_bytes,
                        is_vote,
                        auto_rev
                    ),
                    want,
                    "{line}"
                );
                counts[3] += 1;
            }
            "aft" => {
                let pk = unhex(f[1]);
                let want_allowed: bool = f[2].parse().expect("allowed");
                let want_submission: bool = f[3].parse().expect("submission");
                assert_eq!(
                    is_allowed_ticket_input_script_form(&pk),
                    want_allowed,
                    "{line}"
                );
                assert_eq!(is_stake_submission(&pk), want_submission, "{line}");
                counts[4] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [40, 29, 31, 30, 20], "row counts");
}
