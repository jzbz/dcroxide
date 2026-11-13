// SPDX-License-Identifier: ISC
//! dcrd's TestVoteInputIndex (internal/blockchain/validate_test.go:1944-2002):
//! `checkVoteInputs` accepts a vote whose ticket input names the ticket's
//! first output and refuses one whose ticket input names any other.
//!
//! dcrd plays a regnet chain to stake validation height, takes a vote
//! from the next block and checks it with the original subsidy split.
//! Here the votes come from `data/stakeinputs_vectors.txt`, each one the
//! vectors accept against their own utxo set, and each is checked on
//! mainnet with the subsidy split its row carries, as it is and with its
//! ticket input moved to output 2 (validate.go:3111-3120). The stakebase
//! amount is checked against that subsidy before the index, so the vote
//! is accepted as it is first; the moved copy has the same stakebase and
//! so reaches the index check. As in dcrd, the view holds the ticket's
//! first output and not output 2, so the moved vote is refused for its
//! index; without that check it would be refused as spending a missing
//! output instead. The vectors already hold one vote whose ticket input
//! names output 1, and compare only its error kind; this pins dcrd's
//! output 2 and the text of the refusal.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use dcroxide_blockchain::UtxoEntry;
use dcroxide_blockchain::validate::check_vote_inputs;
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

/// The vectors' utxo set, so each vote finds the ticket the vectors pair
/// it with.
fn vector_utxos(data: &str) -> BTreeMap<UtxoKey, UtxoEntry> {
    let mut utxos = BTreeMap::new();
    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        if f[0] != "utxo" {
            continue;
        }
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
    utxos
}

#[test]
fn a_vote_must_spend_its_tickets_first_output() {
    let params = mainnet_params();
    let mut subsidy_cache = SubsidyCache::new(&params);
    let data = include_str!("data/stakeinputs_vectors.txt");
    let utxos = vector_utxos(data);

    let mut checked = 0usize;
    let mut checked_without_agendas = false;
    for row in data
        .lines()
        .map(|l| l.split(' ').collect::<Vec<&str>>())
        .filter(|f| f[0] == "vote" && f[7] == "ok")
    {
        // vote <height> <treasury> <autorev> <variant> <prevhdr> <txhex>
        //   <verdict>
        let tx_height: i64 = row[1].parse().expect("height");
        let treasury: bool = row[2].parse().expect("treasury");
        let auto_rev: bool = row[3].parse().expect("autorev");
        let variant = match row[4] {
            "0" => SubsidySplitVariant::Original,
            "1" => SubsidySplitVariant::Dcp0010,
            "2" => SubsidySplitVariant::Dcp0012,
            other => panic!("unknown variant {other}"),
        };
        let (prev_header, _) = BlockHeader::from_bytes(&unhex(row[5])).expect("header");
        let (vote, _) = MsgTx::from_bytes(&unhex(row[6])).expect("tx");
        let mut check = |tx: &MsgTx| {
            check_vote_inputs(
                &mut subsidy_cache,
                tx,
                tx_height,
                |op| utxos.get(&utxo_key(op)),
                &params,
                &prev_header,
                treasury,
                auto_rev,
                variant,
            )
        };

        assert_eq!(vote.tx_in[1].previous_out_point.index, 0);
        check(&vote).expect("the vote as the vectors hold it");

        let mut bad_vote = vote.clone();
        bad_vote.tx_in[1].previous_out_point.index = 2;
        assert!(
            !utxos.contains_key(&utxo_key(&bad_vote.tx_in[1].previous_out_point)),
            "the view must not hold output 2 of the ticket",
        );
        let err = check(&bad_vote).expect_err("a vote spending output 2 of its ticket");
        assert_eq!(err.kind.kind_name(), "ErrInvalidVoteInput");
        assert_eq!(
            err.description,
            format!(
                "vote {}:1 references output 2 instead of the first output",
                bad_vote.tx_hash()
            ),
        );

        checked += 1;
        checked_without_agendas |= !treasury && !auto_rev;
    }
    assert!(checked > 0, "the vectors hold accepted votes");
    // dcrd's test runs with the treasury and automatic revocations agendas
    // both off.
    assert!(
        checked_without_agendas,
        "an accepted vote with neither agenda active",
    );
}
