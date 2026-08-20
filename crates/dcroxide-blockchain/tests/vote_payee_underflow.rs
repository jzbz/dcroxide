// SPDX-License-Identifier: ISC
//! A two-output vote carrying a treasury-vote payload must be rejected,
//! not panic (RVW-023).
//!
//! dcrd counts a vote's payment outputs in signed ints —
//! `numVotePayments := len(msgTx.TxOut) - 2 - extra`
//! (internal/blockchain/validate.go:2978) — so a vote with only the two
//! mandatory OP_RETURN outputs, whose vote-bits output doubles as a
//! `'T','V'` treasury-vote payload, yields -1 and falls into the
//! `ErrBadNumPayees` rejection just below.
//!
//! The port computed the same expression over `usize`.  `2 - 2 - 1`
//! underflows: a panic in any overflow-checked build — which is every
//! debug node, every `cargo test`, and cargo-fuzz's default profile —
//! and, since release builds use `panic = "abort"`, an outage rather
//! than an exception.  Release happened to reach dcrd's verdict anyway,
//! by wrapping to `usize::MAX` and failing the comparison for the wrong
//! reason.
//!
//! The vote must reference a real, mature, winning ticket to get this
//! far, so the shape is built from a vote the vectors already accept:
//! the inputs, the block-reference output, and the ticket entry are
//! left exactly as dcrd signed them, and only the output list is
//! reshaped into the trigger.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use dcroxide_blockchain::UtxoEntry;
use dcroxide_blockchain::validate::{ChainSubsidyParams, check_vote_inputs};
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

/// The vote-bits output reshaped into a treasury-vote payload:
/// `OP_RETURN OP_DATA_35 'T' 'V' <32-byte tspend hash> <vote>`.
///
/// 35 bytes clears both gates it has to pass at once — the vote-bits
/// push length (2..=75, dcroxide-stake `check_ssgen_votes`) and the
/// one-tuple treasury payload (2 + 33, `get_ssgen_treasury_votes`) — so
/// the single output satisfies the vote-bits checks and still parses as
/// one treasury vote, which is what drives `extra` to 1.
fn treasury_vote_bits_script() -> Vec<u8> {
    let mut script = vec![0x6a, 0x23, b'T', b'V'];
    script.extend_from_slice(&[0x11u8; 32]);
    script.push(dcroxide_stake::TREASURY_VOTE_YES);
    assert_eq!(script.len(), 37);
    script
}

#[test]
fn a_two_output_vote_with_a_treasury_payload_is_rejected_not_panicked() {
    let params = mainnet_params();
    let mut subsidy_cache = SubsidyCache::new(ChainSubsidyParams(&params));
    let data = include_str!("data/stakeinputs_vectors.txt");

    // The vectors' own utxo set, so the ticket the vote spends is the
    // real mature one dcrd signed against.
    let mut utxos: BTreeMap<UtxoKey, UtxoEntry> = BTreeMap::new();
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

    // A vote the vectors accept outright, on a treasury-active chain:
    // everything ahead of the payee count already passes for it, so the
    // reshape below is the only thing under test.
    let row = data
        .lines()
        .map(|l| l.split(' ').collect::<Vec<&str>>())
        .find(|f| f[0] == "vote" && f[2] == "true" && f[7] == "ok")
        .expect("an accepted treasury-active vote vector");
    let tx_height: i64 = row[1].parse().expect("height");
    let variant = match row[4] {
        "0" => SubsidySplitVariant::Original,
        "1" => SubsidySplitVariant::Dcp0010,
        "2" => SubsidySplitVariant::Dcp0012,
        other => panic!("unknown variant {other}"),
    };
    let (prev_header, _) = BlockHeader::from_bytes(&unhex(row[5])).expect("header");
    let (mut tx, _) = MsgTx::from_bytes(&unhex(row[6])).expect("tx");

    assert!(
        tx.tx_out.len() > 2,
        "the source vote must have payment outputs to strip",
    );

    // Keep the inputs and the block-reference output — they carry the
    // stakebase subsidy and the voted-on height the checks ahead of the
    // payee count consult — and reshape the rest into the trigger.
    tx.tx_out.truncate(2);
    tx.tx_out[1].pk_script = treasury_vote_bits_script();
    // dcrd `wire.TxVersionTreasury`, required once the payload parses as votes.
    tx.version = dcroxide_stake::TX_VERSION_TREASURY;

    // Without this the vote would reach the payee count with extra == 0
    // and 2 - 2 - 0 would not underflow at all: the assertion below
    // would pass for a reason that has nothing to do with the fix.
    let votes = dcroxide_stake::check_ssgen_votes(&tx).expect("the reshaped vote still parses");
    assert_eq!(
        votes.len(),
        1,
        "the payload must contribute exactly one treasury vote"
    );

    // Pre-fix this panics with 'attempt to subtract with overflow'
    // instead of returning, and the test fails by aborting.
    let err = check_vote_inputs(
        &mut subsidy_cache,
        &tx,
        tx_height,
        |op| utxos.get(&utxo_key(op)),
        &params,
        &prev_header,
        true,
        row[3].parse().expect("autorev"),
        variant,
    )
    .expect_err("a vote with no payment outputs cannot match its ticket's commitments");
    assert_eq!(err.kind.kind_name(), "ErrBadNumPayees");
}
