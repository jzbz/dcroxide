// SPDX-License-Identifier: ISC
//! The descriptions of the mempool rule errors that name an outpoint
//! or a serialization type.  They reach clients verbatim, as the text
//! of `sendrawtransaction`'s "rejected transaction" error, and dcrd
//! formats them with `%v`: a `wire.OutPoint` through its `String`
//! method (`hash:index`), and a `wire.TxSerializeType`, a bare
//! `uint16`, as its number.  The vector replays compare kinds only, so
//! the text is pinned here.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::{chain_from_init, error_kind, harness_policy, parse_hash, parse_tx};
use dcroxide_chaincfg::mainnet_params;
use dcroxide_mempool::{PoolError, TxPool, check_transaction_standard};
use dcroxide_stake::TxType;
use dcroxide_testutil::unhex;
use dcroxide_wire::{BlockHeader, MsgTx, TxSerializeType};

/// The description of a rule error.
fn description(err: &PoolError) -> &str {
    match err {
        PoolError::Rule(rule) => &rule.description,
        PoolError::Other(text) => text,
    }
}

/// The description dcrd builds for the rejection kind, or `None` for a
/// kind whose text names neither an outpoint nor a type.
fn dcrd_description(kind: &str, tx: &MsgTx) -> Option<Vec<String>> {
    let tx_hash = tx.tx_hash();
    match kind {
        // mempool.go:2213-2216; any input may be the first missing
        // parent, so every input's rendering is a candidate.
        "ErrOrphan" => Some(
            tx.tx_in
                .iter()
                .map(|tx_in| {
                    format!(
                        "orphan transaction {tx_hash} references output {} of unknown \
                         or fully-spent transaction",
                        tx_in.previous_out_point
                    )
                })
                .collect(),
        ),
        // mempool.go:1393-1396.
        "ErrTooManyVotes" => Some(vec![format!(
            "transaction {} in the pool with more than 5 votes",
            tx.tx_in[1].previous_out_point
        )]),
        // mempool.go:1404-1407.
        "ErrDuplicateRevocation" => Some(vec![format!(
            "transaction {} in the pool as a revocation. Only one revocation is \
             allowed.",
            tx.tx_in[0].previous_out_point
        )]),
        _ => None,
    }
}

/// Replay the votes section of the stake battery, which rejects a vote
/// as an orphan, a sixth vote on one ticket, and a second revocation of
/// a ticket, and compare each of those descriptions with dcrd's.
#[test]
fn outpoint_descriptions_render_as_dcrd_outpoint_strings() {
    let data = include_str!("data/txstake_vectors.txt");
    let lines: Vec<&str> = data.lines().collect();
    assert_eq!(lines[0], "net votes");
    let treasury_at = lines
        .iter()
        .position(|l| *l == "net treasury")
        .expect("treasury section");
    let rows = &lines[1..treasury_at];

    let params = mainnet_params();
    let init: Vec<&str> = rows[0].split(' ').collect();
    let mut pool = TxPool::new(
        chain_from_init(&init),
        harness_policy(params.coinbase_maturity),
        &params,
    );

    let mut checked = Vec::new();
    for line in &rows[1..] {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "sethgt" => pool.chain.best_height = f[1].parse().expect("height"),
            "besthash" => {
                let hash = parse_hash(f[1]);
                let (header, _) = BlockHeader::from_bytes(&unhex(f[2])).expect("header");
                pool.chain.headers.insert(hash.0, header);
                pool.chain.best_hash = hash;
            }
            "utxo" => {
                let tx = parse_tx(f[1]);
                let height: i64 = f[2].parse().expect("height");
                let block_index: u32 = f[3].parse().expect("block index");
                pool.chain
                    .utxos
                    .add_tx_outs(&tx, height, block_index, false);
            }
            "pt" => {
                let tx = parse_tx(f[1]);
                let tag: u64 = f[4].parse().expect("tag");
                let result = pool.process_transaction(&tx, f[2] == "true", f[3] == "true", tag);
                let Err(err) = result else {
                    continue;
                };
                let kind = error_kind(&err);
                assert_eq!(kind, f[5], "{line}: kind");
                if let Some(expected) = dcrd_description(&kind, &tx) {
                    let got = description(&err);
                    assert!(
                        expected.iter().any(|want| want == got),
                        "{kind}: description {got:?}, dcrd renders one of {expected:?}"
                    );
                    checked.push(kind);
                }
            }
            "rmtx" => {
                let tx = parse_tx(f[1]);
                pool.remove_transaction(&tx, &tx.tx_hash(), f[2] == "true");
            }
            "prune" => {
                pool.prune_stake_tx(f[1].parse().expect("sdiff"), f[2].parse().expect("height"));
            }
            // Read-only checks the vector replay already makes.
            "state" | "vhb" | "disap" | "tsh" => {}
            other => panic!("unknown row tag {other}"),
        }
    }

    // Every kind is exercised, so none of the three can regress
    // unnoticed.
    for kind in ["ErrOrphan", "ErrTooManyVotes", "ErrDuplicateRevocation"] {
        assert!(
            checked.iter().any(|k| k == kind),
            "{kind} not reached: {checked:?}"
        );
    }
}

/// A transaction serialized without its witness is rejected as
/// non-standard with the numeric serialization type (policy.go:303-305
/// formats the `uint16` with `%v`), not the Rust variant name.
#[test]
fn the_serialize_type_description_is_the_wire_number() {
    for (ser_type, number) in [
        (TxSerializeType::NoWitness, 1),
        (TxSerializeType::OnlyWitness, 2),
    ] {
        let tx = MsgTx {
            ser_type,
            ..MsgTx::default()
        };
        let err = check_transaction_standard(&tx, TxType::Regular, 1, 0, 1000)
            .expect_err("only full serializations are standard");
        assert_eq!(
            err.description,
            format!("transaction is not serialized with all required data -- type {number}")
        );
    }
}
