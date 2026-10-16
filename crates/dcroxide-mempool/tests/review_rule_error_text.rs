// SPDX-License-Identifier: ISC
//! The descriptions of the mempool rule errors that name an outpoint
//! or a serialization type, of the vote rejections, and of the mixing
//! misbehavior rejection.
//! They reach clients verbatim, as the text of `sendrawtransaction`'s
//! "rejected transaction" error, and dcrd formats them with `%v`: a
//! `wire.OutPoint` through its `String` method (`hash:index`), and a
//! `wire.TxSerializeType`, a bare `uint16`, as its number.  The vector
//! replays compare kinds only, and no vector installs a mixpool probe,
//! so the text is pinned here.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::{apply_block_row, chain_from_init, error_kind, harness_policy, parse_tx};
use dcroxide_chaincfg::mainnet_params;
use dcroxide_mempool::{MixpoolProbe, PoolError, TxPool, check_transaction_standard};
use dcroxide_stake::{TxType, ssgen_block_voted_on};
use dcroxide_wire::{MsgTx, TxSerializeType};

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
        // mempool.go:2406-2409; any input may be the first missing
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
        // mempool.go:1597-1600.
        "ErrTooManyVotes" => Some(vec![format!(
            "transaction {} in the pool with more than 5 votes",
            tx.tx_in[1].previous_out_point
        )]),
        // mempool.go:1609-1612.
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
    let end = lines[1..]
        .iter()
        .position(|l| l.starts_with("net "))
        .expect("a section after the votes")
        + 1;
    let rows = &lines[1..end];

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
        if apply_block_row(&mut pool.chain, &f) {
            continue;
        }
        match f[0] {
            "sethgt" => pool.chain.best_height = f[1].parse().expect("height"),
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

/// The descriptions dcrd builds for the vote rejections that name the
/// vote's block, height or ticket (`mempool.go:1118-1130`, `:1150-1159`,
/// `:1196-1198`), at the chain state the row was processed at.
fn dcrd_vote_description(kind: &str, vote: &MsgTx, chain: &common::FakeChain) -> Option<String> {
    if !matches!(
        kind,
        "ErrOldVote"
            | "ErrFutureVote"
            | "ErrVoteBlockUnknown"
            | "ErrVoteBlockHeight"
            | "ErrIneligibleTicketVote"
    ) {
        return None;
    }
    let vote_hash = vote.tx_hash();
    let (voted_hash, voted_height) = ssgen_block_voted_on(vote);
    let best_height = chain.best_height;
    let text = match kind {
        "ErrOldVote" => format!(
            "vote {vote_hash} references old block height {voted_height} which is before \
             the current cutoff height of {}",
            best_height + 1 - 256
        ),
        "ErrFutureVote" => format!(
            "vote {vote_hash} references block height {voted_height} which is after the \
             maximum permitted future height {}",
            best_height + 5
        ),
        "ErrVoteBlockUnknown" => format!("vote {vote_hash} votes on unknown block {voted_hash}"),
        "ErrVoteBlockHeight" => format!(
            "vote {vote_hash} votes on block {voted_hash} (height {}) with incorrect height \
             {voted_height}",
            chain.headers[&voted_hash.0].height
        ),
        "ErrIneligibleTicketVote" => format!(
            "vote {vote_hash} votes on block {voted_hash} (height {voted_height}) with \
             ineligible ticket {}",
            vote.tx_in[1].previous_out_point.hash
        ),
        _ => return None,
    };
    Some(text)
}

/// Replay every vote section of the stake battery and compare the
/// description of each vote rejection that names a block, a height or a
/// ticket with the one dcrd builds; the battery reaches all five.
#[test]
fn vote_rejection_descriptions_are_dcrds() {
    let data = include_str!("data/txstake_vectors.txt");
    let params = mainnet_params();
    let mut checked = Vec::new();
    let mut pool = None;
    for line in data.lines() {
        if let Some(name) = line.strip_prefix("net ") {
            if name == "treasury" {
                break;
            }
            pool = None;
            continue;
        }
        let f: Vec<&str> = line.split(' ').collect();
        if f[0] == "init" {
            pool = Some(TxPool::new(
                chain_from_init(&f),
                harness_policy(params.coinbase_maturity),
                &params,
            ));
            continue;
        }
        let pool = pool.as_mut().expect("an init row first");
        if apply_block_row(&mut pool.chain, &f) {
            continue;
        }
        match f[0] {
            "sethgt" => pool.chain.best_height = f[1].parse().expect("height"),
            "oldvotes" => pool.policy.allow_old_votes = f[1] == "1",
            "utxo" => {
                let tx = parse_tx(f[1]);
                pool.chain.utxos.add_tx_outs(
                    &tx,
                    f[2].parse().expect("height"),
                    f[3].parse().expect("block index"),
                    false,
                );
            }
            "pt" => {
                let tx = parse_tx(f[1]);
                let result = pool.process_transaction(
                    &tx,
                    f[2] == "true",
                    f[3] == "true",
                    f[4].parse().expect("tag"),
                );
                let Err(err) = result else {
                    continue;
                };
                let kind = error_kind(&err);
                assert_eq!(kind, f[5], "{line}: kind");
                if let Some(want) = dcrd_vote_description(&kind, &tx, &pool.chain) {
                    assert_eq!(description(&err), want, "{kind}");
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
            "state" | "vhb" | "disap" => {}
            other => panic!("unknown row tag {other}"),
        }
    }
    for kind in [
        "ErrOldVote",
        "ErrFutureVote",
        "ErrVoteBlockUnknown",
        "ErrVoteBlockHeight",
        "ErrIneligibleTicketVote",
    ] {
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

/// A probe whose observer has struck every output, and which reserves
/// none for a pair request.
struct EveryOutputStruck;

impl MixpoolProbe for EveryOutputStruck {
    fn non_mix_spends_pair_request(&self, _tx: &MsgTx) -> bool {
        false
    }

    fn misbehaving_mix_spend(&self, _tx: &MsgTx) -> bool {
        true
    }
}

/// A non-mix spend of an output a misbehaving mixing peer controls is
/// rejected with dcrd's text, which names the transaction by its hash
/// (`mempool.go:1557-1560`).
#[test]
fn the_mixing_misbehavior_description_names_the_transaction() {
    let data = include_str!("data/txpool_vectors.txt");
    let mut lines = data.lines();
    let init: Vec<&str> = lines.next().expect("init row").split(' ').collect();
    let tx = lines
        .find_map(|l| {
            l.strip_prefix("pt ")
                .map(|r| parse_tx(r.split(' ').next().expect("txhex")))
        })
        .expect("a pt row");

    let params = mainnet_params();
    let mut pool = TxPool::new(
        chain_from_init(&init),
        harness_policy(params.coinbase_maturity),
        &params,
    );
    pool.set_mixpool_probe(Box::new(EveryOutputStruck));
    let err = pool
        .maybe_accept_transaction_pub(&tx, true)
        .expect_err("the probe flags the spend");
    assert_eq!(error_kind(&err), "ErrMixingMisbehavior");
    assert_eq!(
        description(&err),
        format!(
            "non-mix transaction {} spends outputs controlled by a misbehaving mixing peer",
            tx.tx_hash()
        )
    );
}
