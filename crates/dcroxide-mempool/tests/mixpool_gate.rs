// SPDX-License-Identifier: ISC
//! The acceptance gauntlet's two mixpool steps (dcrd
//! `mempool.go:1547-1561`): a transaction that is not a mix transaction
//! may not spend an output a current pair request depends on, nor an
//! output controlled by a misbehaving mixing peer.
//!
//! dcrd carries `mixpool.NonMixSpendsPairRequest` in its mempool config
//! and consults it for every transaction, so an unmixed spend of a
//! reserved output is rejected with `ErrMixpoolDoubleSpend` before it can
//! displace the pair request.  dcroxide reached that verdict nowhere: the
//! error kind existed but nothing raised it, and a non-mix transaction
//! spending a pair-request output was accepted and relayed (RVW-006).
//! The second step, `MisbehavingMixSpend`, wired to the observer's
//! `MisbehavingTx` (`server.go:4132-4134`), rejects a spend of an output
//! the observer has struck with `ErrMixingMisbehavior`, right after the
//! first.
//!
//! Both directions matter.  The probe firing must reject, and — because
//! the probe is optional and a pool built without one silently skips the
//! steps — the same transaction must be accepted when no probe is
//! installed, which is what makes the first assertion evidence that the
//! step ran rather than evidence that the transaction was bad anyway.

// The shared harness does bounded test arithmetic.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::{FakeChain, apply_block_row, chain_from_init, error_kind, harness_policy, parse_tx};
use dcroxide_chaincfg::mainnet_params;
use dcroxide_mempool::{MixpoolProbe, TxPool};
use dcroxide_stake::{TxType, determine_tx_type};
use dcroxide_wire::MsgTx;

/// A probe with fixed answers to dcrd's two questions for the run: the
/// pair-request one and the misbehavior one.
struct FixedProbe {
    pair_request: bool,
    misbehaving: bool,
}

impl MixpoolProbe for FixedProbe {
    fn non_mix_spends_pair_request(&self, _tx: &MsgTx) -> bool {
        self.pair_request
    }

    fn misbehaving_mix_spend(&self, _tx: &MsgTx) -> bool {
        self.misbehaving
    }
}

fn probe(pair_request: bool, misbehaving: bool) -> Option<FixedProbe> {
    Some(FixedProbe {
        pair_request,
        misbehaving,
    })
}

/// The vectors' init row and its first transaction: a plain spend the
/// gauntlet otherwise accepts, so the only variable is the probe.
fn harness_tx() -> (Vec<String>, MsgTx) {
    let data = include_str!("data/txpool_vectors.txt");
    let mut lines = data.lines();
    let init: Vec<String> = lines
        .next()
        .expect("init row")
        .split(' ')
        .map(str::to_string)
        .collect();
    let tx = lines
        .find_map(|l| {
            l.strip_prefix("pt ")
                .map(|r| parse_tx(r.split(' ').next().expect("txhex")))
        })
        .expect("a pt row");
    (init, tx)
}

fn accept(probe: Option<FixedProbe>) -> Result<(), String> {
    let params = mainnet_params();
    let (init, tx) = harness_tx();
    let init_refs: Vec<&str> = init.iter().map(String::as_str).collect();
    let chain = chain_from_init(&init_refs);
    let policy = harness_policy(params.coinbase_maturity);
    let mut pool = TxPool::new(chain, policy, &params);
    if let Some(probe) = probe {
        pool.set_mixpool_probe(Box::new(probe));
    }
    pool.maybe_accept_transaction_pub(&tx, true)
        .map(|_| ())
        .map_err(|e| error_kind(&e))
}

#[test]
fn a_non_mix_spend_of_a_pair_request_output_is_rejected() {
    assert_eq!(
        accept(probe(true, false)),
        Err("ErrMixpoolDoubleSpend".to_string()),
    );
}

#[test]
fn a_non_mix_spend_of_a_misbehaving_peers_output_is_rejected() {
    assert_eq!(
        accept(probe(false, true)),
        Err("ErrMixingMisbehavior".to_string()),
    );
}

/// dcrd asks about the pair requests first and returns at the first
/// refusal, so a spend both steps refuse reports the pair request.
#[test]
fn the_pair_request_step_runs_before_the_misbehavior_step() {
    assert_eq!(
        accept(probe(true, true)),
        Err("ErrMixpoolDoubleSpend".to_string()),
    );
}

#[test]
fn the_same_spend_is_accepted_when_neither_step_refuses_it() {
    assert_eq!(accept(probe(false, false)), Ok(()));
}

/// The stake vectors' first section up to its first transaction: the
/// chain its init row builds with the rows ahead of that transaction
/// applied, and the section's first vote and first ticket purchase.  With
/// that height and the block the vote votes on known, both clear every
/// check ahead of the mixpool steps and then miss an input, the vote its
/// ticket and the ticket its funding transaction.
fn stake_battery() -> (FakeChain, MsgTx, MsgTx) {
    let data = include_str!("data/txstake_vectors.txt");
    let mut rows = data
        .lines()
        .skip_while(|l| *l != "net votes")
        .skip(1)
        .take_while(|l| !l.starts_with("net "));
    let init: Vec<&str> = rows.next().expect("init row").split(' ').collect();
    let mut chain = chain_from_init(&init);
    let mut txs = Vec::new();
    for row in rows {
        let f: Vec<&str> = row.split(' ').collect();
        match f[0] {
            "pt" => txs.push(parse_tx(f[1])),
            "sethgt" if txs.is_empty() => chain.best_height = f[1].parse().expect("height"),
            _ if txs.is_empty() => {
                apply_block_row(&mut chain, &f);
            }
            _ => {}
        }
    }
    let first = |tx_type: TxType| {
        txs.iter()
            .find(|tx| determine_tx_type(tx) == tx_type)
            .expect("the section offers one")
            .clone()
    };
    let (vote, ticket) = (first(TxType::SSGen), first(TxType::SStx));
    (chain, vote, ticket)
}

/// dcrd consults both mixpool closures for every transaction type, ahead
/// of the branch that sets votes and revocations apart
/// (`mempool.go:1547-1561`), so a vote and a ticket purchase are refused
/// as a regular spend is, and clear both steps when neither refuses them.
#[test]
fn both_steps_run_for_votes_and_ticket_purchases_too() {
    let params = mainnet_params();
    let (_, vote, ticket) = stake_battery();
    for (name, tx) in [("vote", &vote), ("ticket purchase", &ticket)] {
        for (pair_request, misbehaving, want) in [
            (true, false, Some("ErrMixpoolDoubleSpend")),
            (false, true, Some("ErrMixingMisbehavior")),
            (false, false, None),
        ] {
            let (chain, _, _) = stake_battery();
            let mut pool = TxPool::new(chain, harness_policy(params.coinbase_maturity), &params);
            pool.set_mixpool_probe(Box::new(FixedProbe {
                pair_request,
                misbehaving,
            }));
            match (pool.maybe_accept_transaction_pub(tx, true), want) {
                (Err(err), Some(want)) => assert_eq!(error_kind(&err), want, "{name}"),
                (Ok(missing), None) => assert!(!missing.is_empty(), "{name} misses an input"),
                (got, want) => panic!("{name}: got {got:?}, want {want:?}"),
            }
        }
    }
}

/// A probe that flags one transaction as spending a misbehaving mixing
/// peer's outputs and answers no to everything else.
struct FlagsOne(dcroxide_chainhash::Hash);

impl MixpoolProbe for FlagsOne {
    fn non_mix_spends_pair_request(&self, _tx: &MsgTx) -> bool {
        false
    }

    fn misbehaving_mix_spend(&self, tx: &MsgTx) -> bool {
        tx.tx_hash() == self.0
    }
}

/// dcrd runs both mixpool steps ahead of the pool double-spend check
/// (`mempool.go:1547-1561` against `:1572-1577`), so a flagged spend of
/// an output the pool already spends reports the misbehavior, and the
/// same spend unflagged reports the double spend.
#[test]
fn the_misbehavior_step_runs_before_the_pool_double_spend_check() {
    let params = mainnet_params();
    let (init, tx) = harness_tx();
    // A rival spending the same input, paying one atom more in fees.
    let mut rival = tx.clone();
    rival.tx_out[0].value -= 1;

    for (flagged, want) in [
        (rival.tx_hash(), "ErrMixingMisbehavior"),
        (dcroxide_chainhash::Hash([0; 32]), "ErrMempoolDoubleSpend"),
    ] {
        let init_refs: Vec<&str> = init.iter().map(String::as_str).collect();
        let mut pool = TxPool::new(
            chain_from_init(&init_refs),
            harness_policy(params.coinbase_maturity),
            &params,
        );
        pool.set_mixpool_probe(Box::new(FlagsOne(flagged)));
        pool.maybe_accept_transaction_pub(&tx, true)
            .expect("the original spend is accepted");
        let err = pool
            .maybe_accept_transaction_pub(&rival, true)
            .expect_err("the rival spends a pooled output");
        assert_eq!(error_kind(&err), want);
    }
}

/// dcrd's nil-closure guards (`mempool.go:1549`, `:1557`): no mixpool
/// means no reserved and no flagged outputs, not a blanket rejection.
#[test]
fn a_pool_without_a_probe_skips_both_steps() {
    assert_eq!(accept(None), Ok(()));
}
