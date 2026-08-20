// SPDX-License-Identifier: ISC
//! The acceptance gauntlet's mixpool step (dcrd `mempool.go:1351-1357`):
//! a transaction that is not a mix transaction may not spend an output a
//! current pair request depends on.
//!
//! dcrd carries `mixpool.NonMixSpendsPairRequest` in its mempool config
//! and consults it for every transaction, so an unmixed spend of a
//! reserved output is rejected with `ErrMixpoolDoubleSpend` before it can
//! displace the pair request.  dcroxide reached that verdict nowhere: the
//! error kind existed but nothing raised it, and a non-mix transaction
//! spending a pair-request output was accepted and relayed (RVW-006).
//!
//! Both directions matter.  The probe firing must reject, and — because
//! the probe is optional and a pool built without one silently skips the
//! step — the same transaction must be accepted when no probe is
//! installed, which is what makes the first assertion evidence that the
//! step ran rather than evidence that the transaction was bad anyway.

// The shared harness does bounded test arithmetic.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::{chain_from_init, error_kind, harness_policy, parse_tx};
use dcroxide_chaincfg::mainnet_params;
use dcroxide_mempool::{MixpoolProbe, TxPool};
use dcroxide_wire::MsgTx;

/// A probe with dcrd's two answers, fixed for the run.
struct FixedProbe(bool);

impl MixpoolProbe for FixedProbe {
    fn non_mix_spends_pair_request(&self, _tx: &MsgTx) -> bool {
        self.0
    }
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
        accept(Some(FixedProbe(true))),
        Err("ErrMixpoolDoubleSpend".to_string()),
    );
}

#[test]
fn the_same_spend_is_accepted_when_no_pair_request_covers_it() {
    assert_eq!(accept(Some(FixedProbe(false))), Ok(()));
}

/// dcrd's nil-closure guard (`mempool.go:1353`): no mixpool means no
/// reserved outputs, not a blanket rejection.
#[test]
fn a_pool_without_a_probe_skips_the_step() {
    assert_eq!(accept(None), Ok(()));
}
