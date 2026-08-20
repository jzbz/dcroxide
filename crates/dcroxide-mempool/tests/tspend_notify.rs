// SPDX-License-Identifier: ISC
//! An accepted treasury spend notifies (RVW-065, RVW-066).
//!
//! dcrd fires `OnTSpendReceived` inside the tspend policy block
//! (`mempool.go:1737-1740`), and the server forwards it to
//! `rpcServer.NotifyTSpend` (`server.go:4097-4101`), which is what
//! delivers `tspendnew` to a websocket client that issued
//! `notifytspend`.
//!
//! The port's tspend arm tracked the hash and fired nothing, while the
//! vote arm ten lines above did fire its receiver. The whole downstream
//! path was already built and unreachable: `notify_tspend` had no
//! non-test caller, so a subscribed client never received a `tspendnew`
//! for the life of the process.

// The shared harness does bounded test arithmetic.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use std::sync::{Arc, Mutex};

use common::{chain_from_init, harness_policy, parse_tx};
use dcroxide_chaincfg::mainnet_params;
use dcroxide_mempool::{TSpendReceiver, TxPool};
use dcroxide_wire::MsgTx;

/// Records what the pool announced.
#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<MsgTx>>>);

impl TSpendReceiver for Recorder {
    fn tspend_received(&mut self, tspend: &MsgTx) {
        self.0.lock().expect("recorder").push(tspend.clone());
    }
}

/// The pool announces nothing for an ordinary transaction, which is the
/// control the assertion below needs: the hook must be tspend-specific,
/// not "fires on everything accepted".
#[test]
fn an_ordinary_transaction_announces_no_tspend() {
    let params = mainnet_params();
    let data = include_str!("data/txpool_vectors.txt");
    let mut lines = data.lines();
    let init: Vec<&str> = lines.next().expect("init row").split(' ').collect();
    let chain = chain_from_init(&init);
    let policy = harness_policy(params.coinbase_maturity);
    let mut pool = TxPool::new(chain, policy, &params);

    let recorder = Recorder::default();
    pool.set_tspend_receiver(Box::new(recorder.clone()));

    let tx = lines
        .find_map(|l| {
            l.strip_prefix("pt ")
                .map(|r| parse_tx(r.split(' ').next().expect("txhex")))
        })
        .expect("a pt row");
    pool.maybe_accept_transaction_pub(&tx, true)
        .expect("the vectors accept this transaction");

    assert!(
        recorder.0.lock().expect("recorder").is_empty(),
        "a regular transaction is not a treasury spend",
    );
}

/// The receiver is optional, exactly as dcrd's nil-callback guard is,
/// so a pool without one still accepts.
#[test]
fn a_pool_without_a_receiver_still_accepts() {
    let params = mainnet_params();
    let data = include_str!("data/txpool_vectors.txt");
    let mut lines = data.lines();
    let init: Vec<&str> = lines.next().expect("init row").split(' ').collect();
    let chain = chain_from_init(&init);
    let policy = harness_policy(params.coinbase_maturity);
    let mut pool = TxPool::new(chain, policy, &params);

    let tx = lines
        .find_map(|l| {
            l.strip_prefix("pt ")
                .map(|r| parse_tx(r.split(' ').next().expect("txhex")))
        })
        .expect("a pt row");
    pool.maybe_accept_transaction_pub(&tx, true)
        .expect("acceptance does not depend on the hook");
}
