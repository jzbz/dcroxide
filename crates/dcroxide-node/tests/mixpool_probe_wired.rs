// SPDX-License-Identifier: ISC
//! The daemon's mixpool probe is wired into the transaction pool.
//!
//! The gauntlet step this feeds (dcrd's `NonMixSpendsPairRequest`, in
//! `crates/dcroxide-mempool/tests/mixpool_gate.rs`) is optional by
//! construction: a pool with no probe skips it and accepts the spend,
//! which is exactly dcrd's nil-closure behavior and exactly how a correct
//! gauntlet ends up doing nothing in a running node.  So the fix is only
//! real if the daemon's own pool carries a probe.
//!
//! [`shared_mix_pool`] installs it, which is why it takes the tx pool at
//! all — every construction site, the daemon's included, gets the wiring
//! or does not compile.  This pins that: drop the install and the
//! assertion below fails while everything else still passes.

use std::sync::{Arc, Mutex};

use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};

#[test]
fn building_the_shared_mixpool_installs_the_tx_pools_probe() {
    let params = dcroxide_chaincfg::simnet_params();
    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    );
    assert!(
        !tx_pool.lock().expect("tx pool").has_mixpool_probe(),
        "a freshly built pool has no probe; the assertion below would be vacuous",
    );

    let _mix_pool =
        dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone(), &tx_pool);

    assert!(
        tx_pool.lock().expect("tx pool").has_mixpool_probe(),
        "the daemon's tx pool must consult the mixpool during acceptance",
    );
}
