// SPDX-License-Identifier: ISC
//! Lock-order regression for the mempool consult in pair-request
//! acceptance (RVW-001).
//!
//! The daemon has one order between these two mutexes: **tx pool, then
//! mixpool**. The acceptance gauntlet established it — a non-mix
//! transaction is checked against the mixpool's current pair requests
//! while the tx pool's own guard is held (RVW-006).
//!
//! RVW-001 needs the traffic to flow the other way: pair-request
//! acceptance has to know whether the memory pool already spends the
//! outputs a request claims. dcrd asks that inside
//! `mixpoolChain.FetchUtxoEntry`, which runs under the mixpool's own
//! mutex — reproducing that structure here would take the tx-pool lock
//! while holding the mixpool's, and close an AB-BA against the
//! gauntlet.
//!
//! So the answer is computed first, before the mixpool guard is taken,
//! and passed in as a predicate. This pins that: the two orders run
//! concurrently and both must finish.
//!
//! Revert to asking inside the pool and the peer thread holds the
//! mixpool while waiting on the tx pool that the gauntlet thread holds
//! while waiting on the mixpool. Neither reports, and the receives time
//! out rather than the test hanging.

// Test-harness arithmetic over a fixed height.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use dcroxide_blockchain::process::Chain;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_dcrec::secp256k1::PrivateKey;
use dcroxide_mixing::{PoolMessage, SCRIPT_CLASS_P2PKH_V0, sign_message};
use dcroxide_netsync::manager::SyncMixPool;
use dcroxide_wire::{MixPairReqUTXO, MsgMixPairReq, OutPoint};

/// How long the gauntlet-order thread holds the tx pool before reaching
/// for the mixpool, so the peer-order thread has time to get in.
const HANDOFF: Duration = Duration::from_millis(300);

/// Generous next to `HANDOFF`, so only a real deadlock trips it.
const DEADLINE: Duration = Duration::from_secs(20);

/// A signed pair request that reaches the acceptance gauntlet's UTXO
/// loop, which is where the fetcher — and, in the design this guards
/// against, the tx-pool lock — would be reached.
fn pair_request(tip_height: i64) -> MsgMixPairReq {
    let mut bytes = [0u8; 32];
    bytes[0] = 0x11;
    bytes[31] = 7;
    let priv_key = PrivateKey::from_bytes(&bytes).expect("private key");
    let id = priv_key.public_key().serialize_compressed();
    let mut hash = [0u8; 32];
    hash[0] = 7;
    let mut pr = MsgMixPairReq {
        signature: [0u8; 64],
        identity: id,
        expiry: (tip_height + 10) as u32,
        mix_amount: 10_000_000,
        script_class: SCRIPT_CLASS_P2PKH_V0.to_string(),
        tx_version: 1,
        lock_time: 0,
        message_count: 1,
        input_value: 10_100_000,
        utxos: vec![MixPairReqUTXO {
            out_point: OutPoint {
                hash: Hash(hash),
                index: 7,
                tree: 0,
            },
            script: Vec::new(),
            pub_key: id.to_vec(),
            signature: vec![0u8; 64],
            opcode: 0,
        }],
        change: None,
        flags: 0,
        pairing_flags: 0,
    };
    sign_message(&mut pr, &priv_key).expect("sign pair request");
    pr
}

#[test]
fn pair_request_acceptance_never_holds_the_mixpool_across_the_tx_pool() {
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
    // Building it also installs the gauntlet's mixpool probe, which is
    // the edge this order has to stay clear of.
    let mix_pool =
        dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone(), &tx_pool);

    let (done_tx, done_rx) = mpsc::channel::<&'static str>();
    let (held_tx, held_rx) = mpsc::channel::<()>();
    let gauntlet_through = Arc::new(AtomicBool::new(false));

    // Thread A — the gauntlet order: tx pool, then mixpool.
    let gauntlet = {
        let tx_pool = Arc::clone(&tx_pool);
        let mix_pool = Arc::clone(&mix_pool);
        let done_tx = done_tx.clone();
        let through = Arc::clone(&gauntlet_through);
        std::thread::spawn(move || {
            let pool = tx_pool.lock().expect("tx pool mutex poisoned");
            held_tx.send(()).expect("signal tx pool held");
            // Give the peer thread time to start its own acceptance.
            std::thread::sleep(HANDOFF);
            let _mix = mix_pool.lock().expect("mix pool mutex poisoned");
            through.store(true, Ordering::SeqCst);
            drop(_mix);
            drop(pool);
            done_tx.send("gauntlet").expect("gauntlet reports");
        })
    };

    // Thread B — the peer order, through the real adapter.
    let peer = {
        let mix_pool = Arc::clone(&mix_pool);
        let tx_pool = Arc::clone(&tx_pool);
        let done_tx = done_tx.clone();
        std::thread::spawn(move || {
            held_rx.recv().expect("tx pool held");
            let mut sync_pool = dcroxide_node::mixnode::NodeSyncMixPool::new(mix_pool, tx_pool);
            // Rejected — the fixture's outpoint is not in this chain —
            // but it travels the whole path first, which is what
            // matters here.
            let _ = sync_pool.accept_message(&PoolMessage::PR(pair_request(0)), 1);
            done_tx.send("peer").expect("peer reports");
        })
    };

    let mut reported = Vec::new();
    for _ in 0..2 {
        match done_rx.recv_timeout(DEADLINE) {
            Ok(who) => reported.push(who),
            Err(_) => panic!(
                "deadlock: only {reported:?} finished; the mixpool guard was held across \
                 the tx pool (gauntlet through the mixpool: {})",
                gauntlet_through.load(Ordering::SeqCst),
            ),
        }
    }
    reported.sort_unstable();
    assert_eq!(reported, vec!["gauntlet", "peer"]);

    gauntlet.join().expect("gauntlet thread");
    peer.join().expect("peer thread");
}
