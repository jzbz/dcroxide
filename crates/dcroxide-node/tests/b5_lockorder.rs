// SPDX-License-Identifier: ISC
//! Lock-order regression for the chain/mixpool pair (blocker B-5).
//!
//! The daemon has exactly one established order between these two
//! mutexes: **mixpool then chain**.  Every peer's mix-message intake
//! runs it — `dispatch` takes the sync-manager mutex, `NodeSyncMixPool::
//! accept_message` takes the mixpool mutex, and the pool's own tip and
//! UTXO lookups (`NodeMixChain::current_tip`,
//! `NodeMixUtxoFetcher::fetch_utxo_entry`) then take the chain mutex
//! while the pool guard is still held.
//!
//! `ChainNtfnHandler::drain_pending_winning_tickets` used to run the
//! opposite order: it held the chain guard across
//! `mix_pool.lock().misbehaving_block(..)`.  That is harmless only while
//! the drain itself runs under the sync-manager mutex (the netsync
//! adapter's `process_block` path), but the background template
//! generator installs `drain_pending` as its drain hook and fires it
//! from its own thread holding no locks whenever `--miningaddr` is set.
//! Generator thread: holds chain, waits for mixpool.  Peer thread: holds
//! mixpool, waits for chain.  AB-BA — the whole node wedges, remotely
//! triggerable by any unauthenticated inbound mix message.
//!
//! The test below pins the two threads into exactly that interleaving
//! against a real `Chain`, a real `NodeMixPool`, and the real
//! `drain_pending_winning_tickets`.  Revert the fix (put the mixpool
//! acquisition back inside the chain guard) and both threads block
//! forever: the `recv_timeout` expires and the test fails instead of
//! hanging.  With the fix the chain guard is dropped before the pool is
//! asked, so the peer-order thread walks straight through.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use dcroxide_blockchain::notifications::{BlockAcceptedNtfnsData, Notification};
use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};
use dcroxide_node::chainntfns::ChainNtfnHandler;

/// How long the peer-order thread keeps the mixpool guard before it
/// reaches for the chain, giving the drain thread time to get into its
/// own critical section.  Overshooting only costs wall time; a machine
/// too loaded to schedule the drain thread within this window makes the
/// test pass vacuously rather than fail spuriously.
const HANDOFF: Duration = Duration::from_millis(300);

/// The overall deadline for both threads.  Generous next to `HANDOFF`
/// so only a genuine deadlock trips it.
const DEADLINE: Duration = Duration::from_secs(20);

/// Both lock orders run concurrently and both complete: the winning-
/// tickets drain must not hold the chain mutex across its mixpool
/// acquisition.
///
/// Regression guard for B-5.  If `drain_pending_winning_tickets` again
/// calls `mix_pool.lock()` while its chain guard is live, the drain
/// thread parks on the mixpool holding the chain and the peer-order
/// thread parks on the chain holding the mixpool; neither channel send
/// ever happens and the assertions below fail on timeout.
#[test]
fn the_winning_tickets_drain_never_holds_the_chain_across_the_mixpool() {
    let params = dcroxide_chaincfg::simnet_params();
    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    // The real shared pool, holding its own Arc to the same chain — the
    // edge that makes mixpool-then-chain the mandatory order.
    let mix_pool = dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone());
    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    );

    // The genesis block is the only block this chain has, and the drain
    // must find it: a hash the chain cannot supply short-circuits the
    // refusal check and would never reach the pool at all.  Lowering the
    // stake validation height is what lets a height-zero block clear
    // dcrd's winning-tickets gate; nothing else consults it here.
    let genesis = chain
        .lock()
        .expect("chain")
        .block_by_hash(&params.genesis_hash)
        .expect("genesis block");
    let mut gate_params = params.clone();
    gate_params.stake_validation_height = 0;

    let handler = ChainNtfnHandler::new(
        // A notification manager must be present for the accepted block
        // to queue a lottery lookup at all (dcrd's `s.rpcServer != nil`).
        Some(dcroxide_node::websocket::NodeNtfnMgr::new()),
        gate_params,
        // Unsynced mining allowed, so the drain clears the sync gate over
        // this stale genesis-only tip and reaches the refusal check.
        true,
        dcroxide_node::sync::SyncGate::always_current(),
        Some(Arc::clone(&mix_pool)),
        tx_pool,
        dcroxide_node::dispatch::SyncPeers::new(),
        dcroxide_node::dispatch::new_recently_advertised(),
    );
    handler.handle(&Notification::BlockAccepted(BlockAcceptedNtfnsData {
        best_height: 0,
        fork_len: 0,
        block: &genesis,
    }));

    let (done_tx, done_rx) = mpsc::channel::<&'static str>();
    let (pool_held_tx, pool_held_rx) = mpsc::channel::<()>();
    // Set once the peer-order thread is past its chain acquisition, so a
    // deadlocked drain thread can be told apart from a slow one.
    let peer_through = Arc::new(AtomicBool::new(false));

    // Thread B — the peer order (mixpool then chain).  Structurally
    // identical to `NodeSyncMixPool::accept_message` holding the pool
    // guard while `NodeMixChain::current_tip` locks the chain, minus the
    // signed wire message that path needs to get that far.
    let peer = {
        let chain = Arc::clone(&chain);
        let mix_pool = Arc::clone(&mix_pool);
        let done_tx = done_tx.clone();
        let peer_through = Arc::clone(&peer_through);
        std::thread::spawn(move || {
            let pool = mix_pool.lock().expect("mix pool mutex poisoned");
            pool_held_tx.send(()).expect("signal pool held");
            // Let the drain thread get into its chain critical section
            // and reach for the pool before this order needs the chain.
            std::thread::sleep(HANDOFF);
            let best = chain
                .lock()
                .expect("chain mutex poisoned")
                .best_snapshot()
                .height;
            assert_eq!(best, 0, "genesis-only chain");
            peer_through.store(true, Ordering::SeqCst);
            drop(pool);
            done_tx.send("peer").expect("peer done");
        })
    };

    // The drain only starts once the pool guard is genuinely held, so the
    // interleaving is pinned rather than raced for.
    pool_held_rx
        .recv_timeout(DEADLINE)
        .expect("peer thread took the mix pool");

    // Thread A — the generator's drain hook order (chain then, in the
    // buggy shape, mixpool).  The real drain, on the real handler.
    let drain = {
        let chain = Arc::clone(&chain);
        let done_tx = done_tx.clone();
        std::thread::spawn(move || {
            handler.drain_pending_winning_tickets(&chain, 2_000_000_000);
            done_tx.send("drain").expect("drain done");
        })
    };
    drop(done_tx);

    let mut finished = Vec::new();
    for _ in 0..2 {
        match done_rx.recv_timeout(DEADLINE) {
            Ok(who) => finished.push(who),
            Err(_) => panic!(
                "chain/mixpool lock-order inversion: {finished:?} finished, peer past the chain: \
                 {}; the winning-tickets drain is holding the chain mutex across its mixpool \
                 acquisition again (B-5)",
                peer_through.load(Ordering::SeqCst)
            ),
        }
    }

    peer.join().expect("peer thread");
    drain.join().expect("drain thread");
    finished.sort_unstable();
    assert_eq!(finished, vec!["drain", "peer"], "both orders completed");
}
