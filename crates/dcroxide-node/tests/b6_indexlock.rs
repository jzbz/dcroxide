// SPDX-License-Identifier: ISC
//! Lock-hold regression for the exists-address index query path.
//!
//! `existsaddresses` is on the limited-credential list
//! (`dcroxide_rpc::dispatch::RPC_LIMITED`), and the caller chooses how
//! many addresses to send — bounded only by the request body cap, which
//! is 8 MiB for an authenticated client (`rpcrun::
//! RPC_READ_LIMIT_AUTHENTICATED`), so roughly 220,000 addresses.
//!
//! The daemon shares one `ExistsAddrIndex` behind a mutex.  While
//! `NodeRpcExistsAddresser::exists_addresses` held that mutex across its
//! database reads, a single large request parked the index writer — and
//! the index writer takes the database's *writer semaphore* before it
//! waits on the index mutex (`dcroxide_indexers::subscriber`), which
//! every database commit in the daemon queues behind.  One unprivileged
//! authenticated call therefore stalled block connection for its whole
//! duration.
//!
//! dcrd has no such coupling: `ExistsAddresses`
//! (`internal/blockchain/indexers/existsaddrindex.go` 331-364) opens a
//! database view with no index-wide lock held and takes its
//! `unconfirmedLock` only for the mempool overlay.  The port now matches
//! that shape through `ExistsAddrQuery`.
//!
//! What this test pins, and what it does not:
//!
//! - **Pinned.** `exists_addresses` does not hold the index mutex across
//!   its database work.  Revert `NodeRpcExistsAddresser::query` to lock
//!   the index and call through the guard, and the timing assertion
//!   below fails.
//! - **Not pinned.** The companion change — the subscriber taking the
//!   index guard *before* `Database::begin(true)` rather than after — is
//!   a defensive ordering fix.  Reproducing its failure needs a live
//!   subscriber mid-update, so no assertion here goes red if it is
//!   reverted.  It is stated plainly rather than implied to be covered.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use dcroxide_chaincfg::Params;
use dcroxide_database::{Database, Options};
use dcroxide_indexers::{ExistsAddrIndex, IndexSubscriber, Interrupt};
use dcroxide_node::indexes::{NodeChainQueryer, NodeRpcExistsAddresser};
use dcroxide_rpc::server::RpcExistsAddresser;
use dcroxide_txscript::stdaddr::{Address, new_address_pub_key_hash_ecdsa_secp256k1_v0};

use dcroxide_blockchain::process::Chain;
use dcroxide_indexers::ChainQueryer;

/// How long the measured query should run for.
///
/// The address count is calibrated to this at runtime rather than fixed,
/// because both failure modes of a fixed count are machine-speed
/// dependent: too few addresses and a held mutex is over before the
/// probe can see it (the test passes vacuously, or trips its own
/// vacuity guard on a fast machine), too many and a slow CI runner
/// spends minutes here.
const TARGET_QUERY: Duration = Duration::from_millis(1_500);

/// Address count bounds for the calibration.  The upper bound is about
/// what the 8 MiB authenticated body cap actually admits, so the test
/// never claims to exercise more than a real client could send.
const MIN_ADDRS: usize = 20_000;
const MAX_ADDRS: usize = 220_000;

/// Sample size used to measure the per-address lookup cost.
const CALIBRATION_ADDRS: usize = 5_000;

/// The worst index-mutex acquisition must be under this fraction of the
/// query's own duration.
///
/// Everything here is expressed against the query's measured duration
/// rather than a wall-clock constant, because an absolute threshold is
/// wrong in both directions: on a fast machine a held mutex finishes
/// inside the budget and the bug slips through, and on a loaded one an
/// uncontended acquisition can exceed it and the test flakes.  Holding
/// the mutex across the lookups puts the worst wait at essentially the
/// whole query (ratio ~1); taking only a query handle under the guard
/// puts it in the microseconds (ratio ~0).  A quarter separates those
/// two by a wide margin in both directions.
const MAX_HOLD_FRACTION: u32 = 4;

/// The probe must sample this many times inside the query, otherwise it
/// cannot be said to have observed anything.
const MIN_SAMPLES: usize = 10;

/// Overall deadline, so a wedge fails rather than hangs.
const DEADLINE: Duration = Duration::from_secs(120);

fn distinct_addresses(params: &Params, n: usize) -> Vec<Address> {
    (0..n)
        .map(|i| {
            let mut h160 = [0u8; 20];
            h160[..8].copy_from_slice(&(i as u64).to_le_bytes());
            new_address_pub_key_hash_ecdsa_secp256k1_v0(&h160, params).expect("address")
        })
        .collect()
}

/// A large `existsaddresses` must not hold the index mutex while it
/// reads the database.
///
/// Regression guard for the limited-credential write stall.  With the
/// mutex held across the lookups the probe below waits out the entire
/// query — measured in seconds at this size — instead of the
/// sub-millisecond acquisition it gets when only a query handle is taken
/// under the guard.
#[test]
fn a_large_exists_addresses_never_holds_the_index_mutex() {
    let params = dcroxide_chaincfg::simnet_params();
    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db.clone(), &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    let queryer = Arc::new(NodeChainQueryer::new(Arc::clone(&chain), params.clone()));

    let mut subscriber = IndexSubscriber::new(Interrupt::default());
    let index = ExistsAddrIndex::new(
        &mut subscriber,
        Arc::new(db),
        Arc::clone(&queryer) as Arc<dyn ChainQueryer>,
    )
    .expect("exists address index");

    let mut addresser = NodeRpcExistsAddresser::new(Arc::clone(&index), Arc::clone(&queryer));

    // Calibrate: time a small lookup — which also warms the path, so the
    // measured run is not paying first-touch costs — and size the real
    // one so it runs for TARGET_QUERY on this machine.
    let sample = distinct_addresses(&params, CALIBRATION_ADDRS);
    let at = Instant::now();
    addresser.exists_addresses(&sample).expect("calibration");
    let per_addr = at.elapsed() / CALIBRATION_ADDRS as u32;
    let want = if per_addr.is_zero() {
        MAX_ADDRS
    } else {
        (TARGET_QUERY.as_nanos() / per_addr.as_nanos()) as usize
    };
    let n = want.clamp(MIN_ADDRS, MAX_ADDRS);
    let addrs = distinct_addresses(&params, n);

    let running = Arc::new(AtomicBool::new(true));
    let (query_done_tx, query_done_rx) = mpsc::channel::<Duration>();

    // The "RPC client": one maximal lookup, exactly as the seam runs it.
    let querying = {
        let running = Arc::clone(&running);
        std::thread::spawn(move || {
            let started = Instant::now();
            let out = addresser.exists_addresses(&addrs).expect("lookup");
            assert_eq!(out.len(), n, "one verdict per address");
            assert!(!out.iter().any(|&e| e), "no address was ever indexed here");
            running.store(false, Ordering::SeqCst);
            query_done_tx.send(started.elapsed()).expect("query done");
        })
    };

    // Probe: while the query is in flight, taking the index mutex must
    // not wait on it.  Keep sampling so the measurement lands inside the
    // query rather than racing its start.
    let mut worst = Duration::ZERO;
    let mut samples = 0usize;
    while running.load(Ordering::SeqCst) {
        let at = Instant::now();
        let guard = index.lock().expect("exists addr index mutex poisoned");
        let waited = at.elapsed();
        drop(guard);
        worst = worst.max(waited);
        samples += 1;
        std::thread::sleep(Duration::from_millis(1));
    }

    let query_took = query_done_rx
        .recv_timeout(DEADLINE)
        .expect("the lookup finished");
    querying.join().expect("query thread");

    // Guard against a vacuous pass: the probe must actually have sampled
    // while the query ran, and the query must have run long enough that a
    // held mutex would have been visible.
    assert!(
        samples >= MIN_SAMPLES,
        "the probe sampled the mutex only {samples} times during the {query_took:?} query over \
         {n} addresses; too few for the measurement to mean anything"
    );
    // The real assertion, expressed against the query's own duration so
    // it means the same thing on any machine.
    assert!(
        worst * MAX_HOLD_FRACTION < query_took,
        "worst index-mutex acquisition {worst:?} over {samples} samples is more than 1/{} of \
         the {query_took:?} query over {n} addresses: the query is holding the index mutex \
         across its database reads again",
        MAX_HOLD_FRACTION
    );
}
