// SPDX-License-Identifier: ISC
//! End-to-end check for the outbound connection driver: a dialing
//! daemon opens a permanent connection to a listening daemon serving a
//! genesis chain, completes the handshake through the shared outbound
//! serve path, and both sides track the live peer.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};
use dcroxide_node::dispatch::ServerContext;
use dcroxide_node::outbound::{OutboundConfig, start_outbound};
use dcroxide_node::runtime::{ConnectedPeers, ListenerRuntime, PeerTemplate, inbound_peer_handler};
use dcroxide_wire::{CurrencyNet, ServiceFlag};

const NET: CurrencyNet = CurrencyNet::TEST_NET3;

/// Build a server context over a fresh genesis chain in `dir`.
fn genesis_server(dir: &std::path::Path, name: &str) -> (Arc<ServerContext>, ConnectedPeers) {
    let params = dcroxide_chaincfg::testnet3_params();
    let opts = Options::new(dir.join(name), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    let connected = ConnectedPeers::new();
    let server = Arc::new(ServerContext {
        chain: Arc::clone(&chain),
        min_known_work: params.min_known_chain_work,
        disable_banning: false,
        ban_threshold: 100,
        whitelists: Vec::new(),
        addr_manager: Arc::new(Mutex::new(dcroxide_addrmgr::AddrManager::new(dir))),
        sim_or_reg_net: false,
        stake_validation_height: params.stake_validation_height,
        blocks_only: false,
        sync_manager: Arc::new(Mutex::new(dcroxide_node::sync::new_sync_manager(
            Arc::clone(&chain),
            &params,
            false,
            8,
            1000,
        ))),
        sync_peers: dcroxide_node::dispatch::SyncPeers::new(),
        next_peer_id: std::sync::atomic::AtomicI32::new(1),
    });
    (server, connected)
}

fn template(name: &str) -> PeerTemplate {
    PeerTemplate {
        net: NET,
        protocol_version: 0,
        // Advertise NODE_NETWORK so each side treats the other as a
        // sync candidate.
        services: ServiceFlag::NODE_NETWORK,
        user_agent_name: name.to_string(),
        user_agent_version: "0.1.0".to_string(),
        idle_timeout: Duration::from_secs(3600),
        ping_interval: Duration::from_secs(3600),
    }
}

/// The outbound driver dials a listening peer, completes the handshake,
/// and both daemons track the connection; stopping the driver and the
/// listener tears everything down.
#[test]
fn dials_and_serves_a_permanent_connection() {
    let dir = tempfile::tempdir().expect("temp dir");

    // The listening daemon.
    let (listen_server, listen_connected) = genesis_server(dir.path(), "listen");
    let runtime = ListenerRuntime::start(
        &[("tcp4", ":0".to_string())],
        inbound_peer_handler(
            template("listener"),
            listen_connected.clone(),
            Some(listen_server),
        ),
    )
    .expect("start listener");
    let port = runtime.bound_addrs()[0].port();

    // The dialing daemon opens a permanent connection to it.
    let (dial_server, dial_connected) = genesis_server(dir.path(), "dial");
    let connector = start_outbound(OutboundConfig {
        template: template("dialer"),
        connected: dial_connected.clone(),
        server: Some(dial_server),
        target_outbound: 8,
        retry_duration: Duration::from_millis(200),
        dial_timeout: Duration::from_secs(5),
        permanent: vec![format!("127.0.0.1:{port}")],
    });

    // Both sides register the live peer once the handshake completes.
    assert!(
        wait_until(Duration::from_secs(10), || {
            dial_connected.len() == 1 && listen_connected.len() == 1
        }),
        "the outbound connection should be established on both sides \
         (dialer {}, listener {})",
        dial_connected.len(),
        listen_connected.len()
    );

    connector.shutdown();
    dial_connected.disconnect_all();
    listen_connected.disconnect_all();
    runtime.shutdown();
}

/// The driver keeps retrying a permanent connection whose target is
/// not up, without spinning or crashing.
#[test]
fn retries_an_unreachable_permanent_connection() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (dial_server, dial_connected) = genesis_server(dir.path(), "dial");

    // Bind a port, then drop the listener so connects are refused.
    let dead = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let port = dead.local_addr().expect("addr").port();
    drop(dead);

    let connector = start_outbound(OutboundConfig {
        template: template("dialer"),
        connected: dial_connected.clone(),
        server: Some(dial_server),
        target_outbound: 8,
        retry_duration: Duration::from_millis(100),
        dial_timeout: Duration::from_millis(500),
        permanent: vec![format!("127.0.0.1:{port}")],
    });

    // Nothing ever connects, and the driver stays healthy across a few
    // retry cycles.
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(
        dial_connected.len(),
        0,
        "an unreachable target never connects"
    );

    connector.shutdown();
}

/// Poll `cond` until it holds or the timeout elapses.
fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    cond()
}
