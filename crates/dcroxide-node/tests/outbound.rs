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
use dcroxide_node::outbound::{OutboundConfig, outbound_channel, start_outbound};
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
    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    );
    let server = Arc::new(ServerContext {
        target_outbound: 8,
        chain: Arc::clone(&chain),
        min_known_work: params.min_known_chain_work,
        params: params.clone(),
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
            Arc::clone(&tx_pool),
            dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone()),
        ))),
        sync_peers: dcroxide_node::dispatch::SyncPeers::new(),
        next_peer_id: std::sync::atomic::AtomicI32::new(1),
        net_totals: std::sync::Arc::new(dcroxide_node::transport::NetByteTotals::new()),
        disable_listen: false,
        tx_pool: Arc::clone(&tx_pool),
        ntfn: None,
        recently_advertised: dcroxide_node::dispatch::new_recently_advertised(),

        mix_pool: dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone()),
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
            None,
        ),
    )
    .expect("start listener");
    let port = runtime.bound_addrs()[0].port();

    // The dialing daemon opens a permanent connection to it.
    let (dial_server, dial_connected) = genesis_server(dir.path(), "dial");
    let manager = test_manager(200000000);
    let persistent = add_persistent(&manager, &format!("127.0.0.1:{port}"));
    let connector = start_outbound(
        OutboundConfig {
            template: template("dialer"),
            connected: dial_connected.clone(),
            server: Some(dial_server),
            manager: Arc::clone(&manager),
            dial_timeout: Duration::from_secs(5),
            dialer: dcroxide_node::socks::NodeDialer::direct(),
            persistent,
            get_new_address: None,
            addr_manager: None,
        },
        outbound_channel(),
    );

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

    let manager = test_manager(100000000);
    let persistent = add_persistent(&manager, &format!("127.0.0.1:{port}"));
    let connector = start_outbound(
        OutboundConfig {
            template: template("dialer"),
            connected: dial_connected.clone(),
            server: Some(dial_server),
            manager: Arc::clone(&manager),
            dial_timeout: Duration::from_millis(500),
            dialer: dcroxide_node::socks::NodeDialer::direct(),
            persistent,
            get_new_address: None,
            addr_manager: None,
        },
        outbound_channel(),
    );

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

/// `node remove` on a served permanent peer tears the whole chain down
/// end to end: the handshake registered the peer with its live
/// connection-request id, so the remove disconnects it AND stops the
/// connection manager's redial — despite the permanence and a short
/// retry interval (dcrd's `removeNode` nilling `connReq` before
/// `connManager.Remove`).
#[test]
fn removing_a_permanent_peer_stops_its_redial() {
    use dcroxide_rpc::server::RpcConnManager;

    let dir = tempfile::tempdir().expect("temp dir");

    // The listening daemon.
    let (listen_server, listen_connected) = genesis_server(dir.path(), "listen");
    let runtime = ListenerRuntime::start(
        &[("tcp4", ":0".to_string())],
        inbound_peer_handler(
            template("listener"),
            listen_connected.clone(),
            Some(listen_server),
            None,
        ),
    )
    .expect("start listener");
    let port = runtime.bound_addrs()[0].port();

    // The dialing daemon keeps a permanent connection with a retry
    // interval short enough that a leaked redial would be observed.
    let (dial_server, dial_connected) = genesis_server(dir.path(), "dial");
    let channel = dcroxide_node::outbound::outbound_channel();
    let control = channel.control();
    let manager = test_manager(100000000);
    let persistent = add_persistent(&manager, &format!("127.0.0.1:{port}"));
    let connector = start_outbound(
        OutboundConfig {
            template: template("dialer"),
            connected: dial_connected.clone(),
            server: Some(Arc::clone(&dial_server)),
            manager: Arc::clone(&manager),
            dial_timeout: Duration::from_secs(5),
            dialer: dcroxide_node::socks::NodeDialer::direct(),
            persistent,
            get_new_address: None,
            addr_manager: None,
        },
        channel,
    );

    // The handshake completes and the peer registers as persistent.
    let rebroadcaster = dcroxide_node::rebroadcast::start_rebroadcaster(
        Arc::clone(&dial_server.chain),
        dial_server.sync_peers.clone(),
        Arc::clone(&dial_server.recently_advertised),
    );
    let mut manager = dcroxide_node::rpcrun::NodeRpcConnManager::new(
        dial_connected.clone(),
        Arc::new(dcroxide_node::transport::NetByteTotals::new()),
    )
    .with_relay(
        dial_server.sync_peers.clone(),
        Arc::clone(&dial_server.recently_advertised),
        Arc::clone(&dial_server.tx_pool),
        rebroadcaster.sink(),
        dcroxide_node::websocket::NodeNtfnMgr::new(),
    )
    .with_outbound(control);
    assert!(
        wait_until(Duration::from_secs(10), || {
            manager.persistent_peers().len() == 1
        }),
        "the permanent peer must register through the handshake"
    );
    let peer_addr = manager.persistent_peers()[0].addr.clone();

    // Remove it: the peer disconnects, and the request's redial is
    // stopped — both registries settle at zero and stay there across
    // several would-be retry windows.
    manager.remove_by_addr(&peer_addr).expect("remove");
    assert!(
        wait_until(Duration::from_secs(10), || {
            dial_connected.is_empty() && manager.persistent_peers().is_empty()
        }),
        "the removed peer must disconnect"
    );
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        dial_connected.len(),
        0,
        "a removed permanent peer is never redialed"
    );

    connector.shutdown();
    rebroadcaster.shutdown();
    dial_connected.disconnect_all();
    listen_connected.disconnect_all();
    runtime.shutdown();
}

/// A fresh shared connection manager core with the given retry
/// duration in nanoseconds.
fn test_manager(retry_nanos: i64) -> dcroxide_node::outbound::SharedConnManager {
    let mut csprng = dcroxide_connmgr::SystemCsprng::default();
    Arc::new(Mutex::new(dcroxide_connmgr::ConnManager::new(
        dcroxide_connmgr::ManagerConfig {
            retry_duration_nanos: retry_nanos,
            ..Default::default()
        },
        &mut csprng,
    )))
}

/// Register the address as a persistent entry (the binary's startup
/// AddPersistent) and return the driver's entry list.
fn add_persistent(
    manager: &dcroxide_node::outbound::SharedConnManager,
    addr: &str,
) -> Vec<(u64, dcroxide_addrmgr::NetAddress)> {
    let resolved =
        dcroxide_node::outbound::addr_string_to_socket_addr(addr).expect("resolve persistent");
    let na = dcroxide_node::outbound::socket_addr_to_net_address(&resolved);
    let id = manager
        .lock()
        .expect("connmgr mutex")
        .add_persistent(&na)
        .expect("add persistent");
    vec![(id, na)]
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

/// The connection manager's outbound selection draws candidates from
/// the thin address source and skips a group the daemon already has
/// an outbound connection to (dcrd 2.2: `pickOutboundAddr` over
/// `newAddressFunc`).
#[test]
fn outbound_selection_spreads_across_groups() {
    let dir = tempfile::tempdir().expect("temp dir");
    let addr_manager = Arc::new(Mutex::new(dcroxide_addrmgr::AddrManager::new(dir.path())));

    // Seed the manager with routable, succeeded addresses in a single
    // /16 group on the testnet default port.
    let source_na = wire_na([8, 8, 4, 4], 19108);
    {
        let mut mgr = addr_manager.lock().expect("addrmgr");
        for i in 1..=20u8 {
            let na = wire_na([8, 8, 8, i], 19108);
            mgr.add_addresses(std::slice::from_ref(&na), &source_na);
            mgr.good(&na).expect("mark good");
        }
    }

    // The thin source of dcrd 2.2's newAddressFunc: the candidate and
    // its last attempt time.
    let source_mgr = Arc::clone(&addr_manager);
    let mut source = move || {
        let candidate = source_mgr
            .lock()
            .expect("addrmgr")
            .get_address(|_| true)
            .ok_or_else(|| "no valid connect address".to_string())?;
        let candidate = candidate.lock().expect("known address");
        Ok((
            candidate.net_address().clone(),
            candidate.last_attempt().unwrap_or(0),
        ))
    };

    let mut csprng = dcroxide_connmgr::SystemCsprng::default();
    let mut manager = dcroxide_connmgr::ConnManager::new(
        dcroxide_connmgr::ManagerConfig {
            default_port: 19108,
            ..Default::default()
        },
        &mut csprng,
    );
    let now_nanos = 1_700_000_000_000_000_000i64;

    // A candidate is available while the group is unoccupied, and the
    // pick registers the group.
    let picked = manager
        .pick_outbound_addr(&mut source, now_nanos)
        .expect("an address is available");
    assert!(
        picked.key().starts_with("8.8.8."),
        "picked {}",
        picked.key()
    );

    // Once the pick occupies the group, every candidate is skipped and
    // the selection reports no suitable address.
    assert_eq!(
        manager.pick_outbound_addr(&mut source, now_nanos),
        Err(dcroxide_connmgr::NO_SUITABLE_ADDR_MSG.to_string())
    );
}

/// A routable IPv4 addr-manager net address for the seeding above.
fn wire_na(ip: [u8; 4], port: u16) -> dcroxide_addrmgr::NetAddress {
    let mut ip16 = vec![0u8; 16];
    ip16[10] = 0xff;
    ip16[11] = 0xff;
    ip16[12..16].copy_from_slice(&ip);
    dcroxide_addrmgr::NetAddress {
        timestamp: 1,
        services: dcroxide_wire::ServiceFlag(1),
        ip: ip16,
        port,
        addr_type: dcroxide_addrmgr::NetAddressType::IPv4,
    }
}
