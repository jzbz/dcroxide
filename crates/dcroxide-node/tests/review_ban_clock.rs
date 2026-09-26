// SPDX-License-Identifier: ISC
//! The daemon's bans run on the monotonic clock.
//!
//! dcrd stores `bannedUntil := time.Now().Add(cfg.BanDuration)`
//! (`server.go:2763`) and admits a host again once
//! `time.Now().Before(banEnd)` fails (`server.go:2192-2193`).  Both
//! values carry a monotonic reading, so a wall-clock step moves no ban.
//! The port stamped the ban and checked it on the wall clock, so a
//! forward step (or a VM's wall clock catching up after a pause) lifted
//! every ban it covered, and a backward step stretched them.
//!
//! A wall-clock step cannot be staged in a test, so these pin the clock
//! itself: the misbehavior path stamps a monotonic reading, and the
//! pre-handshake check refuses a host whose ban ends an hour from now on
//! that clock (a wall-clock check reads it as long lifted).

// Test-harness arithmetic over fixed durations.
#![allow(clippy::arithmetic_side_effects)]

use std::io::Read as _;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};
use dcroxide_node::dispatch::{ServerContext, ServerPeerHandler};
use dcroxide_node::peerconn::{NodePeerEnv, net_address_v2_from_socket};
use dcroxide_node::peerloop::{OutboundQueue, ServeSignal};
use dcroxide_node::runtime::{ConnectedPeers, ListenerRuntime, PeerTemplate, inbound_peer_handler};
use dcroxide_peer::{Config, Peer, PeerEnv};
use dcroxide_wire::{CurrencyNet, Message, ServiceFlag};

const NET: CurrencyNet = CurrencyNet::TEST_NET3;
const BAN_DURATION_NANOS: i64 = 24 * 60 * 60 * 1_000_000_000;

/// A server context over a fresh genesis chain.  The temporary directory
/// is returned with it so it outlives the chain and the address manager.
fn genesis_server() -> (tempfile::TempDir, Arc<ServerContext>) {
    let params = dcroxide_chaincfg::testnet3_params();
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
    let server = Arc::new(ServerContext {
        external_addr_candidates: Mutex::new(Default::default()),
        external_addr_facts: dcroxide_node::server::ExternalAddrFacts {
            listeners: Vec::new(),
            has_proxy: false,
            no_discover_ip: true,
            has_external_ips: false,
            listen_disabled: false,
            sim_or_reg_net: false,
            services: ServiceFlag::NODE_NETWORK,
            target_outbound: 8,
        },
        lookup: Box::new(|_| Err("no resolver in tests".to_string())),
        target_outbound: 8,
        chain: Arc::clone(&chain),
        min_known_work: params.min_known_chain_work,
        params: params.clone(),
        disable_banning: false,
        ban_threshold: 100,
        whitelists: Vec::new(),
        banned_hosts: Mutex::new(std::collections::BTreeMap::new()),
        ban_duration_nanos: BAN_DURATION_NANOS,
        addr_manager: Arc::new(Mutex::new(dcroxide_addrmgr::AddrManager::new(dir.path()))),
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
            dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone(), &tx_pool),
        ))),
        sync_peers: dcroxide_node::dispatch::SyncPeers::new(),
        net_totals: Arc::new(dcroxide_node::transport::NetByteTotals::new()),
        disable_listen: false,
        tx_pool: Arc::clone(&tx_pool),
        ntfn: None,
        recently_advertised: dcroxide_node::dispatch::new_recently_advertised(),
        mix_pool: dcroxide_node::mixnode::shared_mix_pool(
            Arc::clone(&chain),
            params.clone(),
            &tx_pool,
        ),
    });
    (dir, server)
}

/// A misbehaving peer's ban ends `--banduration` after a monotonic
/// reading taken as it is banned.
#[test]
fn a_ban_is_stamped_on_the_monotonic_clock() {
    let (_dir, ctx) = genesis_server();
    let addr = "52.91.30.41:9108";
    let mut handler =
        ServerPeerHandler::new(Arc::clone(&ctx), false, None, false, None, addr.to_string());
    let mut peer = Peer::new_inbound(Config {
        net: NET,
        services: ServiceFlag::NODE_NETWORK,
        user_agent_name: "review".to_string(),
        user_agent_version: "0.1.0".to_string(),
        protocol_version: 0,
        ..Config::default()
    });
    let na = net_address_v2_from_socket(addr.parse().expect("socket address"), ServiceFlag(0))
        .expect("net address");
    peer.associate(addr, na, NodePeerEnv::new().now_nanos());
    let peer = Arc::new(Mutex::new(peer));
    let (queue, _sent) = OutboundQueue::channel();

    // A getminingstate from a peer at the current protocol version is a
    // knowing violation, banned on the spot (`server.go:1116-1122`).
    let before = dcroxide_connmgr::monotonic_nanos();
    let signal = handler.handle_message(&peer, Message::GetMiningState, None, &queue);
    let after = dcroxide_connmgr::monotonic_nanos();
    assert!(
        matches!(signal, ServeSignal::Disconnect(_)),
        "the peer must be banned, got {signal:?}"
    );

    let until = *ctx
        .banned_hosts
        .lock()
        .expect("banned hosts")
        .get("52.91.30.41")
        .expect("the host is banned");
    assert!(
        (before + BAN_DURATION_NANOS..=after + BAN_DURATION_NANOS).contains(&until),
        "the ban end {until} is no monotonic reading plus the ban duration \
         ({before}..={after} plus {BAN_DURATION_NANOS})"
    );
}

/// The pre-handshake check reads the same clock: a host banned for
/// another hour on it is refused, and its ban stays in place.
#[test]
fn the_pre_handshake_check_reads_the_monotonic_clock() {
    let (_dir, ctx) = genesis_server();
    ctx.banned_hosts.lock().expect("banned hosts").insert(
        "127.0.0.1".to_string(),
        dcroxide_connmgr::monotonic_nanos() + 3_600 * 1_000_000_000,
    );
    let template = PeerTemplate {
        net: NET,
        protocol_version: 0,
        services: ServiceFlag(1),
        user_agent_name: "dcroxide".to_string(),
        user_agent_version: "0.1.0".to_string(),
        idle_timeout: Duration::from_secs(3600),
        ping_interval: Duration::from_secs(3600),
        disable_relay_tx: false,
        proxy: String::new(),
        newest_block: None,
    };
    let runtime = ListenerRuntime::start(
        &[("tcp4", "127.0.0.1:0".to_string())],
        inbound_peer_handler(
            template,
            ConnectedPeers::new(),
            Some(Arc::clone(&ctx)),
            None,
        ),
    )
    .expect("start the listener");
    let port = runtime.bound_addrs()[0].port();

    // A refused connection is closed before the handshake; an admitted
    // one waits for this side's version message and sends nothing.
    let mut conn = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    conn.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let mut byte = [0u8; 1];
    let read = conn.read(&mut byte);
    runtime.shutdown();
    let refused = match &read {
        Ok(n) => *n == 0,
        Err(e) => !matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
    };
    assert!(refused, "the banned host must be refused, got {read:?}");
    assert!(
        ctx.banned_hosts
            .lock()
            .expect("banned hosts")
            .contains_key("127.0.0.1"),
        "a ban still in force must not be lifted"
    );
}
