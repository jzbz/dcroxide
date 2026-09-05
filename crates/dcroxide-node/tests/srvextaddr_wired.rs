// SPDX-License-Identifier: ISC
//! The external address subsystem is wired into a served connection:
//! the address a peer reports seeing for this node reaches the
//! server's candidate cache.
//!
//! `srvextaddr_vectors.rs` pins the subsystem itself against dcrd's
//! dumped rows, but a subsystem with no caller decides nothing — the
//! port carried `considerReportedAddr` and every gate under it for
//! some time with no live caller at all, so a node never learned its
//! own address no matter how many peers reported it.  dcrd's two
//! halves are `serverPeer.OnVersion` storing `&msg.AddrYou` into
//! `sp.reportedLocalAddr` (`server.go:1038`) and `handleAddPeer`
//! handing it to `considerReportedAddr` (`server.go:2670`).
//!
//! Each test here drives both halves through the production peer loop
//! — a real loopback socket, a real version handshake, the real
//! dispatch — and then reads the cache the daemon itself reads.  A
//! synthetic call into the handlers would pass with either half
//! missing.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use dcroxide_addrmgr::{NetAddressReach, NetAddressType};
use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};
use dcroxide_node::dispatch::{ServerContext, ServerPeerHandler};
use dcroxide_node::peerconn::{NodePeerEnv, net_address_v2_from_socket};
use dcroxide_node::peerloop::{OutboundQueue, ServeHooks, ServeSignal, run_peer_connection};
use dcroxide_node::server::{ExternalAddrCandidate, ExternalAddrFacts};
use dcroxide_node::transport::{Teardown, WireTransport};
use dcroxide_peer::{Config, MAX_PROTOCOL_VERSION, Peer, PeerEnv, PeerGlobals};
use dcroxide_wire::{CurrencyNet, Message, NetAddress, ServiceFlag};

const NET: CurrencyNet = CurrencyNet::TEST_NET3;

/// The port every address in this file carries, as the vector dump's
/// addresses do.
const PORT: u16 = 9108;

/// The routable address the remote peer is dialed at or connects
/// from; `srvextaddr_vectors.rs` uses the same one, so a candidate
/// accepted here is accepted for the reason those rows pin.
const REMOTE_IP: &str = "52.91.30.7";

/// The routable address the remote reports seeing for this node
/// (dcrd `msg.AddrYou`).
const REPORTED_IP: &str = "8.8.8.8";

/// Long enough that neither timer can fire inside a test; the
/// connection is ended by closing the remote's socket instead.
const IDLE_TIMEOUT: Duration = Duration::from_secs(3600);
/// See [`IDLE_TIMEOUT`].
const PING_INTERVAL: Duration = Duration::from_secs(3600);

/// `host:port` for one of the literal IPs above.
fn addr_string(ip: &str) -> String {
    format!("{ip}:{PORT}")
}

/// The socket address form of one of the literal IPs above, for the
/// network address constructions the serve paths perform.
fn socket_addr(ip: &str) -> SocketAddr {
    addr_string(ip).parse().expect("literal socket address")
}

/// The dump's `wireAddr` (dcrd `wire.NewNetAddressTimestamp` with
/// `time.Unix(0, 0)`), for seeding a candidate the way
/// `considerReportedAddrOutbound` would have.
fn wire_addr(ip: &str, port: u16) -> NetAddress {
    let mut bytes = [0u8; 16];
    match ip.parse::<std::net::IpAddr>().expect("literal IP") {
        std::net::IpAddr::V4(v4) => {
            bytes[10] = 0xff;
            bytes[11] = 0xff;
            bytes[12..16].copy_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => bytes.copy_from_slice(&v6.octets()),
    }
    NetAddress {
        timestamp: 0,
        services: ServiceFlag::NODE_NETWORK,
        ip: bytes,
        port,
    }
}

/// The configuration the external address subsystem reads with
/// automatic discovery left ON: no proxy, no `--nodiscoverip`, no
/// `--externalip`, listening enabled with a listener configured, and
/// an active network that is neither simnet nor regnet.  Every gate
/// `considerReportedAddrOutbound` consults is open, which is the only
/// shape under which a candidate can ever be recorded.
fn discovering_facts() -> ExternalAddrFacts {
    ExternalAddrFacts {
        listeners: vec![addr_string("0.0.0.0")],
        has_proxy: false,
        no_discover_ip: false,
        has_external_ips: false,
        listen_disabled: false,
        sim_or_reg_net: false,
        services: ServiceFlag::NODE_NETWORK,
        target_outbound: 8,
    }
}

/// [`discovering_facts`] with automatic network address discovery
/// disabled (dcrd `--nodiscoverip`), the shape every other test
/// fixture in this crate uses.
fn no_discover_facts() -> ExternalAddrFacts {
    ExternalAddrFacts {
        no_discover_ip: true,
        ..discovering_facts()
    }
}

/// A server context over a fresh genesis chain, carrying the given
/// external address configuration.  The temporary directory is
/// returned with it so it outlives the chain and the address manager.
fn genesis_server(facts: ExternalAddrFacts) -> (tempfile::TempDir, Arc<ServerContext>) {
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
        external_addr_facts: facts,
        // Unreachable on this path: every candidate address is an IP
        // literal `host_to_net_address` recognizes without a lookup.
        lookup: Box::new(|_| Err("no resolver in tests".to_string())),
        target_outbound: 8,
        chain: Arc::clone(&chain),
        min_known_work: params.min_known_chain_work,
        params: params.clone(),
        disable_banning: false,
        ban_threshold: 100,
        whitelists: Vec::new(),
        banned_hosts: Mutex::new(std::collections::BTreeMap::new()),
        ban_duration_nanos: 24 * 60 * 60 * 1_000_000_000,
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
        next_peer_id: std::sync::atomic::AtomicI32::new(1),
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

/// The peer configuration both ends of a driven connection use; the
/// remote advertises `SFNodeNetwork` because `on_version` rejects an
/// outbound peer that does not (dcrd's "does not provide full node
/// services" rejection).
fn peer_config(user_agent_name: &str) -> Config {
    Config {
        net: NET,
        services: ServiceFlag::NODE_NETWORK,
        user_agent_name: user_agent_name.to_string(),
        user_agent_version: "0.1.0".to_string(),
        // 0 selects the package's maximum protocol version.
        protocol_version: 0,
        ..Config::default()
    }
}

/// The connection lifecycle hooks a served peer runs, forwarding to
/// the server dispatch.  `runtime.rs` forwards the same calls through
/// its `InboundHooks::Server` arm, which is private to that module;
/// the wire violation hook is `pub(crate)` and is left at the trait's
/// no-op default because a hand-driven handshake never trips it.
struct ServerHooks(ServerPeerHandler);

impl ServeHooks for ServerHooks {
    fn on_version(&mut self, peer: &Peer, msg: &dcroxide_wire::MsgVersion) -> Result<(), String> {
        self.0.on_version(peer, msg)
    }

    fn on_connected(
        &mut self,
        peer: &mut Peer,
        peer_handle: &Arc<Mutex<Peer>>,
        outbound: &OutboundQueue,
        remote_disable_relay_tx: bool,
    ) {
        self.0
            .on_connected(peer, peer_handle, outbound, remote_disable_relay_tx);
    }

    fn on_message(
        &mut self,
        peer: &mut Peer,
        msg: &Message,
        outbound: &OutboundQueue,
    ) -> ServeSignal {
        self.0.handle_message(peer, msg, outbound)
    }

    fn on_disconnected(&mut self, peer: &mut Peer) {
        self.0.on_disconnected(peer);
    }
}

/// Poll `cond` until it holds or the timeout elapses.
fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    cond()
}

/// Block until the dispatch's `on_connected` has run for the driven
/// connection.  The peer id is allocated immediately after the
/// candidate consideration and nothing between the two can return
/// early, so an advanced counter is proof the consideration already
/// happened and the cache can be read without racing the serving
/// thread.
fn wait_for_add_peer(ctx: &ServerContext) {
    assert!(
        wait_until(Duration::from_secs(10), || {
            ctx.next_peer_id.load(Ordering::SeqCst) > 1
        }),
        "the handshake must reach the dispatch's add-peer path",
    );
}

/// Serve one OUTBOUND connection through the production peer loop
/// against a remote that reports `reported` as the address it sees
/// for this node, returning once the dispatch has added the peer.
///
/// The served peer's network address is the routable address a
/// connection manager would have dialed (dcrd's
/// `outboundPeerConnected` associating the dialed address); the
/// loopback socket beneath it is only how the bytes reach the
/// hand-driven remote, exactly as it is in `handshake.rs`.  It has to
/// be routable: `getRemoteReachabilityFromLocal` answers `Unreachable`
/// for an unroutable REMOTE, which makes `isExternalAddrCandidate`
/// reject every report, so two daemons peering over 127.0.0.1 could
/// never record a candidate however routable the reported address is.
fn drive_outbound_peer(ctx: &Arc<ServerContext>, reported: &str) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
    let listen_addr = listener.local_addr().expect("listener addr");

    let node_ctx = Arc::clone(ctx);
    let node = thread::spawn(move || {
        let stream = TcpStream::connect(listen_addr).expect("dial the remote");
        let conn = Teardown::new(stream);
        let mut peer =
            Peer::new_outbound(peer_config("dcroxide"), &addr_string(REMOTE_IP)).expect("outbound");
        // The remote's services are unknown until its version message
        // arrives, so the associated address carries none (dcrd's
        // outbound `newNetAddress(remoteAddr, remoteServices)`).
        let na = net_address_v2_from_socket(socket_addr(REMOTE_IP), ServiceFlag(0))
            .expect("remote net address");
        peer.associate(&addr_string(REMOTE_IP), na, NodePeerEnv::new().now_nanos());
        let handler = ServerPeerHandler::new(
            node_ctx,
            false,
            conn.try_clone().ok(),
            false,
            None,
            addr_string(REMOTE_IP),
        );
        run_peer_connection(
            conn,
            peer,
            0,
            NET,
            IDLE_TIMEOUT,
            PING_INTERVAL,
            None,
            ServerHooks(handler),
        )
    });

    // The remote answers as the inbound half of the handshake.  Its
    // own network address is what its version message reports back as
    // `addr_you`, so associating it with `reported` is precisely a
    // peer telling this node where it sees it.
    let (stream, _) = listener.accept().expect("accept the node's dial");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set read timeout");
    let mut transport = WireTransport::new(stream, MAX_PROTOCOL_VERSION, NET);
    let mut env = NodePeerEnv::new();
    let globals = PeerGlobals::new();
    let mut remote = Peer::new_inbound(peer_config("remote"));
    let reported_na = net_address_v2_from_socket(socket_addr(reported), ServiceFlag::NODE_NETWORK)
        .expect("reported net address");
    remote.associate(&addr_string(reported), reported_na, env.now_nanos());
    remote
        .negotiate_inbound_protocol(&mut transport, &mut env, &globals, None)
        .expect("remote negotiation");

    wait_for_add_peer(ctx);

    // Closing the remote's socket ends the served connection.
    drop(transport);
    let _ = node.join().expect("node connection thread");
}

/// Serve one INBOUND connection through the production peer loop
/// against a remote that reports `reported` as the address it sees
/// for this node, returning once the dispatch has added the peer.
fn drive_inbound_peer(ctx: &Arc<ServerContext>, reported: &str) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
    let listen_addr = listener.local_addr().expect("listener addr");

    let node_ctx = Arc::clone(ctx);
    let node = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept the remote's dial");
        let conn = Teardown::new(stream);
        let mut peer = Peer::new_inbound(peer_config("dcroxide"));
        let na = net_address_v2_from_socket(socket_addr(REMOTE_IP), ServiceFlag::NODE_NETWORK)
            .expect("remote net address");
        peer.associate(&addr_string(REMOTE_IP), na, NodePeerEnv::new().now_nanos());
        let handler = ServerPeerHandler::new(
            node_ctx,
            false,
            conn.try_clone().ok(),
            false,
            None,
            addr_string(REMOTE_IP),
        );
        run_peer_connection(
            conn,
            peer,
            0,
            NET,
            IDLE_TIMEOUT,
            PING_INTERVAL,
            None,
            ServerHooks(handler),
        )
    });

    // The remote dials as the outbound half.  `new_outbound` derives
    // its network address from the address string, and the version
    // message reports that address back as `addr_you`.
    let stream = TcpStream::connect(listen_addr).expect("dial the node");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set read timeout");
    let mut transport = WireTransport::new(stream, MAX_PROTOCOL_VERSION, NET);
    let mut env = NodePeerEnv::new();
    let globals = PeerGlobals::new();
    let mut remote =
        Peer::new_outbound(peer_config("remote"), &addr_string(reported)).expect("outbound remote");
    remote
        .negotiate_outbound_protocol(&mut transport, &mut env, &globals, None)
        .expect("remote negotiation");

    wait_for_add_peer(ctx);

    drop(transport);
    let _ = node.join().expect("node connection thread");
}

/// The candidate cache's contents as `ip;score` pairs in LRU order,
/// so an assertion names the keys as well as the scores; the bare-IP
/// key space is half of what QK-0013 turns on.
fn cache_entries(ctx: &ServerContext) -> Vec<(String, u32)> {
    let cache = ctx
        .external_addr_candidates
        .lock()
        .expect("external address candidates poisoned");
    cache
        .entries
        .keys()
        .into_iter()
        .map(|key| {
            let score = cache
                .entries
                .peek(&key)
                .expect("a key the cache just listed")
                .score;
            (key, score)
        })
        .collect()
}

/// An outbound peer's reported address reaches the candidate cache:
/// `on_version` stores it and `on_connected` hands it to
/// `consider_reported_addr`, which records it at score 1 under its
/// bare IP (dcrd `server.go:1038` into `server.go:2670`).
///
/// One report is well short of the 60% majority of eight outbound
/// peers `considerReportedAddrOutbound` requires, so nothing is
/// promoted to a local address; the candidate itself is the whole
/// observable effect of the wiring, and without it the cache is
/// empty.
#[test]
fn an_outbound_peers_reported_address_becomes_a_candidate() {
    let (_dir, ctx) = genesis_server(discovering_facts());
    assert!(
        cache_entries(&ctx).is_empty(),
        "a freshly built server has no candidates; the assertion below would be vacuous",
    );

    drive_outbound_peer(&ctx, REPORTED_IP);

    assert_eq!(
        cache_entries(&ctx),
        vec![(REPORTED_IP.to_string(), 1)],
        "the address the outbound peer reported must be scored as a candidate",
    );

    // The candidate is recorded with the network type and
    // reachability `is_external_addr_candidate` derived, which is what
    // the majority scan and the listener match later read.
    let cache = ctx
        .external_addr_candidates
        .lock()
        .expect("external address candidates poisoned");
    let candidate = cache
        .best_candidate(NetAddressType::IPv4)
        .expect("an IPv4 candidate");
    assert_eq!(candidate.reach, NetAddressReach::Ipv4);
    assert_eq!(candidate.addr.port, PORT);
}

/// `--nodiscoverip` shuts the same drive down: automatic network
/// address discovery is one of the five conditions
/// `considerReportedAddrOutbound` returns on, so no candidate is ever
/// recorded.
///
/// Without this the test above could pass for the wrong reason — a
/// cache that accepted everything reported would look identical.
#[test]
fn no_discover_ip_leaves_an_outbound_peers_report_uncached() {
    let (_dir, ctx) = genesis_server(no_discover_facts());

    drive_outbound_peer(&ctx, REPORTED_IP);

    assert!(
        cache_entries(&ctx).is_empty(),
        "--nodiscoverip must keep a reported address out of the candidate cache",
    );
}

/// An inbound peer reaches `consider_reported_addr` and changes
/// nothing: it neither creates a candidate nor corroborates the one
/// already there.
///
/// DELIBERATE UPSTREAM DEFECT — see QK-0013.  dcrd's inbound branch
/// only ever looks a candidate up, and it builds the lookup key with
/// `net.JoinHostPort` (`8.8.8.8:9108`) while the outbound branch
/// stores under the bare `addr.IP.String()` (`8.8.8.8`).  The two key
/// spaces are disjoint, so the lookup always misses and an inbound
/// peer can never increment a score, notwithstanding the cache's own
/// doc comment.  The seeded candidate below is exactly what an
/// outbound report leaves behind, so a lookup keyed on the bare IP
/// would find it and score it 2; dcroxide must be neither stronger
/// nor weaker than dcrd here.
#[test]
fn an_inbound_peers_reported_address_corroborates_nothing() {
    let (_dir, ctx) = genesis_server(discovering_facts());

    // Seed the candidate an outbound report would have left, under
    // the bare-IP key `consider_reported_addr_outbound` uses.
    ctx.external_addr_candidates
        .lock()
        .expect("external address candidates poisoned")
        .entries
        .put(
            REPORTED_IP.to_string(),
            ExternalAddrCandidate {
                addr: wire_addr(REPORTED_IP, PORT),
                net_type: NetAddressType::IPv4,
                reach: NetAddressReach::Ipv4,
                score: 1,
            },
        );

    drive_inbound_peer(&ctx, REPORTED_IP);

    assert_eq!(
        cache_entries(&ctx),
        vec![(REPORTED_IP.to_string(), 1)],
        "an inbound peer must neither add a candidate nor bump an existing score",
    );
}
