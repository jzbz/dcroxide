// SPDX-License-Identifier: ISC
//! Integration checks for the threaded server listener runtime: it
//! binds an ephemeral listener, accepts inbound connections and reports
//! their addresses to the handler, and shuts its accept threads down
//! cleanly on request.

use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use dcroxide_node::runtime::ListenerRuntime;

/// Bind an ephemeral IPv4 listener, connect to the assigned port, and
/// confirm the accept handler observes the inbound connection.
#[test]
fn accepts_inbound_connections_on_bound_port() {
    let (tx, rx) = mpsc::channel::<SocketAddr>();
    let handler = Arc::new(move |_stream: TcpStream, peer: SocketAddr| {
        let _ = tx.send(peer);
    });

    let runtime = ListenerRuntime::start(&[("tcp4", ":0".to_string())], handler)
        .expect("bind ephemeral listener");

    let bound = runtime.bound_addrs();
    assert_eq!(bound.len(), 1, "one listener spec should bind one address");
    let port = bound[0].port();
    assert_ne!(port, 0, "an ephemeral port should be assigned");

    let mut client =
        TcpStream::connect(("127.0.0.1", port)).expect("connect to the bound listener");
    // Write a byte so the connection is not optimized away before accept.
    let _ = client.write_all(&[0x01]);

    let peer = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("handler should observe the inbound connection");
    assert!(peer.ip().is_loopback(), "peer address: {peer}");

    runtime.shutdown();
}

/// Two listener specs each bind their own address and the runtime joins
/// both accept threads on shutdown.
#[test]
fn binds_multiple_listeners_and_shuts_down() {
    let count = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&count);
    let handler = Arc::new(move |_stream: TcpStream, _peer: SocketAddr| {
        observed.fetch_add(1, Ordering::SeqCst);
    });

    let runtime = ListenerRuntime::start(
        &[("tcp4", ":0".to_string()), ("tcp4", ":0".to_string())],
        handler,
    )
    .expect("bind two ephemeral listeners");
    assert_eq!(runtime.bound_addrs().len(), 2);

    for addr in runtime.bound_addrs() {
        let mut client =
            TcpStream::connect(("127.0.0.1", addr.port())).expect("connect to a bound listener");
        let _ = client.write_all(&[0x01]);
    }

    // Give the accept threads a moment to observe both connections
    // before shutting down.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while count.load(Ordering::SeqCst) < 2 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }

    // shutdown() joins both accept threads; if one failed to stop, this
    // would hang the test rather than return.
    runtime.shutdown();
    assert_eq!(count.load(Ordering::SeqCst), 2, "both connections accepted");
}

/// Start a listener runtime whose handler serves inbound peers, then
/// connect as a peer, negotiate, exchange verack, and confirm a ping is
/// answered with a pong — the full accept-to-serve path.
#[test]
fn serves_an_inbound_peer_through_the_handler() {
    use dcroxide_node::peerconn::NodePeerEnv;
    use dcroxide_node::runtime::{ConnectedPeers, PeerTemplate, inbound_peer_handler};
    use dcroxide_node::transport::WireTransport;
    use dcroxide_peer::{Config, MAX_PROTOCOL_VERSION, MsgTransport, Peer, PeerGlobals};
    use dcroxide_wire::{CurrencyNet, Message, MsgPing, ServiceFlag};

    const NET: CurrencyNet = CurrencyNet::TEST_NET3;

    let template = PeerTemplate {
        net: NET,
        protocol_version: 0,
        services: ServiceFlag(1),
        user_agent_name: "dcroxide".to_string(),
        user_agent_version: "0.1.0".to_string(),
        // Long enough that neither fires during the test.
        idle_timeout: Duration::from_secs(3600),
        ping_interval: Duration::from_secs(3600),
    };

    let runtime = ListenerRuntime::start(
        &[("tcp4", ":0".to_string())],
        inbound_peer_handler(template, ConnectedPeers::new()),
    )
    .expect("start serving runtime");
    let port = runtime.bound_addrs()[0].port();

    // Connect as an outbound peer and complete the handshake.
    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to the server");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut transport = WireTransport::new(stream, MAX_PROTOCOL_VERSION, NET);
    let mut env = NodePeerEnv::new();
    let mut globals = PeerGlobals::new();
    let client_config = Config {
        net: NET,
        services: ServiceFlag(1),
        user_agent_name: "dcroxide-client".to_string(),
        user_agent_version: "0.1.0".to_string(),
        protocol_version: 0,
        ..Config::default()
    };
    let mut peer =
        Peer::new_outbound(client_config, &format!("127.0.0.1:{port}")).expect("outbound peer");
    let remote = peer
        .negotiate_outbound_protocol(&mut transport, &mut env, &mut globals)
        .expect("negotiate with the server");
    assert!(
        remote.user_agent.contains("dcroxide"),
        "server user agent: {}",
        remote.user_agent
    );

    // Exchange verack and confirm the server answers a ping with a pong.
    transport
        .write_message(&Message::VerAck)
        .expect("send verack");
    let ping_nonce = 0x1234_5678_9abc_def0_u64;
    transport
        .write_message(&Message::Ping(MsgPing { nonce: ping_nonce }))
        .expect("send ping");
    assert_eq!(
        transport.read_message().expect("read verack"),
        Message::VerAck
    );
    match transport.read_message().expect("read pong") {
        Message::Pong(pong) => assert_eq!(pong.nonce, ping_nonce),
        other => panic!("expected pong, got {other:?}"),
    }

    drop(transport);
    runtime.shutdown();
}

/// A served peer is tracked in the connected-peers registry while it is
/// active, and disconnecting all peers unblocks it so it deregisters.
#[test]
fn disconnecting_all_peers_tears_down_a_served_connection() {
    use dcroxide_node::peerconn::NodePeerEnv;
    use dcroxide_node::runtime::{ConnectedPeers, PeerTemplate, inbound_peer_handler};
    use dcroxide_node::transport::WireTransport;
    use dcroxide_peer::{Config, MAX_PROTOCOL_VERSION, Peer, PeerGlobals};
    use dcroxide_wire::{CurrencyNet, ServiceFlag};

    const NET: CurrencyNet = CurrencyNet::TEST_NET3;

    let template = PeerTemplate {
        net: NET,
        protocol_version: 0,
        services: ServiceFlag(1),
        user_agent_name: "dcroxide".to_string(),
        user_agent_version: "0.1.0".to_string(),
        idle_timeout: Duration::from_secs(3600),
        ping_interval: Duration::from_secs(3600),
    };

    let connected = ConnectedPeers::new();
    let runtime = ListenerRuntime::start(
        &[("tcp4", ":0".to_string())],
        inbound_peer_handler(template, connected.clone()),
    )
    .expect("start serving runtime");
    let port = runtime.bound_addrs()[0].port();

    // Connect and negotiate so the peer is registered as live.
    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut transport = WireTransport::new(stream, MAX_PROTOCOL_VERSION, NET);
    let mut env = NodePeerEnv::new();
    let mut globals = PeerGlobals::new();
    let config = Config {
        net: NET,
        protocol_version: 0,
        ..Config::default()
    };
    let mut peer = Peer::new_outbound(config, &format!("127.0.0.1:{port}")).expect("outbound peer");
    peer.negotiate_outbound_protocol(&mut transport, &mut env, &mut globals)
        .expect("negotiate");

    // The peer should register shortly after the handshake.
    assert!(
        wait_until(Duration::from_secs(5), || connected.len() == 1),
        "the served peer should be registered as live"
    );

    // Disconnecting all peers unblocks the served connection so it winds
    // down and deregisters itself.
    connected.disconnect_all();
    assert!(
        wait_until(Duration::from_secs(5), || connected.is_empty()),
        "the served peer should deregister after being disconnected"
    );

    drop(transport);
    runtime.shutdown();
}

/// Poll `cond` until it holds or the timeout elapses.
fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    cond()
}
