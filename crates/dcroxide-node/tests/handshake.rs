// SPDX-License-Identifier: ISC
//! Integration check for the version handshake: an inbound and an
//! outbound peer, each running the ported negotiation over the daemon's
//! [`WireTransport`] and [`NodePeerEnv`], complete the version exchange
//! over a real loopback TCP connection and each learns the other's
//! advertised protocol version, services, and user agent.

use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use dcroxide_node::peerconn::{NodePeerEnv, net_address_from_socket};
use dcroxide_node::transport::WireTransport;
use dcroxide_peer::{Config, MAX_PROTOCOL_VERSION, Peer, PeerEnv, PeerGlobals};
use dcroxide_wire::{CurrencyNet, ServiceFlag};

const NET: CurrencyNet = CurrencyNet::TEST_NET3;
const SERVICES: ServiceFlag = ServiceFlag(1);

fn config(user_agent_name: &str) -> Config {
    Config {
        net: NET,
        services: SERVICES,
        user_agent_name: user_agent_name.to_string(),
        user_agent_version: "0.1.0".to_string(),
        // 0 selects the package's maximum protocol version.
        protocol_version: 0,
        ..Config::default()
    }
}

#[test]
fn negotiates_version_between_inbound_and_outbound_peers() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
    let server_addr = listener.local_addr().expect("listener addr");

    // The outbound peer runs on its own thread because negotiation
    // blocks: it writes its version, then waits for the inbound peer's.
    let outbound = thread::spawn(move || {
        let stream = TcpStream::connect(server_addr).expect("dial the listener");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        let mut transport = WireTransport::new(stream, MAX_PROTOCOL_VERSION, NET);
        let mut env = NodePeerEnv::new();
        let mut globals = PeerGlobals::new();
        let mut peer = Peer::new_outbound(config("dcroxide-out"), &server_addr.to_string())
            .expect("build outbound peer");
        let remote = peer
            .negotiate_outbound_protocol(&mut transport, &mut env, &mut globals)
            .expect("outbound negotiation");
        (
            peer.protocol_version(),
            peer.user_agent().to_string(),
            remote.user_agent,
        )
    });

    // The inbound peer reads the version first, then replies with its
    // own, mirroring the accept side of the server.
    let (server_stream, remote_addr) = listener.accept().expect("accept connection");
    server_stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut transport = WireTransport::new(server_stream, MAX_PROTOCOL_VERSION, NET);
    let mut env = NodePeerEnv::new();
    let mut globals = PeerGlobals::new();
    let mut peer = Peer::new_inbound(config("dcroxide-in"));
    let na = net_address_from_socket(remote_addr, ServiceFlag(0)).expect("remote net address");
    peer.associate(&remote_addr.to_string(), na, env.now_nanos());
    let remote = peer
        .negotiate_inbound_protocol(&mut transport, &mut env, &mut globals)
        .expect("inbound negotiation");

    // The inbound peer learned the outbound peer's advertised details.
    assert!(peer.handshake_done());
    assert_eq!(peer.protocol_version(), MAX_PROTOCOL_VERSION);
    assert_eq!(peer.services(), SERVICES);
    assert!(
        remote.user_agent.contains("dcroxide-out"),
        "remote user agent: {}",
        remote.user_agent
    );
    // The peer records the remote's user agent as its own view of it.
    assert_eq!(peer.user_agent(), remote.user_agent);

    let (out_pver, out_self_ua, out_remote_ua) = outbound.join().expect("outbound thread");
    assert_eq!(out_pver, MAX_PROTOCOL_VERSION);
    // The outbound peer learned the inbound peer's advertised details.
    assert!(
        out_remote_ua.contains("dcroxide-in"),
        "remote user agent: {out_remote_ua}"
    );
    assert_eq!(out_self_ua, out_remote_ua);
}
