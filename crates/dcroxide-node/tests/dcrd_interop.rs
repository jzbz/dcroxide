// SPDX-License-Identifier: ISC
//! Interop tests against a real dcrd process over a real socket.
//!
//! The Go oracle (`tools/oracle`) links dcrd's packages in-process and is
//! the right instrument for comparing what a function returns. It cannot
//! test the seam where two *programs* talk: version negotiation across TCP,
//! framing split over real reads, and which side sends what, when. Cuprate
//! covers the analogous seam by spawning monerod inside `cargo test`; this
//! does the same with dcrd.
//!
//! The daemon is built from the parity commit rather than downloaded as a
//! release — a release is a different specification, and `dcroxide-testutil`
//! refuses a binary whose `--version` does not report the pin.
//!
//! simnet, because its proof of work is trivial and it has no seeders to
//! reach for. Skipped unless `DCROXIDE_DCRD_BIN` is set; with
//! `DCROXIDE_REQUIRE_DCRD` set (as in CI) a missing binary is an error, so
//! the leg cannot silently stop testing anything.

use std::net::TcpStream;
use std::time::Duration;

use dcroxide_node::peerconn::NodePeerEnv;
use dcroxide_node::transport::WireTransport;
use dcroxide_peer::{Config, MAX_PROTOCOL_VERSION, MsgTransport, Peer, PeerGlobals};
use dcroxide_testutil::{DcrdNode, dcrd_available, dcrd_or_skip};
use dcroxide_wire::{CurrencyNet, Message, MsgPing, ServiceFlag};

const NET: CurrencyNet = CurrencyNet::SIM_NET;

fn config(user_agent_name: &str) -> Config {
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

/// dcroxide dials dcrd and completes the version handshake.
///
/// This is the direction a syncing node uses, and the one the in-process
/// oracle cannot reach: everything here crosses a socket.
#[test]
fn dcroxide_dials_dcrd_and_negotiates() {
    let Some(dcrd) = dcrd_or_skip() else {
        return;
    };

    let stream = TcpStream::connect(&dcrd.p2p_addr).expect("dial dcrd");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("set read timeout");

    let mut transport = WireTransport::new(stream, MAX_PROTOCOL_VERSION, NET);
    let mut env = NodePeerEnv::new();
    let globals = PeerGlobals::new();
    let mut peer = Peer::new_outbound(config("dcroxide-interop"), &dcrd.p2p_addr)
        .expect("build outbound peer");

    let outcome = peer
        .negotiate_outbound_protocol(&mut transport, &mut env, &globals, None)
        .expect("dcrd must accept dcroxide's version handshake");

    let remote_agent = outcome.remote_version.user_agent;
    assert!(
        remote_agent.contains("dcrd"),
        "the peer should identify as dcrd, got {remote_agent:?}"
    );
    assert!(
        peer.protocol_version() > 0,
        "a protocol version must have been negotiated"
    );
    assert!(
        peer.verack_received(),
        "the handshake is not complete without a verack from dcrd"
    );
}

/// dcrd dials dcroxide and completes the version handshake.
///
/// The reverse direction exercises dcroxide's accept path against a real
/// initiator, including whatever dcrd chooses to send first.
#[test]
fn dcrd_dials_dcroxide_and_negotiates() {
    if !dcrd_available() {
        return;
    }

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let local_addr = listener.local_addr().expect("listener addr");

    // dcrd takes its connect targets at startup, so the listener must exist
    // first and the daemon is spawned pointing at it.
    let dcrd = DcrdNode::spawn_connecting_to(&local_addr.to_string());

    let (stream, _peer_addr) = listener.accept().expect("dcrd should connect back");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("set read timeout");

    let mut transport = WireTransport::new(stream, MAX_PROTOCOL_VERSION, NET);
    let mut env = NodePeerEnv::new();
    let globals = PeerGlobals::new();
    let mut peer = Peer::new_inbound(config("dcroxide-interop"));

    let outcome = peer
        .negotiate_inbound_protocol(&mut transport, &mut env, &globals, None)
        .expect("dcroxide must accept dcrd's version handshake");

    let remote_agent = outcome.remote_version.user_agent;
    assert!(
        remote_agent.contains("dcrd"),
        "the peer should identify as dcrd, got {remote_agent:?}"
    );
    assert!(
        peer.verack_received(),
        "the handshake is not complete without a verack from dcrd"
    );

    // A ping after the handshake proves the session is live in both
    // directions, not merely that negotiation returned.
    transport
        .write_message(&Message::Ping(MsgPing { nonce: 0x5a5a }))
        .expect("send ping to dcrd");
    let mut saw_pong = false;
    for _ in 0..16 {
        match transport.read_message() {
            Ok(Message::Pong(pong)) => {
                assert_eq!(pong.nonce, 0x5a5a, "dcrd must echo the ping nonce");
                saw_pong = true;
                break;
            }
            // dcrd sends its own traffic (addr, getheaders, ping) after the
            // handshake; step past anything that is not our pong.
            Ok(_) => continue,
            Err(e) => panic!("reading from dcrd after the handshake: {e}"),
        }
    }
    assert!(saw_pong, "dcrd never answered the ping");

    drop(dcrd);
}
