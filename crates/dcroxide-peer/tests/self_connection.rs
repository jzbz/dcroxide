// SPDX-License-Identifier: ISC
//! Self-connection detection needs one shared nonce cache (RVW-038).
//!
//! dcrd keeps `sentNonces` in a package global (`peer/peer.go:83-92`):
//! the nonce written when pushing a version message on one connection is
//! what the *next* connection's inbound handshake checks against. A node
//! that dials its own address sees its own nonce come back and
//! disconnects with `ErrSelfConnection`.
//!
//! The port built a fresh `PeerGlobals` per connection, so the outbound
//! half held only its own nonce and the inbound half checked an empty
//! set. Neither could match, the check was dead, and a node that dialled
//! itself completed the handshake and peered with itself. Nothing else
//! catches it: there is no self-address filter on the outbound path in
//! either implementation.
//!
//! The two halves are driven here as two peers over one `PeerGlobals`,
//! which is exactly the shape the daemon now uses.

use std::sync::Mutex;

use dcroxide_peer::{Config, MsgTransport, Peer, PeerEnv, PeerGlobals, ReadError};
use dcroxide_wire::{CurrencyNet, Message, MsgVersion, NetAddress, PROTOCOL_VERSION, ServiceFlag};

const NET: CurrencyNet = CurrencyNet::TEST_NET3;

struct FixedEnv;

impl PeerEnv for FixedEnv {
    fn now_nanos(&mut self) -> i64 {
        1_700_000_000 * 1_000_000_000
    }
    fn rand_u64(&mut self) -> u64 {
        // The nonce every outbound version carries here.
        0xdead_beef_feed_face
    }
    fn shuffle_addrs(&mut self, _addrs: &mut [NetAddress]) {}
    fn shuffle_addrs_v2(&mut self, _addrs: &mut [dcroxide_wire::NetAddressV2]) {}
}

/// Captures what was written and replays a scripted read.
struct Loopback {
    scripted: Vec<Message>,
    written: Vec<Message>,
}

impl MsgTransport for Loopback {
    fn read_message(&mut self) -> Result<Message, ReadError> {
        if self.scripted.is_empty() {
            return Err(ReadError::io("EOF"));
        }
        Ok(self.scripted.remove(0))
    }
    fn write_message(&mut self, msg: &Message) -> Result<(), String> {
        self.written.push(msg.clone());
        Ok(())
    }
}

fn cfg(name: &str) -> Config {
    Config {
        net: NET,
        services: ServiceFlag(1),
        user_agent_name: name.to_string(),
        user_agent_version: "0.1.0".to_string(),
        protocol_version: 0,
        ..Config::default()
    }
}

/// The version message the outbound half wrote, as it would arrive back
/// on the connection a node made to itself.
fn version_with(nonce: u64) -> Message {
    Message::Version(MsgVersion {
        protocol_version: PROTOCOL_VERSION as i32,
        services: ServiceFlag(1),
        timestamp: 1_700_000_000,
        addr_you: NetAddress::default(),
        addr_me: NetAddress::default(),
        nonce,
        user_agent: "/self:1.0.0/".to_string(),
        last_block: 0,
        disable_relay_tx: false,
    })
}

#[test]
fn a_nonce_sent_on_one_connection_is_caught_on_the_next() {
    let globals = PeerGlobals::new();
    let mut env = FixedEnv;

    // Connection one: the outbound half writes its version, which
    // records the nonce.
    let mut out_transport = Loopback {
        scripted: Vec::new(),
        written: Vec::new(),
    };
    let mut outbound =
        Peer::new_outbound(cfg("dcroxide-out"), "127.0.0.1:9108").expect("outbound peer");
    // The handshake cannot complete against an empty script; what
    // matters is that the version went out first.
    let _ = outbound.negotiate_outbound_protocol(&mut out_transport, &mut env, &globals, None);

    let sent_nonce = out_transport
        .written
        .iter()
        .find_map(|m| match m {
            Message::Version(v) => Some(v.nonce),
            _ => None,
        })
        .expect("the outbound half writes a version message");

    // Connection two: that same nonce arrives inbound, which is what a
    // node that dialled its own address sees.
    let mut in_transport = Loopback {
        scripted: vec![version_with(sent_nonce)],
        written: Vec::new(),
    };
    let mut inbound = Peer::new_inbound(cfg("dcroxide-in"));
    let err = match inbound.negotiate_inbound_protocol(&mut in_transport, &mut env, &globals, None)
    {
        Ok(_) => panic!("the node completed a handshake with itself"),
        Err(e) => e,
    };
    assert!(
        err.message.contains("connected to self"),
        "expected dcrd's self-connection rejection, got: {}",
        err.message,
    );
}

/// And an unrelated peer's nonce must still be accepted, or the check
/// above would hold for a reason that has nothing to do with the cache.
#[test]
fn another_peers_nonce_is_not_mistaken_for_our_own() {
    let globals = PeerGlobals::new();
    let mut env = FixedEnv;

    let mut out_transport = Loopback {
        scripted: Vec::new(),
        written: Vec::new(),
    };
    let mut outbound =
        Peer::new_outbound(cfg("dcroxide-out"), "127.0.0.1:9108").expect("outbound peer");
    let _ = outbound.negotiate_outbound_protocol(&mut out_transport, &mut env, &globals, None);

    let mut in_transport = Loopback {
        scripted: vec![version_with(0x0123_4567_89ab_cdef)],
        written: Vec::new(),
    };
    let mut inbound = Peer::new_inbound(cfg("dcroxide-in"));
    let outcome = inbound.negotiate_inbound_protocol(&mut in_transport, &mut env, &globals, None);
    let err = match outcome {
        Ok(_) => return, // got past the version, which is the point
        Err(e) => e,
    };
    assert!(
        !err.message.contains("connected to self"),
        "a stranger's nonce must not read as our own: {}",
        err.message,
    );
}

/// One `PeerGlobals` shared across threads is the shape the daemon uses,
/// so it has to be `Sync`.
#[test]
fn peer_globals_can_be_shared() {
    fn assert_sync<T: Sync>() {}
    assert_sync::<PeerGlobals>();
    let _ = Mutex::new(());
}
