// SPDX-License-Identifier: ISC
//! A read failure during the handshake keeps its wire classification
//! (RVW-012).
//!
//! dcrd runs its `OnRead` listener on the version and verack reads too
//! (`peer/peer.go:1912`, `:1983`, `:2012`), and `serverPeer.OnRead` bans
//! on any `wire.ErrorCode` with no handshake-state guard
//! (`server.go:1851-1857`).  All three of the port's handshake reads
//! collapsed their `ReadError` into an untyped `NegotiateError`, so the
//! daemon could not tell a protocol violation from a dropped connection
//! and never banned for one — a peer could violate the protocol
//! indefinitely by never completing a handshake.
//!
//! The three reads are covered separately because they are three
//! distinct call sites: a fix that threaded the classification through
//! only the first would pass the version case and fail the other two.
//! The I/O cases are the false controls — they are what stops the
//! opposite error, banning on any handshake failure at all.

use dcroxide_peer::{Config, MsgTransport, Peer, PeerEnv, PeerGlobals, ReadError};
use dcroxide_wire::{
    ADDR_V2_VERSION, CurrencyNet, Message, MsgVersion, NetAddress, PROTOCOL_VERSION, ServiceFlag,
};

const NET: CurrencyNet = CurrencyNet::TEST_NET3;

struct FixedEnv;

impl PeerEnv for FixedEnv {
    fn now_nanos(&mut self) -> i64 {
        1_700_000_000 * 1_000_000_000
    }
    fn rand_u64(&mut self) -> u64 {
        0x1234_5678_9abc_def0
    }
    fn shuffle_addrs(&mut self, _addrs: &mut [NetAddress]) {}
    fn shuffle_addrs_v2(&mut self, _addrs: &mut [dcroxide_wire::NetAddressV2]) {}
}

/// Hands out scripted messages, then fails with a chosen error.
struct FailAfter {
    scripted: Vec<Message>,
    err: ReadError,
}

impl MsgTransport for FailAfter {
    fn read_message(&mut self) -> Result<Message, ReadError> {
        if self.scripted.is_empty() {
            return Err(self.err.clone());
        }
        Ok(self.scripted.remove(0))
    }
    fn write_message(&mut self, _msg: &Message) -> Result<(), String> {
        Ok(())
    }
}

fn cfg() -> Config {
    Config {
        net: NET,
        services: ServiceFlag(1),
        user_agent_name: "peertest".to_string(),
        user_agent_version: "1.2.3".to_string(),
        protocol_version: 0,
        ..Config::default()
    }
}

/// A version message the negotiation accepts, so a later read is
/// reached.  `pver` selects which verack reader runs: at or above
/// `ADDR_V2_VERSION` the strict one, below it the tolerant loop that
/// queues up to three non-verack messages.
fn good_version_at(pver: u32) -> Message {
    Message::Version(MsgVersion {
        protocol_version: pver as i32,
        services: ServiceFlag(1),
        timestamp: 1_700_000_000,
        addr_you: NetAddress::default(),
        addr_me: NetAddress::default(),
        // Any nonce but the local one; self-connection detection compares
        // against the nonces this peer has sent.
        nonce: 0xfeed_face_dead_beef,
        user_agent: "/remote:1.0.0/".to_string(),
        last_block: 0,
        disable_relay_tx: false,
    })
}

/// Drive an inbound handshake whose read at `after` scripted messages
/// fails with `err`, and report the resulting classification.
fn inbound_classification(scripted: Vec<Message>, err: ReadError) -> bool {
    let mut transport = FailAfter { scripted, err };
    let mut peer = Peer::new_inbound(cfg());
    let mut env = FixedEnv;
    let globals = PeerGlobals::new();
    match peer.negotiate_inbound_protocol(&mut transport, &mut env, &globals, None) {
        Ok(_) => panic!("the scripted read was supposed to fail the handshake"),
        Err(e) => e.wire_violation,
    }
}

#[test]
fn a_wire_violation_reading_the_version_is_classified_as_one() {
    assert!(
        inbound_classification(Vec::new(), ReadError::wire("ErrPayloadTooLarge")),
        "a coded violation on the version read must survive as one",
    );
}

#[test]
fn an_io_failure_reading_the_version_is_not_a_violation() {
    assert!(
        !inbound_classification(Vec::new(), ReadError::io("connection reset")),
        "an I/O failure on the version read must not ban",
    );
}

#[test]
fn a_wire_violation_reading_the_verack_is_classified_as_one() {
    assert!(
        inbound_classification(
            vec![good_version_at(PROTOCOL_VERSION)],
            ReadError::wire("ErrPayloadTooLarge")
        ),
        "a coded violation after the version was accepted must survive as one",
    );
}

#[test]
fn an_io_failure_reading_the_verack_is_not_a_violation() {
    assert!(
        !inbound_classification(
            vec![good_version_at(PROTOCOL_VERSION)],
            ReadError::io("connection reset")
        ),
        "an I/O failure on the verack read must not ban",
    );
}

/// The third read site: below `ADDR_V2_VERSION` the verack reader
/// tolerates up to three non-verack messages, so a violation on a later
/// read of that loop must classify too.  Covering it separately is what
/// catches a fix that threaded only the two reads above.
#[test]
fn a_wire_violation_in_the_non_verack_tolerance_loop_is_classified_as_one() {
    assert!(
        inbound_classification(
            vec![
                good_version_at(ADDR_V2_VERSION - 1),
                Message::MemPool,
                Message::MemPool,
            ],
            ReadError::wire("ErrPayloadTooLarge"),
        ),
        "a coded violation inside the pre-verack tolerance loop must survive as one",
    );
}

/// And the false control for that same loop.
#[test]
fn an_io_failure_in_the_non_verack_tolerance_loop_is_not_a_violation() {
    assert!(
        !inbound_classification(
            vec![good_version_at(ADDR_V2_VERSION - 1), Message::MemPool],
            ReadError::io("connection reset"),
        ),
        "an I/O failure inside the tolerance loop must not ban",
    );
}
