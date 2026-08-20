// SPDX-License-Identifier: ISC
//! Wire-protocol violations ban during the handshake too (RVW-012).
//!
//! dcrd installs its read listener before `Handshake` for both
//! directions and runs it on the version and verack reads
//! (`peer/peer.go:1912`, `:1983`, `:2012`); `serverPeer.OnRead` bans on
//! any `wire.ErrorCode` with no handshake-state guard
//! (`server.go:1851-1857`).
//!
//! The port dropped the classification on the way out of the handshake
//! — all three reads collapsed into an untyped `NegotiateError` — so a
//! peer could violate the protocol indefinitely by simply never
//! completing one, and pay nothing.
//!
//! The read sites' classification is covered directly in
//! `crates/dcroxide-peer/tests/handshake_classification.rs`; this drives
//! the whole connection so the hook wiring is covered too.
//!
//! The other half is what must *not* ban.  dcrd returns `BtcDecode`'s
//! error raw, so a body that runs out mid-decode carries no
//! `wire.ErrorCode` and the peer is dropped without a ban.  These reads
//! are unauthenticated, so over-banning there costs an honest peer 24
//! hours over a decoder parity gap.

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use dcroxide_node::peerconn::net_address_v2_from_socket;
use dcroxide_node::peerloop::{OutboundQueue, ServeHooks, ServeSignal, run_peer_connection};
use dcroxide_peer::{Config, MAX_PROTOCOL_VERSION, Peer};
use dcroxide_wire::{CurrencyNet, MESSAGE_HEADER_SIZE, Message, MsgPing, ServiceFlag};

const NET: CurrencyNet = CurrencyNet::TEST_NET3;

/// The byte offset of the little-endian payload length, after the
/// 4-byte magic and the 12-byte command.
const PAYLOAD_LEN_OFFSET: usize = 16;

fn config(user_agent_name: &str) -> Config {
    Config {
        net: NET,
        services: ServiceFlag(1),
        user_agent_name: user_agent_name.to_string(),
        user_agent_version: "0.1.0".to_string(),
        protocol_version: 0,
        ..Config::default()
    }
}

/// Records what the server would have banned on.
#[derive(Clone, Default)]
struct BanRecorder(Arc<Mutex<Vec<String>>>);

impl ServeHooks for BanRecorder {
    fn on_wire_violation(&mut self, err: &str) {
        self.0.lock().expect("recorder").push(err.to_string());
    }

    fn on_message(
        &mut self,
        _peer: &mut Peer,
        _msg: &Message,
        _outbound: &OutboundQueue,
    ) -> ServeSignal {
        // No handshake here completes, so nothing reaches this.
        ServeSignal::Continue
    }
}

/// Run a server peer against a client that writes `frames` and closes,
/// returning whatever the server would have banned on.
fn drive(frames: Vec<Vec<u8>>) -> Vec<String> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
    let addr = listener.local_addr().expect("listener addr");
    let recorder = BanRecorder::default();
    let observed = Arc::clone(&recorder.0);

    let server = thread::spawn(move || {
        let (stream, remote_addr) = listener.accept().expect("accept connection");
        let mut peer = Peer::new_inbound(config("dcroxide-in"));
        let na = net_address_v2_from_socket(remote_addr, ServiceFlag(0)).expect("net address");
        peer.associate(&remote_addr.to_string(), na, 0);
        run_peer_connection(
            stream,
            peer,
            MAX_PROTOCOL_VERSION,
            NET,
            Duration::from_secs(30),
            Duration::from_secs(30),
            None,
            recorder,
        );
    });

    let mut stream = TcpStream::connect(addr).expect("dial the listener");
    for frame in frames {
        // The server may already have hung up on us; that is the point.
        let _ = stream.write_all(&frame);
    }
    let _ = stream.flush();
    drop(stream);
    server.join().expect("server thread");

    observed.lock().expect("recorder").clone()
}

/// A header whose declared length exceeds `ping`'s own maximum: a coded
/// `wire.ErrorCode`, rejected from the header alone.
fn oversized_ping_header() -> Vec<u8> {
    let mut header = vec![0u8; MESSAGE_HEADER_SIZE];
    header[0..4].copy_from_slice(&NET.0.to_le_bytes());
    header[4..8].copy_from_slice(b"ping");
    header[PAYLOAD_LEN_OFFSET..PAYLOAD_LEN_OFFSET + 4]
        .copy_from_slice(&(8u32 * 1024 * 1024).to_le_bytes());
    header
}

/// A `ping` framed honestly around a body four bytes short of its nonce:
/// correct magic, known command, honest length, matching checksum. Only
/// the decoder can fail, and it fails by running out.
fn short_bodied_ping() -> Vec<u8> {
    let framed = dcroxide_wire::write_message(
        &Message::Ping(MsgPing {
            nonce: 0x0123_4567_89ab_cdef,
        }),
        MAX_PROTOCOL_VERSION,
        NET,
    )
    .expect("frame a ping");
    let body = &framed[MESSAGE_HEADER_SIZE..MESSAGE_HEADER_SIZE + 4];

    let mut frame = framed[..MESSAGE_HEADER_SIZE].to_vec();
    frame[PAYLOAD_LEN_OFFSET..PAYLOAD_LEN_OFFSET + 4]
        .copy_from_slice(&(body.len() as u32).to_le_bytes());
    let checksum = dcroxide_chainhash::hash_b(body);
    frame[PAYLOAD_LEN_OFFSET + 4..MESSAGE_HEADER_SIZE].copy_from_slice(&checksum[..4]);
    frame.extend_from_slice(body);
    frame
}

/// The primary discriminator: a coded violation as the very first frame,
/// before any handshake state exists at all.
#[test]
fn a_wire_violation_in_place_of_the_version_bans() {
    let banned = drive(vec![oversized_ping_header()]);
    assert_eq!(
        banned.len(),
        1,
        "a coded wire violation before the handshake must ban: {banned:?}",
    );
}

/// A body that ends mid-decode is dropped, not banned — dcrd's
/// `errors.As` finds no code. This is the companion narrowing's
/// discriminator, and the reason the ban widening is safe to make.
#[test]
fn a_payload_that_ends_mid_decode_does_not_ban() {
    let banned = drive(vec![short_bodied_ping()]);
    assert!(
        banned.is_empty(),
        "a short body carries no wire.ErrorCode and must not ban: {banned:?}",
    );
}

/// A peer that simply hangs up mid-handshake is not a violation either,
/// so the widening cannot be a blanket "any negotiation failure bans".
#[test]
fn a_peer_that_disconnects_during_the_handshake_does_not_ban() {
    let banned = drive(Vec::new());
    assert!(
        banned.is_empty(),
        "an abandoned handshake is an I/O failure, not a violation: {banned:?}",
    );
}
