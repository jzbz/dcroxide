// SPDX-License-Identifier: ISC
//! Regression tests for the per-peer stall detector (dcrd's
//! `stallHandler`), over real loopback TCP connections.
//!
//! The deadline table was ported long before anything drove it: no
//! stall thread ran, so a peer could ask to be the sync peer, take a
//! `getdata` for every in-flight block slot, answer none of them, and
//! keep the connection alive forever with the 60-second keepalive
//! pings.  Block download stopped with no log line and no recovery
//! short of an operator restart.  These tests pin the wiring that
//! closes it — and, just as importantly, pin the handler-active
//! accounting that keeps it from firing on honest peers while the
//! local node is busy.
//!
//! Every test uses a short injected [`StallConfig`] so a stall is
//! observable in milliseconds instead of dcrd's 30 seconds, and every
//! wait is bounded so a broken detector fails the test instead of
//! hanging it.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use dcroxide_chainhash::Hash;
use dcroxide_node::peerconn::{NodePeerEnv, net_address_v2_from_socket};
use dcroxide_node::peerloop::{
    OutboundQueue, ServeSignal, StallConfig, run_peer_connection_with_stall,
};
use dcroxide_node::transport::WireTransport;
use dcroxide_peer::{
    Config, MAX_PENDING_INV_BURST, MAX_PROTOCOL_VERSION, MsgTransport, Peer, PeerGlobals,
};
use dcroxide_wire::{
    BlockHeader, CurrencyNet, InvType, InvVect, MAX_INV_PER_MSG, Message, MsgBlock, MsgFeeFilter,
    MsgGetData, MsgNotFound, MsgPing, ServiceFlag,
};

const NET: CurrencyNet = CurrencyNet::TEST_NET3;

/// Long enough that neither the idle timer nor the keepalive ping can
/// end a connection during these tests: only the stall detector can.
const NEVER: Duration = Duration::from_secs(3600);

/// The bound on every wait, so a detector that never fires fails the
/// test rather than hanging the suite.
const PATIENCE: Duration = Duration::from_secs(20);

/// The stall timings every test runs under: the tick has to be shorter
/// than the response timeout, exactly as dcrd's 15s tick is shorter
/// than its 30s timeout, or the check that follows a long callback
/// lands after the callback's credit has already been spent.
const FAST_STALL: StallConfig = StallConfig {
    tick: Duration::from_millis(50),
    response_timeout: Duration::from_millis(250),
};

/// The timings for the burst-ceiling test, which is the one test here
/// that is not about stalling.  Its first `getdata` carries a full
/// inventory message — 50,000 items, close to 1.8 MB — and the output
/// loop arms all 50,000 deadlines *before* starting that write, exactly
/// as dcrd's `sccSendMessage` does.  Under [`FAST_STALL`] the 250 ms
/// budget therefore has to cover pushing 1.8 MB across loopback and
/// reading it back, which a loaded machine misses: the detector shuts
/// the socket down mid-message and the read fails on the truncated
/// stream rather than on anything the test is about.  A timeout that
/// cannot expire leaves the burst ceiling as the only thing able to end
/// the connection, which is the whole point of the test.
const CEILING_STALL: StallConfig = StallConfig {
    tick: Duration::from_millis(50),
    response_timeout: NEVER,
};

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

/// The block the served peer is asked for and, in the honest cases,
/// answers.
fn requested_block() -> InvVect {
    InvVect {
        inv_type: InvType::BLOCK,
        hash: Hash([0x7b; 32]),
    }
}

/// A `getdata` for that block: the message that arms the deadline.
fn getdata() -> Message {
    Message::GetData(MsgGetData {
        inv_list: vec![requested_block()],
    })
}

/// dcrd's answer when requested inventory cannot be served; it settles
/// the request just like the data itself would.
fn notfound() -> Message {
    Message::NotFound(MsgNotFound {
        inv_list: vec![requested_block()],
    })
}

/// Serve one inbound connection with the given stall timings, running
/// `on_message` for every message the remote sends.  The reason the
/// connection ended is published on the returned channel.
///
/// `on_message` stands in for the server handlers: the sync manager
/// asking a peer for blocks, and — in the slow-handler case — a long
/// local validation running on the input thread.
fn serve<F>(stall: StallConfig, on_message: F) -> (SocketAddr, mpsc::Receiver<String>)
where
    F: Fn(&Message, &OutboundQueue) + Send + 'static,
{
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
    let addr = listener.local_addr().expect("listener addr");
    let (reason_tx, reason_rx) = mpsc::channel();

    thread::spawn(move || {
        let (stream, remote_addr) = listener.accept().expect("accept connection");
        let mut peer = Peer::new_inbound(config("dcroxide-in"));
        let na = net_address_v2_from_socket(remote_addr, ServiceFlag(0)).expect("net address");
        peer.associate(&remote_addr.to_string(), na, 0);

        let reason = run_peer_connection_with_stall(
            dcroxide_node::transport::Teardown::new(stream),
            peer,
            MAX_PROTOCOL_VERSION,
            NET,
            NEVER,
            NEVER,
            None,
            move |_peer: &mut Peer, msg: &Message, outbound: &OutboundQueue| {
                on_message(msg, outbound);
                ServeSignal::Continue
            },
            stall,
        );
        let _ = reason_tx.send(format!("{reason:?}"));
    });

    (addr, reason_rx)
}

/// Serve a connection that asks for a block the first time the remote
/// pings (nonce 1) and does nothing else.
fn serve_asking_for_a_block() -> (SocketAddr, mpsc::Receiver<String>) {
    serve(FAST_STALL, |msg, outbound| {
        if matches!(msg, Message::Ping(ping) if ping.nonce == 1) {
            outbound.queue_message(getdata()).expect("queue getdata");
        }
    })
}

/// Connect to the served peer and complete the version handshake.
fn dial(addr: SocketAddr) -> WireTransport<TcpStream> {
    let stream = TcpStream::connect(addr).expect("dial the listener");
    stream
        .set_read_timeout(Some(PATIENCE))
        .expect("set read timeout");
    let mut transport = WireTransport::new(stream, MAX_PROTOCOL_VERSION, NET);
    let mut env = NodePeerEnv::new();
    let globals = PeerGlobals::new();
    let mut peer =
        Peer::new_outbound(config("dcroxide-out"), &addr.to_string()).expect("outbound peer");
    peer.negotiate_outbound_protocol(&mut transport, &mut env, &globals, None)
        .expect("outbound negotiation");
    transport
}

/// Read messages until one of `command` arrives, failing on anything
/// that takes longer than the socket's read timeout.
fn read_until(transport: &mut WireTransport<TcpStream>, command: &str) -> Message {
    loop {
        let msg = transport
            .read_message()
            .unwrap_or_else(|e| panic!("waiting for {command}: {e}"));
        if msg.command() == command {
            return msg;
        }
    }
}

/// Ping the served peer and prove it is still answering.
fn assert_still_serving(transport: &mut WireTransport<TcpStream>, nonce: u64) {
    transport
        .write_message(&Message::Ping(MsgPing { nonce }))
        .expect("send ping");
    match read_until(transport, "pong") {
        Message::Pong(pong) => assert_eq!(pong.nonce, nonce),
        other => panic!("expected pong, got {other:?}"),
    }
}

/// The core regression: a peer that is asked for data and never answers
/// is disconnected once the deadline passes.  Before the stall thread
/// was wired this connection lived forever, holding the requested
/// inventory hostage; with the detector unwired the reason never
/// arrives and this fails on the recv timeout instead of hanging.
#[test]
fn a_peer_that_never_answers_a_getdata_is_disconnected() {
    let (addr, reason_rx) = serve_asking_for_a_block();

    let mut transport = dial(addr);
    transport
        .write_message(&Message::Ping(MsgPing { nonce: 1 }))
        .expect("send ping");
    // The request arrives; the connection then goes deliberately mute
    // while staying open, exactly as the attack does.
    read_until(&mut transport, "getdata");

    let reason = reason_rx
        .recv_timeout(PATIENCE)
        .expect("the stalled peer must be disconnected, not served forever");
    assert!(
        reason.contains("stalled"),
        "the connection must end as a stall, got: {reason}"
    );
    drop(transport);
}

/// A peer that answers what it was asked for is left alone: the
/// detector must not manufacture disconnects.  The connection stays
/// serviceable across a dozen stall ticks and only ends when the remote
/// closes it.
#[test]
fn a_peer_that_answers_is_not_disconnected() {
    let (addr, reason_rx) = serve_asking_for_a_block();

    let mut transport = dial(addr);
    transport
        .write_message(&Message::Ping(MsgPing { nonce: 1 }))
        .expect("send ping");
    read_until(&mut transport, "getdata");
    transport
        .write_message(&notfound())
        .expect("send the answer");

    // Sit through a dozen stall ticks with nothing outstanding.
    thread::sleep(Duration::from_millis(600));
    assert!(
        reason_rx.try_recv().is_err(),
        "an answered peer must not be disconnected"
    );
    assert_still_serving(&mut transport, 2);

    // Only closing the connection ends it, and not as a stall.
    drop(transport);
    let reason = reason_rx
        .recv_timeout(PATIENCE)
        .expect("closing the connection must end the loop");
    assert!(
        !reason.contains("stalled"),
        "the connection must not end as a stall, got: {reason}"
    );
}

/// The handler-active accounting: a local callback that runs longer
/// than the response timeout must not be charged to the peer.
///
/// The request goes out first, so its deadline is already ticking; the
/// input loop then spends far longer than that deadline inside one
/// message callback, which is when a long block validation runs in the
/// real node.  The peer's answer is sitting in the socket buffer the
/// whole time and cannot be read until the callback returns, so without
/// the handler-start/handler-done bracket the deadline expires and the
/// node disconnects a peer that did nothing wrong — a self-inflicted
/// partition.  Drop the bracket, or the offset it feeds, and the
/// connection is gone before the callback ends.
#[test]
fn a_slow_local_handler_does_not_disconnect_an_honest_peer() {
    // Three times the response timeout, sixteen stall ticks.
    let slow = Duration::from_millis(800);
    let (addr, reason_rx) = serve(FAST_STALL, move |msg, outbound| match msg {
        Message::Ping(ping) if ping.nonce == 1 => {
            outbound.queue_message(getdata()).expect("queue getdata");
        }
        // The stand-in for a long local operation on the input thread.
        Message::FeeFilter(_) => thread::sleep(slow),
        _ => {}
    });

    let mut transport = dial(addr);
    transport
        .write_message(&Message::Ping(MsgPing { nonce: 1 }))
        .expect("send ping");
    // The deadline for this request is now armed and running.
    read_until(&mut transport, "getdata");

    // Send the trigger for the slow callback, then answer the request.
    // The answer cannot be read until the callback returns, which is
    // precisely the situation the handler offset covers.
    transport
        .write_message(&Message::FeeFilter(MsgFeeFilter { min_fee: 12345 }))
        .expect("send the slow-handler trigger");
    transport
        .write_message(&notfound())
        .expect("send the answer");

    // Outlast the callback, then prove the connection survived it.
    thread::sleep(slow.saturating_add(Duration::from_millis(400)));
    assert!(
        reason_rx.try_recv().is_err(),
        "a slow local handler must not disconnect an honest peer"
    );
    assert_still_serving(&mut transport, 2);

    drop(transport);
    let reason = reason_rx
        .recv_timeout(PATIENCE)
        .expect("closing the connection must end the loop");
    assert!(
        !reason.contains("stalled"),
        "the connection must not end as a stall, got: {reason}"
    );
}

/// Several blocks requested at once, one of them answered: the peer must
/// still be disconnected for the ones it never served.
///
/// This is the regression that motivated moving from
/// release-v2.1.5's command-keyed table to master's per-inventory one.
/// There, a single `getdata` armed one shared entry per *response
/// command*, so any delivered block cleared the deadline for every block
/// in flight. A peer could answer one request just inside the timeout,
/// over and over, and keep all sixteen sync slots pinned while the chain
/// made no progress — while looking, to the detector, like a peer that
/// was answering.
///
/// With per-inventory deadlines the two unanswered items remain
/// accountable on their own, so the stall still fires.
#[test]
fn answering_one_of_several_requested_blocks_does_not_settle_the_rest() {
    // A real block, and the inventory naming it: delivering the block
    // itself is the attack path, and only its own entry may settle.
    let delivered = MsgBlock {
        header: BlockHeader {
            version: 1,
            prev_block: Hash([0u8; 32]),
            merkle_root: Hash([0u8; 32]),
            stake_root: Hash([0u8; 32]),
            vote_bits: 0,
            final_state: [0u8; 6],
            voters: 0,
            fresh_stake: 0,
            revocations: 0,
            pool_size: 0,
            bits: 0,
            sbits: 0,
            height: 0,
            size: 0,
            timestamp: 1,
            nonce: 0x5eed,
            extra_data: [0u8; 32],
            stake_version: 0,
        },
        transactions: Vec::new(),
        stransactions: Vec::new(),
    };
    let wanted: Vec<InvVect> = vec![
        InvVect {
            inv_type: InvType::BLOCK,
            hash: delivered.block_hash(),
        },
        InvVect {
            inv_type: InvType::BLOCK,
            hash: Hash([0x02; 32]),
        },
        InvVect {
            inv_type: InvType::BLOCK,
            hash: Hash([0x03; 32]),
        },
    ];
    let asked = wanted.clone();

    let (addr, reason_rx) = serve(FAST_STALL, move |msg, outbound| {
        if matches!(msg, Message::Ping(ping) if ping.nonce == 1) {
            outbound
                .queue_message(Message::GetData(MsgGetData {
                    inv_list: asked.clone(),
                }))
                .expect("queue getdata");
        }
    });

    let mut transport = dial(addr);
    transport
        .write_message(&Message::Ping(MsgPing { nonce: 1 }))
        .expect("send ping");
    read_until(&mut transport, "getdata");

    // Deliver exactly one of the three blocks, then go mute. Under the
    // old shared-group table this single delivery cleared all three, and
    // repeating it just inside the timeout kept every slot pinned.
    transport
        .write_message(&Message::Block(delivered))
        .expect("deliver one requested block");

    let reason = reason_rx
        .recv_timeout(PATIENCE)
        .expect("the two unanswered blocks must still stall the peer");
    assert!(
        reason.contains("stalled"),
        "the connection must end as a stall, got: {reason}"
    );
    drop(transport);
}

/// Inventory requested across two `getdata` messages, together past the
/// burst ceiling, ends the connection (dcrd's `maxBurst`).
///
/// The ceiling is one and a half full inventory messages, and a single
/// `getdata` is capped at one full message by the wire encoding, so
/// crossing it always takes more than one request — which is exactly the
/// behaviour the guard is for: a peer that keeps asking for more without
/// serving what it already asked for.
///
/// Runs under [`CEILING_STALL`] rather than [`FAST_STALL`]: the peer here
/// never answers the first request either, so a live detector races the
/// ceiling for the teardown and wins on a slow machine, failing the test
/// on a truncated read long before the ceiling is reached.
#[test]
fn getdata_past_the_burst_ceiling_ends_the_connection() {
    fn blocks(range: std::ops::Range<usize>) -> Vec<InvVect> {
        range
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = (i & 0xff) as u8;
                h[1] = ((i >> 8) & 0xff) as u8;
                h[2] = ((i >> 16) & 0xff) as u8;
                InvVect {
                    inv_type: InvType::BLOCK,
                    hash: Hash(h),
                }
            })
            .collect()
    }

    let full = MAX_INV_PER_MSG as usize;
    // The first request fills a full inventory message and is allowed;
    // the second crosses the ceiling by one and must be refused.
    let first = blocks(0..full);
    let second = blocks(full..MAX_PENDING_INV_BURST + 1);
    assert_eq!(first.len() + second.len(), MAX_PENDING_INV_BURST + 1);

    let (addr, reason_rx) = serve(CEILING_STALL, move |msg, outbound| {
        if let Message::Ping(ping) = msg {
            let batch = match ping.nonce {
                1 => first.clone(),
                2 => second.clone(),
                _ => return,
            };
            let _ = outbound.queue_message(Message::GetData(MsgGetData { inv_list: batch }));
        }
    });

    let mut transport = dial(addr);
    transport
        .write_message(&Message::Ping(MsgPing { nonce: 1 }))
        .expect("send first ping");
    read_until(&mut transport, "getdata");
    transport
        .write_message(&Message::Ping(MsgPing { nonce: 2 }))
        .expect("send second ping");

    // The security property: the over-ceiling request is never served,
    // and the connection ends rather than arming it. The refusal itself
    // is logged by the output loop; the teardown reason cannot carry it,
    // because ending that loop shuts the socket down and the connection
    // reports the resulting end of stream instead.
    // Reads end when the connection is torn down, as required.
    while let Ok(msg) = transport.read_message() {
        assert_ne!(
            msg.command(),
            "getdata",
            "the over-ceiling getdata must never reach the peer"
        );
    }
    let reason = reason_rx
        .recv_timeout(PATIENCE)
        .expect("the connection must actually end");
    // The detector cannot fire under `CEILING_STALL`, so the ceiling is
    // the only thing left that could have ended the connection.  Without
    // this the assertion above passes just as happily when a stall wins
    // the race, which is how the timing bug hid.
    assert!(
        !reason.contains("stalled"),
        "the burst ceiling must end the connection, not the stall detector, got: {reason}"
    );
    drop(transport);
}
