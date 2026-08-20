// SPDX-License-Identifier: ISC
//! Integration checks for the per-peer message loops.  After the version
//! handshake the inbound peer queues its verack and runs the input loop
//! over a shared peer, answering a ping with a pong through the output
//! queue; the output handler drains the queue to the connection in
//! order; and the ping timer queues and records keepalive pings — all
//! over real loopback TCP connections.

use std::net::{TcpListener, TcpStream};
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::Duration;

use dcroxide_node::peerconn::{NodePeerEnv, net_address_v2_from_socket};
use dcroxide_node::peerloop::{
    OutboundQueue, QueueError, ServeSignal, run_peer_connection, run_peer_input, run_peer_output,
    run_ping_timer,
};
use dcroxide_node::transport::WireTransport;
use dcroxide_peer::{Config, MAX_PROTOCOL_VERSION, MsgTransport, Peer, PeerEnv, PeerGlobals};
use dcroxide_wire::{
    CurrencyNet, Message, MsgFeeFilter, MsgPing, MsgPong, MsgTx, ServiceFlag, TxOut,
};

const NET: CurrencyNet = CurrencyNet::TEST_NET3;

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

#[test]
fn inbound_peer_answers_verack_and_ping_through_the_output_queue() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
    let server_addr = listener.local_addr().expect("listener addr");
    let ping_nonce = 0xfeed_face_dead_beef_u64;

    // Server side: negotiate, split the socket into read and write
    // halves, queue the verack, run the output loop on its own thread,
    // and run the input loop over the shared peer.
    let server = thread::spawn(move || {
        let (stream, remote_addr) = listener.accept().expect("accept connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        let write_stream = stream.try_clone().expect("clone stream");
        let mut read_transport = WireTransport::new(stream, MAX_PROTOCOL_VERSION, NET);
        let mut write_transport = WireTransport::new(write_stream, MAX_PROTOCOL_VERSION, NET);
        let mut env = NodePeerEnv::new();
        let globals = PeerGlobals::new();
        let mut peer = Peer::new_inbound(config("dcroxide-in"));
        let na = net_address_v2_from_socket(remote_addr, ServiceFlag(0)).expect("net address");
        peer.associate(&remote_addr.to_string(), na, env.now_nanos());
        let outcome = peer
            .negotiate_inbound_protocol(&mut read_transport, &mut env, &globals, None)
            .expect("inbound negotiation");

        let peer = std::sync::Arc::new(Mutex::new(peer));
        let (queue, outbound) = OutboundQueue::channel();

        let output_peer = std::sync::Arc::clone(&peer);
        let output = thread::spawn(move || {
            let mut output_env = NodePeerEnv::new();
            run_peer_output(
                &output_peer,
                &mut write_transport,
                &mut output_env,
                outbound,
            )
        });

        let mut forwarded: Vec<Message> = Vec::new();
        let reason = run_peer_input(
            &peer,
            &mut read_transport,
            &mut env,
            &queue,
            &mut |_peer: &mut Peer, msg: &Message, _outbound: &OutboundQueue| {
                forwarded.push(msg.clone());
                ServeSignal::Continue
            },
            outcome.delayed,
        );

        // End the output loop by closing the queue, then join it.
        drop(queue);
        let _ = output.join();

        let guard = peer.lock().expect("peer mutex");
        let verack_received = guard.verack_received();
        let snap = guard.stats_snapshot();
        drop(guard);
        (verack_received, forwarded, format!("{reason:?}"), snap)
    });

    // Client side: negotiate, send verack and a ping, then read the
    // server's verack and the pong answering the ping before closing.
    let stream = TcpStream::connect(server_addr).expect("dial the listener");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut transport = WireTransport::new(stream, MAX_PROTOCOL_VERSION, NET);
    let mut env = NodePeerEnv::new();
    let globals = PeerGlobals::new();
    let mut peer = Peer::new_outbound(config("dcroxide-out"), &server_addr.to_string())
        .expect("outbound peer");
    peer.negotiate_outbound_protocol(&mut transport, &mut env, &globals, None)
        .expect("outbound negotiation");

    // The handshake already exchanged the veracks; send a ping.
    transport
        .write_message(&Message::Ping(MsgPing { nonce: ping_nonce }))
        .expect("send ping");

    // The pong answering the ping is written by the output loop.
    match transport.read_message().expect("read pong") {
        Message::Pong(pong) => assert_eq!(pong.nonce, ping_nonce),
        other => panic!("expected pong, got {other:?}"),
    }

    // Closing the connection ends the server's input loop.
    drop(transport);

    let (verack_received, forwarded, reason, snap) = server.join().expect("server thread");
    assert!(
        verack_received,
        "server should have marked the remote verack"
    );
    assert_eq!(
        forwarded,
        vec![Message::Ping(MsgPing { nonce: ping_nonce })],
        "the loop forwards every message in order; the verack was \
         consumed by the handshake",
    );
    // The loop ended because the client closed the connection.
    assert!(reason.contains("ReadError"), "disconnect reason: {reason}");
    // The loops fed the peer's per-message byte accounting: the input
    // pump counted the client's verack and ping, the output loop the
    // server's verack and pong, and both stamped the activity times
    // (dcrd's read/write bookkeeping behind lastsend/lastrecv and the
    // byte counters in getpeerinfo).
    assert!(snap.bytes_recv > 0, "received bytes are counted");
    assert!(snap.bytes_sent > 0, "sent bytes are counted");
    assert!(snap.last_recv_nanos > 0, "the receive time is stamped");
    assert!(snap.last_send_nanos > 0, "the send time is stamped");
}

#[test]
fn output_handler_writes_queued_messages_in_order_then_shuts_down() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
    let addr = listener.local_addr().expect("listener addr");
    let client = TcpStream::connect(addr).expect("dial the listener");
    let (server, _remote) = listener.accept().expect("accept connection");
    server
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    // Queue a couple of messages, then drop the queue so the writer
    // finishes once they are drained.
    let (queue, outbound) = OutboundQueue::channel();
    queue.queue_message(Message::VerAck).expect("queue verack");
    queue
        .queue_message(Message::Ping(MsgPing { nonce: 0x51 }))
        .expect("queue ping");
    drop(queue);

    let writer_peer = std::sync::Arc::new(Mutex::new(Peer::new_inbound(config("dcroxide-out"))));
    let snap_peer = std::sync::Arc::clone(&writer_peer);
    let writer = thread::spawn(move || {
        let mut transport = WireTransport::new(client, MAX_PROTOCOL_VERSION, NET);
        let mut env = NodePeerEnv::new();
        run_peer_output(&writer_peer, &mut transport, &mut env, outbound)
    });

    // The reader sees the queued messages arrive in the order they were
    // queued.
    let mut reader = WireTransport::new(server, MAX_PROTOCOL_VERSION, NET);
    assert_eq!(reader.read_message().expect("read verack"), Message::VerAck);
    assert_eq!(
        reader.read_message().expect("read ping"),
        Message::Ping(MsgPing { nonce: 0x51 })
    );

    // The writer stopped because the queue was closed, not from an error.
    let reason = format!("{:?}", writer.join().expect("writer thread"));
    assert!(
        reason.contains("LocalShutdown"),
        "disconnect reason: {reason}"
    );
    // Both writes fed the peer's send accounting.
    let snap = snap_peer.lock().expect("peer mutex").stats_snapshot();
    assert!(snap.bytes_sent > 0, "sent bytes are counted");
    assert!(snap.last_send_nanos > 0, "the send time is stamped");
}

#[test]
fn queue_message_fails_once_the_output_loop_has_stopped() {
    let (queue, outbound) = OutboundQueue::channel();
    // Dropping the receiver ends any output loop and closes the queue.
    drop(outbound);
    let err = queue
        .queue_message(Message::Pong(MsgPong { nonce: 1 }))
        .expect_err("queueing to a closed queue fails");
    // A closed queue is teardown, not a congested peer; the producers
    // take opposite decisions on the two, so they must stay distinct.
    assert_eq!(err, QueueError::Closed, "error: {err}");
}

#[test]
fn ping_timer_queues_and_records_pings_until_shutdown() {
    let peer = Mutex::new(Peer::new_inbound(config("dcroxide")));
    let (queue, outbound) = OutboundQueue::channel();
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

    let timer = thread::spawn(move || {
        let mut env = NodePeerEnv::new();
        run_ping_timer(
            &peer,
            &mut env,
            &queue,
            Duration::from_millis(20),
            &shutdown_rx,
        );
        peer.lock().expect("peer mutex").last_ping_nonce()
    });

    // The first tick queues a ping.
    let queued = outbound
        .recv_timeout(Duration::from_secs(2))
        .expect("a ping should be queued");
    match queued {
        Message::Ping(_) => {}
        other => panic!("expected a ping, got {other:?}"),
    }

    // Stopping the timer lets it return the last recorded ping nonce,
    // set whenever a ping is queued so the answering pong can be matched.
    shutdown_tx.send(()).expect("signal shutdown");
    let last_recorded = timer.join().expect("timer thread");
    assert_ne!(last_recorded, 0, "a ping nonce should have been recorded");
}

#[test]
fn run_peer_connection_negotiates_and_serves_until_the_remote_closes() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
    let server_addr = listener.local_addr().expect("listener addr");
    let ping_nonce = 0x0bad_c0de_0bad_c0de_u64;

    // Server side: accept, associate the inbound peer, and run the whole
    // connection (handshake + loops) until the client closes.  The ping
    // interval and idle timeout are long so neither fires during the test.
    let server = thread::spawn(move || {
        let (stream, remote_addr) = listener.accept().expect("accept connection");
        let mut peer = Peer::new_inbound(config("dcroxide-in"));
        let na = net_address_v2_from_socket(remote_addr, ServiceFlag(0)).expect("net address");
        peer.associate(&remote_addr.to_string(), na, 0);

        let forwarded = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Message>::new()));
        let sink = std::sync::Arc::clone(&forwarded);
        let reason = run_peer_connection(
            stream,
            peer,
            MAX_PROTOCOL_VERSION,
            NET,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
            None,
            move |_peer: &mut Peer, msg: &Message, _outbound: &OutboundQueue| {
                sink.lock().expect("sink").push(msg.clone());
                ServeSignal::Continue
            },
        );
        let forwarded = forwarded.lock().expect("forwarded").clone();
        (forwarded, format!("{reason:?}"))
    });

    // Client side: negotiate, send verack + ping, read the server's
    // verack and the pong, then close.
    let stream = TcpStream::connect(server_addr).expect("dial the listener");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut transport = WireTransport::new(stream, MAX_PROTOCOL_VERSION, NET);
    let mut env = NodePeerEnv::new();
    let globals = PeerGlobals::new();
    let mut peer = Peer::new_outbound(config("dcroxide-out"), &server_addr.to_string())
        .expect("outbound peer");
    peer.negotiate_outbound_protocol(&mut transport, &mut env, &globals, None)
        .expect("outbound negotiation");

    transport
        .write_message(&Message::Ping(MsgPing { nonce: ping_nonce }))
        .expect("send ping");

    // The connection runtime requests header announcements right
    // after the handshake, then the pong answers the ping.
    assert_eq!(
        transport.read_message().expect("read sendheaders"),
        Message::SendHeaders
    );
    match transport.read_message().expect("read pong") {
        Message::Pong(pong) => assert_eq!(pong.nonce, ping_nonce),
        other => panic!("expected pong, got {other:?}"),
    }

    // Closing the connection ends the server's whole connection runtime.
    drop(transport);

    let (forwarded, reason) = server.join().expect("server thread");
    assert_eq!(
        forwarded,
        vec![Message::Ping(MsgPing { nonce: ping_nonce })],
        "the connection forwards every message in order; the verack \
         was consumed by the handshake",
    );
    assert!(reason.contains("ReadError"), "disconnect reason: {reason}");
}

#[test]
fn run_peer_connection_frames_at_the_negotiated_version_not_the_sentinel() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
    let server_addr = listener.local_addr().expect("listener addr");

    // Server runs the connection with pver 0 — the binary's "package
    // maximum" sentinel. The transport must reframe at the negotiated
    // version after the handshake, not literally 0.
    let server = thread::spawn(move || {
        let (stream, remote_addr) = listener.accept().expect("accept connection");
        let mut peer = Peer::new_inbound(config("dcroxide-in"));
        let na = net_address_v2_from_socket(remote_addr, ServiceFlag(0)).expect("net address");
        peer.associate(&remote_addr.to_string(), na, 0);

        let forwarded = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Message>::new()));
        let sink = std::sync::Arc::clone(&forwarded);
        let _ = run_peer_connection(
            stream,
            peer,
            0,
            NET,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
            None,
            move |_peer: &mut Peer, msg: &Message, _outbound: &OutboundQueue| {
                sink.lock().expect("sink").push(msg.clone());
                ServeSignal::Continue
            },
        );
        forwarded.lock().expect("forwarded").clone()
    });

    let stream = TcpStream::connect(server_addr).expect("dial the listener");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut transport = WireTransport::new(stream, MAX_PROTOCOL_VERSION, NET);
    let mut env = NodePeerEnv::new();
    let globals = PeerGlobals::new();
    let mut peer = Peer::new_outbound(config("dcroxide-out"), &server_addr.to_string())
        .expect("outbound peer");
    peer.negotiate_outbound_protocol(&mut transport, &mut env, &globals, None)
        .expect("outbound negotiation");

    // feefilter is version-gated (FEE_FILTER_VERSION = 5); it decodes only
    // if the server frames at the negotiated version (11), not pver 0
    // where the codec returns MsgInvalidForPVer and the peer is dropped.
    let feefilter = Message::FeeFilter(MsgFeeFilter { min_fee: 12345 });
    transport.write_message(&feefilter).expect("send feefilter");
    assert_eq!(
        transport.read_message().expect("read sendheaders"),
        Message::SendHeaders
    );
    drop(transport);

    let forwarded = server.join().expect("server thread");
    assert!(
        forwarded.contains(&feefilter),
        "the version-gated feefilter should be forwarded (decoded at the \
         negotiated version), got {forwarded:?}"
    );
}

/// A byte-dribbling peer cannot stretch one message read past the
/// absolute budget: dcrd's `SetReadDeadline(now + IdleTimeout)` covers
/// the whole message, not each receive.
#[test]
fn a_dribbled_message_read_ends_at_the_budget() {
    use std::io::Write;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let dribbler = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept");
        // One header byte per 100ms: with a per-receive timeout this
        // 24-byte header would take 2.4s and never time out; the
        // absolute budget must end it at ~300ms.
        for byte in [0xf1u8, 0x86, 0x86, 0x69].iter().cycle().take(24) {
            if conn.write_all(&[*byte]).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });

    let stream = std::net::TcpStream::connect(addr).expect("connect");
    let mut transport = WireTransport::new(stream, MAX_PROTOCOL_VERSION, NET);
    transport.set_read_budget(Some(Duration::from_millis(300)));

    let started = std::time::Instant::now();
    let result = transport.read_message();
    let elapsed = started.elapsed();
    assert!(result.is_err(), "the dribbled read must fail");
    assert!(
        elapsed < Duration::from_millis(1500),
        "the budget must bound the whole message read, took {elapsed:?}"
    );
    drop(transport);
    let _ = dribbler.join();
}

/// A peer that stops reading must not be able to grow its outbound
/// queue without bound: the queue is depth-capped and a send past the
/// cap is refused instead of buffered.
///
/// This is dcroxide hardening, not a dcrd port — dcrd has no bound
/// here.  `peer/peer.go` builds `outputQueue: make(chan outMsg, 5000)`
/// and `queueHandler` moves anything the writer has not taken into a
/// `pendingMsgs []outMsg` slice it grows with `append`, so dcrd buffers
/// 5000 messages in the channel and an unlimited number after it.  (The
/// three-slot semaphore sometimes cited as dcrd's bound is
/// `maxPendingSend` in `server.go`; it limits concurrent getdata serve
/// items only.)  The port's original `mpsc::channel` was unbounded too,
/// so relay, mempool inv and getdata responses piled up for as long as
/// an attacker refused to read.
#[test]
fn outbound_queue_is_depth_capped() {
    let (queue, _receiver) = OutboundQueue::channel();

    // Fill exactly to the cap: every send succeeds while the drain
    // side never runs.
    for i in 0..dcroxide_node::peerloop::MAX_OUTBOUND_QUEUE_DEPTH {
        queue
            .queue_message(Message::Ping(MsgPing { nonce: i as u64 }))
            .unwrap_or_else(|e| panic!("send {i} within the cap must succeed: {e}"));
    }

    // One more is refused rather than buffered, and reported as a
    // congested peer rather than as a closed queue: the producers act
    // on the difference.
    let err = queue
        .queue_message(Message::Ping(MsgPing { nonce: u64::MAX }))
        .expect_err("a send past the cap must fail instead of growing the queue");
    assert_eq!(err, QueueError::Full, "unexpected error: {err}");

    // `try_queue` is the producers' entry point: it reports the drop
    // and answers "not queued" so the caller skips any bookkeeping that
    // would claim the message was sent.
    assert!(
        !queue.try_queue(Message::Ping(MsgPing { nonce: 1 })),
        "try_queue must report a full queue as not queued"
    );
}

/// A transaction message whose charge is dominated by one output script
/// of `script_len` bytes, for driving the queue's byte ceiling without
/// the 128-message depth cap getting there first.
fn bulky_tx(script_len: usize) -> Message {
    let mut tx = MsgTx::default();
    tx.tx_out.push(TxOut {
        value: 0,
        version: 0,
        pk_script: vec![0; script_len],
    });
    Message::Tx(tx)
}

/// The queue's primary bound is bytes, not messages: the depth cap
/// alone let a peer that pipelines max-size requests without reading
/// pin ~46 MB (128 x ~393 KB blocks), so each message is charged its
/// framed size against `MAX_OUTBOUND_QUEUE_BYTES` on enqueue and
/// uncharged when the output loop takes it.  Half-megabyte messages
/// must therefore trip the ceiling long before the 128th slot, and
/// draining one must make room again — the drop-not-disconnect
/// semantics are unchanged, only the ceiling is byte-shaped.
#[test]
fn outbound_queue_is_byte_capped_before_the_depth_cap() {
    let (queue, receiver) = OutboundQueue::channel();

    // Fill with ~500 KB transactions until the byte ceiling refuses
    // one.  The depth cap must play no part: 128 of these would be
    // ~64 MB, sixteen times the byte budget.
    let mut queued = 0usize;
    loop {
        match queue.queue_message(bulky_tx(500_000)) {
            Ok(()) => {
                queued += 1;
                assert!(
                    queued < dcroxide_node::peerloop::MAX_OUTBOUND_QUEUE_DEPTH,
                    "the byte ceiling must trip before the depth cap"
                );
            }
            Err(e) => {
                assert_eq!(e, QueueError::Full, "a byte-full queue reports Full: {e}");
                break;
            }
        }
    }
    assert!(
        queued >= 2,
        "the budget must admit several large messages, admitted {queued}"
    );
    assert!(
        queued * 500_000 <= dcroxide_node::peerloop::MAX_OUTBOUND_QUEUE_BYTES,
        "admitted messages must fit the byte budget, admitted {queued}"
    );

    // The producers' entry point sees the same refusal.
    assert!(
        !queue.try_queue(bulky_tx(500_000)),
        "try_queue must report a byte-full queue as not queued"
    );

    // Draining one message releases its charge, so the queue accepts
    // again — a congested peer that starts reading recovers, exactly
    // as under the depth cap.
    match receiver.recv_timeout(Duration::from_secs(5)) {
        Ok(Message::Tx(_)) => {}
        other => panic!("expected a queued transaction, got {other:?}"),
    }
    assert!(
        queue.try_queue(bulky_tx(500_000)),
        "draining a message must make room under the byte ceiling"
    );
}

/// A message larger than the whole byte budget is admitted into an
/// empty queue instead of being refused forever: refusing it every time
/// would wedge the connection on a message the write path is perfectly
/// able to send (bounded by the write deadline).  No current message
/// type can exceed the budget — this pins the behavior for any future
/// one.  While the oversized message is queued the budget still holds:
/// everything else is refused until it drains.
#[test]
fn oversized_message_is_admitted_alone_then_the_budget_holds() {
    let (queue, receiver) = OutboundQueue::channel();

    let oversized = 2 * dcroxide_node::peerloop::MAX_OUTBOUND_QUEUE_BYTES;
    assert!(
        queue.try_queue(bulky_tx(oversized)),
        "an empty queue must admit a message larger than the budget"
    );

    // The budget is over-committed, so even a ping is refused.
    let err = queue
        .queue_message(Message::Ping(MsgPing { nonce: 7 }))
        .expect_err("an over-budget queue must refuse further messages");
    assert_eq!(err, QueueError::Full, "error: {err}");

    // Draining the oversized message releases its whole charge.
    match receiver.recv_timeout(Duration::from_secs(5)) {
        Ok(Message::Tx(_)) => {}
        other => panic!("expected the oversized transaction, got {other:?}"),
    }
    assert!(
        queue.try_queue(Message::Ping(MsgPing { nonce: 8 })),
        "draining the oversized message must restore the budget"
    );
}

/// A full outbound queue must not kill the keepalive.  The ping timer is
/// what keeps a live-but-quiet peer from tripping the idle read
/// deadline, so a congested tick has to be skipped and retried: before
/// this fix the timer returned on the first failed enqueue, ending the
/// keepalive for the rest of the connection's life and costing a peer
/// that had one transient burst its connection minutes later, when it
/// was reading again.
#[test]
fn ping_timer_survives_a_full_outbound_queue() {
    let peer = Mutex::new(Peer::new_inbound(config("dcroxide")));
    let (queue, outbound) = OutboundQueue::channel();
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

    // Fill the queue to its cap, the way a peer that stopped reading
    // its socket does.
    for i in 0..dcroxide_node::peerloop::MAX_OUTBOUND_QUEUE_DEPTH {
        queue
            .queue_message(Message::Pong(MsgPong { nonce: i as u64 }))
            .unwrap_or_else(|e| panic!("filler {i} within the cap must succeed: {e}"));
    }

    let timer = thread::spawn(move || {
        let mut env = NodePeerEnv::new();
        run_ping_timer(
            &peer,
            &mut env,
            &queue,
            Duration::from_millis(20),
            &shutdown_rx,
        );
    });

    // Several ticks pass with no room in the queue.
    thread::sleep(Duration::from_millis(150));

    // The peer starts reading again, so the backlog drains.
    for i in 0..dcroxide_node::peerloop::MAX_OUTBOUND_QUEUE_DEPTH {
        match outbound.recv_timeout(Duration::from_secs(5)) {
            Ok(Message::Pong(_)) => {}
            other => panic!("expected filler {i}, got {other:?}"),
        }
    }

    // The keepalive is still running: a later tick gets through.  A
    // timer that gave up on the congested tick has dropped its queue by
    // now, so this receive fails instead.
    match outbound.recv_timeout(Duration::from_secs(5)) {
        Ok(Message::Ping(_)) => {}
        other => panic!("the keepalive must survive a congested tick, got {other:?}"),
    }

    shutdown_tx.send(()).expect("signal shutdown");
    timer.join().expect("timer thread");
}

/// The peer transport must arm a write deadline, so a peer advertising
/// a zero receive window cannot park the writer thread forever.  This
/// pins the plumbing: a transport with a write budget set still writes
/// normally, and the budget is what `run_peer_connection` installs.
#[test]
fn transport_accepts_a_write_budget() {
    use std::io::Cursor;
    let mut transport = WireTransport::new(Cursor::new(Vec::new()), MAX_PROTOCOL_VERSION, NET);
    transport.set_write_stall_policy(Some(dcroxide_node::transport::WriteStallPolicy {
        base: std::time::Duration::from_secs(5),
        bytes_per_sec: dcroxide_peer::WRITE_STALL_BYTES_PER_SEC,
    }));
    transport
        .write_message(&Message::Ping(MsgPing { nonce: 7 }))
        .expect("a write under budget succeeds");
    assert!(transport.bytes_written() > 0);
}
