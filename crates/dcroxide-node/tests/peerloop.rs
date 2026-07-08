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

use dcroxide_node::peerconn::{NodePeerEnv, net_address_from_socket};
use dcroxide_node::peerloop::{
    OutboundQueue, run_peer_connection, run_peer_input, run_peer_output, run_ping_timer,
    send_verack,
};
use dcroxide_node::transport::WireTransport;
use dcroxide_peer::{Config, MAX_PROTOCOL_VERSION, MsgTransport, Peer, PeerEnv, PeerGlobals};
use dcroxide_wire::{CurrencyNet, Message, MsgPing, MsgPong, ServiceFlag};

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
        let mut globals = PeerGlobals::new();
        let mut peer = Peer::new_inbound(config("dcroxide-in"));
        let na = net_address_from_socket(remote_addr, ServiceFlag(0)).expect("net address");
        peer.associate(&remote_addr.to_string(), na, env.now_nanos());
        peer.negotiate_inbound_protocol(&mut read_transport, &mut env, &mut globals)
            .expect("inbound negotiation");

        let peer = Mutex::new(peer);
        let (queue, outbound) = OutboundQueue::channel();
        send_verack(&queue).expect("queue verack");

        let output = thread::spawn(move || run_peer_output(&mut write_transport, outbound));

        let mut forwarded: Vec<Message> = Vec::new();
        let reason = run_peer_input(
            &peer,
            &mut read_transport,
            &mut env,
            &queue,
            |_peer, msg| {
                forwarded.push(msg.clone());
            },
        );

        // End the output loop by closing the queue, then join it.
        drop(queue);
        let _ = output.join();

        let verack_received = peer.lock().expect("peer mutex").verack_received();
        (verack_received, forwarded, format!("{reason:?}"))
    });

    // Client side: negotiate, send verack and a ping, then read the
    // server's verack and the pong answering the ping before closing.
    let stream = TcpStream::connect(server_addr).expect("dial the listener");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut transport = WireTransport::new(stream, MAX_PROTOCOL_VERSION, NET);
    let mut env = NodePeerEnv::new();
    let mut globals = PeerGlobals::new();
    let mut peer = Peer::new_outbound(config("dcroxide-out"), &server_addr.to_string())
        .expect("outbound peer");
    peer.negotiate_outbound_protocol(&mut transport, &mut env, &mut globals)
        .expect("outbound negotiation");

    transport
        .write_message(&Message::VerAck)
        .expect("send verack");
    transport
        .write_message(&Message::Ping(MsgPing { nonce: ping_nonce }))
        .expect("send ping");

    // The server replies with its verack (queued on start) and a pong
    // (queued in answer to the ping), both written by the output loop.
    assert_eq!(
        transport.read_message().expect("read verack"),
        Message::VerAck
    );
    match transport.read_message().expect("read pong") {
        Message::Pong(pong) => assert_eq!(pong.nonce, ping_nonce),
        other => panic!("expected pong, got {other:?}"),
    }

    // Closing the connection ends the server's input loop.
    drop(transport);

    let (verack_received, forwarded, reason) = server.join().expect("server thread");
    assert!(
        verack_received,
        "server should have marked the remote verack"
    );
    assert_eq!(
        forwarded,
        vec![
            Message::VerAck,
            Message::Ping(MsgPing { nonce: ping_nonce })
        ],
        "the loop forwards every message in order",
    );
    // The loop ended because the client closed the connection.
    assert!(reason.contains("ReadError"), "disconnect reason: {reason}");
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

    let writer = thread::spawn(move || {
        let mut transport = WireTransport::new(client, MAX_PROTOCOL_VERSION, NET);
        run_peer_output(&mut transport, outbound)
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
}

#[test]
fn queue_message_fails_once_the_output_loop_has_stopped() {
    let (queue, outbound) = OutboundQueue::channel();
    // Dropping the receiver ends any output loop and closes the queue.
    drop(outbound);
    let err = queue
        .queue_message(Message::Pong(MsgPong { nonce: 1 }))
        .expect_err("queueing to a closed queue fails");
    assert!(err.contains("closed"), "error: {err}");
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
        let na = net_address_from_socket(remote_addr, ServiceFlag(0)).expect("net address");
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
            move |_peer, msg| sink.lock().expect("sink").push(msg.clone()),
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
    let mut globals = PeerGlobals::new();
    let mut peer = Peer::new_outbound(config("dcroxide-out"), &server_addr.to_string())
        .expect("outbound peer");
    peer.negotiate_outbound_protocol(&mut transport, &mut env, &mut globals)
        .expect("outbound negotiation");

    transport
        .write_message(&Message::VerAck)
        .expect("send verack");
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

    // Closing the connection ends the server's whole connection runtime.
    drop(transport);

    let (forwarded, reason) = server.join().expect("server thread");
    assert_eq!(
        forwarded,
        vec![
            Message::VerAck,
            Message::Ping(MsgPing { nonce: ping_nonce })
        ],
        "the connection forwards every message in order",
    );
    assert!(reason.contains("ReadError"), "disconnect reason: {reason}");
}
