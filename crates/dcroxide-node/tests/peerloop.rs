// SPDX-License-Identifier: ISC
//! Integration checks for the per-peer input pump and output handler:
//! after the version handshake the inbound peer sends its verack and
//! runs the input loop, marking the remote's verack, answering a ping
//! with a pong, and forwarding every message; and the output handler
//! drains an outbound queue to the connection in order, all over real
//! loopback TCP connections.

use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use dcroxide_node::peerconn::{NodePeerEnv, net_address_from_socket};
use dcroxide_node::peerloop::{OutboundQueue, run_peer_input, run_peer_output, send_verack};
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
fn inbound_peer_completes_verack_and_answers_a_ping() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
    let server_addr = listener.local_addr().expect("listener addr");
    let ping_nonce = 0xfeed_face_dead_beef_u64;

    // Server side: negotiate, send verack, then run the input loop until
    // the client closes the connection.
    let server = thread::spawn(move || {
        let (stream, remote_addr) = listener.accept().expect("accept connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        let mut transport = WireTransport::new(stream, MAX_PROTOCOL_VERSION, NET);
        let mut env = NodePeerEnv::new();
        let mut globals = PeerGlobals::new();
        let mut peer = Peer::new_inbound(config("dcroxide-in"));
        let na = net_address_from_socket(remote_addr, ServiceFlag(0)).expect("net address");
        peer.associate(&remote_addr.to_string(), na, env.now_nanos());
        peer.negotiate_inbound_protocol(&mut transport, &mut env, &mut globals)
            .expect("inbound negotiation");

        send_verack(&mut transport).expect("send verack");

        let mut forwarded: Vec<Message> = Vec::new();
        let reason = run_peer_input(&mut peer, &mut transport, &mut env, |_peer, msg| {
            forwarded.push(msg.clone());
        });
        (peer.verack_received(), forwarded, format!("{reason:?}"))
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

    send_verack(&mut transport).expect("send verack");
    transport
        .write_message(&Message::Ping(MsgPing { nonce: ping_nonce }))
        .expect("send ping");

    // The server replies with its verack (on start) and a pong (in
    // answer to the ping).
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
