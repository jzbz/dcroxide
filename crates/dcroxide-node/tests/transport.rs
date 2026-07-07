// SPDX-License-Identifier: ISC
//! Integration check for the wire-message transport over a real TCP
//! connection: a message framed and written on one end is read back
//! byte-identically on the other, exercising the same socket path the
//! daemon's peer loops use.

use std::io::Write;
use std::net::{TcpListener, TcpStream};

use dcroxide_node::transport::WireTransport;
use dcroxide_peer::{MAX_PROTOCOL_VERSION, MsgTransport};
use dcroxide_wire::{CurrencyNet, Message, MsgPing};

const NET: CurrencyNet = CurrencyNet(0xd9b4_00f9);

#[test]
fn round_trips_messages_over_a_tcp_connection() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
    let addr = listener.local_addr().expect("listener addr");

    let client = TcpStream::connect(addr).expect("connect to listener");
    let (server, _peer) = listener.accept().expect("accept the connection");

    let mut client_transport = WireTransport::new(client, MAX_PROTOCOL_VERSION, NET);
    let mut server_transport = WireTransport::new(server, MAX_PROTOCOL_VERSION, NET);

    // Client -> server: a ping with a distinctive nonce, then a verack.
    let ping = Message::Ping(MsgPing {
        nonce: 0x0011_2233_4455_6677,
    });
    client_transport.write_message(&ping).expect("write ping");
    client_transport
        .write_message(&Message::VerAck)
        .expect("write verack");

    assert_eq!(server_transport.read_message().expect("read ping"), ping);
    assert_eq!(
        server_transport.read_message().expect("read verack"),
        Message::VerAck
    );

    // Server -> client: the pong reply travels the other direction.
    server_transport
        .write_message(&Message::Pong(dcroxide_wire::MsgPong {
            nonce: 0x0011_2233_4455_6677,
        }))
        .expect("write pong");
    // Ensure the write is flushed to the socket before reading.
    server_transport.get_mut().flush().expect("flush server");

    match client_transport.read_message().expect("read pong") {
        Message::Pong(pong) => assert_eq!(pong.nonce, 0x0011_2233_4455_6677),
        other => panic!("expected pong, got {other:?}"),
    }

    assert!(client_transport.bytes_written() > 0);
    assert!(server_transport.bytes_read() > 0);
}
