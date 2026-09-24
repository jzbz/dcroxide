// SPDX-License-Identifier: ISC
//! Peer-to-peer sockets carry TCP_NODELAY, as Go's `newTCPConn`
//! (`net/tcpsock.go`) gives every connection dcrd accepts or dials: an
//! accepted inbound peer, a direct outbound dial, and a dial through a
//! SOCKS5 proxy.  With Nagle's algorithm on, a small message queued
//! behind unacknowledged data waits for the peer's delayed ACK.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use dcroxide_node::runtime::ListenerRuntime;
use dcroxide_node::socks::{NodeDialer, Proxy};

const TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn an_accepted_peer_socket_has_nagle_off() {
    let (tx, rx) = mpsc::channel();
    let tx = Arc::new(Mutex::new(tx));
    let runtime = ListenerRuntime::start(
        &[("tcp4", "127.0.0.1:0".to_string())],
        Arc::new(move |stream: TcpStream, _addr: SocketAddr| {
            let nodelay = stream.nodelay().expect("read TCP_NODELAY");
            let _ = tx.lock().expect("sender").send(nodelay);
        }),
    )
    .expect("start the listener");
    let port = runtime.bound_addrs()[0].port();

    let _client = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let nodelay = rx.recv_timeout(TIMEOUT).expect("the handler ran");
    runtime.shutdown();
    assert!(nodelay, "an accepted peer socket must have TCP_NODELAY set");
}

#[test]
fn a_direct_dial_has_nagle_off() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let conn = NodeDialer::direct().dial(&addr, TIMEOUT).expect("dial");
    let _server = listener.accept().expect("accept");
    assert!(
        conn.nodelay().expect("read TCP_NODELAY"),
        "a direct dial must have TCP_NODELAY set"
    );
}

#[test]
fn a_proxied_dial_has_nagle_off() {
    // A fake SOCKS5 proxy that accepts the anonymous method and answers
    // the connect request with success and an IPv4 bound address.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let proxy_addr = listener.local_addr().expect("addr").to_string();
    let server = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept");
        conn.set_read_timeout(Some(TIMEOUT)).expect("timeout");
        let mut greeting = [0u8; 3];
        conn.read_exact(&mut greeting).expect("greeting");
        conn.write_all(&[5, 0]).expect("auth choice");
        let mut head = [0u8; 5];
        conn.read_exact(&mut head).expect("request head");
        let mut rest = vec![0u8; usize::from(head[4]).saturating_add(2)];
        conn.read_exact(&mut rest).expect("request host and port");
        conn.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0x23, 0x9c])
            .expect("reply");
        // Hold the connection until the client has checked its end.
        let mut byte = [0u8; 1];
        let _ = conn.read(&mut byte);
    });

    let proxy = Proxy {
        addr: proxy_addr,
        ..Proxy::default()
    };
    let conn = proxy.dial("192.0.2.1:9108", TIMEOUT).expect("dial");
    let nodelay = conn.nodelay().expect("read TCP_NODELAY");
    drop(conn);
    server.join().expect("proxy thread");
    assert!(
        nodelay,
        "a dial through the proxy must have TCP_NODELAY set"
    );
}
