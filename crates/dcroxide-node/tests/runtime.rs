// SPDX-License-Identifier: ISC
//! Integration checks for the threaded server listener runtime: it
//! binds an ephemeral listener, accepts inbound connections and reports
//! their addresses to the handler, and shuts its accept threads down
//! cleanly on request.

use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use dcroxide_node::runtime::ListenerRuntime;

/// Bind an ephemeral IPv4 listener, connect to the assigned port, and
/// confirm the accept handler observes the inbound connection.
#[test]
fn accepts_inbound_connections_on_bound_port() {
    let (tx, rx) = mpsc::channel::<SocketAddr>();
    let handler = Arc::new(move |_stream: TcpStream, peer: SocketAddr| {
        let _ = tx.send(peer);
    });

    let runtime = ListenerRuntime::start(&[("tcp4", ":0".to_string())], handler)
        .expect("bind ephemeral listener");

    let bound = runtime.bound_addrs();
    assert_eq!(bound.len(), 1, "one listener spec should bind one address");
    let port = bound[0].port();
    assert_ne!(port, 0, "an ephemeral port should be assigned");

    let mut client =
        TcpStream::connect(("127.0.0.1", port)).expect("connect to the bound listener");
    // Write a byte so the connection is not optimized away before accept.
    let _ = client.write_all(&[0x01]);

    let peer = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("handler should observe the inbound connection");
    assert!(peer.ip().is_loopback(), "peer address: {peer}");

    runtime.shutdown();
}

/// Two listener specs each bind their own address and the runtime joins
/// both accept threads on shutdown.
#[test]
fn binds_multiple_listeners_and_shuts_down() {
    let count = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&count);
    let handler = Arc::new(move |_stream: TcpStream, _peer: SocketAddr| {
        observed.fetch_add(1, Ordering::SeqCst);
    });

    let runtime = ListenerRuntime::start(
        &[("tcp4", ":0".to_string()), ("tcp4", ":0".to_string())],
        handler,
    )
    .expect("bind two ephemeral listeners");
    assert_eq!(runtime.bound_addrs().len(), 2);

    for addr in runtime.bound_addrs() {
        let mut client =
            TcpStream::connect(("127.0.0.1", addr.port())).expect("connect to a bound listener");
        let _ = client.write_all(&[0x01]);
    }

    // Give the accept threads a moment to observe both connections
    // before shutting down.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while count.load(Ordering::SeqCst) < 2 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }

    // shutdown() joins both accept threads; if one failed to stop, this
    // would hang the test rather than return.
    runtime.shutdown();
    assert_eq!(count.load(Ordering::SeqCst), 2, "both connections accepted");
}
