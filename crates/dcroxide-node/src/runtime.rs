// SPDX-License-Identifier: ISC
//! The threaded peer-to-peer server runtime — the OS-threads-and-channels
//! translation of the backbone of dcrd `server.go`'s `Run` and
//! `peerHandler` goroutines.
//!
//! This first slice binds the configured listeners and accepts inbound
//! connections on a dedicated thread per listener, coordinating a
//! graceful shutdown by signalling those threads and joining them.  The
//! connection manager (outbound dialing and seeding), the peer version
//! handshake, the per-peer input and output loops, the sync manager,
//! and the RPC server arrive with later pieces and plug into this same
//! shutdown coordination.

use std::collections::HashMap;
use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use dcroxide_peer::{Config, Peer, PeerEnv};
use dcroxide_wire::{CurrencyNet, ServiceFlag};

use crate::peerconn::{NodePeerEnv, net_address_from_socket};
use crate::peerloop::run_peer_connection;

/// The interval the accept loops wait between polling for shutdown when
/// no connection is pending.
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// A handler invoked for each accepted inbound connection (dcrd
/// `server.inboundPeerConnected`).  It runs on the listener's accept
/// thread and must not block for long, so it hands the connection off to
/// a dedicated peer thread.
pub type InboundHandler = Arc<dyn Fn(TcpStream, SocketAddr) + Send + Sync>;

/// A registry of the live peer connections so they can be disconnected
/// on shutdown (the connected-peer half of dcrd's `peerState`, tracking
/// just the socket needed to interrupt a peer blocked on a read).
#[derive(Clone, Default)]
pub struct ConnectedPeers {
    inner: Arc<Mutex<ConnectedPeersInner>>,
}

#[derive(Default)]
struct ConnectedPeersInner {
    next_id: u64,
    peers: HashMap<u64, TcpStream>,
}

impl ConnectedPeers {
    /// An empty registry.
    pub fn new() -> ConnectedPeers {
        ConnectedPeers::default()
    }

    /// Register a live connection, returning the handle used to remove it.
    fn register(&self, stream: TcpStream) -> u64 {
        let mut inner = self.inner.lock().expect("connected peers mutex poisoned");
        let id = inner.next_id;
        inner.next_id = inner.next_id.wrapping_add(1);
        inner.peers.insert(id, stream);
        id
    }

    /// Remove a connection that has finished.
    fn deregister(&self, id: u64) {
        self.inner
            .lock()
            .expect("connected peers mutex poisoned")
            .peers
            .remove(&id);
    }

    /// The number of live connections.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("connected peers mutex poisoned")
            .peers
            .len()
    }

    /// Whether there are no live connections.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Disconnect every live connection by shutting down its socket,
    /// which unblocks each peer's read loop so it winds down (dcrd's
    /// server shutdown disconnecting all peers).
    pub fn disconnect_all(&self) {
        let inner = self.inner.lock().expect("connected peers mutex poisoned");
        for stream in inner.peers.values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

/// The parameters a fresh inbound peer is built from (the daemon's slice
/// of dcrd's `peer.Config`).  Plain data so it can be cloned per
/// connection; the peer's boxed callbacks are left unset here.
#[derive(Clone)]
pub struct PeerTemplate {
    /// The network to frame messages for.
    pub net: CurrencyNet,
    /// The maximum protocol version to negotiate (0 means the package
    /// maximum).
    pub protocol_version: u32,
    /// The services to advertise.
    pub services: ServiceFlag,
    /// The user agent name to advertise.
    pub user_agent_name: String,
    /// The user agent version to advertise.
    pub user_agent_version: String,
    /// How long a peer may be silent before it is disconnected.
    pub idle_timeout: Duration,
    /// How often to ping an otherwise-quiet peer.
    pub ping_interval: Duration,
}

impl PeerTemplate {
    /// Build a fresh peer configuration for a new connection.
    fn config(&self) -> Config {
        Config {
            net: self.net,
            services: self.services,
            user_agent_name: self.user_agent_name.clone(),
            user_agent_version: self.user_agent_version.clone(),
            protocol_version: self.protocol_version,
            idle_timeout_nanos: self.idle_timeout.as_nanos() as i64,
            ..Config::default()
        }
    }
}

/// Build the inbound handler that serves each accepted connection as a
/// negotiated peer (dcrd `server.inboundPeerConnected`).  Each
/// connection is handled on its own thread: a fresh inbound peer is
/// built from `template`, associated with the remote address, and run
/// through the full connection runtime.  The server-handler dispatch is
/// a no-op for now; the peer-state bookkeeping and message forwarding
/// arrive with the peer-handler piece.
pub fn inbound_peer_handler(template: PeerTemplate, connected: ConnectedPeers) -> InboundHandler {
    Arc::new(move |stream: TcpStream, addr: SocketAddr| {
        let template = template.clone();
        let connected = connected.clone();
        thread::spawn(move || serve_inbound_peer(stream, addr, &template, &connected));
    })
}

/// Build, associate, and run a single inbound peer to completion,
/// keeping it in the connected-peers registry while it is served.
fn serve_inbound_peer(
    stream: TcpStream,
    addr: SocketAddr,
    template: &PeerTemplate,
    connected: &ConnectedPeers,
) {
    let mut peer = Peer::new_inbound(template.config());
    let na = match net_address_from_socket(addr, template.services) {
        Ok(na) => na,
        // An address the manager cannot represent is dropped, matching
        // dcrd refusing to serve an unroutable peer.
        Err(_) => return,
    };
    peer.associate(&addr.to_string(), na, NodePeerEnv::new().now_nanos());

    // Register a socket handle so a shutdown can interrupt this peer's
    // blocking read; a failed clone just leaves it unregistered.
    let handle = stream.try_clone().ok().map(|h| connected.register(h));

    let _ = run_peer_connection(
        stream,
        peer,
        template.protocol_version,
        template.net,
        template.idle_timeout,
        template.ping_interval,
        // Server-handler dispatch (relay, inv, getdata, ...) is wired in
        // a later piece; keepalive and the handshake are handled inside.
        |_peer, _msg| {},
    );

    if let Some(id) = handle {
        connected.deregister(id);
    }
}

/// Resolve a listener spec's bind address, expanding the wildcard host
/// to the family-appropriate any-address (dcrd relies on Go's
/// `net.Listen("tcp4"|"tcp6", ":port")` for this).
fn bind_address(net: &str, addr: &str) -> String {
    match addr.strip_prefix(':') {
        Some(port) if net == "tcp6" => format!("[::]:{port}"),
        Some(port) => format!("0.0.0.0:{port}"),
        None => addr.to_string(),
    }
}

/// Binds the parsed peer-to-peer listeners and accepts inbound
/// connections until shutdown.
pub struct ListenerRuntime {
    shutdown: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    bound: Vec<SocketAddr>,
}

impl ListenerRuntime {
    /// Bind each `(network, address)` listener spec (as produced by
    /// `parse_listeners`) and start accepting inbound connections,
    /// invoking `on_inbound` for each accepted connection.  A bind
    /// failure aborts startup and returns the error, matching dcrd's
    /// refusal to start when it cannot listen on a requested address.
    pub fn start(
        specs: &[(&str, String)],
        on_inbound: InboundHandler,
    ) -> io::Result<ListenerRuntime> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::with_capacity(specs.len());
        let mut bound = Vec::with_capacity(specs.len());

        for (net, addr) in specs {
            let listener = TcpListener::bind(bind_address(net, addr))?;
            // Non-blocking accept so the loop can observe shutdown
            // promptly without a separate wakeup connection.
            listener.set_nonblocking(true)?;
            bound.push(listener.local_addr()?);

            let shutdown = Arc::clone(&shutdown);
            let handler = Arc::clone(&on_inbound);
            threads.push(std::thread::spawn(move || {
                accept_loop(&listener, &shutdown, &handler);
            }));
        }

        Ok(ListenerRuntime {
            shutdown,
            threads,
            bound,
        })
    }

    /// The addresses the runtime is actually listening on (resolved from
    /// the requested specs, so an ephemeral `:0` port is reported as the
    /// assigned port).
    pub fn bound_addrs(&self) -> &[SocketAddr] {
        &self.bound
    }

    /// Signal the accept threads to stop and join them (dcrd's server
    /// shutdown waiting on its wait group).
    pub fn shutdown(self) {
        self.shutdown.store(true, Ordering::SeqCst);
        for thread in self.threads {
            let _ = thread.join();
        }
    }
}

/// Accept inbound connections on the listener until shutdown is
/// signalled, handing each to the handler.
fn accept_loop(listener: &TcpListener, shutdown: &AtomicBool, handler: &InboundHandler) {
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            // The listener is non-blocking so this loop can poll for
            // shutdown; on BSD/macOS the accepted socket inherits that
            // flag, so restore blocking mode before handing it off (Linux
            // accepts already come blocking).  A socket that cannot be put
            // back into blocking mode would break the per-peer read loop,
            // so it is dropped rather than served.
            Ok((stream, addr)) => {
                if stream.set_nonblocking(false).is_ok() {
                    handler(stream, addr);
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            // A hard listener error ends the accept loop; the runtime's
            // other listeners and the shutdown path are unaffected.
            Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_wildcard_bind_addresses() {
        assert_eq!(bind_address("tcp4", ":9108"), "0.0.0.0:9108");
        assert_eq!(bind_address("tcp6", ":9108"), "[::]:9108");
        assert_eq!(bind_address("tcp4", "127.0.0.1:9108"), "127.0.0.1:9108");
        assert_eq!(bind_address("tcp6", "[::1]:9108"), "[::1]:9108");
    }
}
