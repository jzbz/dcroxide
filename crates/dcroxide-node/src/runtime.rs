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

use dcroxide_wire::Message;

use crate::dispatch::{ServerContext, ServerPeerHandler};
use crate::peerconn::{NodePeerEnv, net_address_from_socket};
use crate::peerloop::{OutboundQueue, ServeHooks, ServeSignal, run_peer_connection};
use crate::server::is_whitelisted;

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

    /// Lock the registry, recovering from a poisoned mutex: every
    /// critical section here is a single map operation that cannot leave
    /// the registry in a broken state, and the registry must stay usable
    /// for shutdown's `disconnect_all` even after a peer thread panics.
    fn locked(&self) -> std::sync::MutexGuard<'_, ConnectedPeersInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Register a live connection, returning the handle used to remove it.
    fn register(&self, stream: TcpStream) -> u64 {
        let mut inner = self.locked();
        let id = inner.next_id;
        inner.next_id = inner.next_id.wrapping_add(1);
        inner.peers.insert(id, stream);
        id
    }

    /// Remove a connection that has finished.
    fn deregister(&self, id: u64) {
        self.locked().peers.remove(&id);
    }

    /// The number of live connections.
    pub fn len(&self) -> usize {
        self.locked().peers.len()
    }

    /// Whether there are no live connections.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Disconnect every live connection by shutting down its socket,
    /// which unblocks each peer's read loop so it winds down (dcrd's
    /// server shutdown disconnecting all peers).
    pub fn disconnect_all(&self) {
        let inner = self.locked();
        for stream in inner.peers.values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

/// Removes a connection from the registry when dropped, so a peer
/// deregisters even when its serving thread unwinds from a panic.
struct DeregisterGuard<'a> {
    connected: &'a ConnectedPeers,
    id: u64,
}

impl Drop for DeregisterGuard<'_> {
    fn drop(&mut self) {
        self.connected.deregister(self.id);
    }
}

/// Decrements the outbound-group counter when dropped, so the count is
/// released on every exit path — panic unwinds included — and a leaked
/// count can never permanently exclude an address group from the
/// automatic dialer (mirroring [`DeregisterGuard`]; dcrd's
/// `handleDonePeer` always updates `outboundGroups`).
struct OutboundGroupGuard {
    groups: crate::dispatch::OutboundGroups,
    key: String,
}

impl Drop for OutboundGroupGuard {
    fn drop(&mut self) {
        self.groups.decrement(&self.key);
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
/// through the full connection runtime.  With a [`ServerContext`] the
/// chain-backed server handlers answer the peer's requests; without one
/// (tests exercising just the protocol plumbing) the dispatch is a
/// no-op.
pub fn inbound_peer_handler(
    template: PeerTemplate,
    connected: ConnectedPeers,
    server: Option<Arc<ServerContext>>,
    max_peers: usize,
) -> InboundHandler {
    Arc::new(move |stream: TcpStream, addr: SocketAddr| {
        // Refuse the connection once the total (inbound and outbound)
        // connection count has reached the limit, so an attacker opening
        // sockets cannot spawn unbounded serving threads (dcrd's
        // `handleAddPeer` rejecting a peer over `cfg.MaxPeers`).  A limit
        // of zero means unlimited, matching dcrd.  The dropped stream is
        // closed on return.
        if max_peers != 0 && connected.len() >= max_peers {
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
        let template = template.clone();
        let connected = connected.clone();
        let server = server.clone();
        thread::spawn(move || serve_inbound_peer(stream, addr, &template, &connected, server));
    })
}

/// Build, associate, and run a single inbound peer to completion,
/// keeping it in the connected-peers registry while it is served.
fn serve_inbound_peer(
    stream: TcpStream,
    addr: SocketAddr,
    template: &PeerTemplate,
    connected: &ConnectedPeers,
    server: Option<Arc<ServerContext>>,
) {
    let na = match net_address_from_socket(addr, template.services) {
        Ok(na) => na,
        // An address the manager cannot represent is dropped, matching
        // dcrd refusing to serve an unroutable peer.
        Err(_) => return,
    };
    let mut peer = Peer::new_inbound(template.config());
    peer.associate(&addr.to_string(), na, NodePeerEnv::new().now_nanos());
    // An inbound peer is never a persistent (added) node and has no
    // connection request.
    serve_connection(stream, peer, addr, template, connected, server, false, None);
}

/// Build, associate, and run a single outbound peer to completion,
/// keeping it in the connected-peers registry while it is served (the
/// serving half of dcrd `outboundPeerConnected`).  Called by the
/// connection manager driver once a dial has established the socket;
/// `conn_req_id` is the manager's request id, carried with the peer so
/// the manual-control RPCs can remove the request (dcrd's
/// `serverPeer.connReq`).
pub(crate) fn serve_outbound_peer(
    stream: TcpStream,
    addr: SocketAddr,
    template: &PeerTemplate,
    connected: &ConnectedPeers,
    server: Option<Arc<ServerContext>>,
    permanent: bool,
    conn_req_id: Option<u64>,
) {
    let na = match net_address_from_socket(addr, template.services) {
        Ok(na) => na,
        Err(_) => return,
    };
    let peer = match Peer::new_outbound(template.config(), &addr.to_string()) {
        Ok(mut peer) => {
            peer.associate(&addr.to_string(), na, NodePeerEnv::new().now_nanos());
            peer
        }
        Err(_) => return,
    };

    // Track the outbound group for the connection's lifetime so the
    // automatic dialer spreads across network segments (dcrd
    // `handleAddPeer`/`handleDonePeer` updating `outboundGroups`).  The
    // guard releases the count on drop, so a panic in serve_connection
    // cannot leak it.
    let _group_guard = server.as_ref().map(|ctx| {
        let key = group_key_for(&na);
        ctx.outbound_groups.increment(&key);
        OutboundGroupGuard {
            groups: ctx.outbound_groups.clone(),
            key,
        }
    });

    serve_connection(
        stream,
        peer,
        addr,
        template,
        connected,
        server,
        permanent,
        conn_req_id,
    );
}

/// The address-manager group key for a wire net address.
fn group_key_for(na: &dcroxide_wire::NetAddress) -> String {
    crate::server::wire_to_addrmgr_net_address(na).group_key()
}

/// Register a connected peer, run it through the connection runtime
/// with the server dispatch, and deregister it on exit — shared by the
/// inbound and outbound serve paths (dcrd's `serverPeer` runs the same
/// for both directions).
#[allow(clippy::too_many_arguments)]
fn serve_connection(
    stream: TcpStream,
    peer: Peer,
    addr: SocketAddr,
    template: &PeerTemplate,
    connected: &ConnectedPeers,
    server: Option<Arc<ServerContext>>,
    permanent: bool,
    conn_req_id: Option<u64>,
) {
    // Register a socket handle so a shutdown can interrupt this peer's
    // blocking read; a failed clone just leaves it unregistered.  The
    // guard deregisters on every exit path, panics included.
    let _guard = stream.try_clone().ok().map(|h| DeregisterGuard {
        connected,
        id: connected.register(h),
    });

    // The per-peer server state and dispatch (dcrd `newServerPeer` and
    // the message listeners it registers).  The socket handle lets the
    // sync manager's disconnect actions interrupt this peer's read.
    let server_net_totals = server
        .as_ref()
        .map(|ctx| std::sync::Arc::clone(&ctx.net_totals));
    let hooks = match server {
        Some(ctx) => {
            let whitelisted = is_whitelisted(&ctx.whitelists, &addr.to_string());
            InboundHooks::Server(ServerPeerHandler::new(
                ctx,
                whitelisted,
                stream.try_clone().ok(),
                permanent,
                conn_req_id,
                addr.to_string(),
            ))
        }
        None => InboundHooks::NoOp,
    };

    let net_totals = match &hooks {
        InboundHooks::Server(_) => server_net_totals,
        InboundHooks::NoOp => None,
    };
    let _ = run_peer_connection(
        stream,
        peer,
        template.protocol_version,
        template.net,
        template.idle_timeout,
        template.ping_interval,
        net_totals,
        hooks,
    );
}

/// The lifecycle hooks a served inbound connection runs: the full
/// server dispatch when a [`ServerContext`] is available, or plain
/// protocol serving for tests exercising just the plumbing.
enum InboundHooks {
    Server(ServerPeerHandler),
    NoOp,
}

impl ServeHooks for InboundHooks {
    fn on_connected(
        &mut self,
        peer: &mut Peer,
        peer_handle: &Arc<Mutex<Peer>>,
        outbound: &OutboundQueue,
        remote_disable_relay_tx: bool,
    ) {
        if let InboundHooks::Server(handler) = self {
            handler.on_connected(peer, peer_handle, outbound, remote_disable_relay_tx);
        }
    }

    fn on_message(
        &mut self,
        peer: &mut Peer,
        msg: &Message,
        outbound: &OutboundQueue,
    ) -> ServeSignal {
        match self {
            InboundHooks::Server(handler) => handler.handle_message(peer, msg, outbound),
            InboundHooks::NoOp => ServeSignal::Continue,
        }
    }

    fn on_disconnected(&mut self, peer: &mut Peer) {
        if let InboundHooks::Server(handler) = self {
            handler.on_disconnected(peer);
        }
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

/// Bind a listener spec.  A `tcp6` listener is bound IPv6-only, exactly
/// like Go's `net.Listen("tcp6", ...)` sets `IPV6_V6ONLY`: without it, a
/// dual-stack host (Linux `bindv6only=0`) refuses the `[::]` wildcard
/// with "address in use" once the `0.0.0.0` wildcard for the same port —
/// the other half of the default listener pair — is already bound.
fn bind_listener(net: &str, addr: &str) -> io::Result<TcpListener> {
    let bind_addr = bind_address(net, addr);
    if net == "tcp6" {
        // The address is an IP:port by the time it reaches here (the
        // config pipeline normalizes listeners); fall back to the
        // resolving std bind for anything else.
        if let Ok(sock_addr) = bind_addr.parse::<SocketAddr>() {
            let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None)?;
            socket.set_only_v6(true)?;
            socket.bind(&sock_addr.into())?;
            socket.listen(128)?;
            return Ok(socket.into());
        }
    }
    TcpListener::bind(bind_addr)
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
            let listener = bind_listener(net, addr)?;
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
            // WouldBlock means no connection is pending; anything else
            // is a transient accept error (a peer resetting between the
            // SYN queue and accept, descriptor pressure) that must not
            // kill the listener — dcrd logs and keeps accepting.  Either
            // way wait a poll interval, which also keeps a persistent
            // error from spinning hot.
            Err(_) => {
                std::thread::sleep(ACCEPT_POLL_INTERVAL);
            }
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

    /// The registry stays usable after a thread panics while holding its
    /// lock, so a crashed peer thread cannot break shutdown's
    /// `disconnect_all`.
    #[test]
    fn connected_peers_survive_a_poisoned_lock() {
        let connected = ConnectedPeers::new();

        // Poison the mutex by panicking while holding it.
        let poisoner = connected.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.inner.lock().expect("first lock");
            panic!("poison the registry mutex");
        })
        .join();
        assert!(connected.inner.lock().is_err(), "mutex should be poisoned");

        // Every registry operation still works.
        assert!(connected.is_empty());
        assert_eq!(connected.len(), 0);
        connected.disconnect_all();
        connected.deregister(0);
    }

    /// A guard deregisters its connection even when the serving thread
    /// unwinds from a panic.
    #[test]
    fn deregister_guard_runs_on_unwind() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().expect("addr");
        let stream = TcpStream::connect(addr).expect("connect");

        let connected = ConnectedPeers::new();
        let registered = connected.clone();
        let _ = std::thread::spawn(move || {
            let _guard = DeregisterGuard {
                connected: &registered,
                id: registered.register(stream),
            };
            assert_eq!(registered.len(), 1);
            panic!("unwind through the guard");
        })
        .join();

        assert!(
            connected.is_empty(),
            "the guard should deregister on unwind"
        );
    }

    /// An inbound connection accepted while the registry is already at the
    /// peer limit is refused: its socket is shut down without a serving
    /// thread, so the client reads end-of-file.
    #[test]
    fn inbound_admission_rejects_over_the_peer_limit() {
        use std::io::Read;

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let bound = listener.local_addr().expect("addr");

        // Fill the registry to a limit of one.
        let connected = ConnectedPeers::new();
        let _held_client = TcpStream::connect(bound).expect("connect held");
        let (held_server, _) = listener.accept().expect("accept held");
        connected.register(held_server);
        assert_eq!(connected.len(), 1);

        let template = PeerTemplate {
            net: CurrencyNet::TEST_NET3,
            protocol_version: 0,
            services: ServiceFlag(1),
            user_agent_name: "dcroxide".to_string(),
            user_agent_version: "0.1.0".to_string(),
            idle_timeout: Duration::from_secs(3600),
            ping_interval: Duration::from_secs(3600),
        };
        let handler = inbound_peer_handler(template, connected.clone(), None, 1);

        // The next connection is over the limit and must be refused.
        let mut over_client = TcpStream::connect(bound).expect("connect over");
        let (over_server, over_addr) = listener.accept().expect("accept over");
        handler(over_server, over_addr);

        // The refused connection's socket was shut down, so the client
        // reads end-of-file rather than a version handshake.
        over_client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut buf = [0u8; 1];
        assert_eq!(
            over_client.read(&mut buf).expect("read"),
            0,
            "an over-limit inbound peer is refused"
        );

        // The under-limit connection is untouched by admission control.
        assert_eq!(connected.len(), 1);
    }
}
