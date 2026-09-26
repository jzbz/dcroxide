// SPDX-License-Identifier: ISC
//! The threaded peer-to-peer server runtime — the OS-threads-and-channels
//! translation of the backbone of dcrd `server.go`'s `Run` and
//! `peerHandler` goroutines.
//!
//! It binds the configured peer-to-peer listeners and accepts inbound
//! connections on a dedicated thread per listener, and serves every
//! peer -- accepted here or dialed by the connection manager
//! ([`crate::outbound`]) -- on a thread of its own through the version
//! handshake and the per-peer input and output loops, with the
//! server's message handlers and the sync manager behind them.  The
//! connected-peer registry lets a shutdown disconnect them all, and
//! the listeners stop by signalling their threads and joining them.
//! The daemon binary starts these alongside the RPC server and stops
//! them in its teardown.

use std::collections::HashMap;
use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use dcroxide_addrmgr::NetAddress;
use dcroxide_peer::{Config, Peer, PeerEnv};
use dcroxide_wire::{CurrencyNet, ServiceFlag};

use dcroxide_wire::Message;

use crate::dispatch::{ServerContext, ServerPeerHandler};
use crate::peerconn::{NodePeerEnv, net_address_v2_from_socket};
use crate::peerloop::{
    DisconnectReason, OutboundQueue, ServeHooks, ServeSignal, run_peer_connection,
};
use crate::server::is_whitelisted;

/// The interval the accept loops wait between polling for shutdown when
/// no connection is pending.
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Start a thread on a connection path, handing back the OS's refusal
/// instead of panicking.
///
/// `std::thread::spawn` panics when the OS refuses a thread (`EAGAIN`
/// under `RLIMIT_NPROC` or a cgroup `pids.max`, `ENOMEM` for its stack),
/// and release builds abort on a panic, so a peer arriving under thread
/// exhaustion took the whole node down.  dcrd has no such failure: its
/// connections run as goroutines.  Every thread a remote peer's arrival
/// causes starts here, and each caller treats a refusal as a dropped
/// connection or a failed dial, as the RPC accept loop already does.
pub(crate) fn spawn_conn_thread<F, T>(name: &str, work: F) -> io::Result<JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    #[cfg(test)]
    if REFUSE_CONN_THREADS.with(std::cell::Cell::get) {
        return Err(io::Error::from(io::ErrorKind::WouldBlock));
    }
    thread::Builder::new().name(name.to_string()).spawn(work)
}

#[cfg(test)]
thread_local! {
    /// Makes [`spawn_conn_thread`] on this thread fail the way the OS
    /// refuses a thread, which a test cannot otherwise arrange without
    /// starving the whole test process.
    pub(crate) static REFUSE_CONN_THREADS: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

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
    peers: HashMap<u64, crate::transport::Teardown>,
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
    fn register(&self, conn: crate::transport::Teardown) -> u64 {
        let mut inner = self.locked();
        let id = inner.next_id;
        inner.next_id = inner.next_id.wrapping_add(1);
        inner.peers.insert(id, conn);
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

    /// Disconnect every live connection, which unblocks each peer's
    /// read loop so it winds down (dcrd's server shutdown running
    /// `ForAllPeers(sp.Disconnect)`).
    ///
    /// Through each connection's teardown handle, so the flag its reader
    /// polls goes up with the socket shutdown rather than leaving the
    /// reader parked until its idle budget runs out; see
    /// `transport::Teardown::disconnect`.  The flag is marked as the
    /// shutdown's, so a handshake cut short reports dcrd's
    /// `errHandshakeTimeout` (`Teardown::disconnect_for_shutdown`).
    pub fn disconnect_all(&self) {
        let inner = self.locked();
        for conn in inner.peers.values() {
            conn.disconnect_for_shutdown();
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
    /// How long a peer may be silent before it is disconnected (dcrd's
    /// `IdleTimeout: cfg.PeerIdleTimeout`).
    pub idle_timeout: Duration,
    /// How often to ping an otherwise-quiet peer.
    pub ping_interval: Duration,
    /// Whether the `version` message asks the remote not to relay
    /// transactions (dcrd's `DisableRelayTx: cfg.BlocksOnly`).  A dcrd
    /// peer honours it by leaving transaction and mix inventory out of
    /// what it relays here; without it, a blocks-only node invited that
    /// inventory and then disconnected every peer that sent it.
    pub disable_relay_tx: bool,
    /// The configured SOCKS proxy in host:port form, empty for none
    /// (dcrd's `Proxy: cfg.Proxy`).  The `version` message sends a
    /// connection arriving from the proxy's host an all-zero address as
    /// its `addr_you`, so the proxy's address does not leak.
    pub proxy: String,
    /// Reports the chain tip for the `version` message's `last_block`
    /// (dcrd's `Config.NewestBlock`, fed by `server.NewestBlock`).
    ///
    /// `None` advertises height 0, which is what the daemon did until
    /// this was wired and is why it could not be a sync source for
    /// anyone: dcrd's sync-peer candidate check requires a peer's
    /// advertised height to reach its own, so a node claiming 0 is never
    /// eligible.  A dcroxide peer syncing from one got as far as its
    /// first sync-peer re-selection and then reported "no sync peer
    /// candidates available" with the connection still up.  Left as an
    /// `Option` because the protocol-only tests have no chain.
    pub newest_block: Option<NewestBlockProvider>,
}

/// Reports the chain tip as (hash, height) for the version message.
/// Shared rather than boxed because every connection needs its own
/// `FnMut` and they all read the same chain.
pub type NewestBlockProvider =
    Arc<dyn Fn() -> Result<(dcroxide_chainhash::Hash, i64), String> + Send + Sync>;

impl PeerTemplate {
    /// The daemon's template, taking dcrd `newPeerConfig`'s
    /// configuration-driven fields from the parsed config: the network,
    /// `IdleTimeout` from `--peeridletimeout`, `DisableRelayTx` from
    /// `--blocksonly` and `Proxy` from `--proxy`.  The services are
    /// dcrd's `defaultServices`, the protocol version the package
    /// maximum (dcrd's `maxProtocolVersion`), and the ping interval
    /// dcrd's constant, which `--peeridletimeout` does not move.
    ///
    /// Here rather than in the binary so a test can check the wiring:
    /// while `main` built the template, all three options stopped at
    /// the parser, the idle timeout hard-coded to its default.
    pub fn from_config(
        cfg: &crate::config::Config,
        user_agent_name: &str,
        newest_block: Option<NewestBlockProvider>,
    ) -> PeerTemplate {
        PeerTemplate {
            net: cfg.params.params.net,
            // 0 selects the package's maximum protocol version.
            protocol_version: 0,
            services: ServiceFlag::NODE_NETWORK,
            user_agent_name: user_agent_name.to_string(),
            user_agent_version: crate::version::user_agent_version(),
            // Validated to at least 15 seconds by the config pipeline.
            idle_timeout: Duration::from_nanos(cfg.peer_idle_timeout_nanos.max(0) as u64),
            ping_interval: Duration::from_nanos(dcroxide_peer::PING_INTERVAL as u64),
            disable_relay_tx: cfg.blocks_only,
            proxy: cfg.proxy.clone(),
            newest_block,
        }
    }

    /// Build a fresh peer configuration for a new connection (dcrd
    /// `newPeerConfig`).
    ///
    /// Public so a test can check what the connection will actually
    /// advertise; the height this carries was unwired for a long time
    /// without anything noticing.
    pub fn config(&self) -> Config {
        // dcrd advertises the version's pre-release portion as the one
        // user agent comment, `.../dcrd:2.2.0(pre)/`.
        let pre_release = &crate::version::version_components().pre_release;
        let user_agent_comments = if pre_release.is_empty() {
            Vec::new()
        } else {
            vec![pre_release.clone()]
        };
        Config {
            net: self.net,
            services: self.services,
            user_agent_name: self.user_agent_name.clone(),
            user_agent_version: self.user_agent_version.clone(),
            user_agent_comments,
            protocol_version: self.protocol_version,
            disable_relay_tx: self.disable_relay_tx,
            proxy: self.proxy.clone(),
            idle_timeout_nanos: self.idle_timeout.as_nanos() as i64,
            newest_block: self.newest_block.clone().map(|provider| {
                Box::new(move || provider()) as Box<dyn FnMut() -> Result<_, String> + Send>
            }),
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
    manager: Option<crate::outbound::SharedConnManager>,
) -> InboundHandler {
    // The accept-time randomness for the probabilistic flood drops
    // (dcrd's manager-wide csprng).
    let csprng = Arc::new(Mutex::new(dcroxide_connmgr::SystemCsprng::default()));
    Arc::new(move |stream: TcpStream, addr: SocketAddr| {
        // dcrd 2.2's `listenHandler` admission, inline on the accept
        // path so rejected connections shed before a serving thread
        // exists: rate limiting and flood drops, duplicate rejection,
        // the per-host permit, and the total-connections permit.
        // Tests that exercise just the protocol plumbing pass no
        // manager and skip admission.
        let mut admitted = None;
        if let Some(manager) = &manager {
            let ip_bytes = match addr.ip() {
                std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
                std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
            };
            let remote_na = dcroxide_addrmgr::new_net_address_from_ip_port(
                &ip_bytes,
                addr.port(),
                dcroxide_wire::ServiceFlag(0),
                now_unix_nanos(),
            );
            let mut rng = csprng.lock().expect("csprng mutex poisoned");
            let mut mgr = manager.lock().expect("connmgr mutex poisoned");
            match admit_inbound_now(&mut mgr, &remote_na, &mut *rng) {
                dcroxide_connmgr::InboundDecision::Drop { reason } => {
                    log_inbound_drop(&mut mgr, manager, &addr, &reason);
                    drop(mgr);
                    let _ = stream.shutdown(Shutdown::Both);
                    return;
                }
                dcroxide_connmgr::InboundDecision::DropSilent => {
                    drop(mgr);
                    let _ = stream.shutdown(Shutdown::Both);
                    return;
                }
                dcroxide_connmgr::InboundDecision::Admit {
                    require_permit,
                    host_permit_reserved,
                } => {
                    let record =
                        mgr.register_inbound(&remote_na, require_permit, host_permit_reserved);
                    admitted = Some((Arc::clone(manager), record.id));
                }
            }
        }
        let template = template.clone();
        let connected = connected.clone();
        let server = server.clone();
        // Released by the serving thread when the peer is done, or here
        // when the OS refuses that thread: the socket closes with the
        // refused closure, and the admission's permits go back exactly
        // as they would for a connection that ended at once.
        let release = admitted.clone();
        let spawned = spawn_conn_thread("peer-inbound", move || {
            serve_inbound_peer(stream, addr, &template, &connected, server);
            if let Some((manager, conn_id)) = admitted {
                manager
                    .lock()
                    .expect("connmgr mutex poisoned")
                    .conn_closed(conn_id);
            }
        });
        if let Err(e) = spawned {
            crate::logging::warn(
                "SRVR",
                &format!("Unable to start a thread for inbound peer {addr}: {e} -- dropping it"),
            );
            if let Some((manager, conn_id)) = release {
                manager
                    .lock()
                    .expect("connmgr mutex poisoned")
                    .conn_closed(conn_id);
            }
        }
    })
}

/// The wall clock in unix nanoseconds for the admission path.
fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// dcrd `listenHandler`'s admission of an inbound connection, on the
/// clocks `inboundRateLimiter.Allow` takes from its one `time.Now`: the
/// wall clock for the flood window and the limiter cache's TTL, and a
/// monotonic reading for the group token buckets, as Go's `Time.Sub` of
/// two `time.Now` values is monotonic.
fn admit_inbound_now(
    mgr: &mut dcroxide_connmgr::ConnManager,
    remote_na: &NetAddress,
    csprng: &mut dyn dcroxide_connmgr::Csprng,
) -> dcroxide_connmgr::InboundDecision {
    let now_nanos = now_unix_nanos();
    let now_unix = now_nanos / 1_000_000_000;
    let mono_nanos = dcroxide_connmgr::monotonic_nanos();
    mgr.admit_inbound(remote_na, now_unix, now_nanos, mono_nanos, csprng)
}

/// Route a dropped inbound connection through the drop-log throttle
/// (dcrd `inboundRateLimiter.LogDrops`), arming the suppression-reset
/// timer when one starts.  Like dcrd's, it reads its own clock, the
/// monotonic one its token bucket measures time on.
fn log_inbound_drop(
    mgr: &mut dcroxide_connmgr::ConnManager,
    manager: &crate::outbound::SharedConnManager,
    addr: &SocketAddr,
    reason: &str,
) {
    match mgr
        .inbound_limiter
        .log_drops(dcroxide_connmgr::monotonic_nanos())
    {
        dcroxide_connmgr::LogDropsOutcome::Logged => {
            crate::logging::debug("CMGR", &format!("Dropped connection from {addr}: {reason}"));
        }
        dcroxide_connmgr::LogDropsOutcome::SuppressionStarted { reset_after_nanos } => {
            // dcrd renders the wait rounded to the nearest second.
            let rounded = round_nanos_to_second(reset_after_nanos);
            crate::logging::debug(
                "CMGR",
                &format!(
                    "Dropped connection from {addr}: {reason} -- suppressing drop logs for {}",
                    crate::gostd::go_duration_string(rounded)
                ),
            );
            let manager = Arc::clone(manager);
            let spawned = spawn_conn_thread("drop-log-reset", move || {
                thread::sleep(std::time::Duration::from_nanos(
                    reset_after_nanos.max(0) as u64
                ));
                let summary = manager
                    .lock()
                    .expect("connmgr mutex poisoned")
                    .inbound_limiter
                    .finish_suppression();
                log_suppressed_drops(summary);
            });
            // With no timer to end it, the suppression would last
            // forever; end it now instead, so the next drop logs again.
            if spawned.is_err() {
                log_suppressed_drops(mgr.inbound_limiter.finish_suppression());
            }
        }
        dcroxide_connmgr::LogDropsOutcome::Suppressed => {}
    }
}

/// Log how many inbound drops a finished suppression swallowed (dcrd
/// `inboundRateLimiter`'s reset timer).
fn log_suppressed_drops(summary: Option<u64>) {
    if let Some(dropped) = summary {
        let noun = if dropped == 1 {
            "connection"
        } else {
            "connections"
        };
        crate::logging::debug(
            "CMGR",
            &format!("Dropped {dropped} {noun} while suppressed"),
        );
    }
}

/// Go's `Duration.Round(time.Second)`: round half away from zero to
/// the nearest second, in nanoseconds.
fn round_nanos_to_second(nanos: i64) -> i64 {
    const SECOND: i64 = 1_000_000_000;
    let rem = nanos % SECOND;
    let base = nanos.saturating_sub(rem);
    if rem.saturating_mul(2) >= SECOND {
        base.saturating_add(SECOND)
    } else {
        base
    }
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
    // Refuse connections from banned hosts before any handshake work,
    // clearing expired bans as they are consulted (dcrd 2.2's
    // pre-handshake ban check over `peerState.banned`, bare-IP key).
    if let Some(server) = &server {
        let host = addr.ip().to_string();
        let mut banned = server
            .banned_hosts
            .lock()
            .expect("banned-hosts mutex poisoned");
        let outcome =
            crate::server::handle_banned_conn(&mut banned, &host, crate::server::ban_clock_nanos());
        if outcome.banned {
            return;
        }
    }

    let na = match net_address_v2_from_socket(addr, template.services) {
        Ok(na) => na,
        // An address the manager cannot represent is dropped, matching
        // dcrd refusing to serve an unroutable peer.
        Err(_) => return,
    };
    let mut peer = Peer::new_inbound(template.config());
    peer.associate(&addr.to_string(), na, NodePeerEnv::new().now_nanos());
    // An inbound peer is never a persistent (added) node and has no
    // connection request.
    // The connection's teardown handle is minted here, where the socket
    // first has a reader ahead of it, so every later holder shares one
    // flag (dcrd shares the `net.Conn` itself).
    serve_connection(
        crate::transport::Teardown::new(stream),
        peer,
        &addr.to_string(),
        template,
        connected,
        server,
        false,
        None,
    );
}

/// Build, associate, and run a single outbound peer to completion,
/// keeping it in the connected-peers registry while it is served (the
/// serving half of dcrd `outboundPeerConnected`).  Called by the
/// connection manager driver once a dial has established the socket;
/// `conn_req_id` is the manager's request id, carried with the peer so
/// the manual-control RPCs can remove the request (dcrd's
/// `serverPeer.connReq`).  `addr` is the address the manager dialed,
/// a Tor onion key as well as an IP address (dcrd's
/// `conn.RemoteAddr()` as an `*addrmgr.NetAddress`); the peer is keyed
/// on its `Key` form, dcrd's `addr.String()`.
pub(crate) fn serve_outbound_peer(
    conn: crate::transport::Teardown,
    addr: &NetAddress,
    template: &PeerTemplate,
    connected: &ConnectedPeers,
    server: Option<Arc<ServerContext>>,
    permanent: bool,
    conn_req_id: Option<u64>,
) {
    // Refuse dialing out to banned hosts before any handshake work —
    // dcrd's `outboundPeerConnected` runs the same pre-handshake ban
    // check since the connection manager is unaware of banned
    // addresses.
    if let Some(server) = &server {
        let host = banned_conn_host(addr);
        let mut banned = server
            .banned_hosts
            .lock()
            .expect("banned-hosts mutex poisoned");
        let outcome =
            crate::server::handle_banned_conn(&mut banned, &host, crate::server::ban_clock_nanos());
        if outcome.banned {
            return;
        }
    }

    // The remote's services are unknown until its version message
    // arrives, and the outbound version message is written first, so
    // its addr_you carries zero services (dcrd's outbound
    // `newNetAddress(remoteAddr, remoteServices)` with remoteServices
    // still zero).
    let na = match outbound_net_address_v2(addr) {
        Ok(na) => na,
        Err(_) => return,
    };
    let key = addr.key();
    let peer = match Peer::new_outbound(template.config(), &key) {
        Ok(mut peer) => {
            peer.associate(&key, na, NodePeerEnv::new().now_nanos());
            peer
        }
        Err(_) => return,
    };

    serve_connection(
        conn,
        peer,
        &key,
        template,
        connected,
        server,
        permanent,
        conn_req_id,
    );
}

/// dcrd `handleBannedConn`'s ban key for a dialed address,
/// `net.IP(remoteAddr.IP).String()`.  That is the address manager's
/// rendering for an IP address.  For a Tor v3 address, whose 32-byte
/// key is neither IP length, Go renders `"?"` and the hex bytes, which
/// no ban can match: bans are keyed by the host of the peer's address
/// (`BanPeer`), the `.onion` name.
fn banned_conn_host(addr: &NetAddress) -> String {
    match addr.addr_type {
        dcroxide_addrmgr::NetAddressType::IPv4 | dcroxide_addrmgr::NetAddressType::IPv6 => {
            addr.ip_string()
        }
        _ => {
            let hex: String = addr.ip.iter().map(|b| format!("{b:02x}")).collect();
            format!("?{hex}")
        }
    }
}

/// The dialed address as the outbound peer's wire address, with the
/// timestamp and services still zero because the remote has not sent
/// its version yet.  An IP address takes the socket form the inbound
/// path uses; a Tor v3 address keeps its onion key and type (dcrd's
/// `HostToNetAddress` over the `.onion` host), which the version message
/// sends as an all-zero address as dcrd's does.
fn outbound_net_address_v2(addr: &NetAddress) -> Result<dcroxide_wire::NetAddressV2, String> {
    if addr.addr_type == dcroxide_addrmgr::NetAddressType::TorV3 {
        return Ok(crate::server::addrmgr_to_wire_net_address_v2(&NetAddress {
            timestamp: 0,
            services: dcroxide_wire::ServiceFlag(0),
            ..addr.clone()
        }));
    }
    let socket = addr
        .key()
        .parse::<SocketAddr>()
        .map_err(|e| format!("unservable address {}: {e}", addr.key()))?;
    net_address_v2_from_socket(socket, dcroxide_wire::ServiceFlag(0))
}

/// Register a connected peer, run it through the connection runtime
/// with the server dispatch, and deregister it on exit — shared by the
/// inbound and outbound serve paths (dcrd's `serverPeer` runs the same
/// for both directions).
#[allow(clippy::too_many_arguments)]
fn serve_connection(
    conn: crate::transport::Teardown,
    peer: Peer,
    addr: &str,
    template: &PeerTemplate,
    connected: &ConnectedPeers,
    server: Option<Arc<ServerContext>>,
    permanent: bool,
    conn_req_id: Option<u64>,
) {
    // Register a socket handle so a shutdown can interrupt this peer's
    // blocking read; a failed clone just leaves it unregistered.  The
    // guard deregisters on every exit path, panics included.
    let _guard = conn.try_clone().ok().map(|h| DeregisterGuard {
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
            let whitelisted = is_whitelisted(&ctx.whitelists, addr);
            InboundHooks::Server(ServerPeerHandler::new(
                ctx,
                whitelisted,
                conn.try_clone().ok(),
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
    let direction = if peer.inbound() {
        "inbound"
    } else {
        "outbound"
    };
    let reason = run_peer_connection(
        conn,
        peer,
        template.protocol_version,
        template.net,
        template.idle_timeout,
        template.ping_interval,
        net_totals,
        hooks,
    );
    // dcrd's `inboundPeerConnected`/`outboundPeerConnected` report a
    // failed `Handshake` at debug (`server.go:2291`, `:2324`); the
    // session's own endings are logged by the peer loops, as dcrd's
    // `inHandler` logs them.
    if let DisconnectReason::Negotiate(err) = &reason {
        crate::logging::debug(
            "SRVR",
            &format!("Failed handshake for {direction} peer {addr}: {err}"),
        );
    }
}

/// The lifecycle hooks a served inbound connection runs: the full
/// server dispatch when a [`ServerContext`] is available, or plain
/// protocol serving for tests exercising just the plumbing.
// The server variant carries the whole per-peer dispatch and the plain
// one carries nothing, so the size gap is inherent rather than an
// oversight; boxing it would put an allocation on every inbound
// connection to save a discriminant's worth of stack in the arm that
// never runs in production.
#[allow(clippy::large_enum_variant)]
enum InboundHooks {
    Server(ServerPeerHandler),
    NoOp,
}

impl ServeHooks for InboundHooks {
    fn on_version(
        &mut self,
        peer: &dcroxide_peer::Peer,
        msg: &dcroxide_wire::MsgVersion,
    ) -> Result<(), String> {
        match self {
            InboundHooks::Server(handler) => handler.on_version(peer, msg),
            InboundHooks::NoOp => Ok(()),
        }
    }

    fn on_connected(
        &mut self,
        peer: &Arc<Mutex<Peer>>,
        outbound: &OutboundQueue,
        remote_disable_relay_tx: bool,
    ) {
        if let InboundHooks::Server(handler) = self {
            handler.on_connected(peer, outbound, remote_disable_relay_tx);
        }
    }

    fn on_message(
        &mut self,
        peer: &Mutex<Peer>,
        msg: Message,
        mix_hash: Option<dcroxide_chainhash::Hash>,
        outbound: &OutboundQueue,
    ) -> ServeSignal {
        match self {
            InboundHooks::Server(handler) => handler.handle_message(peer, msg, mix_hash, outbound),
            InboundHooks::NoOp => ServeSignal::Continue,
        }
    }

    fn on_wire_violation(&mut self, err: &str) -> ServeSignal {
        match self {
            InboundHooks::Server(handler) => handler.on_wire_violation(err),
            InboundHooks::NoOp => ServeSignal::Continue,
        }
    }

    fn on_disconnected(&mut self, peer: &Mutex<Peer>) {
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
///
/// Both kinds set `SO_REUSEADDR` outside Windows, as Go's
/// `setDefaultListenerSockopts` (net/sockopt_linux.go, sockopt_bsd.go)
/// does for every listener: std's bind sets it for the `tcp4` one, and
/// the hand-built `tcp6` socket sets it itself.  Without it a restart
/// failed to bind `[::]` for as long as the previous run's IPv6 inbound
/// connections sat in `TIME_WAIT` (they inherit the listener's setting),
/// which is a minute on Linux.  Neither sets it on Windows, where it
/// would let another socket take the port.
pub(crate) fn bind_listener(net: &str, addr: &str) -> io::Result<TcpListener> {
    let bind_addr = bind_address(net, addr);
    if net == "tcp6" {
        // The address is an IP:port by the time it reaches here (the
        // config pipeline normalizes listeners); fall back to the
        // resolving std bind for anything else.
        if let Ok(sock_addr) = bind_addr.parse::<SocketAddr>() {
            let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None)?;
            socket.set_only_v6(true)?;
            // Go leaves it unset on Windows, where it would let another
            // socket take over a port in use; std's bind does the same.
            #[cfg(not(windows))]
            socket.set_reuse_address(true)?;
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
    /// invoking `on_inbound` for each accepted connection.
    ///
    /// A spec that cannot be bound is logged and skipped, as dcrd's
    /// `initListeners` does, so a host where only one half of the
    /// default `tcp4`/`tcp6` pair binds (IPv6 disabled, say) serves on
    /// the other.  Startup fails only when nothing binds, with
    /// `newServer`'s "no valid listen address".
    pub fn start(
        specs: &[(&str, String)],
        on_inbound: InboundHandler,
    ) -> io::Result<ListenerRuntime> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::with_capacity(specs.len());
        let mut bound = Vec::with_capacity(specs.len());

        for (net, addr) in specs {
            // Non-blocking accept so the loop can observe shutdown
            // promptly without a separate wakeup connection.
            let listened = bind_listener(net, addr).and_then(|listener| {
                listener.set_nonblocking(true)?;
                let local = listener.local_addr()?;
                Ok((listener, local))
            });
            let (listener, local) = match listened {
                Ok(listened) => listened,
                Err(e) => {
                    // dcrd logs the spec as given (its `simpleAddr`),
                    // ":9108" for the default pair.
                    crate::logging::warn("SRVR", &format!("Can't listen on {addr}: {e}"));
                    continue;
                }
            };
            bound.push(local);

            let shutdown = Arc::clone(&shutdown);
            let handler = Arc::clone(&on_inbound);
            threads.push(std::thread::spawn(move || {
                accept_loop(&listener, local, &shutdown, &handler);
            }));
        }

        if bound.is_empty() {
            return Err(io::Error::other("no valid listen address"));
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
/// signalled, handing each to the handler (dcrd connmgr's
/// `listenHandler`, with its log lines).
fn accept_loop(
    listener: &TcpListener,
    local: SocketAddr,
    shutdown: &AtomicBool,
    handler: &InboundHandler,
) {
    crate::logging::info("CMGR", &format!("Server listening on {local}"));
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
                    // Go sets TCP_NODELAY on every connection it accepts,
                    // ignoring a failure (`newTCPConn`, `net/tcpsock.go`),
                    // so a small message queued behind unacknowledged data
                    // never waits on Nagle's algorithm for the peer's
                    // delayed ACK.
                    let _ = stream.set_nodelay(true);
                    handler(stream, addr);
                }
            }
            // No connection pending, or an accept error that must not
            // kill the listener (descriptor pressure, say): dcrd logs the
            // error and keeps accepting.  Either way wait a poll
            // interval, which also keeps a persistent error from
            // spinning hot.
            Err(e) => {
                if let Some(msg) = accept_error_log(&e, shutdown.load(Ordering::SeqCst)) {
                    crate::logging::error("CMGR", &msg);
                }
                std::thread::sleep(ACCEPT_POLL_INTERVAL);
            }
        }
    }
    crate::logging::trace("CMGR", &format!("Listener handler done for {local}"));
}

/// The line dcrd's `listenHandler` logs for a failed accept, "Can't
/// accept connection", or `None` when it logs nothing.  It stays quiet
/// during shutdown, and for what never reaches it as an error: the
/// non-blocking poll finding nothing pending, and the `EINTR` and
/// `ECONNABORTED` (a connection reset while still queued) that Go's
/// `Accept` retries internally.
fn accept_error_log(err: &io::Error, shutting_down: bool) -> Option<String> {
    let retried = matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
    );
    if retried || shutting_down {
        return None;
    }
    Some(format!("Can't accept connection: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Server shutdown ends every connection through its teardown
    /// handle.
    ///
    /// dcrd's equivalent is `ForAllPeers(sp.Disconnect)` — the same
    /// `Disconnect` as every other site, which is why the port having a
    /// weaker one here was a divergence rather than a nicety. Cannot
    /// pin the Windows latency this buys.
    #[test]
    fn server_shutdown_ends_every_connection_through_its_teardown() {
        use std::io::Read as _;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let bound = listener.local_addr().expect("addr");
        let connected = ConnectedPeers::new();

        let mut clients = Vec::new();
        let mut flags = Vec::new();
        for _ in 0..2 {
            let client = std::net::TcpStream::connect(bound).expect("connect");
            let (server, _) = listener.accept().expect("accept");
            let conn = crate::transport::Teardown::new(server);
            flags.push(conn.cancel());
            connected.register(conn);
            clients.push(client);
        }

        // Registered but never handed to the registry: proves the sweep
        // reaches the registry's entries rather than every handle alive.
        let stray_client = std::net::TcpStream::connect(bound).expect("connect");
        let (stray_server, _) = listener.accept().expect("accept");
        let stray = crate::transport::Teardown::new(stray_server);
        let stray_flag = stray.cancel();

        for f in &flags {
            assert!(!f.is_cancelled(), "registration must not raise");
        }

        connected.disconnect_all();

        for (n, (f, c)) in flags.iter().zip(clients.iter()).enumerate() {
            assert!(f.is_cancelled(), "connection {n}'s flag must be raised");
            assert!(
                f.is_shutdown(),
                "connection {n}'s flag must be the shutdown's"
            );
            let mut buf = [0u8; 1];
            assert_eq!(
                (&*c).read(&mut buf).expect("read"),
                0,
                "connection {n} must still get its FIN"
            );
        }
        assert!(
            !stray_flag.is_cancelled(),
            "an unregistered connection must be left alone"
        );
        drop((stray, stray_client));
    }

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
                id: registered.register(crate::transport::Teardown::new(stream)),
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

    /// A serving thread the OS refuses drops the accepted connection and
    /// gives its admission back, instead of panicking the accept loop —
    /// which aborted a release build, since `std::thread::spawn` panics
    /// on the refusal.
    #[test]
    fn a_refused_serving_thread_releases_the_admission() {
        use std::io::Read;

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let bound = listener.local_addr().expect("addr");
        let template = PeerTemplate {
            net: CurrencyNet::TEST_NET3,
            protocol_version: 0,
            services: ServiceFlag(1),
            user_agent_name: "dcroxide".to_string(),
            user_agent_version: "0.1.0".to_string(),
            idle_timeout: Duration::from_secs(3600),
            ping_interval: Duration::from_secs(3600),
            disable_relay_tx: false,
            proxy: String::new(),
            newest_block: None,
        };
        let mut csprng = dcroxide_connmgr::SystemCsprng::default();
        let manager = Arc::new(Mutex::new(dcroxide_connmgr::ConnManager::new(
            dcroxide_connmgr::ManagerConfig {
                max_normal_conns: 1,
                ..Default::default()
            },
            &mut csprng,
        )));
        let connected = ConnectedPeers::new();
        let handler = inbound_peer_handler(
            template,
            connected.clone(),
            None,
            Some(Arc::clone(&manager)),
        );

        let mut client = TcpStream::connect(bound).expect("connect");
        let (server, addr) = listener.accept().expect("accept");
        REFUSE_CONN_THREADS.with(|refuse| refuse.set(true));
        handler(server, addr);
        REFUSE_CONN_THREADS.with(|refuse| refuse.set(false));

        assert_eq!(
            manager
                .lock()
                .expect("connmgr mutex")
                .total_normal_conns_sem()
                .used(),
            0,
            "the admission's connection permit must be released"
        );
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut buf = [0u8; 1];
        assert_eq!(
            client.read(&mut buf).expect("read"),
            0,
            "the unserved connection is closed"
        );
        assert!(connected.is_empty());
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
        let (held_server, held_addr) = listener.accept().expect("accept held");
        connected.register(crate::transport::Teardown::new(held_server));
        assert_eq!(connected.len(), 1);

        let template = PeerTemplate {
            net: CurrencyNet::TEST_NET3,
            protocol_version: 0,
            services: ServiceFlag(1),
            user_agent_name: "dcroxide".to_string(),
            user_agent_version: "0.1.0".to_string(),
            idle_timeout: Duration::from_secs(3600),
            ping_interval: Duration::from_secs(3600),
            disable_relay_tx: false,
            proxy: String::new(),
            newest_block: None,
        };
        let mut csprng = dcroxide_connmgr::SystemCsprng::default();
        let manager = Arc::new(Mutex::new(dcroxide_connmgr::ConnManager::new(
            dcroxide_connmgr::ManagerConfig {
                max_normal_conns: 1,
                ..Default::default()
            },
            &mut csprng,
        )));
        // The single permit is held by the registered connection, admitted
        // as the accept path admits it, so the next accepted socket is
        // shed by the admission (dcrd's listenHandler over the
        // total-connections semaphore).
        {
            let mut mgr = manager.lock().expect("connmgr mutex");
            let held = crate::outbound::socket_addr_to_net_address(&held_addr);
            match admit_inbound_now(&mut mgr, &held, &mut csprng) {
                dcroxide_connmgr::InboundDecision::Admit {
                    require_permit,
                    host_permit_reserved,
                } => {
                    mgr.register_inbound(&held, require_permit, host_permit_reserved);
                }
                other => panic!("the held connection is admitted: {other:?}"),
            }
            assert_eq!(mgr.total_normal_conns_sem().used(), 1);
        }
        let handler = inbound_peer_handler(template, connected.clone(), None, Some(manager));

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

    /// An outbound onion peer gets dcrd's forms: its wire address keeps
    /// the onion key and type (the version message then sends the
    /// all-zero address dcrd sends), and the pre-handshake ban check
    /// uses Go's rendering of a 32-byte IP, `"?"` and hex, which no ban
    /// keyed by the `.onion` host matches.  An IP address keeps the
    /// socket forms it had.
    #[test]
    fn an_onion_peer_gets_dcrds_address_forms() {
        let onion = "aaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dyp3kead.onion";
        let (addr_type, key) = dcroxide_addrmgr::encode_host(onion);
        let addr = dcroxide_addrmgr::new_net_address_from_params(
            addr_type,
            &key,
            9108,
            1_700_000_000_000_000_000,
            ServiceFlag(1),
        )
        .expect("onion address");

        let na = outbound_net_address_v2(&addr).expect("an onion peer is servable");
        assert_eq!(na.addr_type, dcroxide_wire::NetAddressType::TOR_V3);
        assert_eq!(na.encoded_addr, key);
        assert_eq!(na.port, 9108);
        assert_eq!(na.timestamp, 0);
        assert_eq!(na.services, ServiceFlag(0));

        let hex: String = (0u8..32).map(|b| format!("{b:02x}")).collect();
        assert_eq!(banned_conn_host(&addr), format!("?{hex}"));

        let ip = crate::outbound::socket_addr_to_net_address(
            &"192.0.2.1:9108".parse().expect("socket address"),
        );
        assert_eq!(banned_conn_host(&ip), "192.0.2.1");
        assert_eq!(
            outbound_net_address_v2(&ip),
            net_address_v2_from_socket(
                "192.0.2.1:9108".parse().expect("socket address"),
                ServiceFlag(0)
            )
        );
    }

    /// Serve one inbound peer from `template` and return the `version`
    /// message it sends a client connecting from loopback.
    fn served_version(template: PeerTemplate) -> dcroxide_wire::MsgVersion {
        let runtime = ListenerRuntime::start(
            &[("tcp4", "127.0.0.1:0".to_string())],
            inbound_peer_handler(template.clone(), ConnectedPeers::new(), None, None),
        )
        .expect("start serving runtime");
        let port = runtime.bound_addrs()[0].port();
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut transport = crate::transport::WireTransport::new(
            stream,
            dcroxide_peer::MAX_PROTOCOL_VERSION,
            template.net,
        );
        let client = Config {
            net: template.net,
            ..Config::default()
        };
        let mut peer = Peer::new_outbound(client, &format!("127.0.0.1:{port}")).expect("peer");
        let outcome = peer
            .negotiate_outbound_protocol(
                &mut transport,
                &mut NodePeerEnv::new(),
                &dcroxide_peer::PeerGlobals::new(),
                None,
            )
            .expect("negotiate with the served peer");
        drop(transport);
        runtime.shutdown();
        *outcome.remote_version
    }

    /// The daemon's template carries dcrd `newPeerConfig`'s
    /// configuration-driven fields into every connection's `version`:
    /// `--blocksonly` as `DisableRelayTx`, `--proxy` hiding the address
    /// of a connection from the proxy's host, and `--peeridletimeout` as
    /// the idle timeout, with the pre-release user agent comment.  The
    /// daemon advertised relay under `--blocksonly`, so every dcrd peer
    /// relayed transactions to it and was disconnected for it.
    #[test]
    fn the_daemon_template_carries_the_config_into_the_version() {
        let mut cfg = crate::config::Config::defaults("/nonexistent/dcroxide-home");
        let defaults = PeerTemplate::from_config(&cfg, "dcroxide", None);
        assert!(!defaults.disable_relay_tx);
        assert_eq!(defaults.proxy, "");
        assert_eq!(defaults.idle_timeout, Duration::from_secs(120));

        cfg.blocks_only = true;
        cfg.proxy = "127.0.0.1:9050".to_string();
        cfg.peer_idle_timeout_nanos = 30_000_000_000;
        let template = PeerTemplate::from_config(&cfg, "dcroxide", None);
        assert_eq!(template.idle_timeout, Duration::from_secs(30));
        assert_eq!(
            template.ping_interval,
            Duration::from_nanos(dcroxide_peer::PING_INTERVAL as u64),
            "dcrd's ping interval is a constant"
        );
        let peer_cfg = template.config();
        assert!(peer_cfg.disable_relay_tx);
        assert_eq!(peer_cfg.proxy, "127.0.0.1:9050");
        assert_eq!(peer_cfg.idle_timeout_nanos, 30_000_000_000);
        assert_eq!(peer_cfg.user_agent_comments, vec!["pre".to_string()]);

        let version = served_version(template);
        assert!(version.disable_relay_tx, "blocks-only asks for no tx relay");
        assert_eq!(
            (version.addr_you.ip, version.addr_you.port),
            ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0], 0),
            "a connection from the proxy's host is told 0.0.0.0:0"
        );
        let agent = format!("dcroxide:{}(pre)/", crate::version::user_agent_version());
        assert!(
            version.user_agent.ends_with(&agent),
            "{}",
            version.user_agent
        );

        let version = served_version(defaults);
        assert!(!version.disable_relay_tx);
        assert_eq!(
            version.addr_you.ip,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1],
            "without a proxy the remote's own address goes back"
        );
    }

    /// A `tcp6` listener rebinds its port while the previous listener's
    /// connections are still closing, as Go's listeners do through
    /// `SO_REUSEADDR`.  Without it the accepted socket, closed first by
    /// the node, held the port in `TIME_WAIT` and a restart failed with
    /// "address in use" for a minute.
    #[cfg(not(windows))]
    #[test]
    fn a_tcp6_listener_rebinds_over_its_closing_connections() {
        use std::io::Read as _;

        // A host without IPv6 loopback has nothing to test.
        let Ok(first) = bind_listener("tcp6", "[::1]:0") else {
            return;
        };
        let port = first.local_addr().expect("addr").port();
        let mut client = TcpStream::connect(("::1", port)).expect("connect");
        let (server, _) = first.accept().expect("accept");
        // The node closes first, so the port's side of the connection
        // is the one left in FIN_WAIT/TIME_WAIT.
        drop(server);
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut buf = [0u8; 1];
        assert_eq!(client.read(&mut buf).expect("read"), 0);
        drop(client);
        drop(first);

        let second = bind_listener("tcp6", &format!("[::1]:{port}"))
            .expect("the port rebinds while its closed connection lingers");
        assert_eq!(second.local_addr().expect("addr").port(), port);
    }

    /// A listener that cannot bind is skipped and the rest serve, as
    /// dcrd's `initListeners` warns and carries on; only when nothing
    /// binds does startup fail, with `newServer`'s error.
    #[test]
    fn a_listener_that_cannot_bind_is_skipped() {
        let taken = TcpListener::bind("127.0.0.1:0").expect("bind");
        let taken_addr = taken.local_addr().expect("addr").to_string();
        let handler: InboundHandler = Arc::new(|_stream, _addr| {});

        let runtime = ListenerRuntime::start(
            &[
                ("tcp4", taken_addr.clone()),
                ("tcp4", "127.0.0.1:0".to_string()),
            ],
            Arc::clone(&handler),
        )
        .expect("the listener that binds serves");
        assert_eq!(runtime.bound_addrs().len(), 1);
        assert_ne!(runtime.bound_addrs()[0].to_string(), taken_addr);
        runtime.shutdown();

        let err = match ListenerRuntime::start(&[("tcp4", taken_addr)], handler) {
            Ok(_) => panic!("nothing bound"),
            Err(e) => e,
        };
        assert_eq!(err.to_string(), "no valid listen address");
    }

    /// A failed accept is logged with dcrd's `listenHandler` text unless
    /// it is one Go's `Accept` retries internally or the listener is
    /// shutting down; the port slept through every error silently.
    #[test]
    fn accept_errors_are_logged_like_dcrds() {
        let emfile = io::Error::from_raw_os_error(24);
        assert_eq!(
            accept_error_log(&emfile, false),
            Some(format!("Can't accept connection: {emfile}"))
        );
        assert_eq!(accept_error_log(&emfile, true), None);
        for quiet in [
            io::ErrorKind::WouldBlock,
            io::ErrorKind::Interrupted,
            io::ErrorKind::ConnectionAborted,
        ] {
            assert_eq!(accept_error_log(&io::Error::from(quiet), false), None);
        }
    }

    /// The admission path's group token buckets run on
    /// `monotonic_nanos`, as dcrd's `Time.Sub` of two `time.Now` values
    /// is monotonic: a bucket it drained is refilled five seconds later
    /// on that clock.  Handed the wall clock, the bucket's stamp sat
    /// some 1.7e18ns past every monotonic reading, which is how a
    /// backward wall-clock step froze a drained group.
    #[test]
    fn inbound_admission_times_its_buckets_on_the_monotonic_clock() {
        use dcroxide_connmgr::InboundDecision;

        let mut csprng = dcroxide_connmgr::SystemCsprng::default();
        let mut mgr = dcroxide_connmgr::ConnManager::new(Default::default(), &mut csprng);
        let remote = dcroxide_addrmgr::new_net_address_from_ip_port(
            &[203, 0, 113, 7],
            9108,
            ServiceFlag(0),
            now_unix_nanos(),
        );
        let rate_limited = |decision: &InboundDecision| match decision {
            InboundDecision::Drop { reason } => reason == "rate limited",
            _ => false,
        };
        for _ in 0..dcroxide_connmgr::GROUP_BURST_LIMIT {
            let decision = admit_inbound_now(&mut mgr, &remote, &mut csprng);
            assert!(!rate_limited(&decision), "{decision:?}");
        }
        let decision = admit_inbound_now(&mut mgr, &remote, &mut csprng);
        assert!(rate_limited(&decision), "the burst is spent: {decision:?}");

        // One token (0.2/s) is back five monotonic seconds later.
        let now_nanos = now_unix_nanos();
        let later = dcroxide_connmgr::monotonic_nanos() + 5_000_000_000;
        let decision = mgr.admit_inbound(
            &remote,
            now_nanos / 1_000_000_000,
            now_nanos,
            later,
            &mut csprng,
        );
        assert!(!rate_limited(&decision), "{decision:?}");
    }

    /// The drop-log throttle runs on `monotonic_nanos` too: the burst it
    /// spent regains a token a minute later on that clock.
    #[test]
    fn inbound_drop_logging_times_its_bucket_on_the_monotonic_clock() {
        let mut csprng = dcroxide_connmgr::SystemCsprng::default();
        let manager = Arc::new(Mutex::new(dcroxide_connmgr::ConnManager::new(
            Default::default(),
            &mut csprng,
        )));
        let addr: SocketAddr = "203.0.113.7:9108".parse().expect("addr");
        let mut mgr = manager.lock().expect("connmgr mutex");
        for _ in 0..dcroxide_connmgr::DROP_LOG_BURST_LIMIT {
            log_inbound_drop(&mut mgr, &manager, &addr, "rate limited");
        }
        let later = dcroxide_connmgr::monotonic_nanos() + 61_000_000_000;
        assert_eq!(
            mgr.inbound_limiter.log_drops(later),
            dcroxide_connmgr::LogDropsOutcome::Logged
        );
    }
}
