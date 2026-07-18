// SPDX-License-Identifier: ISC
//! The outbound connection driver — the event-loop driver over the
//! ported decision-core connection manager (dcrd `connmgr.ConnManager`
//! driven by `server.go`'s connection callbacks).
//!
//! The connection manager itself is synchronous: it returns [`Event`]s
//! describing dials to make, retries to schedule, and connections that
//! came up or went down.  This driver runs it on a dedicated thread,
//! turning the dial events into per-request dialer threads (dcrd's
//! `Connect` goroutines, reporting back through the manager's
//! `dial_outcome`), the scheduling events into timer threads, and the
//! connection events into served outbound peers, feeding every result
//! back in — so the event loop, and the RPC control commands riding it,
//! never block on a dial.  A dialed socket rides inside the manager's
//! connection handle so the `Connected` event can hand it to
//! [`serve_outbound_peer`], which runs it through the same server
//! dispatch as an inbound peer (dcrd's `serverPeer` serves both
//! directions), registering it with the sync manager so the daemon
//! syncs from the peers it dials.
//!
//! The driver opens the permanent connections requested with
//! `--connect` and fills the remaining outbound slots from the address
//! source; [`new_address_source`] is dcrd's `newAddressFunc` over the
//! shared address manager, with its outbound-group spreading,
//! recent-attempt, and default-port filtering.

use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use dcroxide_addrmgr::{AddrManager, NetAddressType};
use dcroxide_connmgr::{Config, Conn, ConnManager, Event, ReqAddr};

use crate::dispatch::{OutboundGroups, ServerContext};
use crate::runtime::{ConnectedPeers, PeerTemplate, serve_outbound_peer};

/// The address source the automatic dialer draws from.
pub type AddressSource = Box<dyn FnMut() -> Result<ReqAddr, String> + Send>;

/// A dialed connection handle owned by the connection manager.  It
/// carries the established stream so the `Connected` event can hand it
/// to the peer runtime, and a second handle so the manager can close
/// the socket on cancel or disconnect (dcrd closes the `net.Conn`).
struct DialedConn {
    stream: Arc<Mutex<Option<TcpStream>>>,
    shutdown: TcpStream,
}

impl Conn for DialedConn {
    fn close(&mut self) {
        let _ = self.shutdown.shutdown(Shutdown::Both);
    }
}

/// The configuration for the outbound connection driver.
pub struct OutboundConfig {
    /// The peer template each dialed connection is built from.
    pub template: PeerTemplate,
    /// The registry the served outbound peers are tracked in.
    pub connected: ConnectedPeers,
    /// The server dispatch context the peers are served through.
    pub server: Option<Arc<ServerContext>>,
    /// The number of automatic outbound connections to maintain (dcrd
    /// `TargetOutbound`); only the address-source dialing honours it,
    /// so it is unused until that source lands.
    pub target_outbound: u32,
    /// The maximum number of peers, bounding RPC-requested connects
    /// (dcrd `rpcConnManager.Connect`'s `cfg.MaxPeers` check against
    /// the peer count).
    pub max_peers: usize,
    /// How long to wait before retrying a failed permanent connection
    /// (dcrd `RetryDuration`).
    pub retry_duration: Duration,
    /// How long to wait for a dial to complete (dcrd `Timeout`).
    pub dial_timeout: Duration,
    /// The addresses to keep permanent connections to (dcrd's
    /// `--connect`).
    pub permanent: Vec<String>,
    /// The source of new addresses to dial automatically, maintaining
    /// `target_outbound` connections (dcrd's `NewConnReq` address
    /// source); absent when only permanent connections are wanted.
    pub get_new_address: Option<AddressSource>,
    /// The dial routing (direct, SOCKS5 proxy, and the onion rules;
    /// dcrd's `dcrdDial` over the configured closures).
    pub dialer: crate::socks::NodeDialer,
    /// The address manager, so each dial records an attempt against it
    /// (dcrd `attemptDcrdDial`'s `Attempt`).  `Some` only off simnet and
    /// regnet, matching where dcrd installs that dial hook; `None`
    /// otherwise leaves the dial path free of address bookkeeping.
    pub addr_manager: Option<Arc<Mutex<AddrManager>>>,
}

/// Build dcrd's `newAddressFunc` over the shared address manager: draw
/// candidates, skipping addresses in a group the daemon already has an
/// outbound connection to, recently attempted addresses for the first
/// thirty tries, and non-default ports for the first fifty.
pub fn new_address_source(
    addr_manager: Arc<Mutex<AddrManager>>,
    groups: OutboundGroups,
    default_port: String,
    filter: impl Fn(NetAddressType) -> bool + Send + 'static,
) -> AddressSource {
    Box::new(move || {
        for tries in 0..100 {
            let candidate = addr_manager
                .lock()
                .expect("addrmgr mutex poisoned")
                .get_address(&filter);
            let Some(candidate) = candidate else {
                break;
            };
            let candidate = candidate.lock().expect("known address poisoned");
            let net_addr = candidate.net_address();

            // Just check that we don't already have an address in the
            // same group so that we are not connecting to the same
            // network segment at the expense of others.
            if groups.count(&net_addr.group_key()) != 0 {
                continue;
            }

            // Skip recently attempted nodes until we have tried 30
            // times.
            if tries < 30
                && let Some(last_attempt) = candidate.last_attempt()
                && now_nanos().saturating_sub(last_attempt) < 10 * 60 * 1_000_000_000
            {
                continue;
            }

            // Allow non-default ports after 50 failed tries.
            if net_addr.port.to_string() != default_port && tries < 50 {
                continue;
            }

            return Ok(ReqAddr::tcp(&net_addr.key()));
        }
        Err("no valid connect address".to_string())
    })
}

/// The current unix time in nanoseconds for the recent-attempt check
/// (dcrd's `time.Since(lastAttempt)`).
fn now_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// The state the connection events need to serve a dialed peer and to
/// run the deferred dials off the event thread.
struct ServeState {
    template: PeerTemplate,
    connected: ConnectedPeers,
    server: Option<Arc<ServerContext>>,
    /// How long each dial may take (dcrd `Timeout` wrapping the dial
    /// context).
    dial_timeout: Duration,
    dialer: crate::socks::NodeDialer,
    /// The address manager each dial records an attempt against (dcrd
    /// `attemptDcrdDial`); `None` on simnet and regnet.
    addr_manager: Option<Arc<Mutex<AddrManager>>>,
}

/// A command the driver's event loop processes.
enum Command {
    /// A served outbound peer's connection ended; the manager should
    /// clean it up and schedule a replacement.
    PeerDone(u64),
    /// A scheduled retry timer for the identified request fired.
    RetryFire(u64),
    /// A scheduled new-connection timer fired.
    NewConnFire,
    /// A deferred dial finished on its dialer thread (dcrd's `Connect`
    /// goroutine messaging `handleConnected`/`handleFailed`); the
    /// manager processes the outcome without ever having blocked on
    /// the dial.
    DialDone(u64, Result<DialedConn, String>),
    /// An RPC-requested outbound connection (dcrd
    /// `rpcConnManager.Connect`): the loop runs the duplicate and
    /// max-peers checks over its state, replies with their result, and
    /// hands the dial to a dialer thread — so the RPC never waits on a
    /// dial (dcrd's `go connManager.Connect`).  The address is resolved
    /// by the sender on the RPC thread — where dcrd's
    /// `addrStringToNetAddr` runs — so a slow resolver never stalls the
    /// dial scheduling; the pre-computed result is unwrapped after the
    /// duplicate check to keep dcrd's error precedence.
    RpcConnect {
        addr: String,
        resolved: Result<SocketAddr, String>,
        permanent: bool,
        reply: mpsc::Sender<Result<(), String>>,
    },
    /// Remove the identified connection request so a persistent peer is
    /// not redialed (dcrd `connManager.Remove` from the RPC adaptor's
    /// `removeNode`).
    RpcRemove(u64),
    /// Cancel the pending connection to the address (dcrd
    /// `connManager.CancelPending` — `addnode remove`/`node remove` for
    /// a persistent peer that is mid-dial or awaiting a retry).
    RpcCancelPending {
        addr: String,
        reply: mpsc::Sender<Result<(), String>>,
    },
    /// Stop the driver.
    Stop,
}

/// The RPC control handle into the driver's event loop — the seams
/// dcrd's `rpcConnManager` reaches through `cm.server.connManager`.
/// Clones share the same driver.
#[derive(Clone)]
pub struct OutboundControl {
    commands: mpsc::Sender<Command>,
}

/// The failure every control call reports once the driver has stopped
/// and the command channel is closed — or was never attached (dcrd's
/// connmgr methods report "connection manager stopped" after quit).
pub(crate) const STOPPED: &str = "connection manager stopped";

impl OutboundControl {
    /// Add the address as a new outbound peer, persistent or one-try
    /// (dcrd `rpcConnManager.Connect`): duplicate requests, unresolvable
    /// addresses, and a full peer table are errors; the dial itself
    /// happens after this returns.
    pub fn connect(&self, addr: &str, permanent: bool) -> Result<(), String> {
        let (reply, result) = mpsc::channel();
        self.commands
            .send(Command::RpcConnect {
                addr: addr.to_string(),
                // Resolve here on the caller's thread (dcrd's
                // `addrStringToNetAddr` on the RPC goroutine); the loop
                // reports the outcome in dcrd's check order.
                resolved: addr_string_to_socket_addr(addr),
                permanent,
                reply,
            })
            .map_err(|_| STOPPED.to_string())?;
        result.recv().map_err(|_| STOPPED.to_string())?
    }

    /// Remove the connection request so its peer is not redialed (dcrd
    /// `connManager.Remove`); the peer's socket teardown is the
    /// caller's, exactly like dcrd's `removeNode` disconnecting the
    /// peer after the remove.
    pub fn remove(&self, conn_req_id: u64) {
        let _ = self.commands.send(Command::RpcRemove(conn_req_id));
    }

    /// Cancel the pending connection to the address (dcrd
    /// `connManager.CancelPending`).
    pub fn cancel_pending(&self, addr: &str) -> Result<(), String> {
        let (reply, result) = mpsc::channel();
        self.commands
            .send(Command::RpcCancelPending {
                addr: addr.to_string(),
                reply,
            })
            .map_err(|_| STOPPED.to_string())?;
        result.recv().map_err(|_| STOPPED.to_string())?
    }
}

/// The pre-created command channel a driver runs on, so the control
/// handle can be wired into consumers (the RPC connection manager)
/// before the driver itself starts.
pub struct OutboundChannel {
    control: OutboundControl,
    receiver: mpsc::Receiver<Command>,
}

impl OutboundChannel {
    /// A control handle for this channel's driver.
    pub fn control(&self) -> OutboundControl {
        self.control.clone()
    }
}

/// Create the command channel for a driver.
pub fn outbound_channel() -> OutboundChannel {
    let (commands, receiver) = mpsc::channel();
    OutboundChannel {
        control: OutboundControl { commands },
        receiver,
    }
}

/// The running outbound connection driver.  Dropping it (or calling
/// [`OutboundConnector::shutdown`]) stops the event loop.
pub struct OutboundConnector {
    commands: mpsc::Sender<Command>,
    thread: Option<JoinHandle<()>>,
}

impl OutboundConnector {
    /// Stop the driver's event loop and wait for it to finish.  The
    /// live outbound peers are torn down by the caller's connected-peer
    /// disconnect sweep, exactly like the listener runtime's shutdown.
    pub fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        let _ = self.commands.send(Command::Stop);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for OutboundConnector {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Start the outbound connection driver on the given channel, dialing
/// the configured permanent connections and keeping them up with the
/// manager's retry backoff.
pub fn start_outbound(cfg: OutboundConfig, channel: OutboundChannel) -> OutboundConnector {
    let commands = channel.control.commands;
    let receiver = channel.receiver;
    let loop_commands = commands.clone();
    let thread = thread::spawn(move || run_event_loop(cfg, loop_commands, receiver));
    OutboundConnector {
        commands,
        thread: Some(thread),
    }
}

/// Resolve an address string to a socket address (dcrd
/// `addrStringToNetAddr`, in its order): the host and port split with
/// Go's `net.SplitHostPort` semantics, the host resolves first — an IP
/// literal directly, a `.onion` host refused while Tor is unwired, any
/// other host through the system resolver taking the first answer —
/// and the port parses last, so a bad host surfaces its lookup error
/// before a bad port like dcrd.  The one divergence: the port must fit
/// sixteen bits here (a socket address cannot hold more), where dcrd
/// carries any integer and only fails the eventual dial.  The daemon
/// resolves its `--connect` peers through this at startup — where
/// dcrd's `newServer` does, failing the start on an unresolvable
/// address — so the manager's stored request addresses are always the
/// resolved form the duplicate and cancel checks compare against.
pub fn addr_string_to_socket_addr(addr: &str) -> Result<SocketAddr, String> {
    use std::net::ToSocketAddrs;
    let (host, port) = crate::gostd::split_host_port(addr)?;
    let ip = if let Ok(ip) = host.parse::<IpAddr>() {
        ip
    } else if host.ends_with(".onion") {
        // Tor addresses cannot be resolved to an IP; the Tor dial path
        // is not wired, matching dcrd's answer when onion support is
        // disabled.
        return Err("tor has been disabled".to_string());
    } else {
        // The resolver only accepts host:port pairs; the port is not
        // yet validated, so resolve with a placeholder and keep the
        // first answer's IP (dcrd's `dcrdLookup(host)` taking ips[0]).
        (host.as_str(), 0u16)
            .to_socket_addrs()
            .map_err(|e| e.to_string())?
            .next()
            .ok_or_else(|| format!("no addresses found for {host}"))?
            .ip()
    };
    let port: u16 = port
        .parse()
        .map_err(|_| format!("invalid port {port} in address {addr}"))?;
    Ok(SocketAddr::new(ip, port))
}

/// Dial the address for a connection request, wrapping the established
/// stream in the manager's connection handle (dcrd's `Dial`).
fn dial(
    req: &ReqAddr,
    timeout: Duration,
    dialer: &crate::socks::NodeDialer,
    addr_manager: Option<&Arc<Mutex<AddrManager>>>,
) -> Result<DialedConn, String> {
    // The sim/reg-net gate lives upstream: the manager is `None` on
    // those networks.
    if let Some(addr_manager) = addr_manager {
        mark_dial_attempt(addr_manager, dialer, &req.addr, timeout)?;
    }
    let stream = dialer
        .dial(&req.addr, timeout)
        .map_err(|e| format!("dial failed: {e}"))?;
    let shutdown = stream
        .try_clone()
        .map_err(|e| format!("dial clone failed: {e}"))?;
    Ok(DialedConn {
        stream: Arc::new(Mutex::new(Some(stream))),
        shutdown,
    })
}

/// The connection manager event loop: connect the permanent addresses,
/// then process the scheduling and connection events until stopped.
fn run_event_loop(
    cfg: OutboundConfig,
    commands: mpsc::Sender<Command>,
    receiver: mpsc::Receiver<Command>,
) {
    let serve = Arc::new(ServeState {
        template: cfg.template,
        connected: cfg.connected,
        server: cfg.server,
        dial_timeout: cfg.dial_timeout,
        dialer: cfg.dialer.clone(),
        addr_manager: cfg.addr_manager.clone(),
    });
    let max_peers = cfg.max_peers;

    let manager = ConnManager::new(Config {
        target_outbound: cfg.target_outbound,
        retry_duration_nanos: cfg.retry_duration.as_nanos() as i64,
        // Dials are deferred to per-request dialer threads (dcrd's
        // `Connect` goroutines), so the event loop never blocks on one
        // and the scheduling — and the RPC control commands — stay
        // responsive while dials are in flight.
        deferred_dials: true,
        get_new_address: cfg
            .get_new_address
            // Re-box to drop the Send bound the driver thread needed.
            .map(|source| source as Box<dyn FnMut() -> Result<ReqAddr, String>>),
        timeout_nanos: cfg.dial_timeout.as_nanos() as i64,
        ..Config::default()
    });
    let Ok(mut manager) = manager else {
        return;
    };

    // Open the permanent connections (dcrd `Connect` with permanent set
    // for each `--connect` address), then let the manager fill the
    // remaining outbound slots from the address source (dcrd `Start`).
    let mut events = Vec::new();
    for addr in &cfg.permanent {
        let (_id, dial_events) = manager.connect(ReqAddr::tcp(addr), true);
        events.extend(dial_events);
    }
    events.extend(manager.start());
    handle_events(&mut manager, events, &serve, &commands);

    while let Ok(command) = receiver.recv() {
        let events = match command {
            Command::Stop => break,
            Command::PeerDone(id) => manager.disconnect(id),
            Command::RetryFire(id) => manager.retry_connect(id),
            Command::NewConnFire => manager.new_conn_req_now(),
            Command::DialDone(id, outcome) => manager.dial_outcome(id, outcome),
            Command::RpcConnect {
                addr,
                resolved,
                permanent,
                reply,
            } => {
                match rpc_connect_checks(&manager, &serve, max_peers, &addr, resolved) {
                    Err(err) => {
                        let _ = reply.send(Err(err));
                        continue;
                    }
                    Ok(resolved) => {
                        // Reply before the dial so the RPC caller never
                        // waits on it (dcrd's `go connManager.Connect`
                        // after the synchronous checks).
                        let _ = reply.send(Ok(()));
                        let (_id, events) = manager.connect(resolved, permanent);
                        events
                    }
                }
            }
            Command::RpcRemove(id) => manager.remove(id),
            Command::RpcCancelPending { addr, reply } => {
                let _ = reply.send(manager.cancel_pending(&addr));
                continue;
            }
        };
        handle_events(&mut manager, events, &serve, &commands);
    }
}

/// The synchronous half of dcrd `rpcConnManager.Connect`, in its check
/// order: refuse a duplicate request, surface the (pre-computed)
/// resolution outcome, and refuse to exceed the peer limit.  Returns
/// the resolved dial address.
fn rpc_connect_checks(
    manager: &ConnManager<DialedConn>,
    serve: &ServeState,
    max_peers: usize,
    addr: &str,
    resolved: Result<SocketAddr, String>,
) -> Result<ReqAddr, String> {
    // Prevent duplicate connections to the same peer.  The comparison
    // is against the request's stored dial string — the resolved
    // address for RPC-added peers — matching dcrd comparing
    // `c.Addr.String()` against the normalized input (so a hostname
    // spelled differently from its stored resolution passes, exactly
    // like dcrd).
    manager.for_each_conn_req(|req| {
        let Some(req_addr) = &req.addr else {
            return Ok(());
        };
        if req_addr.addr == addr {
            if req.permanent {
                return Err("peer exists as a permanent peer".to_string());
            }
            match req.state {
                dcroxide_connmgr::ConnState::Pending => {
                    return Err("peer pending connection".to_string());
                }
                dcroxide_connmgr::ConnState::Established => {
                    return Err("peer already connected".to_string());
                }
                _ => {}
            }
        }
        Ok(())
    })?;

    // The resolution ran on the RPC thread; its error surfaces after
    // the duplicate check, in dcrd's order.
    let resolved = resolved?;

    // Limit max number of total peers (dcrd checks the peer-state count
    // against `cfg.MaxPeers`).  The connected-peers registry tracks
    // served connections in both directions from raw-socket serve time,
    // slightly earlier than dcrd's post-handshake `peerState` — the
    // same population the inbound admission cap counts, so the two
    // limits stay coherent within the daemon.
    if serve.connected.len() >= max_peers {
        return Err("max peers reached".to_string());
    }

    Ok(ReqAddr::tcp(&resolved.to_string()))
}

/// Act on the manager's events: serve established connections, and turn
/// the scheduling events into timers that feed commands back.
fn handle_events(
    manager: &mut ConnManager<DialedConn>,
    events: Vec<Event>,
    serve: &Arc<ServeState>,
    commands: &mpsc::Sender<Command>,
) {
    for event in events {
        match event {
            // A deferred dial: run it on its own thread (dcrd's
            // `Connect` goroutine) and report the outcome back as a
            // command, so the event loop never blocks on a dial.
            Event::Dial { id } => {
                let addr = manager.conn_req(id).and_then(|req| req.addr.clone());
                let Some(addr) = addr else { continue };
                let serve = Arc::clone(serve);
                let commands = commands.clone();
                thread::spawn(move || {
                    let outcome = dial(
                        &addr,
                        serve.dial_timeout,
                        &serve.dialer,
                        serve.addr_manager.as_ref(),
                    );
                    let _ = commands.send(Command::DialDone(id, outcome));
                });
            }
            Event::Connected { id } => {
                // Take the dialed stream out of the request and serve it
                // on its own thread, reporting back when it ends.
                let stream = manager
                    .conn_req(id)
                    .and_then(|req| req.conn.as_ref())
                    .and_then(|conn| conn.stream.lock().expect("dial stream poisoned").take());
                let addr = manager
                    .conn_req(id)
                    .and_then(|req| req.addr.as_ref())
                    .and_then(|addr| addr.addr.parse::<SocketAddr>().ok());
                // Whether this is a persistent (added-node) connection, so
                // the served peer is registered as one (dcrd's
                // `serverPeer.persistent`).
                let permanent = manager
                    .conn_req(id)
                    .map(|req| req.permanent)
                    .unwrap_or(false);
                if let (Some(stream), Some(addr)) = (stream, addr) {
                    let serve = Arc::clone(serve);
                    let commands = commands.clone();
                    thread::spawn(move || {
                        serve_outbound_peer(
                            stream,
                            addr,
                            &serve.template,
                            &serve.connected,
                            serve.server.clone(),
                            permanent,
                            // The connection-request id rides with the
                            // served peer so `node remove` can stop its
                            // redial (dcrd's `serverPeer.connReq`).
                            Some(id),
                        );
                        let _ = commands.send(Command::PeerDone(id));
                    });
                }
            }
            // The disconnect bookkeeping is driven by the peer thread's
            // PeerDone command; nothing extra to do here.
            Event::Disconnected { .. } => {}
            Event::ScheduleRetry { id, delay_nanos } => {
                spawn_timer(delay_nanos, commands.clone(), Command::RetryFire(id));
            }
            Event::ScheduleNewConn { delay_nanos } => {
                spawn_timer(delay_nanos, commands.clone(), Command::NewConnFire);
            }
        }
    }
}

/// dcrd `attemptDcrdDial`'s address bookkeeping: make sure the
/// address exists in the address manager (`AddAddresses` with the
/// address as its own source, so a `--connect`/addnode target the
/// manager never learned joins it for gossip and persistence) and
/// mark it attempted (the recently-attempted gate and `chance()`
/// penalty), before the actual dial.  The host/port split, the port
/// parse, and the net-address conversion failures fail the dial
/// exactly as dcrd returns them; the `Attempt` error is only logged
/// there and is discarded here.
fn mark_dial_attempt(
    addr_manager: &Arc<Mutex<AddrManager>>,
    dialer: &crate::socks::NodeDialer,
    addr: &str,
    timeout: Duration,
) -> Result<(), String> {
    let (host, port_str) = crate::gostd::split_host_port(addr)?;
    let port: u16 = port_str
        .parse()
        .map_err(|e| format!("strconv.ParseUint: parsing \"{port_str}\": {e}"))?;
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let na = crate::server::host_to_net_address(
        &host,
        port,
        dcroxide_wire::ServiceFlag(0),
        &|h| dialer.lookup(h, timeout),
        now_unix,
    )?;
    let mut mgr = addr_manager.lock().expect("addr manager mutex poisoned");
    mgr.add_addresses(core::slice::from_ref(&na), &na);
    let _ = mgr.attempt(&na);
    Ok(())
}

/// Fire the command back to the event loop after the delay (dcrd arms a
/// `time.After` for the same schedule).  The timer is detached; once
/// the loop stops and drops the receiver the send simply fails.
fn spawn_timer(delay_nanos: i64, commands: mpsc::Sender<Command>, command: Command) {
    let delay = Duration::from_nanos(delay_nanos.max(0) as u64);
    thread::spawn(move || {
        thread::sleep(delay);
        let _ = commands.send(command);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// dcrd `attemptDcrdDial`'s bookkeeping: a routable dial target the
    /// manager never learned joins it (AddAddresses with itself as the
    /// source) and is marked attempted before the dial.
    #[test]
    fn dial_bookkeeping_adds_and_attempts_the_target() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mgr = Arc::new(Mutex::new(AddrManager::new(dir.path())));
        let dialer = crate::socks::NodeDialer::direct();

        mark_dial_attempt(&mgr, &dialer, "8.8.8.8:9108", Duration::from_secs(1))
            .expect("bookkeeping");

        let locked = mgr.lock().expect("addrmgr");
        let known = locked
            .get_address(|_| true)
            .expect("the target must join the manager");
        let known = known.lock().expect("known address");
        assert_eq!(known.net_address().key(), "8.8.8.8:9108");
        assert!(
            known.last_attempt().is_some(),
            "the dial must be marked attempted"
        );
    }

    /// An unparseable dial address fails the dial like dcrd's
    /// attemptDcrdDial returning the split error.
    #[test]
    fn dial_bookkeeping_rejects_malformed_addresses() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mgr = Arc::new(Mutex::new(AddrManager::new(dir.path())));
        let dialer = crate::socks::NodeDialer::direct();
        assert!(
            mark_dial_attempt(&mgr, &dialer, "no-port", Duration::from_secs(1)).is_err(),
            "a missing port must fail the dial"
        );
    }
}
