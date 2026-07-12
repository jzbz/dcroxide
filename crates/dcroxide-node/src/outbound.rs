// SPDX-License-Identifier: ISC
//! The outbound connection driver — the event-loop driver over the
//! ported decision-core connection manager (dcrd `connmgr.ConnManager`
//! driven by `server.go`'s connection callbacks).
//!
//! The connection manager itself is synchronous: it returns [`Event`]s
//! describing dials to make, retries to schedule, and connections that
//! came up or went down.  This driver runs it on a dedicated thread,
//! turning the scheduling events into timer threads and the connection
//! events into served outbound peers, and feeding the results back in.
//! A dialed socket rides inside the manager's connection handle so the
//! `Connected` event can hand it to [`serve_outbound_peer`], which runs
//! it through the same server dispatch as an inbound peer (dcrd's
//! `serverPeer` serves both directions), registering it with the sync
//! manager so the daemon syncs from the peers it dials.
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

use dcroxide_addrmgr::AddrManager;
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
) -> AddressSource {
    Box::new(move || {
        for tries in 0..100 {
            let candidate = addr_manager
                .lock()
                .expect("addrmgr mutex poisoned")
                .get_address();
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

/// The state the connection events need to serve a dialed peer.
struct ServeState {
    template: PeerTemplate,
    connected: ConnectedPeers,
    server: Option<Arc<ServerContext>>,
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
    /// Stop the driver.
    Stop,
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

/// Start the outbound connection driver, dialing the configured
/// permanent connections and keeping them up with the manager's retry
/// backoff.
pub fn start_outbound(cfg: OutboundConfig) -> OutboundConnector {
    let (commands, receiver) = mpsc::channel();
    let loop_commands = commands.clone();
    let thread = thread::spawn(move || run_event_loop(cfg, loop_commands, receiver));
    OutboundConnector {
        commands,
        thread: Some(thread),
    }
}

/// Dial the address for a connection request, wrapping the established
/// stream in the manager's connection handle (dcrd's `Dial`).
fn dial(
    req: &ReqAddr,
    timeout: Duration,
    addr_manager: Option<&Arc<Mutex<AddrManager>>>,
) -> Result<DialedConn, String> {
    let socket: SocketAddr = req
        .addr
        .parse()
        .map_err(|e| format!("invalid dial address {}: {e}", req.addr))?;
    // Record the dial attempt so the address manager's recently-attempted
    // gate and chance() penalty apply, and the same dead address is not
    // redialed in a tight loop (dcrd `attemptDcrdDial` marking `Attempt`
    // before the dial).  A not-found address — a permanent `--connect`
    // peer the manager never learned — is ignored, as dcrd does; the
    // address's services and timestamp do not affect the lookup, which
    // keys on the canonicalized host and port.
    if let Some(addr_manager) = addr_manager {
        let ip_bytes = match socket.ip() {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        let na = dcroxide_addrmgr::new_net_address_from_ip_port(
            &ip_bytes,
            socket.port(),
            dcroxide_wire::ServiceFlag(0),
            0,
        );
        let _ = addr_manager
            .lock()
            .expect("addr manager mutex poisoned")
            .attempt(&na);
    }
    let stream =
        TcpStream::connect_timeout(&socket, timeout).map_err(|e| format!("dial failed: {e}"))?;
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
    });
    let dial_timeout = cfg.dial_timeout;
    let dial_addr_manager = cfg.addr_manager.clone();

    let manager = ConnManager::new(Config {
        target_outbound: cfg.target_outbound,
        retry_duration_nanos: cfg.retry_duration.as_nanos() as i64,
        dial: Some(Box::new(move |req: &ReqAddr| {
            dial(req, dial_timeout, dial_addr_manager.as_ref())
        })),
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
        };
        handle_events(&mut manager, events, &serve, &commands);
    }
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
