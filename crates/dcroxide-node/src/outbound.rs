// SPDX-License-Identifier: ISC
//! The outbound connection driver — the daemon threads over the dcrd
//! 2.2 connection manager decision core (dcrd `internal/connmgr`'s
//! goroutines: `targetOutboundHandler`, the per-entry `runPersistent`
//! loops, and the dial goroutines, driven by `server.go`'s callbacks).
//!
//! The core is synchronous and shared behind a mutex; this driver
//! runs the loops dcrd runs as goroutines: an event thread processing
//! commands, per-dial dialer threads reporting outcomes back (so the
//! event thread never blocks on a dial), and the served-peer threads.
//! The retry backoff and the failed-attempt pause are deadlines the
//! event thread keeps itself and waits on between commands, rather than
//! a thread per timer: with every outbound slot held, the permit poll
//! re-arms every retry interval for as long as the node runs.
//! The automatic-outbound fill mirrors dcrd's `targetOutboundHandler`
//! — permits from the two semaphore counters (parking on the total one
//! as dcrd's handler blocks on it), `pick_outbound_addr` over the
//! address source, the per-host permit, and up to
//! `MAX_FAILED_ATTEMPTS` quick retries before pausing for the retry
//! duration.  Persistent entries mirror `runPersistent`: an attempt
//! stamps its start, a drop within one retry interval of it backs off
//! exponentially with jitter, and a connection that held longer
//! resets the ladder.
//!
//! dcrd's `Connect` and `AddPersistent` are reached from the RPC
//! adapter through [`OutboundControl`]; per dcrd 2.2 the connection
//! manager's typed error descriptions surface raw (the v1 adapter's
//! custom duplicate strings are gone upstream).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use dcroxide_addrmgr::{AddrManager, NetAddress, new_net_address_from_ip_port};
use dcroxide_connmgr::manager::{
    ClosePlan, ConnManager, DisconnectAction, MAX_FAILED_ATTEMPTS, NO_SUITABLE_ADDR_MSG,
    PICK_OUTBOUND_RETRIES,
};
use dcroxide_connmgr::{AutoBegin, AutoPermits, ConnectionType, SystemCsprng};

use crate::dispatch::ServerContext;
use crate::runtime::{ConnectedPeers, PeerTemplate, serve_outbound_peer};

/// The shared connection manager decision core (dcrd's `ConnManager`
/// reached from the server, the listener runtime, and this driver).
pub type SharedConnManager = Arc<Mutex<ConnManager>>;

/// The address source the automatic dialer draws from: dcrd
/// `Config.GetNewAddress`, returning the candidate and its last
/// attempt time in unix nanoseconds, 0 when it was never attempted
/// (dcrd's `lastTry time.Time`, which
/// [`ConnManager::pick_outbound_addr`] compares against its ten-minute
/// recent-attempt window in nanoseconds).
pub type AddressSource = Box<dyn FnMut() -> Result<(NetAddress, i64), String> + Send>;

/// A dialed connection handle: the established connection for the serve
/// thread, and a teardown clone so `Disconnect`/`Remove` can end it
/// (dcrd closing the `net.Conn`).
///
/// Both halves are `Teardown`s sharing one flag, so ending the
/// connection from the driver raises the same flag the serve thread's
/// reader polls.  Holding a bare socket here was the bug: `close` shut
/// the socket down and left the flag alone, which is the half this
/// module's transport documentation says cannot be relied on to abort
/// an in-flight `recv` under Winsock.
struct DialedConn {
    stream: Arc<Mutex<Option<crate::transport::Teardown>>>,
    shutdown: crate::transport::Teardown,
}

impl DialedConn {
    fn close(&self) {
        self.shutdown.disconnect();
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
    /// The shared connection manager core.
    pub manager: SharedConnManager,
    /// How long to wait for a dial to complete (dcrd
    /// `Config.DialTimeout`).
    pub dial_timeout: Duration,
    /// The persistent entries registered at startup (dcrd's
    /// `--connect`/`--addpeer` peers added via `AddPersistent` by the
    /// binary before the driver starts).
    pub persistent: Vec<(u64, NetAddress)>,
    /// The source of new addresses for automatic outbound
    /// connections (dcrd `Config.GetNewAddress`); `None` disables
    /// automatic dialing exactly as a nil `GetNewAddress` does.
    pub get_new_address: Option<AddressSource>,
    /// The dial routing (direct, SOCKS5 proxy, and the onion rules;
    /// dcrd's `dcrdDial` over the configured closures).
    pub dialer: crate::socks::NodeDialer,
    /// The address manager each dial records an attempt against
    /// (dcrd `attemptDcrdDial`); `None` on simnet and regnet.
    pub addr_manager: Option<Arc<Mutex<AddrManager>>>,
}

/// The state the connection events need to serve a dialed peer and
/// run the dials off the event thread.
struct ServeState {
    template: PeerTemplate,
    connected: ConnectedPeers,
    server: Option<Arc<ServerContext>>,
    dial_timeout: Duration,
    dialer: crate::socks::NodeDialer,
    addr_manager: Option<Arc<Mutex<AddrManager>>>,
}

/// What kind of dial a `DialDone` outcome finishes, carrying the
/// reservations its close plan (or failure unwind) must release.
enum DialKind {
    /// An automatic outbound dial (dcrd `ConnTypeOutbound` from
    /// `targetOutboundHandler`).
    Auto {
        addr: NetAddress,
        host_permit_reserved: bool,
    },
    /// A manual one-try dial (dcrd `Connect` → `ConnTypeManual`); the
    /// RPC reply resolves with the dial outcome, matching master's
    /// synchronous `Connect` error propagation.
    Manual {
        addr: NetAddress,
        plan: ClosePlan,
        reply: mpsc::Sender<Result<(), String>>,
    },
    /// A persistent entry's dial (dcrd `runPersistent` →
    /// `ConnTypeManual` with the entry's stable ID).
    Persistent {
        addr: NetAddress,
        host_permit_reserved: bool,
    },
}

/// A command the driver's event loop processes.
enum Command {
    /// A served outbound peer's connection ended.
    PeerDone(u64),
    /// A persistent entry's backoff timer fired (a [`Wake::Retry`]
    /// coming due).
    RetryFire(u64),
    /// The failed-attempt pause (or an external nudge) elapsed;
    /// resume filling the outbound target (a [`Wake::NewConn`] coming
    /// due).
    NewConnFire,
    /// A release handed the parked fill the total-connections permit
    /// it was waiting on (dcrd's blocked `Acquire` returning); resume
    /// filling.
    PermitGranted,
    /// A dial finished on its dialer thread.
    DialDone(u64, DialKind, Result<DialedConn, String>),
    /// dcrd `rpcConnManager.Connect`: resolved on the RPC thread,
    /// gated and dialed here; the reply carries the connection
    /// manager's raw error description.
    RpcConnect {
        resolved: Result<NetAddress, String>,
        permanent: bool,
        reply: mpsc::Sender<Result<(), String>>,
    },
    /// Remove the identified connection (dcrd `connManager.Remove`
    /// from the RPC adapter).
    RpcRemove(u64),
    /// dcrd `RemoveByID`'s fallback: remove the ID only when it is a
    /// persistent entry.
    RpcRemoveIfPersistent { id: u64, reply: mpsc::Sender<bool> },
    /// dcrd `RemoveByAddr`'s fallback: find the persistent entry
    /// whose stored key equals the raw address string and remove it.
    RpcRemovePersistentByAddr {
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
    /// The lookup routing [`OutboundControl::connect`] resolves its
    /// target through (dcrd's `dcrdLookup` inside
    /// `addrStringToNetAddr`).
    dialer: crate::socks::NodeDialer,
}

/// The failure every control call reports once the driver has
/// stopped and the command channel is closed (dcrd's connmgr methods
/// after quit).
pub(crate) const STOPPED: &str = "connection manager stopped";

impl OutboundControl {
    /// Add the address as a new outbound peer, persistent or one-try
    /// (dcrd `rpcConnManager.Connect`): the address resolves on this
    /// thread through the channel's routing — dcrd's
    /// `addrStringToNetAddr` on the RPC goroutine — and the connection
    /// manager's gate errors surface raw.  A one-try dial that runs out
    /// its timeout, or is canceled, fails with
    /// [`dcroxide_rpc::server::CONNECT_DEADLINE_EXCEEDED`] or
    /// [`dcroxide_rpc::server::CONNECT_CANCELED`], dcrd's context
    /// errors.
    pub fn connect(&self, addr: &str, permanent: bool) -> Result<(), String> {
        let (reply, result) = mpsc::channel();
        self.commands
            .send(Command::RpcConnect {
                resolved: addr_string_to_net_address(addr, &self.dialer),
                permanent,
                reply,
            })
            .map_err(|_| STOPPED.to_string())?;
        result.recv().map_err(|_| STOPPED.to_string())?
    }

    /// Remove the connection so a persistent peer is not redialed
    /// (dcrd `connManager.Remove` after `removeNode` matched a
    /// connected persistent peer).
    pub fn remove(&self, conn_id: u64) {
        let _ = self.commands.send(Command::RpcRemove(conn_id));
    }

    /// dcrd `RemoveByID`'s fallback: treat the ID as a connection ID
    /// and remove it when it belongs to a persistent entry.
    pub fn remove_if_persistent(&self, id: u64) -> bool {
        let (reply, result) = mpsc::channel();
        if self
            .commands
            .send(Command::RpcRemoveIfPersistent { id, reply })
            .is_err()
        {
            return false;
        }
        result.recv().unwrap_or(false)
    }

    /// dcrd `RemoveByAddr`'s fallback: find the persistent entry
    /// whose stored key equals the raw address string and remove it;
    /// "peer not found" when absent (dcrd matches the unresolved
    /// string against the stored resolved keys, so a hostname spelled
    /// differently from its resolution is not found, exactly like
    /// upstream).
    pub fn remove_persistent_by_addr(&self, addr: &str) -> Result<(), String> {
        let (reply, result) = mpsc::channel();
        self.commands
            .send(Command::RpcRemovePersistentByAddr {
                addr: addr.to_string(),
                reply,
            })
            .map_err(|_| STOPPED.to_string())?;
        result.recv().map_err(|_| STOPPED.to_string())?
    }
}

/// The pre-created command channel a driver runs on, so the control
/// handle can be wired into consumers before the driver starts.
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

/// Create the command channel for a driver whose control handle
/// resolves `connect` targets with the default routing (dcrd's
/// `net.LookupIP`: the system resolver).  The daemon passes its
/// configured routing through [`outbound_channel_with_dialer`].
pub fn outbound_channel() -> OutboundChannel {
    outbound_channel_with_dialer(crate::socks::NodeDialer::direct())
}

/// Create the command channel for a driver whose control handle
/// resolves `connect` targets through `dialer` — the routing the
/// driver dials with ([`OutboundConfig::dialer`]), so a proxied daemon
/// resolves `addnode`/`node connect` names through Tor like dcrd's
/// `dcrdLookup` rather than the system resolver.
pub fn outbound_channel_with_dialer(dialer: crate::socks::NodeDialer) -> OutboundChannel {
    let (commands, receiver) = mpsc::channel();
    OutboundChannel {
        control: OutboundControl { commands, dialer },
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
    /// Stop the driver's event loop and wait for it to finish.
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

/// Start the outbound connection driver on the given channel.
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

/// How long resolving a `connect` or persistent target may take.  dcrd's
/// `dcrdLookup` runs without a deadline; one minute bounds a Tor
/// resolution the way the `getaddednodeinfo` lookup does
/// (`rpcrun.rs`).  The system resolver ignores it.
const TARGET_LOOKUP_TIMEOUT: Duration = Duration::from_secs(60);

/// Resolve an address string to the connection manager's address form
/// (dcrd `addrStringToNetAddr`, and then `stdlibNetAddrToAddrMgrNetAddr`,
/// which `Connect` and `AddPersistent` run over its result), in dcrd's
/// order.  The host and port split with Go's `net.SplitHostPort`
/// semantics.  A Tor v3 host stays unresolved (dcrd's `simpleAddr`) and
/// takes the onion route when it is dialed.  Any other host, IP
/// literals included, resolves through `dialer`'s `dcrdLookup` routing
/// and the first answer is used: through Tor when `--proxy` is set
/// without `--noonion`, a `.onion` name through the onion route, and
/// otherwise through the system resolver, which answers a literal
/// itself.  The port number parses last, so a bad host surfaces its
/// lookup error before a bad port, as in dcrd.
pub fn addr_string_to_net_address(
    addr: &str,
    dialer: &crate::socks::NodeDialer,
) -> Result<NetAddress, String> {
    let (host, port) = crate::gostd::split_host_port(addr)?;

    // Determine the network that the address belongs to and return
    // early if a DNS lookup should not be performed for the address.
    let (addr_type, addr_bytes) = dcroxide_addrmgr::encode_host(&host);
    if addr_type == dcroxide_addrmgr::NetAddressType::TorV3 {
        // `stdlibNetAddrToAddrMgrNetAddr`'s string path over the
        // unresolved address.
        let port = go_parse_uint16(&port)
            .map_err(|_| format!("invalid port for address {}", crate::gostd::go_quote(addr)))?;
        return dcroxide_addrmgr::new_net_address_from_params(
            addr_type,
            &addr_bytes,
            port,
            now_unix().saturating_mul(1_000_000_000),
            dcroxide_wire::ServiceFlag(0),
        )
        .map_err(|e| e.description);
    }

    // The lookup runs over Tor when the configuration says so (dcrd:
    // "The dcrdLookup function will transparently handle performing
    // the lookup over Tor if necessary").
    let ips = dialer.lookup(&host, TARGET_LOOKUP_TIMEOUT)?;
    let Some(ip) = ips.first() else {
        return Err(format!("no addresses found for {host}"));
    };
    let port = go_parse_uint16(&port)?;
    Ok(socket_addr_to_net_address(&SocketAddr::new(*ip, port)))
}

/// Go's `strconv.ParseUint(s, 10, 16)`, with its `NumError` texts: the
/// digits accumulate left to right, so an overflow is reported before a
/// later non-digit, as in Go.
fn go_parse_uint16(s: &str) -> Result<u16, String> {
    let error = |reason: &str| {
        format!(
            "strconv.ParseUint: parsing {}: {reason}",
            crate::gostd::go_quote(s)
        )
    };
    if s.is_empty() {
        return Err(error("invalid syntax"));
    }
    let mut n: u16 = 0;
    for c in s.bytes() {
        if !c.is_ascii_digit() {
            return Err(error("invalid syntax"));
        }
        n = n
            .checked_mul(10)
            .and_then(|n| n.checked_add(u16::from(c.wrapping_sub(b'0'))))
            .ok_or_else(|| error("value out of range"))?;
    }
    Ok(n)
}

/// The address-manager form of a resolved socket address (dcrd's
/// `stdlibNetAddrToAddrMgrNetAddr` fast path for TCP addresses).
pub fn socket_addr_to_net_address(addr: &SocketAddr) -> NetAddress {
    let ip_bytes = match addr.ip() {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    new_net_address_from_ip_port(
        &ip_bytes,
        addr.port(),
        dcroxide_wire::ServiceFlag(0),
        now_unix().saturating_mul(1_000_000_000),
    )
}

/// The current unix time in seconds.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The current unix time in nanoseconds (the recent-attempt and
/// backoff clock).
fn now_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// A wake the event loop owes itself once its deadline passes (dcrd
/// arms a `time.Timer`, or sleeps in line, for the same schedule).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wake {
    /// A persistent entry's backoff elapsed ([`Command::RetryFire`]).
    Retry(u64),
    /// The failed-attempt pause or the permit poll elapsed
    /// ([`Command::NewConnFire`]).
    NewConn,
}

impl Wake {
    fn command(self) -> Command {
        match self {
            Wake::Retry(id) => Command::RetryFire(id),
            Wake::NewConn => Command::NewConnFire,
        }
    }
}

/// The per-entry retry state of dcrd's `runPersistent` loop.
struct PersistState {
    addr: NetAddress,
    retry_count: u32,
    last_attempt_nanos: Option<i64>,
}

/// The driver's event-loop state.
struct LoopState {
    manager: SharedConnManager,
    serve: Arc<ServeState>,
    commands: mpsc::Sender<Command>,
    csprng: SystemCsprng,
    get_new_address: Option<AddressSource>,
    /// dcrd `targetOutboundHandler`'s `failedAttempts`.
    failed_attempts: u64,
    /// Whether a wake timer is already armed (the failed-attempt
    /// pause, or the poll while every outbound permit is held), so
    /// timers are not stacked.
    pause_armed: bool,
    /// The pause elapsed: the next fill iteration attempts once even
    /// though the failure count is at the threshold (dcrd's loop
    /// sleeps and then falls through to one more attempt).
    resume_after_pause: bool,
    /// The persistent runner states by entry ID.
    persistent: HashMap<u64, PersistState>,
    /// The sockets of established managed connections, for the
    /// force-close paths of `Disconnect`/`Remove`.
    sockets: HashMap<u64, DialedConn>,
    /// The armed wakes and when each comes due, in arming order.
    timers: Vec<(Instant, Wake)>,
}

/// Dial the address on a dialer thread, reporting the outcome back
/// (dcrd's dial goroutines over `Config.Dial`).
///
/// The dial's kind is handed to the thread only once it exists, so a
/// thread the OS refuses gives it back and the dial is reported failed
/// through the ordinary outcome path, releasing its reservations; see
/// [`crate::runtime::spawn_conn_thread`].
fn spawn_dial(state: &LoopState, id: u64, addr: NetAddress, kind: DialKind) {
    let serve = Arc::clone(&state.serve);
    let commands = state.commands.clone();
    let (handoff, pending) = mpsc::sync_channel::<DialKind>(1);
    let spawned = crate::runtime::spawn_conn_thread("peer-dial", move || {
        let outcome = dial(
            &addr.key(),
            serve.dial_timeout,
            &serve.dialer,
            serve.addr_manager.as_ref(),
        );
        if let Ok(kind) = pending.recv() {
            let _ = commands.send(Command::DialDone(id, kind, outcome));
        }
    });
    match spawned {
        Ok(_) => {
            let _ = handoff.send(kind);
        }
        Err(e) => {
            let _ = state.commands.send(Command::DialDone(
                id,
                kind,
                Err(format!("dial failed: unable to start a thread: {e}")),
            ));
        }
    }
}

/// Dial the address, wrapping the established stream in the driver's
/// connection handle (dcrd's `Dial` through `attemptDcrdDial`).
fn dial(
    addr: &str,
    timeout: Duration,
    dialer: &crate::socks::NodeDialer,
    addr_manager: Option<&Arc<Mutex<AddrManager>>>,
) -> Result<DialedConn, String> {
    if let Some(addr_manager) = addr_manager {
        mark_dial_attempt(addr_manager, dialer, addr, timeout)?;
    }
    // The connection's teardown handle is minted here, at the dial, so
    // the driver's `close` and the serve thread's reader share one flag
    // (dcrd shares the `net.Conn` itself).
    let stream = crate::transport::Teardown::new(dialer.dial(addr, timeout).map_err(dial_failure)?);
    let shutdown = stream
        .try_clone()
        .map_err(|e| format!("dial clone failed: {e}"))?;
    Ok(DialedConn {
        stream: Arc::new(Mutex::new(Some(stream))),
        shutdown,
    })
}

/// std's text for a TCP connect that ran out its timeout
/// (`TcpStream::connect_timeout`'s `TimedOut`), which is what the dialer
/// reports for a direct dial or a connect to the SOCKS proxy that the
/// dial timeout cut short.
const CONNECT_TIMED_OUT: &str = "connection timed out";

/// The outcome text of a failed dial.  dcrd dials under
/// `context.WithTimeout(ctx, DialTimeout)`
/// (`internal/connmgr/connmanager.go:901-902`), and Go's dialer reports
/// a TCP connect that the deadline cut short, whether directly or to the
/// proxy, with an error that `errors.Is` `context.DeadlineExceeded`.
/// The RPC connect handlers answer that error with their timeout error
/// instead of an internal one, so it becomes
/// [`dcroxide_rpc::server::CONNECT_DEADLINE_EXCEEDED`] here.  Two other
/// failures are not that error in dcrd and keep their text: a SOCKS
/// handshake that outlasts the deadline (go-socks fails it on the
/// connection deadline, `i/o timeout`) and an OS-level `ETIMEDOUT`.
/// Every other failure is the dialer's own text, unprefixed, since
/// dcrd's `dial` returns `Config.Dial`'s error as it is and the RPC
/// handlers put it on the wire unchanged (`rpcInternalErr`).
fn dial_failure(e: String) -> String {
    if e == CONNECT_TIMED_OUT {
        dcroxide_rpc::server::CONNECT_DEADLINE_EXCEEDED.to_string()
    } else {
        e
    }
}

/// The connection manager driver loop.
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
    let mut state = LoopState {
        manager: cfg.manager,
        serve,
        commands,
        csprng: SystemCsprng::default(),
        get_new_address: cfg.get_new_address,
        failed_attempts: 0,
        pause_armed: false,
        resume_after_pause: false,
        persistent: HashMap::new(),
        sockets: HashMap::new(),
        timers: Vec::new(),
    };

    // Resume the fill when a release hands it the total-connections
    // permit it is parked on; dcrd's handler wakes from its blocking
    // `Acquire` by itself.  The waker runs under the manager lock, so
    // it only posts a command.
    let waker = state.commands.clone();
    state
        .manager
        .lock()
        .expect("connmgr mutex poisoned")
        .set_permit_waker(Box::new(move || {
            let _ = waker.send(Command::PermitGranted);
        }));

    // Start the persistent runners for the entries the binary added
    // (dcrd's persistentConnsHandler receiving the pre-run sends).
    for (id, addr) in cfg.persistent {
        state.persistent.insert(
            id,
            PersistState {
                addr,
                retry_count: 0,
                last_attempt_nanos: None,
            },
        );
        dial_persistent(&mut state, id);
    }

    // Fill the automatic outbound slots (dcrd targetOutboundHandler).
    fill_outbound(&mut state);

    loop {
        // A wake that came due is handled before the next command, so a
        // steady stream of commands cannot starve it.
        let command = match take_due_wake(&mut state) {
            Some(wake) => wake.command(),
            None => match state.timers.iter().map(|(at, _)| *at).min() {
                Some(at) => {
                    match receiver.recv_timeout(at.saturating_duration_since(Instant::now())) {
                        Ok(command) => command,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
                None => match receiver.recv() {
                    Ok(command) => command,
                    Err(_) => break,
                },
            },
        };
        match command {
            Command::Stop => {
                // dcrd Run()'s teardown: mark shutdown and remove
                // every persistent, pending, and active connection.
                let ids = {
                    let mut manager = state.manager.lock().expect("connmgr mutex poisoned");
                    manager.begin_shutdown();
                    manager.all_ids()
                };
                for conn_id in ids {
                    apply_remove(&mut state, conn_id);
                }
                break;
            }
            Command::PeerDone(id) => {
                state.sockets.remove(&id);
                let record = state
                    .manager
                    .lock()
                    .expect("connmgr mutex poisoned")
                    .conn_closed(id);
                if let Some(record) = record
                    && record.close_plan.signal_persistent.is_some()
                {
                    handle_persistent_drop(&mut state, id);
                } else {
                    fill_outbound(&mut state);
                }
            }
            Command::RetryFire(id) => dial_persistent(&mut state, id),
            Command::NewConnFire => {
                state.pause_armed = false;
                state.resume_after_pause = true;
                fill_outbound(&mut state);
            }
            Command::PermitGranted => fill_outbound(&mut state),
            Command::DialDone(id, kind, outcome) => {
                handle_dial_done(&mut state, id, kind, outcome);
            }
            Command::RpcConnect {
                resolved,
                permanent,
                reply,
            } => {
                // Permanent adds and gate failures reply here; a
                // manual dial's reply resolves with its outcome.
                if let Some(result) = rpc_connect(&mut state, resolved, permanent, reply.clone()) {
                    let _ = reply.send(result);
                }
            }
            Command::RpcRemove(id) => {
                apply_remove(&mut state, id);
            }
            Command::RpcRemoveIfPersistent { id, reply } => {
                let is_persistent = state
                    .manager
                    .lock()
                    .expect("connmgr mutex poisoned")
                    .is_persistent(id);
                if is_persistent {
                    apply_remove(&mut state, id);
                }
                let _ = reply.send(is_persistent);
            }
            Command::RpcRemovePersistentByAddr { addr, reply } => {
                let id = state
                    .manager
                    .lock()
                    .expect("connmgr mutex poisoned")
                    .find_persistent_addr_id_by_key(&addr);
                let result = match id {
                    Some(id) => {
                        apply_remove(&mut state, id);
                        Ok(())
                    }
                    None => Err("peer not found".to_string()),
                };
                let _ = reply.send(result);
            }
        }
    }
}

/// Remove and return the earliest armed wake whose deadline has passed.
fn take_due_wake(state: &mut LoopState) -> Option<Wake> {
    let now = Instant::now();
    let index = state
        .timers
        .iter()
        .enumerate()
        .filter(|(_, (at, _))| *at <= now)
        .min_by_key(|(_, (at, _))| *at)
        .map(|(index, _)| index)?;
    Some(state.timers.remove(index).1)
}

/// dcrd `rpcConnManager.Connect`: a persistent add or a manual dial,
/// surfacing the connection manager's raw gate errors.
fn rpc_connect(
    state: &mut LoopState,
    resolved: Result<NetAddress, String>,
    permanent: bool,
    reply: mpsc::Sender<Result<(), String>>,
) -> Option<Result<(), String>> {
    let addr = match resolved {
        Ok(addr) => addr,
        Err(e) => return Some(Err(e)),
    };
    if permanent {
        let added = {
            let mut manager = state.manager.lock().expect("connmgr mutex poisoned");
            manager
                .persistent_capacity_check()
                .and_then(|()| manager.add_persistent(&addr))
                .map_err(|e| e.description)
        };
        let id = match added {
            Ok(id) => id,
            Err(e) => return Some(Err(e)),
        };
        state.persistent.insert(
            id,
            PersistState {
                addr,
                retry_count: 0,
                last_attempt_nanos: None,
            },
        );
        dial_persistent(state, id);
        return Some(Ok(()));
    }

    // dcrd `Connect`: host permit, total permit, group registration,
    // then the dial; the reply resolves with the dial outcome.
    let gated = {
        let mut manager = state.manager.lock().expect("connmgr mutex poisoned");
        match manager.connect_begin(&addr) {
            Err(e) => Err(e.description),
            Ok(plan) => match manager.begin_dial(&addr, None) {
                Ok(id) => Ok((id, plan)),
                Err(e) => {
                    manager.connect_unwind(&addr, &plan);
                    Err(e.description)
                }
            },
        }
    };
    let (id, plan) = match gated {
        Ok(pair) => pair,
        Err(e) => return Some(Err(e)),
    };
    spawn_dial(
        state,
        id,
        addr.clone(),
        DialKind::Manual { addr, plan, reply },
    );
    None
}

/// Execute a `Remove` against the core and force the socket closed
/// when the action calls for it.
fn apply_remove(state: &mut LoopState, id: u64) {
    let action = state
        .manager
        .lock()
        .expect("connmgr mutex poisoned")
        .remove(id);
    let Ok(action) = action else {
        return;
    };
    match action {
        DisconnectAction::CloseRemoved(record)
        | DisconnectAction::CancelPersistentAndClose(record) => {
            if let Some(socket) = state.sockets.remove(&id) {
                socket.close();
            }
            state
                .manager
                .lock()
                .expect("connmgr mutex poisoned")
                .run_close_plan(&record);
            state.persistent.remove(&id);
            // The serve thread ends on the closed socket and reports
            // PeerDone, whose conn_closed finds nothing — the plan
            // already ran here.
        }
        DisconnectAction::CancelPending | DisconnectAction::CancelPersistentAndPending => {
            // The in-flight dialer thread's late success is dropped
            // by dial_succeeded returning None.
            state.persistent.remove(&id);
        }
        DisconnectAction::CancelPersistent => {
            state.persistent.remove(&id);
        }
        DisconnectAction::None | DisconnectAction::CloseConn => {}
    }
}

/// dcrd `runPersistent`'s dial arm: stamp the attempt, reserve the
/// per-host permit, and dial with the entry's stable ID.
fn dial_persistent(state: &mut LoopState, id: u64) {
    let still_persistent = state
        .manager
        .lock()
        .expect("connmgr mutex poisoned")
        .is_persistent(id);
    if !still_persistent {
        state.persistent.remove(&id);
        return;
    }
    let Some(entry) = state.persistent.get_mut(&id) else {
        return;
    };
    entry.last_attempt_nanos = Some(now_nanos());
    let addr = entry.addr.clone();

    let dial_id = {
        let mut manager = state.manager.lock().expect("connmgr mutex poisoned");
        match manager.maybe_reserve_host_permit(&addr) {
            Err(_) => None,
            Ok(host_permit_reserved) => match manager.begin_dial(&addr, Some(id)) {
                Ok(dial_id) => Some((dial_id, host_permit_reserved)),
                Err(_) => {
                    if host_permit_reserved {
                        manager.release_host_permit(&addr);
                    }
                    None
                }
            },
        }
    };
    match dial_id {
        Some((dial_id, host_permit_reserved)) => {
            spawn_dial(
                state,
                dial_id,
                addr.clone(),
                DialKind::Persistent {
                    addr,
                    host_permit_reserved,
                },
            );
        }
        // The permit or gate failure counts as a failed attempt; the
        // backoff path schedules the retry (dcrd's attempt() signaling
        // disconnected).
        None => handle_persistent_drop(state, id),
    }
}

/// dcrd `runPersistent`'s disconnected arm: back off with jitter when
/// the connection did not hold for a full retry interval, otherwise
/// redial immediately with the ladder reset.
fn handle_persistent_drop(state: &mut LoopState, id: u64) {
    let still_persistent = state
        .manager
        .lock()
        .expect("connmgr mutex poisoned")
        .is_persistent(id);
    if !still_persistent {
        state.persistent.remove(&id);
        return;
    }
    let Some(entry) = state.persistent.get_mut(&id) else {
        return;
    };
    let (should_backoff, delay) = {
        let manager = state.manager.lock().expect("connmgr mutex poisoned");
        let should = manager.persistent_should_backoff(entry.last_attempt_nanos, now_nanos());
        if should {
            entry.retry_count = entry.retry_count.saturating_add(1);
            (
                true,
                manager.backoff_with_jitter(entry.retry_count, &mut state.csprng),
            )
        } else {
            entry.retry_count = 0;
            (false, 0)
        }
    };
    if should_backoff {
        arm_wake(state, delay, Wake::Retry(id));
    } else {
        dial_persistent(state, id);
    }
}

/// dcrd `targetOutboundHandler`'s fill loop: acquire permits, pick an
/// address, and dial — pausing for the retry duration after too many
/// failed attempts.
fn fill_outbound(state: &mut LoopState) {
    if state.get_new_address.is_none() {
        return;
    }
    loop {
        let permits = {
            let mut manager = state.manager.lock().expect("connmgr mutex poisoned");
            // dcrd's handler, holding an outbound permit, blocks in
            // `totalNormalConnsSem.Acquire`.  The fill parks as that
            // semaphore's waiter instead, and the release that frees a
            // permit hands it over directly, ahead of any inbound or
            // manual connection, and wakes the driver
            // (`Command::PermitGranted`).  Nothing to do while parked;
            // once granted, the fill resumes where dcrd's handler
            // returns from the acquire, past the failed-attempt pause.
            if manager.total_normal_conns_sem.is_waiting() {
                return;
            }
            let granted = manager.total_normal_conns_sem.take_grant();

            // Pause automatic dialing after too many failed attempts,
            // then fall through to one more attempt per pause cycle
            // (dcrd's handler sleeping RetryDuration in line before
            // continuing).
            if !granted && state.failed_attempts >= MAX_FAILED_ATTEMPTS && !state.resume_after_pause
            {
                drop(manager);
                arm_fill_wake(state);
                return;
            }
            state.resume_after_pause = false;

            if granted {
                AutoPermits::Held
            } else {
                manager.auto_outbound_acquire()
            }
        };
        match permits {
            AutoPermits::Held => {}
            // Every outbound permit comes back through an automatic
            // dial's own failure or close, which re-runs the fill; the
            // retry-interval poll is a backstop.
            AutoPermits::Exhausted => {
                arm_fill_wake(state);
                return;
            }
            // Parked, keeping the outbound permit as dcrd's handler does
            // while blocked on the second acquire.
            AutoPermits::Parked => return,
        }

        // Both permits are held.  The pick draws its candidates without
        // the manager lock (see `pick_outbound_addr`); the host permit and
        // the dial registration that follow take it again, and unwind
        // their own failures in the core.
        let pick = pick_outbound_addr(state);
        let begun = state
            .manager
            .lock()
            .expect("connmgr mutex poisoned")
            .auto_outbound_reserve(pick);

        match begun {
            // Not an outcome of the reservation phase; handled as the
            // permit poll would be.
            AutoBegin::PermitsExhausted => {
                arm_fill_wake(state);
                return;
            }
            AutoBegin::Failed => {
                state.failed_attempts = state.failed_attempts.saturating_add(1);
            }
            AutoBegin::Dial {
                id,
                addr,
                host_permit_reserved,
            } => {
                // dcrd's handler spawns the dial goroutine and loops
                // immediately, so cold start fires the whole target
                // concurrently.
                spawn_dial(
                    state,
                    id,
                    addr.clone(),
                    DialKind::Auto {
                        addr,
                        host_permit_reserved,
                    },
                );
            }
        }
    }
}

/// dcrd `pickOutboundAddr` over the driver's address source: each
/// candidate is drawn with the connection manager's lock released and
/// then judged under it ([`ConnManager::claim_outbound_candidate`]).
///
/// The source takes the address manager's lock, which is also held
/// across peers.json saves and address processing.  dcrd's pick holds
/// only the outbound groups' own mutex while it calls the source, so
/// its inbound admission never waits on the address manager; drawing
/// under the one connection manager lock made every inbound accept
/// wait behind the address manager instead.
fn pick_outbound_addr(state: &mut LoopState) -> Result<NetAddress, String> {
    let source = state
        .get_new_address
        .as_mut()
        .ok_or_else(|| NO_SUITABLE_ADDR_MSG.to_string())?;
    for tries in 0..PICK_OUTBOUND_RETRIES {
        let (addr, last_try_nanos) = source()?;
        let claimed = state
            .manager
            .lock()
            .expect("connmgr mutex poisoned")
            .claim_outbound_candidate(tries, &addr, last_try_nanos, now_nanos());
        if claimed {
            return Ok(addr);
        }
    }
    Err(NO_SUITABLE_ADDR_MSG.to_string())
}

/// Arm a single wake timer for the fill loop (the failed-attempt
/// pause and the permit poll share it).
fn arm_fill_wake(state: &mut LoopState) {
    if state.pause_armed {
        return;
    }
    state.pause_armed = true;
    let retry = state
        .manager
        .lock()
        .expect("connmgr mutex poisoned")
        .retry_duration_nanos();
    arm_wake(state, retry, Wake::NewConn);
}

/// Process a dial outcome: register success with the core and serve
/// the peer, or unwind the reservations and count the failure.
fn handle_dial_done(
    state: &mut LoopState,
    id: u64,
    kind: DialKind,
    outcome: Result<DialedConn, String>,
) {
    let (addr, conn_type, plan, is_auto, persistent_id, reply) = match kind {
        DialKind::Auto {
            addr,
            host_permit_reserved,
        } => (
            addr,
            ConnectionType::Outbound,
            ClosePlan::auto_outbound(host_permit_reserved),
            true,
            None,
            None,
        ),
        DialKind::Manual { addr, plan, reply } => {
            (addr, ConnectionType::Manual, plan, false, None, Some(reply))
        }
        DialKind::Persistent {
            addr,
            host_permit_reserved,
        } => (
            addr,
            ConnectionType::Manual,
            ClosePlan {
                remove_outbound_group: false,
                release_total_sem: false,
                release_outbound_sem: false,
                release_host_permit: host_permit_reserved,
                signal_persistent: Some(id),
            },
            false,
            Some(id),
            None,
        ),
    };

    match outcome {
        Err(e) => {
            let mut manager = state.manager.lock().expect("connmgr mutex poisoned");
            manager.dial_failed(id);
            // Run the reservations' unwind (dcrd's deferred onClose on
            // the failure path).
            let record = dcroxide_connmgr::manager::ConnRecord {
                id,
                conn_type,
                remote_addr: addr,
                close_plan: plan,
            };
            manager.run_close_plan(&record);
            drop(manager);
            if let Some(reply) = reply {
                let _ = reply.send(Err(e));
            }
            if let Some(pid) = persistent_id {
                handle_persistent_drop(state, pid);
            } else if is_auto {
                state.failed_attempts = state.failed_attempts.saturating_add(1);
                fill_outbound(state);
            }
        }
        Ok(conn) => {
            let registered = state
                .manager
                .lock()
                .expect("connmgr mutex poisoned")
                .dial_succeeded(id, &addr, conn_type, plan.clone());
            let Some(record) = registered else {
                // Canceled while dialing: close the socket and run the
                // reservations' unwind — dcrd returns context.Canceled
                // before setting skipOnClose, so the deferred onClose
                // releases everything the dial had reserved.
                conn.close();
                {
                    let mut manager = state.manager.lock().expect("connmgr mutex poisoned");
                    let record = dcroxide_connmgr::manager::ConnRecord {
                        id,
                        conn_type,
                        remote_addr: addr,
                        close_plan: plan,
                    };
                    manager.run_close_plan(&record);
                }
                if let Some(reply) = reply {
                    let _ = reply.send(Err(dcroxide_rpc::server::CONNECT_CANCELED.to_string()));
                }
                if let Some(pid) = persistent_id {
                    handle_persistent_drop(state, pid);
                } else if is_auto {
                    // dcrd's dial goroutine counts the canceled
                    // outcome as a failed attempt.
                    state.failed_attempts = state.failed_attempts.saturating_add(1);
                    fill_outbound(state);
                }
                return;
            };
            if is_auto {
                state.failed_attempts = 0;
            }
            if let Some(reply) = reply {
                let _ = reply.send(Ok(()));
            }
            let stream = conn.stream.lock().expect("dial stream poisoned").take();
            match stream {
                Some(stream) => {
                    state.sockets.insert(id, conn);
                    let serve = Arc::clone(&state.serve);
                    let commands = state.commands.clone();
                    let permanent = persistent_id.is_some();
                    // Any address the manager dialed is served, a Tor
                    // onion key included (dcrd `outboundPeerConnected`
                    // takes the connection's `*addrmgr.NetAddress`).
                    let remote_addr = record.remote_addr.clone();
                    let spawned = crate::runtime::spawn_conn_thread("peer-outbound", move || {
                        serve_outbound_peer(
                            stream,
                            &remote_addr,
                            &serve.template,
                            &serve.connected,
                            serve.server.clone(),
                            permanent,
                            Some(id),
                        );
                        let _ = commands.send(Command::PeerDone(id));
                    });
                    if let Err(e) = spawned {
                        // A connection that ends at once: close the
                        // socket, and let the ordinary peer-done path
                        // run its close plan and redial.
                        crate::logging::warn(
                            "CMGR",
                            &format!(
                                "Unable to start a thread for outbound peer {}: \
                                 {e} -- disconnecting",
                                record.remote_addr.key()
                            ),
                        );
                        if let Some(conn) = state.sockets.get(&id) {
                            conn.close();
                        }
                        let _ = state.commands.send(Command::PeerDone(id));
                    }
                }
                None => {
                    // The dialed stream was already handed off, which a
                    // fresh dial never is; tear the connection down
                    // instead of holding its permits forever.
                    conn.close();
                    state
                        .manager
                        .lock()
                        .expect("connmgr mutex poisoned")
                        .conn_closed(id);
                    if let Some(pid) = persistent_id {
                        handle_persistent_drop(state, pid);
                    } else if is_auto {
                        state.failed_attempts = state.failed_attempts.saturating_add(1);
                    }
                }
            }
            if is_auto {
                fill_outbound(state);
            }
        }
    }
}

/// dcrd `attemptDcrdDial`'s address bookkeeping: make sure the
/// address exists in the address manager and mark it attempted before
/// the actual dial.
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
    let now_unix = now_unix();
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

/// Owe the event loop `wake` once `delay_nanos` has passed (dcrd arms a
/// timer for the same schedule).  A delay too long to represent never
/// comes due.
fn arm_wake(state: &mut LoopState, delay_nanos: i64, wake: Wake) {
    let delay = Duration::from_nanos(delay_nanos.max(0) as u64);
    if let Some(at) = Instant::now().checked_add(delay) {
        state.timers.push((at, wake));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A driver state with no server, no address source and a fresh
    /// connection manager, plus the receiving end of its command
    /// channel.
    fn loop_state() -> (LoopState, mpsc::Receiver<Command>) {
        let mut csprng = SystemCsprng::default();
        let manager = Arc::new(Mutex::new(ConnManager::new(
            dcroxide_connmgr::ManagerConfig::default(),
            &mut csprng,
        )));
        let (commands, receiver) = mpsc::channel();
        let state = LoopState {
            manager,
            serve: Arc::new(ServeState {
                template: PeerTemplate {
                    net: dcroxide_wire::CurrencyNet::TEST_NET3,
                    protocol_version: 0,
                    services: dcroxide_wire::ServiceFlag(1),
                    user_agent_name: "dcroxide".to_string(),
                    user_agent_version: "0.1.0".to_string(),
                    idle_timeout: Duration::from_secs(3600),
                    ping_interval: Duration::from_secs(3600),
                    disable_relay_tx: false,
                    proxy: String::new(),
                    newest_block: None,
                },
                connected: ConnectedPeers::new(),
                server: None,
                dial_timeout: Duration::from_secs(1),
                dialer: crate::socks::NodeDialer::direct(),
                addr_manager: None,
            }),
            commands,
            csprng,
            get_new_address: None,
            failed_attempts: 0,
            pause_armed: false,
            resume_after_pause: false,
            persistent: HashMap::new(),
            sockets: HashMap::new(),
            timers: Vec::new(),
        };
        (state, receiver)
    }

    /// The fill loop's wake is a deadline the event loop keeps, not a
    /// thread: with every outbound slot held it re-arms each retry
    /// interval for as long as the node runs, which used to start and
    /// retire a sleeping OS thread every five seconds.  It is armed
    /// once, and comes due as the `NewConnFire` the timer thread sent.
    #[test]
    fn the_fill_wake_is_a_deadline_the_event_loop_keeps() {
        let (mut state, _receiver) = loop_state();
        arm_fill_wake(&mut state);
        arm_fill_wake(&mut state);
        assert_eq!(state.timers.len(), 1, "one wake, never stacked");
        assert_eq!(state.timers[0].1, Wake::NewConn);
        assert!(state.pause_armed);

        // Not due yet: nothing fires.
        assert_eq!(take_due_wake(&mut state), None);
        assert_eq!(state.timers.len(), 1);

        // Due: it fires once, as the command the timer thread sent.
        state.timers[0].0 = Instant::now();
        let wake = take_due_wake(&mut state);
        assert_eq!(wake, Some(Wake::NewConn));
        assert!(matches!(
            wake.map(Wake::command),
            Some(Command::NewConnFire)
        ));
        assert!(state.timers.is_empty());
    }

    /// A persistent entry's backoff is a wake too, due after the delay.
    #[test]
    fn a_retry_backoff_is_a_wake_due_after_its_delay() {
        let (mut state, _receiver) = loop_state();
        let before = Instant::now();
        arm_wake(&mut state, 250_000_000, Wake::Retry(9));
        assert_eq!(state.timers.len(), 1);
        let (at, wake) = state.timers[0];
        assert_eq!(wake, Wake::Retry(9));
        assert!(at >= before + Duration::from_millis(250));
    }

    /// A dialer thread the OS refuses reports the dial as failed, with
    /// its kind, so the ordinary outcome path releases its reservations
    /// — instead of panicking the event loop, which aborted a release
    /// build.
    #[test]
    fn a_refused_dial_thread_reports_a_failed_dial() {
        let (state, receiver) = loop_state();
        let addr = socket_addr_to_net_address(&"127.0.0.1:9".parse().expect("addr"));
        crate::runtime::REFUSE_CONN_THREADS.with(|refuse| refuse.set(true));
        spawn_dial(
            &state,
            7,
            addr.clone(),
            DialKind::Auto {
                addr,
                host_permit_reserved: false,
            },
        );
        crate::runtime::REFUSE_CONN_THREADS.with(|refuse| refuse.set(false));
        match receiver.recv_timeout(Duration::from_secs(5)) {
            Ok(Command::DialDone(7, DialKind::Auto { .. }, Err(e))) => {
                assert!(
                    e.starts_with("dial failed: unable to start a thread"),
                    "the dial must fail for want of a thread, not be attempted: {e}"
                );
            }
            Ok(_) => panic!("expected the failed dial's outcome"),
            Err(e) => panic!("no outcome reported: {e}"),
        }
    }

    /// Closing a dialed entry raises the flag the serve thread will
    /// poll, across the take-once handoff.
    ///
    /// The handoff is the only place the driver's control handle and
    /// the serve thread's connection could have drifted apart, which is
    /// what holding a bare socket here used to do: `close` shut the
    /// socket and left the flag alone. Cannot pin that `apply_remove`
    /// is reached in a real driver run, nor the Windows behaviour.
    #[test]
    fn closing_a_dialed_entry_raises_the_flag_the_serve_thread_will_poll() {
        use std::io::Read as _;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let bound = listener.local_addr().expect("addr");
        let peer_end = std::net::TcpStream::connect(bound).expect("connect");
        let (server, _) = listener.accept().expect("accept");

        // Built the way `dial` builds one.
        let dialed = crate::transport::Teardown::new(server);
        let shutdown = dialed.try_clone().expect("clone");
        let conn = DialedConn {
            stream: Arc::new(Mutex::new(Some(dialed))),
            shutdown,
        };

        // The handle the serve thread receives, taken as
        // `handle_dial_done` takes it.
        let handed = conn
            .stream
            .lock()
            .expect("dialed stream mutex poisoned")
            .take()
            .expect("the dialed stream is taken once");
        let flag = handed.cancel();
        assert!(
            !flag.is_cancelled(),
            "neither construction nor the handoff may raise it"
        );

        conn.close();

        assert!(
            flag.is_cancelled(),
            "the driver's close must raise the flag the serve thread polls"
        );
        let mut buf = [0u8; 1];
        assert_eq!(
            (&peer_end).read(&mut buf).expect("read"),
            0,
            "the FIN must still go out"
        );
    }

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

    /// A valid Tor v3 onion host (public key 0x00..0x1f, the addrmgr v2
    /// vectors' first `onionkey` row).
    const ONION: &str = "aaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dyp3kead.onion";

    /// A one-shot fake Tor SOCKS resolver: answers the RESOLVE request
    /// with `ip` and reports the host it was asked to resolve.
    fn fake_tor_resolver(ip: [u8; 4]) -> (String, mpsc::Receiver<String>) {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind resolver");
        let addr = listener.local_addr().expect("addr").to_string();
        let (asked, asked_rx) = mpsc::channel();
        thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            conn.set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            let mut greeting = [0u8; 3];
            conn.read_exact(&mut greeting).expect("greeting");
            conn.write_all(&[5, 0]).expect("auth choice");
            let mut head = [0u8; 5];
            conn.read_exact(&mut head).expect("request head");
            assert_eq!(head[1], 0xf0, "Tor's RESOLVE command");
            let mut host = vec![0u8; usize::from(head[4])];
            conn.read_exact(&mut host).expect("host");
            let mut port = [0u8; 2];
            conn.read_exact(&mut port).expect("port");
            let _ = asked.send(String::from_utf8_lossy(&host).into_owned());
            conn.write_all(&[5, 0, 0, 1]).expect("reply head");
            let mut payload = ip.to_vec();
            payload.extend_from_slice(&[0, 0]);
            conn.write_all(&payload).expect("address");
        });
        (addr, asked_rx)
    }

    /// The routing of `--proxy=<proxy>` without `--noonion`: dials
    /// through the proxy and lookups through Tor's RESOLVE.
    fn tor_dialer(proxy: &str) -> crate::socks::NodeDialer {
        let mut cfg = crate::config::Config::defaults("/tmp/dcroxide-review-home");
        cfg.proxy = proxy.to_string();
        cfg.dial = crate::config::DialSelection::SocksProxy;
        cfg.lookup = crate::config::LookupSelection::TorViaProxy;
        crate::socks::NodeDialer::from_config(&cfg)
    }

    /// dcrd resolves the `addnode`, `node connect`, `--connect` and
    /// `--addpeer` hosts through `dcrdLookup`, which under `--proxy`
    /// without `--noonion` is a Tor RESOLVE through the proxy, IP
    /// literals included.  The port resolved them through the system
    /// resolver whatever the routing, so a node routed through Tor sent
    /// its peers' names out as clear DNS queries from its own address.
    /// A `.invalid` name never resolves through a real resolver, so
    /// only the proxy can have answered.
    #[test]
    fn connect_targets_resolve_through_the_tor_proxy() {
        let (proxy, asked) = fake_tor_resolver([192, 0, 2, 7]);
        let addr = addr_string_to_net_address("peer.dcroxide.invalid:9108", &tor_dialer(&proxy))
            .expect("the proxy resolves the name");
        assert_eq!(addr.key(), "192.0.2.7:9108");
        assert_eq!(
            asked.recv_timeout(Duration::from_secs(5)).as_deref(),
            Ok("peer.dcroxide.invalid")
        );

        // dcrd's lookup does not special-case a literal either.
        let (proxy, asked) = fake_tor_resolver([192, 0, 2, 9]);
        let addr = addr_string_to_net_address("192.0.2.9:9108", &tor_dialer(&proxy))
            .expect("the proxy resolves the literal");
        assert_eq!(addr.key(), "192.0.2.9:9108");
        assert_eq!(
            asked.recv_timeout(Duration::from_secs(5)).as_deref(),
            Ok("192.0.2.9")
        );

        // The RPC control handle resolves with its channel's routing.
        let (proxy, asked) = fake_tor_resolver([192, 0, 2, 8]);
        let channel = outbound_channel_with_dialer(tor_dialer(&proxy));
        let control = channel.control();
        let caller = thread::spawn(move || control.connect("peer.dcroxide.invalid:9108", true));
        match channel.receiver.recv_timeout(Duration::from_secs(5)) {
            Ok(Command::RpcConnect {
                resolved,
                permanent,
                reply,
            }) => {
                assert!(permanent);
                assert_eq!(
                    resolved.map(|addr| addr.key()),
                    Ok("192.0.2.8:9108".to_string())
                );
                let _ = reply.send(Ok(()));
            }
            _ => panic!("expected the connect command"),
        }
        assert_eq!(caller.join().expect("the caller"), Ok(()));
        assert_eq!(
            asked.recv_timeout(Duration::from_secs(5)).as_deref(),
            Ok("peer.dcroxide.invalid")
        );
    }

    /// dcrd's `addrStringToNetAddr` returns a Tor v3 host unresolved
    /// (`simpleAddr`), whatever the routing, and the connection manager
    /// turns it into an onion address.  The port refused every `.onion`
    /// host with "tor has been disabled", so `--addpeer=<v3>.onion`
    /// stopped the daemon at startup and `addnode` failed.
    #[test]
    fn a_tor_v3_target_is_kept_unresolved() {
        // Every lookup through this routing fails (nothing listens on
        // the proxy port), so a result can only come from skipping it.
        let refusing = tor_dialer("127.0.0.1:1");
        let target = format!("{ONION}:9108");
        let addr = addr_string_to_net_address(&target, &refusing).expect("onion target");
        assert_eq!(addr.addr_type, dcroxide_addrmgr::NetAddressType::TorV3);
        assert_eq!(addr.key(), target);
        assert_eq!(
            addr_string_to_net_address(&target, &crate::socks::NodeDialer::direct())
                .map(|addr| addr.key()),
            Ok(target.clone())
        );

        // The port is checked the way `stdlibNetAddrToAddrMgrNetAddr`
        // checks it.
        assert_eq!(
            addr_string_to_net_address(&format!("{ONION}:65536"), &refusing),
            Err(format!("invalid port for address \"{ONION}:65536\""))
        );

        // A `.onion` name that is not a v3 address takes the onion
        // lookup like any other host, which --noonion fails (and which
        // otherwise never reaches DNS, see
        // `a_non_v3_onion_name_never_reaches_dns`).
        let mut cfg = crate::config::Config::defaults("/tmp/dcroxide-review-home");
        cfg.onion = crate::config::OnionSelection::Disabled;
        assert_eq!(
            addr_string_to_net_address(
                "abcdef.onion:9108",
                &crate::socks::NodeDialer::from_config(&cfg)
            ),
            Err("tor has been disabled".to_string())
        );
    }

    /// Go's `strconv.ParseUint(s, 10, 16)` texts for a bad port, the
    /// overflow reported before a later non-digit.
    #[test]
    fn a_bad_port_fails_with_go_texts() {
        let direct = crate::socks::NodeDialer::direct();
        assert_eq!(
            addr_string_to_net_address("127.0.0.1:65536", &direct),
            Err("strconv.ParseUint: parsing \"65536\": value out of range".to_string())
        );
        assert_eq!(
            addr_string_to_net_address("127.0.0.1:9x", &direct),
            Err("strconv.ParseUint: parsing \"9x\": invalid syntax".to_string())
        );
        assert_eq!(
            go_parse_uint16("99999x"),
            Err("strconv.ParseUint: parsing \"99999x\": value out of range".to_string())
        );
        assert_eq!(go_parse_uint16("65535"), Ok(65535));
    }

    /// A `.onion` name that is not a v3 address resolves through the
    /// lookup like any other host, and without a proxy that is dcrd's
    /// `net.LookupIP`, whose resolver sends no DNS query for it (RFC
    /// 7686): no addresses, so "no addresses found".  The port handed
    /// it to the system resolver, which queried DNS for the onion name
    /// (`addnode foo.onion add`, a mistyped v3 name, `--addpeer`).  Any
    /// answer the system resolver gives, a failure included, differs
    /// from the empty one.
    #[test]
    fn a_non_v3_onion_name_never_reaches_dns() {
        let direct = crate::socks::NodeDialer::direct();
        assert_eq!(
            addr_string_to_net_address("abcdefghijklmnop.onion:9108", &direct),
            Err("no addresses found for abcdefghijklmnop.onion".to_string())
        );
        // Go matches the suffix without regard to case and ignores one
        // trailing dot; dcrd's own `.onion` routing is case-sensitive,
        // so these take the ordinary lookup.
        for host in ["FOO.ONION", "foo.Onion", "foo.onion."] {
            assert_eq!(
                direct.lookup(host, Duration::from_secs(1)),
                Ok(Vec::new()),
                "{host}"
            );
        }
    }

    /// A failed dial reports the dialer's own error, which dcrd's
    /// `Connect` returns as it is and `node connect`/`addnode` put on
    /// the wire: Go's `dial tcp <addr>: connect: <errno text>` for a
    /// refused connect, direct or to the SOCKS proxy (go-socks returns
    /// its proxy dial's error raw), and "tor has been disabled" for an
    /// onion target under --noonion.  The port prefixed "dial failed: "
    /// to std's "Connection refused (os error 111)".
    #[test]
    fn a_failed_dial_reports_the_dialers_own_text() {
        let dead = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let dead_addr = dead.local_addr().expect("addr").to_string();
        drop(dead);
        let failure = |target: &str, dialer: &crate::socks::NodeDialer| match dial(
            target,
            Duration::from_secs(10),
            dialer,
            None,
        ) {
            Ok(_) => panic!("the dial to {target} cannot succeed"),
            Err(e) => e,
        };

        let direct = failure(&dead_addr, &crate::socks::NodeDialer::direct());
        let proxied = failure("192.0.2.1:9108", &tor_dialer(&dead_addr));
        for err in [&direct, &proxied] {
            assert!(!err.starts_with("dial failed"), "{err}");
            if cfg!(unix) {
                assert_eq!(
                    *err,
                    format!("dial tcp {dead_addr}: connect: connection refused")
                );
            }
        }

        let mut cfg = crate::config::Config::defaults("/tmp/dcroxide-review-home");
        cfg.onion = crate::config::OnionSelection::Disabled;
        assert_eq!(
            failure(
                &format!("{ONION}:9108"),
                &crate::socks::NodeDialer::from_config(&cfg)
            ),
            "tor has been disabled"
        );
    }

    /// A dialed onion peer is served like any other.  The driver parsed
    /// the peer's key as a socket address, which an onion key does not
    /// have, so every onion dial (a whole Tor circuit) was closed the
    /// moment it connected and counted as a failed attempt.  dcrd's
    /// `outboundPeerConnected` serves whatever `*addrmgr.NetAddress`
    /// the connection carries.
    #[test]
    fn a_dialed_onion_peer_is_served() {
        let (mut state, receiver) = loop_state();
        let (addr_type, key) = dcroxide_addrmgr::encode_host(ONION);
        let addr = dcroxide_addrmgr::new_net_address_from_params(
            addr_type,
            &key,
            9108,
            0,
            dcroxide_wire::ServiceFlag(0),
        )
        .expect("onion address");
        let (id, plan) = {
            let mut manager = state.manager.lock().expect("connmgr");
            let plan = manager.connect_begin(&addr).expect("gate");
            (manager.begin_dial(&addr, None).expect("dial"), plan)
        };

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let peer_end =
            std::net::TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
        let (dialed, _) = listener.accept().expect("accept");
        let dialed = crate::transport::Teardown::new(dialed);
        let shutdown = dialed.try_clone().expect("clone");
        let conn = DialedConn {
            stream: Arc::new(Mutex::new(Some(dialed))),
            shutdown,
        };

        let (reply, replied) = mpsc::channel();
        handle_dial_done(
            &mut state,
            id,
            DialKind::Manual { addr, plan, reply },
            Ok(conn),
        );
        assert_eq!(replied.recv_timeout(Duration::from_secs(5)), Ok(Ok(())));
        assert!(
            state.sockets.contains_key(&id),
            "the connection must be kept for its serving thread"
        );
        assert!(
            state
                .manager
                .lock()
                .expect("connmgr")
                .active_conn(id)
                .is_some(),
            "the connection must stay active rather than be closed"
        );

        // The serving thread runs the peer until the remote goes away.
        drop(peer_end);
        match receiver.recv_timeout(Duration::from_secs(10)) {
            Ok(Command::PeerDone(done)) => assert_eq!(done, id),
            _ => panic!("the served peer must finish through PeerDone"),
        }
    }

    /// dcrd dials under `context.WithTimeout`, and Go reports a TCP
    /// connect the deadline cut short as `context.DeadlineExceeded`,
    /// which the RPC connect handlers answer with their timeout error.
    /// The port flattened it into "dial failed: connection timed out",
    /// an internal error.  An OS-level `ETIMEDOUT` and a SOCKS handshake
    /// timeout are not that error in dcrd and keep their text.
    #[test]
    fn a_connect_cut_short_by_the_dial_timeout_is_the_deadline_error() {
        assert_eq!(
            dial_failure(CONNECT_TIMED_OUT.to_string()),
            dcroxide_rpc::server::CONNECT_DEADLINE_EXCEEDED
        );
        assert_eq!(
            dial_failure("dial tcp 192.0.2.1:9108: connect: connection timed out".to_string()),
            "dial tcp 192.0.2.1:9108: connect: connection timed out"
        );
        assert_eq!(dial_failure("i/o timeout".to_string()), "i/o timeout");

        // A one-try dial's reply carries it to the RPC handler.
        let (mut state, _receiver) = loop_state();
        let addr = socket_addr_to_net_address(&"192.0.2.1:9108".parse().expect("addr"));
        let (id, plan) = {
            let mut manager = state.manager.lock().expect("connmgr");
            let plan = manager.connect_begin(&addr).expect("gate");
            (manager.begin_dial(&addr, None).expect("dial"), plan)
        };
        let (reply, replied) = mpsc::channel();
        handle_dial_done(
            &mut state,
            id,
            DialKind::Manual { addr, plan, reply },
            Err(dial_failure(CONNECT_TIMED_OUT.to_string())),
        );
        assert_eq!(
            replied.recv_timeout(Duration::from_secs(5)),
            Ok(Err(
                dcroxide_rpc::server::CONNECT_DEADLINE_EXCEEDED.to_string()
            ))
        );
        let manager = state.manager.lock().expect("connmgr");
        assert_eq!(manager.total_normal_conns_sem.used(), 0);
    }
}
