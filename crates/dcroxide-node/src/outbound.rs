// SPDX-License-Identifier: ISC
//! The outbound connection driver — the daemon threads over the dcrd
//! 2.2 connection manager decision core (dcrd `internal/connmgr`'s
//! goroutines: `targetOutboundHandler`, the per-entry `runPersistent`
//! loops, and the dial goroutines, driven by `server.go`'s callbacks).
//!
//! The core is synchronous and shared behind a mutex; this driver
//! runs the loops dcrd runs as goroutines: an event thread processing
//! commands, per-dial dialer threads reporting outcomes back (so the
//! event thread never blocks on a dial), timer threads for retry
//! backoff and the failed-attempt pause, and the served-peer threads.
//! The automatic-outbound fill mirrors dcrd's `targetOutboundHandler`
//! — permits from the two semaphore counters, `pick_outbound_addr`
//! over the address source, the per-host permit, and up to
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
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use dcroxide_addrmgr::{AddrManager, NetAddress, new_net_address_from_ip_port};
use dcroxide_connmgr::manager::{ClosePlan, ConnManager, DisconnectAction, MAX_FAILED_ATTEMPTS};
use dcroxide_connmgr::{ConnectionType, SystemCsprng};

use crate::dispatch::ServerContext;
use crate::runtime::{ConnectedPeers, PeerTemplate, serve_outbound_peer};

/// The shared connection manager decision core (dcrd's `ConnManager`
/// reached from the server, the listener runtime, and this driver).
pub type SharedConnManager = Arc<Mutex<ConnManager>>;

/// The address source the automatic dialer draws from: dcrd
/// `Config.GetNewAddress`, returning the candidate and its last
/// attempt time in unix seconds.
pub type AddressSource = Box<dyn FnMut() -> Result<(NetAddress, i64), String> + Send>;

/// A dialed connection handle: the established stream for the serve
/// thread, and a shutdown clone so `Disconnect`/`Remove` can force
/// the socket closed (dcrd closing the `net.Conn`).
struct DialedConn {
    stream: Arc<Mutex<Option<TcpStream>>>,
    shutdown: TcpStream,
}

impl DialedConn {
    fn close(&self) {
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
    /// A persistent entry's backoff timer fired.
    RetryFire(u64),
    /// The failed-attempt pause (or an external nudge) elapsed;
    /// resume filling the outbound target.
    NewConnFire,
    /// A dial finished on its dialer thread.
    DialDone(u64, DialKind, Result<DialedConn, String>),
    /// dcrd `rpcConnManager.Connect`: resolved on the RPC thread,
    /// gated and dialed here; the reply carries the connection
    /// manager's raw error description.
    RpcConnect {
        resolved: Result<SocketAddr, String>,
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
}

/// The failure every control call reports once the driver has
/// stopped and the command channel is closed (dcrd's connmgr methods
/// after quit).
pub(crate) const STOPPED: &str = "connection manager stopped";

impl OutboundControl {
    /// Add the address as a new outbound peer, persistent or one-try
    /// (dcrd `rpcConnManager.Connect`): the address resolves on this
    /// thread — dcrd's `addrStringToNetAddr` on the RPC goroutine —
    /// and the connection manager's gate errors surface raw.
    pub fn connect(&self, addr: &str, permanent: bool) -> Result<(), String> {
        let (reply, result) = mpsc::channel();
        self.commands
            .send(Command::RpcConnect {
                resolved: addr_string_to_socket_addr(addr),
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

/// Resolve an address string to a socket address (dcrd
/// `addrStringToNetAddr`, in its order): the host and port split with
/// Go's `net.SplitHostPort` semantics, the host resolves first — an IP
/// literal directly, a `.onion` host refused while Tor is unwired, any
/// other host through the system resolver taking the first answer —
/// and the port parses last, so a bad host surfaces its lookup error
/// before a bad port like dcrd.  The one divergence: the port must fit
/// sixteen bits here (a socket address cannot hold more), where dcrd
/// carries any integer and only fails the eventual dial.
pub fn addr_string_to_socket_addr(addr: &str) -> Result<SocketAddr, String> {
    use std::net::ToSocketAddrs;
    let (host, port) = crate::gostd::split_host_port(addr)?;
    let ip = if let Ok(ip) = host.parse::<IpAddr>() {
        ip
    } else if host.ends_with(".onion") {
        return Err("tor has been disabled".to_string());
    } else {
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
    /// pause, or the permit poll standing in for dcrd's blocking
    /// semaphore acquire), so timers are not stacked.
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
}

/// Dial the address on a dialer thread, reporting the outcome back
/// (dcrd's dial goroutines over `Config.Dial`).
fn spawn_dial(state: &LoopState, id: u64, addr: NetAddress, kind: DialKind) {
    let serve = Arc::clone(&state.serve);
    let commands = state.commands.clone();
    thread::spawn(move || {
        let outcome = dial(
            &addr.key(),
            serve.dial_timeout,
            &serve.dialer,
            serve.addr_manager.as_ref(),
        );
        let _ = commands.send(Command::DialDone(id, kind, outcome));
    });
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
    let stream = dialer
        .dial(addr, timeout)
        .map_err(|e| format!("dial failed: {e}"))?;
    let shutdown = stream
        .try_clone()
        .map_err(|e| format!("dial clone failed: {e}"))?;
    Ok(DialedConn {
        stream: Arc::new(Mutex::new(Some(stream))),
        shutdown,
    })
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
    };

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

    while let Ok(command) = receiver.recv() {
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

/// dcrd `rpcConnManager.Connect`: a persistent add or a manual dial,
/// surfacing the connection manager's raw gate errors.
fn rpc_connect(
    state: &mut LoopState,
    resolved: Result<SocketAddr, String>,
    permanent: bool,
    reply: mpsc::Sender<Result<(), String>>,
) -> Option<Result<(), String>> {
    let resolved = match resolved {
        Ok(resolved) => resolved,
        Err(e) => return Some(Err(e)),
    };
    let addr = socket_addr_to_net_address(&resolved);
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
        spawn_timer(delay, state.commands.clone(), Command::RetryFire(id));
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
        // Pause automatic dialing after too many failed attempts, then
        // fall through to one more attempt per pause cycle (dcrd's
        // handler sleeping RetryDuration in line before continuing).
        if state.failed_attempts >= MAX_FAILED_ATTEMPTS && !state.resume_after_pause {
            arm_wake(state);
            return;
        }
        state.resume_after_pause = false;

        let mut permits_exhausted = false;
        let picked = {
            let mut manager = state.manager.lock().expect("connmgr mutex poisoned");
            // dcrd blocks in the semaphore acquires and wakes on any
            // release; the driver polls within a retry interval
            // instead, so a permit freed by an inbound close is
            // rediscovered.
            if !manager.active_outbounds_sem.try_acquire() {
                permits_exhausted = true;
                None
            } else if !manager.total_normal_conns_sem.try_acquire() {
                manager.active_outbounds_sem.release();
                permits_exhausted = true;
                None
            } else {
                let source = state.get_new_address.as_mut().expect("checked above");
                match manager.pick_outbound_addr(&mut || source(), now_nanos()) {
                    Err(_) => {
                        manager.total_normal_conns_sem.release();
                        manager.active_outbounds_sem.release();
                        None
                    }
                    Ok(addr) => match manager.maybe_reserve_host_permit(&addr) {
                        Err(_) => {
                            manager.outbound_groups.remove_addr(&addr);
                            manager.total_normal_conns_sem.release();
                            manager.active_outbounds_sem.release();
                            None
                        }
                        Ok(host_permit_reserved) => match manager.begin_dial(&addr, None) {
                            Ok(id) => Some((id, addr, host_permit_reserved)),
                            Err(_) => {
                                manager.outbound_groups.remove_addr(&addr);
                                if host_permit_reserved {
                                    manager.release_host_permit(&addr);
                                }
                                manager.total_normal_conns_sem.release();
                                manager.active_outbounds_sem.release();
                                None
                            }
                        },
                    },
                }
            }
        };
        if permits_exhausted {
            arm_wake(state);
            return;
        }

        match picked {
            None => {
                state.failed_attempts = state.failed_attempts.saturating_add(1);
            }
            Some((id, addr, host_permit_reserved)) => {
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

/// Arm a single wake timer for the fill loop (the failed-attempt
/// pause and the permit poll share it).
fn arm_wake(state: &mut LoopState) {
    if state.pause_armed {
        return;
    }
    state.pause_armed = true;
    let retry = state
        .manager
        .lock()
        .expect("connmgr mutex poisoned")
        .retry_duration_nanos();
    spawn_timer(retry, state.commands.clone(), Command::NewConnFire);
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
            ClosePlan {
                remove_outbound_group: true,
                release_total_sem: true,
                release_outbound_sem: true,
                release_host_permit: host_permit_reserved,
                signal_persistent: None,
            },
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
                    let _ = reply.send(Err("context canceled".to_string()));
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
            let socket_addr = record.remote_addr.key().parse::<SocketAddr>().ok();
            match (stream, socket_addr) {
                (Some(stream), Some(socket_addr)) => {
                    state.sockets.insert(id, conn);
                    let serve = Arc::clone(&state.serve);
                    let commands = state.commands.clone();
                    let permanent = persistent_id.is_some();
                    thread::spawn(move || {
                        serve_outbound_peer(
                            stream,
                            socket_addr,
                            &serve.template,
                            &serve.connected,
                            serve.server.clone(),
                            permanent,
                            Some(id),
                        );
                        let _ = commands.send(Command::PeerDone(id));
                    });
                }
                _ => {
                    // The peer runtime cannot serve this address form
                    // yet (a Tor onion key has no socket address), so
                    // tear the connection down instead of holding its
                    // permits forever.
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

/// Fire the command back to the event loop after the delay (dcrd arms
/// a timer for the same schedule).
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
