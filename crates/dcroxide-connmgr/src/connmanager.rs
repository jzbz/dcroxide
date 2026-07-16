// SPDX-License-Identifier: ISC
//! The connection manager (dcrd connmgr `connmanager.go`).
//!
//! dcrd runs a channel-driven handler goroutine, dials concurrently,
//! and fires retries through `time.After`; that is daemon-phase
//! concurrency.  The port is synchronous with identical state
//! transitions: dialing goes through a caller-provided closure,
//! callback invocations and timer arm requests are returned as
//! [`Event`] values, and the daemon (or test) drives scheduled work by
//! calling back into the manager.  Iteration orders that Go leaves to
//! random map ordering (pending scans in `CancelPending` and
//! `ForEachConnReq`) use ascending id order here, which is one of the
//! orders dcrd can produce.

use std::collections::BTreeMap;

use crate::{ConnmgrError, ErrorKind, make_error};

/// The max duration retrying of a persistent connection is allowed to
/// grow to, in nanoseconds (dcrd `maxRetryDuration`).
pub const MAX_RETRY_DURATION: i64 = 5 * 60 * 1_000_000_000;

/// The maximum number of successive failed connection attempts after
/// which network failure is assumed (dcrd `maxFailedAttempts`).
pub const MAX_FAILED_ATTEMPTS: u64 = 25;

/// The default duration for retrying persistent connections, in
/// nanoseconds (dcrd `defaultRetryDuration`).
pub const DEFAULT_RETRY_DURATION: i64 = 5 * 1_000_000_000;

/// The default number of outbound connections to maintain (dcrd
/// `defaultTargetOutbound`).
pub const DEFAULT_TARGET_OUTBOUND: u32 = 8;

/// The state of a requested connection (dcrd `ConnState`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnState {
    /// The connection is registered but not yet established.
    Pending,
    /// The connection is established.
    Established,
    /// An established connection that was disconnected and removed.
    Disconnected,
    /// The most recent connection attempt failed.
    Failed,
    /// The request was canceled before it succeeded.
    Canceled,
}

/// The address of a connection request (Go `net.Addr`: a network name
/// and a string form).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReqAddr {
    /// The network, e.g. `tcp`.
    pub network: String,
    /// The address string, e.g. `127.0.0.1:9108`.
    pub addr: String,
}

impl ReqAddr {
    /// A TCP address.
    pub fn tcp(addr: &str) -> ReqAddr {
        ReqAddr {
            network: "tcp".to_string(),
            addr: addr.to_string(),
        }
    }
}

/// A connection request to a network address (dcrd `ConnReq`).
#[derive(Debug)]
pub struct ConnReq<C> {
    /// The unique identifier for this request.
    pub id: u64,
    /// The current state.
    pub state: ConnState,
    /// The number of times a permanent request has been retried since
    /// the last successful connection.
    pub retry_count: u32,
    /// The established connection handle, if any.
    pub conn: Option<C>,
    /// The address to connect to.
    pub addr: Option<ReqAddr>,
    /// Whether the connection should be retried on disconnection with
    /// increasing backoff.
    pub permanent: bool,
}

impl<C> ConnReq<C> {
    /// A human-readable string for the request (dcrd `String`).
    pub fn go_string(&self) -> String {
        match &self.addr {
            Some(a) if !a.addr.is_empty() => format!("{} (reqid {})", a.addr, self.id),
            _ => format!("reqid {}", self.id),
        }
    }
}

/// Work the daemon must perform on the manager's behalf: callback
/// invocations and timer arms that dcrd performs with goroutines.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// Dial the identified request's address and report the result
    /// through [`ConnManager::dial_outcome`] (only under
    /// [`Config::deferred_dials`]).  dcrd's `Connect` performs this
    /// dial on its own goroutine before messaging the `connHandler`,
    /// so the driver should dial off its event thread.  The address is
    /// available through [`ConnManager::conn_req`].
    Dial {
        /// The connection request id.
        id: u64,
    },
    /// A new outbound connection was established; dcrd fires the
    /// `OnConnection` callback.  The connection handle is available
    /// through [`ConnManager::conn_req`].
    Connected {
        /// The connection request id.
        id: u64,
    },
    /// An established connection was disconnected; dcrd fires the
    /// `OnDisconnection` callback.
    Disconnected {
        /// The connection request id.
        id: u64,
    },
    /// Retry the identified permanent request after the delay (dcrd
    /// arms `time.After` and calls `Connect`); the driver calls
    /// [`ConnManager::retry_connect`] when it fires.
    ScheduleRetry {
        /// The connection request id.
        id: u64,
        /// The backoff delay in nanoseconds.
        delay_nanos: i64,
    },
    /// Request a brand new connection after the delay (dcrd arms
    /// `time.After` and calls `newConnReq`); the driver calls
    /// [`ConnManager::new_conn_req`] when it fires.
    ScheduleNewConn {
        /// The delay in nanoseconds.
        delay_nanos: i64,
    },
}

/// A connection handle owned by the manager.  dcrd closes the
/// underlying `net.Conn` when requests are canceled or disconnected.
pub trait Conn {
    /// Close the connection.
    fn close(&mut self);
}

type DialFn<C> = Box<dyn FnMut(&ReqAddr) -> Result<C, String>>;
type GetNewAddressFn = Box<dyn FnMut() -> Result<ReqAddr, String>>;

/// The configuration options for the connection manager (dcrd
/// `Config`).  The listener/accept surface is daemon-phase and not
/// modeled here.
pub struct Config<C> {
    /// The number of outbound network connections to maintain.
    /// Defaults to 8.
    pub target_outbound: u32,
    /// The duration to wait before retrying connection requests, in
    /// nanoseconds.  Defaults to 5s.
    pub retry_duration_nanos: i64,
    /// A way to get an address to make a network connection to.  When
    /// absent, no new connections are made automatically.
    pub get_new_address: Option<GetNewAddressFn>,
    /// Connects to the address on the named network.  Either `dial`
    /// or `dial_addr` must be specified (but not both).
    pub dial: Option<DialFn<C>>,
    /// An alternative to `dial` receiving the full address value.
    pub dial_addr: Option<DialFn<C>>,
    /// The time to wait for a connection to complete before giving
    /// up, in nanoseconds; applied by the caller-provided dialer
    /// (dcrd wraps the dial context).
    pub timeout_nanos: i64,
    /// Defer dials to the driver instead of calling a dial closure
    /// inline: each dial request surfaces as [`Event::Dial`] and the
    /// driver reports back through [`ConnManager::dial_outcome`].  This
    /// is dcrd's actual structure — `Connect` dials on its own
    /// goroutine and the `connHandler` only processes the
    /// `handleConnected`/`handleFailed` outcomes — so the manager's
    /// state machine never blocks on a dial.  When set, `dial` and
    /// `dial_addr` are unused and may be `None`.
    pub deferred_dials: bool,
}

impl<C> Default for Config<C> {
    fn default() -> Self {
        Config {
            target_outbound: 0,
            retry_duration_nanos: 0,
            get_new_address: None,
            dial: None,
            dial_addr: None,
            timeout_nanos: 0,
            deferred_dials: false,
        }
    }
}

/// The connection manager (dcrd `ConnManager`).
pub struct ConnManager<C> {
    conn_req_count: u64,
    cfg: Config<C>,
    failed_attempts: u64,
    reqs: BTreeMap<u64, ConnReq<C>>,
    pending: Vec<u64>,
    conns: Vec<u64>,
}

impl<C: Conn> ConnManager<C> {
    /// A new connection manager with the provided configuration (dcrd
    /// `New`), applying the retry duration and target outbound
    /// defaults.
    pub fn new(mut cfg: Config<C>) -> Result<ConnManager<C>, ConnmgrError> {
        // A deferred-dial manager never calls a dial closure, so none is
        // required (the driver dials on [`Event::Dial`] and reports back
        // through `dial_outcome`).
        if !cfg.deferred_dials && cfg.dial.is_none() && cfg.dial_addr.is_none() {
            return Err(make_error(ErrorKind::DialNil, "dial cannot be nil"));
        }
        if cfg.dial.is_some() && cfg.dial_addr.is_some() {
            return Err(make_error(
                ErrorKind::BothDialsFilled,
                "cannot specify both Dial and DialAddr",
            ));
        }
        // Default to sane values.
        if cfg.retry_duration_nanos <= 0 {
            cfg.retry_duration_nanos = DEFAULT_RETRY_DURATION;
        }
        if cfg.target_outbound == 0 {
            cfg.target_outbound = DEFAULT_TARGET_OUTBOUND;
        }
        Ok(ConnManager {
            conn_req_count: 0,
            cfg,
            failed_attempts: 0,
            reqs: BTreeMap::new(),
            pending: Vec::new(),
            conns: Vec::new(),
        })
    }

    /// The connection request for an id, including finished ones.
    pub fn conn_req(&self, id: u64) -> Option<&ConnReq<C>> {
        self.reqs.get(&id)
    }

    /// The number of established connections.
    pub fn conn_count(&self) -> usize {
        self.conns.len()
    }

    /// The number of successive failed connection attempts since the
    /// last success.
    pub fn failed_attempts(&self) -> u64 {
        self.failed_attempts
    }

    /// Start enough outbound connections to reach the target number
    /// when an address source is configured (the connection half of
    /// dcrd `Run`; listeners are daemon-phase).
    pub fn start(&mut self) -> Vec<Event> {
        let mut events = Vec::new();
        if self.cfg.get_new_address.is_some() {
            let cur = self.conn_req_count;
            for _ in cur..self.cfg.target_outbound as u64 {
                self.new_conn_req(&mut events);
            }
        }
        events
    }

    /// Create a new connection request backed by the configured
    /// address source and connect to it (dcrd `newConnReq`).  The
    /// driver also calls this when a scheduled new-connection timer
    /// fires.
    pub fn new_conn_req_now(&mut self) -> Vec<Event> {
        let mut events = Vec::new();
        self.new_conn_req(&mut events);
        events
    }

    fn new_conn_req(&mut self, events: &mut Vec<Event>) {
        self.conn_req_count = self.conn_req_count.wrapping_add(1);
        let id = self.conn_req_count;
        let req = ConnReq {
            id,
            state: ConnState::Pending,
            retry_count: 0,
            conn: None,
            addr: None,
            permanent: false,
        };
        self.reqs.insert(id, req);
        self.pending.push(id);

        let addr = match self.cfg.get_new_address.as_mut() {
            Some(get) => get(),
            None => return,
        };
        match addr {
            Ok(addr) => {
                if let Some(req) = self.reqs.get_mut(&id) {
                    req.addr = Some(addr);
                }
                self.dial_registered(id, events);
            }
            Err(err) => self.handle_failed(id, &err, events),
        }
    }

    /// Assign an id to a fresh connection request for the given
    /// address, register it, and dial it (dcrd `Connect` for a request
    /// that has not been assigned an id).  Returns the assigned id and
    /// the resulting events.
    pub fn connect(&mut self, addr: ReqAddr, permanent: bool) -> (u64, Vec<Event>) {
        let mut events = Vec::new();
        self.conn_req_count = self.conn_req_count.wrapping_add(1);
        let id = self.conn_req_count;
        let req = ConnReq {
            id,
            state: ConnState::Pending,
            retry_count: 0,
            conn: None,
            addr: Some(addr),
            permanent,
        };
        self.reqs.insert(id, req);
        self.pending.push(id);
        self.dial_registered(id, &mut events);
        (id, events)
    }

    /// Re-dial an existing connection request when a scheduled retry
    /// fires (dcrd `Connect` for a request that already has an id).
    /// A request canceled while the retry timer was pending is
    /// ignored.
    pub fn retry_connect(&mut self, id: u64) -> Vec<Event> {
        let mut events = Vec::new();
        let Some(req) = self.reqs.get(&id) else {
            return events;
        };
        // During the time waited for retry the connection may have
        // been cancelled.
        if req.state == ConnState::Canceled {
            return events;
        }
        self.dial_registered(id, &mut events);
        events
    }

    /// Dial a registered request and process the outcome (the dial
    /// plus `handleConnected`/`handleFailed` halves of dcrd's
    /// `Connect`).  Under deferred dials the request surfaces as an
    /// [`Event::Dial`] instead, and the driver reports the outcome
    /// through [`ConnManager::dial_outcome`] — dcrd's `Connect`
    /// goroutine dialing and then messaging the `connHandler`.
    fn dial_registered(&mut self, id: u64, events: &mut Vec<Event>) {
        let addr = match self.reqs.get(&id).and_then(|r| r.addr.clone()) {
            Some(addr) => addr,
            None => return,
        };
        if self.cfg.deferred_dials {
            events.push(Event::Dial { id });
            return;
        }
        let dial = self
            .cfg
            .dial
            .as_mut()
            .or(self.cfg.dial_addr.as_mut())
            .expect("validated at construction");
        match dial(&addr) {
            Ok(conn) => self.handle_connected(id, conn, events),
            Err(err) => self.handle_failed(id, &err, events),
        }
    }

    /// Report the outcome of a deferred dial (dcrd's `Connect`
    /// goroutine messaging `handleConnected` on success or
    /// `handleFailed` on error).  A request canceled or removed while
    /// the dial was in flight closes a successful connection and
    /// ignores a failure, exactly like dcrd's handlers checking the
    /// pending set.
    pub fn dial_outcome(&mut self, id: u64, outcome: Result<C, String>) -> Vec<Event> {
        let mut events = Vec::new();
        match outcome {
            Ok(conn) => self.handle_connected(id, conn, &mut events),
            Err(err) => self.handle_failed(id, &err, &mut events),
        }
        events
    }

    /// dcrd `handleConnected`.
    fn handle_connected(&mut self, id: u64, mut conn: C, events: &mut Vec<Event>) {
        if !self.pending.contains(&id) {
            // Ignore connections for canceled requests.
            conn.close();
            return;
        }
        let req = self.reqs.get_mut(&id).expect("registered");
        req.state = ConnState::Established;
        req.conn = Some(conn);
        req.retry_count = 0;
        self.failed_attempts = 0;
        self.pending.retain(|p| *p != id);
        self.conns.push(id);
        events.push(Event::Connected { id });
    }

    /// dcrd `handleFailed`.
    fn handle_failed(&mut self, id: u64, _err: &str, events: &mut Vec<Event>) {
        if !self.pending.contains(&id) {
            // Ignore connections for canceled requests.
            return;
        }
        if let Some(req) = self.reqs.get_mut(&id) {
            req.state = ConnState::Failed;
        }
        self.handle_failed_conn(id, events);
    }

    /// dcrd `handleFailedConn`: retry a permanent connection with
    /// increasing backoff, or request a new connection, delaying it
    /// once the failure threshold is reached.
    fn handle_failed_conn(&mut self, id: u64, events: &mut Vec<Event>) {
        let (permanent, retry_count) = match self.reqs.get_mut(&id) {
            Some(req) => {
                if req.permanent {
                    req.retry_count = req.retry_count.wrapping_add(1);
                }
                (req.permanent, req.retry_count)
            }
            None => return,
        };
        if permanent {
            let mut d = (retry_count as i64).saturating_mul(self.cfg.retry_duration_nanos);
            if d > MAX_RETRY_DURATION {
                d = MAX_RETRY_DURATION;
            }
            events.push(Event::ScheduleRetry { id, delay_nanos: d });
        } else if self.cfg.get_new_address.is_some() {
            self.failed_attempts = self.failed_attempts.wrapping_add(1);
            if self.failed_attempts >= MAX_FAILED_ATTEMPTS {
                events.push(Event::ScheduleNewConn {
                    delay_nanos: self.cfg.retry_duration_nanos,
                });
            } else {
                // dcrd spawns the new request immediately; the
                // synchronous port recurses, which is bounded by the
                // failure threshold.
                self.new_conn_req(events);
            }
        }
    }

    /// Disconnect the connection corresponding to the given id,
    /// retrying it when appropriate (dcrd `Disconnect`).
    pub fn disconnect(&mut self, id: u64) -> Vec<Event> {
        let mut events = Vec::new();
        self.handle_disconnected(id, true, &mut events);
        events
    }

    /// Remove the connection corresponding to the given id from known
    /// connections, or cancel a lingering attempt (dcrd `Remove`).
    pub fn remove(&mut self, id: u64) -> Vec<Event> {
        let mut events = Vec::new();
        self.handle_disconnected(id, false, &mut events);
        events
    }

    /// dcrd `handleDisconnected`.
    fn handle_disconnected(&mut self, id: u64, retry: bool, events: &mut Vec<Event>) {
        if !self.conns.contains(&id) {
            // A pending connection is canceled so a later, successful
            // connection is ignored.
            if self.pending.contains(&id) {
                if let Some(req) = self.reqs.get_mut(&id) {
                    req.state = ConnState::Canceled;
                }
                self.pending.retain(|p| *p != id);
            }
            return;
        }

        // An existing connection: mark disconnected and fire the
        // disconnection callback.
        self.conns.retain(|c| *c != id);
        let permanent = {
            let req = self.reqs.get_mut(&id).expect("known conn");
            // Close AND drop the connection handle so its socket file
            // descriptors are released immediately.  Go's `net.Conn.Close`
            // does both, but the port's `Conn::close` only shuts the
            // socket; keeping the handle would leak an fd per disconnect
            // (a non-persistent peer's request is replaced by a fresh
            // one on redial and never reused, so its handle is never
            // dropped) and exhaust the process's descriptors under peer
            // churn.
            if let Some(mut conn) = req.conn.take() {
                conn.close();
            }
            req.permanent
        };
        events.push(Event::Disconnected { id });

        if !retry {
            if let Some(req) = self.reqs.get_mut(&id) {
                req.state = ConnState::Disconnected;
            }
            return;
        }

        // Attempt a reconnection when below the target or persistent.
        let num_conns = self.conns.len() as u32;
        if num_conns < self.cfg.target_outbound || permanent {
            if permanent {
                let req = self.reqs.get_mut(&id).expect("known conn");
                req.state = ConnState::Pending;
                self.pending.push(id);
            }
            self.handle_failed_conn(id, events);
        }
    }

    /// Remove the pending connection with the given address (dcrd
    /// `CancelPending`).  Where dcrd scans its pending map in random
    /// order, the port cancels the earliest-registered match.
    pub fn cancel_pending(&mut self, addr: &str) -> Result<(), String> {
        let mut found: Option<u64> = None;
        for id in &self.pending {
            let req = &self.reqs[id];
            let Some(req_addr) = &req.addr else { continue };
            if req_addr.addr == addr {
                found = Some(*id);
                break;
            }
        }
        match found {
            Some(id) => {
                self.pending.retain(|p| *p != id);
                if let Some(req) = self.reqs.get_mut(&id) {
                    req.state = ConnState::Canceled;
                }
                Ok(())
            }
            None => Err(format!("no pending connection to {addr}")),
        }
    }

    /// Call the provided function with each connection request known
    /// to the manager, including pending ones, stopping early on error
    /// (dcrd `ForEachConnReq`).  Pending requests are visited before
    /// established ones, each in registration order, which is one of
    /// the orders dcrd's random map iteration can produce.
    pub fn for_each_conn_req<F: FnMut(&ConnReq<C>) -> Result<(), String>>(
        &self,
        mut f: F,
    ) -> Result<(), String> {
        for id in &self.pending {
            f(&self.reqs[id])?;
        }
        for id in &self.conns {
            f(&self.reqs[id])?;
        }
        Ok(())
    }
}
