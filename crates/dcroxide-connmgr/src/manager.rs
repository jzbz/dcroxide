// SPDX-License-Identifier: ISC
//! The dcrd 2.2 connection manager decision core (dcrd
//! `internal/connmgr` `ConnManager`, rewritten upstream from the v1
//! `connmgr` package this crate previously mirrored).
//!
//! dcrd's manager owns goroutines (per-listener accept loops, a
//! persistent-connection runner per entry, the target-outbound
//! maintainer), blocking channel semaphores, contexts, and the
//! sockets themselves.  Per the port's conventions those are
//! daemon-phase concurrency: this core keeps dcrd's exact state —
//! the pending/active/persistent maps with their shared
//! address-index ownership rules, the semaphore counters (with the
//! automatic outbound fill's blocking acquire as a parked waiter a
//! release wakes through [`ConnManager::set_permit_waker`]), per-host
//! permits, outbound group tracking, and the inbound rate limiter —
//! and makes dcrd's exact decisions in dcrd's order, the automatic
//! outbound attempt's reservations included
//! ([`ConnManager::auto_outbound_acquire`] and
//! [`ConnManager::auto_outbound_reserve`]).  The daemon passes in the
//! clock readings (wall-clock time, and [`crate::monotonic_nanos`]
//! where dcrd subtracts two `time.Now` values, as for the inbound
//! token buckets), the randomness, and the address source, owns the
//! sockets, and executes the returned actions (dial, close, cancel,
//! and a timer armed for each returned delay).  Close-time
//! cleanup dcrd composes as nested `onClose` closures is recorded
//! per connection as an explicit [`ClosePlan`] executed by
//! [`ConnManager::conn_closed`].

use std::collections::HashMap;

use dcroxide_addrmgr::{GoTime, NetAddress};

use crate::conntype::ConnectionType;
use crate::csprng::Csprng;
use crate::groups::OutboundGroupInfo;
use crate::ratelimiter::InboundRateLimiter;
use crate::{ConnmgrError, ErrorKind, make_error};

/// The maximum number of persistent connections that can be added
/// (dcrd `MaxPersistent`).  Persistent connections do not count
/// toward the automatic outbound connection limits.
pub const MAX_PERSISTENT: usize = 8;

/// The successive failed connection attempts after which network
/// failure is assumed and new connections are delayed by the retry
/// duration (dcrd `maxFailedAttempts`).
pub const MAX_FAILED_ATTEMPTS: u64 = 25;

/// The default retry duration for persistent connections, in
/// nanoseconds (dcrd `defaultRetryDuration`).
pub const DEFAULT_RETRY_DURATION: i64 = 5 * 1_000_000_000;

/// The default maximum a persistent retry backoff grows to, in
/// nanoseconds (dcrd `defaultMaxRetryDuration`).
pub const DEFAULT_MAX_RETRY_DURATION: i64 = 5 * 60 * 1_000_000_000;

/// The default maximum connections per outbound group to strongly
/// prefer when choosing automatic outbound addresses (dcrd
/// `defaultMaxPerOutboundGroup`).
pub const DEFAULT_MAX_PER_OUTBOUND_GROUP: u32 = 1;

/// The default maximum number of normal inbound, outbound, and
/// pending connections (dcrd `defaultMaxNormalConns`).
pub const DEFAULT_MAX_NORMAL_CONNS: u32 = 125;

/// The default number of outbound connections to maintain (dcrd
/// `defaultTargetOutbound`).
pub const DEFAULT_TARGET_OUTBOUND: u32 = 8;

/// The connection manager configuration (the policy subset of dcrd's
/// `Config`; the listener, dialer, and callback closures live with
/// the daemon).
pub struct ManagerConfig {
    /// The default peer-to-peer port for the active network; 0
    /// removes it from address-selection policy (dcrd
    /// `Config.DefaultPort`).
    pub default_port: u16,
    /// The maximum number of normal inbound, outbound, and pending
    /// connections; 0 selects the default 125 (dcrd
    /// `Config.MaxNormalConns`).
    pub max_normal_conns: u32,
    /// The maximum connections with the same host; 0 disables the
    /// limit (dcrd `Config.MaxConnsPerHost`).
    pub max_conns_per_host: u32,
    /// The number of outbound connections to maintain automatically;
    /// 0 selects the default 8, and the value is forced to at most
    /// `max_normal_conns` (dcrd `Config.TargetOutbound`).
    pub target_outbound: u32,
    /// The base duration between connection retries in nanoseconds;
    /// non-positive selects the default 5s (dcrd
    /// `Config.RetryDuration`).
    pub retry_duration_nanos: i64,
    /// Whether the address is whitelisted (dcrd `IsWhitelisted` over
    /// `Config.Whitelists`; the daemon supplies its CIDR matcher).
    pub is_whitelisted: Box<dyn Fn(&NetAddress) -> bool + Send>,
}

impl Default for ManagerConfig {
    fn default() -> ManagerConfig {
        ManagerConfig {
            default_port: 0,
            max_normal_conns: 0,
            max_conns_per_host: 0,
            target_outbound: 0,
            retry_duration_nanos: 0,
            is_whitelisted: Box::new(|_| false),
        }
    }
}

/// A counting semaphore mirroring dcrd's channel-based `semaphore`:
/// try-acquire never blocks, release silently tolerates
/// over-release, and dcrd's blocking `Acquire` is modelled for its one
/// caller that blocks, the automatic outbound fill
/// (`targetOutboundHandler`), as a single parked waiter
/// ([`SemCount::acquire_or_wait`]).
///
/// A release while the waiter is parked hands the freed permit
/// straight to it: dcrd's `Release` is a channel receive, and the Go
/// runtime completes a sender blocked on the full channel inside that
/// same receive, so the permit never becomes free for a concurrent
/// `TryAcquire` (an inbound connection or a manual `Connect`).  The
/// waiter collects it with [`SemCount::take_grant`].
#[derive(Debug, Clone, Copy)]
pub struct SemCount {
    capacity: u32,
    used: u32,
    /// Whether the waiter is parked on the semaphore.
    waiting: bool,
    /// A permit a release handed to the parked waiter that it has not
    /// collected yet; it stays counted in `used`.
    granted: bool,
}

impl SemCount {
    fn new(capacity: u32) -> SemCount {
        SemCount {
            capacity,
            used: 0,
            waiting: false,
            granted: false,
        }
    }

    /// Acquire without blocking; false when at capacity (dcrd
    /// `semaphore.TryAcquire` with a live context).
    pub fn try_acquire(&mut self) -> bool {
        if self.used >= self.capacity {
            return false;
        }
        self.used = self.used.wrapping_add(1);
        true
    }

    /// Acquire, or park the caller as the waiter when at capacity
    /// (dcrd `semaphore.Acquire` blocking): false means parked, and the
    /// next release hands the caller its permit instead of freeing it.
    pub fn acquire_or_wait(&mut self) -> bool {
        if self.try_acquire() {
            return true;
        }
        self.waiting = true;
        false
    }

    /// Whether the waiter is parked and has not been handed a permit.
    pub fn is_waiting(&self) -> bool {
        self.waiting
    }

    /// Collect the permit a release handed to the parked waiter, if
    /// one did (dcrd's blocked `Acquire` returning).
    pub fn take_grant(&mut self) -> bool {
        std::mem::take(&mut self.granted)
    }

    /// Release one permit; over-release is ignored like dcrd's
    /// non-blocking channel receive.  With the waiter parked the permit
    /// passes to it instead and stays counted as used; returns whether
    /// it did, so the caller can wake the waiter.
    pub fn release(&mut self) -> bool {
        if self.waiting {
            self.waiting = false;
            self.granted = true;
            return true;
        }
        self.used = self.used.saturating_sub(1);
        false
    }

    /// The permits currently held.
    pub fn used(&self) -> u32 {
        self.used
    }

    /// The total capacity.
    pub fn capacity(&self) -> u32 {
        self.capacity
    }
}

/// The close-time cleanup for a tracked connection: what dcrd
/// composes as nested `onClose` closures at dial/accept time, made
/// explicit so [`ConnManager::conn_closed`] can execute it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClosePlan {
    /// Remove the address from the outbound groups (Connect and
    /// automatic outbound dials).
    pub remove_outbound_group: bool,
    /// Release the total-normal-connections permit.
    pub release_total_sem: bool,
    /// Release the active-outbounds permit (automatic outbound
    /// dials).
    pub release_outbound_sem: bool,
    /// Release the per-host permit (reserved when per-host limiting
    /// applies to the address).
    pub release_host_permit: bool,
    /// Signal the persistent runner for this entry that its
    /// connection dropped (dcrd's `disconnected` channel send).
    pub signal_persistent: Option<u64>,
}

/// A tracked established connection (the bookkeeping half of dcrd's
/// `Conn`; the socket and callbacks live with the daemon).
#[derive(Debug, Clone)]
pub struct ConnRecord {
    /// The unique connection ID (dcrd `Conn.id`).
    pub id: u64,
    /// The connection type (dcrd `Conn.connType`).
    pub conn_type: ConnectionType,
    /// The remote address (dcrd `Conn.remoteAddr`).
    pub remote_addr: NetAddress,
    /// The close-time cleanup.
    pub close_plan: ClosePlan,
}

/// A pending connection attempt (dcrd `pendingConnInfo`; the cancel
/// handle lives with the daemon's dial thread).
#[derive(Debug, Clone)]
struct PendingConnInfo {
    id: u64,
    addr: NetAddress,
}

/// A persistent connection entry (dcrd `persistentEntry`).
#[derive(Debug, Clone)]
pub struct PersistentEntry {
    /// The stable connection ID reused across reconnects.
    pub id: u64,
    /// The address to maintain a connection with.
    pub addr: NetAddress,
}

/// The action the daemon must take after [`ConnManager::disconnect`]
/// or [`ConnManager::remove`].
#[derive(Debug, Clone)]
pub enum DisconnectAction {
    /// Nothing further (e.g. a persistent entry awaiting retry).
    None,
    /// Cancel the in-flight dial for the ID.
    CancelPending,
    /// Close the established connection (which re-enters
    /// [`ConnManager::conn_closed`]).
    CloseConn,
    /// Close the connection already removed from the active map; the
    /// daemon closes the socket and applies the carried record's
    /// close plan via [`ConnManager::run_close_plan`] (dcrd's Remove
    /// removes under the lock and the composed `onClose` still runs).
    CloseRemoved(ConnRecord),
    /// Cancel the persistent runner, and also cancel its in-flight
    /// dial.
    CancelPersistentAndPending,
    /// Cancel the persistent runner, and also close its established
    /// connection (removed here; the daemon closes the socket and
    /// applies the carried record's close plan).
    CancelPersistentAndClose(ConnRecord),
    /// Cancel the persistent runner; it had no live connection.
    CancelPersistent,
}

/// The decision for an accepted inbound connection (dcrd's
/// `listenHandler` admission sequence).
#[derive(Debug)]
pub enum InboundDecision {
    /// Drop the connection and route the reason through the drop-log
    /// throttle (dcrd `LogDrops(rAddr, reason)` then close).
    Drop {
        /// dcrd's exact drop reason string.
        reason: String,
    },
    /// Drop without logging (the try-acquire context-error path,
    /// only reachable at shutdown).
    DropSilent,
    /// Admit: the daemon registers the connection via
    /// [`ConnManager::register_inbound`] with these reservations.
    Admit {
        /// Whether a total-normal-connections permit was reserved
        /// (false only for whitelisted addresses).
        require_permit: bool,
        /// Whether a per-host permit was reserved.
        host_permit_reserved: bool,
    },
}

/// The connection manager decision core (dcrd `ConnManager`).
pub struct ConnManager {
    cfg: ManagerConfig,
    /// The last assigned connection ID (dcrd `nextConnID`; IDs start
    /// at 1).
    next_conn_id: u64,
    /// Whether the manager is shutting down (dcrd's closed `quit`
    /// channel).
    shutdown: bool,
    /// The maximum persistent retry backoff, in nanoseconds (dcrd
    /// `maxRetryDuration`).
    max_retry_duration: i64,
    /// The maximum exponential backoff scaling bits such that
    /// multiplying the retry duration cannot overflow (dcrd
    /// `maxRetryScalingBits`).
    max_retry_scaling_bits: u8,
    /// The maximum connections per outbound group preferred during
    /// address selection (dcrd `maxPerOutboundGroup`).
    max_per_outbound_group: u32,
    /// The total normal connections permit counter (dcrd
    /// `totalNormalConnsSem`).
    pub(crate) total_normal_conns_sem: SemCount,
    /// The active automatic outbound permit counter (dcrd
    /// `activeOutboundsSem`).
    pub(crate) active_outbounds_sem: SemCount,
    /// Per-host connection counts (dcrd `perHostCounts`).
    per_host_counts: HashMap<String, u32>,
    /// Outbound address group tracking (dcrd `outboundGroups`).
    pub(crate) outbound_groups: OutboundGroupInfo,
    /// Inbound rate limiting and flood detection (dcrd
    /// `inboundLimiter`).
    pub inbound_limiter: InboundRateLimiter,
    /// Registered persistent entries (dcrd `persistent`).
    persistent: HashMap<u64, PersistentEntry>,
    /// Connection attempts that have yet to succeed (dcrd `pending`).
    pending: HashMap<u64, PendingConnInfo>,
    /// Established connections (dcrd `active`).
    active: HashMap<u64, ConnRecord>,
    /// Connection IDs by address (host:port), kept in sync with the
    /// three maps; persistent entries own their address key (dcrd
    /// `connIDByAddr`).
    conn_id_by_addr: HashMap<String, u64>,
    /// Called when a release hands the parked automatic outbound fill
    /// its total-connections permit, so the daemon's driver resumes it
    /// (dcrd's `targetOutboundHandler` wakes from `Acquire` by itself).
    permit_waker: Option<Box<dyn Fn() + Send>>,
}

/// No suitable outbound address was found within the allowed
/// attempts (dcrd `errNoSuitableAddr`, a plain error distinct from
/// the typed kinds).
pub const NO_SUITABLE_ADDR_MSG: &str = "no suitable outbound address";

/// The number of addresses outbound selection requests before giving
/// up for now (dcrd `pickOutboundAddr`'s `retries`).
pub const PICK_OUTBOUND_RETRIES: u32 = 100;

impl ConnManager {
    /// A new connection manager with defaults applied (dcrd `New`;
    /// the dial-closure nil check lives with the daemon assembly
    /// since the core holds no dialer).
    pub fn new(mut cfg: ManagerConfig, csprng: &mut dyn Csprng) -> ConnManager {
        if cfg.retry_duration_nanos <= 0 {
            cfg.retry_duration_nanos = DEFAULT_RETRY_DURATION;
        }
        if cfg.max_normal_conns == 0 {
            cfg.max_normal_conns = DEFAULT_MAX_NORMAL_CONNS;
        }
        if cfg.target_outbound == 0 {
            cfg.target_outbound = DEFAULT_TARGET_OUTBOUND;
        }
        cfg.target_outbound = cfg.target_outbound.min(cfg.max_normal_conns);
        // dcrd: 63 - uint8(math.Ceil(math.Log2(float64(RetryDuration)))).
        let retry_duration_bits = (cfg.retry_duration_nanos as f64).log2().ceil() as u8;
        let max_retry_scaling_bits = 63u8.wrapping_sub(retry_duration_bits);
        let total = SemCount::new(cfg.max_normal_conns);
        let outbound = SemCount::new(cfg.target_outbound);
        ConnManager {
            next_conn_id: 0,
            shutdown: false,
            max_retry_duration: DEFAULT_MAX_RETRY_DURATION,
            max_retry_scaling_bits,
            max_per_outbound_group: DEFAULT_MAX_PER_OUTBOUND_GROUP,
            total_normal_conns_sem: total,
            active_outbounds_sem: outbound,
            per_host_counts: HashMap::new(),
            outbound_groups: OutboundGroupInfo::new(csprng),
            inbound_limiter: InboundRateLimiter::new(csprng),
            persistent: HashMap::with_capacity(MAX_PERSISTENT),
            pending: HashMap::new(),
            active: HashMap::new(),
            conn_id_by_addr: HashMap::new(),
            permit_waker: None,
            cfg,
        }
    }

    /// Install the callback that wakes the automatic outbound fill when
    /// a release hands it the total-connections permit it is parked on
    /// ([`SemCount::acquire_or_wait`]).  It runs with the manager
    /// borrowed, so it must only signal.
    pub fn set_permit_waker(&mut self, waker: Box<dyn Fn() + Send>) {
        self.permit_waker = Some(waker);
    }

    /// Release a total-connections permit, waking the parked outbound
    /// fill when the permit passes to it.
    fn release_total_permit(&mut self) {
        if self.total_normal_conns_sem.release()
            && let Some(waker) = &self.permit_waker
        {
            waker();
        }
    }

    /// The configured retry duration in nanoseconds.
    pub fn retry_duration_nanos(&self) -> i64 {
        self.cfg.retry_duration_nanos
    }

    /// The effective target of automatic outbound connections.
    pub fn target_outbound(&self) -> u32 {
        self.cfg.target_outbound
    }

    /// The configured maximum of normal connections.
    pub fn max_normal_conns(&self) -> u32 {
        self.cfg.max_normal_conns
    }

    /// The total normal connections semaphore (dcrd
    /// `totalNormalConnsSem`), for reading.  Its permits are taken and
    /// given back only through the manager's own gates, close plans and
    /// automatic outbound sequence; nothing outside the crate takes or
    /// releases one directly.
    pub fn total_normal_conns_sem(&self) -> &SemCount {
        &self.total_normal_conns_sem
    }

    /// The active automatic outbound semaphore (dcrd
    /// `activeOutboundsSem`), for reading.
    pub fn active_outbounds_sem(&self) -> &SemCount {
        &self.active_outbounds_sem
    }

    /// The outbound address group tracking (dcrd `outboundGroups`), for
    /// reading.
    pub fn outbound_groups(&self) -> &OutboundGroupInfo {
        &self.outbound_groups
    }

    /// Begin shutdown: further operations return
    /// [`ErrorKind::Shutdown`] (dcrd's closed `quit` channel).
    pub fn begin_shutdown(&mut self) {
        self.shutdown = true;
    }

    /// The IDs of every persistent, pending, and active connection,
    /// for the shutdown sweep that removes each (dcrd `Run`'s
    /// teardown).
    pub fn all_ids(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self
            .persistent
            .keys()
            .chain(self.pending.keys())
            .chain(self.active.keys())
            .copied()
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    fn check_shutdown(&self) -> Result<(), ConnmgrError> {
        if self.shutdown {
            return Err(make_error(
                ErrorKind::Shutdown,
                "connection manager shutdown",
            ));
        }
        Ok(())
    }

    /// Whether the address is whitelisted (dcrd `IsWhitelisted`).
    pub fn is_whitelisted(&self, addr: &NetAddress) -> bool {
        (self.cfg.is_whitelisted)(addr)
    }

    // ==================== connIDByAddr bookkeeping ====================

    fn add_pending_info(&mut self, info: PendingConnInfo) {
        if !self.persistent.contains_key(&info.id) {
            self.conn_id_by_addr.insert(info.addr.key(), info.id);
        }
        self.pending.insert(info.id, info);
    }

    fn remove_pending_info(&mut self, id: u64) {
        if let Some(info) = self.pending.remove(&id)
            && !self.persistent.contains_key(&id)
        {
            self.conn_id_by_addr.remove(&info.addr.key());
        }
    }

    fn add_active_conn(&mut self, conn: ConnRecord) {
        if !self.persistent.contains_key(&conn.id) {
            self.conn_id_by_addr.insert(conn.remote_addr.key(), conn.id);
        }
        self.active.insert(conn.id, conn);
    }

    fn remove_active_conn(&mut self, id: u64) -> Option<ConnRecord> {
        let conn = self.active.remove(&id)?;
        if !self.persistent.contains_key(&id) {
            self.conn_id_by_addr.remove(&conn.remote_addr.key());
        }
        Some(conn)
    }

    fn add_persistent_entry(&mut self, entry: PersistentEntry) {
        self.conn_id_by_addr.insert(entry.addr.key(), entry.id);
        self.outbound_groups.add_addr(&entry.addr);
        self.persistent.insert(entry.id, entry);
    }

    fn remove_persistent_entry(&mut self, id: u64) -> Option<PersistentEntry> {
        let entry = self.persistent.remove(&id)?;
        let pending = self.pending.contains_key(&id);
        let active = self.active.contains_key(&id);
        if !pending && !active {
            self.conn_id_by_addr.remove(&entry.addr.key());
        }
        self.outbound_groups.remove_addr(&entry.addr);
        Some(entry)
    }

    // ==================== rejection gates ====================

    /// Reject when the address already has an established connection
    /// or pending attempt (dcrd `rejectConnectedAddr`).
    pub fn reject_connected_addr(&self, addr: &NetAddress) -> Result<(), ConnmgrError> {
        let Some(&conn_id) = self.conn_id_by_addr.get(&addr.key()) else {
            return Ok(());
        };
        if self.pending.contains_key(&conn_id) {
            let str = format!("a pending connection to {} already exists", addr.key());
            return Err(make_error(ErrorKind::AlreadyPending, &str));
        }
        if self.active.contains_key(&conn_id) {
            let str = format!("a connection to {} is already established", addr.key());
            return Err(make_error(ErrorKind::AlreadyConnected, &str));
        }
        Ok(())
    }

    fn find_persistent_addr_id(&self, addr: &NetAddress) -> Option<u64> {
        let conn_id = self.conn_id_by_addr.get(&addr.key())?;
        self.persistent.get(conn_id).map(|entry| entry.id)
    }

    /// Reject when a persistent entry exists for the address (dcrd
    /// `rejectPersistentAddr`).
    pub fn reject_persistent_addr(&self, addr: &NetAddress) -> Result<(), ConnmgrError> {
        if self.find_persistent_addr_id(addr).is_some() {
            let str = format!("a persistent connection for {} already exists", addr.key());
            return Err(make_error(ErrorKind::DuplicatePersistent, &str));
        }
        Ok(())
    }

    /// Reject when a persistent entry, pending attempt, or
    /// established connection exists for the address (dcrd
    /// `rejectDuplicateAddr`).
    pub fn reject_duplicate_addr(&self, addr: &NetAddress) -> Result<(), ConnmgrError> {
        self.reject_persistent_addr(addr)?;
        self.reject_connected_addr(addr)?;
        Ok(())
    }

    // ==================== per-host permits ====================

    /// Whether the address requires a per-host permit (dcrd
    /// `needsHostPermit`): per-host limiting enabled and the address
    /// neither whitelisted nor loopback.
    pub fn needs_host_permit(&self, addr: &NetAddress) -> bool {
        if self.cfg.max_conns_per_host == 0 {
            return false;
        }
        !(self.is_whitelisted(addr) || is_loopback(&addr.ip))
    }

    /// Reserve a per-host permit when one is required (dcrd
    /// `maybeReserveHostPermit`): Ok(true) when reserved, Ok(false)
    /// when exempt, and [`ErrorKind::MaxConnsPerHost`] when full.
    pub fn maybe_reserve_host_permit(&mut self, addr: &NetAddress) -> Result<bool, ConnmgrError> {
        if !self.needs_host_permit(addr) {
            return Ok(false);
        }
        let host_key = addr_host_key(addr);
        let max_allowed = self.cfg.max_conns_per_host;
        let num_conns = self.per_host_counts.get(&host_key).copied().unwrap_or(0);
        if num_conns.wrapping_add(1) > max_allowed {
            let str = format!(
                "a maximum of {} {} per host is allowed",
                max_allowed,
                pick_noun(u64::from(max_allowed), "connection", "connections"),
            );
            return Err(make_error(ErrorKind::MaxConnsPerHost, &str));
        }
        self.per_host_counts
            .insert(host_key, num_conns.wrapping_add(1));
        Ok(true)
    }

    /// Release a per-host permit (dcrd `releaseHostPermitFn`'s
    /// returned closure).
    pub fn release_host_permit(&mut self, addr: &NetAddress) {
        let host_key = addr_host_key(addr);
        if let Some(count) = self.per_host_counts.get_mut(&host_key) {
            *count = count.wrapping_sub(1);
            if *count == 0 {
                self.per_host_counts.remove(&host_key);
            }
        }
    }

    // ==================== dial bookkeeping ====================

    /// Register a dial attempt (the bookkeeping prologue of dcrd
    /// `dial`): shutdown check, the rejection gate — duplicates for
    /// fresh dials, connected-only when re-dialing a persistent entry
    /// — and the pending registration.  Returns the connection ID for
    /// the daemon's dial thread.
    pub fn begin_dial(
        &mut self,
        addr: &NetAddress,
        persistent_conn_id: Option<u64>,
    ) -> Result<u64, ConnmgrError> {
        self.check_shutdown()?;
        match persistent_conn_id {
            Some(_) => self.reject_connected_addr(addr)?,
            None => self.reject_duplicate_addr(addr)?,
        }
        let conn_id = match persistent_conn_id {
            Some(id) => id,
            None => self.next_id(),
        };
        self.add_pending_info(PendingConnInfo {
            id: conn_id,
            addr: addr.clone(),
        });
        Ok(conn_id)
    }

    /// Record a failed dial: drops the pending entry when still
    /// present (dcrd `dial`'s deferred pending removal; the flavor
    /// cleanup runs via the caller-held [`ClosePlan`] equivalent).
    /// Returns whether it was: `false` when the attempt was canceled
    /// while it dialed, where dcrd's dial fails with `context.Canceled`.
    pub fn dial_failed(&mut self, conn_id: u64) -> bool {
        let pending = self.pending.contains_key(&conn_id);
        self.remove_pending_info(conn_id);
        pending
    }

    /// Record a successful dial: when the pending entry was already
    /// canceled the daemon must close the socket (dcrd returns
    /// `context.Canceled`); otherwise the connection becomes active
    /// with the provided close plan and the record is returned.
    pub fn dial_succeeded(
        &mut self,
        conn_id: u64,
        addr: &NetAddress,
        conn_type: ConnectionType,
        close_plan: ClosePlan,
    ) -> Option<ConnRecord> {
        if !self.pending.contains_key(&conn_id) {
            return None;
        }
        self.remove_pending_info(conn_id);
        let record = ConnRecord {
            id: conn_id,
            conn_type,
            remote_addr: addr.clone(),
            close_plan,
        };
        self.add_active_conn(record.clone());
        Some(record)
    }

    /// Execute a closed connection's cleanup: remove it from the
    /// active set and run its close plan (dcrd's composed `onClose`
    /// chain).  Returns the persistent entry ID to signal when the
    /// plan carries one and the record itself.
    pub fn conn_closed(&mut self, conn_id: u64) -> Option<ConnRecord> {
        // The record may have been removed by `remove` already; dcrd's
        // removeActiveConn tolerates that, but the close plan still
        // ran through Conn.Close's onClose — the daemon applies the
        // record it holds via `run_close_plan` in that case.
        let record = self.remove_active_conn(conn_id)?;
        self.run_close_plan(&record);
        Some(record)
    }

    /// Run a close plan against the shared counters (split out so the
    /// daemon can apply plans for records already removed from the
    /// active map by `remove`).
    pub fn run_close_plan(&mut self, record: &ConnRecord) {
        let plan = &record.close_plan;
        if plan.remove_outbound_group {
            self.outbound_groups.remove_addr(&record.remote_addr);
        }
        if plan.release_host_permit {
            self.release_host_permit(&record.remote_addr);
        }
        if plan.release_total_sem {
            self.release_total_permit();
        }
        if plan.release_outbound_sem {
            self.active_outbounds_sem.release();
        }
    }

    fn next_id(&mut self) -> u64 {
        self.next_conn_id = self.next_conn_id.wrapping_add(1);
        self.next_conn_id
    }

    // ==================== Connect (manual) ====================

    /// The gate sequence of dcrd `Connect` before its dial: per-host
    /// permit, total-connections permit, and the outbound-group
    /// registration.  On success the returned close plan carries the
    /// reservations for the eventual close (or the failure unwind).
    pub fn connect_begin(&mut self, addr: &NetAddress) -> Result<ClosePlan, ConnmgrError> {
        let host_permit_reserved = self.maybe_reserve_host_permit(addr)?;
        if self.shutdown {
            // dcrd's TryAcquire returns the context error at shutdown
            // and Connect prefers the shutdown error.
            if host_permit_reserved {
                self.release_host_permit(addr);
            }
            return Err(make_error(
                ErrorKind::Shutdown,
                "connection manager shutdown",
            ));
        }
        if !self.total_normal_conns_sem.try_acquire() {
            if host_permit_reserved {
                self.release_host_permit(addr);
            }
            let max_allowed = self.cfg.max_normal_conns;
            let str = format!(
                "a maximum of {} {} is allowed",
                max_allowed,
                pick_noun(u64::from(max_allowed), "connection", "connections"),
            );
            return Err(make_error(ErrorKind::MaxNormalConns, &str));
        }
        self.outbound_groups.add_addr(addr);
        Ok(ClosePlan {
            remove_outbound_group: true,
            release_total_sem: true,
            release_outbound_sem: false,
            release_host_permit: host_permit_reserved,
            signal_persistent: None,
        })
    }

    /// Unwind a `connect_begin` reservation when the subsequent dial
    /// registration or dial itself fails (dcrd's `onClose` invoked on
    /// the failure path).
    pub fn connect_unwind(&mut self, addr: &NetAddress, plan: &ClosePlan) {
        if plan.remove_outbound_group {
            self.outbound_groups.remove_addr(addr);
        }
        if plan.release_host_permit {
            self.release_host_permit(addr);
        }
        if plan.release_total_sem {
            self.release_total_permit();
        }
        if plan.release_outbound_sem {
            self.active_outbounds_sem.release();
        }
    }

    // ==================== inbound admission ====================

    /// The admission decision for an accepted inbound connection,
    /// in dcrd `listenHandler`'s exact order: rate limiting and
    /// probabilistic flood drops (skipped for whitelisted and
    /// loopback addresses), duplicate rejection, the per-host
    /// permit, and the total-connections permit (required unless
    /// whitelisted).  The clocks are
    /// [`InboundRateLimiter::allow`]'s: wall-clock seconds and
    /// nanoseconds, and a monotonic nanosecond reading.
    pub fn admit_inbound(
        &mut self,
        addr: &NetAddress,
        now_unix: i64,
        now_nanos: i64,
        mono_nanos: i64,
        csprng: &mut dyn Csprng,
    ) -> InboundDecision {
        let is_whitelisted = self.is_whitelisted(addr);
        let is_loopback = is_loopback(&addr.ip);

        if !is_whitelisted && !is_loopback {
            if !self
                .inbound_limiter
                .allow(addr, now_unix, now_nanos, mono_nanos)
            {
                return InboundDecision::Drop {
                    reason: "rate limited".to_string(),
                };
            }
            if self.inbound_limiter.should_drop_probabilistic(csprng) {
                return InboundDecision::Drop {
                    reason: "probabilistically blocked during flood".to_string(),
                };
            }
        }

        if let Err(err) = self.reject_duplicate_addr(addr) {
            return InboundDecision::Drop {
                reason: err.description,
            };
        }

        let host_permit_reserved = match self.maybe_reserve_host_permit(addr) {
            Ok(reserved) => reserved,
            Err(err) => {
                return InboundDecision::Drop {
                    reason: err.description,
                };
            }
        };

        let require_permit = !is_whitelisted;
        if require_permit {
            if self.shutdown {
                if host_permit_reserved {
                    self.release_host_permit(addr);
                }
                return InboundDecision::DropSilent;
            }
            if !self.total_normal_conns_sem.try_acquire() {
                if host_permit_reserved {
                    self.release_host_permit(addr);
                }
                let max_conns = self.cfg.max_normal_conns;
                let reason = format!(
                    "a maximum of {} {} is allowed",
                    max_conns,
                    pick_noun(u64::from(max_conns), "connection", "connections"),
                );
                return InboundDecision::Drop { reason };
            }
        }

        InboundDecision::Admit {
            require_permit,
            host_permit_reserved,
        }
    }

    /// Register an admitted inbound connection: assigns the next ID
    /// and tracks it active with the close plan releasing the
    /// admission reservations (the body of dcrd `listenHandler`'s
    /// accept goroutine).
    pub fn register_inbound(
        &mut self,
        addr: &NetAddress,
        require_permit: bool,
        host_permit_reserved: bool,
    ) -> ConnRecord {
        let id = self.next_id();
        let record = ConnRecord {
            id,
            conn_type: ConnectionType::Inbound,
            remote_addr: addr.clone(),
            close_plan: ClosePlan {
                remove_outbound_group: false,
                release_total_sem: require_permit,
                release_outbound_sem: false,
                release_host_permit: host_permit_reserved,
                signal_persistent: None,
            },
        };
        self.add_active_conn(record.clone());
        record
    }

    // ==================== persistent connections ====================

    /// Reject when registering another persistent connection for the
    /// host would exceed the per-host maximum (dcrd
    /// `rejectMaxPersistentsPerHost`); only other persistent entries
    /// are counted.
    pub fn reject_max_persistents_per_host(&self, addr: &NetAddress) -> Result<(), ConnmgrError> {
        if !self.needs_host_permit(addr) {
            return Ok(());
        }
        let host_key = addr_host_key(addr);
        let count = self
            .persistent
            .values()
            .filter(|entry| addr_host_key(&entry.addr) == host_key)
            .count() as u32;
        let max_allowed = self.cfg.max_conns_per_host;
        if count.wrapping_add(1) > max_allowed {
            let str = format!(
                "a maximum of {} persistent {} per host is allowed",
                max_allowed,
                pick_noun(u64::from(max_allowed), "connection", "connections"),
            );
            return Err(make_error(ErrorKind::MaxPersistentPerHost, &str));
        }
        Ok(())
    }

    /// The capacity gate of dcrd `AddPersistent`, split out because
    /// dcrd checks it before converting the caller's address — the
    /// daemon calls this, then converts, then [`Self::add_persistent`]
    /// so a full table wins over a malformed address exactly as
    /// upstream.
    pub fn persistent_capacity_check(&self) -> Result<(), ConnmgrError> {
        if self.persistent.len().wrapping_add(1) > MAX_PERSISTENT {
            let str = format!("a maximum of {MAX_PERSISTENT} persistent connections is allowed");
            return Err(make_error(ErrorKind::MaxPersistent, &str));
        }
        Ok(())
    }

    /// Add an address to always maintain a connection with (dcrd
    /// `AddPersistent`): capacity, duplicate, and per-host gates,
    /// then the entry registration.  The daemon starts the runner for
    /// the returned entry (dcrd's buffered `runPersistentChan` send).
    pub fn add_persistent(&mut self, addr: &NetAddress) -> Result<u64, ConnmgrError> {
        self.persistent_capacity_check()?;
        self.reject_duplicate_addr(addr)?;
        self.reject_max_persistents_per_host(addr)?;
        let id = self.next_id();
        self.add_persistent_entry(PersistentEntry {
            id,
            addr: addr.clone(),
        });
        Ok(id)
    }

    /// Whether the ID belongs to a persistent connection (dcrd
    /// `IsPersistent`).
    pub fn is_persistent(&self, id: u64) -> bool {
        self.persistent.contains_key(&id)
    }

    /// The persistent connection ID for the address, when one exists
    /// (dcrd `FindPersistentAddrID`).
    pub fn find_persistent_addr_id_pub(&self, addr: &NetAddress) -> Option<u64> {
        self.find_persistent_addr_id(addr)
    }

    /// The persistent connection ID whose stored address key equals
    /// the raw `host:port` string (dcrd `FindPersistentAddrID` over a
    /// `simpleAddr`, which compares the unresolved caller string
    /// against the stored resolved keys).
    pub fn find_persistent_addr_id_by_key(&self, key: &str) -> Option<u64> {
        let conn_id = self.conn_id_by_addr.get(key)?;
        self.persistent.get(conn_id).map(|entry| entry.id)
    }

    /// The persistent entry for an ID, for the daemon's runner.
    pub fn persistent_entry(&self, id: u64) -> Option<PersistentEntry> {
        self.persistent.get(&id).cloned()
    }

    /// An exponential backoff delay with jitter for the given number
    /// of retries, in nanoseconds (dcrd `backoffWithJitter`): the
    /// shift is capped so the multiply cannot overflow, the backoff
    /// clamps to the maximum retry duration, and 50% jitter is drawn
    /// from the CSPRNG.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn backoff_with_jitter(&self, retries: u32, csprng: &mut dyn Csprng) -> i64 {
        if retries == 0 {
            return 0;
        }
        let shift = (retries - 1).min(u32::from(self.max_retry_scaling_bits));
        let factor = 1u64 << (shift & 63);
        let base_retry_duration = self.cfg.retry_duration_nanos;
        let backoff =
            (base_retry_duration.wrapping_mul(factor as i64)).min(self.max_retry_duration);
        if backoff == 0 {
            return 0;
        }
        // Apply 50% jitter.
        let half_backoff = backoff / 2;
        let jitter = csprng.uint64n(half_backoff as u64) as i64;
        half_backoff + jitter
    }

    /// Whether a dropped persistent connection should wait out a
    /// backoff before redialing (dcrd `runPersistent`'s disconnected
    /// arm): true when a prior attempt exists and less than a single
    /// retry interval has elapsed since it.
    pub fn persistent_should_backoff(
        &self,
        last_attempt_nanos: Option<i64>,
        now_nanos: i64,
    ) -> bool {
        match last_attempt_nanos {
            None => false,
            Some(last) => now_nanos.saturating_sub(last) < self.cfg.retry_duration_nanos,
        }
    }

    // ==================== disconnect / remove ====================

    /// Disconnect the connection with the ID or cancel its pending
    /// attempt; persistent entries stay registered and will be
    /// retried (dcrd `Disconnect`).
    pub fn disconnect(&mut self, id: u64) -> Result<DisconnectAction, ConnmgrError> {
        let is_persistent = self.persistent.contains_key(&id);
        if let Some(info) = self.pending.get(&id).cloned() {
            self.remove_pending_info(id);
            if !is_persistent {
                self.outbound_groups.remove_addr(&info.addr);
            }
            return Ok(DisconnectAction::CancelPending);
        }
        if self.active.contains_key(&id) {
            return Ok(DisconnectAction::CloseConn);
        }
        if is_persistent {
            return Ok(DisconnectAction::None);
        }
        let str = format!("no entries with id {id} exist");
        Err(make_error(ErrorKind::NotFound, &str))
    }

    /// Close, cancel, or remove the connection with the ID across
    /// all states and types; persistent entries are removed so no
    /// future retries occur (dcrd `Remove`).
    pub fn remove(&mut self, id: u64) -> Result<DisconnectAction, ConnmgrError> {
        let is_persistent = self.remove_persistent_entry(id).is_some();
        if let Some(info) = self.pending.get(&id).cloned() {
            self.remove_pending_info(id);
            if !is_persistent {
                self.outbound_groups.remove_addr(&info.addr);
            }
            return Ok(if is_persistent {
                DisconnectAction::CancelPersistentAndPending
            } else {
                DisconnectAction::CancelPending
            });
        }
        if let Some(record) = self.remove_active_conn(id) {
            return Ok(if is_persistent {
                DisconnectAction::CancelPersistentAndClose(record)
            } else {
                DisconnectAction::CloseRemoved(record)
            });
        }
        if is_persistent {
            return Ok(DisconnectAction::CancelPersistent);
        }
        let str = format!("no entries with id {id} exist");
        Err(make_error(ErrorKind::NotFound, &str))
    }

    // ==================== outbound address selection ====================

    /// An address suitable for a new automatic outbound connection
    /// (dcrd `pickOutboundAddr`): calls the address source up to
    /// [`PICK_OUTBOUND_RETRIES`] times, judging each candidate with
    /// [`ConnManager::claim_outbound_candidate`]; the picked address is
    /// registered in the outbound groups and the caller removes it when
    /// no longer used.  The error string for exhaustion is
    /// [`NO_SUITABLE_ADDR_MSG`]; source errors pass through.  The
    /// source returns each candidate's last attempt time (dcrd's
    /// `lastTry time.Time`, the zero [`GoTime`] when it was never
    /// attempted), and `now` is dcrd's `time.Now()`.
    ///
    /// This runs the source with the manager borrowed.  The daemon's
    /// driver instead draws each candidate before taking the manager's
    /// lock and claims it under the lock, because its source takes the
    /// address manager's lock and inbound admission must not wait on
    /// that (dcrd holds only the outbound groups' own mutex here).
    pub fn pick_outbound_addr(
        &mut self,
        get_new_address: &mut dyn FnMut() -> Result<(NetAddress, GoTime), String>,
        now: GoTime,
    ) -> Result<NetAddress, String> {
        for tries in 0..PICK_OUTBOUND_RETRIES {
            let (addr, last_try) = get_new_address()?;
            if self.claim_outbound_candidate(tries, &addr, last_try, now) {
                return Ok(addr);
            }
        }

        Err(NO_SUITABLE_ADDR_MSG.to_string())
    }

    /// One iteration of dcrd `pickOutboundAddr`'s loop: whether the
    /// candidate the address source returned on try `tries` (counting
    /// from 0) is suitable, registering it in the outbound groups when
    /// it is.  Skipped are addresses whose outbound group is already
    /// connected, recently attempted addresses for the first 30 tries,
    /// and non-default ports for the first 50.  "Recently" is Go's
    /// `lastTry.Add(10*time.Minute).After(now)`: running time for an
    /// address attempted in this process, whose attempt time carries a
    /// monotonic reading, and wall-clock time for one loaded from
    /// `peers.json`.
    pub fn claim_outbound_candidate(
        &mut self,
        tries: u32,
        addr: &NetAddress,
        last_try: GoTime,
        now: GoTime,
    ) -> bool {
        const SKIP_RECENTS_UNTIL: u32 = (PICK_OUTBOUND_RETRIES * 3) / 10;
        const SKIP_DEFAULT_PORT_UNTIL: u32 = PICK_OUTBOUND_RETRIES / 2;
        const TEN_MINUTES_NANOS: i64 = 10 * 60 * 1_000_000_000;

        if self.outbound_groups.group_count(addr) >= self.max_per_outbound_group {
            return false;
        }

        if tries < SKIP_RECENTS_UNTIL && last_try.add_nanos(TEN_MINUTES_NANOS).after(now) {
            return false;
        }

        let default_port = self.cfg.default_port;
        if default_port != 0 && tries < SKIP_DEFAULT_PORT_UNTIL && addr.port != default_port {
            return false;
        }

        self.outbound_groups.add_addr(addr);
        true
    }

    /// The active connection record for an ID.
    pub fn active_conn(&self, id: u64) -> Option<ConnRecord> {
        self.active.get(&id).cloned()
    }

    /// The derived backoff scaling bits, for the differential tests.
    #[doc(hidden)]
    pub fn max_retry_scaling_bits_snapshot(&self) -> u8 {
        self.max_retry_scaling_bits
    }

    /// The `(persistent, pending, active, conn_id_by_addr, per_host)`
    /// map sizes, for the differential tests.
    #[doc(hidden)]
    pub fn map_sizes(&self) -> (usize, usize, usize, usize, usize) {
        (
            self.persistent.len(),
            self.pending.len(),
            self.active.len(),
            self.conn_id_by_addr.len(),
            self.per_host_counts.len(),
        )
    }
}

/// The host portion of the address as a map key (dcrd
/// `addrHostKey`, Go's `net.IP.String` over the stored bytes — the
/// address manager's canonical host rendering).
pub fn addr_host_key(addr: &NetAddress) -> String {
    addr.ip_string()
}

/// Go's `net.IP.IsLoopback` over the stored address bytes: 127.0.0.0/8
/// for IPv4 and ::1 for IPv6.
fn is_loopback(ip: &[u8]) -> bool {
    match ip.len() {
        4 => ip[0] == 127,
        16 => {
            if ip[..10] == [0u8; 10] && ip[10] == 0xff && ip[11] == 0xff {
                return ip[12] == 127;
            }
            ip == [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        }
        _ => false,
    }
}

/// dcrd `pickNoun`: the singular or plural form for a count.
fn pick_noun<'a>(n: u64, singular: &'a str, plural: &'a str) -> &'a str {
    if n == 1 { singular } else { plural }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcroxide_addrmgr::{NetAddressType, new_net_address_from_params};
    use dcroxide_wire::ServiceFlag;

    /// A csprng returning scripted values at the interface level,
    /// like dcrd's test PRNG substitution.
    struct ScriptedRng {
        u64s: Vec<u64>,
        u64ns: Vec<u64>,
    }

    impl Csprng for ScriptedRng {
        fn uint64(&mut self) -> u64 {
            self.u64s.remove(0)
        }
        fn uint64n(&mut self, _n: u64) -> u64 {
            self.u64ns.remove(0)
        }
    }

    fn rng() -> ScriptedRng {
        ScriptedRng {
            u64s: vec![1, 2, 3, 4, 5, 6, 7, 8],
            u64ns: vec![0; 8],
        }
    }

    fn v4(last: u8, port: u16) -> NetAddress {
        new_net_address_from_params(
            NetAddressType::IPv4,
            &[192, 0, 2, last],
            port,
            0,
            ServiceFlag(0),
        )
        .expect("test address")
    }

    fn mgr(cfg: ManagerConfig) -> ConnManager {
        ConnManager::new(cfg, &mut rng())
    }

    /// The dial lifecycle: pending blocks duplicates as
    /// ErrAlreadyPending, established as ErrAlreadyConnected, and the
    /// close plan releases what it carries.
    #[test]
    fn dial_lifecycle_and_duplicate_gates() {
        let mut m = mgr(ManagerConfig::default());
        let addr = v4(10, 9108);

        let plan = m.connect_begin(&addr).expect("connect_begin");
        assert!(plan.release_total_sem && plan.remove_outbound_group);
        assert!(!plan.release_host_permit, "per-host limiting disabled");
        assert_eq!(m.total_normal_conns_sem.used(), 1);

        let id = m.begin_dial(&addr, None).expect("begin_dial");
        assert_eq!(id, 1, "IDs start at 1");

        let err = m.begin_dial(&addr, None).expect_err("dup pending");
        assert_eq!(err.kind, ErrorKind::AlreadyPending);
        assert_eq!(
            err.description,
            "a pending connection to 192.0.2.10:9108 already exists"
        );

        let record = m
            .dial_succeeded(id, &addr, ConnectionType::Manual, plan)
            .expect("became active");
        assert_eq!(record.conn_type, ConnectionType::Manual);

        let err = m.begin_dial(&addr, None).expect_err("dup active");
        assert_eq!(err.kind, ErrorKind::AlreadyConnected);
        assert_eq!(
            err.description,
            "a connection to 192.0.2.10:9108 is already established"
        );

        let closed = m.conn_closed(id).expect("close runs the plan");
        assert_eq!(closed.id, id);
        assert_eq!(m.total_normal_conns_sem.used(), 0);
        assert_eq!(m.map_sizes(), (0, 0, 0, 0, 0));
    }

    /// A canceled pending dial makes a late success report a
    /// canceled connection the daemon must close.
    #[test]
    fn canceled_dial_ignores_late_success() {
        let mut m = mgr(ManagerConfig::default());
        let addr = v4(11, 9108);
        let id = m.begin_dial(&addr, None).expect("begin_dial");
        let action = m.disconnect(id).expect("disconnect pending");
        assert!(matches!(action, DisconnectAction::CancelPending));
        assert!(
            m.dial_succeeded(id, &addr, ConnectionType::Outbound, ClosePlan::default())
                .is_none(),
            "late success after cancel is dropped"
        );
        let err = m.disconnect(id).expect_err("gone");
        assert_eq!(err.kind, ErrorKind::NotFound);
        assert_eq!(err.description, format!("no entries with id {id} exist"));
    }

    /// Persistent entries own their address-index key across pending
    /// and active states, disconnect leaves them registered, and
    /// remove drops everything.
    #[test]
    fn persistent_ownership_and_remove() {
        let mut m = mgr(ManagerConfig::default());
        let addr = v4(12, 9108);

        let pid = m.add_persistent(&addr).expect("add_persistent");
        let err = m.add_persistent(&addr).expect_err("dup persistent");
        assert_eq!(err.kind, ErrorKind::DuplicatePersistent);
        assert_eq!(
            err.description,
            "a persistent connection for 192.0.2.12:9108 already exists"
        );
        let err = m.begin_dial(&addr, None).expect_err("fresh dial rejected");
        assert_eq!(err.kind, ErrorKind::DuplicatePersistent);

        // The persistent re-dial passes the connected-only gate.
        let did = m.begin_dial(&addr, Some(pid)).expect("persistent dial");
        assert_eq!(did, pid);
        let record = m
            .dial_succeeded(
                pid,
                &addr,
                ConnectionType::Manual,
                ClosePlan {
                    signal_persistent: Some(pid),
                    ..ClosePlan::default()
                },
            )
            .expect("active");
        assert_eq!(record.close_plan.signal_persistent, Some(pid));

        // Disconnect keeps the entry for retries.
        let action = m.disconnect(pid).expect("disconnect");
        assert!(matches!(action, DisconnectAction::CloseConn));
        assert!(m.is_persistent(pid));

        // Remove cancels the runner and closes the live conn.
        let action = m.remove(pid).expect("remove");
        match action {
            DisconnectAction::CancelPersistentAndClose(rec) => assert_eq!(rec.id, pid),
            other => panic!("unexpected action {other:?}"),
        }
        assert!(!m.is_persistent(pid));
        assert_eq!(m.map_sizes(), (0, 0, 0, 0, 0));

        let err = m.remove(pid).expect_err("already removed");
        assert_eq!(err.kind, ErrorKind::NotFound);
    }

    /// The persistent capacity and per-host gates use dcrd's exact
    /// messages.
    #[test]
    fn persistent_capacity_and_per_host_gates() {
        let mut m = mgr(ManagerConfig {
            max_conns_per_host: 2,
            ..ManagerConfig::default()
        });
        for i in 0..MAX_PERSISTENT {
            m.add_persistent(&v4(20 + i as u8, 9108)).expect("fits");
        }
        let err = m.persistent_capacity_check().expect_err("full");
        assert_eq!(err.kind, ErrorKind::MaxPersistent);
        assert_eq!(
            err.description,
            "a maximum of 8 persistent connections is allowed"
        );

        let mut m = mgr(ManagerConfig {
            max_conns_per_host: 2,
            ..ManagerConfig::default()
        });
        m.add_persistent(&v4(30, 9108)).expect("first");
        m.add_persistent(&v4(30, 9109)).expect("second same host");
        let err = m.add_persistent(&v4(30, 9110)).expect_err("third");
        assert_eq!(err.kind, ErrorKind::MaxPersistentPerHost);
        assert_eq!(
            err.description,
            "a maximum of 2 persistent connections per host is allowed"
        );
    }

    /// Inbound admission: loopback skips rate limiting but still
    /// needs a permit; the normal-connections limit drops with dcrd's
    /// message; duplicates drop.
    #[test]
    fn inbound_admission_gates() {
        let mut m = mgr(ManagerConfig {
            max_normal_conns: 1,
            ..ManagerConfig::default()
        });
        let mut r = rng();
        let loopback = new_net_address_from_params(
            NetAddressType::IPv4,
            &[127, 0, 0, 1],
            5000,
            0,
            ServiceFlag(0),
        )
        .expect("loopback");

        match m.admit_inbound(
            &loopback,
            1_700_000_000,
            1_700_000_000_000_000_000,
            0,
            &mut r,
        ) {
            InboundDecision::Admit {
                require_permit,
                host_permit_reserved,
            } => {
                assert!(require_permit, "loopback still requires a permit");
                assert!(!host_permit_reserved);
            }
            other => panic!("unexpected decision {other:?}"),
        }
        let rec = m.register_inbound(&loopback, true, false);
        assert_eq!(rec.conn_type, ConnectionType::Inbound);

        // The single permit is used; the next inbound drops.
        let addr = v4(40, 5001);
        match m.admit_inbound(&addr, 1_700_000_000, 1_700_000_000_000_000_000, 0, &mut r) {
            InboundDecision::Drop { reason } => {
                assert_eq!(reason, "a maximum of 1 connection is allowed");
            }
            other => panic!("unexpected decision {other:?}"),
        }

        // A duplicate of the registered address drops with the
        // established message.
        match m.admit_inbound(
            &loopback,
            1_700_000_000,
            1_700_000_000_000_000_000,
            0,
            &mut r,
        ) {
            InboundDecision::Drop { reason } => {
                assert_eq!(
                    reason,
                    "a connection to 127.0.0.1:5000 is already established"
                );
            }
            other => panic!("unexpected decision {other:?}"),
        }
    }

    /// `admit_inbound` hands the group limiter its monotonic reading and
    /// keeps the wall clock for the flood window and the cache TTL, as
    /// dcrd's limiter subtracts `time.Now` values monotonically: a group
    /// drained just before the wall clock steps back ten minutes is let
    /// in again five monotonic seconds later.  The drop-log throttle
    /// likewise gets its token back a minute later on that clock.
    #[test]
    fn a_backward_wall_clock_step_does_not_freeze_inbound_admission() {
        let mut m = mgr(ManagerConfig::default());
        let mut r = rng();
        let addr = v4(60, 9108);
        let rate_limited = |decision: &InboundDecision| match decision {
            InboundDecision::Drop { reason } => reason == "rate limited",
            _ => false,
        };
        let wall = 1_700_000_000_000_000_000i64;
        let mono = 5_000_000_000i64;
        for _ in 0..crate::GROUP_BURST_LIMIT {
            let decision = m.admit_inbound(&addr, wall / 1_000_000_000, wall, mono, &mut r);
            assert!(!rate_limited(&decision), "{decision:?}");
        }
        let decision = m.admit_inbound(&addr, wall / 1_000_000_000, wall, mono, &mut r);
        assert!(rate_limited(&decision), "the burst is spent: {decision:?}");
        for _ in 0..crate::DROP_LOG_BURST_LIMIT {
            assert_eq!(
                m.inbound_limiter.log_drops(mono),
                crate::LogDropsOutcome::Logged
            );
        }

        let wall = wall - 600 * 1_000_000_000;
        let mono = mono + 5_000_000_000;
        let decision = m.admit_inbound(&addr, wall / 1_000_000_000, wall, mono, &mut r);
        assert!(!rate_limited(&decision), "a token is back: {decision:?}");
        assert_eq!(
            m.inbound_limiter.log_drops(mono + 55_000_000_000),
            crate::LogDropsOutcome::Logged
        );
    }

    /// A total-connections permit freed while the automatic outbound
    /// fill is parked on it goes straight to the fill, as dcrd's
    /// blocked `totalNormalConnsSem.Acquire` receives it inside the
    /// releasing channel receive: the waker fires, the permit stays
    /// counted, and an inbound connection arriving before the fill runs
    /// again is refused rather than taking the slot.  Without a waiter a
    /// release frees the permit as before.
    #[test]
    fn a_freed_permit_goes_to_the_parked_outbound_fill() {
        let mut m = mgr(ManagerConfig {
            max_normal_conns: 2,
            target_outbound: 1,
            ..ManagerConfig::default()
        });
        let wakes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&wakes);
        m.set_permit_waker(Box::new(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));
        let now_unix = 1_700_000_000;
        let now_nanos = 1_700_000_000_000_000_000;
        let mut r = rng();

        // Two inbound peers take every total permit.
        let mut ids = Vec::new();
        for last in [50, 51] {
            let addr = v4(last, 9108);
            match m.admit_inbound(&addr, now_unix, now_nanos, 0, &mut r) {
                InboundDecision::Admit {
                    require_permit,
                    host_permit_reserved,
                } => ids.push(
                    m.register_inbound(&addr, require_permit, host_permit_reserved)
                        .id,
                ),
                other => panic!("unexpected decision {other:?}"),
            }
        }

        // The fill takes its outbound permit and parks on the total.
        assert!(m.active_outbounds_sem.try_acquire());
        assert!(!m.total_normal_conns_sem.acquire_or_wait());
        assert!(m.total_normal_conns_sem.is_waiting());

        // An inbound close hands its permit to the fill.
        m.conn_closed(ids[0]).expect("close");
        assert_eq!(wakes.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(!m.total_normal_conns_sem.is_waiting());
        assert_eq!(m.total_normal_conns_sem.used(), 2, "the permit stays held");

        // A new inbound peer finds no free slot.
        match m.admit_inbound(&v4(52, 9108), now_unix, now_nanos, 0, &mut r) {
            InboundDecision::Drop { reason } => {
                assert_eq!(reason, "a maximum of 2 connections is allowed");
            }
            other => panic!("unexpected decision {other:?}"),
        }

        // The fill collects the permit exactly once.
        assert!(m.total_normal_conns_sem.take_grant());
        assert!(!m.total_normal_conns_sem.take_grant());

        // With nothing parked, a close frees its permit without a wake.
        m.conn_closed(ids[1]).expect("close");
        assert_eq!(wakes.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(m.total_normal_conns_sem.used(), 1);
    }

    /// A manual connection's unwind hands its permit over the same way.
    #[test]
    fn a_connect_unwind_hands_its_permit_to_the_parked_fill() {
        let mut m = mgr(ManagerConfig {
            max_normal_conns: 1,
            target_outbound: 1,
            ..ManagerConfig::default()
        });
        let wakes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&wakes);
        m.set_permit_waker(Box::new(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));

        let addr = v4(60, 9108);
        let plan = m.connect_begin(&addr).expect("connect_begin");
        assert!(m.active_outbounds_sem.try_acquire());
        assert!(!m.total_normal_conns_sem.acquire_or_wait());

        m.connect_unwind(&addr, &plan);
        assert_eq!(wakes.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(m.total_normal_conns_sem.used(), 1);
        assert!(m.connect_begin(&v4(61, 9108)).is_err(), "no free slot");
        assert!(m.total_normal_conns_sem.take_grant());
    }

    /// backoff_with_jitter: zero retries return zero, the exponential
    /// doubles from half the base, and the growth clamps at the max
    /// retry duration (5s base → scaling bits 30).
    #[test]
    fn backoff_with_jitter_scaling() {
        let m = mgr(ManagerConfig::default());
        let mut r = ScriptedRng {
            u64s: vec![],
            u64ns: vec![0, 7, 0, 0],
        };
        assert_eq!(m.backoff_with_jitter(0, &mut r), 0);
        // retries=1: shift 0, backoff 5s, half 2.5s + jitter 0.
        assert_eq!(m.backoff_with_jitter(1, &mut r), 2_500_000_000);
        // retries=2: shift 1, backoff 10s, half 5s + jitter 7.
        assert_eq!(m.backoff_with_jitter(2, &mut r), 5_000_000_007);
        // retries=7: 5s<<6 = 320s clamps to 300s, half 150s.
        assert_eq!(m.backoff_with_jitter(7, &mut r), 150_000_000_000);
        // Far past the scaling cap the clamp still holds.
        let mut r = ScriptedRng {
            u64s: vec![],
            u64ns: vec![1],
        };
        assert_eq!(
            m.backoff_with_jitter(4_000_000_000, &mut r),
            150_000_000_001
        );
    }

    /// pick_outbound_addr: group-full skips, the recency skip relaxes
    /// after 30 tries, the port preference after 50, and exhaustion
    /// returns dcrd's plain error string.
    #[test]
    fn pick_outbound_addr_thresholds() {
        let mut m = mgr(ManagerConfig {
            default_port: 9108,
            ..ManagerConfig::default()
        });
        let now_nanos = GoTime::wall(1_700_000_000_000_000_000i64);
        let now_secs = 1_700_000_000i64;

        // A fresh non-default-port address is skipped for 50 tries
        // and then accepted.
        let addr = v4(50, 19108);
        let mut calls = 0u32;
        let picked = m
            .pick_outbound_addr(
                &mut || {
                    calls += 1;
                    Ok((addr.clone(), GoTime::default()))
                },
                now_nanos,
            )
            .expect("picked after port preference relaxes");
        assert_eq!(picked.port, 19108);
        assert_eq!(calls, 51, "50 skips then accept");

        // Its group (the /16) is now taken: same-group candidates
        // exhaust all 100 tries.
        let same_group = v4(51, 9108);
        let err = m
            .pick_outbound_addr(
                &mut || Ok((same_group.clone(), GoTime::default())),
                now_nanos,
            )
            .expect_err("group filled");
        assert_eq!(err, NO_SUITABLE_ADDR_MSG);

        // A recently tried address in a fresh group is skipped for 30
        // tries; the exact 10-minute boundary is not "recent".
        let mut m = mgr(ManagerConfig {
            default_port: 9108,
            ..ManagerConfig::default()
        });
        let recent = v4(60, 9108);
        let mut calls = 0u32;
        let picked = m
            .pick_outbound_addr(
                &mut || {
                    calls += 1;
                    Ok((
                        recent.clone(),
                        GoTime::wall((now_secs - 60) * 1_000_000_000),
                    ))
                },
                now_nanos,
            )
            .expect("picked after recency relaxes");
        assert_eq!(picked.port, 9108);
        assert_eq!(calls, 31, "30 skips then accept");

        let mut m = mgr(ManagerConfig {
            default_port: 9108,
            ..ManagerConfig::default()
        });
        let boundary = v4(61, 9108);
        let mut calls = 0u32;
        m.pick_outbound_addr(
            &mut || {
                calls += 1;
                Ok((
                    boundary.clone(),
                    GoTime::wall((now_secs - 600) * 1_000_000_000),
                ))
            },
            now_nanos,
        )
        .expect("exactly ten minutes ago is not recent");
        assert_eq!(calls, 1);

        // Source errors pass through immediately.
        let mut m = mgr(ManagerConfig::default());
        let err = m
            .pick_outbound_addr(
                &mut || Err("no valid connect address".to_string()),
                now_nanos,
            )
            .expect_err("source error");
        assert_eq!(err, "no valid connect address");
    }
}
