// SPDX-License-Identifier: ISC
//! An implementation of dcrd 2.2's `internal/connmgr` package:
//! dynamic ban scores and the rewritten connection manager decision
//! core (inbound anti-flood admission, outbound group spreading,
//! per-host permits, and persistent retry policy).  dcrd 2.2
//! relocated the HTTPS seeding and Tor DNS resolution into
//! `addrmgr`; they live in `dcroxide-addrmgr` accordingly.
//!
//! dcrd's goroutines, channels, and timers are daemon-phase
//! concurrency; the ports are synchronous with identical state
//! transitions, network transports are injectable traits, and timer
//! arms are returned as events for the daemon to drive.

mod banscore;
mod conntype;
mod csprng;
pub mod goexp;
mod groups;
pub mod manager;
mod ratelimiter;

pub use banscore::{DynamicBanScore, HALFLIFE, LIFETIME, decay_factor_bits};
pub use conntype::{ConnectionType, NUM_CONN_TYPES, conn_type_string};
pub use csprng::{Csprng, SystemCsprng};
pub use groups::OutboundGroupInfo;
pub use manager::{
    ClosePlan, ConnManager, ConnRecord, DEFAULT_MAX_NORMAL_CONNS, DEFAULT_MAX_PER_OUTBOUND_GROUP,
    DEFAULT_MAX_RETRY_DURATION, DEFAULT_RETRY_DURATION, DEFAULT_TARGET_OUTBOUND, DisconnectAction,
    InboundDecision, MAX_FAILED_ATTEMPTS, MAX_PERSISTENT, ManagerConfig, NO_SUITABLE_ADDR_MSG,
    PersistentEntry, SemCount, addr_host_key,
};
pub use ratelimiter::{
    DROP_LOG_BURST_LIMIT, DROP_LOG_RATE_LIMIT, FLOOD_HIGH_FACTOR, FLOOD_LOW, FLOOD_MAX_DROP_PROB,
    FLOOD_MIN_DROP_PROB, FLOOD_RAMP, GROUP_BURST_LIMIT, GROUP_RATE_LIMIT, InboundGroupKey,
    InboundRateLimiter, LogDropsOutcome, MAX_GROUP_LIMITERS, MAX_PER_GROUP_TTL,
};

/// A kind of connection manager error (dcrd `internal/connmgr`
/// `ErrorKind` at master).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// Dial cannot be nil in the configuration.
    DialNil,
    /// An attempt to connect to an address that already has a pending
    /// connection attempt.
    AlreadyPending,
    /// An attempt to connect to an address that already has an
    /// established connection.
    AlreadyConnected,
    /// A connection attempt would exceed the maximum allowed number
    /// of normal connections.
    MaxNormalConns,
    /// A connection attempt would exceed the maximum allowed number
    /// of connections per host.
    MaxConnsPerHost,
    /// An attempt to add more than the maximum allowed number of
    /// persistent connections.
    MaxPersistent,
    /// An attempt to add more than the maximum allowed number of
    /// persistent connections with the same host address.
    MaxPersistentPerHost,
    /// An attempt to add a persistent connection to an address that
    /// already exists.
    DuplicatePersistent,
    /// A specified connection ID or address is unknown to the
    /// connection manager.
    NotFound,
    /// An address is either an unsupported type or unrecognized due
    /// to being malformed.
    UnsupportedAddr,
    /// The connection manager is shutting down or already has.
    Shutdown,
    /// An invalid address was returned by the Tor DNS resolver.
    TorInvalidAddressResponse,
    /// The Tor proxy returned a response in an unexpected format.
    TorInvalidProxyResponse,
    /// The authentication method provided is not recognized.
    TorUnrecognizedAuthMethod,
    /// A general tor error.
    TorGeneralError,
    /// Tor connections are not allowed.
    TorNotAllowed,
    /// The tor network is unreachable.
    TorNetUnreachable,
    /// The tor host is unreachable.
    TorHostUnreachable,
    /// The tor connection was refused.
    TorConnectionRefused,
    /// The tor request Time-To-Live (TTL) expired.
    TorTTLExpired,
    /// The tor command is not supported.
    TorCmdNotSupported,
    /// The tor address type is not supported.
    TorAddrNotSupported,
}

impl ErrorKind {
    /// The dcrd constant name for the kind, as printed by the Go
    /// `ErrorKind.Error` method.
    pub fn kind_name(self) -> &'static str {
        match self {
            ErrorKind::DialNil => "ErrDialNil",
            ErrorKind::AlreadyPending => "ErrAlreadyPending",
            ErrorKind::AlreadyConnected => "ErrAlreadyConnected",
            ErrorKind::MaxNormalConns => "ErrMaxNormalConns",
            ErrorKind::MaxConnsPerHost => "ErrMaxConnsPerHost",
            ErrorKind::MaxPersistent => "ErrMaxPersistent",
            ErrorKind::MaxPersistentPerHost => "ErrMaxPersistentPerHost",
            ErrorKind::DuplicatePersistent => "ErrDuplicatePersistent",
            ErrorKind::NotFound => "ErrNotFound",
            ErrorKind::UnsupportedAddr => "ErrUnsupportedAddr",
            ErrorKind::Shutdown => "ErrShutdown",
            ErrorKind::TorInvalidAddressResponse => "ErrTorInvalidAddressResponse",
            ErrorKind::TorInvalidProxyResponse => "ErrTorInvalidProxyResponse",
            ErrorKind::TorUnrecognizedAuthMethod => "ErrTorUnrecognizedAuthMethod",
            ErrorKind::TorGeneralError => "ErrTorGeneralError",
            ErrorKind::TorNotAllowed => "ErrTorNotAllowed",
            ErrorKind::TorNetUnreachable => "ErrTorNetUnreachable",
            ErrorKind::TorHostUnreachable => "ErrTorHostUnreachable",
            ErrorKind::TorConnectionRefused => "ErrTorConnectionRefused",
            ErrorKind::TorTTLExpired => "ErrTorTTLExpired",
            ErrorKind::TorCmdNotSupported => "ErrTorCmdNotSupported",
            ErrorKind::TorAddrNotSupported => "ErrTorAddrNotSupported",
        }
    }
}

/// An error related to the connection manager (dcrd `Error`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnmgrError {
    /// The kind of error.
    pub kind: ErrorKind,
    /// The human-readable description.
    pub description: String,
}

impl core::fmt::Display for ConnmgrError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.description)
    }
}

impl std::error::Error for ConnmgrError {}

/// Create a [`ConnmgrError`] given a set of arguments (dcrd
/// `MakeError`).
pub(crate) fn make_error(kind: ErrorKind, description: &str) -> ConnmgrError {
    ConnmgrError {
        kind,
        description: description.to_string(),
    }
}
