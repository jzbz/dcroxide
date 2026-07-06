// SPDX-License-Identifier: ISC
//! An implementation of dcrd's `connmgr` package: dynamic ban scores,
//! the connection manager, HTTPS seeding, and Tor DNS resolution.
//!
//! dcrd's goroutines, channels, and timers are daemon-phase
//! concurrency; the ports are synchronous with identical state
//! transitions, network transports are injectable traits, and timer
//! arms are returned as events for the daemon to drive.

mod banscore;
mod connmanager;
pub mod goexp;
mod seed;
mod tor;

pub use banscore::{DynamicBanScore, HALFLIFE, LIFETIME, decay_factor_bits};
pub use connmanager::{
    Config, Conn, ConnManager, ConnReq, ConnState, DEFAULT_RETRY_DURATION, DEFAULT_TARGET_OUTBOUND,
    Event, MAX_FAILED_ATTEMPTS, MAX_RETRY_DURATION, ReqAddr,
};
pub use seed::{
    DURATION_3_DAYS, DURATION_4_DAYS, HttpsSeederFilters, SeedEnv, SeederTransport, seed_addrs,
    seeder_url,
};
pub use tor::{TorTransport, tor_lookup_ip};

/// A kind of connection manager error (dcrd `ErrorKind`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// Dial cannot be nil in the configuration.
    DialNil,
    /// Dial and DialAddr cannot both be specified.
    BothDialsFilled,
    /// An invalid address was returned by the Tor DNS resolver.
    TorInvalidAddressResponse,
    /// The Tor proxy returned a response in an unexpected format.
    TorInvalidProxyResponse,
    /// The authentication method is not recognized.
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
    /// The tor request TTL expired.
    TorTTLExpired,
    /// The tor command is not supported.
    TorCmdNotSupported,
    /// The tor address type is not supported.
    TorAddrNotSupported,
    /// A transport-level failure outside dcrd's kinds, carrying the
    /// underlying I/O error text.
    Transport,
}

impl ErrorKind {
    /// The dcrd constant name for the kind, as printed by the Go
    /// `ErrorKind.Error` method.
    pub fn kind_name(self) -> &'static str {
        match self {
            ErrorKind::DialNil => "ErrDialNil",
            ErrorKind::BothDialsFilled => "ErrBothDialsFilled",
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
            ErrorKind::Transport => "Transport",
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
