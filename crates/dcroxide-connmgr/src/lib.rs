// SPDX-License-Identifier: ISC
//! An implementation of dcrd's `connmgr` package: dynamic ban scores
//! and the connection manager.  dcrd 2.2 relocated the HTTPS seeding
//! and Tor DNS resolution into `addrmgr`; they live in
//! `dcroxide-addrmgr` accordingly.
//!
//! dcrd's goroutines, channels, and timers are daemon-phase
//! concurrency; the ports are synchronous with identical state
//! transitions, network transports are injectable traits, and timer
//! arms are returned as events for the daemon to drive.

mod banscore;
mod connmanager;
pub mod goexp;

pub use banscore::{DynamicBanScore, HALFLIFE, LIFETIME, decay_factor_bits};
pub use connmanager::{
    Config, Conn, ConnManager, ConnReq, ConnState, DEFAULT_RETRY_DURATION, DEFAULT_TARGET_OUTBOUND,
    Event, MAX_FAILED_ATTEMPTS, MAX_RETRY_DURATION, ReqAddr,
};

/// A kind of connection manager error (dcrd `ErrorKind`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// Dial cannot be nil in the configuration.
    DialNil,
    /// Dial and DialAddr cannot both be specified.
    BothDialsFilled,
}

impl ErrorKind {
    /// The dcrd constant name for the kind, as printed by the Go
    /// `ErrorKind.Error` method.
    pub fn kind_name(self) -> &'static str {
        match self {
            ErrorKind::DialNil => "ErrDialNil",
            ErrorKind::BothDialsFilled => "ErrBothDialsFilled",
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
