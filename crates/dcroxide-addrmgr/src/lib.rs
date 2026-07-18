// SPDX-License-Identifier: ISC
//! Concurrency safe address manager for caching potential peers on
//! the Decred network, mirroring dcrd's `addrmgr` package at master
//! `452c1a6c` (the 2.2 pre-release): network address types with
//! dcrd's key and group key formatting including Tor v3 onion
//! addresses, the RFC-range classification and reachability rules,
//! known-address viability tracking, the new/tried bucket machinery
//! over BLAKE-256 bucket derivation with per-bucket type statistics
//! and filtered address selection, local address bookkeeping, the
//! `peers.json` serialization, and the HTTPS seeder and Tor DNS
//! resolution dcrd 2.2 relocated into this package.
//!
//! dcrd guards the manager with mutexes and persists peers from a
//! ticker goroutine; this port is synchronous with identical state
//! transitions, and both the clock and the random source are
//! injectable so every path is deterministic under test.

use core::fmt;

mod manager;
mod netaddress;
mod network;
mod seed;
mod tordns;

pub use manager::{
    AddrManager, AddrRng, AddressPriority, Clock, KnownAddress, KnownAddressRef, LocalAddr,
    NEW_BUCKET_COUNT, NetAddressReach, PEERS_FILENAME, SystemRng, TRIED_BUCKET_COUNT,
};
pub use netaddress::{
    NetAddress, encode_host, new_net_address_from_ip_port, new_net_address_from_params,
};
pub use network::{NetAddressType, NetAddressTypeFilter, is_routable};
pub use seed::{
    DURATION_3_DAYS, DURATION_4_DAYS, HttpsSeederFilters, MAX_RESP_SIZE, SeedEnv, SeederTransport,
    seed_addrs, seeder_url,
};
pub use tordns::{TorTransport, tor_lookup_ip};

/// The kind of an address manager error; each variant's
/// [`kind_name`](ErrorKind::kind_name) matches dcrd's `ErrorKind`
/// string exactly.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// An operation failed due to an address lookup failure.
    AddressNotFound,
    /// The network address type could not be determined.
    UnknownAddressType,
    /// A network address' derived type does not match the expected
    /// type.
    MismatchedAddressType,
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
    /// underlying I/O error text; this is the port's seam for the
    /// injectable transports, not a dcrd kind.
    Transport,
}

impl ErrorKind {
    /// dcrd's name for this error kind.
    pub fn kind_name(self) -> &'static str {
        match self {
            ErrorKind::AddressNotFound => "ErrAddressNotFound",
            ErrorKind::UnknownAddressType => "ErrUnknownAddressType",
            ErrorKind::MismatchedAddressType => "ErrMismatchedAddressType",
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

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind_name())
    }
}

/// An address manager error (dcrd `Error`): a kind plus a
/// human-readable description.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrError {
    /// The kind of error that occurred.
    pub kind: ErrorKind,
    /// The human-readable description.
    pub description: String,
}

impl fmt::Display for AddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.description)
    }
}

impl std::error::Error for AddrError {}

pub(crate) fn make_error(kind: ErrorKind, description: impl Into<String>) -> AddrError {
    AddrError {
        kind,
        description: description.into(),
    }
}
