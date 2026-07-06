// SPDX-License-Identifier: ISC
//! Concurrency safe address manager for caching potential peers on
//! the Decred network, mirroring dcrd's `addrmgr` package at
//! `release-v2.1.5`: network address types with dcrd's key and group
//! key formatting, the RFC-range classification and reachability
//! rules, known-address viability tracking, the new/tried bucket
//! machinery over BLAKE-256 bucket derivation, local address
//! bookkeeping, and the `peers.json` serialization.
//!
//! dcrd guards the manager with mutexes and persists peers from a
//! ticker goroutine; this port is synchronous with identical state
//! transitions, and both the clock and the random source are
//! injectable so every path is deterministic under test.

use core::fmt;

mod manager;
mod netaddress;
mod network;

pub use manager::{
    AddrManager, AddrRng, AddressPriority, Clock, KnownAddress, KnownAddressRef, LocalAddr,
    NEW_BUCKET_COUNT, NetAddressReach, PEERS_FILENAME, SystemRng, TRIED_BUCKET_COUNT,
};
pub use netaddress::{
    NetAddress, encode_host, new_net_address_from_ip_port, new_net_address_from_params,
};
pub use network::{NetAddressType, NetAddressTypeFilter, is_routable};

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
}

impl ErrorKind {
    /// dcrd's name for this error kind.
    pub fn kind_name(self) -> &'static str {
        match self {
            ErrorKind::AddressNotFound => "ErrAddressNotFound",
            ErrorKind::UnknownAddressType => "ErrUnknownAddressType",
            ErrorKind::MismatchedAddressType => "ErrMismatchedAddressType",
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
