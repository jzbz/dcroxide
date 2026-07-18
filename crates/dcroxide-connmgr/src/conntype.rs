// SPDX-License-Identifier: ISC
//! Connection types (dcrd `internal/connmgr` `ConnectionType`, new in
//! dcrd 2.2's connection manager rewrite).

use std::fmt;

/// The different types of supported connections (dcrd
/// `ConnectionType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ConnectionType {
    /// The connection was established by a remote peer.  No further
    /// details are known about this connection until a handshake
    /// takes place (dcrd `ConnTypeInbound`).
    Inbound = 0,
    /// A normal outbound connection that was established with no
    /// additional restrictions imposed on the type of information the
    /// local peer is willing to relay (dcrd `ConnTypeOutbound`).
    Outbound = 1,
    /// An outbound connection that was manually requested via
    /// `Connect` or `AddPersistent` — in practice the result of an
    /// RPC method (e.g. "node connect") or command line options
    /// (e.g. --addpeer and --connect) (dcrd `ConnTypeManual`).
    Manual = 2,
}

/// The number of connection types (dcrd `numConnTypes`).
pub const NUM_CONN_TYPES: u8 = 3;

impl fmt::Display for ConnectionType {
    /// The human-readable form (dcrd `ConnectionType.String`); the
    /// port's enum cannot hold dcrd's out-of-range values, so the
    /// "Unknown ConnectionType (%d)" fallback lives in
    /// [`conn_type_string`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ConnectionType::Inbound => "inbound",
            ConnectionType::Outbound => "outbound",
            ConnectionType::Manual => "manual",
        })
    }
}

/// The human-readable form of a raw connection type value, including
/// dcrd's fallback for values outside the enum (dcrd
/// `ConnectionType.String` over its uint8-typed constant).
pub fn conn_type_string(raw: u8) -> String {
    match raw {
        0 => "inbound".to_string(),
        1 => "outbound".to_string(),
        2 => "manual".to_string(),
        other => format!("Unknown ConnectionType ({other})"),
    }
}
