// SPDX-License-Identifier: ISC
//! The protocol decision core of dcrd's `peer` package: version
//! negotiation, local version construction, the push message
//! builders with their duplicate-request filters, ping/pong state,
//! known-inventory tracking, the stall deadline table, and the
//! configuration surface.
//!
//! dcrd wraps this core in goroutine pumps — the input, output,
//! queue, and stall handlers plus connection association — which are
//! daemon-phase concurrency.  The port is synchronous: message I/O
//! goes through a caller-provided [`MsgTransport`], the wall clock
//! and randomness come from a [`PeerEnv`], the state dcrd keeps in
//! package globals (the peer id counter and the sent version nonces)
//! lives in an explicit [`PeerGlobals`], and messages dcrd queues to
//! its output channel are returned to the caller to send.

mod deadline;
mod netaddress;
mod peer;

pub use deadline::maybe_add_deadline;
pub use netaddress::{PeerAddr, new_net_address};
pub use peer::{Config, NegotiateError, Peer, PeerEnv, PeerGlobals, StatsSnap};

use dcroxide_wire::Message;

/// The max protocol version the peer supports (dcrd
/// `MaxProtocolVersion`, the addrv2 version since dcrd 2.2).
pub const MAX_PROTOCOL_VERSION: u32 = dcroxide_wire::ADDR_V2_VERSION;

/// The maximum amount of inventory in a single inv message when
/// trickling (dcrd `maxInvTrickleSize`).
pub const MAX_INV_TRICKLE_SIZE: usize = 1000;

/// The maximum number of known-inventory cache items (dcrd
/// `maxKnownInventory`).
pub const MAX_KNOWN_INVENTORY: u32 = 1000;

/// The known-inventory expiry, in nanoseconds (dcrd
/// `maxKnownInventoryTTL`).
pub const MAX_KNOWN_INVENTORY_TTL: i64 = 15 * 60 * 1_000_000_000;

/// The lower bound of the random inventory trickle delay, in
/// nanoseconds (dcrd `minInvTrickleTimeout`).
pub const MIN_INV_TRICKLE_TIMEOUT: i64 = 100 * 1_000_000;

/// The upper bound of the random inventory trickle delay, in
/// nanoseconds (dcrd `maxInvTrickleTimeout`).
pub const MAX_INV_TRICKLE_TIMEOUT: i64 = 500 * 1_000_000;

/// The duration of inactivity before version negotiation times out,
/// in nanoseconds (dcrd `negotiateTimeout`); enforced by the daemon.
pub const NEGOTIATE_TIMEOUT: i64 = 30 * 1_000_000_000;

/// The interval between stall checks, in nanoseconds (dcrd
/// `stallTickInterval`).
pub const STALL_TICK_INTERVAL: i64 = 15 * 1_000_000_000;

/// The base response deadline for messages that expect a response, in
/// nanoseconds (dcrd `stallResponseTimeout`).
pub const STALL_RESPONSE_TIMEOUT: i64 = 30 * 1_000_000_000;

/// The default duration of inactivity before a peer is timed out, in
/// nanoseconds (dcrd `defaultIdleTimeout`).
pub const DEFAULT_IDLE_TIMEOUT: i64 = 120 * 1_000_000_000;

/// The interval between pings, in nanoseconds (dcrd `pingInterval`).
pub const PING_INTERVAL: i64 = DEFAULT_IDLE_TIMEOUT - 13 * 1_000_000_000;

/// The size of the sent version nonce cache (dcrd `sentNonces`).
pub const SENT_NONCES_LIMIT: u32 = 50;

/// A transport read failure, classified so the daemon can mirror
/// dcrd's `OnRead` ban for wire-protocol violations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadError {
    /// The error text (dcrd's error string).
    pub message: String,
    /// Whether the failure was a wire-protocol violation (dcrd's
    /// `wire.ErrorCode`) rather than an IO or timeout failure.
    pub wire_violation: bool,
}

impl ReadError {
    /// An IO-classified read failure.
    pub fn io(message: impl Into<String>) -> ReadError {
        ReadError {
            message: message.into(),
            wire_violation: false,
        }
    }

    /// A wire-protocol violation.
    pub fn wire(message: impl Into<String>) -> ReadError {
        ReadError {
            message: message.into(),
            wire_violation: true,
        }
    }
}

impl core::fmt::Display for ReadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

/// The message transport version negotiation runs over.  The daemon
/// implements this with dcrd's wire framing over the connection
/// (including the read deadline and byte accounting); tests script
/// it.
pub trait MsgTransport {
    /// Read the next message from the remote peer.
    fn read_message(&mut self) -> Result<Message, ReadError>;
    /// Write a message to the remote peer.
    fn write_message(&mut self, msg: &Message) -> Result<(), String>;
    /// Adopt the negotiated protocol version for subsequent frames.
    /// dcrd frames every read at the peer's live `ProtocolVersion`,
    /// which the version exchange lowers before the verack phase — a
    /// legacy peer's pre-verack messages must decode at the
    /// negotiated version, not the local maximum.  Transports without
    /// version-dependent framing ignore it.
    fn set_protocol_version(&mut self, _pver: u32) {}
    /// The cumulative bytes read off the underlying connection, so the
    /// serving loops can attribute per-message deltas to the peer's
    /// receive counters (dcrd's `readMessage` returning the byte count
    /// it adds to `bytesReceived`).  Transports that do not track it
    /// report zero and the accounting is skipped.
    fn total_bytes_read(&self) -> u64 {
        0
    }
    /// The cumulative bytes written to the underlying connection (the
    /// send-side counterpart, dcrd's `writeMessage` count).
    fn total_bytes_written(&self) -> u64 {
        0
    }
}
