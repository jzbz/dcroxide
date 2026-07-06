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
/// `MaxProtocolVersion`).
pub const MAX_PROTOCOL_VERSION: u32 = dcroxide_wire::BATCHED_CFILTERS_V2_VERSION;

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

/// The message transport version negotiation runs over.  The daemon
/// implements this with dcrd's wire framing over the connection
/// (including the read deadline and byte accounting); tests script
/// it.
pub trait MsgTransport {
    /// Read the next message from the remote peer.
    fn read_message(&mut self) -> Result<Message, String>;
    /// Write a message to the remote peer.
    fn write_message(&mut self, msg: &Message) -> Result<(), String>;
}
