// SPDX-License-Identifier: ISC
//! The pipe-based IPC lifecycle protocol (dcrd `ipc.go`): the binary
//! message format parent processes like Decrediton consume over the
//! `--pipetx` descriptor.  Messages are encoded as:
//!
//!   - Protocol version (1 byte, currently 1)
//!   - Message type length (1 byte)
//!   - Message type string (encoded as UTF8, no longer than 255 bytes)
//!   - Message payload length (4 bytes, little endian)
//!   - Message payload bytes
//!
//! The pipe reader/writer loops and the outgoing message channel are
//! daemon runtime; this module owns the message set and its exact
//! encoding.

// Length arithmetic over the bounded message header.
#![allow(clippy::arithmetic_side_effects)]

/// The IPC protocol version.
const PROTOCOL_VERSION: u8 = 1;

/// A lifetime event kind (dcrd `lifetimeEventID`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifetimeEventId {
    /// The startup event is about to run.
    StartupEvent = 0,
    /// All startup tasks have completed.
    StartupComplete = 1,
    /// The shutdown event is about to run.
    ShutdownEvent = 2,
}

/// A lifetime event subject (dcrd `lifetimeAction`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifetimeAction {
    /// Database opening/closing.
    DbOpen = 0,
    /// Peer-to-peer server starting/stopping.
    P2pServer = 1,
}

/// A message sent over the notification pipe (dcrd `pipeMessage`
/// implementations).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipeMessage {
    /// A startup or shutdown event (type "lifetimeevent"); the
    /// action byte is ignored for startup completion.
    LifetimeEvent {
        /// The event kind.
        event: LifetimeEventId,
        /// The event subject.
        action: LifetimeAction,
    },
    /// A bound local address for the P2P interface (type
    /// "p2plistenaddr").
    BoundP2pListenAddr(String),
    /// A bound local address for the RPC interface (type
    /// "rpclistenaddr").
    BoundRpcListenAddr(String),
}

impl PipeMessage {
    /// The startup event notification (dcrd `notifyStartupEvent`).
    pub fn startup_event(action: LifetimeAction) -> PipeMessage {
        PipeMessage::LifetimeEvent {
            event: LifetimeEventId::StartupEvent,
            action,
        }
    }

    /// The startup completion notification (dcrd
    /// `notifyStartupComplete`; the action byte is zero).
    pub fn startup_complete() -> PipeMessage {
        PipeMessage::LifetimeEvent {
            event: LifetimeEventId::StartupComplete,
            action: LifetimeAction::DbOpen,
        }
    }

    /// The shutdown event notification (dcrd
    /// `notifyShutdownEvent`).
    pub fn shutdown_event(action: LifetimeAction) -> PipeMessage {
        PipeMessage::LifetimeEvent {
            event: LifetimeEventId::ShutdownEvent,
            action,
        }
    }

    /// The message type string (dcrd `pipeMessage.Type`).
    pub fn type_str(&self) -> &'static str {
        match self {
            PipeMessage::LifetimeEvent { .. } => "lifetimeevent",
            PipeMessage::BoundP2pListenAddr(_) => "p2plistenaddr",
            PipeMessage::BoundRpcListenAddr(_) => "rpclistenaddr",
        }
    }

    /// The message payload bytes (dcrd `pipeMessage.WritePayload`).
    pub fn payload(&self) -> Vec<u8> {
        match self {
            PipeMessage::LifetimeEvent { event, action } => {
                vec![*event as u8, *action as u8]
            }
            PipeMessage::BoundP2pListenAddr(addr) | PipeMessage::BoundRpcListenAddr(addr) => {
                addr.as_bytes().to_vec()
            }
        }
    }

    /// The complete framed message exactly as dcrd's
    /// `serviceControlPipeTx` writes it.
    pub fn encode(&self) -> Vec<u8> {
        let mtype = self.type_str();
        let payload = self.payload();
        let mut out = Vec::with_capacity(1 + 1 + mtype.len() + 4 + payload.len());
        out.push(PROTOCOL_VERSION);
        out.push(mtype.len() as u8);
        out.extend_from_slice(mtype.as_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&payload);
        out
    }
}
