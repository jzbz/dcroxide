// SPDX-License-Identifier: ISC
//! The per-peer message loops — dcrd `peer.go`'s `inHandler`,
//! `outHandler`, and `pingHandler`.
//!
//! Once the version handshake completes the daemon reads messages in a
//! loop, giving the protocol-level messages their fixed handling (a
//! duplicate version or verack disconnects, a ping is answered with a
//! pong, a pong updates the ping statistics, and a sendheaders records
//! the peer's preference) and forwarding every message to the server's
//! handlers.  The dispatch itself is a decision core over the ported
//! [`Peer`] handlers ([`classify_incoming`]); [`run_peer_input`] is the
//! read loop, [`run_peer_output`] the write loop draining the
//! [`OutboundQueue`], and [`run_ping_timer`] the periodic keepalive.
//!
//! dcrd runs these as separate goroutines sharing the peer under its
//! mutexes, so the peer is passed as a `&Mutex<Peer>` and every write to
//! the connection — including the input loop's protocol replies and the
//! keepalive pings — goes through the outbound queue, keeping all writes
//! on the single output loop.  The blocking read is taken without the
//! peer lock held so the ping timer and the server make progress.  The
//! stall detector and the inventory trickle queue arrive later.  The
//! idle read deadline is applied by the caller on the underlying stream
//! (`TcpStream::set_read_timeout`); a read timeout ends the loop exactly
//! like dcrd's idle disconnect.

use std::sync::{Mutex, mpsc};
use std::time::Duration;

use dcroxide_peer::{MsgTransport, Peer, PeerEnv};
use dcroxide_wire::{Message, MsgPing};

/// The protocol-level handling an incoming message calls for, before it
/// is forwarded to the server handlers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncomingAction {
    /// Drop the connection with dcrd's reason (a second version or a
    /// second verack).
    Disconnect(&'static str),
    /// Process the message: send `reply` if present, then forward the
    /// message to the server.
    Process {
        /// An immediate protocol reply (the pong answering a ping),
        /// boxed to keep the action small.
        reply: Option<Box<Message>>,
    },
}

/// Why an input or output loop stopped.
#[derive(Debug)]
pub enum DisconnectReason {
    /// A protocol violation with dcrd's reason string.
    Protocol(&'static str),
    /// Reading the next message failed (a closed connection or an idle
    /// read timeout).
    ReadError(String),
    /// Writing a message failed.
    WriteError(String),
    /// The outbound queue was closed, so the output loop finished (a
    /// locally initiated shutdown).
    LocalShutdown,
}

/// Give an incoming message its protocol-level handling, updating the
/// peer state and returning the action the loop should take (dcrd
/// `inHandler`'s message switch).
pub fn classify_incoming<E: PeerEnv>(
    peer: &mut Peer,
    msg: &Message,
    env: &mut E,
) -> IncomingAction {
    match msg {
        // Only one version message is allowed per peer.
        Message::Version(_) => IncomingAction::Disconnect("duplicate version message"),

        Message::VerAck => {
            if peer.verack_received() {
                IncomingAction::Disconnect("duplicate verack message")
            } else {
                peer.handle_verack_msg();
                IncomingAction::Process { reply: None }
            }
        }

        Message::Ping(ping) => IncomingAction::Process {
            reply: Some(Box::new(peer.handle_ping_msg(ping))),
        },

        Message::Pong(pong) => {
            peer.handle_pong_msg(env, pong);
            IncomingAction::Process { reply: None }
        }

        Message::SendHeaders => {
            peer.handle_send_headers_msg();
            IncomingAction::Process { reply: None }
        }

        // Everything else is handed straight to the server handlers.
        _ => IncomingAction::Process { reply: None },
    }
}

/// Queue the verack that follows a successful negotiation (dcrd
/// `start`'s `QueueMessage(NewMsgVerAck())`).
pub fn send_verack(outbound: &OutboundQueue) -> Result<(), String> {
    outbound.queue_message(Message::VerAck)
}

/// Read and dispatch messages until the peer disconnects.  Each message
/// is given its protocol-level handling (queueing any immediate reply on
/// the outbound queue) and then forwarded to `on_message` for the server
/// handlers, mirroring dcrd's `inHandler`.
pub fn run_peer_input<T, E, F>(
    peer: &Mutex<Peer>,
    transport: &mut T,
    env: &mut E,
    outbound: &OutboundQueue,
    mut on_message: F,
) -> DisconnectReason
where
    T: MsgTransport,
    E: PeerEnv,
    F: FnMut(&mut Peer, &Message),
{
    loop {
        // Read without the peer lock held so the ping timer and the
        // server keep making progress while this thread blocks.
        let msg = match transport.read_message() {
            Ok(msg) => msg,
            Err(e) => return DisconnectReason::ReadError(e),
        };

        let mut peer = peer.lock().expect("peer mutex poisoned");
        match classify_incoming(&mut peer, &msg, env) {
            IncomingAction::Disconnect(reason) => return DisconnectReason::Protocol(reason),
            IncomingAction::Process { reply } => {
                // Immediate replies go through the outbound queue so all
                // writes stay serialized on the output loop; a closed
                // queue means the output loop already stopped.
                if let Some(reply) = reply
                    && outbound.queue_message(*reply).is_err()
                {
                    return DisconnectReason::LocalShutdown;
                }
                on_message(&mut peer, &msg);
            }
        }
    }
}

/// A handle for originating messages to a peer (dcrd `QueueMessage`).
///
/// The server, the input pump's replies, and the ping timer send
/// through clones of this handle; a single output loop drains the
/// receiver and does the actual writing, so all writes to the
/// connection are serialized on one thread.  dcrd's separate inventory
/// trickle queue (`QueueInventory`) and the send semaphore are
/// refinements that arrive later; this is the plain message queue.
#[derive(Clone)]
pub struct OutboundQueue {
    sender: mpsc::Sender<Message>,
}

impl OutboundQueue {
    /// Create an outbound queue and the receiver its output loop drains.
    pub fn channel() -> (OutboundQueue, mpsc::Receiver<Message>) {
        let (sender, receiver) = mpsc::channel();
        (OutboundQueue { sender }, receiver)
    }

    /// Queue a message to be sent to the peer.  Fails only once the
    /// output loop has stopped and dropped the receiver.
    pub fn queue_message(&self, msg: Message) -> Result<(), String> {
        self.sender
            .send(msg)
            .map_err(|_| "peer output queue is closed".to_string())
    }
}

/// Write queued messages to the peer until the outbound queue is closed
/// or a write fails (dcrd's `outHandler` draining the send queue).
pub fn run_peer_output<T: MsgTransport>(
    transport: &mut T,
    outbound: mpsc::Receiver<Message>,
) -> DisconnectReason {
    while let Ok(msg) = outbound.recv() {
        if let Err(e) = transport.write_message(&msg) {
            return DisconnectReason::WriteError(e);
        }
    }
    DisconnectReason::LocalShutdown
}

/// Send a ping to the peer every `interval` until shutdown is signalled
/// or the outbound queue closes (dcrd's `pingHandler`).  Each ping gets
/// a fresh nonce recorded on the peer so the answering pong can be timed.
pub fn run_ping_timer<E: PeerEnv>(
    peer: &Mutex<Peer>,
    env: &mut E,
    outbound: &OutboundQueue,
    interval: Duration,
    shutdown: &mpsc::Receiver<()>,
) {
    loop {
        // Wait a full interval unless shutdown arrives first.
        match shutdown.recv_timeout(interval) {
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let ping = MsgPing {
                    nonce: env.rand_u64(),
                };
                peer.lock()
                    .expect("peer mutex poisoned")
                    .record_sent_ping(env, &ping);
                if outbound.queue_message(Message::Ping(ping)).is_err() {
                    return;
                }
            }
            // Shutdown signalled, or the signalling half was dropped.
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peerconn::NodePeerEnv;

    use dcroxide_peer::Config;
    use dcroxide_wire::{CurrencyNet, MsgPing, MsgPong};

    fn test_peer() -> Peer {
        let cfg = Config {
            net: CurrencyNet::TEST_NET3,
            ..Config::default()
        };
        Peer::new_inbound(cfg)
    }

    #[test]
    fn ping_is_answered_with_a_matching_pong() {
        let mut peer = test_peer();
        let mut env = NodePeerEnv::new();
        let action = classify_incoming(&mut peer, &Message::Ping(MsgPing { nonce: 42 }), &mut env);
        assert_eq!(
            action,
            IncomingAction::Process {
                reply: Some(Box::new(Message::Pong(MsgPong { nonce: 42 }))),
            }
        );
    }

    #[test]
    fn first_verack_marks_the_peer_and_a_second_disconnects() {
        let mut peer = test_peer();
        let mut env = NodePeerEnv::new();
        assert!(!peer.verack_received());

        let first = classify_incoming(&mut peer, &Message::VerAck, &mut env);
        assert_eq!(first, IncomingAction::Process { reply: None });
        assert!(peer.verack_received());

        let second = classify_incoming(&mut peer, &Message::VerAck, &mut env);
        assert_eq!(
            second,
            IncomingAction::Disconnect("duplicate verack message")
        );
    }

    #[test]
    fn a_second_version_disconnects() {
        let mut peer = test_peer();
        let mut env = NodePeerEnv::new();
        let version = dcroxide_wire::MsgVersion {
            protocol_version: 11,
            services: dcroxide_wire::ServiceFlag(0),
            timestamp: 0,
            addr_you: net_address(),
            addr_me: net_address(),
            nonce: 7,
            user_agent: String::new(),
            last_block: 0,
            disable_relay_tx: false,
        };
        let action = classify_incoming(&mut peer, &Message::Version(version), &mut env);
        assert_eq!(
            action,
            IncomingAction::Disconnect("duplicate version message")
        );
    }

    #[test]
    fn sendheaders_sets_the_wants_headers_preference() {
        let mut peer = test_peer();
        let mut env = NodePeerEnv::new();
        assert!(!peer.wants_headers());
        let action = classify_incoming(&mut peer, &Message::SendHeaders, &mut env);
        assert_eq!(action, IncomingAction::Process { reply: None });
        assert!(peer.wants_headers());
    }

    #[test]
    fn pong_answering_the_last_ping_records_the_round_trip() {
        let mut peer = test_peer();
        let mut env = NodePeerEnv::new();
        // Record an outstanding ping so the pong has something to match.
        peer.record_sent_ping(&mut env, &MsgPing { nonce: 99 });
        assert_eq!(peer.last_ping_nonce(), 99);

        let action = classify_incoming(&mut peer, &Message::Pong(MsgPong { nonce: 99 }), &mut env);
        assert_eq!(action, IncomingAction::Process { reply: None });
        // The outstanding ping is cleared once answered.
        assert_eq!(peer.last_ping_nonce(), 0);
    }

    fn net_address() -> dcroxide_wire::NetAddress {
        dcroxide_wire::NetAddress {
            timestamp: 0,
            services: dcroxide_wire::ServiceFlag(0),
            ip: [0u8; 16],
            port: 0,
        }
    }
}
