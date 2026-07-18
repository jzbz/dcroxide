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
//! idle read deadline is applied through the transport's absolute
//! per-message read budget (dcrd's
//! `SetReadDeadline` before each read); a read timeout ends the loop exactly
//! like dcrd's idle disconnect.

use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use dcroxide_peer::{
    MAX_PROTOCOL_VERSION, MsgTransport, NEGOTIATE_TIMEOUT, Peer, PeerEnv, PeerGlobals,
};
use dcroxide_wire::{CurrencyNet, Message, MsgPing};

use crate::peerconn::NodePeerEnv;
use crate::transport::WireTransport;

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
    /// The version handshake failed with dcrd's negotiation error.
    Negotiate(String),
    /// A protocol violation with dcrd's reason string.
    Protocol(std::borrow::Cow<'static, str>),
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

/// What the server's message handler decided about the connection
/// (dcrd's handlers either return or call `Disconnect`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeSignal {
    /// Keep serving the peer.
    Continue,
    /// Drop the connection with dcrd's reason.
    Disconnect(std::borrow::Cow<'static, str>),
}

/// The server-side connection lifecycle a served peer runs through:
/// dcrd's `AddPeer` after the handshake, the message listeners while
/// the connection lives, and `DonePeer` on the way out.  A plain
/// message closure satisfies this with no-op lifecycle hooks.
pub trait ServeHooks {
    /// The peer sent bytes that failed wire decoding (dcrd `OnRead`
    /// observing a `wire.ErrorCode`): the server bans the host with
    /// dcrd's "sent malformed wire message" reason.  The read loop
    /// disconnects regardless, so implementations only record the
    /// ban.
    fn on_wire_violation(&mut self, _err: &str) {}
    /// The connection completed its handshake (dcrd `AddPeer`).  The
    /// shared `peer_handle` is the same `Arc<Mutex<Peer>>` both loops
    /// run behind, handed over so the server can register it for live
    /// stat snapshots (`getpeerinfo`) without ever locking it here — the
    /// caller already holds the guard across this call.
    fn on_connected(
        &mut self,
        _peer: &mut Peer,
        _peer_handle: &std::sync::Arc<std::sync::Mutex<Peer>>,
        _outbound: &OutboundQueue,
        _remote_disable_relay_tx: bool,
    ) {
    }
    /// The remote's version message arrived during the handshake
    /// (dcrd 2.2's `OnVersionCallback`); an error aborts the
    /// handshake and disconnects the peer.
    fn on_version(
        &mut self,
        _peer: &dcroxide_peer::Peer,
        _msg: &dcroxide_wire::MsgVersion,
    ) -> Result<(), String> {
        Ok(())
    }
    /// A message arrived for the server handlers.
    fn on_message(
        &mut self,
        peer: &mut Peer,
        msg: &Message,
        outbound: &OutboundQueue,
    ) -> ServeSignal;
    /// The connection is winding down (dcrd `DonePeer`).
    fn on_disconnected(&mut self, _peer: &mut Peer) {}
}

impl<F> ServeHooks for F
where
    F: FnMut(&mut Peer, &Message, &OutboundQueue) -> ServeSignal,
{
    fn on_message(
        &mut self,
        peer: &mut Peer,
        msg: &Message,
        outbound: &OutboundQueue,
    ) -> ServeSignal {
        self(peer, msg, outbound)
    }
}

/// Read and dispatch messages until the peer disconnects.  Each message
/// is given its protocol-level handling (queueing any immediate reply on
/// the outbound queue) and then forwarded to the hooks' message handler,
/// which queues its responses through the outbound queue and may request
/// a disconnect, mirroring dcrd's `inHandler`.
pub fn run_peer_input<T, E, H>(
    peer: &Mutex<Peer>,
    transport: &mut T,
    env: &mut E,
    outbound: &OutboundQueue,
    hooks: &mut H,
    delayed: Vec<Message>,
) -> DisconnectReason
where
    T: MsgTransport,
    E: PeerEnv,
    H: ServeHooks,
{
    // Replay any messages a legacy peer sent before its verack first
    // (dcrd's `inHandler` draining `delayedHandshakeMsgs`); their
    // bytes were folded into the handshake accounting already.
    for msg in delayed {
        let mut peer = peer.lock().expect("peer mutex poisoned");
        match classify_incoming(&mut peer, &msg, env) {
            IncomingAction::Disconnect(reason) => return DisconnectReason::Protocol(reason.into()),
            IncomingAction::Process { reply } => {
                if let Some(reply) = reply
                    && outbound.queue_message(*reply).is_err()
                {
                    return DisconnectReason::LocalShutdown;
                }
                if let ServeSignal::Disconnect(reason) = hooks.on_message(&mut peer, &msg, outbound)
                {
                    return DisconnectReason::Protocol(reason);
                }
            }
        }
    }

    // Snapshot the transport's cumulative read counter so each message
    // contributes its delta to the peer's receive accounting (dcrd's
    // `readMessage` adding its byte count to `bytesReceived`); the
    // handshake's bytes were folded in by the connection assembly.
    let mut read_total = transport.total_bytes_read();
    loop {
        // Read without the peer lock held so the ping timer and the
        // server keep making progress while this thread blocks.
        let msg = match transport.read_message() {
            Ok(msg) => msg,
            Err(e) => {
                // Ban peers sending messages that do not conform to
                // the wire protocol (dcrd `OnRead` on a
                // `wire.ErrorCode`); the read loop exits either way.
                if e.wire_violation {
                    hooks.on_wire_violation(&e.message);
                }
                return DisconnectReason::ReadError(e.message);
            }
        };
        let read_delta = transport.total_bytes_read().wrapping_sub(read_total);
        read_total = transport.total_bytes_read();

        let mut peer = peer.lock().expect("peer mutex poisoned");
        // Per-message receive accounting (dcrd stamping `lastRecv` in
        // `inHandler` after each read); transports without byte
        // tracking report zero deltas and skip it.
        if read_delta > 0 {
            peer.record_recv(read_delta, env.now_nanos());
        }
        match classify_incoming(&mut peer, &msg, env) {
            IncomingAction::Disconnect(reason) => return DisconnectReason::Protocol(reason.into()),
            IncomingAction::Process { reply } => {
                // Immediate replies go through the outbound queue so all
                // writes stay serialized on the output loop; a closed
                // queue means the output loop already stopped.
                if let Some(reply) = reply
                    && outbound.queue_message(*reply).is_err()
                {
                    return DisconnectReason::LocalShutdown;
                }
                if let ServeSignal::Disconnect(reason) = hooks.on_message(&mut peer, &msg, outbound)
                {
                    return DisconnectReason::Protocol(reason);
                }
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
/// or a write fails (dcrd's `outHandler` draining the send queue).  Each
/// completed write contributes its byte delta and timestamp to the
/// peer's send accounting (dcrd's `writeMessage` bookkeeping).
pub fn run_peer_output<T, E>(
    peer: &Mutex<Peer>,
    transport: &mut T,
    env: &mut E,
    outbound: mpsc::Receiver<Message>,
) -> DisconnectReason
where
    T: MsgTransport,
    E: PeerEnv,
{
    let mut write_total = transport.total_bytes_written();
    while let Ok(msg) = outbound.recv() {
        if let Err(e) = transport.write_message(&msg) {
            return DisconnectReason::WriteError(e);
        }
        let write_delta = transport.total_bytes_written().wrapping_sub(write_total);
        write_total = transport.total_bytes_written();
        if write_delta > 0 {
            peer.lock()
                .expect("peer mutex poisoned")
                .record_send(write_delta, env.now_nanos());
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

/// Run a peer connection from the negotiated handshake through the
/// steady-state message loops until it disconnects (dcrd `peer.go`'s
/// `start` plus the per-peer goroutine set, as OS threads).
///
/// The socket is split into read and write halves; the version handshake
/// runs (inbound or outbound per the peer) before the loops start; then
/// the output loop and the ping timer run on their own threads while the
/// input loop runs on this thread.  When the input loop ends the ping
/// timer is signalled and the outbound queue is closed so the other
/// threads finish, and both are joined before returning the reason the
/// connection stopped.  `idle_timeout` bounds each read so a silent peer
/// eventually disconnects (dcrd's idle timer); `ping_interval` should be
/// shorter so a live peer answers before that fires.
#[allow(clippy::too_many_arguments)] // Mirrors dcrd's connection surface.
pub fn run_peer_connection<H>(
    stream: TcpStream,
    mut peer: Peer,
    pver: u32,
    net: CurrencyNet,
    idle_timeout: Duration,
    ping_interval: Duration,
    net_totals: Option<Arc<crate::transport::NetByteTotals>>,
    mut hooks: H,
) -> DisconnectReason
where
    H: ServeHooks,
{
    // Bound the version handshake by dcrd's 30-second negotiate deadline
    // (peer `NEGOTIATE_TIMEOUT`), shorter than the idle timeout, so a peer
    // that connects and then stalls the handshake is dropped promptly
    // instead of holding a serving thread for the full idle window; the
    // idle timeout takes over once the session begins.
    let negotiate_timeout = Duration::from_nanos(NEGOTIATE_TIMEOUT.max(0) as u64);
    let write_stream = match stream.try_clone() {
        Ok(write_stream) => write_stream,
        Err(e) => return DisconnectReason::WriteError(e.to_string()),
    };
    // The handshake is framed at the local maximum protocol version (0
    // is dcrd's "package maximum" sentinel); the transport is lowered to
    // the negotiated version below.
    let handshake_pver = if pver == 0 {
        MAX_PROTOCOL_VERSION
    } else {
        pver
    };
    let mut read_transport = WireTransport::new(stream, handshake_pver, net);
    // The negotiate deadline bounds the handshake message read
    // absolutely, so a peer dribbling bytes cannot stretch the
    // handshake past it; dcrd's negotiation reads also run under the
    // per-message idle deadline inside its 30-second select, so a
    // configured idle timeout below the negotiate window bounds the
    // read tighter, exactly as dcrd's does.
    read_transport.set_read_budget(Some(negotiate_timeout.min(idle_timeout)));
    let mut write_transport = WireTransport::new(write_stream, handshake_pver, net);
    // Both halves contribute to the server-wide byte totals from the
    // handshake onward, exactly like dcrd's read/write listeners.
    if let Some(totals) = net_totals {
        read_transport.set_net_totals(Arc::clone(&totals));
        write_transport.set_net_totals(totals);
    }

    // Run the handshake (version and verack exchange) before starting
    // the loops, firing the server's version listener from inside it
    // exactly where dcrd 2.2's `onVersion` callback runs.  The read
    // transport is full duplex, so it also writes the local messages.
    let mut env = NodePeerEnv::new();
    let mut globals = PeerGlobals::new();
    let outcome = {
        let mut on_version = |p: &Peer, msg: &dcroxide_wire::MsgVersion| hooks.on_version(p, msg);
        let negotiated = if peer.inbound() {
            peer.negotiate_inbound_protocol(
                &mut read_transport,
                &mut env,
                &mut globals,
                Some(&mut on_version),
            )
        } else {
            peer.negotiate_outbound_protocol(
                &mut read_transport,
                &mut env,
                &mut globals,
                Some(&mut on_version),
            )
        };
        match negotiated {
            Ok(outcome) => outcome,
            Err(e) => return DisconnectReason::Negotiate(e.message),
        }
    };
    let remote_version = outcome.remote_version;

    // Frame the rest of the session at the negotiated version (dcrd
    // re-reads the peer's protocol version on every message).
    let negotiated_pver = peer.protocol_version();
    read_transport.set_protocol_version(negotiated_pver);
    write_transport.set_protocol_version(negotiated_pver);

    // The handshake completed within the negotiate deadline; the longer
    // idle timeout governs each message read from here, again as an
    // absolute per-message bound (dcrd's readMessage arming
    // SetReadDeadline(now + IdleTimeout) before every read).
    read_transport.set_read_budget(Some(idle_timeout));

    // Fold the handshake's traffic into the peer's counters: dcrd's
    // negotiation reads and writes go through the same counted
    // `readMessage`/`writeMessage` bookkeeping as the session, and the
    // version exchange ran on the (full-duplex) read transport.
    let handshake_now = env.now_nanos();
    let handshake_read = read_transport.bytes_read();
    if handshake_read > 0 {
        peer.record_recv(handshake_read, handshake_now);
    }
    let handshake_written = read_transport.bytes_written();
    if handshake_written > 0 {
        peer.record_send(handshake_written, handshake_now);
    }

    // Share the peer across the loops and request all block
    // announcements via full headers instead of the inv message (dcrd
    // `serverPeer.Run` queueing `NewMsgSendHeaders` after the
    // handshake).
    let peer = Arc::new(Mutex::new(peer));
    let (outbound, receiver) = OutboundQueue::channel();
    if outbound.queue_message(Message::SendHeaders).is_err() {
        return DisconnectReason::LocalShutdown;
    }

    // The handshake is complete: hand the peer to the server's
    // lifecycle hook (dcrd `AddPeer` signalling the sync manager).
    hooks.on_connected(
        &mut peer.lock().expect("peer mutex poisoned"),
        &peer,
        &outbound,
        remote_version.disable_relay_tx,
    );

    let output_peer = Arc::clone(&peer);
    let output = thread::spawn(move || {
        let mut output_env = NodePeerEnv::new();
        let reason = run_peer_output(
            &output_peer,
            &mut write_transport,
            &mut output_env,
            receiver,
        );
        // Shut the socket down when the output loop ends (a write error
        // or a closed queue) so the input loop's blocking read unblocks
        // and the connection tears down instead of lingering.
        let _ = write_transport.get_mut().shutdown(Shutdown::Both);
        reason
    });

    let (ping_shutdown, ping_shutdown_rx) = mpsc::channel();
    let ping_peer = Arc::clone(&peer);
    let ping_outbound = outbound.clone();
    let ping = thread::spawn(move || {
        let mut ping_env = NodePeerEnv::new();
        run_ping_timer(
            &ping_peer,
            &mut ping_env,
            &ping_outbound,
            ping_interval,
            &ping_shutdown_rx,
        );
    });

    // Drive the input loop on this thread until the peer disconnects.
    let reason = run_peer_input(
        &peer,
        &mut read_transport,
        &mut env,
        &outbound,
        &mut hooks,
        outcome.delayed,
    );

    // The connection is winding down (dcrd `DonePeer`).
    hooks.on_disconnected(&mut peer.lock().expect("peer mutex poisoned"));

    // Tear down: shut the socket down so the output loop's blocking write
    // unblocks (a peer that stopped reading would otherwise wedge it),
    // stop the ping timer, and close the outbound queue, then join both
    // threads.
    let _ = read_transport.get_mut().shutdown(Shutdown::Both);
    let _ = ping_shutdown.send(());
    drop(outbound);
    let _ = ping.join();
    let _ = output.join();
    reason
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
