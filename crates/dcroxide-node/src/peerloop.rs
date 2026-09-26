// SPDX-License-Identifier: ISC
//! The per-peer message loops — dcrd `peer.go`'s `inHandler`,
//! `outHandler` (with the keepalive ticker it owns), and
//! `stallHandler`.
//!
//! Once the version handshake completes the daemon reads messages in a
//! loop, giving the protocol-level messages their fixed handling (a
//! duplicate version or verack disconnects, a ping is answered with a
//! pong, a pong updates the ping statistics, and a sendheaders records
//! the peer's preference) and forwarding every message to the server's
//! handlers.  The dispatch itself is a decision core over the ported
//! [`Peer`] handlers ([`classify_incoming`]); [`run_peer_input`] is the
//! read loop, [`run_peer_output`] the write loop draining the
//! [`OutboundQueue`], and [`run_peer_timers`] the one timer thread a
//! served connection runs for the periodic keepalive and the
//! pending-response check.  [`run_ping_timer`] is that same scheduler
//! with the stall check left out.
//!
//! dcrd runs these as separate goroutines sharing the peer under its
//! mutexes, so the peer is passed as a `&Mutex<Peer>` and every write to
//! the connection — including the input loop's protocol replies and the
//! keepalive pings — goes through the outbound queue, keeping all writes
//! on the single output loop.  The peer lock is held only for the
//! bookkeeping itself, the way dcrd holds `statsMtx` and `flagsMtx`:
//! never across the blocking read, and never across the server's hooks
//! (the message handler, and the connection and disconnection hooks),
//! which may wait out a block validation or a chain flush.  The output
//! loop, the timers, the getdata server and
//! `getpeerinfo` therefore keep going while a handler runs, as dcrd's
//! `outHandler` keeps writing (pings included) while `inHandler`
//! blocks.  dcrd's separate inventory trickle queue (`QueueInventory`)
//! is not ported: each announcement is its own message.  The idle read
//! deadline is applied through the transport's absolute per-message
//! read budget (dcrd's `SetReadDeadline` before each read); a read
//! timeout ends the loop exactly like dcrd's idle disconnect.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use dcroxide_peer::{
    ArmOutcome, MAX_PROTOCOL_VERSION, MsgTransport, NEGOTIATE_TIMEOUT, NegotiateError,
    NegotiateErrorKind, Peer, PeerEnv, PeerGlobals, ReadError, STALL_RESPONSE_TIMEOUT,
    STALL_TICK_INTERVAL, StallDetector, StallReason,
};
use dcroxide_wire::{CurrencyNet, MESSAGE_HEADER_SIZE, Message, MsgPing, MsgVersion};

use crate::peerconn::NodePeerEnv;
use crate::socktimeout::SocketTimeout;
use crate::transport::{WireTransport, WriteStallPolicy};

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
    /// Reading the next message failed: a closed connection, an idle
    /// read timeout, or a payload that ran out inside its message's
    /// structure (a decode failure that is not a wire violation).
    ReadError(String),
    /// Writing a message failed.
    WriteError(String),
    /// The outbound queue was closed, so the output loop finished (a
    /// locally initiated shutdown).
    LocalShutdown,
    /// The OS refused a thread the connection needs, so it was dropped
    /// before the server saw it.  dcrd has no counterpart: its loops
    /// are goroutines, which cannot fail to start.
    ThreadRefused(String),
}

/// dcrd `directionString`.
pub(crate) fn direction_string(inbound: bool) -> &'static str {
    if inbound { "inbound" } else { "outbound" }
}

/// How dcrd's peer logging names a peer (`Peer.String`: the remote
/// address and its direction).
pub(crate) fn peer_log_label(peer: &Peer) -> String {
    format!("{} ({})", peer.addr(), direction_string(peer.inbound()))
}

/// The debug line dcrd's `processInboundMessage` logs before it
/// disconnects a peer for a second `version` or `verack`
/// (`peer/peer.go:1319-1327`).
fn already_received_log_line(command: &str, peer: &Peer) -> String {
    format!(
        "Already received '{command}' from peer {} -- disconnecting",
        peer_log_label(peer)
    )
}

/// Give an incoming message its protocol-level handling, updating the
/// peer state and returning the action the loop should take (dcrd
/// `inHandler`'s message switch, `processInboundMessage`), logging at
/// debug the disconnects it decides, as dcrd does.
pub fn classify_incoming<E: PeerEnv>(
    peer: &mut Peer,
    msg: &Message,
    env: &mut E,
) -> IncomingAction {
    match msg {
        // Only one version message is allowed per peer.
        Message::Version(_) => {
            crate::logging::debug("PEER", &already_received_log_line("version", peer));
            IncomingAction::Disconnect("duplicate version message")
        }

        Message::VerAck => {
            if peer.verack_received() {
                crate::logging::debug("PEER", &already_received_log_line("verack", peer));
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
    /// dcrd's "sent malformed wire message" reason.  The read loop ends
    /// either way; the answer says whether the ban also disconnected
    /// the peer (dcrd's `BanPeer` calling `Disconnect`), which is
    /// [`ServeSignal::Continue`] when the server declined to ban
    /// (banning disabled, a whitelisted peer) or has no ban to make.
    fn on_wire_violation(&mut self, _err: &str) -> ServeSignal {
        ServeSignal::Continue
    }
    /// The connection completed its handshake (dcrd `AddPeer`).  `peer`
    /// is the same `Arc<Mutex<Peer>>` both loops run behind, handed over
    /// so the server can register it for live stat snapshots
    /// (`getpeerinfo`).
    ///
    /// The peer arrives unlocked, for the reason given at
    /// [`on_message`](ServeHooks::on_message): registering the peer and
    /// telling the sync manager about it can wait out a block
    /// validation, and dcrd's `AddPeer` holds no peer lock.  The output
    /// loop is already running.
    fn on_connected(
        &mut self,
        _peer: &Arc<Mutex<Peer>>,
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
    /// A message arrived for the server handlers.  It is handed over by
    /// value, so a handler can keep it without copying it, together with
    /// the mixing identity hash the input loop computed as it read the
    /// message (dcrd's `readMessage` caching `WriteHash` on it); the hash
    /// is `None` for every other message and when hashing failed.
    ///
    /// The peer arrives unlocked.  dcrd runs its message listeners with
    /// no peer lock held, reading peer state through short `flagsMtx`
    /// and `statsMtx` sections, and a handler may block for as long as
    /// a block validation or a chain flush takes.  Holding the peer
    /// across that would stall everything else that needs it: the
    /// output loop's send accounting after every write, the ping stamp,
    /// the getdata server's pacing, `getpeerinfo`, and every handshake's
    /// outbound count.  Implementations lock only around the peer state
    /// they actually read or change.
    fn on_message(
        &mut self,
        peer: &Mutex<Peer>,
        msg: Message,
        mix_hash: Option<dcroxide_chainhash::Hash>,
        outbound: &OutboundQueue,
    ) -> ServeSignal;
    /// The connection is winding down (dcrd `DonePeer`).  The peer
    /// arrives unlocked, as at [`on_connected`](ServeHooks::on_connected):
    /// it stays registered until the sync manager has let it go.  The
    /// socket is already shut down and the timers stopped, as dcrd's
    /// `DonePeer` runs only after `Peer.Run` has returned, so nothing
    /// queued to the peer from here on reaches it.
    fn on_disconnected(&mut self, _peer: &Mutex<Peer>) {}
}

/// A plain message closure, run with the peer locked for the whole call
/// — a convenience for tests exercising the plumbing, whose handlers
/// never block.
impl<F> ServeHooks for F
where
    F: FnMut(&mut Peer, &Message, &OutboundQueue) -> ServeSignal,
{
    fn on_message(
        &mut self,
        peer: &Mutex<Peer>,
        msg: Message,
        _mix_hash: Option<dcroxide_chainhash::Hash>,
        outbound: &OutboundQueue,
    ) -> ServeSignal {
        self(
            &mut peer.lock().expect("peer mutex poisoned"),
            &msg,
            outbound,
        )
    }
}

/// Read and dispatch messages until the peer disconnects, without stall
/// detection (dcrd's `inHandler` for a peer whose stall handler is not
/// running).
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
    run_peer_input_with_stall(peer, transport, env, outbound, hooks, delayed, None)
}

/// Read and dispatch messages until the peer disconnects.  Each message
/// is given its protocol-level handling (queueing any immediate reply on
/// the outbound queue) and then forwarded to the hooks' message handler,
/// which queues its responses through the outbound queue and may request
/// a disconnect, mirroring dcrd's `inHandler`.
///
/// Every received message is reported to the stall detector, clearing
/// the deadlines it answers, and the handling of each message is
/// bracketed by the detector's handler-active window (dcrd's
/// `sccReceiveMessage`, `sccHandlerStart` and `sccHandlerDone`).  The
/// bracket is what keeps a slow local callback from looking like a
/// remote stall: the next message is not read until this one finishes
/// processing, so the time spent here is credited back to every pending
/// deadline.  The messages a legacy peer delayed past the handshake are
/// replayed without stall signalling, exactly as dcrd's `inHandler`
/// drains `delayedHandshakeMsgs` before its stall handler is involved.
pub fn run_peer_input_with_stall<T, E, H>(
    peer: &Mutex<Peer>,
    transport: &mut T,
    env: &mut E,
    outbound: &OutboundQueue,
    hooks: &mut H,
    delayed: Vec<Message>,
    stall: Option<&Mutex<StallDetector>>,
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
        // dcrd's `readMessage` hashed these too, during the handshake.
        let mix_hash = mix_message_hash(&msg);
        // Only the protocol-level bookkeeping runs under the peer lock;
        // see the steady-state loop below.
        let action = classify_incoming(&mut peer.lock().expect("peer mutex poisoned"), &msg, env);
        match action {
            IncomingAction::Disconnect(reason) => return DisconnectReason::Protocol(reason.into()),
            IncomingAction::Process { reply } => {
                if let Some(reply) = reply {
                    let command = reply.command();
                    match outbound.queue_message(*reply) {
                        Ok(()) => {}
                        // See the steady-state loop below: a full queue
                        // drops the reply and is reported, it does not
                        // end the connection.
                        Err(QueueError::Full) => outbound.report_full(command),
                        Err(QueueError::Closed) => return DisconnectReason::LocalShutdown,
                    }
                }
                if let ServeSignal::Disconnect(reason) =
                    hooks.on_message(peer, msg, mix_hash, outbound)
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
                // dcrd's `OnRead` runs inside `readMessage`, so a ban's
                // `Disconnect` lands before `inHandler` looks at the
                // error, and `shouldHandleReadError` then declines to
                // log it.  A ban that disconnects therefore ends the
                // connection as the ban, not as a read error.
                if e.wire_violation
                    && let ServeSignal::Disconnect(reason) = hooks.on_wire_violation(&e.message)
                {
                    return DisconnectReason::Protocol(reason);
                }
                return DisconnectReason::ReadError(e.message);
            }
        };
        let read_delta = transport.total_bytes_read().wrapping_sub(read_total);
        read_total = transport.total_bytes_read();

        // Hash a mixing message once, before taking any lock: dcrd does
        // this in `readMessage` and caches the hash on the message, and
        // the stall detector and the server handler both read this one.
        let mix_hash = mix_message_hash(&msg);

        // Settle any deadline this message answers and open the
        // handler-active window before taking any lock, so every
        // moment between finishing the read and finishing the handling
        // is credited to the local node rather than blamed on the peer.
        // What the message settles is worked out before the stall lock
        // is taken: it hashes a transaction or block header (and names
        // a `notfound`'s list in place), and this peer's output loop
        // takes the same lock to arm every request it sends.
        if let Some(stall) = stall {
            let settled = dcroxide_peer::settles(&msg, mix_hash);
            let mut stall = stall.lock().expect("stall mutex poisoned");
            stall.received_settles(&settled);
            stall.handler_start();
        }

        // The peer lock covers the receive accounting and the
        // protocol-level handling only, dcrd's short `statsMtx` and
        // `flagsMtx` sections.  It is released before the server's
        // handler runs: that handler can wait out another peer's block
        // validation or a chain flush, and holding the peer across it
        // stopped this connection's output loop after one write, held
        // back its keepalive pings, and stalled `getpeerinfo` and every
        // handshake behind it.  dcrd's `inHandler` holds no peer lock
        // around `processInboundMessage`.
        let action = {
            let mut peer = peer.lock().expect("peer mutex poisoned");
            // Per-message receive accounting (dcrd stamping `lastRecv`
            // in `inHandler` after each read); transports without byte
            // tracking report zero deltas and skip it.
            if read_delta > 0 {
                peer.record_recv(read_delta, env.now_nanos());
            }
            classify_incoming(&mut peer, &msg, env)
        };
        match action {
            IncomingAction::Disconnect(reason) => return DisconnectReason::Protocol(reason.into()),
            IncomingAction::Process { reply } => {
                // Immediate replies go through the outbound queue so all
                // writes stay serialized on the output loop.  A closed
                // queue means the output loop already stopped, so this
                // connection is over.  A full queue means the peer is
                // not draining its socket, which is reported and the
                // pong dropped: hanging up here would let a burst of
                // relay announcements to a momentarily slow but honest
                // peer cost it its connection, and the peer's own ping
                // timeout, the writer's write deadline and the stall
                // detector already bound a peer that has truly stopped
                // reading.
                if let Some(reply) = reply {
                    let command = reply.command();
                    match outbound.queue_message(*reply) {
                        Ok(()) => {}
                        Err(QueueError::Full) => outbound.report_full(command),
                        Err(QueueError::Closed) => return DisconnectReason::LocalShutdown,
                    }
                }
                if let ServeSignal::Disconnect(reason) =
                    hooks.on_message(peer, msg, mix_hash, outbound)
                {
                    return DisconnectReason::Protocol(reason);
                }
            }
        }

        // The message is handled.  The peer lock was released above, so
        // closing the handler-active window never holds the peer lock
        // and the stall lock at once (the output loop takes them in the
        // opposite order).
        if let Some(stall) = stall {
            stall.lock().expect("stall mutex poisoned").handler_done();
        }
    }
}

/// The mixing-message identity hash for the eight mix commands, and
/// `None` for anything else.
///
/// dcrd computes this once in `readMessage`, immediately after
/// deserializing, and caches it on the wire message so
/// `maybeRemoveDeadline` and `onMixMessage` merely read it back.  The
/// port's wire messages carry no cache, so the input loop computes it
/// once per received message, by reference, and hands it to the stall
/// detector and the server handler — the same one-hash-per-message
/// shape, with the cache in the caller.
///
/// Which messages are hashed is the wire's one list
/// ([`Message::mix_hash`]), which the stall detector's settlement reads
/// too ([`Message::is_mix`]), so every mixing message it expects a hash
/// for is hashed here.
fn mix_message_hash(msg: &Message) -> Option<dcroxide_chainhash::Hash> {
    msg.mix_hash().and_then(Result::ok)
}

/// A handle for originating messages to a peer (dcrd `QueueMessage`).
///
/// The server, the input pump's replies, and the ping timer send
/// through clones of this handle; a single output loop drains the
/// receiver and does the actual writing, so all writes to the
/// connection are serialized on one thread.  This is the plain message
/// queue: dcrd's separate inventory trickle queue (`QueueInventory`) is
/// not ported, and the getdata server's `maxPendingSend` pacing lives
/// with that server in `dispatch`.
#[derive(Clone)]
pub struct OutboundQueue {
    sender: mpsc::SyncSender<QueuedMessage>,
    state: Arc<OutboundQueueState>,
}

/// A queued message carrying the byte charge it holds against
/// [`MAX_OUTBOUND_QUEUE_BYTES`] until the output loop takes it.
struct QueuedMessage {
    msg: Message,
    charge: usize,
}

/// The draining end of an [`OutboundQueue`].  Every receive releases the
/// message's byte charge, so the queue's accounting tracks exactly the
/// messages that are still queued unsent (the one message the output
/// loop is currently writing is bounded separately, by the write
/// deadline).
pub struct OutboundReceiver {
    inner: mpsc::Receiver<QueuedMessage>,
    state: Arc<OutboundQueueState>,
}

impl OutboundReceiver {
    fn take(&self, queued: QueuedMessage) -> Message {
        self.state
            .bytes
            .fetch_sub(queued.charge, std::sync::atomic::Ordering::Relaxed);
        queued.msg
    }

    /// Receive the next queued message, blocking until one is queued or
    /// every sender is dropped.
    pub fn recv(&self) -> Result<Message, mpsc::RecvError> {
        self.inner.recv().map(|q| self.take(q))
    }

    /// Receive the next queued message, waiting at most `timeout`.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Message, mpsc::RecvTimeoutError> {
        self.inner.recv_timeout(timeout).map(|q| self.take(q))
    }

    /// Receive the next queued message without blocking.
    pub fn try_recv(&self) -> Result<Message, mpsc::TryRecvError> {
        self.inner.try_recv().map(|q| self.take(q))
    }
}

/// The reporting state every clone of an [`OutboundQueue`] shares.
struct OutboundQueueState {
    /// The peer this queue feeds, for the congestion report; set once by
    /// the connection assembly and left at its placeholder in the unit
    /// tests, which have no socket.
    label: std::sync::OnceLock<String>,
    /// Bytes charged for the queued-but-unsent messages, against
    /// [`MAX_OUTBOUND_QUEUE_BYTES`].
    bytes: std::sync::atomic::AtomicUsize,
    /// Whether a full-queue drop has already been reported since the
    /// last successful enqueue.  A congested peer can otherwise turn
    /// every relayed transaction into a log line, which is its own
    /// resource-exhaustion lever, so one line is emitted per congestion
    /// episode.
    reported_full: std::sync::atomic::AtomicBool,
}

/// Why a message could not be handed to a peer's output loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    /// The queue already holds [`MAX_OUTBOUND_QUEUE_DEPTH`] unsent
    /// messages, or queuing this message would push the unsent bytes
    /// past [`MAX_OUTBOUND_QUEUE_BYTES`].  The output loop is blocked in
    /// a write, so the peer is not draining its socket; the message
    /// cannot be queued without growing the per-peer memory charge
    /// without bound.
    Full,
    /// The output loop has stopped and dropped the receiver, so the
    /// connection is already tearing down.  This is the ordinary
    /// shutdown path, not a peer fault.
    Closed,
}

impl std::fmt::Display for QueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueueError::Full => write!(f, "peer output queue is full"),
            QueueError::Closed => write!(f, "peer output queue is closed"),
        }
    }
}

/// The number of messages that may sit unsent in a peer's outbound
/// queue.
///
/// dcrd bounds this queue by bytes alone, not by count.  Its `peer.go`
/// builds `outputQueue: make(chan outMsg, outputBufferSize)` (5000)
/// alongside `sendQueue: make(chan outMsg, 1)`, and `queueHandler`
/// moves everything the writer has not taken yet into a
/// `pendingMsgs []outMsg` slice it grows with `append`, so the message
/// count is unbounded.  What bounds it is `queueOutMsg` (since
/// `589dd4c5`): every queued message is charged its `msgSize` against
/// `maxQueuedOutputBytes` (40 MiB), and a peer whose charge would pass
/// that is *disconnected* and the message dropped.  (The three-slot
/// semaphore often cited as the bound is `maxPendingSend` in
/// `server.go`, which limits concurrent *getdata serve* items only.)
///
/// This depth is the port's own secondary guard, with no dcrd
/// counterpart, against a flood of tiny messages; the primary bound is
/// the byte charge, [`MAX_OUTBOUND_QUEUE_BYTES`].  Against a byte
/// budget the count alone would be coarse, since the largest message
/// this queue carries is a max-size `MsgHeaders` (2000 headers x 180
/// bytes ~ 360 KB) or a max-size `MsgBlock` (~393 KB), and 128 of those
/// is ~46 MB per peer, ~5.7 GB at the default `maxpeers` of 125.  The
/// window is further bounded by the writer's per-message write
/// deadline: once the peer stops reading, the first blocked write times
/// out and the connection is torn down.  How the two ceilings and the
/// drop-not-disconnect policy differ from dcrd's 40 MiB disconnect is
/// the *Per-peer outbound queue* row of `PARITY.md`.
///
/// The depth is generous enough that ordinary bursts (a mempool inv
/// fan-out, a headers response, the initial handshake traffic) never
/// trip it.  When it is tripped, [`OutboundQueue::try_queue`] reports it
/// instead of dropping the message silently; the per-call-site comments
/// say what each producer does about it.
pub const MAX_OUTBOUND_QUEUE_DEPTH: usize = 128;

/// The bytes that may sit unsent in a peer's outbound queue, charged at
/// each message's framed size (header plus encoded payload).
///
/// dcrd's counterpart is `maxQueuedOutputBytes`, 40 MiB charged per
/// message in `queueOutMsg`, past which dcrd disconnects the peer.  The
/// port deliberately differs in value and in action: 40 MiB across a
/// full default peer set is the same order of memory this budget exists
/// to rule out, and a refused message is dropped and reported rather
/// than ending the connection, since a peer that has stopped reading
/// altogether is already cut off by the write deadline (the *Per-peer
/// outbound queue* row of `PARITY.md`).  The charge is computed on
/// enqueue and released when the output loop takes
/// the message, and it is dcrd's own `msgSize` arithmetic: the header
/// plus [`Message::serialize_size`], with nothing encoded to measure it.
///
/// 4 MiB caps the pipelining worst case near ~500 MiB across a full
/// default peer set — down from ~5.7 GB under the count bound alone —
/// while staying far above honest traffic: a congested honest peer's
/// queue is well under 100 KB (a relay inv is ~40 bytes, a block
/// announcement ~180), and the serve path holds at most dcrd's
/// `maxPendingSend` (3) getdata items at a time, ~1.2 MB of blocks.  A
/// message larger than the whole budget — only the protocol maxima of
/// `cfiltersv2` and the largest mix messages are, far above anything
/// real — is admitted into an empty queue rather than wedging the
/// connection.
pub const MAX_OUTBOUND_QUEUE_BYTES: usize = 4 * 1024 * 1024;

/// The byte charge for a message: its framed wire size (dcrd `msgSize`,
/// the header plus the message's `SerializeSize`).  The size is
/// arithmetic over the fields and exact for every message that frames;
/// measuring it by framing the message doubled the encode and checksum
/// work for every reply.  A message the codec refuses to frame is still
/// charged its fields' size, as dcrd charges it — the output loop's
/// write will surface the error and tear the connection down.
fn message_charge(msg: &Message) -> usize {
    MESSAGE_HEADER_SIZE.saturating_add(msg.serialize_size())
}

impl OutboundQueue {
    /// Create an outbound queue and the receiver its output loop drains.
    pub fn channel() -> (OutboundQueue, OutboundReceiver) {
        let (sender, receiver) = mpsc::sync_channel(MAX_OUTBOUND_QUEUE_DEPTH);
        let state = Arc::new(OutboundQueueState {
            label: std::sync::OnceLock::new(),
            bytes: std::sync::atomic::AtomicUsize::new(0),
            reported_full: std::sync::atomic::AtomicBool::new(false),
        });
        let queue = OutboundQueue {
            sender,
            state: Arc::clone(&state),
        };
        (
            queue,
            OutboundReceiver {
                inner: receiver,
                state,
            },
        )
    }

    /// Name the peer this queue feeds, so a congestion report identifies
    /// it the way dcrd's peer logging does.  The first call wins.
    pub fn set_peer_label(&self, label: String) {
        let _ = self.state.label.set(label);
    }

    /// The peer label, or a placeholder when none was set (the unit
    /// tests, which have no socket).
    pub fn peer_label(&self) -> &str {
        self.state.label.get().map(String::as_str).unwrap_or("peer")
    }

    /// Queue a message to be sent to the peer.
    ///
    /// [`QueueError::Full`] means the peer is not draining its socket —
    /// either ceiling, [`MAX_OUTBOUND_QUEUE_DEPTH`] messages or
    /// [`MAX_OUTBOUND_QUEUE_BYTES`] charged bytes, refuses the message —
    /// and the message was **not** queued; the caller must decide what
    /// that means for its own state, and in particular must not record
    /// the message as sent.  [`QueueError::Closed`] means the output
    /// loop already stopped, which is the ordinary teardown path.
    pub fn queue_message(&self, msg: Message) -> Result<(), QueueError> {
        self.queue_message_or_return(msg).map_err(|(err, _)| err)
    }

    /// [`Self::queue_message`], handing a refused message back with the
    /// reason instead of dropping it, so a caller that retries it or
    /// passes it on never has to copy it first.  A reply copied for
    /// every attempt cost a full deep copy of a block per refusal, which
    /// a peer holding its own queue full could repeat every serve poll.
    /// The message comes back boxed, which moves its few hundred bytes of
    /// fields and none of the data they own.
    pub fn queue_message_or_return(&self, msg: Message) -> Result<(), (QueueError, Box<Message>)> {
        let charge = message_charge(&msg);
        // Charge first, then admit: concurrent producers may briefly
        // over-count, which errs on the refusing side.  An empty queue
        // admits any single message so an oversized one cannot wedge
        // the connection by being refused forever.
        let prev = self
            .state
            .bytes
            .fetch_add(charge, std::sync::atomic::Ordering::Relaxed);
        if prev > 0 && prev.saturating_add(charge) > MAX_OUTBOUND_QUEUE_BYTES {
            self.state
                .bytes
                .fetch_sub(charge, std::sync::atomic::Ordering::Relaxed);
            return Err((QueueError::Full, Box::new(msg)));
        }
        match self.sender.try_send(QueuedMessage { msg, charge }) {
            Ok(()) => {
                // Room again: re-arm the congestion report so the next
                // episode is logged.
                self.state
                    .reported_full
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::TrySendError::Full(queued)) => {
                self.state
                    .bytes
                    .fetch_sub(charge, std::sync::atomic::Ordering::Relaxed);
                Err((QueueError::Full, Box::new(queued.msg)))
            }
            Err(mpsc::TrySendError::Disconnected(queued)) => {
                self.state
                    .bytes
                    .fetch_sub(charge, std::sync::atomic::Ordering::Relaxed);
                Err((QueueError::Closed, Box::new(queued.msg)))
            }
        }
    }

    /// Queue a message, reporting a full queue instead of discarding it
    /// silently, and return whether it was queued.
    ///
    /// This is the entry point for every producer that tolerates a drop.
    /// The caller must treat `false` as "not sent" and skip any
    /// bookkeeping that claims otherwise — a peer marked as knowing an
    /// inventory item it was never told about never gets a retry.
    /// A closed queue is teardown, so it is not reported.
    pub fn try_queue(&self, msg: Message) -> bool {
        let command = msg.command();
        match self.queue_message(msg) {
            Ok(()) => true,
            Err(QueueError::Full) => {
                self.report_full(command);
                false
            }
            Err(QueueError::Closed) => false,
        }
    }

    /// Log that a message was dropped because the queue is full, at most
    /// once per congestion episode.  Exposed for the producers that take
    /// their own action (a disconnect, say) on top of the report.
    pub fn report_full(&self, command: &str) {
        if self
            .state
            .reported_full
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            return;
        }
        let unsent_kib = self.state.bytes.load(std::sync::atomic::Ordering::Relaxed) / 1024;
        crate::logging::warn(
            "PEER",
            &format!(
                "Outbound queue for peer {} is full ({unsent_kib} KiB in at most \
                 {MAX_OUTBOUND_QUEUE_DEPTH} unsent messages) -- dropping {command}",
                self.peer_label()
            ),
        );
    }
}

/// Write queued messages to the peer until the outbound queue is closed
/// or a write fails, without stall detection (dcrd's `outHandler` for a
/// peer whose stall handler is not running).
pub fn run_peer_output<T, E>(
    peer: &Mutex<Peer>,
    transport: &mut T,
    env: &mut E,
    outbound: OutboundReceiver,
) -> DisconnectReason
where
    T: MsgTransport,
    E: PeerEnv,
{
    run_peer_output_with_stall(peer, transport, env, outbound, None)
}

/// Write queued messages to the peer until the outbound queue is closed
/// or a write fails (dcrd's `outHandler` draining the send queue).  Each
/// completed write contributes its byte delta and timestamp to the
/// peer's send accounting (dcrd's `writeMessage` bookkeeping).
///
/// Every ping is stamped as the outstanding one immediately before it
/// is written, whoever queued it — the keepalive timer or the `ping`
/// RPC's broadcast — so the answering pong is matched and its round
/// trip excludes the time the ping spent waiting in the queue (dcrd's
/// `outHandler` setting `lastPingNonce`/`lastPingTime` for every
/// `MsgPing` it takes off the send queue).
///
/// Every message is reported to the stall detector just before it goes
/// out, arming a deadline for the response it expects (dcrd's
/// `sccSendMessage`, signalled from `outHandler` at the same point).
pub fn run_peer_output_with_stall<T, E>(
    peer: &Mutex<Peer>,
    transport: &mut T,
    env: &mut E,
    outbound: OutboundReceiver,
    stall: Option<&Mutex<StallDetector>>,
) -> DisconnectReason
where
    T: MsgTransport,
    E: PeerEnv,
{
    let mut write_total = transport.total_bytes_written();
    while let Ok(msg) = outbound.recv() {
        // Setup ping statistics, first and under the peer lock alone,
        // exactly where dcrd's `outHandler` does it.  Stamped before the
        // write, so the pong cannot be read before its nonce is known.
        if let Message::Ping(ping) = &msg {
            peer.lock()
                .expect("peer mutex poisoned")
                .record_sent_ping(env, ping);
        }
        // Arm the deadline before the write, and hold only the stall
        // lock while doing so: the send accounting below takes the peer
        // lock, and the input loop takes them in the opposite order.
        if let Some(stall) = stall {
            let outcome = stall
                .lock()
                .expect("stall mutex poisoned")
                .sent_message(&msg);
            if outcome == ArmOutcome::ExceededPendingBurst {
                // dcrd logs and disconnects rather than arming, so the
                // peer cannot run further ahead with inventory it has
                // not served.  The message is dropped unsent.
                //
                // Logged here because the reason does not survive
                // teardown: ending this loop shuts the socket down, and
                // the connection's reason comes from the input loop,
                // which by then sees only the resulting end of stream.
                // dcrd's `maybeAddDeadline` logs this at debug
                // (`peer/peer.go:1113`).
                let label = peer_log_label(&peer.lock().expect("peer mutex poisoned"));
                crate::logging::debug(
                    "PEER",
                    &format!(
                        "Peer {label} exceeded max pending inventory announcements \
                         without serving data -- disconnecting"
                    ),
                );
                return DisconnectReason::Protocol(
                    "exceeded max pending inventory announcements without serving data".into(),
                );
            }
        }
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
/// or the outbound queue closes (the ping ticker dcrd's `outHandler`
/// owns).  Each tick queues a ping with a fresh nonce and nothing more:
/// the output loop stamps it as the outstanding ping when it writes it,
/// as dcrd's `outHandler` does for every `MsgPing` whoever queued it.
///
/// A full queue does **not** end the timer.  The keepalive is what keeps
/// a live-but-quiet peer from tripping the idle read deadline, so
/// abandoning it because of one congested tick would turn a transient
/// burst into a disconnect several minutes later, for a peer that is
/// reading again by then.  The tick is skipped, reported, and the next
/// one tries again; only a closed queue (the connection tearing down)
/// stops the timer.
///
/// This is the scheduler a served connection runs ([`run_peer_timers`])
/// with the stall check left out, so what holds here holds for the
/// keepalive the daemon actually runs.
pub fn run_ping_timer<E: PeerEnv>(
    env: &mut E,
    outbound: &OutboundQueue,
    interval: Duration,
    shutdown: &mpsc::Receiver<()>,
) {
    let _ = run_timers(env, outbound, interval, None, shutdown);
}

/// Queue one keepalive ping (a tick of dcrd's ping ticker, `QueueMessage(
/// wire.NewMsgPing(rand.Uint64()))`), returning false once the queue is
/// closed.  A full queue skips the tick and reports it.
fn queue_keepalive<E: PeerEnv>(env: &mut E, outbound: &OutboundQueue) -> bool {
    let ping = MsgPing {
        nonce: env.rand_u64(),
    };
    match outbound.queue_message(Message::Ping(ping)) {
        Ok(()) => true,
        Err(QueueError::Full) => {
            outbound.report_full("ping");
            true
        }
        Err(QueueError::Closed) => false,
    }
}

/// How long a stall detector waits between checks and how long it
/// grants an expected response to arrive (dcrd's `stallTickInterval`
/// and `stallResponseTimeout`).
///
/// [`StallConfig::default`] is dcrd's production pair; tests shorten
/// both so a stall is observable in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StallConfig {
    /// The interval between stall checks.
    pub tick: Duration,
    /// The base deadline granted to an expected response.
    pub response_timeout: Duration,
}

impl Default for StallConfig {
    fn default() -> StallConfig {
        StallConfig {
            tick: Duration::from_nanos(STALL_TICK_INTERVAL.max(0) as u64),
            response_timeout: Duration::from_nanos(STALL_RESPONSE_TIMEOUT.max(0) as u64),
        }
    }
}

/// Run one stall check (a tick of dcrd's `stallHandler`), disconnecting
/// the peer and returning the stalled command when a pending response
/// is past its adjusted deadline.
///
/// dcrd funnels the stall events through a `stallControl` channel into a
/// dedicated goroutine because that is Go's idiom for owning mutable
/// state; the port shares the state behind its own mutex instead, which
/// is the direct Rust idiom, keeps the I/O loops from ever blocking on a
/// control channel, and removes the channel-versus-quit race entirely.
/// The observable behavior is dcrd's: the same deadlines, the same
/// per-tick check, and the same disconnect.
///
/// Disconnecting ends the connection through its [`Teardown`] handle,
/// which raises the flag the input loop polls and shuts the socket down
/// in one call — the mechanism every teardown in the daemon now shares,
/// and the reason a `shutdown` alone is not enough: issued on a
/// different handle to the same socket it is not a portable way to
/// abort a receive already in flight (dcrd's `Disconnect` closing the
/// conn does both).  The stalled command is returned so the caller can
/// report why the connection ended.
///
/// [`Teardown`]: crate::transport::Teardown
fn check_stall(
    stall: &Mutex<StallDetector>,
    conn: &crate::transport::Teardown,
    peer_label: &str,
) -> Option<StallReason> {
    let reason = stall.lock().expect("stall mutex poisoned").check()?;
    crate::logging::info(
        "PEER",
        &format!(
            "Peer {peer_label} appears to be stalled or misbehaving \
             (reason: {}) -- disconnecting",
            reason.exceeded_text()
        ),
    );
    // Both halves, in this order: the flag is what the input loop
    // actually watches, while the socket shutdown still delivers the
    // FIN the remote is owed; see `Teardown::disconnect`.
    conn.disconnect();
    Some(reason)
}

/// Run a served connection's two timers on one thread until shutdown is
/// signalled: the keepalive ping every `ping_interval` (dcrd's
/// `outHandler` ticker, see [`run_ping_timer`]) and the stall check
/// every `stall_tick` (dcrd's `stallHandler`, see `check_stall`).
///
/// dcrd's timers are goroutines, which cost nothing; each OS thread
/// here is a real task against the process's thread limit, and both of
/// these do nothing but sleep, so one thread wakes for whichever is due
/// next.  Each keeps its own schedule: a congested ping tick is
/// skipped, a closed queue stops the pings but not the stall checks,
/// and a stall disconnects the peer and returns the stalled command.
#[allow(clippy::too_many_arguments)] // The two timers' inputs, side by side.
pub fn run_peer_timers<E: PeerEnv>(
    env: &mut E,
    outbound: &OutboundQueue,
    ping_interval: Duration,
    stall: &Mutex<StallDetector>,
    conn: &crate::transport::Teardown,
    peer_label: &str,
    stall_tick: Duration,
    shutdown: &mpsc::Receiver<()>,
) -> Option<StallReason> {
    let stall = StallCheck {
        stall,
        conn,
        peer_label,
        tick: stall_tick,
    };
    run_timers(env, outbound, ping_interval, Some(&stall), shutdown)
}

/// The stall half of [`run_peer_timers`]: the shared detector state, the
/// teardown handle a stall ends the connection through, the peer's log
/// label, and the check interval.
struct StallCheck<'a> {
    stall: &'a Mutex<StallDetector>,
    conn: &'a crate::transport::Teardown,
    peer_label: &'a str,
    tick: Duration,
}

/// The one timer scheduler: the keepalive every `ping_interval` and,
/// when `stall` is given, the stall check on its own tick, until
/// shutdown is signalled.  Without a stall check a closed queue ends it,
/// since nothing is left to schedule.
fn run_timers<E: PeerEnv>(
    env: &mut E,
    outbound: &OutboundQueue,
    ping_interval: Duration,
    stall: Option<&StallCheck<'_>>,
    shutdown: &mpsc::Receiver<()>,
) -> Option<StallReason> {
    // `None` is "never": an interval too long to represent as an
    // instant, or a ping timer whose queue has closed.
    let start = Instant::now();
    let mut next_ping = start.checked_add(ping_interval);
    let mut next_stall = stall.and_then(|check| start.checked_add(check.tick));
    loop {
        let next = match (next_ping, next_stall) {
            (Some(ping), Some(stall)) => Some(ping.min(stall)),
            (ping, stall) => ping.or(stall),
        };
        let signal = match next {
            Some(at) => shutdown.recv_timeout(at.saturating_duration_since(Instant::now())),
            None => shutdown
                .recv()
                .map_err(|_| mpsc::RecvTimeoutError::Disconnected),
        };
        match signal {
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let now = Instant::now();
                if let Some(check) = stall
                    && next_stall.is_some_and(|at| now >= at)
                {
                    if let Some(reason) = check_stall(check.stall, check.conn, check.peer_label) {
                        return Some(reason);
                    }
                    next_stall = now.checked_add(check.tick);
                }
                if next_ping.is_some_and(|at| now >= at) {
                    if queue_keepalive(env, outbound) {
                        next_ping = now.checked_add(ping_interval);
                    } else if stall.is_none() {
                        return None;
                    } else {
                        next_ping = None;
                    }
                }
            }
            // Shutdown signalled, or the signalling half was dropped.
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return None,
        }
    }
}

/// Bypass self-connection detection for in-process harnesses.
///
/// The check compares an arriving nonce against every nonce this
/// *process* has sent, so two nodes stood up in one test process look
/// exactly like a node dialling itself.  dcrd carries the same escape
/// for the same reason (`peer.go:108-111`, set at `peer_test.go:1089`).
#[doc(hidden)]
pub fn allow_self_connections() {
    peer_globals().set_allow_self_conns(true);
}

/// The peer state dcrd keeps in package globals: the id counter and the
/// nonces of version messages this node has sent.
///
/// Process-wide for the same reason dcrd's are — self-connection
/// detection compares a nonce arriving on one connection against the
/// nonces sent on all the others, so a per-connection cache can never
/// match.
fn peer_globals() -> &'static PeerGlobals {
    static GLOBALS: std::sync::LazyLock<PeerGlobals> = std::sync::LazyLock::new(PeerGlobals::new);
    &GLOBALS
}

/// Run a peer connection with dcrd's production stall timings.
#[allow(clippy::too_many_arguments)] // Mirrors dcrd's connection surface.
pub fn run_peer_connection<H>(
    conn: crate::transport::Teardown,
    peer: Peer,
    pver: u32,
    net: CurrencyNet,
    idle_timeout: Duration,
    ping_interval: Duration,
    net_totals: Option<Arc<crate::transport::NetByteTotals>>,
    hooks: H,
) -> DisconnectReason
where
    H: ServeHooks,
{
    run_peer_connection_with_stall(
        conn,
        peer,
        pver,
        net,
        idle_timeout,
        ping_interval,
        net_totals,
        hooks,
        StallConfig::default(),
    )
}

/// dcrd's `errHandshakeTimeout` text.
const HANDSHAKE_TIMEOUT_TEXT: &str = "protocol handshake timeout";

/// The version handshake's view of the connection: every read and write
/// is bounded by what remains of one absolute deadline.
///
/// dcrd's `Handshake` runs the whole exchange inside one `select` on
/// `time.After(negotiateTimeout)` (`peer/peer.go:2341-2354`) and
/// disconnects when it fires, so the
/// 30 seconds cover the handshake, not each message of it.  A budget
/// re-armed per read let a peer spend up to 30 seconds on each of the
/// version and verack reads, and on each of the three extra reads a
/// legacy (pre-addrv2) peer is allowed before its verack, holding an
/// admitted connection two to four times as long as dcrd would.  Each
/// read here gets the time remaining, or the idle timeout if shorter
/// (dcrd's `readMessage` arms `SetReadDeadline(now + IdleTimeout)`
/// inside that select too); each write gets dcrd's write-stall bound,
/// cut short by the same deadline.
struct HandshakeTransport<'t, S> {
    inner: &'t mut WireTransport<S>,
    deadline: Instant,
    idle_timeout: Duration,
}

impl<S> HandshakeTransport<'_, S> {
    fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
}

impl<S: Read + Write + SocketTimeout> MsgTransport for HandshakeTransport<'_, S> {
    fn read_message(&mut self) -> Result<Message, ReadError> {
        let budget = self.remaining().min(self.idle_timeout);
        self.inner.set_read_budget(Some(budget));
        // dcrd's `ReadMessageN` reports every short read as `io.EOF`,
        // and its `Handshake` returns that error as it is, so a remote
        // that closes, resets or goes quiet mid-handshake is logged as
        // `Failed handshake for %s peer %s: EOF` (`server.go:2291`, `:2324`).
        self.inner.read_message().map_err(|mut e| {
            if !e.wire_violation && is_short_read(&e.message) {
                e.message = CODEC_EOF_TEXT.to_string();
            }
            e
        })
    }

    fn write_message(&mut self, msg: &Message) -> Result<(), String> {
        let policy = WriteStallPolicy::dcrd();
        self.inner.set_write_stall_policy(Some(WriteStallPolicy {
            base: policy.base.min(self.remaining()),
            ..policy
        }));
        let result = self.inner.write_message(msg);
        self.inner.set_write_stall_policy(None);
        result
    }

    fn set_protocol_version(&mut self, pver: u32) {
        WireTransport::set_protocol_version(self.inner, pver);
    }

    fn total_bytes_read(&self) -> u64 {
        self.inner.total_bytes_read()
    }

    fn total_bytes_written(&self) -> u64 {
        self.inner.total_bytes_written()
    }
}

/// Run the version handshake (inbound or outbound per the peer) within
/// `negotiate_timeout` as a whole, firing `on_version` from inside it
/// exactly where dcrd 2.2's `onVersion` callback runs, and return the
/// remote version plus the messages a legacy peer sent before its
/// verack.
///
/// A handshake still unfinished at the deadline fails with dcrd's
/// `errHandshakeTimeout` text rather than with the read or write it
/// interrupted, as dcrd's `select` does, and so does one the node's
/// shutdown cut short (the connection's flag raised by
/// `Teardown::disconnect_for_shutdown`), as dcrd's `ctx.Done` arm does
/// (`peer/peer.go:2352-2353`).  A read that fails at the socket
/// otherwise fails with dcrd's `EOF` ([`is_short_read`]), a conn closed
/// under it by the connection manager included.  A wire violation
/// already read is still reported as one, so the caller bans on it.
fn negotiate_within<S, E>(
    peer: &mut Peer,
    transport: &mut WireTransport<S>,
    env: &mut E,
    on_version: &mut dyn FnMut(&Peer, &MsgVersion) -> Result<(), String>,
    negotiate_timeout: Duration,
    idle_timeout: Duration,
) -> Result<(Box<MsgVersion>, Vec<Message>), NegotiateError>
where
    S: Read + Write + SocketTimeout,
    E: PeerEnv,
{
    let now = Instant::now();
    let mut bounded = HandshakeTransport {
        inner: transport,
        deadline: now.checked_add(negotiate_timeout).unwrap_or(now),
        idle_timeout,
    };
    // Shared by every connection, because that is the only way the check
    // it feeds can fire.  dcrd keeps `sentNonces` and `nodeCount` in
    // package globals (`peer/peer.go:100-106`); a fresh set per connection
    // means the outbound half holds only its own nonce and the inbound
    // half checks against an empty set, so a node that dials itself
    // completes the handshake and peers with itself.
    let globals = peer_globals();
    let negotiated = if peer.inbound() {
        peer.negotiate_inbound_protocol(&mut bounded, env, globals, Some(on_version))
    } else {
        peer.negotiate_outbound_protocol(&mut bounded, env, globals, Some(on_version))
    };
    let shutting_down = bounded
        .inner
        .cancel_flag()
        .is_some_and(crate::transport::Cancel::is_shutdown);
    match negotiated {
        Ok(outcome) => Ok((outcome.remote_version, outcome.delayed)),
        Err(e) if !e.wire_violation && (bounded.remaining().is_zero() || shutting_down) => {
            Err(NegotiateError {
                message: HANDSHAKE_TIMEOUT_TEXT.to_string(),
                kind: Some(NegotiateErrorKind::HandshakeTimeout),
                remote_version: e.remote_version,
                wire_violation: false,
            })
        }
        Err(e) => Err(e),
    }
}

/// The error text of the transport's absolute read deadline expiring
/// (`read_exact_by_deadline` in `transport.rs`), which is dcrd's read
/// deadline timeout.
const READ_TIMED_OUT_TEXT: &str = "read timed out";

/// The error text of a read that found the stream closed
/// (`read_exact_by_deadline` in `transport.rs`, which words it as `std`'s
/// `read_exact` does), which is dcrd's `io.EOF`.
const READ_EOF_TEXT: &str = "failed to fill whole buffer";

/// The error text of a read the connection's own teardown cut short
/// (`read_exact_by_deadline` in `transport.rs`): dcrd's read of a conn
/// closed under it.
const READ_TORN_DOWN_TEXT: &str = "the connection was torn down locally";

/// The wire codec's text for Go's `io.EOF`: a payload that ends on a
/// field boundary (`WireError::Eof`).
const CODEC_EOF_TEXT: &str = "EOF";

/// Whether a failed read is a failure of the socket read itself rather
/// than of the wire codec, which dcrd sees as `io.EOF`: since
/// `04fef0bf`, `wire.ReadMessageN` turns any short read into `io.EOF`
/// (`wire/message.go:375-377`, `:457-459`), whether the remote closed
/// the stream, the socket failed, the read deadline expired or the
/// local side closed the conn.
///
/// The transport reports failures as text, so they are told apart by
/// its own messages: its deadline, closed-stream and teardown texts,
/// and `std`'s rendering of an OS error with its `(os error N)` suffix.
fn is_short_read(message: &str) -> bool {
    matches!(
        message,
        READ_TIMED_OUT_TEXT | READ_EOF_TEXT | READ_TORN_DOWN_TEXT
    ) || message.contains("(os error ")
}

/// The read error dcrd's `inHandler` would log, at error, as "Can't
/// read message from %s: %v" for the way a connection's input loop
/// ended, if any (`peer/peer.go:1556-1561` over `shouldHandleReadError`,
/// `:1054`).
///
/// At the pin dcrd logs only failures of the wire codec.  Every failure
/// of the socket read itself is silent: `wire.ReadMessageN` turns it
/// into `io.EOF` ([`is_short_read`]), and `shouldHandleReadError`
/// declines `io.EOF`.  The same rewrite makes the "Peer %s no answer
/// for %s -- disconnecting" warning that follows
/// (`peer/peer.go:1563-1566`) unreachable: its `net.Error` timeout test
/// never matches `io.EOF`, so an idle peer is dropped without a word and
/// the warning is not ported.  Nothing is logged either when the local
/// side is already disconnecting (`p.disconnect`, here the connection's
/// teardown flag), and a ban that disconnected the peer ends the loop
/// as [`DisconnectReason::Protocol`], not as a read error.
///
/// A payload that runs out inside the message's structure is not a
/// socket failure but a decode one, which dcrd's `BtcDecode`
/// returns raw (`wire/message.go:482-485`): `io.EOF` (silent) when the
/// payload ends on a field boundary and `io.ErrUnexpectedEOF` (logged)
/// when it ends inside a field (`shortRead` at `wire/common.go:131-137`,
/// and `io.ReadFull` alike).  The wire crate tells the two apart
/// (`WireError::Eof` renders `EOF`, `WireError::UnexpectedEof` renders
/// `unexpected EOF`), and the transport passes either on as a read
/// error that is not a wire violation, so neither is banned.  This
/// function logs `unexpected EOF` as dcrd does and declines `EOF`, as
/// dcrd's `errors.Is(err, io.EOF)` does (`peer/peer.go:1063-1065`).
fn read_error_to_log(reason: &DisconnectReason, cancelled: bool) -> Option<&str> {
    let DisconnectReason::ReadError(message) = reason else {
        return None;
    };
    if cancelled {
        return None;
    }
    match message.as_str() {
        CODEC_EOF_TEXT => None,
        socket if is_short_read(socket) => None,
        codec => Some(codec),
    }
}

/// Drop a connection whose thread the OS refused, before the server has
/// heard of it.  `std::thread::spawn` would have panicked instead, and
/// release builds abort on a panic, so one peer arriving under thread
/// exhaustion took the whole node down; dcrd's goroutines cannot fail
/// to start.
fn refuse_connection(
    transport: &WireTransport<crate::transport::Teardown>,
    label: &str,
    err: &std::io::Error,
) -> DisconnectReason {
    crate::logging::warn(
        "PEER",
        &format!("Unable to start a thread for peer {label}: {err} -- disconnecting"),
    );
    transport.get_ref().disconnect();
    DisconnectReason::ThreadRefused(err.to_string())
}

/// Run a peer connection from the negotiated handshake through the
/// steady-state message loops until it disconnects (dcrd's `Handshake`
/// then `serverPeer.Run` over `Peer.Run`, the goroutines as OS threads).
///
/// The socket is split into read and write halves; the version handshake
/// runs (inbound or outbound per the peer) before the loops start,
/// bounded as a whole by dcrd's negotiate timeout; then the output loop
/// runs on its own thread, the keepalive ping and the stall detector
/// share a second ([`run_peer_timers`]), and the input loop runs on this
/// thread.  When the input loop ends the socket is shut down and the
/// timer thread signalled before the server's disconnection hook runs
/// (dcrd's `Disconnect` before `DonePeer`); then the outbound queue is
/// closed so the output loop finishes, and both threads are joined
/// before returning the reason the connection stopped.
/// `idle_timeout` bounds each read so a silent peer eventually
/// disconnects (dcrd's idle timer); `ping_interval` should be shorter so
/// a live peer answers before that fires.
///
/// The idle timer alone is not enough: a peer that keeps answering the
/// keepalive pings while never serving the data it was asked for looks
/// perfectly alive to it, yet pins every in-flight request slot
/// forever.  `stall` is what bounds that — the pending responses are
/// checked every `stall.tick` and the peer is disconnected once one has
/// not arrived by its deadline (dcrd's `stallHandler`).
///
/// Both threads start before the server hears of the peer, as dcrd's
/// `serverPeer.Run` starts `Peer.Run` before `AddPeer`, so a thread the
/// OS refuses drops the connection with nothing to unwind
/// ([`DisconnectReason::ThreadRefused`]).
#[allow(clippy::too_many_arguments)] // Mirrors dcrd's connection surface.
pub fn run_peer_connection_with_stall<H>(
    conn: crate::transport::Teardown,
    mut peer: Peer,
    pver: u32,
    net: CurrencyNet,
    idle_timeout: Duration,
    ping_interval: Duration,
    net_totals: Option<Arc<crate::transport::NetByteTotals>>,
    mut hooks: H,
    stall: StallConfig,
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
    let write_stream = match conn.try_clone() {
        Ok(write_stream) => write_stream,
        Err(e) => return DisconnectReason::WriteError(e.to_string()),
    };
    // A third handle on the same connection, so the stall detector can
    // tear it down from its own thread (dcrd's `Disconnect`).
    let stall_stream = match conn.try_clone() {
        Ok(stall_stream) => stall_stream,
        Err(e) => return DisconnectReason::WriteError(e.to_string()),
    };
    // The connection's teardown flag, minted with the socket at the
    // accept or the dial rather than here, so the server's own
    // disconnect paths -- which never enter this function -- raise the
    // one flag this transport polls.  Taken before the transport
    // consumes the handle.
    let cancel = conn.cancel();
    // The handshake is framed at the local maximum protocol version (0
    // is dcrd's "package maximum" sentinel); the transport is lowered to
    // the negotiated version below.
    let handshake_pver = if pver == 0 {
        MAX_PROTOCOL_VERSION
    } else {
        pver
    };
    let mut read_transport = WireTransport::new(conn, handshake_pver, net);
    // The connection's teardown signal, installed before the handshake.
    // The read budgets are seconds to minutes long, so without something
    // the reader polls, a peer this node has decided to drop stays
    // parked in its receive until that budget runs out — the socket
    // shutdown the other loops perform cannot be relied on to cut it
    // short across platforms.  The flag was minted with the socket, so
    // raising it is the same act for the server's disconnect paths
    // (shutdown's `disconnect_all` included, mid-handshake) as for this
    // connection's own loops: dcrd's `Peer.Disconnect` reaches every
    // teardown because the conn is the shared object, and here the
    // `Teardown` is.
    read_transport.set_cancel(cancel.clone());
    let mut write_transport = WireTransport::new(write_stream, handshake_pver, net);
    // Every send is bounded so a peer that stops reading its socket is
    // disconnected instead of parking the writer thread with the
    // outbound queue held.  The bound is dcrd's write-stall policy —
    // twenty seconds plus a second per 256 KiB of the framed message —
    // not the idle timeout: dcrd keeps the two separate, and a flat
    // budget is wrong at both ends of the size range, cutting off a
    // large block on an honest slow link while indulging a peer that
    // stalls a tiny one.
    write_transport.set_write_stall_policy(Some(WriteStallPolicy::dcrd()));
    // Both halves contribute to the server-wide byte totals from the
    // handshake onward, exactly like dcrd's read/write listeners.
    if let Some(totals) = net_totals {
        read_transport.set_net_totals(Arc::clone(&totals));
        write_transport.set_net_totals(totals);
    }

    // Run the handshake (version and verack exchange) before starting
    // the loops, firing the server's version listener from inside it.
    // The read transport is full duplex, so it also writes the local
    // messages.
    let mut env = NodePeerEnv::new();
    let (remote_version, delayed) = {
        let mut on_version = |p: &Peer, msg: &MsgVersion| hooks.on_version(p, msg);
        let negotiated = negotiate_within(
            &mut peer,
            &mut read_transport,
            &mut env,
            &mut on_version,
            negotiate_timeout,
            idle_timeout,
        );
        match negotiated {
            Ok(outcome) => outcome,
            Err(e) => {
                // A wire violation bans during the handshake too.
                // dcrd installs its read listener before `Handshake`
                // for both directions and runs it on the version and
                // verack reads (`peer.go:1998`, `:2069`, `:2098`), and
                // `serverPeer.OnRead` bans on any `wire.ErrorCode` with
                // no handshake-state guard (`server.go:1851-1857`).
                // Without this a peer could violate the protocol
                // indefinitely by never completing a handshake.  The
                // failed handshake is reported the same way whether or
                // not the ban disconnected (`server.go:2290-2293`).
                if e.wire_violation {
                    let _ = hooks.on_wire_violation(&e.message);
                }
                return DisconnectReason::Negotiate(e.message);
            }
        }
    };

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

    // How dcrd's peer logging names this peer, for every line below.
    let label = peer_log_label(&peer);
    let peer = Arc::new(Mutex::new(peer));
    let (outbound, receiver) = OutboundQueue::channel();
    // Name the queue so a congestion report identifies the peer.
    outbound.set_peer_label(label.clone());

    // The stall state the three loops share: the output loop arms the
    // deadlines, the input loop settles them and brackets the
    // callbacks, and the timer thread checks them (dcrd's stall control
    // channel into `stallHandler`).
    let stall_state = Arc::new(Mutex::new(StallDetector::with_response_timeout(
        i64::try_from(stall.response_timeout.as_nanos()).unwrap_or(i64::MAX),
    )));

    let output_peer = Arc::clone(&peer);
    let output_stall = Arc::clone(&stall_state);
    let output = crate::runtime::spawn_conn_thread("peer-output", move || {
        let mut output_env = NodePeerEnv::new();
        let reason = run_peer_output_with_stall(
            &output_peer,
            &mut write_transport,
            &mut output_env,
            receiver,
            Some(&output_stall),
        );
        // A failed write is not logged.  dcrd's `outHandler` has the
        // line ("Failed to send message to %s", `peer/peer.go:1792`),
        // but it calls `Disconnect` first (`:1790`), and
        // `shouldLogWriteError` then always declines on the disconnect
        // flag that just went up (`:1744`).
        //
        // End the connection when the output loop ends (a write error
        // or a closed queue).  One call raises the flag the input loop
        // polls and shuts the socket so the remote gets its FIN; see
        // `Teardown::disconnect`.
        write_transport.get_ref().disconnect();
        reason
    });
    let output = match output {
        Ok(output) => output,
        Err(e) => return refuse_connection(&read_transport, &label, &e),
    };

    // The keepalive ping and the stall detector share one thread: a peer
    // that keeps the connection alive while never serving what it was
    // asked for is disconnected instead of pinning the request slots
    // forever (dcrd's `stallHandler`).
    let (timer_shutdown, timer_shutdown_rx) = mpsc::channel();
    let timer_outbound = outbound.clone();
    let timer_stall = Arc::clone(&stall_state);
    let timer_label = label.clone();
    let stall_tick = stall.tick;
    let timers = crate::runtime::spawn_conn_thread("peer-timers", move || {
        let mut timer_env = NodePeerEnv::new();
        run_peer_timers(
            &mut timer_env,
            &timer_outbound,
            ping_interval,
            &timer_stall,
            &stall_stream,
            &timer_label,
            stall_tick,
            &timer_shutdown_rx,
        )
    });
    let timers = match timers {
        Ok(timers) => timers,
        Err(e) => {
            let reason = refuse_connection(&read_transport, &label, &e);
            // Closing the queue ends the output loop; join it so no
            // thread outlives the connection.
            drop(outbound);
            let _ = output.join();
            return reason;
        }
    };

    // Request all block announcements via full headers instead of the
    // inv message (dcrd `serverPeer.Run` queueing `NewMsgSendHeaders`
    // before `AddPeer`).  The queue is empty here, so this cannot fail
    // with [`QueueError::Full`]; a failure is a closed queue.
    let connected = outbound.queue_message(Message::SendHeaders).is_ok();
    let reason = if !connected {
        DisconnectReason::LocalShutdown
    } else {
        // The handshake is complete: hand the peer to the server's
        // lifecycle hook (dcrd `AddPeer` signalling the sync manager),
        // unlocked (see [`ServeHooks::on_connected`]).
        hooks.on_connected(&peer, &outbound, remote_version.disable_relay_tx);

        // Drive the input loop on this thread until the peer disconnects.
        let reason = run_peer_input_with_stall(
            &peer,
            &mut read_transport,
            &mut env,
            &outbound,
            &mut hooks,
            delayed,
            Some(&stall_state),
        );
        // dcrd's `inHandler` logs the failed read before it disconnects,
        // so the flag still says whether something else ended the
        // connection first.
        if let Some(err) = read_error_to_log(&reason, cancel.is_cancelled()) {
            crate::logging::error("PEER", &format!("Can't read message from {label}: {err}"));
        }
        reason
    };

    // Tear down before the server lets the peer go, in dcrd's order:
    // `inHandler` ends with `p.Disconnect()` (`peer/peer.go:1593-1594`),
    // and `DonePeer` runs only once `Peer.Run` has returned
    // (`server.go:725-727`).  Shutting the socket down gives the remote
    // its FIN now and fails any write the output loop still attempts
    // (dcrd's `writeMessage` sends nothing once disconnecting), which
    // also unblocks a write a peer that stopped reading would otherwise
    // wedge; stopping the timers ends the pings and the stall checks
    // (dcrd's `stallHandler` exits on `quit`).  The server's hook can
    // then wait out another peer's block validation on the sync manager
    // without this peer seeing any of it: before, the socket stayed open
    // for that wait, relay traffic and pings kept being written to a
    // peer already dropped, and a deadline expiring meanwhile logged a
    // stall for a peer that was already gone.
    read_transport.get_ref().disconnect();
    let _ = timer_shutdown.send(());
    if connected {
        // The connection is winding down (dcrd `DonePeer`).
        hooks.on_disconnected(&peer);
    }

    // Close the outbound queue and join both threads.  The output loop
    // ends once every sender is gone, and the server's clones (its relay
    // registry and getdata worker) are released by `on_disconnected`.
    drop(outbound);
    let _ = output.join();
    // A stall is the real reason the connection ended; the input loop
    // only saw the socket the detector shut down under it.
    match timers.join() {
        Ok(Some(command)) => DisconnectReason::Protocol(
            format!("peer appears to be stalled or misbehaving, {command} timeout").into(),
        ),
        Ok(None) | Err(_) => reason,
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

    const NET: CurrencyNet = CurrencyNet::TEST_NET3;
    const NEVER: Duration = Duration::from_secs(3600);

    fn loopback_config(name: &str) -> Config {
        Config {
            net: NET,
            services: dcroxide_wire::ServiceFlag(1),
            user_agent_name: name.to_string(),
            user_agent_version: "0.1.0".to_string(),
            protocol_version: 0,
            ..Config::default()
        }
    }

    /// A connected loopback pair: the accepted (server) end as a
    /// teardown handle with its remote address, and the dialing end.
    fn loopback_pair() -> (
        crate::transport::Teardown,
        std::net::SocketAddr,
        std::net::TcpStream,
    ) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let client =
            std::net::TcpStream::connect(listener.local_addr().expect("addr")).expect("dial");
        let (server, remote) = listener.accept().expect("accept");
        (crate::transport::Teardown::new(server), remote, client)
    }

    /// An inbound peer associated with the accepted address, the way
    /// `serve_inbound_peer` builds one.
    fn inbound_peer(remote: std::net::SocketAddr) -> Peer {
        let mut peer = Peer::new_inbound(loopback_config("dcroxide-in"));
        let na = crate::peerconn::net_address_v2_from_socket(remote, dcroxide_wire::ServiceFlag(0))
            .expect("net address");
        peer.associate(&remote.to_string(), na, 0);
        peer
    }

    /// Complete the outbound half of the version handshake on the
    /// dialing end, returning its framed transport.
    fn client_handshake(client: std::net::TcpStream) -> WireTransport<std::net::TcpStream> {
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let addr = client.peer_addr().expect("peer addr").to_string();
        let mut transport = WireTransport::new(client, MAX_PROTOCOL_VERSION, NET);
        let mut peer =
            Peer::new_outbound(loopback_config("dcroxide-out"), &addr).expect("outbound peer");
        peer.negotiate_outbound_protocol(
            &mut transport,
            &mut NodePeerEnv::new(),
            &PeerGlobals::new(),
            None,
        )
        .expect("outbound negotiation");
        transport
    }

    /// Serve hooks whose handler blocks on a ping with nonce 1, after
    /// queueing two pongs, until the test releases it: a stand-in for
    /// a block handler waiting out another peer's validation.  With
    /// `block_connect`, the connection hook blocks the same way, after
    /// queueing a pong with nonce 201: a stand-in for `AddPeer` waiting
    /// on the sync manager.
    struct BlockingHooks {
        handle: Arc<Mutex<Option<Arc<Mutex<Peer>>>>>,
        entered: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
        connected: Arc<std::sync::atomic::AtomicBool>,
        block_connect: bool,
    }

    impl ServeHooks for BlockingHooks {
        fn on_connected(
            &mut self,
            peer: &Arc<Mutex<Peer>>,
            outbound: &OutboundQueue,
            _remote_disable_relay_tx: bool,
        ) {
            self.connected
                .store(true, std::sync::atomic::Ordering::SeqCst);
            *self.handle.lock().expect("handle slot") = Some(Arc::clone(peer));
            if self.block_connect {
                assert!(outbound.try_queue(Message::Pong(MsgPong { nonce: 201 })));
                let _ = self.entered.send(());
                let _ = self.release.recv_timeout(Duration::from_secs(20));
            }
        }

        fn on_message(
            &mut self,
            _peer: &Mutex<Peer>,
            msg: Message,
            _mix_hash: Option<dcroxide_chainhash::Hash>,
            outbound: &OutboundQueue,
        ) -> ServeSignal {
            if matches!(msg, Message::Ping(ping) if ping.nonce == 1) {
                assert!(outbound.try_queue(Message::Pong(MsgPong { nonce: 101 })));
                assert!(outbound.try_queue(Message::Pong(MsgPong { nonce: 102 })));
                let _ = self.entered.send(());
                let _ = self.release.recv_timeout(Duration::from_secs(20));
            }
            ServeSignal::Continue
        }
    }

    /// A handler blocked in the server leaves the peer unlocked: the
    /// output loop keeps writing and anything else can read the peer,
    /// as dcrd's `outHandler` keeps writing while `inHandler` blocks.
    /// Holding the peer across the handler stopped the output loop
    /// after one write, so the second and third pongs never left.
    #[test]
    fn a_blocked_handler_does_not_hold_the_peer() {
        let (conn, remote, client) = loopback_pair();
        let handle = Arc::new(Mutex::new(None));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let hooks = BlockingHooks {
            handle: Arc::clone(&handle),
            entered: entered_tx,
            release: release_rx,
            connected: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            block_connect: false,
        };
        let server = std::thread::spawn(move || {
            run_peer_connection(
                conn,
                inbound_peer(remote),
                0,
                NET,
                NEVER,
                NEVER,
                None,
                hooks,
            )
        });

        let mut transport = client_handshake(client);
        transport
            .write_message(&Message::Ping(MsgPing { nonce: 1 }))
            .expect("send ping");
        entered_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the handler runs");

        // Every pong reaches the wire while the handler is still blocked.
        let mut pongs = Vec::new();
        while !pongs.contains(&102) {
            match transport.read_message() {
                Ok(Message::Pong(pong)) => pongs.push(pong.nonce),
                Ok(_) => {}
                Err(e) => panic!("the output loop stalled behind the handler: {e}"),
            }
        }
        assert_eq!(pongs, vec![1, 101, 102]);

        // And the peer can be locked from another thread meanwhile.
        let peer = handle
            .lock()
            .expect("handle slot")
            .clone()
            .expect("the peer was registered");
        let (locked_tx, locked_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = peer
                .lock()
                .map(|peer| locked_tx.send(peer.addr().to_string()));
        });
        assert_eq!(
            locked_rx.recv_timeout(Duration::from_secs(5)),
            Ok(remote.to_string()),
            "the peer must be lockable while the handler blocks"
        );

        release_tx.send(()).expect("release the handler");
        drop(transport);
        let reason = server.join().expect("server thread");
        assert!(
            matches!(reason, DisconnectReason::ReadError(_)),
            "the client closing ends the connection: {reason:?}"
        );
    }

    /// The connection hook runs with the peer unlocked too, as dcrd's
    /// `AddPeer` holds no peer lock.  The server registers the peer and
    /// then waits on the sync manager, which another peer's block
    /// validation can hold for seconds; holding the peer across that
    /// stalled `getpeerinfo` and outbound handshakes' mixing counts
    /// behind the registered peer, and stopped the output loop after
    /// its first write.
    #[test]
    fn a_blocked_connection_hook_does_not_hold_the_peer() {
        let (conn, remote, client) = loopback_pair();
        let handle = Arc::new(Mutex::new(None));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let hooks = BlockingHooks {
            handle: Arc::clone(&handle),
            entered: entered_tx,
            release: release_rx,
            connected: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            block_connect: true,
        };
        let server = std::thread::spawn(move || {
            run_peer_connection(
                conn,
                inbound_peer(remote),
                0,
                NET,
                NEVER,
                NEVER,
                None,
                hooks,
            )
        });

        let mut transport = client_handshake(client);
        entered_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the connection hook runs");

        // The sendheaders queued before the hook and the pong queued
        // inside it both reach the wire while the hook is blocked.
        let mut seen = Vec::new();
        loop {
            match transport.read_message() {
                Ok(Message::Pong(MsgPong { nonce: 201 })) => break,
                Ok(msg) => seen.push(msg),
                Err(e) => panic!("the output loop stalled behind the connection hook: {e}"),
            }
        }
        assert!(seen.contains(&Message::SendHeaders), "{seen:?}");

        // And the registered peer can be locked from another thread.
        let peer = handle
            .lock()
            .expect("handle slot")
            .clone()
            .expect("the peer was registered");
        let (locked_tx, locked_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = peer
                .lock()
                .map(|peer| locked_tx.send(peer.addr().to_string()));
        });
        assert_eq!(
            locked_rx.recv_timeout(Duration::from_secs(5)),
            Ok(remote.to_string()),
            "the peer must be lockable while the connection hook blocks"
        );

        release_tx.send(()).expect("release the hook");
        drop(transport);
        let reason = server.join().expect("server thread");
        assert!(
            matches!(reason, DisconnectReason::ReadError(_)),
            "the client closing ends the connection: {reason:?}"
        );
    }

    /// The output loop stamps every ping it writes as the outstanding
    /// one, whoever queued it (dcrd's `outHandler`); a ping queued by
    /// the `ping` RPC's broadcast rather than the keepalive timer used
    /// to go out unrecorded, so its pong was ignored.
    #[test]
    fn a_ping_is_stamped_when_written_whoever_queued_it() {
        let (conn, _remote, client) = loopback_pair();
        let peer = Arc::new(Mutex::new(Peer::new_inbound(loopback_config("dcroxide"))));
        let (queue, receiver) = OutboundQueue::channel();
        queue
            .queue_message(Message::Ping(MsgPing { nonce: 77 }))
            .expect("queue the ping");
        drop(queue);

        let writer_peer = Arc::clone(&peer);
        let writer = std::thread::spawn(move || {
            let mut transport = WireTransport::new(conn, MAX_PROTOCOL_VERSION, NET);
            run_peer_output(
                &writer_peer,
                &mut transport,
                &mut NodePeerEnv::new(),
                receiver,
            )
        });
        let mut reader = WireTransport::new(client, MAX_PROTOCOL_VERSION, NET);
        assert_eq!(
            reader.read_message().expect("read the ping"),
            Message::Ping(MsgPing { nonce: 77 })
        );
        let _ = writer.join().expect("writer thread");

        let mut guard = peer.lock().expect("peer mutex");
        assert_eq!(
            guard.last_ping_nonce(),
            77,
            "the written ping is outstanding"
        );
        // Its pong is then matched and clears it.
        guard.handle_pong_msg(&mut NodePeerEnv::new(), &MsgPong { nonce: 77 });
        assert_eq!(guard.last_ping_nonce(), 0);
    }

    /// Writes each message only after a pause, so a handshake can be
    /// made to straddle a deadline one message at a time.
    struct SlowWrites<T> {
        inner: T,
        pause: Duration,
    }

    impl<T: MsgTransport> MsgTransport for SlowWrites<T> {
        fn read_message(&mut self) -> Result<Message, ReadError> {
            self.inner.read_message()
        }

        fn write_message(&mut self, msg: &Message) -> Result<(), String> {
            std::thread::sleep(self.pause);
            self.inner.write_message(msg)
        }

        fn set_protocol_version(&mut self, pver: u32) {
            self.inner.set_protocol_version(pver);
        }
    }

    /// The negotiate timeout bounds the whole handshake, as dcrd's
    /// single `select` on `time.After(negotiateTimeout)` does, not each
    /// read.  Each of the remote's two messages here arrives well within
    /// the timeout of the read waiting for it, but the verack comes
    /// after the handshake's deadline, so the handshake fails with
    /// dcrd's `errHandshakeTimeout` text; a budget re-armed per read
    /// accepted it.
    ///
    /// The verack lands `2 * PAUSE - NEGOTIATE` after the deadline, and
    /// the elapsed bound allows `PAUSE / 2` past it: half a second each,
    /// so a runner whose socket receive timeouts fire late (macOS CI
    /// oversleeps severalfold) does not deliver the verack in time or
    /// overrun the bound.
    #[test]
    fn the_negotiate_timeout_bounds_the_whole_handshake() {
        const NEGOTIATE: Duration = Duration::from_millis(1500);
        const PAUSE: Duration = Duration::from_millis(1000);

        let (conn, remote, client) = loopback_pair();
        let dialer = std::thread::spawn(move || {
            let addr = client.peer_addr().expect("peer addr").to_string();
            let mut transport = SlowWrites {
                inner: WireTransport::new(client, MAX_PROTOCOL_VERSION, NET),
                pause: PAUSE,
            };
            let mut peer =
                Peer::new_outbound(loopback_config("dcroxide-out"), &addr).expect("outbound");
            // The server gives up first, so this side's outcome is moot.
            let _ = peer.negotiate_outbound_protocol(
                &mut transport,
                &mut NodePeerEnv::new(),
                &PeerGlobals::new(),
                None,
            );
        });

        let mut peer = inbound_peer(remote);
        let mut transport = WireTransport::new(conn, MAX_PROTOCOL_VERSION, NET);
        let started = Instant::now();
        let outcome = negotiate_within(
            &mut peer,
            &mut transport,
            &mut NodePeerEnv::new(),
            &mut |_: &Peer, _: &MsgVersion| Ok(()),
            NEGOTIATE,
            NEVER,
        );
        let elapsed = started.elapsed();
        match outcome {
            Ok(_) => panic!("a handshake finishing after the deadline must fail"),
            Err(e) => {
                assert_eq!(e.message, "protocol handshake timeout");
                assert_eq!(e.kind, Some(NegotiateErrorKind::HandshakeTimeout));
                assert!(!e.wire_violation);
            }
        }
        assert!(
            elapsed < NEGOTIATE + PAUSE / 2,
            "the handshake must end at its deadline, not a read budget later: {elapsed:?}"
        );
        drop(transport);
        dialer.join().expect("dialer thread");
    }

    /// dcrd's `inHandler` logging decisions for the read that ended a
    /// connection, over the texts the transport really produces.  At the
    /// pin only a codec failure is logged: every socket failure, the
    /// idle deadline included, reaches `inHandler` as `io.EOF`.
    #[test]
    fn read_failures_are_logged_as_dcrd_logs_them() {
        use std::io::Write as _;

        let read_error = |e: ReadError| DisconnectReason::ReadError(e.message);

        // A real idle expiry, so the timeout text cannot drift from the
        // transport's.  dcrd neither logs "Can't read message" nor its
        // unreachable "no answer" warning for it.
        let (conn, _remote, client) = loopback_pair();
        let mut transport = WireTransport::new(conn, MAX_PROTOCOL_VERSION, NET);
        transport.set_read_budget(Some(Duration::from_millis(50)));
        let timed_out = read_error(transport.read_message().expect_err("nothing arrives"));
        assert_eq!(read_error_to_log(&timed_out, false), None);

        // The remote closing the stream is `io.EOF` too.
        drop(client);
        let closed = read_error(transport.read_message().expect_err("the stream is closed"));
        assert_eq!(read_error_to_log(&closed, false), None);

        // A frame the codec rejects is logged; with the local side
        // already tearing down, nothing is.
        let (conn, _remote, mut client) = loopback_pair();
        let mut transport = WireTransport::new(conn, MAX_PROTOCOL_VERSION, NET);
        transport.set_read_budget(Some(Duration::from_secs(5)));
        client
            .write_all(&[0u8; MESSAGE_HEADER_SIZE])
            .expect("write junk");
        let rejected = transport.read_message().expect_err("a bad header");
        assert!(rejected.wire_violation, "{}", rejected.message);
        let text = rejected.message.clone();
        let rejected = read_error(rejected);
        assert_eq!(read_error_to_log(&rejected, false), Some(text.as_str()));
        assert_eq!(read_error_to_log(&rejected, true), None);

        // A socket error from the OS.
        let reset = DisconnectReason::ReadError(std::io::Error::from_raw_os_error(104).to_string());
        assert_eq!(read_error_to_log(&reset, false), None);
    }

    /// A payload that runs out inside its message's structure is not a
    /// wire violation, and whether dcrd logs it depends on where it
    /// runs out.  dcrd's `BtcDecode` returns the raw reader error: a cut
    /// on a field boundary is `io.EOF`, which `shouldHandleReadError`
    /// declines (`peer/peer.go:1063-1065`), and a cut inside a field is
    /// `io.ErrUnexpectedEOF`, logged as `Can't read message from %s:
    /// unexpected EOF`.  A `ping` framed with a short payload hits each.
    #[test]
    fn a_payload_cut_on_a_field_boundary_is_not_logged() {
        use std::io::Write as _;

        let ping_frame = |payload: &[u8]| {
            let mut frame = Vec::with_capacity(MESSAGE_HEADER_SIZE + payload.len());
            frame.extend_from_slice(&NET.0.to_le_bytes());
            let mut command = [0u8; 12];
            command[..4].copy_from_slice(b"ping");
            frame.extend_from_slice(&command);
            frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            frame.extend_from_slice(&dcroxide_chainhash::hash_b(payload)[..4]);
            frame.extend_from_slice(payload);
            frame
        };
        for (payload, text, logged) in [
            (&[][..], "EOF", false),
            (&[1u8, 2, 3, 4][..], "unexpected EOF", true),
        ] {
            let (conn, _remote, mut client) = loopback_pair();
            let mut transport = WireTransport::new(conn, MAX_PROTOCOL_VERSION, NET);
            transport.set_read_budget(Some(Duration::from_secs(5)));
            client.write_all(&ping_frame(payload)).expect("write frame");
            let err = transport.read_message().expect_err("the nonce is short");
            assert!(!err.wire_violation, "{}", err.message);
            assert_eq!(err.message, text);
            let reason = DisconnectReason::ReadError(err.message);
            assert_eq!(
                read_error_to_log(&reason, false).is_some(),
                logged,
                "{text}"
            );
        }
    }

    /// Hooks whose server answers a wire violation with `answer`.
    struct ViolationHooks {
        answer: ServeSignal,
        seen: usize,
    }

    impl ServeHooks for ViolationHooks {
        fn on_wire_violation(&mut self, _err: &str) -> ServeSignal {
            self.seen = self.seen.saturating_add(1);
            self.answer.clone()
        }

        fn on_message(
            &mut self,
            _peer: &Mutex<Peer>,
            _msg: Message,
            _mix_hash: Option<dcroxide_chainhash::Hash>,
            _outbound: &OutboundQueue,
        ) -> ServeSignal {
            ServeSignal::Continue
        }
    }

    /// A wire violation whose ban disconnects the peer is not logged as
    /// a failed read: dcrd's `OnRead` bans from inside `readMessage`, and
    /// `BanPeer`'s `Disconnect` is in place before `inHandler` asks
    /// `shouldHandleReadError`.  One the server declines to ban (banning
    /// disabled, a whitelisted peer) disconnects nothing, so dcrd logs
    /// it, and so does the port.
    #[test]
    fn a_banned_wire_violation_is_not_logged_as_a_failed_read() {
        use std::io::Write as _;

        let banned: std::borrow::Cow<'static, str> = "sent malformed wire message: x".into();
        for (answer, logged) in [
            (ServeSignal::Disconnect(banned.clone()), false),
            (ServeSignal::Continue, true),
        ] {
            let (conn, _remote, mut client) = loopback_pair();
            let mut transport = WireTransport::new(conn, MAX_PROTOCOL_VERSION, NET);
            transport.set_read_budget(Some(Duration::from_secs(5)));
            client
                .write_all(&[0u8; MESSAGE_HEADER_SIZE])
                .expect("write junk");
            let mut hooks = ViolationHooks {
                answer: answer.clone(),
                seen: 0,
            };
            let (queue, _receiver) = OutboundQueue::channel();
            let reason = run_peer_input(
                &Mutex::new(test_peer()),
                &mut transport,
                &mut NodePeerEnv::new(),
                &queue,
                &mut hooks,
                Vec::new(),
            );
            assert_eq!(hooks.seen, 1, "the violation reaches the server");
            assert_eq!(
                read_error_to_log(&reason, false).is_some(),
                logged,
                "{answer:?}: {reason:?}"
            );
            if !logged {
                assert!(
                    matches!(&reason, DisconnectReason::Protocol(r) if *r == banned),
                    "the ban ends the connection: {reason:?}"
                );
            }
        }
    }

    /// dcrd's `Peer.String`: the address and the direction.
    #[test]
    fn peers_are_labelled_with_their_direction() {
        let (_conn, remote, _client) = loopback_pair();
        assert_eq!(
            peer_log_label(&inbound_peer(remote)),
            format!("{remote} (inbound)")
        );
        let outbound = Peer::new_outbound(loopback_config("x"), "10.0.0.1:9108").expect("peer");
        assert!(peer_log_label(&outbound).ends_with(" (outbound)"));
    }

    /// The keepalive ping and the stall check share one thread, each on
    /// its own schedule: pings keep being queued, and a response past
    /// its deadline ends the connection with the stalled command.
    #[test]
    fn one_timer_thread_pings_and_detects_stalls() {
        // The stall window is long next to the 40ms ping interval so the
        // ping count holds on runners whose sleeps overshoot (macOS CI
        // oversleeps 25ms ticks severalfold).
        let (conn, _remote, _client) = loopback_pair();
        let flag = conn.cancel();
        let (queue, receiver) = OutboundQueue::channel();
        let stall = Mutex::new(StallDetector::with_response_timeout(
            Duration::from_millis(1000).as_nanos() as i64,
        ));
        let armed = stall
            .lock()
            .expect("stall mutex")
            .sent_message(&Message::GetInitState(dcroxide_wire::MsgGetInitState {
                types: Vec::new(),
            }));
        assert_eq!(armed, ArmOutcome::Armed);
        let (_shutdown_tx, shutdown_rx) = mpsc::channel();

        let started = Instant::now();
        let reason = run_peer_timers(
            &mut NodePeerEnv::new(),
            &queue,
            Duration::from_millis(40),
            &stall,
            &conn,
            "test (inbound)",
            Duration::from_millis(25),
            &shutdown_rx,
        );
        assert!(
            matches!(reason, Some(StallReason::Command(_))),
            "the overdue response stalls: {reason:?}"
        );
        assert!(started.elapsed() >= Duration::from_millis(1000));
        assert!(flag.is_cancelled(), "the stall tears the connection down");
        let pings = std::iter::from_fn(|| receiver.try_recv().ok())
            .filter(|msg| matches!(msg, Message::Ping(_)))
            .count();
        assert!(pings >= 3, "the pings kept coming meanwhile: {pings}");
    }

    /// A thread the OS refuses drops the connection before the server
    /// hears of it, instead of panicking (which aborts a release build).
    #[test]
    fn a_refused_thread_drops_the_connection() {
        use std::io::Read as _;

        let (conn, remote, client) = loopback_pair();
        let connected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (entered_tx, _entered_rx) = mpsc::channel();
        let (_release_tx, release_rx) = mpsc::channel();
        let hooks = BlockingHooks {
            handle: Arc::new(Mutex::new(None)),
            entered: entered_tx,
            release: release_rx,
            connected: Arc::clone(&connected),
            block_connect: false,
        };
        let server = std::thread::spawn(move || {
            crate::runtime::REFUSE_CONN_THREADS.with(|refuse| refuse.set(true));
            run_peer_connection(
                conn,
                inbound_peer(remote),
                0,
                NET,
                NEVER,
                NEVER,
                None,
                hooks,
            )
        });

        let transport = client_handshake(client);
        // The remote gets its FIN, not a session.
        let mut stream = transport.into_inner();
        let mut buf = [0u8; 1];
        assert_eq!(
            stream.read(&mut buf).expect("read"),
            0,
            "the connection is dropped"
        );
        drop(stream);
        let reason = server.join().expect("the server must not panic");
        assert!(
            matches!(reason, DisconnectReason::ThreadRefused(_)),
            "{reason:?}"
        );
        assert!(
            !connected.load(std::sync::atomic::Ordering::SeqCst),
            "the server never hears of a peer it cannot serve"
        );
    }

    /// Every refusal hands the message back intact -- by depth, by bytes,
    /// and once the output loop is gone -- so a caller retrying a reply
    /// or passing a request on never copies it up front, and the queue
    /// charges nothing for what it refused.
    #[test]
    fn a_refused_message_is_handed_back_intact() {
        use dcroxide_wire::{InvType, InvVect, MsgNotFound};

        // About 1.8 MB: two fit the 4 MiB budget, a third does not.
        let bulky = |seed: u8| {
            Message::NotFound(MsgNotFound {
                inv_list: vec![
                    InvVect {
                        inv_type: InvType::TX,
                        hash: dcroxide_chainhash::Hash([seed; 32]),
                    };
                    dcroxide_wire::MAX_INV_PER_MSG as usize
                ],
            })
        };

        let (queue, receiver) = OutboundQueue::channel();
        queue
            .queue_message(bulky(1))
            .expect("an empty queue admits");
        queue
            .queue_message(bulky(2))
            .expect("the budget admits a second");
        let charged = queue.state.bytes.load(std::sync::atomic::Ordering::Relaxed);
        let (err, back) = queue
            .queue_message_or_return(bulky(3))
            .expect_err("the byte budget refuses a third");
        assert_eq!(err, QueueError::Full);
        assert_eq!(*back, bulky(3));
        assert_eq!(
            queue.state.bytes.load(std::sync::atomic::Ordering::Relaxed),
            charged,
            "a refused message holds no charge"
        );

        // Drain, then fill by depth with small messages.
        while receiver.try_recv().is_ok() {}
        for nonce in 0..MAX_OUTBOUND_QUEUE_DEPTH as u64 {
            queue
                .queue_message(Message::Ping(MsgPing { nonce }))
                .expect("room below the depth");
        }
        let ping = Message::Ping(MsgPing { nonce: u64::MAX });
        assert_eq!(
            queue.queue_message_or_return(ping.clone()),
            Err((QueueError::Full, Box::new(ping.clone())))
        );

        drop(receiver);
        assert_eq!(
            queue.queue_message_or_return(ping.clone()),
            Err((QueueError::Closed, Box::new(ping)))
        );
    }

    /// Serve hooks that drop the peer when it pings with nonce 2, and
    /// whose disconnection hook -- a stand-in for `DonePeer` waiting on
    /// the sync manager while another peer's block validates -- queues a
    /// pong with nonce 301 to the still-registered peer, as relay traffic
    /// would be, and then blocks until the test releases it.
    struct DropThenBlockHooks {
        queue: Option<OutboundQueue>,
        entered: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    }

    impl ServeHooks for DropThenBlockHooks {
        fn on_connected(
            &mut self,
            _peer: &Arc<Mutex<Peer>>,
            outbound: &OutboundQueue,
            _remote_disable_relay_tx: bool,
        ) {
            self.queue = Some(outbound.clone());
        }

        fn on_message(
            &mut self,
            _peer: &Mutex<Peer>,
            msg: Message,
            _mix_hash: Option<dcroxide_chainhash::Hash>,
            _outbound: &OutboundQueue,
        ) -> ServeSignal {
            if matches!(msg, Message::Ping(ping) if ping.nonce == 2) {
                return ServeSignal::Disconnect("dropped by the handler".into());
            }
            ServeSignal::Continue
        }

        fn on_disconnected(&mut self, _peer: &Mutex<Peer>) {
            if let Some(queue) = self.queue.take() {
                let _ = queue.queue_message(Message::Pong(MsgPong { nonce: 301 }));
            }
            let _ = self.entered.send(());
            let _ = self.release.recv_timeout(Duration::from_secs(20));
        }
    }

    /// A peer the node drops is disconnected before the server lets it
    /// go, as dcrd's `inHandler` calls `Disconnect` before `DonePeer`
    /// runs: the remote reads the end of the stream while the
    /// disconnection hook is still waiting, and nothing queued to the
    /// peer after the drop reaches it.  The hook used to run first, so
    /// the socket stayed open for as long as it waited on the sync
    /// manager, and relay traffic and pings kept being written to the
    /// dropped peer meanwhile.
    #[test]
    fn a_dropped_peer_is_disconnected_before_the_server_lets_it_go() {
        use std::io::Read as _;

        let (conn, remote, client) = loopback_pair();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let hooks = DropThenBlockHooks {
            queue: None,
            entered: entered_tx,
            release: release_rx,
        };
        let server = std::thread::spawn(move || {
            run_peer_connection(
                conn,
                inbound_peer(remote),
                0,
                NET,
                NEVER,
                NEVER,
                None,
                hooks,
            )
        });

        let mut transport = client_handshake(client);
        transport
            .write_message(&Message::Ping(MsgPing { nonce: 2 }))
            .expect("send ping");
        entered_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the disconnection hook runs");

        // The hook is still blocked.  The client's five-second read
        // timeout is what ends this read if the socket is still open.
        let mut stream = transport.into_inner();
        let mut bytes = Vec::new();
        let end = stream.read_to_end(&mut bytes);
        assert!(
            end.is_ok(),
            "the remote must see the end of the stream before the server lets the peer go: {end:?}"
        );
        let mut seen = Vec::new();
        let mut rest = &bytes[..];
        while !rest.is_empty() {
            let (msg, used) = dcroxide_wire::read_message(rest, MAX_PROTOCOL_VERSION, NET)
                .expect("whole messages up to the end of the stream");
            seen.push(msg);
            rest = &rest[used..];
        }
        assert!(
            !seen.contains(&Message::Pong(MsgPong { nonce: 301 })),
            "nothing queued after the drop may reach the peer: {seen:?}"
        );

        release_tx.send(()).expect("release the hook");
        let reason = server.join().expect("server thread");
        assert!(
            matches!(&reason, DisconnectReason::Protocol(r) if r == "dropped by the handler"),
            "the handler's drop is the reason: {reason:?}"
        );
    }

    /// dcrd's `processInboundMessage` logs a second version or verack at
    /// debug, naming the peer, before it disconnects
    /// (`peer/peer.go:1319-1327`).
    #[test]
    fn a_second_version_or_verack_is_logged_as_dcrd_logs_it() {
        let (_conn, remote, _client) = loopback_pair();
        let peer = inbound_peer(remote);
        assert_eq!(
            already_received_log_line("version", &peer),
            format!("Already received 'version' from peer {remote} (inbound) -- disconnecting")
        );
        assert_eq!(
            already_received_log_line("verack", &peer),
            format!("Already received 'verack' from peer {remote} (inbound) -- disconnecting")
        );
    }

    /// A handshake read that fails at the socket fails the handshake with
    /// dcrd's `EOF`: `wire.ReadMessageN` turns every short read into
    /// `io.EOF`, which `Handshake` returns and `inboundPeerConnected`
    /// logs as `Failed handshake for inbound peer %s: EOF`
    /// (`server.go:2291`).  The transport's own texts reached that line.
    #[test]
    fn a_handshake_read_failing_at_the_socket_is_eof() {
        let fail =
            |conn: crate::transport::Teardown, remote: std::net::SocketAddr, idle: Duration| {
                let mut peer = inbound_peer(remote);
                let mut transport = WireTransport::new(conn, MAX_PROTOCOL_VERSION, NET);
                negotiate_within(
                    &mut peer,
                    &mut transport,
                    &mut NodePeerEnv::new(),
                    &mut |_: &Peer, _: &MsgVersion| Ok(()),
                    NEVER,
                    idle,
                )
                .map(|_| ())
                .expect_err("the handshake cannot complete")
            };

        // The remote closes before its version.
        let (conn, remote, client) = loopback_pair();
        drop(client);
        let err = fail(conn, remote, NEVER);
        assert_eq!(err.message, "EOF");
        assert_eq!(err.kind, None);
        assert!(!err.wire_violation);

        // The idle read deadline expires with the handshake's own time
        // far from spent.
        let (conn, remote, _client) = loopback_pair();
        let err = fail(conn, remote, Duration::from_millis(50));
        assert_eq!(err.message, "EOF");
        assert_eq!(err.kind, None);

        // The local side closes the conn under the read, as the
        // connection manager's `Disconnect` or `Remove` closes an active
        // conn: dcrd's handshake read fails with `EOF`.
        let err = torn_down_handshake(crate::transport::Teardown::disconnect);
        assert_eq!(err.message, "EOF");
        assert_eq!(err.kind, None);
    }

    /// A handshake the node's shutdown cuts short fails with dcrd's
    /// `errHandshakeTimeout`: the shutdown cancels the server context
    /// before it disconnects anything, and `Handshake` returns that
    /// error from its `ctx.Done` arm (`peer/peer.go:2352-2353`,
    /// `server.go:2357-2363`).  It was `EOF`, the text of the read it
    /// interrupted.
    #[test]
    fn a_handshake_the_shutdown_cuts_short_is_a_handshake_timeout() {
        let err = torn_down_handshake(crate::transport::Teardown::disconnect_for_shutdown);
        assert_eq!(err.message, HANDSHAKE_TIMEOUT_TEXT);
        assert_eq!(err.kind, Some(NegotiateErrorKind::HandshakeTimeout));
        assert!(!err.wire_violation);
    }

    /// Run an inbound handshake whose connection `teardown` ends before
    /// the remote sends anything, returning how it failed.
    fn torn_down_handshake(teardown: fn(&crate::transport::Teardown)) -> NegotiateError {
        let (conn, remote, _client) = loopback_pair();
        let handle = conn.try_clone().expect("clone the teardown");
        let mut peer = inbound_peer(remote);
        let mut transport = WireTransport::new(conn, MAX_PROTOCOL_VERSION, NET);
        transport.set_cancel(handle.cancel());
        teardown(&handle);
        negotiate_within(
            &mut peer,
            &mut transport,
            &mut NodePeerEnv::new(),
            &mut |_: &Peer, _: &MsgVersion| Ok(()),
            NEVER,
            NEVER,
        )
        .map(|_| ())
        .expect_err("the handshake cannot complete")
    }

    /// Without a stall check the scheduler is the lone keepalive, which
    /// stops once its queue has closed, as it always has: nothing is
    /// left to schedule.
    #[test]
    fn a_lone_ping_timer_stops_with_its_queue() {
        let (queue, receiver) = OutboundQueue::channel();
        drop(receiver);
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (_shutdown_tx, shutdown_rx) = mpsc::channel();
            run_ping_timer(
                &mut NodePeerEnv::new(),
                &queue,
                Duration::from_millis(10),
                &shutdown_rx,
            );
            let _ = done_tx.send(());
        });
        done_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the timer stops with its queue");
    }

    /// One of each of the eight mixing messages, each one that hashes.
    fn mix_messages() -> Vec<Message> {
        use dcroxide_wire::{
            MsgMixCiphertexts, MsgMixConfirm, MsgMixDCNet, MsgMixFactoredPoly, MsgMixKeyExchange,
            MsgMixPairReq, MsgMixSecrets, MsgMixSlotReserve, MsgTx,
        };
        vec![
            Message::MixPairReq(MsgMixPairReq {
                signature: [0; 64],
                identity: [0; 33],
                expiry: 0,
                mix_amount: 0,
                script_class: String::new(),
                tx_version: 0,
                lock_time: 0,
                message_count: 0,
                input_value: 0,
                utxos: Vec::new(),
                change: None,
                flags: 0,
                pairing_flags: 0,
            }),
            Message::MixKeyExchange(Box::new(MsgMixKeyExchange {
                signature: [0; 64],
                identity: [0; 33],
                session_id: [0; 32],
                epoch: 0,
                run: 0,
                pos: 0,
                ecdh: [0; 33],
                pqpk: [0; 1218],
                commitment: [0; 32],
                seen_prs: Vec::new(),
            })),
            Message::MixCiphertexts(MsgMixCiphertexts {
                signature: [0; 64],
                identity: [0; 33],
                session_id: [0; 32],
                run: 0,
                ciphertexts: Vec::new(),
                seen_key_exchanges: Vec::new(),
            }),
            // The one type whose encoding, and so its hash, needs a
            // non-empty matrix.
            Message::MixSlotReserve(MsgMixSlotReserve {
                signature: [0; 64],
                identity: [0; 33],
                session_id: [0; 32],
                run: 0,
                dc_mix: vec![vec![vec![1; 32]]],
                seen_ciphertexts: Vec::new(),
            }),
            Message::MixFactoredPoly(MsgMixFactoredPoly {
                signature: [0; 64],
                identity: [0; 33],
                session_id: [0; 32],
                run: 0,
                roots: Vec::new(),
                seen_slot_reserves: Vec::new(),
            }),
            Message::MixDCNet(MsgMixDCNet {
                signature: [0; 64],
                identity: [0; 33],
                session_id: [0; 32],
                run: 0,
                dc_net: Vec::new(),
                seen_slot_reserves: Vec::new(),
            }),
            Message::MixConfirm(MsgMixConfirm {
                signature: [0; 64],
                identity: [0; 33],
                session_id: [0; 32],
                run: 0,
                mix: MsgTx::default(),
                seen_dc_nets: Vec::new(),
            }),
            Message::MixSecrets(MsgMixSecrets {
                signature: [0; 64],
                identity: [0; 33],
                session_id: [0; 32],
                run: 0,
                seed: [0; 32],
                slot_reserve_msgs: Vec::new(),
                dc_net_msgs: Vec::new(),
                seen_secrets: Vec::new(),
            }),
        ]
    }

    /// A mixing message the input loop does not hash leaves its deadline
    /// armed, so the stall detector drops honest mixing peers.  The
    /// input loop's hashing and the stall detector's settlement both read
    /// the wire's one exhaustive list of mixing messages, so they cannot
    /// drift apart; this pins that each of the eight is hashed and
    /// settles its own mix inventory with that hash, and that other
    /// messages are not hashed.
    #[test]
    fn every_mixing_message_is_hashed_for_the_deadline_it_settles() {
        use dcroxide_wire::{InvType, InvVect};

        let messages = mix_messages();
        let mut commands: Vec<&str> = messages.iter().map(Message::command).collect();
        commands.sort_unstable();
        commands.dedup();
        assert_eq!(
            commands.len(),
            8,
            "one of each mixing command: {commands:?}"
        );
        for msg in &messages {
            let hash = mix_message_hash(msg)
                .unwrap_or_else(|| panic!("{} is not hashed by the input loop", msg.command()));
            assert_eq!(
                dcroxide_peer::settles(msg, Some(hash)),
                dcroxide_peer::Settles::Inventory(InvVect {
                    inv_type: InvType::MIX,
                    hash,
                }),
                "{}",
                msg.command()
            );
        }
        for msg in [
            Message::Ping(MsgPing { nonce: 1 }),
            Message::GetAddr,
            Message::Tx(dcroxide_wire::MsgTx::default()),
        ] {
            assert_eq!(mix_message_hash(&msg), None, "{}", msg.command());
        }
    }
}
