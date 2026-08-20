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
    ArmOutcome, MAX_PROTOCOL_VERSION, MsgTransport, NEGOTIATE_TIMEOUT, Peer, PeerEnv, PeerGlobals,
    STALL_RESPONSE_TIMEOUT, STALL_TICK_INTERVAL, StallDetector, StallReason,
};
use dcroxide_wire::{
    CurrencyNet, MESSAGE_HEADER_SIZE, Message, MsgPing, write_message as wire_write_message,
};

use crate::peerconn::NodePeerEnv;
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
        let mut peer = peer.lock().expect("peer mutex poisoned");
        match classify_incoming(&mut peer, &msg, env) {
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

        // Settle any deadline this message answers and open the
        // handler-active window before taking any lock, so every
        // moment between finishing the read and finishing the handling
        // is credited to the local node rather than blamed on the peer.
        if let Some(stall) = stall {
            // Hash a mixing message before taking the lock: dcrd does
            // this once in `readMessage`, and it must not happen with
            // the stall mutex held.
            let mix_hash = mix_message_hash(&msg);
            let mut stall = stall.lock().expect("stall mutex poisoned");
            stall.received_message(&msg, mix_hash);
            stall.handler_start();
        }

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
                if let ServeSignal::Disconnect(reason) = hooks.on_message(&mut peer, &msg, outbound)
                {
                    return DisconnectReason::Protocol(reason);
                }
            }
        }

        // The message is handled: release the peer before closing the
        // handler-active window, so this loop never holds the peer lock
        // and the stall lock at once (the output loop takes them in the
        // opposite order).
        drop(peer);
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
/// `maybeRemoveDeadline` merely reads it back.  dcroxide keeps mix
/// hashing in the mixing crate, so the input loop computes it once per
/// received message and hands it to the stall detector — the same
/// one-hash-per-message shape, with the cache in the caller.
fn mix_message_hash(msg: &Message) -> Option<dcroxide_chainhash::Hash> {
    match msg {
        Message::MixPairReq(_)
        | Message::MixKeyExchange(_)
        | Message::MixCiphertexts(_)
        | Message::MixSlotReserve(_)
        | Message::MixFactoredPoly(_)
        | Message::MixDCNet(_)
        | Message::MixConfirm(_)
        | Message::MixSecrets(_) => {
            crate::mixnode::wire_to_pool_message(msg.clone()).and_then(|pool| pool.mix_hash().ok())
        }
        _ => None,
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
    /// The framing parameters the byte charge is computed under, set
    /// once by the connection assembly after the handshake (the queue
    /// only ever carries session traffic, framed at the negotiated
    /// version).  The unit tests leave the default, the local maximum
    /// over mainnet.
    wire: std::sync::OnceLock<(u32, CurrencyNet)>,
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
/// This is a deliberate hardening choice, not a port of a dcrd bound —
/// dcrd has no bound here.  dcrd's `peer.go` sets `outputBufferSize =
/// 5000` and builds `outputQueue: make(chan outMsg, 5000)` alongside
/// `sendQueue: make(chan outMsg, 1)`; `queueHandler` then moves
/// everything the writer has not taken yet into a plain
/// `pendingMsgs []outMsg` slice that it grows with `append`.  So dcrd
/// buffers 5000 messages in the channel and an unlimited number in the
/// pending slice, and `QueueMessage` blocks only after the 5000-slot
/// channel fills.  (The three-slot semaphore often cited as the bound
/// is `maxPendingSend` in `server.go`, which limits concurrent *getdata
/// serve* items only; nothing throttles relay, announcements, addr,
/// cfilter or init-state traffic.)
///
/// dcroxide's original port used `std::sync::mpsc::channel`, which is
/// unbounded in the channel too, so a peer that stopped reading could
/// pin unbounded heap.  128 slots caps that, and
/// [`MAX_OUTBOUND_QUEUE_BYTES`] charges what the slots actually hold:
/// against a byte budget the count alone is coarse, since the largest
/// message this queue carries is a max-size `MsgHeaders` (2000 headers
/// x 180 bytes ~ 360 KB) or a max-size `MsgBlock` (~393 KB), and 128 of
/// those is ~46 MB per peer — ~5.7 GB at the default `maxpeers` of 125.
/// The byte charge is the primary memory bound; the depth stays as the
/// secondary guard against a flood of tiny messages, and the window is
/// further bounded by the writer's per-message write deadline: once the
/// peer stops reading, the first blocked write times out and the
/// connection is torn down.
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
/// Like the depth above this is a deliberate hardening choice with no
/// dcrd counterpart — dcrd's `queueHandler` buffers without bound.  The
/// charge is computed on enqueue and released when the output loop takes
/// the message: exact arithmetic for the two messages that dominate any
/// real queue (`MsgBlock` and `MsgTx`, whose ported `serialize_size`
/// methods are cheap), and one measuring serialization for everything
/// else, whose sizes are control-plane small (the extra encode never
/// touches the block-serving hot path).
///
/// 4 MiB caps the pipelining worst case near ~500 MiB across a full
/// default peer set — down from ~5.7 GB under the count bound alone —
/// while staying far above honest traffic: a congested honest peer's
/// queue is well under 100 KB (a relay inv is ~40 bytes, a block
/// announcement ~180), and the serve path holds at most dcrd's
/// `maxPendingSend` (3) getdata items at a time, ~1.2 MB of blocks.  A
/// message larger than the whole budget — none exists today — is
/// admitted into an empty queue rather than wedging the connection.
pub const MAX_OUTBOUND_QUEUE_BYTES: usize = 4 * 1024 * 1024;

/// The byte charge for a message: its framed wire size under the
/// queue's negotiated parameters.  `MsgBlock` and `MsgTx` take the
/// arithmetic path (their `serialize_size` is a ported dcrd
/// `SerializeSize`, exact by upstream's own tests); every other message
/// is measured by framing it once, which is exact and cheap at
/// control-plane sizes.  A message the codec refuses to frame is
/// charged the header alone — the output loop's write will surface the
/// same error and tear the connection down.
fn message_charge(msg: &Message, pver: u32, net: CurrencyNet) -> usize {
    match msg {
        Message::Block(block) => MESSAGE_HEADER_SIZE.saturating_add(block.serialize_size()),
        Message::Tx(tx) => MESSAGE_HEADER_SIZE.saturating_add(tx.serialize_size()),
        _ => wire_write_message(msg, pver, net)
            .map(|frame| frame.len())
            .unwrap_or(MESSAGE_HEADER_SIZE),
    }
}

impl OutboundQueue {
    /// Create an outbound queue and the receiver its output loop drains.
    pub fn channel() -> (OutboundQueue, OutboundReceiver) {
        let (sender, receiver) = mpsc::sync_channel(MAX_OUTBOUND_QUEUE_DEPTH);
        let state = Arc::new(OutboundQueueState {
            label: std::sync::OnceLock::new(),
            wire: std::sync::OnceLock::new(),
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

    /// Set the framing parameters the byte charge is computed under —
    /// the negotiated protocol version and the network — so the charge
    /// matches what the write transport will actually frame.  The first
    /// call wins.
    pub fn set_wire_params(&self, pver: u32, net: CurrencyNet) {
        let _ = self.state.wire.set((pver, net));
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
        let (pver, net) = self
            .state
            .wire
            .get()
            .copied()
            .unwrap_or((MAX_PROTOCOL_VERSION, CurrencyNet::MAIN_NET));
        let charge = message_charge(&msg, pver, net);
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
            return Err(QueueError::Full);
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
            Err(mpsc::TrySendError::Full(_)) => {
                self.state
                    .bytes
                    .fetch_sub(charge, std::sync::atomic::Ordering::Relaxed);
                Err(QueueError::Full)
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                self.state
                    .bytes
                    .fetch_sub(charge, std::sync::atomic::Ordering::Relaxed);
                Err(QueueError::Closed)
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
                let label = peer.lock().expect("peer mutex poisoned").addr().to_string();
                crate::logging::info(
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
/// or the outbound queue closes (dcrd's `pingHandler`).  Each ping gets
/// a fresh nonce recorded on the peer so the answering pong can be timed.
///
/// A full queue does **not** end the timer.  The keepalive is what keeps
/// a live-but-quiet peer from tripping the idle read deadline, so
/// abandoning it because of one congested tick would turn a transient
/// burst into a disconnect several minutes later, for a peer that is
/// reading again by then.  The tick is skipped, reported, and the next
/// one tries again; only a closed queue (the connection tearing down)
/// stops the timer.
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
                // Hold the peer lock across the enqueue so the nonce is
                // recorded before the input loop can process the pong
                // answering it, and record it only when the ping is
                // really on its way — dcrd stamps `lastPingNonce` in
                // `outHandler`, immediately before the write, so a ping
                // that never leaves never becomes the pending nonce.
                let mut peer = peer.lock().expect("peer mutex poisoned");
                match outbound.queue_message(Message::Ping(ping)) {
                    Ok(()) => peer.record_sent_ping(env, &ping),
                    Err(QueueError::Full) => {
                        // Report without the peer lock held.
                        drop(peer);
                        outbound.report_full("ping");
                    }
                    Err(QueueError::Closed) => return,
                }
            }
            // Shutdown signalled, or the signalling half was dropped.
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
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

/// Check the peer's pending responses every `tick` until shutdown is
/// signalled, disconnecting it when one has not arrived by its adjusted
/// deadline (dcrd's `stallHandler`).
///
/// dcrd funnels the stall events through a `stallControl` channel into a
/// dedicated goroutine because that is Go's idiom for owning mutable
/// state; the port shares the state behind its own mutex instead, which
/// is the direct Rust idiom, keeps the I/O loops from ever blocking on a
/// control channel, and removes the channel-versus-quit race entirely.
/// The observable behavior is dcrd's: the same deadlines, the same
/// per-tick check, and the same disconnect.
///
/// Disconnecting is a shutdown of the connection — the mechanism the
/// input and output loops already use to break each other out of a
/// blocked read or write, and raises the connection's [`Cancel`] flag —
/// which is what actually unblocks the input loop's read, since a
/// `shutdown` issued on a different handle to the same socket is not a
/// portable way to abort a receive already in flight.  Together they
/// tear the whole connection down (dcrd's `Disconnect` closing the
/// conn).  The stalled command is returned so the caller can report why
/// the connection ended.
///
/// [`Cancel`]: crate::transport::Cancel
pub fn run_stall_detector(
    stall: &Mutex<StallDetector>,
    conn: &TcpStream,
    cancel: &crate::transport::Cancel,
    peer_label: &str,
    tick: Duration,
    shutdown: &mpsc::Receiver<()>,
) -> Option<StallReason> {
    loop {
        // Wait a full tick unless shutdown arrives first.
        match shutdown.recv_timeout(tick) {
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let stalled = stall.lock().expect("stall mutex poisoned").check();
                if let Some(reason) = stalled {
                    crate::logging::info(
                        "PEER",
                        &format!(
                            "Peer {peer_label} appears to be stalled or misbehaving \
                             (reason: {}) -- disconnecting",
                            reason.exceeded_text()
                        ),
                    );
                    // Both, and in this order.  The flag is what the
                    // input loop actually watches — `shutdown` on this
                    // cloned handle does not reliably abort a `recv`
                    // already in flight on the loop's own handle under
                    // Winsock — while the socket shutdown still delivers
                    // the FIN the remote is owed.
                    cancel.cancel();
                    let _ = conn.shutdown(Shutdown::Both);
                    return Some(reason);
                }
            }
            // Shutdown signalled, or the signalling half was dropped.
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return None,
        }
    }
}

/// Run a peer connection with dcrd's production stall timings.
#[allow(clippy::too_many_arguments)] // Mirrors dcrd's connection surface.
pub fn run_peer_connection<H>(
    stream: TcpStream,
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
        stream,
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

/// Run a peer connection from the negotiated handshake through the
/// steady-state message loops until it disconnects (dcrd `peer.go`'s
/// `start` plus the per-peer goroutine set, as OS threads).
///
/// The socket is split into read and write halves; the version handshake
/// runs (inbound or outbound per the peer) before the loops start; then
/// the output loop and the ping timer run on their own threads while the
/// input loop runs on this thread, with the stall detector ticking on a
/// fourth.  When the input loop ends the ping timer and the stall
/// detector are signalled and the outbound queue is closed so the other
/// threads finish, and all three are joined before returning the reason
/// the connection stopped.  `idle_timeout` bounds each read so a silent
/// peer eventually disconnects (dcrd's idle timer); `ping_interval`
/// should be shorter so a live peer answers before that fires.
///
/// The idle timer alone is not enough: a peer that keeps answering the
/// keepalive pings while never serving the data it was asked for looks
/// perfectly alive to it, yet pins every in-flight request slot
/// forever.  `stall` is what bounds that — the pending responses are
/// checked every `stall.tick` and the peer is disconnected once one has
/// not arrived by its deadline (dcrd's `stallHandler`).
#[allow(clippy::too_many_arguments)] // Mirrors dcrd's connection surface.
pub fn run_peer_connection_with_stall<H>(
    stream: TcpStream,
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
    let write_stream = match stream.try_clone() {
        Ok(write_stream) => write_stream,
        Err(e) => return DisconnectReason::WriteError(e.to_string()),
    };
    // A third handle on the same socket, so the stall detector can shut
    // the connection down from its own thread (dcrd's `Disconnect`).
    let stall_stream = match stream.try_clone() {
        Ok(stall_stream) => stall_stream,
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
            Err(e) => {
                // A wire violation bans during the handshake too.
                // dcrd installs its read listener before `Handshake`
                // for both directions and runs it on the version and
                // verack reads (`peer.go:1912`, `:1983`, `:2012`), and
                // `serverPeer.OnRead` bans on any `wire.ErrorCode` with
                // no handshake-state guard (`server.go:1851-1857`).
                // Without this a peer could violate the protocol
                // indefinitely by never completing a handshake.
                if e.wire_violation {
                    hooks.on_wire_violation(&e.message);
                }
                return DisconnectReason::Negotiate(e.message);
            }
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

    // The connection's teardown signal.  The idle budget above is
    // minutes long, so without something the reader polls, a peer this
    // node has decided to drop stays parked in its receive until that
    // budget runs out — the socket shutdown the other loops perform
    // cannot be relied on to cut it short across platforms.
    let cancel = crate::transport::Cancel::new();
    read_transport.set_cancel(cancel.clone());

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
    // Name the queue so a congestion report identifies the peer, and
    // frame its byte charges at the negotiated version the write
    // transport uses.
    outbound.set_peer_label(peer.lock().expect("peer mutex poisoned").addr().to_string());
    outbound.set_wire_params(negotiated_pver, net);
    // The queue is empty here, so this cannot fail with
    // [`QueueError::Full`]; a failure is a closed queue.
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

    // The stall state the three loops share: the output loop arms the
    // deadlines, the input loop settles them and brackets the
    // callbacks, and the stall thread checks them (dcrd's stall control
    // channel into `stallHandler`).
    let stall_state = Arc::new(Mutex::new(StallDetector::with_response_timeout(
        i64::try_from(stall.response_timeout.as_nanos()).unwrap_or(i64::MAX),
    )));

    let output_peer = Arc::clone(&peer);
    let output_stall = Arc::clone(&stall_state);
    let output_cancel = cancel.clone();
    let output = thread::spawn(move || {
        let mut output_env = NodePeerEnv::new();
        let reason = run_peer_output_with_stall(
            &output_peer,
            &mut write_transport,
            &mut output_env,
            receiver,
            Some(&output_stall),
        );
        // End the connection when the output loop ends (a write error or
        // a closed queue): raise the flag the input loop polls, and shut
        // the socket down so the remote gets its FIN.  The flag is the
        // half that makes the input loop return promptly; see
        // `run_stall_detector`.
        output_cancel.cancel();
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

    // Watch the pending responses on a fourth thread: a peer that keeps
    // the connection alive while never serving what it was asked for is
    // disconnected instead of pinning the request slots forever (dcrd's
    // `stallHandler`).
    let (stall_shutdown, stall_shutdown_rx) = mpsc::channel();
    let stall_label = peer.lock().expect("peer mutex poisoned").addr().to_string();
    let stall_tick = stall.tick;
    let stall_thread_state = Arc::clone(&stall_state);
    let stall_thread_cancel = cancel.clone();
    let stall_thread = thread::spawn(move || {
        run_stall_detector(
            &stall_thread_state,
            &stall_stream,
            &stall_thread_cancel,
            &stall_label,
            stall_tick,
            &stall_shutdown_rx,
        )
    });

    // Drive the input loop on this thread until the peer disconnects.
    let reason = run_peer_input_with_stall(
        &peer,
        &mut read_transport,
        &mut env,
        &outbound,
        &mut hooks,
        outcome.delayed,
        Some(&stall_state),
    );

    // The connection is winding down (dcrd `DonePeer`).
    hooks.on_disconnected(&mut peer.lock().expect("peer mutex poisoned"));

    // Tear down: shut the socket down so the output loop's blocking write
    // unblocks (a peer that stopped reading would otherwise wedge it),
    // stop the ping timer and the stall detector, and close the outbound
    // queue, then join the three threads.
    cancel.cancel();
    let _ = read_transport.get_mut().shutdown(Shutdown::Both);
    let _ = ping_shutdown.send(());
    let _ = stall_shutdown.send(());
    drop(outbound);
    let _ = ping.join();
    let _ = output.join();
    // A stall is the real reason the connection ended; the input loop
    // only saw the socket the detector shut down under it.
    match stall_thread.join() {
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
}
