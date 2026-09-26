// SPDX-License-Identifier: ISC
//! The daemon's websocket serving loop — the OS-threads translation of
//! dcrd `rpcwebsocket.go`'s per-client goroutines.
//!
//! After the RFC 6455 handshake, a websocket client speaks the same
//! JSON-RPC as the HTTP endpoint over text frames, plus the
//! subscription commands.  The connection runs dcrd's `inHandler`
//! gate — an unauthenticated client must send `authenticate` first,
//! limited users are refused non-limited methods, and notifications
//! (null id) draw no reply — then dispatches each request through the
//! ported [`ws_service_request`], writing one reply per request.
//!
//! The notification manager is dcrd's `wsNotificationManager` in
//! threaded form: the registration maps record each client's
//! subscriptions, connected clients register their shared state and an
//! outbound queue, and a delivery thread (dcrd's `notificationHandler`
//! goroutine) receives chain and mempool events over a channel, runs
//! the ported notification builders against the subscribed clients,
//! and queues the marshalled JSON on each target's outbound queue.
//! The serving loop drains that queue whenever the connection is idle
//! or between requests — the poll-loop translation of dcrd's separate
//! out-handler goroutine.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex, mpsc};

use dcroxide_chainhash::Hash;
use dcroxide_dcrjson::{
    RPCError, RpcId, err_rpc_internal, err_rpc_invalid_params, err_rpc_invalid_request,
    err_rpc_parse,
};
use dcroxide_rpc::dispatch::{RPC_LIMITED, create_marshalled_reply, parse_cmd};
use dcroxide_rpc::http::{split_raw_array, unmarshal_request};
use dcroxide_rpc::server::Server;
use dcroxide_rpc::websocket::{self as rpcws, RpcNtfnManager, WsClient, ws_service_request};
use dcroxide_wire::{Message, MsgBlock, MsgTx};

use crate::rpcrun::NodeRpcChain;
use crate::wsframe::{WsConn, WsIn, accept_key};

pub use dcroxide_rpc::websocket::TemplateUpdateReason;

/// The websocket read limit before authentication (dcrd
/// `websocketReadLimitUnauthenticated`).
const READ_LIMIT_UNAUTHENTICATED: usize = 1 << 12;

/// The websocket read limit after authentication (dcrd
/// `websocketReadLimitAuthenticated`).
const READ_LIMIT_AUTHENTICATED: usize = 1 << 24;

/// The daemon's notification manager (dcrd's `wsNotificationManager`):
/// the per-kind subscription maps, the connected-client registry, and
/// the event channel feeding the delivery thread.  Clones share the
/// same state, so the copy installed on the RPC server and the copies
/// held by the daemon's event sources all drive one manager.
#[derive(Clone)]
pub struct NodeNtfnMgr {
    inner: Arc<Mutex<Subscriptions>>,
    clients: Arc<Mutex<HashMap<u64, ClientHandle>>>,
    /// How many clients `clients` holds, kept beside it so a producer
    /// can ask [`NodeNtfnMgr::has_clients`] without taking the lock.
    registered: Arc<std::sync::atomic::AtomicUsize>,
    events: mpsc::Sender<NtfnEvent>,
    receiver: Arc<Mutex<Option<mpsc::Receiver<NtfnEvent>>>>,
    /// The maximum number of concurrent websocket clients (dcrd's
    /// `RPCMaxWebsockets`).  A value of zero rejects every client, as
    /// dcrd's `NumClients()+1 > 0` does.
    max_websockets: usize,
}

/// The default concurrent websocket client cap (dcrd's
/// `defaultMaxRPCWebsockets`).
const DEFAULT_MAX_WEBSOCKETS: usize = 25;

/// The per-notification-kind subscriber sets, keyed by session id.
#[derive(Default)]
struct Subscriptions {
    blocks: HashSet<u64>,
    work: HashSet<u64>,
    tspends: HashSet<u64>,
    winning_tickets: HashSet<u64>,
    new_tickets: HashSet<u64>,
    mempool_txs: HashSet<u64>,
    mix_messages: HashSet<u64>,
}

/// A client's pending output and the signal that wakes its writer
/// (dcrd's buffered `sendChan`, which `outHandler` drains at
/// `rpcwebsocket.go:1896-1922`).
///
/// The flag lives under the same mutex as the items so a push cannot
/// land between the writer finding the queue empty and going to sleep;
/// that is the wakeup this would otherwise lose.
#[derive(Default)]
pub struct OutboundQueue {
    /// The queued messages and whether the connection has ended.
    pending: Mutex<Pending>,
    /// Signalled by every push and by [`OutboundQueue::close`].
    wake: Condvar,
}

/// The mutex-guarded half of [`OutboundQueue`].
#[derive(Default)]
struct Pending {
    /// Messages handed to the writer, oldest first: dcrd's `sendChan`.
    /// Holds every reply and at most one notification.
    items: VecDeque<String>,
    /// Notifications held back while one is already with the writer:
    /// dcrd's `pendingNtfns` (`rpcwebsocket.go:1849`).
    held_notifications: VecDeque<String>,
    /// Whether a notification is with the writer: dcrd's `waiting`
    /// (`:1850`). True from the moment one is handed over until its
    /// write completes, so it sits in `items` or in the batch the stream
    /// holder is writing; outside that holder's hands, `items` is empty
    /// only if `held_notifications` is too.
    waiting: bool,
    /// Set once nothing further will be queued.
    closed: bool,
}

impl OutboundQueue {
    /// Queue one message and wake the writer.
    ///
    /// Queue a reply, which goes straight to the writer.
    ///
    /// dcrd's replies go through `SendMessage` onto `sendChan` with no
    /// throttle (`rpcwebsocket.go:1925-1940`), so a reply waits behind
    /// at most the one notification already there -- never behind a
    /// backlog.
    fn push_reply(&self, json: String) {
        self.pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .items
            .push_back(json);
        self.wake.notify_all();
    }

    /// Queue a notification, holding it back if one is already with the
    /// writer.
    ///
    /// This is `notificationQueueHandler` (`rpcwebsocket.go:1837-1888`):
    /// the first notification goes to the writer and the rest wait in a
    /// list, so only ever one is ahead of a reply. Without the throttle
    /// a reply queues behind every notification, which is the whole
    /// reason dcrd separates the two paths.
    fn push_notification(&self, json: String) {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if pending.waiting {
            pending.held_notifications.push_back(json);
        } else {
            pending.items.push_back(json);
        }
        pending.waiting = true;
        drop(pending);
        self.wake.notify_all();
    }

    /// Stop the writer, discarding anything still queued, and wake it if
    /// it is asleep.
    ///
    /// Discarding is dcrd's behaviour, not an economy: `Disconnect`
    /// closes the connection outright -- `close(c.quit)` then
    /// `c.conn.Close()` (`rpcwebsocket.go:1981-1990`) -- and whatever
    /// was still on `sendChan` goes with it. Draining instead would
    /// deliver more than dcrd does, and would put data frames on the
    /// wire after the close frame the read loop has already sent, which
    /// RFC 6455 forbids.
    fn close(&self) {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        pending.items.clear();
        pending.held_notifications.clear();
        pending.waiting = false;
        pending.closed = true;
        drop(pending);
        self.wake.notify_all();
    }

    /// Wait until there is something to write, or the queue closes.
    ///
    /// Returns `false` once closed, which is the writer's signal to
    /// stop -- so it can never park on a queue nobody will fill. It
    /// deliberately does NOT take the items: the writer collects them
    /// under the stream lock, so that whoever holds the stream is the
    /// one draining and output cannot be reordered by two drainers
    /// racing.
    fn wait_for_items(&self) -> bool {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            if !pending.items.is_empty() {
                return true;
            }
            if pending.closed {
                return false;
            }
            pending = self
                .wake
                .wait(pending)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }

    /// Everything handed to the writer right now, without waiting: every
    /// reply and at most one notification.
    ///
    /// Called only with the stream lock held, by whichever thread holds
    /// it, and followed by [`OutboundQueue::batch_written`] once the
    /// batch is on the wire (see [`write_queued_batch`]). That is what
    /// keeps the writes ordered.
    fn take_all_now(&self) -> Vec<String> {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        pending.items.drain(..).collect()
    }

    /// Record that the batch last taken has been written: the
    /// notification that was with the writer has left, so the next held
    /// one takes its place -- dcrd promoting from `pendingNtfns` when
    /// `ntfnSentChan` fires (`:1868-1880`), which `outHandler` signals
    /// only once `WriteMessage` has returned (`:1902-1908`).
    ///
    /// Promoting on completion rather than when the batch is taken is
    /// what orders a reply queued during the write ahead of the next
    /// notification, as on dcrd's `sendChan`.
    ///
    /// A promotion is a push like any other and wakes the writer: the
    /// batch may have been the reader's, and a reader that stops on its
    /// drain budget leaves the rest to the writer.
    fn batch_written(&self) {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if pending.waiting {
            match pending.held_notifications.pop_front() {
                Some(next) => {
                    pending.items.push_back(next);
                    drop(pending);
                    self.wake.notify_all();
                }
                None => pending.waiting = false,
            }
        }
    }
}

/// Write one batch of queued output to the stream the caller holds,
/// then promote the next held notification: `Ok(false)` when there was
/// nothing to write.
///
/// A backlog therefore drains one notification per batch, each written
/// before the next is handed over, which keeps dcrd's guarantee that a
/// reply waits behind at most one notification.
fn write_queued_batch<S: Read + Write>(
    conn: &mut WsConn<S>,
    outbound: &OutboundQueue,
) -> Result<bool, String> {
    let batch = outbound.take_all_now();
    if batch.is_empty() {
        return Ok(false);
    }
    for json in batch {
        conn.write_text(json.as_bytes())?;
    }
    outbound.batch_written();
    Ok(true)
}

/// How long the reader spends writing queued output before it reads
/// again: one read poll interval (`rpcrun`'s `WS_POLL_INTERVAL`).
///
/// The reader keeps writing batches until the queue is empty, because
/// it holds the stream across the blocking read that follows and the
/// writer cannot deliver anything meanwhile. Draining one batch per
/// read, as the port first did, delivered one notification per read
/// interval to a client that only listens -- twenty a second, with any
/// faster stream growing the held list without bound. The budget
/// bounds the other direction: a stream the client takes more slowly
/// than it is produced still lets the reader read requests between
/// drains, which dcrd's separate `inHandler` does continuously.
const READER_DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_millis(50);

/// The reader's drain before each read: write batches until the queue
/// is empty or `budget` ([`READER_DRAIN_BUDGET`] from the reader) has
/// been spent, so a backlog goes out at socket speed rather than one
/// notification per read interval.  At least one batch is written
/// whatever the budget.
fn drain_before_read<S: Read + Write>(
    conn: &mut WsConn<S>,
    outbound: &OutboundQueue,
    budget: std::time::Duration,
) -> Result<(), String> {
    let started = std::time::Instant::now();
    while write_queued_batch(conn, outbound)? {
        if started.elapsed() >= budget {
            break;
        }
    }
    Ok(())
}

/// One connected client: its shared request state (the ported
/// `WsClient` with its transaction filter) and the outbound
/// queue its writer drains (dcrd's `sendChan`).
#[derive(Clone)]
struct ClientHandle {
    state: Arc<Mutex<WsClient>>,
    outbound: Arc<OutboundQueue>,
}

/// A chain or mempool event awaiting fan-out (dcrd's
/// `notification*` queue types).
enum NtfnEvent {
    /// A block connected to the main chain, shared with the rest of
    /// the notification fan-out through the `Arc`.
    BlockConnected(Arc<MsgBlock>),
    /// A block disconnected from the main chain, shared with the rest
    /// of the notification fan-out through the `Arc`.
    BlockDisconnected(Arc<MsgBlock>),
    /// A new block template (dcrd `notificationWork`).
    Work(Box<MsgBlock>, TemplateUpdateReason),
    /// A treasury spend arrived in the mempool.
    TSpend(Box<MsgTx>),
    /// The chain reorganized.
    Reorganization {
        old_hash: Hash,
        old_height: i64,
        new_hash: Hash,
        new_height: i64,
    },
    /// The winning tickets of a newly accepted block.
    WinningTickets {
        block_hash: Hash,
        block_height: i64,
        tickets: Vec<Hash>,
    },
    /// Tickets matured into the live pool.
    NewTickets {
        hash: Hash,
        height: i64,
        stake_difficulty: i64,
        tickets_new: Vec<Hash>,
    },
    /// A transaction was accepted into the mempool, along with its
    /// tree (dcrd `notificationTxAcceptedByMempool` with isNew=true —
    /// nothing in dcrd sends false).
    MempoolTx(Box<MsgTx>, i8),
    /// A mixing message was accepted.
    MixMessage(Box<Message>),
    /// Stop the delivery thread.
    Shutdown,
}

impl NodeNtfnMgr {
    /// An empty notification manager (with dcrd's default websocket cap)
    /// whose delivery thread has not started yet.
    pub fn new() -> NodeNtfnMgr {
        NodeNtfnMgr::with_max_websockets(DEFAULT_MAX_WEBSOCKETS)
    }

    /// An empty notification manager with an explicit concurrent
    /// websocket client cap (the daemon threads `RPCMaxWebsockets` here).
    pub fn with_max_websockets(max_websockets: usize) -> NodeNtfnMgr {
        let (events, receiver) = mpsc::channel();
        NodeNtfnMgr {
            inner: Arc::default(),
            clients: Arc::default(),
            registered: Arc::default(),
            events,
            receiver: Arc::new(Mutex::new(Some(receiver))),
            max_websockets,
        }
    }

    /// Start the delivery thread over the RPC server (dcrd
    /// `wsNotificationManager.Run`'s notification handler).  Returns
    /// `None` when this manager's thread is already running.
    pub fn start(&self, server: Arc<Server<NodeRpcChain>>) -> Option<std::thread::JoinHandle<()>> {
        let receiver = self.receiver.lock().expect("ntfn receiver").take()?;
        let subs = Arc::clone(&self.inner);
        let clients = Arc::clone(&self.clients);
        Some(std::thread::spawn(move || {
            deliver_events(receiver, server, subs, clients);
        }))
    }

    /// Stop the delivery thread after the events already queued.
    pub fn shutdown(&self) {
        let _ = self.events.send(NtfnEvent::Shutdown);
    }

    /// Whether any websocket client is registered.
    ///
    /// Every event is delivered only to registered clients, so with none
    /// there is nothing for the delivery thread to do: the producers
    /// below skip the send, and a caller that has to copy or classify
    /// something just to build an event can ask first.  dcrd's
    /// `notificationHandler` finds the same empty client maps and sends
    /// nothing; a client registering an instant later misses the event
    /// either way, since subscribing takes it a round trip after that.
    pub fn has_clients(&self) -> bool {
        self.registered.load(std::sync::atomic::Ordering::Relaxed) != 0
    }

    /// Queue an event for the delivery thread, unless no client could
    /// receive it.
    fn send(&self, event: NtfnEvent) {
        if self.has_clients() {
            let _ = self.events.send(event);
        }
    }

    /// Queue a block-connected event (dcrd
    /// `Server.NotifyBlockConnected`).
    pub fn notify_block_connected(&self, block: Arc<MsgBlock>) {
        self.send(NtfnEvent::BlockConnected(block));
    }

    /// Queue a block-disconnected event (dcrd
    /// `Server.NotifyBlockDisconnected`).
    pub fn notify_block_disconnected(&self, block: Arc<MsgBlock>) {
        self.send(NtfnEvent::BlockDisconnected(block));
    }

    /// Queue a new-template work event (dcrd's template subscription
    /// forwarding into `NotifyWork`).
    pub fn notify_work(&self, template_block: MsgBlock, reason: TemplateUpdateReason) {
        self.send(NtfnEvent::Work(Box::new(template_block), reason));
    }

    /// Queue a treasury-spend event (dcrd `Server.NotifyTSpend`).
    pub fn notify_tspend(&self, tspend: MsgTx) {
        self.send(NtfnEvent::TSpend(Box::new(tspend)));
    }

    /// Queue a reorganization event (dcrd
    /// `Server.NotifyReorganization`).
    pub fn notify_reorganization(
        &self,
        old_hash: Hash,
        old_height: i64,
        new_hash: Hash,
        new_height: i64,
    ) {
        self.send(NtfnEvent::Reorganization {
            old_hash,
            old_height,
            new_hash,
            new_height,
        });
    }

    /// Queue a new-tickets event (dcrd `Server.NotifyNewTickets`).
    pub fn notify_new_tickets(
        &self,
        hash: Hash,
        height: i64,
        stake_difficulty: i64,
        tickets_new: Vec<Hash>,
    ) {
        self.send(NtfnEvent::NewTickets {
            hash,
            height,
            stake_difficulty,
            tickets_new,
        });
    }

    /// Queue mempool-acceptance events for the transactions with
    /// their trees (dcrd `Server.NotifyNewTransactions`).
    pub fn notify_new_transactions(&self, txns: Vec<(MsgTx, i8)>) {
        for (tx, tree) in txns {
            self.send(NtfnEvent::MempoolTx(Box::new(tx), tree));
        }
    }

    /// Queue mixing-message events (dcrd `Server.NotifyMixMessages`).
    pub fn notify_mix_messages(&self, msgs: Vec<Message>) {
        for msg in msgs {
            self.send(NtfnEvent::MixMessage(Box::new(msg)));
        }
    }

    /// Register a connected client, returning `false` without inserting
    /// when the concurrent websocket cap is reached (dcrd rejecting when
    /// `NumClients()+1 > RPCMaxWebsockets`).  The check and insert happen
    /// under the same lock, so concurrent connection threads cannot race
    /// past the cap.  `len() >= max` is `len()+1 > max` without the
    /// overflow-prone increment.
    ///
    /// A client counts against the cap from its upgrade, before it has
    /// authenticated, and nothing makes it authenticate in time: dcrd
    /// registers it the same way (`rpcwebsocket.go:108-127`) with no
    /// read deadline, so silent unauthenticated connections can hold
    /// every slot on either daemon (SECURITY.md).
    fn add_client(
        &self,
        session_id: u64,
        state: Arc<Mutex<WsClient>>,
        outbound: Arc<OutboundQueue>,
    ) -> bool {
        let mut clients = self.clients.lock().expect("ws clients");
        if clients.len() >= self.max_websockets {
            return false;
        }
        clients.insert(session_id, ClientHandle { state, outbound });
        self.registered
            .store(clients.len(), std::sync::atomic::Ordering::Relaxed);
        true
    }

    /// Drop a disconnected client: the registry entry and every
    /// subscription EXCEPT mix messages — dcrd's unregister-client
    /// case skips the mix map (`rpcwebsocket.go:563-573`), kept
    /// bug-for-bug and recorded in QUIRKS.md.  The stale entry is never
    /// seen, since delivery only reaches registered clients, but the set
    /// keeps one per session that ever subscribed, for the life of the
    /// process, as dcrd's map keeps each such client.
    ///
    /// This runs from [`ClientRegistration`]'s `Drop`, so it is reached
    /// on an unwind out of the serving loop as well as on a clean
    /// disconnect — dcrd unregisters from a `defer`.
    fn remove_client(&self, session_id: u64) {
        {
            let mut subs = self.inner.lock().expect("subs");
            subs.blocks.remove(&session_id);
            subs.work.remove(&session_id);
            subs.tspends.remove(&session_id);
            subs.winning_tickets.remove(&session_id);
            subs.new_tickets.remove(&session_id);
            subs.mempool_txs.remove(&session_id);
        }
        let mut clients = self.clients.lock().expect("ws clients");
        clients.remove(&session_id);
        self.registered
            .store(clients.len(), std::sync::atomic::Ordering::Relaxed);
    }

    /// The number of currently registered websocket clients (dcrd
    /// `wsNotificationManager.NumClients`).
    pub fn num_clients(&self) -> usize {
        self.clients.lock().expect("ws clients").len()
    }
}

/// A client's registration with the notification manager, released when
/// the guard is dropped.
///
/// dcrd unregisters each client from a `defer` in its per-client
/// goroutine, so the registration goes away whether the client leaves
/// cleanly or the goroutine dies.  A bare `remove_client` statement at
/// the end of the serving loop does not match that: an unwind from
/// anywhere inside the loop skips it and strands the session in the
/// client registry and in every subscription set for the life of the
/// process, with an outbound queue no thread will ever drain and a
/// websocket slot no client can ever reclaim.  Owning the registration
/// restores dcrd's `defer`.
struct ClientRegistration<'a> {
    ntfn: &'a NodeNtfnMgr,
    session_id: u64,
}

impl<'a> ClientRegistration<'a> {
    /// Register the client, or return `None` when the concurrent
    /// websocket cap refuses it (dcrd rejecting when `NumClients()+1 >
    /// RPCMaxWebsockets`).  A client that was never admitted gets no
    /// guard, so nothing is unregistered on its behalf.
    fn register(
        ntfn: &'a NodeNtfnMgr,
        session_id: u64,
        state: Arc<Mutex<WsClient>>,
        outbound: Arc<OutboundQueue>,
    ) -> Option<ClientRegistration<'a>> {
        ntfn.add_client(session_id, state, outbound)
            .then(|| ClientRegistration { ntfn, session_id })
    }
}

impl Drop for ClientRegistration<'_> {
    fn drop(&mut self) {
        self.ntfn.remove_client(self.session_id);
    }
}

impl Default for NodeNtfnMgr {
    fn default() -> NodeNtfnMgr {
        NodeNtfnMgr::new()
    }
}

impl RpcNtfnManager for NodeNtfnMgr {
    fn register_block_updates(&self, session_id: u64) {
        self.inner.lock().expect("subs").blocks.insert(session_id);
    }
    fn unregister_block_updates(&self, session_id: u64) {
        self.inner.lock().expect("subs").blocks.remove(&session_id);
    }
    fn register_work_updates(&self, session_id: u64) {
        self.inner.lock().expect("subs").work.insert(session_id);
    }
    fn unregister_work_updates(&self, session_id: u64) {
        self.inner.lock().expect("subs").work.remove(&session_id);
    }
    fn register_tspend_updates(&self, session_id: u64) {
        self.inner.lock().expect("subs").tspends.insert(session_id);
    }
    fn unregister_tspend_updates(&self, session_id: u64) {
        self.inner.lock().expect("subs").tspends.remove(&session_id);
    }
    fn register_winning_tickets(&self, session_id: u64) {
        self.inner
            .lock()
            .expect("subs")
            .winning_tickets
            .insert(session_id);
    }
    fn register_new_tickets(&self, session_id: u64) {
        self.inner
            .lock()
            .expect("subs")
            .new_tickets
            .insert(session_id);
    }
    fn register_new_mempool_txs_updates(&self, session_id: u64) {
        self.inner
            .lock()
            .expect("subs")
            .mempool_txs
            .insert(session_id);
    }
    fn unregister_new_mempool_txs_updates(&self, session_id: u64) {
        self.inner
            .lock()
            .expect("subs")
            .mempool_txs
            .remove(&session_id);
    }
    fn register_mix_messages(&self, session_id: u64) {
        self.inner
            .lock()
            .expect("subs")
            .mix_messages
            .insert(session_id);
    }
    fn unregister_mix_messages(&self, session_id: u64) {
        self.inner
            .lock()
            .expect("subs")
            .mix_messages
            .remove(&session_id);
    }

    fn notify_winning_tickets(&self, block_hash: &Hash, block_height: i64, tickets: &[Hash]) {
        self.send(NtfnEvent::WinningTickets {
            block_hash: *block_hash,
            block_height,
            tickets: tickets.to_vec(),
        });
    }
}

/// The delivery thread body (dcrd's `notificationHandler` goroutine):
/// receive events until shutdown and fan each one out to its
/// subscribers' outbound queues.
fn deliver_events(
    events: mpsc::Receiver<NtfnEvent>,
    server: Arc<Server<NodeRpcChain>>,
    subs: Arc<Mutex<Subscriptions>>,
    clients: Arc<Mutex<HashMap<u64, ClientHandle>>>,
) {
    while let Ok(event) = events.recv() {
        if matches!(event, NtfnEvent::Shutdown) {
            break;
        }
        deliver_one(event, &server, &subs, &clients);
    }
}

/// Fan one event out: pick the subscriber set the event notifies
/// (dcrd's per-kind client maps), run the ported builder against those
/// clients, and queue the marshalled JSON on each target's outbound
/// queue.  The builder needs no server-wide lock — dcrd's notification
/// manager takes none either — so a handler thread serving a long
/// request no longer blocks notification construction.  The event is
/// taken by value so a work template moves into the template pool
/// rather than being copied there.
fn deliver_one(
    event: NtfnEvent,
    server: &Arc<Server<NodeRpcChain>>,
    subs: &Arc<Mutex<Subscriptions>>,
    clients: &Arc<Mutex<HashMap<u64, ClientHandle>>>,
) {
    // Snapshot the target handles for the event's subscriber set.  A
    // mempool transaction also runs the relevant-tx filter pass over
    // EVERY connected client, exactly as dcrd's handler does.
    let (targets, everyone) = {
        let subs = subs.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let clients = clients
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let pick = |set: &HashSet<u64>| -> Vec<(u64, ClientHandle)> {
            set.iter()
                .filter_map(|id| clients.get(id).map(|h| (*id, h.clone())))
                .collect()
        };
        let targets = match &event {
            NtfnEvent::BlockConnected(_)
            | NtfnEvent::BlockDisconnected(_)
            | NtfnEvent::Reorganization { .. } => pick(&subs.blocks),
            NtfnEvent::Work(..) => pick(&subs.work),
            NtfnEvent::TSpend(_) => pick(&subs.tspends),
            NtfnEvent::WinningTickets { .. } => pick(&subs.winning_tickets),
            NtfnEvent::NewTickets { .. } => pick(&subs.new_tickets),
            NtfnEvent::MempoolTx(..) => pick(&subs.mempool_txs),
            NtfnEvent::MixMessage(_) => pick(&subs.mix_messages),
            NtfnEvent::Shutdown => Vec::new(),
        };
        let everyone: Vec<(u64, ClientHandle)> = if matches!(event, NtfnEvent::MempoolTx(..)) {
            clients.iter().map(|(id, h)| (*id, h.clone())).collect()
        } else {
            Vec::new()
        };
        (targets, everyone)
    };
    if targets.is_empty() && everyone.is_empty() {
        return;
    }

    let out = match event {
        NtfnEvent::BlockConnected(ref block) => build(server, &targets, |srv, refs| {
            rpcws::notify_block_connected(srv, refs, block)
        }),
        NtfnEvent::BlockDisconnected(ref block) => build(server, &targets, |srv, refs| {
            rpcws::notify_block_disconnected(srv, refs, block)
        }),
        NtfnEvent::Work(template_block, reason) => {
            build_from_snapshots(server, &targets, |srv, refs| {
                rpcws::notify_work(srv, refs, *template_block, reason)
            })
        }
        NtfnEvent::TSpend(ref tspend) => build(server, &targets, |srv, refs| {
            rpcws::notify_tspend(srv, refs, tspend)
        }),
        NtfnEvent::Reorganization {
            ref old_hash,
            old_height,
            ref new_hash,
            new_height,
        } => build(server, &targets, |srv, refs| {
            rpcws::notify_reorganization(srv, refs, old_hash, old_height, new_hash, new_height)
        }),
        NtfnEvent::WinningTickets {
            ref block_hash,
            block_height,
            ref tickets,
        } => build(server, &targets, |srv, refs| {
            rpcws::notify_winning_tickets_ntfn(srv, refs, block_hash, block_height, tickets)
        }),
        NtfnEvent::NewTickets {
            ref hash,
            height,
            stake_difficulty,
            ref tickets_new,
        } => build(server, &targets, |srv, refs| {
            rpcws::notify_new_tickets(srv, refs, hash, height, stake_difficulty, tickets_new)
        }),
        NtfnEvent::MempoolTx(ref tx, tree) => {
            // dcrd notifies the txaccepted subscribers only when some
            // exist, then always runs the relevant-tx pass over every
            // client.
            let mut out = if targets.is_empty() {
                Vec::new()
            } else {
                build_from_snapshots(server, &targets, |srv, refs| {
                    rpcws::notify_for_new_tx(srv, refs, tx)
                })
            };
            out.extend(build(server, &everyone, |srv, refs| {
                rpcws::notify_relevant_tx_accepted(srv, refs, tx, tree)
            }));
            out
        }
        NtfnEvent::MixMessage(ref msg) => build(server, &targets, |srv, refs| {
            rpcws::notify_mix_message(srv, refs, msg)
        }),
        NtfnEvent::Shutdown => Vec::new(),
    };

    // Queue the JSON on each target's outbound queue; the serving
    // loops write them out when their connections go idle.
    let by_id: HashMap<u64, &ClientHandle> = targets
        .iter()
        .chain(everyone.iter())
        .map(|(id, h)| (*id, h))
        .collect();
    for (session_id, json) in out {
        if let Some(handle) = by_id.get(&session_id) {
            handle.outbound.push_notification(json);
        }
    }
}

/// Lock the given clients' shared state and run a ported builder over
/// them, for the builders that update a client's transaction filter.
/// Those touch nothing else that locks, so the client locks are held
/// only while the filters are searched.
fn build<F>(
    server: &Server<NodeRpcChain>,
    handles: &[(u64, ClientHandle)],
    builder: F,
) -> Vec<(u64, String)>
where
    F: FnOnce(&Server<NodeRpcChain>, &mut [&mut WsClient]) -> Vec<(u64, String)>,
{
    let mut guards: Vec<_> = handles
        .iter()
        .map(|(_, h)| {
            h.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        })
        .collect();
    let mut refs: Vec<&mut WsClient> = guards.iter_mut().map(|g| &mut **g).collect();
    builder(server, &mut refs)
}

/// Run a ported builder over snapshots of the given clients, for the
/// builders that call into the chain or the work state and read nothing
/// from a client but its session id and verbose flag.
///
/// dcrd's `notifyForNewTx` and `notifyWork` make those calls with no
/// client locked, reading `verboseTxUpdates` unlocked
/// (`rpcwebsocket.go:1093-1104`, `:865-907`).  [`build`] would hold every
/// target's lock across them, and each target's reader takes that same
/// lock for every request it serves -- so a block validation, a UTXO
/// flush or a getwork submission holding the chain mutex or the work
/// state stopped every subscriber from being served until it let go.
/// Each client is locked here only long enough to copy the two fields.
fn build_from_snapshots<F>(
    server: &Server<NodeRpcChain>,
    handles: &[(u64, ClientHandle)],
    builder: F,
) -> Vec<(u64, String)>
where
    F: FnOnce(&Server<NodeRpcChain>, &mut [&mut WsClient]) -> Vec<(u64, String)>,
{
    let mut snapshots: Vec<WsClient> = handles
        .iter()
        .map(|(_, h)| {
            let wsc = h
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut snapshot = WsClient::new(wsc.session_id);
            snapshot.verbose_tx_updates = wsc.verbose_tx_updates;
            snapshot
        })
        .collect();
    let mut refs: Vec<&mut WsClient> = snapshots.iter_mut().collect();
    builder(server, &mut refs)
}

/// The RPC server's log subsystem, which dcrd's websocket code logs
/// under (`internal/rpcserver`'s package logger, bound to `RPCS`).
const RPCS: &str = "RPCS";

/// Start a connection's writer on the scope, handing back the OS's
/// refusal instead of panicking.
///
/// `Scope::spawn` panics when the OS refuses a thread (`EAGAIN` under
/// `RLIMIT_NPROC` or a cgroup `pids.max`, `ENOMEM` for its stack), and
/// release builds abort on a panic; this is the scoped counterpart of
/// [`crate::runtime::spawn_conn_thread`], and honours the same test
/// switch.
fn spawn_writer<'scope, 'env, F>(
    scope: &'scope std::thread::Scope<'scope, 'env>,
    work: F,
) -> std::io::Result<std::thread::ScopedJoinHandle<'scope, ()>>
where
    F: FnOnce() + Send + 'scope,
{
    #[cfg(test)]
    if crate::runtime::REFUSE_CONN_THREADS.with(std::cell::Cell::get) {
        return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
    }
    std::thread::Builder::new()
        .name("ws-writer".to_string())
        .spawn_scoped(scope, work)
}

/// A random session id for a websocket client (dcrd
/// `newWebsocketClient`, `internal/rpcserver/rpcwebsocket.go:2034`).
///
/// From the process-wide generator, not a fresh kernel read: dcrd
/// imports `crypto/rand` and calls the package function
/// (`rpcwebsocket.go:25`, `:2037`), and the draw happens after the 101
/// but before a client has had to authenticate, so an unauthenticated
/// caller sets its rate.  Under this workspace's `panic = "abort"`
/// release profile a failed read there would be an outage; the package
/// generator cannot fail once seeded, which the daemon does at startup.
fn new_session_id() -> u64 {
    dcroxide_crypto::rand::uint64()
}

/// Complete the RFC 6455 handshake and serve the client's requests
/// until it disconnects (dcrd `WebsocketHandler` plus the per-client
/// loops).  `remote_addr` is the client's address as dcrd's
/// `r.RemoteAddr` renders it, for the log lines that name the client.
/// `pre_authenticated` reflects a Basic-auth header accepted
/// before the upgrade; an unauthenticated client must send
/// `authenticate` before any other command.  The client registers with
/// the notification manager for delivery, and its outbound queue is
/// drained whenever the connection goes idle or between requests.
#[allow(clippy::too_many_arguments)]
pub fn serve_websocket<S: Read + Write + Send>(
    mut stream: S,
    head: &crate::rpcrun::HttpHead,
    remote_addr: &str,
    pre_authenticated: bool,
    is_admin: bool,
    server: &Arc<Server<NodeRpcChain>>,
    ntfn: &NodeNtfnMgr,
    shutdown: &Arc<std::sync::atomic::AtomicBool>,
) {
    // gorilla's `Upgrade` runs its checks in one fixed order
    // (`gorilla/websocket@v1.5.1 server.go:126-191`), and each failure
    // goes out through `returnError`, whose body is the status text and
    // whose one extra header is the version hint.  The order is
    // observable: a request wrong in two of these ways gets the answer
    // for whichever is tested first.
    if !crate::rpcrun::header_has_token(&head.connection, "upgrade")
        || !crate::rpcrun::header_has_token(&head.upgrade, "websocket")
    {
        let _ = write_handshake_error(&mut stream, "400 Bad Request", "Bad Request");
        return;
    }
    // Compared exactly, as gorilla does (`r.Method != http.MethodGet`,
    // `server.go:137`): Go never case-folds a request method, so a
    // lowercase `get` is a method of its own and draws the 405.
    if head.method != "GET" {
        let _ = write_handshake_error(&mut stream, "405 Method Not Allowed", "Method Not Allowed");
        return;
    }
    // The version is a `1#token` header too, so gorilla scans every
    // copy of it with the same grammar (`server.go:141`).
    if !crate::rpcrun::header_has_token(&head.sec_websocket_version, "13") {
        let _ = write_handshake_error(&mut stream, "400 Bad Request", "Bad Request");
        return;
    }
    // The origin check sits between the version and the key, and dcrd
    // supplies its own (`rpcserver.go:5972-6007`).
    if !crate::rpcrun::check_origin(head) {
        let _ = write_handshake_error(&mut stream, "403 Forbidden", "Forbidden");
        return;
    }
    let key = match &head.sec_websocket_key {
        Some(key) if valid_ws_key(key) => key.clone(),
        _ => {
            let _ = write_handshake_error(&mut stream, "400 Bad Request", "Bad Request");
            return;
        }
    };

    // Refuse a handshake that declared a request body, dropping the
    // connection with no answer at all.  gorilla inspects the hijacked
    // reader and closes outright on any byte that arrived alongside the
    // handshake -- "client sent data before handshake is complete"
    // (`gorilla/websocket@v1.5.1 server.go:186-191`) -- which dcrd
    // surfaces only as a log line, never as a response
    // (`rpcserver.go:6009-6015`).  Without this the declared bytes are
    // read as the first RFC 6455 frames, so a proxy that forwarded them
    // as a `Content-Length` body and this server disagree about where
    // the request ended.
    //
    // The test differs from gorilla's because the reader here cannot
    // hold what gorilla's inspects: `read_http_head` takes the head one
    // byte at a time and stops on the blank line, so nothing is ever
    // buffered past it and there is no arrival to detect -- the
    // declared framing is what can be tested.  That is stricter for a
    // body declared but not yet sent (gorilla upgrades, this refuses)
    // and looser for bytes pipelined without a `Content-Length`
    // (gorilla refuses, this upgrades); only the declared form can
    // desync a proxy, which is the case that matters.
    if head.declares_body() {
        return;
    }

    // Answer the handshake.
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        accept_key(&key)
    );
    if stream.write_all(response.as_bytes()).is_err() || stream.flush().is_err() {
        return;
    }
    serve_upgraded(
        stream,
        remote_addr,
        pre_authenticated,
        is_admin,
        server,
        ntfn,
        shutdown,
    );
}

/// Serve a client whose upgrade has been answered: register it, start
/// its writer, and read its requests until it disconnects (dcrd
/// `wsClient.Run`'s three goroutines).
fn serve_upgraded<S: Read + Write + Send>(
    stream: S,
    remote_addr: &str,
    pre_authenticated: bool,
    is_admin: bool,
    server: &Arc<Server<NodeRpcChain>>,
    ntfn: &NodeNtfnMgr,
    shutdown: &Arc<std::sync::atomic::AtomicBool>,
) {
    let session_id = new_session_id();
    let state = Arc::new(Mutex::new({
        let mut wsc = WsClient::new(session_id);
        wsc.authenticated = pre_authenticated;
        wsc.is_admin = is_admin;
        wsc
    }));
    let outbound: Arc<OutboundQueue> = Arc::default();
    // Register the client, or refuse it when the websocket cap is
    // reached: dropping `stream` closes the connection with no close
    // frame, exactly as dcrd's `conn.Close()` does.  Returning here
    // before the serve loop keeps `remove_client` from running for a
    // client that was never admitted.  The guard releases the
    // registration on every exit from this function — a clean
    // disconnect, an early `break`, or an unwind — the way dcrd's
    // `defer` does.
    let Some(_registration) =
        ClientRegistration::register(ntfn, session_id, Arc::clone(&state), Arc::clone(&outbound))
    else {
        return;
    };
    // dcrd gives each client an `outHandler` goroutine that owns the
    // write side and drains `sendChan` (`rpcwebsocket.go:1896-1922`),
    // which is why a notification reaches a client while one of its own
    // requests is still running.  This is that goroutine.
    //
    // Read and write cannot be split apart here: under TLS the stream is
    // one `rustls::StreamOwned`, so both share a mutex.  The reader holds
    // it only across `read_message`, never across a handler, so the
    // writer runs during a request -- the whole point.  The writer is
    // scoped rather than detached so it is always joined, and the queue
    // is closed on every exit so it can never park on a queue nobody
    // will fill.
    let conn = Mutex::new(WsConn::new(stream));
    let write_failed = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|scope| {
        let spawned = spawn_writer(scope, || {
            // Waits without the stream, then drains with it: the lock
            // order is pending (released) then conn here, and conn then
            // pending in the reader, so neither holds one while asking
            // for the other in the opposite order.  One batch per
            // acquisition, so the reader can take the stream between
            // them; each written batch promotes the next notification,
            // which is what brings this thread straight back.
            while outbound.wait_for_items() {
                let mut conn = conn.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                if write_queued_batch(&mut conn, &outbound).is_err() {
                    write_failed.store(true, std::sync::atomic::Ordering::SeqCst);
                    return;
                }
            }
        });
        // A refused writer drops the connection, as the RPC accept loop
        // drops one whose serving thread the OS refuses: returning here
        // closes the stream and the registration guard frees the
        // websocket slot.  `Scope::spawn` panics instead, which the
        // release profile turns into an abort of the whole node, and the
        // upgrade that reaches it needs no credentials.  dcrd's
        // `outHandler` is a goroutine, which cannot fail to start.
        if let Err(e) = spawned {
            crate::logging::warn(
                RPCS,
                &format!(
                    "Unable to start a writer thread for websocket client {remote_addr}: {e} \
                     -- dropping it"
                ),
            );
            return;
        }
        // Closing from a guard rather than a trailing statement, for
        // the reason `ClientRegistration` already documents: a panic
        // anywhere in the read loop that is not caught by the dispatch
        // guard would otherwise skip the close, leave the writer parked
        // on the condvar, and hang `thread::scope`'s join forever --
        // turning an unwind into a stuck connection thread.
        struct CloseOnExit<'a>(&'a OutboundQueue);
        impl Drop for CloseOnExit<'_> {
            fn drop(&mut self) {
                self.0.close();
            }
        }
        let _close = CloseOnExit(&outbound);
        serve_ws_reads(
            &conn,
            &outbound,
            &write_failed,
            &state,
            remote_addr,
            server,
            shutdown,
        );
    });
}

/// The read half of the serving loop: dcrd's `inHandler`.
///
/// Every reply is queued rather than written here, because dcrd queues
/// its own through `SendMessage` onto the very channel `outHandler`
/// drains (`rpcwebsocket.go:1925-1940`).  One writer means replies and
/// notifications leave in the order they were queued, which two writers
/// could not promise.
fn serve_ws_reads<S: Read + Write>(
    conn: &Mutex<WsConn<S>>,
    outbound: &Arc<OutboundQueue>,
    write_failed: &std::sync::atomic::AtomicBool,
    state: &Arc<Mutex<WsClient>>,
    remote_addr: &str,
    server: &Arc<Server<NodeRpcChain>>,
    shutdown: &Arc<std::sync::atomic::AtomicBool>,
) {
    // The connection's read limit, gorilla's `readLimit`: set at the
    // upgrade from whether the client arrived authenticated
    // (`rpcserver.go:6036-6040`), and raised after that only by the
    // single-request authenticate arm (`rpcwebsocket.go:1496-1497`).  It
    // is not the authenticated flag -- dcrd's batch arm authenticates a
    // client without raising it, so one that authenticated in a batch
    // keeps the unauthenticated limit for good (QUIRKS.md).
    let mut read_limit = if client_flags(state).0 {
        READ_LIMIT_AUTHENTICATED
    } else {
        READ_LIMIT_UNAUTHENTICATED
    };
    loop {
        // A server shutdown ends the connection like dcrd's
        // `close(s.quit)` unblocking every websocket loop; the poll
        // read below wakes this check within its interval.
        if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        // A failed write means the connection is gone; the writer saw
        // it first and this ends the read loop the way the inline write
        // used to.
        if write_failed.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }

        // One acquisition: write whatever is queued, then read. Draining
        // here is what makes the writer's fairness irrelevant -- a plain
        // mutex lets this thread barge, and it does, so it takes the
        // output with it rather than leaving it for a writer it keeps
        // outrunning. It drains until the queue is empty (or its budget
        // is spent), not one batch, because the writer is shut out for
        // the read that follows. The lock is
        // released before dispatch, which is when the writer gets its
        // turn and the whole point of having one.
        let read = {
            let mut conn = conn.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if drain_before_read(&mut conn, outbound, READER_DRAIN_BUDGET).is_err() {
                write_failed.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            conn.read_message(read_limit)
        };
        let message = match read {
            Ok(WsIn::Text(payload)) => payload,
            // An idle read just returns to the top of the loop; the
            // writer, not this thread, delivers what is queued.
            Ok(WsIn::Idle) => continue,
            // A close frame, a clean disconnect, or a protocol error
            // ends the connection.
            Ok(WsIn::Close) | Err(_) => break,
        };
        // dcrd services a websocket command with a context, the same one
        // the standard HTTP handlers get: `serviceRequest` falls through
        // to `standardCmdResult(ctx, r)` for any method not in its
        // websocket-only table, and getwork is not in that table
        // (`rpcwebsocket.go:1807-1819`).
        //
        // That context is the UPGRADE request's (`rpcserver.go:6041`
        // passing `r.Context()`), which descends from the server's
        // through `BaseContext` (`rpcserver.go:5921-5927`), so shutdown
        // cancels it.
        //
        // dcrd also reaches it on a client hangup, but only where it
        // dispatches concurrently: a non-batched command runs in a
        // goroutine (`rpcwebsocket.go:1550`) that `Run`'s `wg.Add(3)`
        // does not cover (`:1998-2011`), so it outlives the client
        // teardown and is still selecting on the context when
        // `conn.serve` fires `w.cancelCtx()` after `ServeHTTP` returns --
        // unconditionally, before the `c.hijacked()` check
        // (`net/http/server.go:2137-2140`).
        //
        // This loop dispatches synchronously, so while a request runs
        // nothing is reading and a hangup cannot be noticed at all.  That
        // is dcrd's own behaviour on the two arms where it also stops
        // reading: a batched request, which it services inline
        // (`rpcwebsocket.go:1748`), and any request once
        // `serviceRequestSem` is exhausted, since that is acquired before
        // the spawn (`:1549`).  So the shutdown flag is the whole of what
        // this token can carry here; see PARITY for what closing the rest
        // would take.
        let outcome = {
            let _cancel = dcroxide_rpc::worksem::scope_request_cancel(Arc::clone(shutdown));
            handle_ws_request(server, state, remote_addr, &message, &mut read_limit)
        };
        match outcome {
            WsOutcome::Reply(reply) => outbound.push_reply(reply),
            WsOutcome::Skip => {}
            WsOutcome::Disconnect => break,
            // dcrd's bare `return` out of `inHandler` skips the trailing
            // `c.Disconnect()` (`rpcwebsocket.go:1800`), so nothing reads
            // the client again but nothing closes it either: `Run` still
            // waits on `ctx.Done()` or `c.quit` (`:2019-2023`), and the
            // writer keeps delivering notifications until a write fails
            // or the server shuts down.
            WsOutcome::StopReading => {
                park_without_reading(write_failed, shutdown);
                break;
            }
        }
    }
}

/// How often a client that is no longer read checks whether its
/// connection has gone: the read poll's own interval (`rpcrun`'s
/// `WS_POLL_INTERVAL`).
const PARKED_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);

/// Hold a client whose input is no longer read until a write to it
/// fails or the server shuts down, the only two things that disconnect
/// a dcrd client once its `inHandler` has returned without calling
/// `Disconnect` (`outHandler`'s failed write at `rpcwebsocket.go:1903-1905`
/// and `Run`'s `ctx.Done()` arm at `:2020-2021`).
fn park_without_reading(
    write_failed: &std::sync::atomic::AtomicBool,
    shutdown: &std::sync::atomic::AtomicBool,
) {
    while !shutdown.load(std::sync::atomic::Ordering::SeqCst)
        && !write_failed.load(std::sync::atomic::Ordering::SeqCst)
    {
        std::thread::sleep(PARKED_POLL_INTERVAL);
    }
}

/// The client's (authenticated, is_admin) flags under a brief lock.
fn client_flags(state: &Arc<Mutex<WsClient>>) -> (bool, bool) {
    let wsc = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    (wsc.authenticated, wsc.is_admin)
}

/// What to do with one websocket request.
enum WsOutcome {
    /// Send this reply text to the client.
    Reply(String),
    /// No reply (a notification, or a dropped marshalling failure).
    Skip,
    /// Drop the connection (dcrd's silent disconnect on malformed or
    /// unauthenticated traffic).
    Disconnect,
    /// Abandon the message and never read the client again, but leave
    /// it connected (dcrd's batch arm returning from `inHandler` when a
    /// command's reply fails to marshal).
    StopReading,
}

/// dcrd's log text for most replies `inHandler` fails to marshal
/// (`rpcwebsocket.go:1426`, `:1440`, `:1465`, `:1598`, `:1642`, `:1670`).
const MARSHAL_REPLY_FAILED: &str = "Failed to marshal reply";

/// dcrd's log text for a limited user's refusal that fails to marshal
/// (`rpcwebsocket.go:1520`, `:1729`).
const MARSHAL_LIMITED_REPLY_FAILED: &str = "Failed to marshal parse failure reply";

/// dcrd's log text for the batch arm's bare `MarshalResponse` failing
/// (`rpcwebsocket.go:1577`, `:1625`).
const CREATE_REPLY_FAILED: &str = "Failed to create reply";

/// Log a reply that failed to marshal, as dcrd's `log.Errorf("<what>:
/// %v", err)` does before dropping it.
fn log_marshal_failure(failure: &str, err: &str) {
    crate::logging::error(RPCS, &format!("{failure}: {err}"));
}

/// A request that parsed, logged at debug before the authentication
/// check (`rpcwebsocket.go:1472`, `:1680`).
fn log_received_command(method: &str, remote_addr: &str) {
    crate::logging::debug(
        RPCS,
        &format!("Received command <{method}> from {remote_addr}"),
    );
}

/// An authenticate request from a client that already authenticated:
/// dcrd warns and disconnects it (`rpcwebsocket.go:1480-1482`,
/// `:1688-1690`).
fn already_authenticated(remote_addr: &str) -> WsOutcome {
    crate::logging::warn(
        RPCS,
        &format!("Websocket client {remote_addr} is already authenticated"),
    );
    WsOutcome::Disconnect
}

/// Anything but authenticate from a client that has not authenticated:
/// dcrd warns, without naming the client, and disconnects it
/// (`rpcwebsocket.go:1484-1486`, `:1692-1694`).
fn unauthenticated_message() -> WsOutcome {
    crate::logging::warn(RPCS, "Unauthenticated websocket message received");
    WsOutcome::Disconnect
}

/// The outcome for a request that could not be parsed: dcrd disconnects
/// an unauthenticated client on any parse failure and hands an
/// authenticated one an RPC parse error (dcrd `inHandler`).  Shared by
/// the JSON parse path and the raw-frame syntax check.
fn parse_error_outcome(authenticated: bool, err_text: &str) -> WsOutcome {
    if !authenticated {
        return WsOutcome::Disconnect;
    }
    let json_err = RPCError::new(
        err_rpc_parse().code,
        &format!("Failed to parse request: {err_text}"),
    );
    reply_or_skip(
        create_marshalled_reply("1.0", &RpcId::Null, None, Some(&json_err)),
        MARSHAL_REPLY_FAILED,
    )
}

/// The reply for a request whose handling panicked: dcrd's internal
/// error, carrying a null id.
///
/// The id is deliberately not the request's own.  Whatever panicked
/// might have been the marshalling of that id, in which case echoing it
/// back would panic a second time — this time with no handler left to
/// catch it.  A null id is the same answer the HTTP path's
/// panic-recovery gives.
fn panic_recovery_outcome() -> WsOutcome {
    let json_err = RPCError::new(
        err_rpc_internal().code,
        "internal error: the handler's daemon seam is not yet wired",
    );
    reply_or_skip(
        create_marshalled_reply("1.0", &RpcId::Null, None, Some(&json_err)),
        MARSHAL_REPLY_FAILED,
    )
}

/// Give one websocket request its dcrd `inHandler` handling, with the
/// whole of it inside a single `catch_unwind`.
///
/// Nothing about handling one request may unwind past this point.  The
/// serving loop above holds the client's notification registration, and
/// an escaping panic would tear down the connection thread while the
/// notification manager kept queueing onto a session that no longer has
/// a reader — so every step, including marshalling the client's own id,
/// runs under the guard, and the recovery answers with a null id.
fn handle_ws_request(
    server: &Arc<Server<NodeRpcChain>>,
    state: &Arc<Mutex<WsClient>>,
    remote_addr: &str,
    message: &[u8],
    read_limit: &mut usize,
) -> WsOutcome {
    catch_unwind(AssertUnwindSafe(|| {
        handle_ws_request_inner(server, state, remote_addr, message, read_limit)
    }))
    .unwrap_or_else(|_| panic_recovery_outcome())
}

/// The dcrd `inHandler` body: the batch branch, then the single-request
/// ladder.
///
/// The order of the arms below is dcrd's, and it is not the order the
/// HTTP transport uses.  `processRequest` gates the limited user before
/// parsing the command; `inHandler` parses first and answers the parse
/// error, so a limited client learns whether a method exists from a
/// different oracle on each transport.  The port modelled the HTTP
/// ladder here for both, which diverged in three ways at once; all
/// three are reproduced now (RVW-001, RVW-002 and RVW-003 of an
/// external review of `382864f5`).
fn handle_ws_request_inner(
    server: &Arc<Server<NodeRpcChain>>,
    state: &Arc<Mutex<WsClient>>,
    remote_addr: &str,
    message: &[u8],
    read_limit: &mut usize,
) -> WsOutcome {
    // dcrd tests the raw first byte (`bytes.HasPrefix(msg,
    // batchedRequestPrefix)`), so a leading space makes an array a
    // single request that then fails to unmarshal, not a batch.
    let batched = message.first() == Some(&b'[');

    // dcrd hands the frame to `json.Unmarshal` as it arrived
    // (`rpcwebsocket.go:1413`, `:1563`) -- gorilla checks UTF-8 only in a
    // close frame's reason -- so invalid UTF-8 inside a string is served,
    // decoded as U+FFFD, and a stray byte anywhere else is Go's syntax
    // error, answered by whichever arm the first byte chose.
    let body = match dcroxide_dcrjson::gojson::unmarshal_input(message) {
        Ok(body) => body,
        Err(err) => {
            let authenticated = client_flags(state).0;
            return if batched {
                batch_parse_error_outcome(authenticated, &err)
            } else {
                parse_error_outcome(authenticated, &err.go_message())
            };
        }
    };
    if batched {
        return handle_ws_batch(server, state, remote_addr, &body);
    }
    handle_ws_single(server, state, remote_addr, &body, read_limit)
}

/// One non-batched websocket request (dcrd `inHandler`'s
/// `!batchedRequest` arm).
fn handle_ws_single(
    server: &Arc<Server<NodeRpcChain>>,
    state: &Arc<Mutex<WsClient>>,
    remote_addr: &str,
    body: &str,
    read_limit: &mut usize,
) -> WsOutcome {
    let (authenticated, is_admin) = client_flags(state);
    let req = match unmarshal_request(body) {
        Ok(req) => req,
        Err(err_text) => return parse_error_outcome(authenticated, &err_text),
    };

    // A malformed request is answered before authentication and leaves
    // the connection open, unlike every other rejection here.
    if req.method.is_empty() {
        let json_err = RPCError::new(err_rpc_invalid_request().code, "Invalid request: malformed");
        return reply_or_skip(
            create_marshalled_reply(&req.jsonrpc, &req.id, None, Some(&json_err)),
            MARSHAL_REPLY_FAILED,
        );
    }

    // Valid requests with no id are notifications and draw no response.
    // This gate sits ahead of the authenticate arm, so an id-less
    // authenticate never reaches it: an unauthenticated sender is
    // disconnected and an authenticated one is ignored.
    if matches!(req.id, RpcId::Null) {
        return if authenticated {
            WsOutcome::Skip
        } else {
            WsOutcome::Disconnect
        };
    }

    let param_refs: Vec<&str> = req.params.iter().map(|s| s.as_str()).collect();
    let parsed = parse_cmd(
        &server.registry,
        &req.jsonrpc,
        &req.method,
        &param_refs,
        &req.id,
    );
    if let Some(err) = parsed.err {
        if !authenticated {
            return WsOutcome::Disconnect;
        }
        return reply_or_skip(
            create_marshalled_reply(&req.jsonrpc, &req.id, None, Some(&err)),
            MARSHAL_REPLY_FAILED,
        );
    }

    log_received_command(&req.method, remote_addr);

    // The authenticate state machine, keyed on whether the parsed
    // command is the authenticate one.
    let is_auth_cmd = req.method == "authenticate";
    match (authenticated, is_auth_cmd) {
        (true, true) => return already_authenticated(remote_addr),
        (false, false) => return unauthenticated_message(),
        (false, true) => {
            let outcome = authenticate(
                server,
                state,
                remote_addr,
                &req.jsonrpc,
                parsed.params.as_ref(),
                &req.id,
            );
            // Only this arm raises the read limit, and it does so once
            // the credentials check out, ahead of marshalling the reply
            // (`rpcwebsocket.go:1496-1497`).
            if !matches!(outcome, WsOutcome::Disconnect) {
                *read_limit = READ_LIMIT_AUTHENTICATED;
            }
            return outcome;
        }
        (true, false) => {}
    }

    // dcrd passes an empty version here (`rpcwebsocket.go:1518`), which
    // `MarshalResponse` coerces to "1.0" -- so this reply reads
    // `"jsonrpc":"1.0"` even for a 2.0 request.  The batch arm passes
    // the request's version through, matching dcrd's gate at `:1727`.
    if !is_admin && !RPC_LIMITED.contains(&req.method.as_str()) {
        let json_err = RPCError::new(
            err_rpc_invalid_params().code,
            "limited user not authorized for this method",
        );
        return reply_or_skip(
            create_marshalled_reply("", &req.id, None, Some(&json_err)),
            MARSHAL_LIMITED_REPLY_FAILED,
        );
    }

    // A reply that fails to marshal is logged and dropped
    // (`serviceRequest`, `rpcwebsocket.go:1821-1826`); the log line is
    // `ws_service_request`'s.
    dispatch_ws_command(server, state, &req, parsed.params, WsOutcome::Skip)
}

/// Dispatch one fully-gated command, under the panic guard.
///
/// The server is shared, not locked, which is dcrd's behaviour:
/// `wsClient.serviceRequest` takes no server-wide lock, calling the
/// handler directly, and `rpcserver.Server` carries only fine-grained
/// mutexes each guarding one field.  The client's own state is not held
/// across the request either: dcrd's `wsClient` embeds one mutex taken a
/// field at a time, and holding it for the whole call meant a request
/// that waits -- a rescan, a `generate`, a `getwork` template wait --
/// stalled the delivery thread and so the fan-out to every other client.
///
/// `marshal_failure` is the outcome when the reply fails to marshal (a
/// result Go's `json.Marshal` refuses, or an id of an invalid type),
/// which the two arms of dcrd's `inHandler` treat differently.
fn dispatch_ws_command(
    server: &Arc<Server<NodeRpcChain>>,
    state: &Arc<Mutex<WsClient>>,
    req: &dcroxide_rpc::http::RawRequest,
    params: Option<dcroxide_dcrjson::GoValue>,
    marshal_failure: WsOutcome,
) -> WsOutcome {
    let jsonrpc = req.jsonrpc.clone();
    let id = req.id.clone();
    let method = req.method.clone();
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let cmd = params.expect("a parsed command has params");
        ws_service_request(server, state, &jsonrpc, &method, &cmd, &id)
    }));
    match outcome {
        Ok(Some(reply)) => WsOutcome::Reply(reply),
        Ok(None) => marshal_failure,
        Err(_) => panic_recovery_outcome(),
    }
}

/// A batched websocket request (dcrd `inHandler`'s `batchedRequest`
/// arm).
///
/// Each entry runs the same ladder as a single request, with three
/// differences dcrd's own code carries: a malformed entry is one whose
/// method is empty *or* that has no `params` array at all, an
/// unparseable entry is answered `Invalid request` at version "2.0"
/// rather than a parse error, and the limited gate passes the request's
/// own version through where the single arm passes an empty one.
///
/// A disconnect anywhere abandons the whole message, as dcrd's
/// `break out` does: the replies already collected are dropped with the
/// connection.  So does a command whose reply fails to marshal, which
/// dcrd answers with a bare `return` from `inHandler`
/// (`rpcwebsocket.go:1753-1758`): the entries after it never run, and
/// the client is never read again but stays connected.  Every other
/// marshal failure in the arm drops only its own entry (`continue`).
fn handle_ws_batch(
    server: &Arc<Server<NodeRpcChain>>,
    state: &Arc<Mutex<WsClient>>,
    remote_addr: &str,
    body: &str,
) -> WsOutcome {
    let (authenticated, _) = client_flags(state);
    let mut results: Vec<String> = Vec::new();
    let mut batch_size = 0usize;

    match dcroxide_dcrjson::gojson::validate(body) {
        Err(err) => return batch_parse_error_outcome(authenticated, &err),
        Ok(()) => {
            let entries = split_raw_array(body.trim_start_matches([' ', '\t', '\n', '\r']));
            if entries.is_empty() {
                if !authenticated {
                    return WsOutcome::Disconnect;
                }
                let json_err = RPCError::new(
                    err_rpc_invalid_request().code,
                    "Invalid request: empty batch",
                );
                match create_marshalled_reply("2.0", &RpcId::Null, None, Some(&json_err)) {
                    Ok(reply) => results.push(reply),
                    Err(e) => log_marshal_failure(MARSHAL_REPLY_FAILED, &e),
                }
            } else {
                batch_size = entries.len();
                for entry in entries {
                    match handle_ws_batch_entry(server, state, remote_addr, &entry) {
                        WsOutcome::Reply(reply) => results.push(reply),
                        WsOutcome::Skip => {}
                        WsOutcome::Disconnect => return WsOutcome::Disconnect,
                        WsOutcome::StopReading => return WsOutcome::StopReading,
                    }
                }
            }
        }
    }

    // dcrd sends whatever payload this produces, including the empty
    // one a batch of pure notifications leaves behind.
    if batch_size > 0 {
        if results.is_empty() {
            return WsOutcome::Reply(String::new());
        }
        return WsOutcome::Reply(alloc_batch_array(&results));
    }
    match results.into_iter().next() {
        Some(first) => WsOutcome::Reply(first),
        None => WsOutcome::Reply(String::new()),
    }
}

/// The outcome for a batch whose message does not parse as JSON: a
/// disconnect for an unauthenticated client, otherwise the parse error
/// at version "2.0" as the whole reply -- or the empty payload dcrd
/// sends when even that fails to marshal (`rpcwebsocket.go:1563-1583`,
/// `:1767-1794`).
fn batch_parse_error_outcome(
    authenticated: bool,
    err: &dcroxide_dcrjson::gojson::JsonError,
) -> WsOutcome {
    if !authenticated {
        return WsOutcome::Disconnect;
    }
    let json_err = RPCError::new(
        err_rpc_parse().code,
        &format!("Failed to parse request: {}", err.go_message()),
    );
    WsOutcome::Reply(
        create_marshalled_reply("2.0", &RpcId::Null, None, Some(&json_err)).unwrap_or_else(|e| {
            log_marshal_failure(CREATE_REPLY_FAILED, &e);
            String::new()
        }),
    )
}

/// The batched response json: the entry replies joined in one array.
fn alloc_batch_array(results: &[String]) -> String {
    let mut out = String::new();
    out.push('[');
    let mut rest = results.len();
    for reply in results {
        out.push_str(reply);
        rest = rest.saturating_sub(1);
        if rest == 0 {
            out.push(']');
        } else {
            out.push(',');
        }
    }
    out
}

/// One entry of a batch, returning the reply to collect, `Skip` for a
/// notification, or `Disconnect` to abandon the message.
fn handle_ws_batch_entry(
    server: &Arc<Server<NodeRpcChain>>,
    state: &Arc<Mutex<WsClient>>,
    remote_addr: &str,
    entry: &str,
) -> WsOutcome {
    let (authenticated, is_admin) = client_flags(state);
    let req = match unmarshal_request(entry) {
        Ok(req) => req,
        Err(err_text) => {
            if !authenticated {
                return WsOutcome::Disconnect;
            }
            let json_err = RPCError::new(
                err_rpc_invalid_request().code,
                &format!("Invalid request: {err_text}"),
            );
            return reply_or_skip(
                create_marshalled_reply("2.0", &RpcId::Null, None, Some(&json_err)),
                CREATE_REPLY_FAILED,
            );
        }
    };

    // The batch arm calls an entry with no params array malformed too,
    // which the single arm does not.
    if req.method.is_empty() || !req.params_present {
        let json_err = RPCError::new(err_rpc_invalid_request().code, "Invalid request: malformed");
        return reply_or_skip(
            create_marshalled_reply(&req.jsonrpc, &req.id, None, Some(&json_err)),
            MARSHAL_REPLY_FAILED,
        );
    }

    if matches!(req.id, RpcId::Null) {
        return if authenticated {
            WsOutcome::Skip
        } else {
            WsOutcome::Disconnect
        };
    }

    let param_refs: Vec<&str> = req.params.iter().map(|s| s.as_str()).collect();
    let parsed = parse_cmd(
        &server.registry,
        &req.jsonrpc,
        &req.method,
        &param_refs,
        &req.id,
    );
    if let Some(err) = parsed.err {
        if !authenticated {
            return WsOutcome::Disconnect;
        }
        return reply_or_skip(
            create_marshalled_reply(&req.jsonrpc, &req.id, None, Some(&err)),
            MARSHAL_REPLY_FAILED,
        );
    }

    log_received_command(&req.method, remote_addr);

    let is_auth_cmd = req.method == "authenticate";
    match (authenticated, is_auth_cmd) {
        (true, true) => return already_authenticated(remote_addr),
        (false, false) => return unauthenticated_message(),
        (false, true) => {
            return authenticate(
                server,
                state,
                remote_addr,
                &req.jsonrpc,
                parsed.params.as_ref(),
                &req.id,
            );
        }
        (true, false) => {}
    }

    // Unlike the single arm, this one passes the request's version.
    if !is_admin && !RPC_LIMITED.contains(&req.method.as_str()) {
        let json_err = RPCError::new(
            err_rpc_invalid_params().code,
            "limited user not authorized for this method",
        );
        return reply_or_skip(
            create_marshalled_reply(&req.jsonrpc, &req.id, None, Some(&json_err)),
            MARSHAL_LIMITED_REPLY_FAILED,
        );
    }

    // Unlike every marshal failure above, this one is not a `continue`
    // but a `return` out of `inHandler` (`rpcwebsocket.go:1753-1758`).
    dispatch_ws_command(server, state, &req, parsed.params, WsOutcome::StopReading)
}

/// Handle the `authenticate` command: verify the credentials, mark the
/// client authenticated, and answer success — or disconnect on bad or
/// missing credentials (dcrd's `authenticate` case).
fn authenticate(
    server: &Arc<Server<NodeRpcChain>>,
    state: &Arc<Mutex<WsClient>>,
    remote_addr: &str,
    jsonrpc: &str,
    params: Option<&dcroxide_dcrjson::GoValue>,
    id: &RpcId,
) -> WsOutcome {
    // The command was parsed by the caller, which is where dcrd parses
    // it too: `inHandler` runs `parseCmd` before the authenticate switch
    // and hands the switch the parsed params.
    let Some(dcroxide_dcrjson::GoValue::Struct(fields)) = params else {
        return WsOutcome::Disconnect;
    };
    let username = struct_string(fields, 0);
    let passphrase = struct_string(fields, 1);
    // A failed check is logged by `check_auth_user_pass` itself, with
    // the client's address, as dcrd's `checkAuthMAC` does.
    let (authed, is_admin) = server.check_auth_user_pass(&username, &passphrase, remote_addr);
    if !authed {
        return WsOutcome::Disconnect;
    }
    {
        let mut wsc = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        wsc.authenticated = true;
        wsc.is_admin = is_admin;
    }
    reply_or_skip(
        create_marshalled_reply(jsonrpc, id, None, None),
        "Failed to marshal authenticate reply",
    )
}

/// The string value of a struct field, or empty when absent.
fn struct_string(fields: &[dcroxide_dcrjson::GoValue], index: usize) -> String {
    match fields.get(index) {
        Some(dcroxide_dcrjson::GoValue::String(s)) => s.clone(),
        _ => String::new(),
    }
}

/// Turn a marshalled reply into an outcome, dropping the reply when
/// marshalling fails.  dcrd logs each such failure at error level before
/// dropping it, under the text its arm uses (`failure`).
fn reply_or_skip(reply: Result<String, String>, failure: &str) -> WsOutcome {
    match reply {
        Ok(reply) => WsOutcome::Reply(reply),
        Err(e) => {
            log_marshal_failure(failure, &e);
            WsOutcome::Skip
        }
    }
}

/// Whether a `Sec-WebSocket-Key` is the base64 of exactly 16 bytes
/// (gorilla's key check): 24 characters, the last two padding.
fn valid_ws_key(key: &str) -> bool {
    key.len() == 24
        && key.ends_with("==")
        && key[..22]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// Answer a rejected upgrade the way gorilla's `returnError` does
/// (`server.go:83-93`): the version hint, then `http.Error` with the
/// status text as the message -- so text/plain, the sniffing opt-out,
/// and the trailing newline `Fprintln` adds.  The reason gorilla builds
/// goes into the error it returns to the caller, never into the
/// response, and dcrd only logs it (`rpcserver.go:6010-6015`).
fn write_handshake_error<S: Write>(
    stream: &mut S,
    status: &str,
    body: &str,
) -> std::io::Result<()> {
    let body = format!("{body}\n");
    let header = format!(
        "HTTP/1.1 {status}\r\nSec-Websocket-Version: 13\r\nContent-Type: text/plain; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nDate: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        crate::rpcrun::http_date(),
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

/// Forwards accepted treasury spends from the transaction pool to the
/// websocket notification manager (dcrd's mempool `OnTSpendReceived`
/// firing `s.rpcServer.NotifyTSpend`, `server.go:4097-4101`).
pub struct NodeTSpendReceiver {
    ntfn: NodeNtfnMgr,
}

impl NodeTSpendReceiver {
    /// A receiver feeding the given notification manager.
    pub fn new(ntfn: NodeNtfnMgr) -> NodeTSpendReceiver {
        NodeTSpendReceiver { ntfn }
    }
}

impl dcroxide_mempool::TSpendReceiver for NodeTSpendReceiver {
    fn tspend_received(&mut self, tspend: &MsgTx) {
        self.ntfn.notify_tspend(tspend.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whoever holds the stream drains the queue, so two drainers can
    /// never reorder output.
    #[test]
    fn a_drain_takes_everything_in_order() {
        let queue = OutboundQueue::default();
        queue.push_reply("first".to_string());
        queue.push_reply("second".to_string());
        assert_eq!(
            queue.take_all_now(),
            vec!["first".to_string(), "second".to_string()],
            "queue order is the wire order"
        );
        assert!(
            queue.take_all_now().is_empty(),
            "a second drain finds nothing"
        );
    }

    /// dcrd's `notificationQueueHandler`: only one notification is ever
    /// with the writer, so a reply overtakes the backlog instead of
    /// queueing behind all of it.
    #[test]
    fn a_reply_overtakes_a_notification_backlog() {
        let queue = OutboundQueue::default();
        for i in 0..5 {
            queue.push_notification(format!("ntfn{i}"));
        }
        queue.push_reply("reply".to_string());

        // One notification went to the writer; the other four are held,
        // so the reply is second out rather than sixth.
        assert_eq!(
            queue.take_all_now(),
            vec!["ntfn0".to_string(), "reply".to_string()],
            "a reply waits behind one notification, never behind the backlog"
        );
    }

    /// And the backlog still drains, one per written batch, in order:
    /// the next notification is handed over only once the one before it
    /// has been written.
    #[test]
    fn held_notifications_are_promoted_as_each_is_written() {
        let queue = OutboundQueue::default();
        for i in 0..3 {
            queue.push_notification(format!("ntfn{i}"));
        }
        for i in 0..3 {
            assert_eq!(
                queue.take_all_now(),
                vec![format!("ntfn{i}")],
                "one notification per batch, oldest first"
            );
            assert!(
                queue.take_all_now().is_empty(),
                "nothing more until the batch is written"
            );
            queue.batch_written();
        }
        assert!(
            queue.take_all_now().is_empty(),
            "and then the backlog is empty"
        );
        // The throttle resets, so a later notification is not held back.
        queue.push_notification("later".to_string());
        assert_eq!(queue.take_all_now(), vec!["later".to_string()]);
    }

    /// dcrd promotes the next notification when `outHandler` reports the
    /// last one written, so a reply queued while that write was under way
    /// is already on `sendChan` ahead of it.  Promoting as the batch was
    /// taken put the reply second.
    #[test]
    fn a_reply_queued_during_a_write_goes_ahead_of_the_next_notification() {
        let queue = OutboundQueue::default();
        queue.push_notification("ntfn0".to_string());
        queue.push_notification("ntfn1".to_string());
        assert_eq!(queue.take_all_now(), vec!["ntfn0".to_string()]);
        // The reply arrives while ntfn0 is being written.
        queue.push_reply("reply".to_string());
        queue.batch_written();
        assert_eq!(
            queue.take_all_now(),
            vec!["reply".to_string(), "ntfn1".to_string()]
        );
    }

    /// A stream that serves `input` and then an idle read, and records
    /// what is written to it where the test can still see it once the
    /// stream is gone.
    #[derive(Default)]
    struct ScriptedStream {
        input: std::io::Cursor<Vec<u8>>,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl Read for ScriptedStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.input.read(buf)? {
                0 => Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
                n => Ok(n),
            }
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.lock().expect("written").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The payloads of the short unmasked text frames in `wire`.
    fn text_frames(wire: &[u8]) -> Vec<String> {
        let mut frames = Vec::new();
        let mut rest = wire;
        while let [first, second, tail @ ..] = rest {
            assert_eq!(*first, 0x81, "a final text frame");
            let len = usize::from(*second);
            assert!(len < 126, "short payloads only");
            frames.push(String::from_utf8(tail[..len].to_vec()).expect("utf8"));
            rest = &tail[len..];
        }
        frames
    }

    /// An RPC server over a genesis testnet chain with the credentials
    /// user:pass, as the websocket integration tests build it.
    fn genesis_rpc_server() -> (tempfile::TempDir, Arc<Server<NodeRpcChain>>) {
        use dcroxide_rpc::server::Config;

        let params = dcroxide_chaincfg::testnet3_params();
        let dir = tempfile::tempdir().expect("temp dir");
        let opts = dcroxide_database::Options::new(dir.path().join("blocks"), params.net.0);
        let db = dcroxide_database::Database::create(&opts).expect("create database");
        let chain = Arc::new(Mutex::new(
            dcroxide_blockchain::process::Chain::open(db, &params, params.assume_valid, false, 0)
                .expect("open chain"),
        ));
        let tx_pool = crate::txmempool::new_shared_tx_pool(
            Arc::clone(&chain),
            &params,
            false,
            100,
            10000,
            false,
            false,
        );
        let sync_manager = Arc::new(Mutex::new(crate::sync::new_sync_manager(
            Arc::clone(&chain),
            &params,
            false,
            8,
            1000,
            Arc::clone(&tx_pool),
            crate::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone(), &tx_pool),
        )));
        let server = Server::new(Config {
            chain: NodeRpcChain::new(chain, params.clone()),
            chain_params: params.clone(),
            subsidy_cache: Mutex::new(dcroxide_standalone::SubsidyCache::new(params.clone())),
            min_relay_tx_fee: 10000,
            max_protocol_version: dcroxide_wire::PROTOCOL_VERSION,
            sync_mgr: Box::new(crate::rpcrun::NodeRpcSyncManager::new(
                sync_manager,
                Arc::clone(&tx_pool),
            )),
            conn_mgr: Box::new(crate::rpcrun::NodeRpcConnManager::new(
                crate::runtime::ConnectedPeers::new(),
                Arc::new(crate::transport::NetByteTotals::new()),
            )),
            client_cert_auth: false,
            tx_mempooler: Box::new(crate::txmempool::NodeRpcTxMempooler::new(Arc::clone(
                &tx_pool,
            ))),
            clock: Box::new(crate::rpcrun::SystemClock),
            interfaces: Box::new(dcroxide_rpc::helpers::NoInterfaces),
            rand_u64: Box::new(|| 7),
            tx_indexer: None,
            db: Box::new(()),
            filterer_v2: Box::new(()),
            exists_addresser: None,
            log_manager: Box::new(()),
            fee_estimator: Box::new(()),
            block_templater: None,
            sanity_checker: Box::new(()),
            time_source: Box::new(crate::rpcrun::SystemTimeSource),
            proxy: String::new(),
            test_net: true,
            runtime_version: String::new(),
            cpu_miner: Box::new(()),
            mix_pooler: Box::new(()),
            profiler_mgr: Box::new(()),
            addr_manager: Box::new(()),
            mining_addrs: Vec::new(),
            user_agent_version: "0.1.0".to_string(),
            net_info: Vec::new(),
            services: 0,
            request_shutdown: Box::new(|| {}),
            allow_unsynced_mining: false,
            rpc_user: "user".to_string(),
            rpc_pass: "pass".to_string(),
            rpc_limit_user: "limit".to_string(),
            rpc_limit_pass: "limitpass".to_string(),
        });
        (dir, Arc::new(server))
    }

    /// A masked client text frame carrying `payload`.
    fn client_frame(payload: &[u8]) -> Vec<u8> {
        assert!(payload.len() < 126, "short payloads only");
        let mask = [0x12u8, 0x34, 0x56, 0x78];
        let mut frame = vec![0x81, 0x80 | payload.len() as u8];
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i & 3]));
        frame
    }

    /// The OS refusing the writer thread drops the connection -- nothing
    /// read, nothing written -- and frees its websocket slot, instead of
    /// `Scope::spawn`'s panic, which the release profile turns into an
    /// abort of the whole node.  The upgrade needs no credentials, so any
    /// client that reaches the RPC port could otherwise take the node
    /// down once the host is at its task limit.
    #[test]
    fn a_refused_writer_drops_the_connection_and_frees_the_slot() {
        let (_dir, server) = genesis_rpc_server();
        let ntfn = NodeNtfnMgr::with_max_websockets(1);
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stream = ScriptedStream {
            input: std::io::Cursor::new(client_frame(
                br#"{"jsonrpc":"1.0","method":"session","params":[],"id":1}"#,
            )),
            written: Arc::default(),
        };
        let written = Arc::clone(&stream.written);
        // Ends a connection that was served after all, so a regression
        // fails the assertions below rather than hanging the test.
        {
            let written = Arc::clone(&written);
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while written.lock().expect("written").is_empty()
                    && std::time::Instant::now() < deadline
                {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
            });
        }

        crate::runtime::REFUSE_CONN_THREADS.with(|refuse| refuse.set(true));
        serve_upgraded(stream, "127.0.0.1:1", true, true, &server, &ntfn, &shutdown);
        crate::runtime::REFUSE_CONN_THREADS.with(|refuse| refuse.set(false));

        assert!(
            written.lock().expect("written").is_empty(),
            "the refused connection is dropped unserved"
        );
        assert_eq!(ntfn.num_clients(), 0, "its websocket slot is free again");
        assert!(
            ntfn.add_client(9, Arc::new(Mutex::new(WsClient::new(9))), Arc::default()),
            "and another client can take it"
        );
    }

    /// The same connection with its writer running is served: the
    /// request is read and answered before the idle stream ends it at
    /// shutdown.  This is what the refusal above must not do.
    #[test]
    fn a_connection_with_its_writer_is_served() {
        let (_dir, server) = genesis_rpc_server();
        let ntfn = NodeNtfnMgr::with_max_websockets(1);
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stream = ScriptedStream {
            input: std::io::Cursor::new(client_frame(
                br#"{"jsonrpc":"1.0","method":"session","params":[],"id":1}"#,
            )),
            written: Arc::default(),
        };
        let written = Arc::clone(&stream.written);
        let stopper = {
            let written = Arc::clone(&written);
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while written.lock().expect("written").is_empty()
                    && std::time::Instant::now() < deadline
                {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
            })
        };
        serve_upgraded(stream, "127.0.0.1:1", true, true, &server, &ntfn, &shutdown);
        stopper.join().expect("stopper");
        let frames = text_frames_any(&written.lock().expect("written"));
        assert_eq!(frames.len(), 1, "one reply");
        assert!(frames[0].contains("sessionid"), "{}", frames[0]);
        assert_eq!(ntfn.num_clients(), 0, "the slot is released on exit");
    }

    /// The payloads of the unmasked text frames in `wire`, of any length
    /// up to 64 KiB.
    fn text_frames_any(wire: &[u8]) -> Vec<String> {
        let mut frames = Vec::new();
        let mut rest = wire;
        while let [first, second, tail @ ..] = rest {
            assert_eq!(*first, 0x81, "a final text frame");
            let (len, tail) = match *second {
                126 => (
                    usize::from(u16::from_be_bytes([tail[0], tail[1]])),
                    &tail[2..],
                ),
                n => (usize::from(n), tail),
            };
            frames.push(String::from_utf8(tail[..len].to_vec()).expect("utf8"));
            rest = &tail[len..];
        }
        frames
    }

    /// The reader holds the stream across the read that follows its
    /// drain, so it must write the whole backlog first.  Draining one
    /// batch per read delivered one notification per read interval to a
    /// client that only listens: twenty a second, however fast the
    /// socket.
    ///
    /// The budget is unbounded here so the one-pass assertion does not
    /// depend on the test thread being scheduled; the budget's own stop
    /// is pinned by `the_reader_drain_stops_when_its_budget_is_spent`.
    #[test]
    fn the_reader_drains_a_whole_backlog_before_it_reads() {
        let queue = OutboundQueue::default();
        for i in 0..100 {
            queue.push_notification(format!("ntfn{i}"));
        }
        queue.push_reply("reply".to_string());
        let stream = ScriptedStream::default();
        let written = Arc::clone(&stream.written);
        let mut conn = WsConn::new(stream);
        drain_before_read(&mut conn, &queue, std::time::Duration::MAX).expect("drain");
        let frames = text_frames(&written.lock().expect("written"));
        assert_eq!(frames.len(), 101, "the whole backlog in one pass");
        // A reply still waits behind only the notification ahead of it.
        assert_eq!(frames[0], "ntfn0");
        assert_eq!(frames[1], "reply");
        for (i, frame) in frames[2..].iter().enumerate() {
            assert_eq!(*frame, format!("ntfn{}", i + 1), "oldest first");
        }
        assert!(queue.take_all_now().is_empty());
    }

    /// A spent budget ends the drain after the batch in hand, so the
    /// reader gets back to reading requests; the rest stays queued, in
    /// order, for the writer.  A zero budget is spent as soon as the
    /// first batch is written, which makes the stop deterministic.
    #[test]
    fn the_reader_drain_stops_when_its_budget_is_spent() {
        let queue = OutboundQueue::default();
        for i in 0..3 {
            queue.push_notification(format!("ntfn{i}"));
        }
        let stream = ScriptedStream::default();
        let written = Arc::clone(&stream.written);
        let mut conn = WsConn::new(stream);
        drain_before_read(&mut conn, &queue, std::time::Duration::ZERO).expect("drain");
        assert_eq!(
            text_frames(&written.lock().expect("written")),
            ["ntfn0"],
            "one batch, then back to reading"
        );
        assert_eq!(queue.take_all_now(), ["ntfn1"], "the next one was promoted");
    }

    /// The writer parks until there is something to write.
    #[test]
    fn the_writer_waits_for_work() {
        let queue = Arc::new(OutboundQueue::default());
        let writer = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.wait_for_items())
        };
        queue.push_reply("wake up".to_string());
        assert!(writer.join().expect("writer"), "a push wakes the writer");
    }

    /// Closing wakes a parked writer and tells it to stop, so the
    /// scoped thread is always joinable.
    #[test]
    fn closing_the_queue_stops_a_parked_writer() {
        let queue = Arc::new(OutboundQueue::default());
        let writer = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.wait_for_items())
        };
        queue.close();
        assert!(
            !writer.join().expect("writer"),
            "a closed queue is the writer's signal to return"
        );
    }

    /// A close DISCARDS what is still queued, held notifications
    /// included, as dcrd's `Disconnect` does by closing the socket out
    /// from under `sendChan`.
    #[test]
    fn closing_discards_what_is_still_queued() {
        let queue = OutboundQueue::default();
        queue.push_reply("undelivered".to_string());
        queue.push_notification("also undelivered".to_string());
        queue.push_notification("held".to_string());
        queue.close();
        assert!(
            queue.take_all_now().is_empty(),
            "a closed queue hands the writer nothing further to write"
        );
        assert!(!queue.wait_for_items(), "and stops it");
    }

    #[test]
    fn removing_a_client_clears_every_subscription_except_mix() {
        let mgr = NodeNtfnMgr::new();
        mgr.add_client(7, Arc::new(Mutex::new(WsClient::new(7))), Arc::default());
        {
            let m = mgr.clone();
            m.register_block_updates(7);
            m.register_work_updates(7);
            m.register_tspend_updates(7);
            m.register_winning_tickets(7);
            m.register_new_tickets(7);
            m.register_new_mempool_txs_updates(7);
            m.register_mix_messages(7);
        }
        mgr.remove_client(7);

        let subs = mgr.inner.lock().expect("subs");
        assert!(subs.blocks.is_empty());
        assert!(subs.work.is_empty());
        assert!(subs.tspends.is_empty());
        assert!(subs.winning_tickets.is_empty());
        assert!(subs.new_tickets.is_empty());
        assert!(subs.mempool_txs.is_empty());
        // dcrd's unregister-client case skips the mix map; the stale
        // entry stays, kept bug-for-bug.
        assert!(subs.mix_messages.contains(&7));
        assert!(mgr.clients.lock().expect("clients").is_empty());
    }

    /// The concurrent-websocket cap admits up to the limit and refuses
    /// the next client (dcrd rejecting when `NumClients()+1 >
    /// RPCMaxWebsockets`), and a cap of zero refuses every client.
    #[test]
    fn add_client_enforces_the_websocket_cap() {
        let mgr = NodeNtfnMgr::with_max_websockets(2);
        assert!(mgr.add_client(1, Arc::new(Mutex::new(WsClient::new(1))), Arc::default()));
        assert!(mgr.add_client(2, Arc::new(Mutex::new(WsClient::new(2))), Arc::default()));
        assert!(
            !mgr.add_client(3, Arc::new(Mutex::new(WsClient::new(3))), Arc::default()),
            "the third client is over the cap of two"
        );
        assert_eq!(mgr.clients.lock().expect("clients").len(), 2);

        // A freed slot admits a replacement.
        mgr.remove_client(1);
        assert!(mgr.add_client(4, Arc::new(Mutex::new(WsClient::new(4))), Arc::default()));

        // A zero cap refuses every client.
        let none = NodeNtfnMgr::with_max_websockets(0);
        assert!(
            !none.add_client(1, Arc::new(Mutex::new(WsClient::new(1))), Arc::default()),
            "a zero cap refuses every client"
        );
    }

    /// A panic unwinding through the serving loop must still release
    /// the client's registration.  dcrd unregisters from a `defer`; a
    /// plain statement after the loop is skipped by an unwind, which
    /// would strand the session in the registry and in every
    /// subscription set for the life of the process and burn a
    /// websocket slot no client could reclaim.
    #[test]
    fn an_unwind_past_the_serving_loop_releases_the_registration() {
        // A cap of one makes a leaked slot immediately visible.
        let mgr = NodeNtfnMgr::with_max_websockets(1);
        let outbound: Arc<OutboundQueue> = Arc::default();

        let unwound = catch_unwind(AssertUnwindSafe(|| {
            let _registration = ClientRegistration::register(
                &mgr,
                7,
                Arc::new(Mutex::new(WsClient::new(7))),
                Arc::clone(&outbound),
            )
            .expect("the first client fits the cap");
            let subscriber = mgr.clone();
            subscriber.register_block_updates(7);
            subscriber.register_new_mempool_txs_updates(7);
            assert_eq!(mgr.num_clients(), 1);
            panic!("a request handler unwound out of the serving loop");
        }));
        assert!(unwound.is_err(), "the panic must have been caught here");

        // The registry and the subscription sets are clear...
        assert_eq!(
            mgr.num_clients(),
            0,
            "the unwind stranded the client in the registry"
        );
        {
            let subs = mgr.inner.lock().expect("subs");
            assert!(subs.blocks.is_empty(), "a stranded block subscription");
            assert!(
                subs.mempool_txs.is_empty(),
                "a stranded mempool subscription"
            );
        }

        // ...and the slot is reusable.
        let replacement = ClientRegistration::register(
            &mgr,
            8,
            Arc::new(Mutex::new(WsClient::new(8))),
            Arc::default(),
        )
        .expect("the freed slot admits a replacement");
        assert_eq!(mgr.num_clients(), 1);

        // A clean exit releases it just the same.
        drop(replacement);
        assert_eq!(mgr.num_clients(), 0);
    }

    /// A client refused by the cap gets no guard, so nothing is
    /// unregistered on its behalf and the admitted client keeps its
    /// registration.
    #[test]
    fn a_refused_client_does_not_unregister_the_admitted_one() {
        let mgr = NodeNtfnMgr::with_max_websockets(1);
        let admitted = ClientRegistration::register(
            &mgr,
            1,
            Arc::new(Mutex::new(WsClient::new(1))),
            Arc::default(),
        )
        .expect("the first client fits the cap");
        assert!(
            ClientRegistration::register(
                &mgr,
                2,
                Arc::new(Mutex::new(WsClient::new(2))),
                Arc::default(),
            )
            .is_none(),
            "the second client is over the cap"
        );
        assert_eq!(mgr.num_clients(), 1, "the admitted client is untouched");
        drop(admitted);
        assert_eq!(mgr.num_clients(), 0);
    }
}
