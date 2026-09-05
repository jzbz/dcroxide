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
use std::sync::{Arc, Mutex, mpsc};

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

/// One connected client: its shared request state (the ported
/// `WsClient` with its transaction filter) and the outbound
/// notification queue its serving loop drains (dcrd's per-client
/// pending-notification list).
#[derive(Clone)]
struct ClientHandle {
    state: Arc<Mutex<WsClient>>,
    outbound: Arc<Mutex<VecDeque<String>>>,
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

    /// Queue a block-connected event (dcrd
    /// `Server.NotifyBlockConnected`).
    pub fn notify_block_connected(&self, block: Arc<MsgBlock>) {
        let _ = self.events.send(NtfnEvent::BlockConnected(block));
    }

    /// Queue a block-disconnected event (dcrd
    /// `Server.NotifyBlockDisconnected`).
    pub fn notify_block_disconnected(&self, block: Arc<MsgBlock>) {
        let _ = self.events.send(NtfnEvent::BlockDisconnected(block));
    }

    /// Queue a new-template work event (dcrd's template subscription
    /// forwarding into `NotifyWork`).
    pub fn notify_work(&self, template_block: MsgBlock, reason: TemplateUpdateReason) {
        let _ = self
            .events
            .send(NtfnEvent::Work(Box::new(template_block), reason));
    }

    /// Queue a treasury-spend event (dcrd `Server.NotifyTSpend`).
    pub fn notify_tspend(&self, tspend: MsgTx) {
        let _ = self.events.send(NtfnEvent::TSpend(Box::new(tspend)));
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
        let _ = self.events.send(NtfnEvent::Reorganization {
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
        let _ = self.events.send(NtfnEvent::NewTickets {
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
            let _ = self.events.send(NtfnEvent::MempoolTx(Box::new(tx), tree));
        }
    }

    /// Queue mixing-message events (dcrd `Server.NotifyMixMessages`).
    pub fn notify_mix_messages(&self, msgs: Vec<Message>) {
        for msg in msgs {
            let _ = self.events.send(NtfnEvent::MixMessage(Box::new(msg)));
        }
    }

    /// Register a connected client, returning `false` without inserting
    /// when the concurrent websocket cap is reached (dcrd rejecting when
    /// `NumClients()+1 > RPCMaxWebsockets`).  The check and insert happen
    /// under the same lock, so concurrent connection threads cannot race
    /// past the cap.  `len() >= max` is `len()+1 > max` without the
    /// overflow-prone increment.
    fn add_client(
        &self,
        session_id: u64,
        state: Arc<Mutex<WsClient>>,
        outbound: Arc<Mutex<VecDeque<String>>>,
    ) -> bool {
        let mut clients = self.clients.lock().expect("ws clients");
        if clients.len() >= self.max_websockets {
            return false;
        }
        clients.insert(session_id, ClientHandle { state, outbound });
        true
    }

    /// Drop a disconnected client: the registry entry and every
    /// subscription EXCEPT mix messages — dcrd's unregister-client
    /// case skips the mix map (kept bug-for-bug; the stale entry is
    /// harmless because delivery only reaches registered clients).
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
        self.clients.lock().expect("ws clients").remove(&session_id);
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
        outbound: Arc<Mutex<VecDeque<String>>>,
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
        let _ = self.events.send(NtfnEvent::WinningTickets {
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
        deliver_one(&event, &server, &subs, &clients);
    }
}

/// Fan one event out: pick the subscriber set the event notifies
/// (dcrd's per-kind client maps), run the ported builder against those
/// clients, and queue the marshalled JSON on each target's outbound
/// queue.  The builder needs no server-wide lock — dcrd's notification
/// manager takes none either — so a handler thread serving a long
/// request no longer blocks notification construction.
fn deliver_one(
    event: &NtfnEvent,
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
        let targets = match event {
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
        NtfnEvent::BlockConnected(block) => build(server, &targets, |srv, refs| {
            rpcws::notify_block_connected(srv, refs, block)
        }),
        NtfnEvent::BlockDisconnected(block) => build(server, &targets, |srv, refs| {
            rpcws::notify_block_disconnected(srv, refs, block)
        }),
        NtfnEvent::Work(template_block, reason) => build(server, &targets, |srv, refs| {
            rpcws::notify_work(srv, refs, template_block, *reason)
        }),
        NtfnEvent::TSpend(tspend) => build(server, &targets, |srv, refs| {
            rpcws::notify_tspend(srv, refs, tspend)
        }),
        NtfnEvent::Reorganization {
            old_hash,
            old_height,
            new_hash,
            new_height,
        } => build(server, &targets, |srv, refs| {
            rpcws::notify_reorganization(srv, refs, old_hash, *old_height, new_hash, *new_height)
        }),
        NtfnEvent::WinningTickets {
            block_hash,
            block_height,
            tickets,
        } => build(server, &targets, |srv, refs| {
            rpcws::notify_winning_tickets_ntfn(srv, refs, block_hash, *block_height, tickets)
        }),
        NtfnEvent::NewTickets {
            hash,
            height,
            stake_difficulty,
            tickets_new,
        } => build(server, &targets, |srv, refs| {
            rpcws::notify_new_tickets(srv, refs, hash, *height, *stake_difficulty, tickets_new)
        }),
        NtfnEvent::MempoolTx(tx, tree) => {
            // dcrd notifies the txaccepted subscribers only when some
            // exist, then always runs the relevant-tx pass over every
            // client.
            let mut out = if targets.is_empty() {
                Vec::new()
            } else {
                build(server, &targets, |srv, refs| {
                    rpcws::notify_for_new_tx(srv, refs, tx)
                })
            };
            out.extend(build(server, &everyone, |srv, refs| {
                rpcws::notify_relevant_tx_accepted(srv, refs, tx, *tree)
            }));
            out
        }
        NtfnEvent::MixMessage(msg) => build(server, &targets, |srv, refs| {
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
            handle
                .outbound
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push_back(json);
        }
    }
}

/// Lock the given clients' shared state (with the server already
/// locked, preserving the server-then-client order every path uses)
/// and run a ported builder over them.
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
/// loops).  `pre_authenticated` reflects a Basic-auth header accepted
/// before the upgrade; an unauthenticated client must send
/// `authenticate` before any other command.  The client registers with
/// the notification manager for delivery, and its outbound queue is
/// drained whenever the connection goes idle or between requests.
pub fn serve_websocket<S: Read + Write>(
    mut stream: S,
    head: &crate::rpcrun::HttpHead,
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
    if !head.method.eq_ignore_ascii_case("GET") {
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

    let session_id = new_session_id();
    let state = Arc::new(Mutex::new({
        let mut wsc = WsClient::new(session_id);
        wsc.authenticated = pre_authenticated;
        wsc.is_admin = is_admin;
        wsc
    }));
    let outbound: Arc<Mutex<VecDeque<String>>> = Arc::default();
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
    let mut conn = WsConn::new(stream);

    loop {
        // A server shutdown ends the connection like dcrd's
        // `close(s.quit)` unblocking every websocket loop; the poll
        // read below wakes this check within its interval.
        if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        // Drain queued notifications before waiting for the next
        // request (the poll-loop translation of dcrd's out handler).
        let mut write_failed = false;
        loop {
            let next = {
                outbound
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .pop_front()
            };
            let Some(json) = next else { break };
            if conn.write_text(json.as_bytes()).is_err() {
                write_failed = true;
                break;
            }
        }
        if write_failed {
            break;
        }

        let authenticated = client_flags(&state).0;
        let read_limit = if authenticated {
            READ_LIMIT_AUTHENTICATED
        } else {
            READ_LIMIT_UNAUTHENTICATED
        };
        let message = match conn.read_message(read_limit) {
            Ok(WsIn::Text(payload)) => payload,
            // An idle read wakes the loop to drain notifications.
            Ok(WsIn::Idle) => continue,
            // A close frame, a clean disconnect, or a protocol error
            // ends the connection.
            Ok(WsIn::Close) | Err(_) => break,
        };
        // A non-UTF-8 (e.g. binary) frame cannot be JSON; dcrd feeds the
        // raw bytes to json.Unmarshal, so an authenticated client gets a
        // parse-error reply and an unauthenticated one is disconnected,
        // rather than the frame being dropped silently.
        let outcome = match String::from_utf8(message) {
            Ok(body) => {
                // dcrd services a websocket command with a context, the
                // same one the standard HTTP handlers get: `serviceRequest`
                // falls through to `standardCmdResult(ctx, r)` for any
                // method not in its websocket-only table, and getwork is
                // not in that table (`rpcwebsocket.go:1807-1819`).
                //
                // That context is the UPGRADE request's
                // (`rpcserver.go:6041` passing `r.Context()`), which
                // descends from the server's through `BaseContext`
                // (`rpcserver.go:5921-5927`), so shutdown cancels it.
                //
                // dcrd also reaches it on a client hangup, but only where
                // it dispatches concurrently: a non-batched command runs
                // in a goroutine (`rpcwebsocket.go:1550`) that `Run`'s
                // `wg.Add(3)` does not cover (`:1998-2011`), so it
                // outlives the client teardown and is still selecting on
                // the context when `conn.serve` fires `w.cancelCtx()`
                // after `ServeHTTP` returns -- unconditionally, before
                // the `c.hijacked()` check (`net/http/server.go:2137-2140`).
                //
                // This loop dispatches synchronously, so while a request
                // runs nothing is reading and a hangup cannot be noticed
                // at all.  That is dcrd's own behaviour on the two arms
                // where it also stops reading: a batched request, which
                // it services inline (`rpcwebsocket.go:1748`), and any
                // request once `serviceRequestSem` is exhausted, since
                // that is acquired before the spawn (`:1549`).  So the
                // shutdown flag is the whole of what this token can
                // carry here; see PARITY for what closing the rest would
                // take.
                let _cancel = dcroxide_rpc::worksem::scope_request_cancel(Arc::clone(shutdown));
                handle_ws_request(server, &state, &body)
            }
            Err(_) => parse_error_outcome(authenticated, "invalid UTF-8"),
        };
        match outcome {
            WsOutcome::Reply(reply) => {
                if conn.write_text(reply.as_bytes()).is_err() {
                    break;
                }
            }
            WsOutcome::Skip => {}
            WsOutcome::Disconnect => break,
        }
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
}

/// The outcome for a request that could not be parsed: dcrd disconnects
/// an unauthenticated client on any parse failure and hands an
/// authenticated one an RPC parse error (dcrd `inHandler`).  Shared by
/// the JSON parse path and the non-UTF-8 frame path.
fn parse_error_outcome(authenticated: bool, err_text: &str) -> WsOutcome {
    if !authenticated {
        return WsOutcome::Disconnect;
    }
    let json_err = RPCError::new(
        err_rpc_parse().code,
        &format!("Failed to parse request: {err_text}"),
    );
    reply_or_skip(create_marshalled_reply(
        "1.0",
        &RpcId::Null,
        None,
        Some(&json_err),
    ))
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
    reply_or_skip(create_marshalled_reply(
        "1.0",
        &RpcId::Null,
        None,
        Some(&json_err),
    ))
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
    body: &str,
) -> WsOutcome {
    catch_unwind(AssertUnwindSafe(|| {
        handle_ws_request_inner(server, state, body)
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
    body: &str,
) -> WsOutcome {
    // dcrd tests the raw first byte (`bytes.HasPrefix(msg,
    // batchedRequestPrefix)`), so a leading space makes an array a
    // single request that then fails to unmarshal, not a batch.
    if body.as_bytes().first() == Some(&b'[') {
        return handle_ws_batch(server, state, body);
    }
    handle_ws_single(server, state, body)
}

/// One non-batched websocket request (dcrd `inHandler`'s
/// `!batchedRequest` arm).
fn handle_ws_single(
    server: &Arc<Server<NodeRpcChain>>,
    state: &Arc<Mutex<WsClient>>,
    body: &str,
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
        return reply_or_skip(create_marshalled_reply(
            &req.jsonrpc,
            &req.id,
            None,
            Some(&json_err),
        ));
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
        return reply_or_skip(create_marshalled_reply(
            &req.jsonrpc,
            &req.id,
            None,
            Some(&err),
        ));
    }

    // The authenticate state machine, keyed on whether the parsed
    // command is the authenticate one.
    let is_auth_cmd = req.method == "authenticate";
    match (authenticated, is_auth_cmd) {
        (true, true) => return WsOutcome::Disconnect,
        (false, false) => return WsOutcome::Disconnect,
        (false, true) => {
            return authenticate(server, state, &req.jsonrpc, parsed.params.as_ref(), &req.id);
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
        return reply_or_skip(create_marshalled_reply("", &req.id, None, Some(&json_err)));
    }

    dispatch_ws_command(server, state, &req, parsed.params)
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
fn dispatch_ws_command(
    server: &Arc<Server<NodeRpcChain>>,
    state: &Arc<Mutex<WsClient>>,
    req: &dcroxide_rpc::http::RawRequest,
    params: Option<dcroxide_dcrjson::GoValue>,
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
        Ok(None) => WsOutcome::Skip,
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
/// connection.
fn handle_ws_batch(
    server: &Arc<Server<NodeRpcChain>>,
    state: &Arc<Mutex<WsClient>>,
    body: &str,
) -> WsOutcome {
    let (authenticated, _) = client_flags(state);
    let mut results: Vec<String> = Vec::new();
    let mut batch_size = 0usize;

    match dcroxide_dcrjson::gojson::validate(body) {
        Err(err) => {
            if !authenticated {
                return WsOutcome::Disconnect;
            }
            let json_err = RPCError::new(
                err_rpc_parse().code,
                &format!("Failed to parse request: {}", err.go_message()),
            );
            if let Ok(reply) = create_marshalled_reply("2.0", &RpcId::Null, None, Some(&json_err)) {
                results.push(reply);
            }
        }
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
                if let Ok(reply) =
                    create_marshalled_reply("2.0", &RpcId::Null, None, Some(&json_err))
                {
                    results.push(reply);
                }
            } else {
                batch_size = entries.len();
                for entry in entries {
                    match handle_ws_batch_entry(server, state, &entry) {
                        WsOutcome::Reply(reply) => results.push(reply),
                        WsOutcome::Skip => {}
                        WsOutcome::Disconnect => return WsOutcome::Disconnect,
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
            return reply_or_skip(create_marshalled_reply(
                "2.0",
                &RpcId::Null,
                None,
                Some(&json_err),
            ));
        }
    };

    // The batch arm calls an entry with no params array malformed too,
    // which the single arm does not.
    if req.method.is_empty() || !req.params_present {
        let json_err = RPCError::new(err_rpc_invalid_request().code, "Invalid request: malformed");
        return reply_or_skip(create_marshalled_reply(
            &req.jsonrpc,
            &req.id,
            None,
            Some(&json_err),
        ));
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
        return reply_or_skip(create_marshalled_reply(
            &req.jsonrpc,
            &req.id,
            None,
            Some(&err),
        ));
    }

    let is_auth_cmd = req.method == "authenticate";
    match (authenticated, is_auth_cmd) {
        (true, true) => return WsOutcome::Disconnect,
        (false, false) => return WsOutcome::Disconnect,
        (false, true) => {
            return authenticate(server, state, &req.jsonrpc, parsed.params.as_ref(), &req.id);
        }
        (true, false) => {}
    }

    // Unlike the single arm, this one passes the request's version.
    if !is_admin && !RPC_LIMITED.contains(&req.method.as_str()) {
        let json_err = RPCError::new(
            err_rpc_invalid_params().code,
            "limited user not authorized for this method",
        );
        return reply_or_skip(create_marshalled_reply(
            &req.jsonrpc,
            &req.id,
            None,
            Some(&json_err),
        ));
    }

    dispatch_ws_command(server, state, &req, parsed.params)
}

/// Handle the `authenticate` command: verify the credentials, mark the
/// client authenticated, and answer success — or disconnect on bad or
/// missing credentials (dcrd's `authenticate` case).
fn authenticate(
    server: &Arc<Server<NodeRpcChain>>,
    state: &Arc<Mutex<WsClient>>,
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
    let (authed, is_admin) = server.check_auth_user_pass(&username, &passphrase);
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
    reply_or_skip(create_marshalled_reply(jsonrpc, id, None, None))
}

/// The string value of a struct field, or empty when absent.
fn struct_string(fields: &[dcroxide_dcrjson::GoValue], index: usize) -> String {
    match fields.get(index) {
        Some(dcroxide_dcrjson::GoValue::String(s)) => s.clone(),
        _ => String::new(),
    }
}

/// Turn a marshalled reply into an outcome, dropping the reply when
/// marshalling fails (dcrd logs and drops such failures).
fn reply_or_skip(reply: Result<String, dcroxide_dcrjson::DcrjsonError>) -> WsOutcome {
    match reply {
        Ok(reply) => WsOutcome::Reply(reply),
        Err(_) => WsOutcome::Skip,
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
        let outbound: Arc<Mutex<VecDeque<String>>> = Arc::default();

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
