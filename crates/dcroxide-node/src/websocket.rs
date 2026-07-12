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
use dcroxide_dcrjson::{RPCError, RpcId, err_rpc_internal, err_rpc_invalid_params, err_rpc_parse};
use dcroxide_rpc::dispatch::{RPC_LIMITED, create_marshalled_reply, parse_cmd};
use dcroxide_rpc::http::unmarshal_request;
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
    /// A block connected to the main chain.
    BlockConnected(Box<MsgBlock>),
    /// A block disconnected from the main chain.
    BlockDisconnected(Box<MsgBlock>),
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
    pub fn start(
        &self,
        server: Arc<Mutex<Server<NodeRpcChain>>>,
    ) -> Option<std::thread::JoinHandle<()>> {
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
    pub fn notify_block_connected(&self, block: MsgBlock) {
        let _ = self.events.send(NtfnEvent::BlockConnected(Box::new(block)));
    }

    /// Queue a block-disconnected event (dcrd
    /// `Server.NotifyBlockDisconnected`).
    pub fn notify_block_disconnected(&self, block: MsgBlock) {
        let _ = self
            .events
            .send(NtfnEvent::BlockDisconnected(Box::new(block)));
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
}

impl Default for NodeNtfnMgr {
    fn default() -> NodeNtfnMgr {
        NodeNtfnMgr::new()
    }
}

impl RpcNtfnManager for NodeNtfnMgr {
    fn register_block_updates(&mut self, session_id: u64) {
        self.inner.lock().expect("subs").blocks.insert(session_id);
    }
    fn unregister_block_updates(&mut self, session_id: u64) {
        self.inner.lock().expect("subs").blocks.remove(&session_id);
    }
    fn register_work_updates(&mut self, session_id: u64) {
        self.inner.lock().expect("subs").work.insert(session_id);
    }
    fn unregister_work_updates(&mut self, session_id: u64) {
        self.inner.lock().expect("subs").work.remove(&session_id);
    }
    fn register_tspend_updates(&mut self, session_id: u64) {
        self.inner.lock().expect("subs").tspends.insert(session_id);
    }
    fn unregister_tspend_updates(&mut self, session_id: u64) {
        self.inner.lock().expect("subs").tspends.remove(&session_id);
    }
    fn register_winning_tickets(&mut self, session_id: u64) {
        self.inner
            .lock()
            .expect("subs")
            .winning_tickets
            .insert(session_id);
    }
    fn register_new_tickets(&mut self, session_id: u64) {
        self.inner
            .lock()
            .expect("subs")
            .new_tickets
            .insert(session_id);
    }
    fn register_new_mempool_txs_updates(&mut self, session_id: u64) {
        self.inner
            .lock()
            .expect("subs")
            .mempool_txs
            .insert(session_id);
    }
    fn unregister_new_mempool_txs_updates(&mut self, session_id: u64) {
        self.inner
            .lock()
            .expect("subs")
            .mempool_txs
            .remove(&session_id);
    }
    fn register_mix_messages(&mut self, session_id: u64) {
        self.inner
            .lock()
            .expect("subs")
            .mix_messages
            .insert(session_id);
    }
    fn unregister_mix_messages(&mut self, session_id: u64) {
        self.inner
            .lock()
            .expect("subs")
            .mix_messages
            .remove(&session_id);
    }

    fn notify_winning_tickets(&mut self, block_hash: &Hash, block_height: i64, tickets: &[Hash]) {
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
    server: Arc<Mutex<Server<NodeRpcChain>>>,
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
/// clients under the server lock, and queue the marshalled JSON on
/// each target's outbound queue.
fn deliver_one(
    event: &NtfnEvent,
    server: &Arc<Mutex<Server<NodeRpcChain>>>,
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

    let mut server_guard = server
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let out = match event {
        NtfnEvent::BlockConnected(block) => build(&mut server_guard, &targets, |srv, refs| {
            rpcws::notify_block_connected(srv, refs, block)
        }),
        NtfnEvent::BlockDisconnected(block) => build(&mut server_guard, &targets, |srv, refs| {
            rpcws::notify_block_disconnected(srv, refs, block)
        }),
        NtfnEvent::Work(template_block, reason) => {
            build(&mut server_guard, &targets, |srv, refs| {
                rpcws::notify_work(srv, refs, template_block, *reason)
            })
        }
        NtfnEvent::TSpend(tspend) => build(&mut server_guard, &targets, |srv, refs| {
            rpcws::notify_tspend(srv, refs, tspend)
        }),
        NtfnEvent::Reorganization {
            old_hash,
            old_height,
            new_hash,
            new_height,
        } => build(&mut server_guard, &targets, |srv, refs| {
            rpcws::notify_reorganization(srv, refs, old_hash, *old_height, new_hash, *new_height)
        }),
        NtfnEvent::WinningTickets {
            block_hash,
            block_height,
            tickets,
        } => build(&mut server_guard, &targets, |srv, refs| {
            rpcws::notify_winning_tickets_ntfn(srv, refs, block_hash, *block_height, tickets)
        }),
        NtfnEvent::NewTickets {
            hash,
            height,
            stake_difficulty,
            tickets_new,
        } => build(&mut server_guard, &targets, |srv, refs| {
            rpcws::notify_new_tickets(srv, refs, hash, *height, *stake_difficulty, tickets_new)
        }),
        NtfnEvent::MempoolTx(tx, tree) => {
            // dcrd notifies the txaccepted subscribers only when some
            // exist, then always runs the relevant-tx pass over every
            // client.
            let mut out = if targets.is_empty() {
                Vec::new()
            } else {
                build(&mut server_guard, &targets, |srv, refs| {
                    rpcws::notify_for_new_tx(srv, refs, tx)
                })
            };
            out.extend(build(&mut server_guard, &everyone, |srv, refs| {
                rpcws::notify_relevant_tx_accepted(srv, refs, tx, *tree)
            }));
            out
        }
        NtfnEvent::MixMessage(msg) => build(&mut server_guard, &targets, |srv, refs| {
            rpcws::notify_mix_message(srv, refs, msg)
        }),
        NtfnEvent::Shutdown => Vec::new(),
    };
    drop(server_guard);

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
    server: &mut Server<NodeRpcChain>,
    handles: &[(u64, ClientHandle)],
    builder: F,
) -> Vec<(u64, String)>
where
    F: FnOnce(&mut Server<NodeRpcChain>, &mut [&mut WsClient]) -> Vec<(u64, String)>,
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

/// A random session id for a websocket client (dcrd draws it from
/// `crypto/rand`).
fn new_session_id() -> u64 {
    let mut buf = [0u8; 8];
    getrandom::fill(&mut buf).expect("system random source");
    u64::from_le_bytes(buf)
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
    server: &Arc<Mutex<Server<NodeRpcChain>>>,
    ntfn: &NodeNtfnMgr,
) {
    // Validate the remaining upgrade requirements (gorilla's checks
    // after the method and header tokens): version 13 and a 16-byte
    // base64 key.
    let version_ok = head
        .sec_websocket_version
        .as_deref()
        .map(|v| v.split(',').any(|t| t.trim() == "13"))
        .unwrap_or(false);
    let key = match &head.sec_websocket_key {
        Some(key) if version_ok && valid_ws_key(key) => key.clone(),
        _ => {
            let _ = write_bad_request(&mut stream);
            return;
        }
    };

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
    // client that was never admitted.
    if !ntfn.add_client(session_id, Arc::clone(&state), Arc::clone(&outbound)) {
        return;
    }
    let mut conn = WsConn::new(stream);

    loop {
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
        let Ok(body) = String::from_utf8(message) else {
            // Non-UTF-8 payloads cannot be JSON; dcrd's JSON parse is
            // the backstop, so treat it as a parse failure.
            if !authenticated {
                break;
            }
            continue;
        };

        match handle_ws_request(server, &state, &body) {
            WsOutcome::Reply(reply) => {
                if conn.write_text(reply.as_bytes()).is_err() {
                    break;
                }
            }
            WsOutcome::Skip => {}
            WsOutcome::Disconnect => break,
        }
    }

    ntfn.remove_client(session_id);
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

/// Give one websocket request its dcrd `inHandler` handling: the
/// authenticate state machine, the limited-user gate, the
/// notification-id skip, and dispatch through the ported service
/// handler.
fn handle_ws_request(
    server: &Arc<Mutex<Server<NodeRpcChain>>>,
    state: &Arc<Mutex<WsClient>>,
    body: &str,
) -> WsOutcome {
    let (authenticated, is_admin) = client_flags(state);
    let req = match unmarshal_request(body) {
        Ok(req) => req,
        Err(err_text) => {
            // dcrd disconnects an unauthenticated client on any parse
            // failure; an authenticated one gets the parse error.
            if !authenticated {
                return WsOutcome::Disconnect;
            }
            let json_err = RPCError::new(
                err_rpc_parse().code,
                &format!("Failed to parse request: {err_text}"),
            );
            return reply_or_skip(create_marshalled_reply(
                "1.0",
                &RpcId::Null,
                None,
                Some(&json_err),
            ));
        }
    };
    let param_refs: Vec<&str> = req.params.iter().map(|s| s.as_str()).collect();

    // The authenticate command drives the auth state machine.
    if req.method == "authenticate" {
        if authenticated {
            // A second authenticate is a protocol violation.
            return WsOutcome::Disconnect;
        }
        return authenticate(server, state, &req.jsonrpc, &param_refs, &req.id);
    }

    // Every other command requires an authenticated client.
    if !authenticated {
        return WsOutcome::Disconnect;
    }

    // A request without an id is a notification and draws no reply.
    if matches!(req.id, RpcId::Null) {
        return WsOutcome::Skip;
    }

    // Limited users may only call the limited method set.
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

    // Parse and dispatch the command through the ported websocket
    // service handler (falling back to the standard handlers), holding
    // the server for the duration like dcrd's per-request locking (the
    // client state locks after the server, the order every path
    // uses).  A not-yet-wired seam panics; it is caught and answered
    // as an internal error so the connection survives.
    let jsonrpc = req.jsonrpc.clone();
    let id = req.id.clone();
    let method = req.method.clone();
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let mut server = server
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut wsc = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let parsed = parse_cmd(&server.registry, &jsonrpc, &method, &param_refs, &id);
        if let Some(err) = parsed.err {
            return create_marshalled_reply(&jsonrpc, &id, None, Some(&err)).ok();
        }
        let cmd = parsed.params.expect("a parsed command has params");
        ws_service_request(&mut server, &mut wsc, &jsonrpc, &method, &cmd, &id)
    }));
    match outcome {
        Ok(Some(reply)) => WsOutcome::Reply(reply),
        Ok(None) => WsOutcome::Skip,
        Err(_) => {
            let json_err = RPCError::new(
                err_rpc_internal().code,
                "internal error: the handler's daemon seam is not yet wired",
            );
            reply_or_skip(create_marshalled_reply(
                &req.jsonrpc,
                &req.id,
                None,
                Some(&json_err),
            ))
        }
    }
}

/// Handle the `authenticate` command: verify the credentials, mark the
/// client authenticated, and answer success — or disconnect on bad or
/// missing credentials (dcrd's `authenticate` case).
fn authenticate(
    server: &Arc<Mutex<Server<NodeRpcChain>>>,
    state: &Arc<Mutex<WsClient>>,
    jsonrpc: &str,
    param_refs: &[&str],
    id: &RpcId,
) -> WsOutcome {
    let server_guard = server
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let parsed = parse_cmd(
        &server_guard.registry,
        jsonrpc,
        "authenticate",
        param_refs,
        id,
    );
    let Some(dcroxide_dcrjson::GoValue::Struct(fields)) = parsed.params else {
        return WsOutcome::Disconnect;
    };
    let username = struct_string(&fields, 0);
    let passphrase = struct_string(&fields, 1);
    let (authed, is_admin) = server_guard.check_auth_user_pass(&username, &passphrase);
    drop(server_guard);
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

/// Write a bare 400 for a rejected upgrade (gorilla's handshake error
/// response, with the version hint every failure carries).
fn write_bad_request<S: Write>(stream: &mut S) -> std::io::Result<()> {
    let body = b"Bad Request";
    let header = format!(
        "HTTP/1.1 400 Bad Request\r\nSec-WebSocket-Version: 13\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removing_a_client_clears_every_subscription_except_mix() {
        let mgr = NodeNtfnMgr::new();
        mgr.add_client(7, Arc::new(Mutex::new(WsClient::new(7))), Arc::default());
        {
            let mut m = mgr.clone();
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
}
