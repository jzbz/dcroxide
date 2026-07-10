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
//! The notification manager is installed as a subscription recorder
//! (dcrd's `wsNotificationManager` registration maps); the actual
//! notification fan-out over chain and mempool events arrives with a
//! later piece, since the daemon does not yet emit those events.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex};

use dcroxide_chainhash::Hash;
use dcroxide_dcrjson::{RPCError, RpcId, err_rpc_internal, err_rpc_invalid_params, err_rpc_parse};
use dcroxide_rpc::dispatch::{RPC_LIMITED, create_marshalled_reply, parse_cmd};
use dcroxide_rpc::http::unmarshal_request;
use dcroxide_rpc::server::Server;
use dcroxide_rpc::websocket::{RpcNtfnManager, WsClient, ws_service_request};

use crate::rpcrun::NodeRpcChain;
use crate::wsframe::{WsConn, WsIn, accept_key};

/// The websocket read limit before authentication (dcrd
/// `websocketReadLimitUnauthenticated`).
const READ_LIMIT_UNAUTHENTICATED: usize = 1 << 12;

/// The websocket read limit after authentication (dcrd
/// `websocketReadLimitAuthenticated`).
const READ_LIMIT_AUTHENTICATED: usize = 1 << 24;

/// A subscription-recording notification manager (dcrd's
/// `wsNotificationManager` registration maps).  The daemon records
/// each client's subscriptions so the subscription commands answer
/// instead of panicking; the notification fan-out over chain and
/// mempool events, which reads these sets, arrives with a later piece.
#[derive(Clone, Default)]
pub struct NodeNtfnMgr {
    inner: Arc<Mutex<Subscriptions>>,
}

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

impl NodeNtfnMgr {
    /// An empty notification manager.
    pub fn new() -> NodeNtfnMgr {
        NodeNtfnMgr::default()
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

    fn notify_winning_tickets(
        &mut self,
        _block_hash: &Hash,
        _block_height: i64,
        _tickets: &[Hash],
    ) {
        // The winning-ticket fan-out over the recorded subscribers
        // arrives with the notification-delivery piece; recording the
        // subscription is enough for the subscription command to
        // succeed.
    }
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
/// `authenticate` before any other command.
pub fn serve_websocket<S: Read + Write>(
    mut stream: S,
    head: &crate::rpcrun::HttpHead,
    pre_authenticated: bool,
    is_admin: bool,
    server: &Arc<Mutex<Server<NodeRpcChain>>>,
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

    let mut wsc = WsClient::new(new_session_id());
    wsc.authenticated = pre_authenticated;
    wsc.is_admin = is_admin;
    let mut conn = WsConn::new(stream);

    loop {
        let read_limit = if wsc.authenticated {
            READ_LIMIT_AUTHENTICATED
        } else {
            READ_LIMIT_UNAUTHENTICATED
        };
        let message = match conn.read_message(read_limit) {
            Ok(WsIn::Text(payload)) => payload,
            // A close frame, a clean disconnect, or a protocol error
            // ends the connection.
            Ok(WsIn::Close) | Err(_) => break,
        };
        let Ok(body) = String::from_utf8(message) else {
            // Non-UTF-8 payloads cannot be JSON; dcrd's JSON parse is
            // the backstop, so treat it as a parse failure.
            if !wsc.authenticated {
                break;
            }
            continue;
        };

        match handle_ws_request(server, &mut wsc, &body) {
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
    wsc: &mut WsClient,
    body: &str,
) -> WsOutcome {
    let req = match unmarshal_request(body) {
        Ok(req) => req,
        Err(err_text) => {
            // dcrd disconnects an unauthenticated client on any parse
            // failure; an authenticated one gets the parse error.
            if !wsc.authenticated {
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
        if wsc.authenticated {
            // A second authenticate is a protocol violation.
            return WsOutcome::Disconnect;
        }
        return authenticate(server, wsc, &req.jsonrpc, &param_refs, &req.id);
    }

    // Every other command requires an authenticated client.
    if !wsc.authenticated {
        return WsOutcome::Disconnect;
    }

    // A request without an id is a notification and draws no reply.
    if matches!(req.id, RpcId::Null) {
        return WsOutcome::Skip;
    }

    // Limited users may only call the limited method set.
    if !wsc.is_admin && !RPC_LIMITED.contains(&req.method.as_str()) {
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
    // the server for the duration like dcrd's per-request locking.  A
    // not-yet-wired seam panics; it is caught and answered as an
    // internal error so the connection survives.
    let jsonrpc = req.jsonrpc.clone();
    let id = req.id.clone();
    let method = req.method.clone();
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let mut server = server
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let parsed = parse_cmd(&server.registry, &jsonrpc, &method, &param_refs, &id);
        if let Some(err) = parsed.err {
            return create_marshalled_reply(&jsonrpc, &id, None, Some(&err)).ok();
        }
        let cmd = parsed.params.expect("a parsed command has params");
        ws_service_request(&mut server, wsc, &jsonrpc, &method, &cmd, &id)
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
    wsc: &mut WsClient,
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
    wsc.authenticated = true;
    wsc.is_admin = is_admin;
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
