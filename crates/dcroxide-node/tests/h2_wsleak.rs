// SPDX-License-Identifier: ISC
//! A hostile JSON-RPC id must not strand a websocket client.
//!
//! `1e999` parses to `f64::INFINITY` in Rust (Go's `strconv.ParseFloat`
//! reports `ErrRange` and fails the unmarshal), and rendering an
//! infinite float used to panic the shortest-digits formatter.  On the
//! websocket path that panic escaped the request handler, tore down the
//! serving thread, and skipped the plain `remove_client` statement at
//! the end of the loop — leaving the session registered in the
//! notification manager and in its subscription sets forever, with an
//! outbound queue no thread would ever drain and a websocket slot no
//! client could ever reclaim.  Any credential could do it, the limited
//! class included.
//!
//! These checks drive the real listener: the request must draw a clean
//! JSON-RPC parse error carrying Go's own text, the connection must
//! keep serving afterwards, the client must be gone from the manager
//! once it disconnects, and its slot must be reusable.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};
use dcroxide_node::rpcrun::{
    NodeRpcChain, NodeRpcConnManager, NodeRpcSyncManager, RpcListener, RpcTransport,
    start_rpc_listener,
};
use dcroxide_node::runtime::ConnectedPeers;
use dcroxide_node::websocket::NodeNtfnMgr;
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::server::{Config, RpcSubsidyParams, Server};
use dcroxide_standalone::SubsidyCache;
use dcroxide_wire::PROTOCOL_VERSION;

/// Go's `encoding/json` error for an id past the range of `float64`,
/// as `json.Unmarshal` into `dcrjson.Request` reports it.
const GO_ID_RANGE_ERROR: &str =
    "json: cannot unmarshal number 1e999 into Go struct field Request.id of type float64";

/// A request whose id overflows `float64`.
const OVERFLOWING_ID_REQUEST: &[u8] =
    br#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":1e999}"#;

/// The same, naming a method outside the limited set so a limited
/// credential reaches the authorization gate.
const OVERFLOWING_ID_ADMIN_METHOD: &[u8] =
    br#"{"jsonrpc":"1.0","method":"getpeerinfo","params":[],"id":1e999}"#;

/// Start a plain-HTTP RPC listener (which also serves `/ws`) over a
/// genesis testnet chain with an admin credential of user:pass and a
/// limited credential of limit:limitpass, capped at `max_websockets`
/// concurrent websocket clients.
fn serve_ws(max_websockets: usize) -> (tempfile::TempDir, RpcListener, u16, NodeNtfnMgr) {
    let params = dcroxide_chaincfg::testnet3_params();
    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    let connected = ConnectedPeers::new();
    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    );
    let sync_manager = Arc::new(Mutex::new(dcroxide_node::sync::new_sync_manager(
        Arc::clone(&chain),
        &params,
        false,
        8,
        1000,
        Arc::clone(&tx_pool),
        dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone()),
    )));
    let mut server = Server::new(Config {
        chain: NodeRpcChain::new(chain, params.clone()),
        chain_params: params.clone(),
        subsidy_cache: std::sync::Mutex::new(SubsidyCache::new(RpcSubsidyParams(params.clone()))),
        min_relay_tx_fee: 10000,
        max_protocol_version: PROTOCOL_VERSION,
        sync_mgr: Box::new(NodeRpcSyncManager::new(sync_manager, Arc::clone(&tx_pool))),
        conn_mgr: Box::new(NodeRpcConnManager::new(
            connected,
            Arc::new(dcroxide_node::transport::NetByteTotals::new()),
        )),
        client_cert_auth: false,
        tx_mempooler: Box::new(dcroxide_node::txmempool::NodeRpcTxMempooler::new(
            Arc::clone(&tx_pool),
        )),
        clock: Box::new(dcroxide_node::rpcrun::SystemClock),
        interfaces: Box::new(NoInterfaces),
        rand_u64: Box::new(|| 7),
        tx_indexer: None,
        db: Box::new(()),
        filterer_v2: Box::new(()),
        exists_addresser: None,
        log_manager: Box::new(()),
        fee_estimator: Box::new(()),
        block_templater: None,
        sanity_checker: Box::new(()),
        time_source: Box::new(dcroxide_node::rpcrun::SystemTimeSource),
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
    let ntfn = NodeNtfnMgr::with_max_websockets(max_websockets);
    server.ntfn_mgr = Box::new(ntfn.clone());
    let server = Arc::new(server);
    ntfn.start(Arc::clone(&server)).expect("delivery thread");

    let listener = start_rpc_listener(
        &["127.0.0.1:0".to_string()],
        server,
        RpcTransport::Plain,
        ntfn.clone(),
        128,
    )
    .expect("start rpc listener");
    let port = listener.bound_addrs()[0].port();
    (dir, listener, port, ntfn)
}

/// Complete the RFC 6455 handshake over a fresh connection.
fn handshake(port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("set timeout");
    let request = "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: \
                   Upgrade\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\nSec-WebSocket-Version: \
                   13\r\n\r\n";
    stream.write_all(request.as_bytes()).expect("write upgrade");

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).expect("read head");
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8(head).expect("utf8 head");
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    stream
}

/// Write a masked client text frame (all client frames must be masked).
fn write_client_frame(stream: &mut TcpStream, payload: &[u8]) {
    let mut frame = vec![0x81]; // FIN + text.
    let len = payload.len();
    assert!(len < 126, "test payloads stay small");
    frame.push(0x80 | len as u8); // MASK + length.
    let mask = [0x12u8, 0x34, 0x56, 0x78];
    frame.extend_from_slice(&mask);
    for (i, byte) in payload.iter().enumerate() {
        frame.push(byte ^ mask[i & 3]);
    }
    stream.write_all(&frame).expect("write frame");
}

/// Read one unmasked server text frame's payload.
fn read_server_frame(stream: &mut TcpStream) -> String {
    let mut header = [0u8; 2];
    stream
        .read_exact(&mut header)
        .expect("the connection must survive to answer");
    assert_eq!(header[0] & 0x0F, 0x1, "server sends text frames");
    let len = match header[1] & 0x7F {
        126 => {
            let mut ext = [0u8; 2];
            stream.read_exact(&mut ext).expect("read extended length");
            u16::from_be_bytes(ext) as usize
        }
        127 => {
            let mut ext = [0u8; 8];
            stream.read_exact(&mut ext).expect("read extended length");
            u64::from_be_bytes(ext) as usize
        }
        n => n as usize,
    };
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).expect("read frame payload");
    String::from_utf8(payload).expect("utf8 payload")
}

/// Authenticate in band with the given credentials.
fn authenticate(stream: &mut TcpStream, user: &str, pass: &str) {
    let body = format!(
        r#"{{"jsonrpc":"1.0","method":"authenticate","params":["{user}","{pass}"],"id":1}}"#
    );
    write_client_frame(stream, body.as_bytes());
    let reply = read_server_frame(stream);
    assert!(reply.contains("\"error\":null"), "{reply}");
}

/// Wait for the manager's client count to settle on `want`, which the
/// serving thread updates asynchronously as connections come and go.
fn wait_for_clients(ntfn: &NodeNtfnMgr, want: usize) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        if ntfn.num_clients() == want {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(
        ntfn.num_clients(),
        want,
        "the notification manager never settled on {want} clients; a session was stranded"
    );
}

/// An admin client sending an id past `float64` gets Go's parse error,
/// keeps its connection, and is unregistered when it finally leaves.
#[test]
fn an_overflowing_id_answers_cleanly_and_frees_the_client() {
    let (_dir, listener, port, ntfn) = serve_ws(2);
    let mut ws = handshake(port);
    authenticate(&mut ws, "user", "pass");
    wait_for_clients(&ntfn, 1);

    // The hostile id draws a parse error, not a dead connection.  This
    // request used to reach the reply marshaller with an infinite id,
    // panic there, panic a second time in the recovery arm on the same
    // id, and unwind out of the serving thread.
    write_client_frame(&mut ws, OVERFLOWING_ID_REQUEST);
    let reply = read_server_frame(&mut ws);
    assert!(reply.contains("\"code\":-32700"), "{reply}");
    assert!(
        reply.contains(&format!("Failed to parse request: {GO_ID_RANGE_ERROR}")),
        "the reply must carry Go's own unmarshal text: {reply}"
    );
    assert!(reply.contains("\"id\":null"), "{reply}");

    // The connection is still serving.
    write_client_frame(
        &mut ws,
        br#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":2}"#,
    );
    let reply = read_server_frame(&mut ws);
    assert!(reply.contains("\"result\":0"), "{reply}");
    assert_eq!(ntfn.num_clients(), 1, "the client is still connected");

    // Disconnecting releases the registration.
    drop(ws);
    wait_for_clients(&ntfn, 0);
    listener.shutdown();
}

/// The limited credential reaches the same defect through the
/// authorization gate, which marshalled the id before any recovery
/// handler was in scope.  A subscribed limited client must still be
/// unregistered from every subscription set, and its slot must be
/// reusable — twenty-five stranded sessions would otherwise deny
/// websocket service outright.
#[test]
fn a_limited_user_cannot_strand_a_websocket_slot() {
    // A cap of one makes the leaked slot observable directly.
    let (_dir, listener, port, ntfn) = serve_ws(1);
    let mut ws = handshake(port);
    authenticate(&mut ws, "limit", "limitpass");
    wait_for_clients(&ntfn, 1);

    // Subscribe, so a stranded session would also keep receiving
    // notifications onto a queue nobody drains.  Both subscription
    // commands are in the limited set.
    for body in [
        &br#"{"jsonrpc":"1.0","method":"notifyblocks","params":[],"id":2}"#[..],
        &br#"{"jsonrpc":"1.0","method":"notifynewtransactions","params":[],"id":3}"#[..],
    ] {
        write_client_frame(&mut ws, body);
        let reply = read_server_frame(&mut ws);
        assert!(reply.contains("\"error\":null"), "{reply}");
    }

    // A non-limited method with the overflowing id: rejected while
    // parsing, before the authorization gate ever renders the id.
    write_client_frame(&mut ws, OVERFLOWING_ID_ADMIN_METHOD);
    let reply = read_server_frame(&mut ws);
    assert!(reply.contains("\"code\":-32700"), "{reply}");
    assert!(
        reply.contains(&format!("Failed to parse request: {GO_ID_RANGE_ERROR}")),
        "{reply}"
    );

    // The authorization gate itself still behaves for a sane id.
    write_client_frame(
        &mut ws,
        br#"{"jsonrpc":"1.0","method":"getpeerinfo","params":[],"id":4}"#,
    );
    let reply = read_server_frame(&mut ws);
    assert!(
        reply.contains("limited user not authorized for this method"),
        "{reply}"
    );

    // While it is connected the single slot is taken: a second client
    // is refused with no upgrade.
    assert_eq!(ntfn.num_clients(), 1);

    // On disconnect the session leaves the registry and the slot is
    // reusable by a fresh client, which then serves normally.
    drop(ws);
    wait_for_clients(&ntfn, 0);

    let mut next = handshake(port);
    authenticate(&mut next, "user", "pass");
    wait_for_clients(&ntfn, 1);
    write_client_frame(
        &mut next,
        br#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":5}"#,
    );
    let reply = read_server_frame(&mut next);
    assert!(reply.contains("\"result\":0"), "{reply}");

    drop(next);
    wait_for_clients(&ntfn, 0);
    listener.shutdown();
}

/// The HTTP endpoint answers the same request with the same parse
/// error.  There a panic was contained by the connection handler's
/// recovery, so the defect showed up as a bogus `-32603` internal
/// error instead of Go's `-32700`.
#[test]
fn the_http_endpoint_answers_an_overflowing_id_with_gos_parse_error() {
    let (_dir, listener, port, _ntfn) = serve_ws(2);
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("set timeout");
    let credentials = dcroxide_rpc::http::base64_std_encode(b"user:pass");
    let body = String::from_utf8(OVERFLOWING_ID_REQUEST.to_vec()).expect("utf8");
    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {credentials}\r\nContent-Type: \
         application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write request");

    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read response");
    let response = String::from_utf8(response).expect("utf8 response");
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("\"code\":-32700"), "{response}");
    assert!(
        response.contains(&format!("Failed to parse request: {GO_ID_RANGE_ERROR}")),
        "{response}"
    );
    assert!(
        !response.contains("-32603"),
        "the id must be rejected while parsing, not caught as a panic: {response}"
    );

    listener.shutdown();
}
