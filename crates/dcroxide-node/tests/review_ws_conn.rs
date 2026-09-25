// SPDX-License-Identifier: ISC
//! The websocket connection against gorilla's and dcrd's behaviour over
//! a real socket: the upgrade's method check, the read limit a batch
//! authenticate leaves in place, requests carrying invalid UTF-8 (on
//! the HTTP endpoint too), and a notification that waits on the chain
//! without freezing its subscriber.

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};
use dcroxide_node::rpcrun::{
    NodeRpcChain, NodeRpcConnManager, NodeRpcSyncManager, RpcListener, RpcTransport,
    start_rpc_listener,
};
use dcroxide_node::runtime::ConnectedPeers;
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::server::{Config, Server};
use dcroxide_standalone::SubsidyCache;
use dcroxide_wire::PROTOCOL_VERSION;

/// A plain-HTTP RPC listener serving `/ws` over a genesis testnet chain
/// with the credentials user:pass (the setup `wsrpc.rs` uses), with the
/// chain handed back so a test can hold its mutex.
fn serve_ws() -> (
    tempfile::TempDir,
    RpcListener,
    u16,
    dcroxide_node::websocket::NodeNtfnMgr,
    Arc<Mutex<Chain>>,
) {
    let params = dcroxide_chaincfg::testnet3_params();
    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    let shared_chain = Arc::clone(&chain);
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
        dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone(), &tx_pool),
    )));
    let mut server = Server::new(Config {
        chain: NodeRpcChain::new(chain, params.clone()),
        chain_params: params.clone(),
        subsidy_cache: std::sync::Mutex::new(SubsidyCache::new(params.clone())),
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
    let ntfn = dcroxide_node::websocket::NodeNtfnMgr::new();
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
    (dir, listener, port, ntfn, shared_chain)
}

/// The upgrade request for `/ws` with the given method.
fn upgrade_request(method: &str) -> String {
    format!(
        "{method} /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
}

/// Complete the RFC 6455 handshake over a fresh connection.
fn handshake(port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .write_all(upgrade_request("GET").as_bytes())
        .expect("write upgrade");
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).expect("read head");
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).expect("utf8 head");
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set timeout");
    stream
}

/// Write a masked client text frame.
fn write_client_frame(stream: &mut TcpStream, payload: &[u8]) {
    let mut frame = vec![0x81];
    let len = payload.len();
    if len < 126 {
        frame.push(0x80 | len as u8);
    } else {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    }
    let mask = [0x12u8, 0x34, 0x56, 0x78];
    frame.extend_from_slice(&mask);
    for (i, byte) in payload.iter().enumerate() {
        frame.push(byte ^ mask[i & 3]);
    }
    stream.write_all(&frame).expect("write frame");
}

/// Read one unmasked server frame: its opcode and payload.
fn read_server_frame_raw(stream: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).expect("read frame header");
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
    (header[0] & 0x0F, payload)
}

/// Read one server text frame's payload.
fn read_server_frame(stream: &mut TcpStream) -> String {
    let (opcode, payload) = read_server_frame_raw(stream);
    assert_eq!(opcode, 0x1, "server sends text frames");
    String::from_utf8(payload).expect("utf8 payload")
}

/// Authenticate in-band as the admin user with a single request.
fn authenticated(port: u16) -> TcpStream {
    let mut ws = handshake(port);
    write_client_frame(
        &mut ws,
        br#"{"jsonrpc":"1.0","method":"authenticate","params":["user","pass"],"id":1}"#,
    );
    let reply = read_server_frame(&mut ws);
    assert!(reply.contains("\"error\":null"), "{reply}");
    ws
}

/// The connection has ended: the next read sees end of stream (or a
/// reset), not a frame.
fn assert_closed(ws: &mut TcpStream) {
    let mut byte = [0u8; 1];
    match ws.read(&mut byte) {
        Ok(0) => {}
        Err(e) if !matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
        other => panic!("the connection is still open: {other:?}"),
    }
}

/// A request that is `pad` bytes of JSON, padded with an ignored field.
fn padded_request(id: u32, len: usize) -> Vec<u8> {
    let head =
        format!(r#"{{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":{id},"pad":""#);
    let mut body = head.into_bytes();
    body.resize(len.saturating_sub(2), b'x');
    body.extend_from_slice(br#""}"#);
    body
}

/// gorilla compares the upgrade's method exactly (`server.go:137`), and
/// Go never case-folds a method, so `get` is refused with a 405 where
/// `GET` upgrades.
#[test]
fn a_lowercase_get_is_not_an_upgrade() {
    let (_dir, listener, port, _ntfn, _chain) = serve_ws();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set timeout");
    stream
        .write_all(upgrade_request("get").as_bytes())
        .expect("write");
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    assert!(
        response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"),
        "{response}"
    );
    assert!(
        response.contains("Sec-Websocket-Version: 13\r\n"),
        "{response}"
    );

    listener.shutdown();
}

/// dcrd raises the read limit only in the single-request authenticate
/// arm (`rpcwebsocket.go:1496-1497`); its batch arm authenticates without
/// it, so a client that authenticated in a batch keeps the 4 KiB limit
/// and its first larger message draws a 1009 close.
#[test]
fn a_batch_authenticate_keeps_the_unauthenticated_read_limit() {
    let (_dir, listener, port, _ntfn, _chain) = serve_ws();

    let mut ws = handshake(port);
    write_client_frame(
        &mut ws,
        br#"[{"jsonrpc":"1.0","method":"authenticate","params":["user","pass"],"id":1}]"#,
    );
    let reply = read_server_frame(&mut ws);
    assert!(
        reply.starts_with('[') && reply.contains("\"error\":null"),
        "{reply}"
    );
    // Authenticated now, so a small request is served...
    write_client_frame(
        &mut ws,
        br#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":2}"#,
    );
    let reply = read_server_frame(&mut ws);
    assert!(reply.contains("\"result\":0"), "{reply}");
    // ...but one past 4 KiB is still over the limit.
    write_client_frame(&mut ws, &padded_request(3, 5000));
    let (opcode, payload) = read_server_frame_raw(&mut ws);
    assert_eq!(opcode, 0x8, "a close frame");
    assert_eq!(payload, [0x03, 0xF1], "1009, with no reason");
    assert_closed(&mut ws);

    // The single-request arm does raise it.
    let mut ws = authenticated(port);
    write_client_frame(&mut ws, &padded_request(4, 5000));
    let reply = read_server_frame(&mut ws);
    assert!(
        reply.contains("\"result\":0") && reply.contains("\"id\":4"),
        "{reply}"
    );

    drop(ws);
    listener.shutdown();
}

/// dcrd hands a frame's raw bytes to `json.Unmarshal`: invalid UTF-8
/// inside a string is served (decoded as U+FFFD), and a stray byte
/// outside one is Go's syntax error, naming the byte as Go does, in
/// whichever arm the first byte picked.
#[test]
fn a_frame_with_invalid_utf8_is_read_as_go_reads_it() {
    let (_dir, listener, port, _ntfn, _chain) = serve_ws();
    let mut ws = authenticated(port);

    write_client_frame(
        &mut ws,
        b"{\"jsonrpc\":\"1.0\",\"id\":\"a\xffb\",\"method\":\"getblockcount\",\"params\":[],\"x\":\"\xe2\x82\"}",
    );
    let reply = read_server_frame(&mut ws);
    assert_eq!(
        reply,
        "{\"jsonrpc\":\"1.0\",\"result\":0,\"error\":null,\"id\":\"a\u{FFFD}b\"}"
    );

    write_client_frame(&mut ws, b"{\"jsonrpc\":\"1.0\",\"id\":1\xff}");
    let reply = read_server_frame(&mut ws);
    assert_eq!(
        reply,
        "{\"jsonrpc\":\"1.0\",\"result\":null,\"error\":{\"code\":-32700,\"message\":\"Failed to parse request: invalid character 'ÿ' after object key:value pair\"},\"id\":null}"
    );

    // A batch, invalid inside a string: served entry by entry.
    write_client_frame(
        &mut ws,
        b"[{\"jsonrpc\":\"1.0\",\"id\":5,\"method\":\"getblockcount\",\"params\":[],\"x\":\"\xc3\"}]",
    );
    let reply = read_server_frame(&mut ws);
    assert_eq!(
        reply,
        "[{\"jsonrpc\":\"1.0\",\"result\":0,\"error\":null,\"id\":5}]"
    );

    // A batch, invalid outside a string: the batch arm's "2.0" error.
    write_client_frame(&mut ws, b"[\xff]");
    let reply = read_server_frame(&mut ws);
    assert_eq!(
        reply,
        "{\"jsonrpc\":\"2.0\",\"result\":null,\"error\":{\"code\":-32700,\"message\":\"Failed to parse request: invalid character 'ÿ' looking for beginning of value\"},\"id\":null}"
    );
    drop(ws);

    // Before authenticating, invalid UTF-8 inside a string does not stop
    // the authenticate request from being served.
    let mut ws = handshake(port);
    write_client_frame(
        &mut ws,
        b"{\"jsonrpc\":\"1.0\",\"method\":\"authenticate\",\"params\":[\"user\",\"pass\"],\"id\":1,\"x\":\"\xff\"}",
    );
    let reply = read_server_frame(&mut ws);
    assert!(reply.contains("\"error\":null"), "{reply}");
    drop(ws);

    // A stray byte from an unauthenticated client is a parse failure,
    // which disconnects it.
    let mut ws = handshake(port);
    write_client_frame(&mut ws, b"\xff");
    assert_closed(&mut ws);

    listener.shutdown();
}

/// Send one authenticated raw HTTP POST and return the response.
fn post(port: u16, body: &[u8]) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let mut request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        dcroxide_rpc::http::base64_std_encode(b"user:pass"),
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    stream.write_all(&request).expect("write");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read");
    String::from_utf8(response).expect("utf8 response")
}

/// The HTTP endpoint reads the body as dcrd does too: served when the
/// invalid UTF-8 is inside a string, Go's syntax error in the arm's
/// version when it is not -- never a 400.
#[test]
fn an_http_body_with_invalid_utf8_is_read_as_go_reads_it() {
    let (_dir, listener, port, _ntfn, _chain) = serve_ws();

    let response = post(
        port,
        b"{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"getblockcount\",\"params\":[],\"x\":\"\xff\"}",
    );
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(
        response.ends_with("\r\n\r\n{\"jsonrpc\":\"1.0\",\"result\":0,\"error\":null,\"id\":1}\n"),
        "{response}"
    );

    let response = post(port, b"\xff");
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(
        response.ends_with("\r\n\r\n{\"jsonrpc\":\"1.0\",\"result\":null,\"error\":{\"code\":-32700,\"message\":\"Failed to parse request: invalid character 'ÿ' looking for beginning of value\"},\"id\":null}\n"),
        "{response}"
    );

    let response = post(port, b"[1,\xc3]");
    assert!(
        response.ends_with("\r\n\r\n{\"jsonrpc\":\"2.0\",\"result\":null,\"error\":{\"code\":-32700,\"message\":\"Failed to parse request: invalid character 'Ã' looking for beginning of value\"},\"id\":null}\n"),
        "{response}"
    );

    listener.shutdown();
}

/// A mempool notification that waits on the chain mutex must not hold
/// its subscriber's lock meanwhile.  dcrd's `notifyForNewTx` locks no
/// client (`rpcwebsocket.go:1093-1104`), so the subscriber keeps being
/// served however long the chain is busy; holding every target's lock
/// across the chain call froze each subscriber's reader for as long as a
/// block validation or a flush held the chain.
#[test]
fn a_notification_waiting_on_the_chain_does_not_freeze_its_subscriber() {
    let (_dir, listener, port, ntfn, chain) = serve_ws();
    let mut ws = authenticated(port);
    write_client_frame(
        &mut ws,
        br#"{"jsonrpc":"1.0","method":"notifynewtransactions","params":[],"id":2}"#,
    );
    let reply = read_server_frame(&mut ws);
    assert!(reply.contains("\"error\":null"), "{reply}");

    // Hold the chain, as a block validation would, and accept a
    // transaction: the delivery thread builds the notification and
    // waits on the chain for the treasury agenda.
    let busy = chain.lock().expect("chain mutex");
    ntfn.notify_new_transactions(vec![(dcroxide_wire::MsgTx::default(), 0)]);
    std::thread::sleep(Duration::from_millis(300));

    // The subscriber is still served meanwhile.
    write_client_frame(
        &mut ws,
        br#"{"jsonrpc":"1.0","method":"session","params":[],"id":3}"#,
    );
    let reply = read_server_frame(&mut ws);
    assert!(
        reply.contains("\"id\":3") && reply.contains("sessionid"),
        "{reply}"
    );

    // Once the chain is free, the notification arrives.
    drop(busy);
    let notification = read_server_frame(&mut ws);
    assert!(
        notification.contains("\"method\":\"txaccepted\""),
        "{notification}"
    );

    drop(ws);
    listener.shutdown();
}

/// A reply must not wait on the client's delayed ACK.  Writing a frame's
/// header and payload separately on a socket with Nagle's algorithm on
/// held every reply's payload until the client acknowledged its header,
/// some 40ms on Linux; gorilla writes a frame in one go and Go sets
/// TCP_NODELAY on every accepted connection, so dcrd answers at once.
/// The bound is generous: a stalled trip is 40ms, a prompt one a
/// fraction of a millisecond.
#[test]
fn sequential_round_trips_do_not_wait_on_delayed_acks() {
    let (_dir, listener, port, _ntfn, _chain) = serve_ws();
    let mut ws = authenticated(port);
    let mut trips = Vec::new();
    for id in 0..30u32 {
        let start = std::time::Instant::now();
        write_client_frame(
            &mut ws,
            format!(r#"{{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":{id}}}"#)
                .as_bytes(),
        );
        let reply = read_server_frame(&mut ws);
        trips.push(start.elapsed());
        assert!(reply.contains("\"result\":0"), "{reply}");
    }
    trips.sort();
    let median = trips[trips.len() / 2];
    assert!(
        median < Duration::from_millis(20),
        "the median round trip took {median:?}"
    );

    drop(ws);
    listener.shutdown();
}
