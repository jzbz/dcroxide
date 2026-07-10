// SPDX-License-Identifier: ISC
//! End-to-end checks for the websocket RPC endpoint: a raw RFC 6455
//! handshake against a genesis chain, then JSON-RPC over text frames —
//! an unauthenticated client authenticates in-band and then queries the
//! chain, and a bad upgrade request is refused.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};
use dcroxide_node::rpcrun::{
    NodeRpcChain, NodeRpcConnManager, NodeRpcSyncManager, RpcListener, RpcTransport,
    start_rpc_listener,
};
use dcroxide_node::runtime::ConnectedPeers;
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::server::{Config, RpcSubsidyParams, Server};
use dcroxide_standalone::SubsidyCache;
use dcroxide_wire::PROTOCOL_VERSION;

/// Start a plain-HTTP RPC listener (which also serves `/ws`) over a
/// genesis testnet chain with the credentials user:pass.
fn serve_ws() -> (tempfile::TempDir, RpcListener, u16) {
    let params = dcroxide_chaincfg::testnet3_params();
    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    let connected = ConnectedPeers::new();
    let sync_manager = Arc::new(Mutex::new(dcroxide_node::sync::new_sync_manager(
        Arc::clone(&chain),
        &params,
        false,
        8,
        1000,
    )));
    let mut server = Server::new(Config {
        chain: NodeRpcChain::new(chain, params.clone()),
        chain_params: params.clone(),
        subsidy_cache: SubsidyCache::new(RpcSubsidyParams(params.clone())),
        min_relay_tx_fee: 10000,
        max_protocol_version: PROTOCOL_VERSION,
        sync_mgr: Box::new(NodeRpcSyncManager::new(sync_manager)),
        conn_mgr: Box::new(NodeRpcConnManager::new(
            connected,
            Arc::new(dcroxide_node::transport::NetByteTotals::new()),
        )),
        tx_mempooler: Box::new(()),
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
        rpc_limit_user: String::new(),
        rpc_limit_pass: String::new(),
    });
    server.ntfn_mgr = Box::new(dcroxide_node::websocket::NodeNtfnMgr::new());

    let listener = start_rpc_listener(
        &["127.0.0.1:0".to_string()],
        Arc::new(Mutex::new(server)),
        RpcTransport::Plain,
    )
    .expect("start rpc listener");
    let port = listener.bound_addrs()[0].port();
    (dir, listener, port)
}

/// Complete the RFC 6455 handshake over a fresh connection, returning
/// the connected stream ready for frames.
fn handshake(port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    // A fixed 16-byte key; the accept value is verified below.
    let key = "AAAAAAAAAAAAAAAAAAAAAA==";
    let request = format!(
        "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).expect("write upgrade");

    // Read the response head up to the blank line.
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
    assert!(
        head.contains(&format!(
            "Sec-WebSocket-Accept: {}",
            dcroxide_node::wsframe::accept_key(key)
        )),
        "{head}"
    );
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
    stream.read_exact(&mut header).expect("read frame header");
    assert_eq!(header[0] & 0x0F, 0x1, "server sends text frames");
    let len = (header[1] & 0x7F) as usize;
    // Server frames are never masked, and test replies are small.
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).expect("read frame payload");
    String::from_utf8(payload).expect("utf8 payload")
}

#[test]
fn authenticates_and_queries_over_websocket() {
    let (_dir, listener, port) = serve_ws();
    let mut ws = handshake(port);

    // A query before authenticating drops the connection... but first
    // authenticate on a fresh connection to prove the happy path.
    write_client_frame(
        &mut ws,
        br#"{"jsonrpc":"1.0","method":"authenticate","params":["user","pass"],"id":1}"#,
    );
    let reply = read_server_frame(&mut ws);
    assert!(reply.contains("\"result\":null"), "{reply}");
    assert!(reply.contains("\"error\":null"), "{reply}");

    // Now authenticated, a chain query answers.
    write_client_frame(
        &mut ws,
        br#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":2}"#,
    );
    let reply = read_server_frame(&mut ws);
    assert!(reply.contains("\"result\":0"), "{reply}");

    // A subscription command answers through the notification recorder.
    write_client_frame(
        &mut ws,
        br#"{"jsonrpc":"1.0","method":"notifyblocks","params":[],"id":3}"#,
    );
    let reply = read_server_frame(&mut ws);
    assert!(reply.contains("\"result\":null"), "{reply}");
    assert!(reply.contains("\"error\":null"), "{reply}");

    drop(ws);
    listener.shutdown();
}

#[test]
fn a_command_before_authenticate_drops_the_connection() {
    let (_dir, listener, port) = serve_ws();
    let mut ws = handshake(port);

    // An unauthenticated client that skips authenticate is disconnected
    // with no reply.
    write_client_frame(
        &mut ws,
        br#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":1}"#,
    );
    let mut byte = [0u8; 1];
    assert!(
        ws.read_exact(&mut byte).is_err(),
        "the connection should be dropped without a reply"
    );

    listener.shutdown();
}

#[test]
fn a_bad_upgrade_request_is_refused() {
    let (_dir, listener, port) = serve_ws();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    // Missing Sec-WebSocket-Version.
    let request = "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n\r\n";
    stream.write_all(request.as_bytes()).expect("write");
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");

    listener.shutdown();
}
