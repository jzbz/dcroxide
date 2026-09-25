// SPDX-License-Identifier: ISC
//! A websocket batch entry whose reply fails to marshal ends dcrd's
//! `inHandler` with a bare `return` (`rpcwebsocket.go:1753-1758`), not
//! the `continue` every other marshal failure in the batch arm takes:
//! the batch is abandoned with nothing sent, the client is never read
//! again, and because the `return` skips the trailing `c.Disconnect()`
//! (`:1800`) the connection stays open and notifications keep arriving.
//! The single-request arm only logs and drops the reply
//! (`serviceRequest`, `:1821-1826`).
//!
//! An id of a type `IsValidIDType` refuses (a JSON bool here) makes
//! `MarshalResponse` fail for any command; a result Go's `json.Marshal`
//! refuses, such as getvoteinfo's `0/0` choice progress, takes the same
//! path.

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
/// with the credentials user:pass (the setup `wsrpc.rs` uses).
fn serve_ws() -> (
    tempfile::TempDir,
    RpcListener,
    u16,
    dcroxide_node::websocket::NodeNtfnMgr,
) {
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
    (dir, listener, port, ntfn)
}

/// Complete the RFC 6455 handshake over a fresh connection.
fn handshake(port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let request = "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    stream.write_all(request.as_bytes()).expect("write upgrade");
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).expect("read head");
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).expect("utf8 head");
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
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

/// Read one unmasked server text frame's payload.
fn read_server_frame(stream: &mut TcpStream) -> String {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).expect("read frame header");
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

/// Authenticate as the admin user and subscribe to block notifications,
/// so a later notification shows whether the connection is still open.
fn authenticated_block_subscriber(port: u16) -> TcpStream {
    let mut ws = handshake(port);
    write_client_frame(
        &mut ws,
        br#"{"jsonrpc":"1.0","method":"authenticate","params":["user","pass"],"id":1}"#,
    );
    let reply = read_server_frame(&mut ws);
    assert!(reply.contains("\"error\":null"), "{reply}");
    write_client_frame(
        &mut ws,
        br#"{"jsonrpc":"1.0","method":"notifyblocks","params":[],"id":2}"#,
    );
    let reply = read_server_frame(&mut ws);
    assert!(reply.contains("\"error\":null"), "{reply}");
    ws
}

/// Nothing arrives within the window, and the socket is not closed
/// either: the read times out rather than seeing end of stream.
fn assert_silent_but_open(ws: &mut TcpStream, what: &str) {
    ws.set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set timeout");
    let mut probe = [0u8; 1];
    match ws.read(&mut probe) {
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
        Ok(0) => panic!("{what}: the connection was closed"),
        Ok(_) => panic!("{what}: a frame arrived"),
        Err(e) => panic!("{what}: {e}"),
    }
}

/// The batch is abandoned at the entry whose reply cannot be marshalled:
/// the reply already collected for the entry before it is never sent,
/// the entry after it never runs, and no later request is read -- yet
/// the connection stays open and still carries notifications.
#[test]
fn a_batch_reply_that_fails_to_marshal_stops_reading_the_client() {
    let (_dir, listener, port, ntfn) = serve_ws();
    let mut ws = authenticated_block_subscriber(port);

    write_client_frame(
        &mut ws,
        br#"[{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":3},{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":true},{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":5}]"#,
    );
    assert_silent_but_open(&mut ws, "the abandoned batch");

    // The client is no longer read, so a well-formed request goes
    // unanswered.
    write_client_frame(
        &mut ws,
        br#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":6}"#,
    );
    assert_silent_but_open(&mut ws, "a request after the abandoned batch");

    // The write side still runs: a connected block reaches the client.
    let genesis = dcroxide_chaincfg::testnet3_params().genesis_block;
    ntfn.notify_block_connected(Arc::new(genesis));
    ws.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set timeout");
    let notification = read_server_frame(&mut ws);
    assert!(
        notification.contains("\"method\":\"blockconnected\""),
        "{notification}"
    );

    // Shutdown still ends the parked client.
    listener.shutdown();
}

/// The single-request arm drops the unmarshallable reply and carries on
/// reading.
#[test]
fn a_single_reply_that_fails_to_marshal_is_only_dropped() {
    let (_dir, listener, port, _ntfn) = serve_ws();
    let mut ws = authenticated_block_subscriber(port);

    write_client_frame(
        &mut ws,
        br#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":true}"#,
    );
    write_client_frame(
        &mut ws,
        br#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":4}"#,
    );
    ws.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set timeout");
    let reply = read_server_frame(&mut ws);
    assert!(
        reply.contains("\"id\":4") && reply.contains("\"result\":0"),
        "only the second request is answered: {reply}"
    );

    drop(ws);
    listener.shutdown();
}
