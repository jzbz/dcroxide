// SPDX-License-Identifier: ISC
//! A websocket subscriber that only listens gets a notification backlog
//! at socket speed, as dcrd's `notificationQueueHandler` promotes each
//! notification as soon as `outHandler` has written the one before it.
//! The port promoted one per read of the connection, and an idle client
//! is read once per 50 ms poll interval: twenty notifications a second,
//! with anything faster -- a block connected per notification during
//! initial sync -- growing the held list without bound.

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

/// Complete the RFC 6455 handshake over a fresh connection.
fn handshake(port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .write_all(
            b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
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
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("set timeout");
    stream
}

/// Write a masked client text frame.
fn write_client_frame(stream: &mut TcpStream, payload: &[u8]) {
    assert!(payload.len() < 126, "short payloads only");
    let mask = [0x12u8, 0x34, 0x56, 0x78];
    let mut frame = vec![0x81, 0x80 | payload.len() as u8];
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i & 3]));
    stream.write_all(&frame).expect("write frame");
}

/// Read one unmasked server text frame's payload.
fn read_server_frame(stream: &mut TcpStream) -> String {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).expect("read frame header");
    assert_eq!(header[0], 0x81, "a final text frame");
    let len = match header[1] & 0x7F {
        126 => {
            let mut ext = [0u8; 2];
            stream.read_exact(&mut ext).expect("read extended length");
            usize::from(u16::from_be_bytes(ext))
        }
        127 => {
            let mut ext = [0u8; 8];
            stream.read_exact(&mut ext).expect("read extended length");
            u64::from_be_bytes(ext) as usize
        }
        n => usize::from(n),
    };
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).expect("read frame payload");
    String::from_utf8(payload).expect("utf8 payload")
}

/// Two hundred notifications queued together reach a client that sends
/// nothing in well under a second, where one per 50 ms read interval
/// took ten.
#[test]
fn an_idle_subscriber_gets_a_backlog_at_socket_speed() {
    const COUNT: usize = 200;
    let (_dir, listener, port, ntfn, _chain) = serve_ws();
    let mut ws = handshake(port);
    write_client_frame(
        &mut ws,
        br#"{"jsonrpc":"1.0","method":"authenticate","params":["user","pass"],"id":1}"#,
    );
    let reply = read_server_frame(&mut ws);
    assert!(reply.contains("\"error\":null"), "{reply}");
    write_client_frame(
        &mut ws,
        br#"{"jsonrpc":"1.0","method":"notifynewtransactions","params":[],"id":2}"#,
    );
    let reply = read_server_frame(&mut ws);
    assert!(reply.contains("\"error\":null"), "{reply}");

    // From here the client only listens.
    let start = Instant::now();
    ntfn.notify_new_transactions(
        (0..COUNT)
            .map(|_| (dcroxide_wire::MsgTx::default(), 0))
            .collect(),
    );
    for i in 0..COUNT {
        let notification = read_server_frame(&mut ws);
        assert!(
            notification.contains("\"method\":\"txaccepted\""),
            "notification {i}: {notification}"
        );
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "{COUNT} notifications took {elapsed:?}"
    );

    drop(ws);
    listener.shutdown();
}
