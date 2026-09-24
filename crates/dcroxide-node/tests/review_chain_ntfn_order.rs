// SPDX-License-Identifier: ISC
//! The websocket frame order a client sees across a chain
//! reorganization.  dcrd's chain sends NTBlockConnected and then
//! NTNewTickets for each connected block, and NTReorganization only
//! after every disconnect and connect of the reorg; the server handles
//! each inline, queueing blockconnected, newtickets, blockdisconnected
//! and reorganization onto the one notification queue in that emission
//! order.  The daemon defers the block frames to the post-processing
//! drain, so the reorganization and new-ticket frames must be deferred
//! with them rather than sent at callback time, or a notifyblocks client
//! sees the reorganization before the frames of the reorg it describes.

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
/// genesis testnet chain with the credentials user:pass, handing back
/// the notification manager so tests can queue events.
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
    // The two short length encodings; batch bodies outgrow the first.
    if len < 126 {
        frame.push(0x80 | len as u8); // MASK + length.
    } else {
        assert!(len <= usize::from(u16::MAX), "test payloads stay small");
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
    // Server frames are never masked.
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

/// A client subscribed to block and new-ticket notifications receives
/// one reorg's frames in dcrd's order: the blockdisconnected frame, the
/// blockconnected frame, the newtickets frame of the block that matured
/// the tickets, and the reorganization frame last.
///
/// Regression for the reorganization and newtickets frames being sent
/// from the chain callback while the block frames waited for the drain,
/// which put both ahead of the block frames they follow in dcrd.
#[test]
fn a_reorg_reaches_a_client_in_dcrds_frame_order() {
    use dcroxide_blockchain::notifications::{
        BlockConnectedNtfnsData, BlockDisconnectedNtfnsData, Notification, ReorganizationNtfnsData,
        TicketNotificationsData,
    };
    use dcroxide_blockchain::validate::AgendaFlags;
    use dcroxide_chainhash::Hash;

    let (_dir, listener, port, ntfn, chain) = serve_ws();
    let params = dcroxide_chaincfg::testnet3_params();
    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    );
    let handler = dcroxide_node::chainntfns::ChainNtfnHandler::new(
        Some(ntfn.clone()),
        params.clone(),
        true,
        dcroxide_node::sync::SyncGate::always_current(),
        None,
        Arc::clone(&tx_pool),
        dcroxide_node::dispatch::SyncPeers::new(),
        dcroxide_node::dispatch::new_recently_advertised(),
    );

    let mut ws = handshake(port);
    for (id, method) in [
        (1, r#""authenticate","params":["user","pass"]"#),
        (2, r#""notifyblocks","params":[]"#),
        (3, r#""notifynewtickets","params":[]"#),
    ] {
        write_client_frame(
            &mut ws,
            format!(r#"{{"jsonrpc":"1.0","method":{method},"id":{id}}}"#).as_bytes(),
        );
        let reply = read_server_frame(&mut ws);
        assert!(reply.contains("\"error\":null"), "{reply}");
    }
    ws.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .expect("set timeout");

    // The chain's emission order for a one-block reorg from the old tip
    // to a replacement at the same height: the reorg-started marker,
    // the disconnect, the connect with the tickets it matured, the
    // reorganization, then the reorg-done marker — all from inside the
    // processing call, before the drain.
    let old_tip = Arc::new(params.genesis_block.clone());
    let mut replacement = params.genesis_block.clone();
    replacement.header.nonce ^= 1;
    let new_tip = Arc::new(replacement);
    handler.handle(&Notification::ChainReorgStarted);
    handler.handle(&Notification::BlockDisconnected(
        BlockDisconnectedNtfnsData {
            block: Arc::clone(&old_tip),
            parent_block: Arc::clone(&old_tip),
            check_tx_flags: AgendaFlags::default(),
        },
    ));
    handler.handle(&Notification::BlockConnected(BlockConnectedNtfnsData {
        block: Arc::clone(&new_tip),
        parent_block: Arc::clone(&old_tip),
        check_tx_flags: AgendaFlags::default(),
    }));
    handler.handle(&Notification::NewTickets(TicketNotificationsData {
        hash: new_tip.header.block_hash(),
        height: 0,
        stake_difficulty: 20000,
        tickets_new: vec![Hash([0x11; 32])],
    }));
    handler.handle(&Notification::Reorganization(ReorganizationNtfnsData {
        old_hash: old_tip.header.block_hash(),
        old_height: 0,
        new_hash: new_tip.header.block_hash(),
        new_height: 0,
    }));
    handler.handle(&Notification::ChainReorgDone);

    // The post-processing drain (the netsync adapter runs the whole
    // `drain_pending` once the chain mutex is free).
    handler.drain_pending(&chain, 2_000_000_000);

    let methods: Vec<String> = (0..4)
        .map(|_| {
            let frame = read_server_frame(&mut ws);
            let at = frame.find("\"method\":\"").expect("a notification frame") + 10;
            let len = frame[at..].find('"').expect("method end");
            frame[at..at + len].to_string()
        })
        .collect();
    assert_eq!(
        methods,
        [
            "blockdisconnected",
            "blockconnected",
            "newtickets",
            "reorganization"
        ],
        "one reorg's frames in dcrd's order"
    );

    listener.shutdown();
}
