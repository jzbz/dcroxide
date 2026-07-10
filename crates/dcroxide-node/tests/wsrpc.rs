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
    )));
    let mut server = Server::new(Config {
        chain: NodeRpcChain::new(chain, params.clone()),
        chain_params: params.clone(),
        subsidy_cache: SubsidyCache::new(RpcSubsidyParams(params.clone())),
        min_relay_tx_fee: 10000,
        max_protocol_version: PROTOCOL_VERSION,
        sync_mgr: Box::new(NodeRpcSyncManager::new(sync_manager, Arc::clone(&tx_pool))),
        conn_mgr: Box::new(NodeRpcConnManager::new(
            connected,
            Arc::new(dcroxide_node::transport::NetByteTotals::new()),
        )),
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
        rpc_limit_user: String::new(),
        rpc_limit_pass: String::new(),
    });
    let ntfn = dcroxide_node::websocket::NodeNtfnMgr::new();
    server.ntfn_mgr = Box::new(ntfn.clone());
    let server = Arc::new(Mutex::new(server));
    ntfn.start(Arc::clone(&server)).expect("delivery thread");

    let listener = start_rpc_listener(
        &["127.0.0.1:0".to_string()],
        server,
        RpcTransport::Plain,
        ntfn.clone(),
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

#[test]
fn authenticates_and_queries_over_websocket() {
    let (_dir, listener, port, _ntfn, _chain) = serve_ws();
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

/// Delivery: a queued block-connected event reaches the subscribed
/// client as a JSON-RPC notification, skips the unsubscribed one, and
/// the connection keeps answering requests afterwards; a disconnected
/// subscriber is cleaned up without disturbing later events.
#[test]
fn notifications_reach_only_subscribers() {
    let (_dir, listener, port, ntfn, _chain) = serve_ws();
    let genesis = dcroxide_chaincfg::testnet3_params().genesis_block;

    // Client A authenticates and subscribes to block notifications.
    let mut a = handshake(port);
    write_client_frame(
        &mut a,
        br#"{"jsonrpc":"1.0","method":"authenticate","params":["user","pass"],"id":1}"#,
    );
    read_server_frame(&mut a);
    write_client_frame(
        &mut a,
        br#"{"jsonrpc":"1.0","method":"notifyblocks","params":[],"id":2}"#,
    );
    read_server_frame(&mut a);

    // Client B authenticates but subscribes to nothing.
    let mut b = handshake(port);
    write_client_frame(
        &mut b,
        br#"{"jsonrpc":"1.0","method":"authenticate","params":["user","pass"],"id":1}"#,
    );
    read_server_frame(&mut b);

    // A connected block fans out to A as a null-id notification...
    ntfn.notify_block_connected(genesis.clone());
    a.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .expect("set timeout");
    let notification = read_server_frame(&mut a);
    assert!(
        notification.contains("\"method\":\"blockconnected\""),
        "{notification}"
    );
    assert!(notification.contains("\"id\":null"), "{notification}");
    // The params carry the serialized header hex.
    let header_hex: String =
        genesis
            .header
            .serialize()
            .iter()
            .fold(String::new(), |mut acc, byte| {
                acc.push_str(&format!("{byte:02x}"));
                acc
            });
    assert!(notification.contains(&header_hex), "{notification}");

    // ...and not to B, whose read times out with no frame.
    b.set_read_timeout(Some(std::time::Duration::from_millis(400)))
        .expect("set timeout");
    let mut probe = [0u8; 1];
    assert!(
        b.read(&mut probe).is_err(),
        "the unsubscribed client must receive nothing"
    );

    // A still answers requests after the notification (the serving
    // loop interleaves notification writes with request handling).
    write_client_frame(
        &mut a,
        br#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":3}"#,
    );
    let reply = read_server_frame(&mut a);
    assert!(reply.contains("\"result\":0"), "{reply}");

    // Dropping the subscriber cleans it up; later events go nowhere
    // and the survivor keeps answering.
    drop(a);
    std::thread::sleep(std::time::Duration::from_millis(300));
    ntfn.notify_block_connected(genesis);
    b.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .expect("set timeout");
    write_client_frame(
        &mut b,
        br#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":2}"#,
    );
    let reply = read_server_frame(&mut b);
    assert!(reply.contains("\"result\":0"), "{reply}");

    listener.shutdown();
}

/// The daemon chain-event handler translates blockchain notifications
/// into manager events end to end: a connected block and maturing
/// tickets reach the subscribed websocket client, and a gate-passing
/// accepted block whose lottery lookup fails is skipped without being
/// recorded (dcrd's logged break).
#[test]
fn the_chain_event_handler_feeds_websocket_subscribers() {
    use dcroxide_blockchain::notifications::{
        BlockAcceptedNtfnsData, BlockConnectedNtfnsData, Notification, TicketNotificationsData,
    };
    use dcroxide_blockchain::validate::AgendaFlags;
    use dcroxide_chainhash::Hash;

    let (_dir, listener, port, ntfn, chain) = serve_ws();
    let params = dcroxide_chaincfg::testnet3_params();
    // Unsynced mining allowed so the drain's is-current gate stays
    // open over the genesis-only fixture chain.
    let handler = dcroxide_node::chainntfns::ChainNtfnHandler::new(
        Some(ntfn.clone()),
        params.clone(),
        true,
        dcroxide_node::txmempool::new_shared_tx_pool(
            Arc::clone(&chain),
            &params,
            false,
            100,
            10000,
            false,
            false,
        ),
        dcroxide_node::dispatch::SyncPeers::new(),
        dcroxide_node::dispatch::new_recently_advertised(),
    );

    // Subscribe to block and new-ticket notifications.
    let mut ws = handshake(port);
    write_client_frame(
        &mut ws,
        br#"{"jsonrpc":"1.0","method":"authenticate","params":["user","pass"],"id":1}"#,
    );
    read_server_frame(&mut ws);
    write_client_frame(
        &mut ws,
        br#"{"jsonrpc":"1.0","method":"notifyblocks","params":[],"id":2}"#,
    );
    read_server_frame(&mut ws);
    write_client_frame(
        &mut ws,
        br#"{"jsonrpc":"1.0","method":"notifynewtickets","params":[],"id":3}"#,
    );
    read_server_frame(&mut ws);
    ws.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .expect("set timeout");

    // A connected-block event flows through the handler to the
    // subscriber.
    let genesis = params.genesis_block.clone();
    handler.handle(&Notification::BlockConnected(BlockConnectedNtfnsData {
        block: &genesis,
        parent_block: &genesis,
        check_tx_flags: AgendaFlags::default(),
    }));
    let frame = read_server_frame(&mut ws);
    assert!(frame.contains("\"method\":\"blockconnected\""), "{frame}");

    // A new-tickets event follows the same path.
    handler.handle(&Notification::NewTickets(TicketNotificationsData {
        hash: genesis.header.block_hash(),
        height: 1,
        stake_difficulty: 20000,
        tickets_new: vec![Hash([0x11; 32])],
    }));
    let frame = read_server_frame(&mut ws);
    assert!(frame.contains("\"method\":\"newtickets\""), "{frame}");

    // A gate-passing accepted block queues its winning-tickets
    // lookup; the drain runs it against the chain, and the unknown
    // block's failed lookup is skipped without a notification.
    let mut accepted = params.genesis_block.clone();
    accepted.header.height = (params.stake_validation_height - 1) as u32;
    accepted.header.version = 11;
    handler.handle(&Notification::BlockAccepted(BlockAcceptedNtfnsData {
        best_height: params.stake_validation_height - 1,
        fork_len: 0,
        block: &accepted,
    }));
    // The connected block queued its mempool maintenance; draining it
    // over the empty pool is a no-op that must not disturb anything.
    handler.drain_pending_block_events();
    handler.drain_pending_winning_tickets(&chain, 2_000_000_000);
    ws.set_read_timeout(Some(std::time::Duration::from_millis(300)))
        .expect("set timeout");
    let mut probe = [0u8; 1];
    assert!(
        ws.read(&mut probe).is_err(),
        "a failed lottery lookup must not notify"
    );

    listener.shutdown();
}

#[test]
fn a_command_before_authenticate_drops_the_connection() {
    let (_dir, listener, port, _ntfn, _chain) = serve_ws();
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
    let (_dir, listener, port, _ntfn, _chain) = serve_ws();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    // Missing Sec-WebSocket-Version.
    let request = "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n\r\n";
    stream.write_all(request.as_bytes()).expect("write");
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");

    listener.shutdown();
}
