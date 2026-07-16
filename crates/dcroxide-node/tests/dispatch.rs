// SPDX-License-Identifier: ISC
//! End-to-end checks for the server-handler dispatch: a genesis chain
//! served through the full listener runtime answers a connected peer's
//! getheaders, getblocks, and getdata requests through the chain-backed
//! handlers, and the getdata intake gates drop an abusive peer.

use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dcroxide_blockchain::process::Chain;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_node::dispatch::ServerContext;
use dcroxide_node::peerconn::NodePeerEnv;
use dcroxide_node::runtime::{ConnectedPeers, ListenerRuntime, PeerTemplate, inbound_peer_handler};
use dcroxide_node::transport::WireTransport;
use dcroxide_peer::{Config, MAX_PROTOCOL_VERSION, MsgTransport, Peer, PeerGlobals};
use dcroxide_wire::{
    BlockLocator, CurrencyNet, InvType, InvVect, Message, MsgGetData, MsgGetHeaders, ServiceFlag,
};

const NET: CurrencyNet = CurrencyNet::TEST_NET3;

/// Bring up a genesis-state testnet chain in a temporary database and
/// serve it through the listener runtime, returning the runtime, the
/// registry, and a negotiated client transport talking to it.
fn serve_genesis_chain() -> (
    tempfile::TempDir,
    ListenerRuntime,
    ConnectedPeers,
    WireTransport<TcpStream>,
    Hash,
    Arc<Mutex<dcroxide_addrmgr::AddrManager>>,
) {
    let params = dcroxide_chaincfg::testnet3_params();
    let genesis_hash = params.genesis_hash;

    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));

    let addr_manager = Arc::new(Mutex::new(dcroxide_addrmgr::AddrManager::new(dir.path())));
    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    );
    let server = Arc::new(ServerContext {
        chain: Arc::clone(&chain),
        min_known_work: params.min_known_chain_work,
        params: params.clone(),
        disable_banning: false,
        ban_threshold: 100,
        whitelists: Vec::new(),
        addr_manager: Arc::clone(&addr_manager),
        sim_or_reg_net: false,
        stake_validation_height: params.stake_validation_height,
        blocks_only: false,
        sync_manager: Arc::new(Mutex::new(dcroxide_node::sync::new_sync_manager(
            Arc::clone(&chain),
            &params,
            false,
            8,
            1000,
            Arc::clone(&tx_pool),
            dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone()),
        ))),
        sync_peers: dcroxide_node::dispatch::SyncPeers::new(),
        next_peer_id: std::sync::atomic::AtomicI32::new(1),
        outbound_groups: dcroxide_node::dispatch::OutboundGroups::new(),
        net_totals: std::sync::Arc::new(dcroxide_node::transport::NetByteTotals::new()),
        disable_listen: false,
        tx_pool: Arc::clone(&tx_pool),
        ntfn: None,
        recently_advertised: dcroxide_node::dispatch::new_recently_advertised(),

        mix_pool: dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone()),
    });

    let template = PeerTemplate {
        net: NET,
        protocol_version: 0,
        services: ServiceFlag(1),
        user_agent_name: "dcroxide".to_string(),
        user_agent_version: "0.1.0".to_string(),
        idle_timeout: Duration::from_secs(3600),
        ping_interval: Duration::from_secs(3600),
    };
    let connected = ConnectedPeers::new();
    let runtime = ListenerRuntime::start(
        &[("tcp4", ":0".to_string())],
        inbound_peer_handler(template, connected.clone(), Some(server), 0),
    )
    .expect("start serving runtime");
    let port = runtime.bound_addrs()[0].port();

    // Connect as an outbound peer and complete the handshake.
    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to the server");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut transport = WireTransport::new(stream, MAX_PROTOCOL_VERSION, NET);
    let mut env = NodePeerEnv::new();
    let mut globals = PeerGlobals::new();
    let config = Config {
        net: NET,
        protocol_version: 0,
        ..Config::default()
    };
    let mut peer = Peer::new_outbound(config, &format!("127.0.0.1:{port}")).expect("outbound");
    peer.negotiate_outbound_protocol(&mut transport, &mut env, &mut globals)
        .expect("negotiate");
    transport
        .write_message(&Message::VerAck)
        .expect("send verack");
    assert_eq!(
        transport.read_message().expect("read verack"),
        Message::VerAck
    );

    (
        dir,
        runtime,
        connected,
        transport,
        genesis_hash,
        addr_manager,
    )
}

/// A block locator anchored at the given hash.
fn locator(hash: Hash) -> BlockLocator {
    BlockLocator {
        protocol_version: MAX_PROTOCOL_VERSION,
        block_locator_hashes: vec![hash],
        hash_stop: Hash([0u8; 32]),
    }
}

/// getheaders at the genesis tip answers with a headers message; the
/// testnet minimum known chain work far exceeds the genesis tip's, so
/// the low-work gate makes it the empty message (dcrd sends it rather
/// than appearing unresponsive), and getdata serves the genesis block
/// from the chain while misses accumulate into notfound.
#[test]
fn serves_chain_backed_requests() {
    let (_dir, runtime, _connected, mut transport, genesis_hash, _addrmgr) = serve_genesis_chain();

    // getheaders -> an empty headers message via the low-work gate.
    transport
        .write_message(&Message::GetHeaders(MsgGetHeaders(locator(genesis_hash))))
        .expect("send getheaders");
    match transport.read_message().expect("read headers") {
        Message::Headers(headers) => assert!(
            headers.headers.is_empty(),
            "a genesis tip is below testnet's min known work"
        ),
        other => panic!("expected headers, got {other:?}"),
    }

    // getdata for the genesis block -> the block itself.
    let genesis_iv = InvVect {
        inv_type: InvType::BLOCK,
        hash: genesis_hash,
    };
    transport
        .write_message(&Message::GetData(MsgGetData {
            inv_list: vec![genesis_iv],
        }))
        .expect("send getdata");
    match transport.read_message().expect("read block") {
        Message::Block(block) => assert_eq!(
            block.header.block_hash(),
            genesis_hash,
            "the served block should be the genesis block"
        ),
        other => panic!("expected block, got {other:?}"),
    }

    // getdata for an unknown block and a transaction -> one notfound
    // consolidating both misses (no mempool is wired, matching an
    // empty pool).
    let unknown_block = InvVect {
        inv_type: InvType::BLOCK,
        hash: Hash([0x55; 32]),
    };
    let unknown_tx = InvVect {
        inv_type: InvType::TX,
        hash: Hash([0x66; 32]),
    };
    transport
        .write_message(&Message::GetData(MsgGetData {
            inv_list: vec![unknown_block, unknown_tx],
        }))
        .expect("send getdata");
    match transport.read_message().expect("read notfound") {
        Message::NotFound(not_found) => {
            assert_eq!(not_found.inv_list, vec![unknown_block, unknown_tx]);
        }
        other => panic!("expected notfound, got {other:?}"),
    }

    drop(transport);
    runtime.shutdown();
}

/// getdata for a mix message the pool does not hold misses into a
/// notfound, exactly as dcrd resolves a getdata MIX inv against its
/// empty `mixMsgPool` (the daemon shares one pool between this serve
/// path and the netsync intake).
#[test]
fn serves_notfound_for_an_absent_mix_message() {
    let (_dir, runtime, _connected, mut transport, _genesis_hash, _addrmgr) = serve_genesis_chain();

    let unknown_mix = InvVect {
        inv_type: InvType::MIX,
        hash: Hash([0x77; 32]),
    };
    transport
        .write_message(&Message::GetData(MsgGetData {
            inv_list: vec![unknown_mix],
        }))
        .expect("send getdata for a mix message");
    match transport.read_message().expect("read notfound") {
        Message::NotFound(not_found) => {
            assert_eq!(not_found.inv_list, vec![unknown_mix]);
        }
        other => panic!("expected notfound, got {other:?}"),
    }

    drop(transport);
    runtime.shutdown();
}

/// An empty getdata request is a bannable offense: the server drops
/// the connection (dcrd bans and disconnects).
#[test]
fn an_empty_getdata_disconnects_the_peer() {
    let (_dir, runtime, connected, mut transport, _genesis_hash, _addrmgr) = serve_genesis_chain();

    transport
        .write_message(&Message::GetData(MsgGetData { inv_list: vec![] }))
        .expect("send empty getdata");

    // The server disconnects; the next read observes the closed
    // connection rather than a reply.
    assert!(
        transport.read_message().is_err(),
        "the connection should be dropped"
    );
    // The registry drains as the serving thread winds down.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !connected.is_empty() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(connected.is_empty(), "the served peer should deregister");

    runtime.shutdown();
}

/// The addr exchange: a getaddr from an inbound peer is answered with
/// a subset of the address cache, an advertised addr list lands in the
/// address manager, and an empty addr list drops the connection.
#[test]
fn exchanges_addresses_with_a_served_peer() {
    let (_dir, runtime, _connected, mut transport, _genesis_hash, addr_manager) =
        serve_genesis_chain();

    // Seed the manager with routable addresses so the cache subset is
    // non-empty (the 23% cache cap rounds small pools down).
    let now_nanos = dcroxide_peer::PeerEnv::now_nanos(&mut NodePeerEnv::new());
    {
        let mut mgr = addr_manager.lock().expect("addrmgr");
        let source = wire_na([8, 8, 4, 4], 9108, now_nanos);
        for i in 1..=20u8 {
            let na =
                dcroxide_node::wire_to_addrmgr_net_address(&wire_na([8, 8, 8, i], 9108, now_nanos));
            mgr.add_addresses(
                std::slice::from_ref(&na),
                &dcroxide_node::wire_to_addrmgr_net_address(&source),
            );
            // The cache only serves addresses that have succeeded.
            mgr.good(&na).expect("mark good");
        }
    }

    transport
        .write_message(&Message::GetAddr)
        .expect("send getaddr");
    match transport.read_message().expect("read addr") {
        Message::Addr(addr) => assert!(
            !addr.addr_list.is_empty(),
            "the cache subset should contain seeded addresses"
        ),
        other => panic!("expected addr, got {other:?}"),
    }

    // An advertised address is forwarded into the manager.
    let advertised =
        dcroxide_node::wire_to_addrmgr_net_address(&wire_na([8, 8, 6, 6], 9108, now_nanos));
    transport
        .write_message(&Message::Addr(dcroxide_wire::MsgAddr {
            addr_list: vec![wire_na([8, 8, 6, 6], 9108, now_nanos)],
        }))
        .expect("send addr");

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut known = false;
    while !known && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
        known = addr_manager
            .lock()
            .expect("addrmgr")
            .known_address(&advertised.key())
            .is_some();
    }
    assert!(known, "the advertised address should be added");

    // An empty addr list is a bannable offense; the server disconnects.
    transport
        .write_message(&Message::Addr(dcroxide_wire::MsgAddr { addr_list: vec![] }))
        .expect("send empty addr");
    assert!(
        transport.read_message().is_err(),
        "the connection should be dropped"
    );

    runtime.shutdown();
}

/// An IPv4 wire net address with the given timestamp.
fn wire_na(ip: [u8; 4], port: u16, now_nanos: i64) -> dcroxide_wire::NetAddress {
    let mut ip16 = [0u8; 16];
    ip16[10] = 0xff;
    ip16[11] = 0xff;
    ip16[12..16].copy_from_slice(&ip);
    dcroxide_wire::NetAddress {
        timestamp: (now_nanos / 1_000_000_000) as u32,
        services: ServiceFlag(1),
        ip: ip16,
        port,
    }
}

/// The committed-filter and init-state handlers: getcfilterv2 serves
/// the genesis block's version 2 filter with its inclusion proof,
/// getcfsv2 serves the one-block batch, and getinitstate answers the
/// pre-stake-validation chain with the empty message exactly once per
/// connection.
#[test]
fn serves_cfilters_and_init_state() {
    let (_dir, runtime, _connected, mut transport, genesis_hash, _addrmgr) = serve_genesis_chain();

    // getcfilterv2 for the genesis block.
    transport
        .write_message(&Message::GetCFilterV2(dcroxide_wire::MsgGetCFilterV2 {
            block_hash: genesis_hash,
        }))
        .expect("send getcfilterv2");
    match transport.read_message().expect("read cfilterv2") {
        Message::CFilterV2(cf) => assert_eq!(cf.block_hash, genesis_hash),
        other => panic!("expected cfilterv2, got {other:?}"),
    }

    // getcfsv2 over the single-block genesis range.
    transport
        .write_message(&Message::GetCFsV2(dcroxide_wire::MsgGetCFsV2 {
            start_hash: genesis_hash,
            end_hash: genesis_hash,
        }))
        .expect("send getcfsv2");
    match transport.read_message().expect("read cfiltersv2") {
        Message::CFiltersV2(cfs) => {
            assert_eq!(cfs.cfilters.len(), 1);
            assert_eq!(cfs.cfilters[0].block_hash, genesis_hash);
        }
        other => panic!("expected cfiltersv2, got {other:?}"),
    }

    // getinitstate before stake validation answers with the empty
    // message; a repeat on the same connection is ignored, so the
    // following ping is answered next.
    transport
        .write_message(&Message::GetInitState(dcroxide_wire::MsgGetInitState {
            types: vec![
                dcroxide_wire::INIT_STATE_HEAD_BLOCKS.to_string(),
                dcroxide_wire::INIT_STATE_HEAD_BLOCK_VOTES.to_string(),
                dcroxide_wire::INIT_STATE_TSPENDS.to_string(),
            ],
        }))
        .expect("send getinitstate");
    match transport.read_message().expect("read initstate") {
        Message::InitState(init) => {
            assert!(init.block_hashes.is_empty());
            assert!(init.vote_hashes.is_empty());
            assert!(init.tspend_hashes.is_empty());
        }
        other => panic!("expected initstate, got {other:?}"),
    }
    transport
        .write_message(&Message::GetInitState(dcroxide_wire::MsgGetInitState {
            types: vec![dcroxide_wire::INIT_STATE_HEAD_BLOCKS.to_string()],
        }))
        .expect("send second getinitstate");
    transport
        .write_message(&Message::Ping(dcroxide_wire::MsgPing { nonce: 7 }))
        .expect("send ping");
    match transport.read_message().expect("read pong") {
        Message::Pong(pong) => assert_eq!(pong.nonce, 7, "the repeat getinitstate is ignored"),
        other => panic!("expected pong, got {other:?}"),
    }

    // getminingstate early in the chain sends nothing at all — dcrd's
    // blank pushMiningStateMsg aborts on zero blocks (unlike the empty
    // initstate above) — so the next reply is the pong.
    transport
        .write_message(&Message::GetMiningState)
        .expect("send getminingstate");
    transport
        .write_message(&Message::Ping(dcroxide_wire::MsgPing { nonce: 8 }))
        .expect("send ping");
    match transport.read_message().expect("read pong") {
        Message::Pong(pong) => assert_eq!(
            pong.nonce, 8,
            "an early-chain getminingstate produces no reply"
        ),
        other => panic!("expected pong, got {other:?}"),
    }

    // A miningstate advertisement requests the unknown blocks through
    // the sync manager (dcrd `OnMiningState` -> `RequestFromPeer`).
    let advertised = Hash([0x5a; 32]);
    transport
        .write_message(&Message::MiningState(dcroxide_wire::MsgMiningState {
            version: 1,
            height: 1,
            block_hashes: vec![advertised],
            vote_hashes: Vec::new(),
        }))
        .expect("send miningstate");
    match transport.read_message().expect("read getdata") {
        Message::GetData(getdata) => {
            assert_eq!(getdata.inv_list.len(), 1);
            assert_eq!(getdata.inv_list[0].hash, advertised);
            assert_eq!(getdata.inv_list[0].inv_type, dcroxide_wire::InvType::BLOCK);
        }
        other => panic!("expected getdata for the advertised block, got {other:?}"),
    }

    drop(transport);
    runtime.shutdown();
}

/// The inventory intake gates: a block announcement passes through
/// (the sync-manager forward is a later piece, so the connection just
/// stays up), and an empty announcement drops the connection.
#[test]
fn gates_inventory_announcements() {
    let (_dir, runtime, _connected, mut transport, genesis_hash, _addrmgr) = serve_genesis_chain();

    // A block announcement passes the gate; the connection stays
    // healthy, verified by a following ping.
    transport
        .write_message(&Message::Inv(dcroxide_wire::MsgInv {
            inv_list: vec![InvVect {
                inv_type: InvType::BLOCK,
                hash: genesis_hash,
            }],
        }))
        .expect("send inv");
    transport
        .write_message(&Message::Ping(dcroxide_wire::MsgPing { nonce: 9 }))
        .expect("send ping");
    match transport.read_message().expect("read pong") {
        Message::Pong(pong) => assert_eq!(pong.nonce, 9),
        other => panic!("expected pong, got {other:?}"),
    }

    // An empty announcement is a bannable offense; the server
    // disconnects.
    transport
        .write_message(&Message::Inv(dcroxide_wire::MsgInv { inv_list: vec![] }))
        .expect("send empty inv");
    assert!(
        transport.read_message().is_err(),
        "the connection should be dropped"
    );

    runtime.shutdown();
}

/// The sync-manager driver milestone: a data-serving peer connecting to
/// a stale chain is picked as the header-sync peer, and the daemon
/// initiates the sync by sending getheaders right after the handshake
/// (dcrd `OnPeerConnected` starting the initial header sync).
#[test]
fn initiates_header_sync_with_a_data_serving_peer() {
    let params = dcroxide_chaincfg::testnet3_params();
    let genesis_hash = params.genesis_hash;

    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    );
    let server = Arc::new(ServerContext {
        chain: Arc::clone(&chain),
        min_known_work: params.min_known_chain_work,
        params: params.clone(),
        disable_banning: false,
        ban_threshold: 100,
        whitelists: Vec::new(),
        addr_manager: Arc::new(Mutex::new(dcroxide_addrmgr::AddrManager::new(dir.path()))),
        sim_or_reg_net: false,
        stake_validation_height: params.stake_validation_height,
        blocks_only: false,
        sync_manager: Arc::new(Mutex::new(dcroxide_node::sync::new_sync_manager(
            Arc::clone(&chain),
            &params,
            false,
            8,
            1000,
            Arc::clone(&tx_pool),
            dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone()),
        ))),
        sync_peers: dcroxide_node::dispatch::SyncPeers::new(),
        next_peer_id: std::sync::atomic::AtomicI32::new(1),
        outbound_groups: dcroxide_node::dispatch::OutboundGroups::new(),
        net_totals: std::sync::Arc::new(dcroxide_node::transport::NetByteTotals::new()),
        disable_listen: false,
        tx_pool: Arc::clone(&tx_pool),
        ntfn: None,
        recently_advertised: dcroxide_node::dispatch::new_recently_advertised(),

        mix_pool: dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone()),
    });
    let template = PeerTemplate {
        net: NET,
        protocol_version: 0,
        services: ServiceFlag(1),
        user_agent_name: "dcroxide".to_string(),
        user_agent_version: "0.1.0".to_string(),
        idle_timeout: Duration::from_secs(3600),
        ping_interval: Duration::from_secs(3600),
    };
    let connected = ConnectedPeers::new();
    let runtime = ListenerRuntime::start(
        &[("tcp4", ":0".to_string())],
        inbound_peer_handler(template, connected.clone(), Some(server), 0),
    )
    .expect("start serving runtime");
    let port = runtime.bound_addrs()[0].port();

    // Connect advertising NODE_NETWORK so the daemon selects this peer
    // for its initial header sync.
    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut transport = WireTransport::new(stream, MAX_PROTOCOL_VERSION, NET);
    let mut env = NodePeerEnv::new();
    let mut globals = PeerGlobals::new();
    let config = Config {
        net: NET,
        protocol_version: 0,
        services: ServiceFlag::NODE_NETWORK,
        ..Config::default()
    };
    let mut peer = Peer::new_outbound(config, &format!("127.0.0.1:{port}")).expect("outbound");
    peer.negotiate_outbound_protocol(&mut transport, &mut env, &mut globals)
        .expect("negotiate");
    transport
        .write_message(&Message::VerAck)
        .expect("send verack");

    // The daemon initiates the header sync: among the first messages
    // after the handshake is a getheaders anchored at the genesis tip.
    let mut saw_getheaders = false;
    for _ in 0..4 {
        match transport.read_message() {
            Ok(Message::GetHeaders(get)) => {
                assert_eq!(get.0.block_locator_hashes.first(), Some(&genesis_hash));
                saw_getheaders = true;
                break;
            }
            Ok(_) => continue,
            Err(e) => panic!("expected getheaders, got read error {e}"),
        }
    }
    assert!(saw_getheaders, "the daemon should initiate the header sync");

    drop(transport);
    runtime.shutdown();
}

/// The header-sync stall watchdog: a data-serving peer is chosen as
/// the sync peer and sent getheaders, never answers, and is
/// disconnected when the stall timeout fires (dcrd\'s stallHandler
/// timer case).
#[test]
fn disconnects_a_stalled_header_sync_peer() {
    let params = dcroxide_chaincfg::testnet3_params();

    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    let sync_peers = dcroxide_node::dispatch::SyncPeers::new();
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
    // A short stall timeout so the test observes the watchdog firing.
    let stall_timer = dcroxide_node::dispatch::start_stall_timer(
        Arc::clone(&sync_manager),
        sync_peers.clone(),
        Duration::from_millis(300),
    );
    let server = Arc::new(ServerContext {
        chain: Arc::clone(&chain),
        min_known_work: params.min_known_chain_work,
        params: params.clone(),
        disable_banning: false,
        ban_threshold: 100,
        whitelists: Vec::new(),
        addr_manager: Arc::new(Mutex::new(dcroxide_addrmgr::AddrManager::new(dir.path()))),
        sim_or_reg_net: false,
        stake_validation_height: params.stake_validation_height,
        blocks_only: false,
        sync_manager,
        sync_peers,
        next_peer_id: std::sync::atomic::AtomicI32::new(1),
        outbound_groups: dcroxide_node::dispatch::OutboundGroups::new(),
        net_totals: std::sync::Arc::new(dcroxide_node::transport::NetByteTotals::new()),
        disable_listen: false,
        tx_pool: Arc::clone(&tx_pool),
        ntfn: None,
        recently_advertised: dcroxide_node::dispatch::new_recently_advertised(),

        mix_pool: dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone()),
    });
    let template = PeerTemplate {
        net: NET,
        protocol_version: 0,
        services: ServiceFlag(1),
        user_agent_name: "dcroxide".to_string(),
        user_agent_version: "0.1.0".to_string(),
        idle_timeout: Duration::from_secs(3600),
        ping_interval: Duration::from_secs(3600),
    };
    let connected = ConnectedPeers::new();
    let runtime = ListenerRuntime::start(
        &[("tcp4", ":0".to_string())],
        inbound_peer_handler(template, connected.clone(), Some(server), 0),
    )
    .expect("start serving runtime");
    let port = runtime.bound_addrs()[0].port();

    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut transport = WireTransport::new(stream, MAX_PROTOCOL_VERSION, NET);
    let mut env = NodePeerEnv::new();
    let mut globals = PeerGlobals::new();
    let config = Config {
        net: NET,
        protocol_version: 0,
        services: ServiceFlag::NODE_NETWORK,
        ..Config::default()
    };
    let mut peer = Peer::new_outbound(config, &format!("127.0.0.1:{port}")).expect("outbound");
    peer.negotiate_outbound_protocol(&mut transport, &mut env, &mut globals)
        .expect("negotiate");
    transport
        .write_message(&Message::VerAck)
        .expect("send verack");

    // The daemon initiates the header sync, then this peer stalls: it
    // never answers the getheaders, so the watchdog disconnects it and
    // the reads run out with a closed connection.
    let mut disconnected = false;
    for _ in 0..8 {
        match transport.read_message() {
            Ok(_) => continue,
            Err(_) => {
                disconnected = true;
                break;
            }
        }
    }
    assert!(disconnected, "the stalled sync peer should be disconnected");

    stall_timer.shutdown();
    runtime.shutdown();
}

/// The mempool serving arms: a mempool request over an empty pool
/// queues no inventory (dcrd sends nothing when there is nothing to
/// announce), a getdata for an unknown transaction answers notfound
/// from the empty pool, and the connection keeps serving afterwards.
#[test]
fn serves_mempool_requests_over_the_empty_pool() {
    let (_dir, runtime, _connected, mut transport, _genesis_hash, _addrmgr) = serve_genesis_chain();

    // A mempool request over an empty pool queues nothing; prove the
    // arm ran and the connection survived with a ping round trip.
    transport
        .write_message(&Message::MemPool)
        .expect("send mempool");
    transport
        .write_message(&Message::Ping(dcroxide_wire::MsgPing { nonce: 41 }))
        .expect("send ping");
    match transport.read_message().expect("read pong") {
        Message::Pong(pong) => assert_eq!(pong.nonce, 41),
        other => panic!("expected pong, got {other:?}"),
    }

    // A getdata for an unknown transaction resolves against the pool
    // and answers notfound.
    let unknown_tx = InvVect {
        inv_type: InvType::TX,
        hash: dcroxide_chainhash::Hash([0x42; 32]),
    };
    transport
        .write_message(&Message::GetData(MsgGetData {
            inv_list: vec![unknown_tx],
        }))
        .expect("send getdata");
    match transport.read_message().expect("read notfound") {
        Message::NotFound(notfound) => {
            assert_eq!(notfound.inv_list.len(), 1);
            assert_eq!(
                notfound.inv_list[0].hash,
                dcroxide_chainhash::Hash([0x42; 32])
            );
        }
        other => panic!("expected notfound, got {other:?}"),
    }

    runtime.shutdown();
}

/// A regnet daemon over dcrd's full-block battery announces connected
/// blocks to its served peers: as an inventory by default, and as the
/// header itself once the peer sends sendheaders (dcrd's
/// `RelayBlockAnnouncement` from the accepted case, with unsynced
/// mining allowed since the battery chain's timestamps are stale).
#[test]
fn announces_connected_blocks_to_served_peers() {
    let params = dcroxide_chaincfg::regnet_params();
    let net = params.net;

    // The linear accepted main-chain prefix of the battery.
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcroxide-blockchain/tests/data/fullblock_vectors.txt"
    );
    let data = std::fs::read_to_string(path).expect("fullblock vectors");
    let mut tip = params.genesis_hash;
    let mut blocks = Vec::new();
    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        // accept <name> <mainchain> <orphan> <blockhex>
        if f[0] != "accept" {
            continue;
        }
        let (block, _) =
            dcroxide_wire::MsgBlock::from_bytes(&dcroxide_testutil::unhex(f[4])).expect("block");
        if f[2] != "true" || block.header.prev_block != tip {
            continue;
        }
        tip = block.header.block_hash();
        blocks.push(block);
        if blocks.len() == 2 {
            break;
        }
    }
    assert_eq!(blocks.len(), 2, "battery must provide two blocks");

    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    let addr_manager = Arc::new(Mutex::new(dcroxide_addrmgr::AddrManager::new(dir.path())));
    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    );
    let sync_peers = dcroxide_node::dispatch::SyncPeers::new();
    let server = Arc::new(ServerContext {
        chain: Arc::clone(&chain),
        min_known_work: params.min_known_chain_work,
        params: params.clone(),
        disable_banning: false,
        ban_threshold: 100,
        whitelists: Vec::new(),
        addr_manager,
        sim_or_reg_net: true,
        stake_validation_height: params.stake_validation_height,
        blocks_only: false,
        sync_manager: Arc::new(Mutex::new(dcroxide_node::sync::new_sync_manager(
            Arc::clone(&chain),
            &params,
            false,
            8,
            1000,
            Arc::clone(&tx_pool),
            dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone()),
        ))),
        sync_peers: sync_peers.clone(),
        next_peer_id: std::sync::atomic::AtomicI32::new(1),
        outbound_groups: dcroxide_node::dispatch::OutboundGroups::new(),
        net_totals: std::sync::Arc::new(dcroxide_node::transport::NetByteTotals::new()),
        disable_listen: false,
        tx_pool: Arc::clone(&tx_pool),
        ntfn: None,
        recently_advertised: dcroxide_node::dispatch::new_recently_advertised(),

        mix_pool: dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone()),
    });

    // The daemon's chain handler wiring: the callback queues the
    // announcements and the sync chain drains them into the fan-out
    // (unsynced mining allowed so the stale battery chain announces).
    let handler = dcroxide_node::chainntfns::ChainNtfnHandler::new(
        None,
        params.clone(),
        true,
        Arc::clone(&tx_pool),
        sync_peers.clone(),
        dcroxide_node::dispatch::new_recently_advertised(),
    );
    {
        let callback_handler = handler.clone();
        chain
            .lock()
            .expect("chain")
            .set_notification_callback(Box::new(move |n| callback_handler.handle(n)));
    }
    let mut sync_chain =
        dcroxide_node::sync::NodeSyncChain::new(Arc::clone(&chain), params.clone());
    sync_chain.set_chain_ntfn_handler(handler);

    let template = PeerTemplate {
        net,
        protocol_version: 0,
        services: ServiceFlag(1),
        user_agent_name: "dcroxide".to_string(),
        user_agent_version: "0.1.0".to_string(),
        idle_timeout: Duration::from_secs(3600),
        ping_interval: Duration::from_secs(3600),
    };
    let connected = ConnectedPeers::new();
    let runtime = ListenerRuntime::start(
        &[("tcp4", ":0".to_string())],
        inbound_peer_handler(template, connected.clone(), Some(server), 0),
    )
    .expect("start serving runtime");
    let port = runtime.bound_addrs()[0].port();

    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to the server");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut transport = WireTransport::new(stream, MAX_PROTOCOL_VERSION, net);
    let mut env = NodePeerEnv::new();
    let mut globals = PeerGlobals::new();
    let config = Config {
        net,
        protocol_version: 0,
        ..Config::default()
    };
    let mut peer = Peer::new_outbound(config, &format!("127.0.0.1:{port}")).expect("outbound");
    peer.negotiate_outbound_protocol(&mut transport, &mut env, &mut globals)
        .expect("negotiate");
    transport
        .write_message(&Message::VerAck)
        .expect("send verack");
    assert_eq!(
        transport.read_message().expect("read verack"),
        Message::VerAck
    );

    // A ping round trip guarantees the served peer is registered with
    // the relay before the first block connects.
    transport
        .write_message(&Message::Ping(dcroxide_wire::MsgPing { nonce: 7 }))
        .expect("send ping");
    assert_eq!(
        transport.read_message().expect("read pong"),
        Message::Pong(dcroxide_wire::MsgPong { nonce: 7 })
    );

    // The first connected block announces as an inventory.
    let fork_len = dcroxide_netsync::manager::SyncChain::process_block(&mut sync_chain, &blocks[0])
        .expect("first block accepts");
    assert_eq!(fork_len, 0);
    match transport.read_message().expect("read announcement") {
        Message::Inv(msg) => assert_eq!(
            msg.inv_list,
            vec![dcroxide_wire::InvVect {
                inv_type: dcroxide_wire::InvType::BLOCK,
                hash: blocks[0].header.block_hash(),
            }]
        ),
        other => panic!("expected block inv, got {other:?}"),
    }

    // After sendheaders the next block announces as the header itself.
    transport
        .write_message(&Message::SendHeaders)
        .expect("send sendheaders");
    transport
        .write_message(&Message::Ping(dcroxide_wire::MsgPing { nonce: 8 }))
        .expect("send ping");
    assert_eq!(
        transport.read_message().expect("read pong"),
        Message::Pong(dcroxide_wire::MsgPong { nonce: 8 })
    );
    dcroxide_netsync::manager::SyncChain::process_block(&mut sync_chain, &blocks[1])
        .expect("second block accepts");
    match transport.read_message().expect("read headers announcement") {
        Message::Headers(msg) => assert_eq!(msg.headers, vec![blocks[1].header]),
        other => panic!("expected headers, got {other:?}"),
    }

    runtime.shutdown();
}
