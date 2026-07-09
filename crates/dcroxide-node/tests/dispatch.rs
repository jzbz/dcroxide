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
) {
    let params = dcroxide_chaincfg::testnet3_params();
    let genesis_hash = params.genesis_hash;

    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain");

    let server = Arc::new(ServerContext {
        chain: Arc::new(Mutex::new(chain)),
        min_known_work: params.min_known_chain_work,
        disable_banning: false,
        ban_threshold: 100,
        whitelists: Vec::new(),
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
        inbound_peer_handler(template, connected.clone(), Some(server)),
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

    (dir, runtime, connected, transport, genesis_hash)
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
    let (_dir, runtime, _connected, mut transport, genesis_hash) = serve_genesis_chain();

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

/// An empty getdata request is a bannable offense: the server drops
/// the connection (dcrd bans and disconnects).
#[test]
fn an_empty_getdata_disconnects_the_peer() {
    let (_dir, runtime, connected, mut transport, _genesis_hash) = serve_genesis_chain();

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
