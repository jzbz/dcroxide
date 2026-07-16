// SPDX-License-Identifier: ISC
//! The RPC control and chain-query seam batch over the live listener: a
//! regnet chain built from dcrd's own full-block battery backs the
//! filter and sanity seams, a live address manager backs the network
//! info, and a recording shutdown hook backs `stop` — so `getcfilterv2`
//! answers the committed filter, `verifychain` runs the ported block
//! sanity checks, `getnetworkinfo` reports the local addresses and the
//! configured network reachability, and `stop` fires the graceful
//! shutdown, each over the same HTTP JSON-RPC path a client uses.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use dcroxide_addrmgr::{AddrManager, AddressPriority, NetAddress, NetAddressType};
use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};
use dcroxide_node::rpcrun::{
    IdleCpuMiner, NodeRpcAddrManager, NodeRpcChain, NodeRpcConnManager, NodeRpcFiltererV2,
    NodeRpcSanityChecker, NodeRpcSyncManager, start_rpc_listener,
};
use dcroxide_node::runtime::ConnectedPeers;
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::server::{Config, RpcNetworkInfo, RpcSanityChecker, RpcSubsidyParams, Server};
use dcroxide_standalone::SubsidyCache;
use dcroxide_testutil::unhex;
use dcroxide_wire::{MsgBlock, PROTOCOL_VERSION, ServiceFlag};

/// The leading consecutive main-chain prefix of accepted blocks from
/// dcrd's `fullblocktests.Generate` battery, with the generation time.
fn accepted_prefix(limit: usize) -> (i64, Vec<MsgBlock>) {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcroxide-blockchain/tests/data/fullblock_vectors.txt"
    );
    let data = std::fs::read_to_string(path).expect("fullblock vectors");
    let mut now: i64 = 0;
    let mut tip = dcroxide_chaincfg::regnet_params().genesis_hash;
    let mut blocks = Vec::new();
    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("generation time"),
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                if f[2] != "true" || block.header.prev_block != tip {
                    continue;
                }
                tip = block.header.block_hash();
                blocks.push(block);
                if blocks.len() == limit {
                    break;
                }
            }
            _ => {}
        }
    }
    assert_eq!(blocks.len(), limit, "battery must provide the prefix");
    (now, blocks)
}

/// A regnet chain with the first `history` accepted battery blocks
/// connected.
fn regnet_chain(history: usize) -> (tempfile::TempDir, Arc<Mutex<Chain>>) {
    let params = dcroxide_chaincfg::regnet_params();
    let (now, blocks) = accepted_prefix(history);
    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    for block in &blocks {
        let (_, errs) = chain
            .lock()
            .expect("chain")
            .process_block(block, now, &params);
        assert!(errs.is_empty(), "battery block must accept: {errs:?}");
    }
    (dir, chain)
}

fn shared_tx_pool(chain: &Arc<Mutex<Chain>>) -> Arc<Mutex<dcroxide_node::txmempool::NodeTxPool>> {
    let params = dcroxide_chaincfg::regnet_params();
    dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    )
}

/// A lowercase hex rendering matching the RPC handler's `hex_str`.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Post an authenticated JSON-RPC request over plain HTTP and return the
/// raw response.
fn post(port: u16, body: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let auth = format!(
        "Authorization: Basic {}\r\n",
        dcroxide_rpc::http::base64_std_encode(b"user:pass")
    );
    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    response
}

/// `getcfilterv2`, `verifychain`, `getnetworkinfo`, and `stop` all answer
/// over the live listener with the four newly-wired seams.
#[test]
fn control_and_chain_query_seams_over_http() {
    let params = dcroxide_chaincfg::regnet_params();
    let (_dir, chain) = regnet_chain(2);
    let tx_pool = shared_tx_pool(&chain);
    let sync_manager = Arc::new(Mutex::new(dcroxide_node::sync::new_sync_manager(
        Arc::clone(&chain),
        &params,
        false,
        8,
        1000,
        Arc::clone(&tx_pool),
        dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone()),
    )));

    // An address manager holding one routable local address, so the
    // getnetworkinfo seam reports a non-empty local address set.
    let am_dir = tempfile::tempdir().expect("temp dir");
    let addr_manager = {
        let mut am = AddrManager::new(am_dir.path());
        let na = NetAddress {
            addr_type: NetAddressType::IPv4,
            ip: vec![8, 8, 8, 8],
            port: 9108,
            timestamp: 0,
            services: ServiceFlag::NODE_NETWORK,
        };
        am.add_local_address(&na, AddressPriority::Manual)
            .expect("add local address");
        Arc::new(Mutex::new(am))
    };

    // The stop seam records that a graceful shutdown was requested.
    let shutdown_requested = Arc::new(AtomicBool::new(false));
    let request_shutdown: Box<dyn FnMut() + Send> = {
        let flag = Arc::clone(&shutdown_requested);
        Box::new(move || flag.store(true, Ordering::SeqCst))
    };

    // The committed filter for the tip, read straight from the chain, is
    // what the getcfilterv2 seam must return.
    let (tip_hash, expected_filter_hex) = {
        let chain = chain.lock().expect("chain");
        let hash = chain.best_snapshot().hash;
        let (filter, _proof) = chain.filter_by_block_hash(&hash).expect("tip filter");
        (hash, to_hex(filter.bytes()))
    };
    // Guard the byte-for-byte assertion below: `String::contains("")` is
    // always true, so an empty expected filter would make it vacuous.
    assert!(
        !expected_filter_hex.is_empty(),
        "the tip block carries a non-empty committed filter"
    );

    let net_info = vec![
        RpcNetworkInfo {
            name: "IPV4".to_string(),
            limited: false,
            reachable: true,
            proxy: String::new(),
            proxy_randomize_credentials: false,
        },
        RpcNetworkInfo {
            name: "IPV6".to_string(),
            limited: true,
            reachable: false,
            proxy: String::new(),
            proxy_randomize_credentials: false,
        },
        RpcNetworkInfo {
            name: "Onion".to_string(),
            limited: false,
            reachable: false,
            proxy: String::new(),
            proxy_randomize_credentials: false,
        },
    ];

    let server = Arc::new(Mutex::new(Server::new(Config {
        chain: NodeRpcChain::new(Arc::clone(&chain), params.clone()),
        chain_params: params.clone(),
        subsidy_cache: SubsidyCache::new(RpcSubsidyParams(params.clone())),
        min_relay_tx_fee: 10000,
        max_protocol_version: PROTOCOL_VERSION,
        sync_mgr: Box::new(NodeRpcSyncManager::new(sync_manager, Arc::clone(&tx_pool))),
        conn_mgr: Box::new(NodeRpcConnManager::new(
            ConnectedPeers::new(),
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
        filterer_v2: Box::new(NodeRpcFiltererV2::new(Arc::clone(&chain))),
        exists_addresser: None,
        log_manager: Box::new(()),
        fee_estimator: Box::new(()),
        block_templater: None,
        sanity_checker: Box::new(NodeRpcSanityChecker::new(params.clone())),
        time_source: Box::new(dcroxide_node::rpcrun::SystemTimeSource),
        proxy: String::new(),
        test_net: false,
        runtime_version: String::new(),
        cpu_miner: Box::new(IdleCpuMiner),
        mix_pooler: Box::new(()),
        profiler_mgr: Box::new(()),
        addr_manager: Box::new(NodeRpcAddrManager::new(addr_manager)),
        mining_addrs: Vec::new(),
        user_agent_version: "0.1.0".to_string(),
        net_info,
        services: 0,
        request_shutdown,
        allow_unsynced_mining: true,
        rpc_user: "user".to_string(),
        rpc_pass: "pass".to_string(),
        rpc_limit_user: String::new(),
        rpc_limit_pass: String::new(),
    })));

    let listener = start_rpc_listener(
        &["127.0.0.1:0".to_string()],
        server,
        dcroxide_node::rpcrun::RpcTransport::Plain,
        dcroxide_node::websocket::NodeNtfnMgr::new(),
        128,
    )
    .expect("start rpc listener");
    let port = listener.bound_addrs()[0].port();

    // getcfilterv2 for the tip returns the block's committed filter,
    // byte-for-byte the chain's own answer.
    let response = post(
        port,
        &format!(r#"{{"jsonrpc":"1.0","id":1,"method":"getcfilterv2","params":["{tip_hash}"]}}"#),
    );
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(!response.contains("\"error\":{"), "{response}");
    assert!(
        response.contains(&expected_filter_hex),
        "getcfilterv2 returns the committed filter: {response}"
    );

    // getcfilterv2 for an unknown block is dcrd's "Block not found".
    let bogus = "00".repeat(32);
    let response = post(
        port,
        &format!(r#"{{"jsonrpc":"1.0","id":2,"method":"getcfilterv2","params":["{bogus}"]}}"#),
    );
    assert!(
        response.contains("Block not found"),
        "getcfilterv2 for an unknown block is not found: {response}"
    );

    // verifychain at level 1, depth 1 runs the sanity checks on the tip
    // and answers true.
    let response = post(
        port,
        r#"{"jsonrpc":"1.0","id":3,"method":"verifychain","params":[1,1]}"#,
    );
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(!response.contains("\"error\":{"), "{response}");
    assert!(
        response.contains("\"result\":true"),
        "verifychain passes the sanity checks: {response}"
    );

    // getnetworkinfo reports the address manager's local address and the
    // three configured networks.
    let response = post(
        port,
        r#"{"jsonrpc":"1.0","id":4,"method":"getnetworkinfo","params":[]}"#,
    );
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(!response.contains("\"error\":{"), "{response}");
    assert!(
        response.contains("8.8.8.8"),
        "getnetworkinfo reports the local address: {response}"
    );
    assert!(
        response.contains("IPV4") && response.contains("IPV6") && response.contains("Onion"),
        "getnetworkinfo reports all three configured networks: {response}"
    );

    // stop returns dcrd's string and fires the graceful shutdown request.
    let response = post(
        port,
        r#"{"jsonrpc":"1.0","id":5,"method":"stop","params":[]}"#,
    );
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.contains("dcrd stopping."), "{response}");
    assert!(
        shutdown_requested.load(Ordering::SeqCst),
        "stop requested a graceful shutdown"
    );

    listener.shutdown();
}

/// The sanity-checker seam actually runs the ported checks and surfaces a
/// rule error as a message: a valid battery block passes, a block with its
/// transactions removed fails.  This is the negative path the end-to-end
/// `verifychain` test cannot exercise (it reads only already-valid blocks
/// from the chain), so without it a seam that always returned `Ok` would
/// go undetected.
#[test]
fn sanity_checker_seam_runs_the_checks() {
    let params = dcroxide_chaincfg::regnet_params();
    let (_now, blocks) = accepted_prefix(1);
    let mut checker = NodeRpcSanityChecker::new(params.clone());

    // A valid battery block passes the context-free checks.
    assert!(
        checker.check_block_sanity(&blocks[0]).is_ok(),
        "a valid block passes the sanity checks"
    );

    // Emptying the regular transaction tree makes the block fail, and the
    // seam surfaces the rule error as a non-empty message.
    let mut tampered = blocks[0].clone();
    tampered.transactions.clear();
    let message = checker
        .check_block_sanity(&tampered)
        .expect_err("a block with no regular transactions fails sanity");
    assert!(
        !message.is_empty(),
        "the sanity failure carries a rule-error message"
    );
}
