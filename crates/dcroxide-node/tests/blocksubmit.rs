// SPDX-License-Identifier: ISC
//! End-to-end block submission over the daemon's block-submit seam: a
//! regnet chain built from dcrd's own full-block battery backs a real
//! sync manager, and a locally-submitted battery block runs through the
//! same `ProcessBlock` path as a network block — `submitblock` answers
//! `null` on acceptance and `rejected: <rule error>` on a duplicate,
//! exactly like dcrd.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};
use dcroxide_node::rpcrun::{
    IdleCpuMiner, NodeRpcChain, NodeRpcConnManager, NodeRpcSyncManager, start_rpc_listener,
};
use dcroxide_node::runtime::ConnectedPeers;
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::server::{Config, RpcSubsidyParams, RpcSyncManager, Server};
use dcroxide_standalone::SubsidyCache;
use dcroxide_testutil::unhex;
use dcroxide_wire::{MsgBlock, PROTOCOL_VERSION};

/// The leading consecutive main-chain prefix of accepted blocks from
/// dcrd's `fullblocktests.Generate` battery (fully signed regnet
/// blocks) with the battery's recorded generation time, each block
/// paired with its raw hex exactly as `submitblock` receives it.
fn accepted_prefix(limit: usize) -> (i64, Vec<(MsgBlock, String)>) {
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
            // accept <name> <mainchain> <orphan> <blockhex>
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                // Only the linear main-chain prefix: an accepted block
                // extending anything else is a side chain or orphan.
                if f[2] != "true" || block.header.prev_block != tip {
                    continue;
                }
                tip = block.header.block_hash();
                blocks.push((block, f[4].to_string()));
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

/// A regnet chain with the first `history` battery blocks connected,
/// returned with the still-unconnected blocks (each with its raw hex)
/// that follow the prefix.
#[allow(clippy::type_complexity)]
fn regnet_chain_with_prefix(
    history: usize,
    total: usize,
) -> (
    tempfile::TempDir,
    Arc<Mutex<Chain>>,
    Vec<(MsgBlock, String)>,
) {
    let params = dcroxide_chaincfg::regnet_params();
    let (now, mut blocks) = accepted_prefix(total);
    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    for (block, _) in &blocks[..history] {
        let (_, errs) = chain
            .lock()
            .expect("chain")
            .process_block(block, now, &params);
        assert!(errs.is_empty(), "battery block must accept: {errs:?}");
    }
    let remaining = blocks.split_off(history);
    (dir, chain, remaining)
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

/// The block-submit seam accepts a locally-submitted block through the
/// sync manager's `ProcessBlock` path and rejects a resubmission as
/// dcrd's duplicate rule error.
#[test]
fn the_submit_seam_accepts_a_block_and_rejects_a_duplicate() {
    let params = dcroxide_chaincfg::regnet_params();
    // Connect two battery blocks; the third is the one to submit.
    let (_dir, chain, remaining) = regnet_chain_with_prefix(2, 3);
    let (next_block, _hex) = &remaining[0];

    let tx_pool = shared_tx_pool(&chain);
    let sync_manager = Arc::new(Mutex::new(dcroxide_node::sync::new_sync_manager(
        Arc::clone(&chain),
        &params,
        false,
        8,
        1000,
        Arc::clone(&tx_pool),
    )));
    let mut rpc_sync = NodeRpcSyncManager::new(sync_manager, Arc::clone(&tx_pool));

    // The submitted block runs through ProcessBlock and extends the tip.
    rpc_sync
        .submit_block(next_block)
        .expect("the battery block is accepted through the seam");
    assert_eq!(
        chain.lock().expect("chain").best_snapshot().height,
        3,
        "the submitted block became the new tip"
    );

    // Resubmitting the same block is dcrd's duplicate rule error, so the
    // seam classifies it as a rule error (getwork -> false, submitblock
    // -> "rejected: ...").
    let failure = rpc_sync
        .submit_block(next_block)
        .expect_err("a duplicate block is rejected");
    assert!(failure.is_rule_error, "duplicate is a rule error");
    assert!(
        failure.message.contains("already have block"),
        "dcrd's duplicate text: {}",
        failure.message
    );
}

/// A block submitted through the seam runs the chain handler's drains
/// (relay/announce/prune) after `process_block` exactly as a network
/// block does, proving the seam's lock nesting — the RPC thread taking
/// the sync manager, then the chain mutex inside `process_block`, then
/// the peer registry inside the released-lock drains — runs to
/// completion without deadlock.
#[test]
fn a_submitted_block_drains_the_chain_handler() {
    use dcroxide_node::chainntfns::ChainNtfnHandler;
    use dcroxide_node::dispatch::{SyncPeers, new_recently_advertised};

    let params = dcroxide_chaincfg::regnet_params();
    let (_dir, chain, remaining) = regnet_chain_with_prefix(2, 3);
    let (next_block, _hex) = &remaining[0];
    let tx_pool = shared_tx_pool(&chain);

    let sync_manager = Arc::new(Mutex::new(dcroxide_node::sync::new_sync_manager(
        Arc::clone(&chain),
        &params,
        false,
        8,
        1000,
        Arc::clone(&tx_pool),
    )));

    // Install the chain handler both as the chain's notification
    // callback (queues events under the chain mutex) and on the sync
    // manager's chain (drains them after process_block), exactly as the
    // daemon wires it; unsynced mining opens the accepted-block
    // announcement drain over the stale regnet tip.
    let handler = ChainNtfnHandler::new(
        None,
        params.clone(),
        true,
        Arc::clone(&tx_pool),
        SyncPeers::new(),
        new_recently_advertised(),
    );
    {
        let callback = handler.clone();
        chain
            .lock()
            .expect("chain")
            .set_notification_callback(Box::new(move |n| callback.handle(n)));
    }
    sync_manager
        .lock()
        .expect("sync manager")
        .chain_mut()
        .set_chain_ntfn_handler(handler);

    let mut rpc_sync = NodeRpcSyncManager::new(Arc::clone(&sync_manager), Arc::clone(&tx_pool));
    rpc_sync
        .submit_block(next_block)
        .expect("the battery block is accepted through the seam");

    assert_eq!(
        chain.lock().expect("chain").best_snapshot().height,
        3,
        "the submitted block became the new tip after the drains ran"
    );
}

/// Send one authenticated raw HTTP POST and return the response body.
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

/// `submitblock` over the live RPC listener answers `null` on
/// acceptance and dcrd's `rejected: <error>` string on a duplicate.
#[test]
fn submitblock_over_http_accepts_then_rejects_duplicate() {
    let params = dcroxide_chaincfg::regnet_params();
    let (_dir, chain, remaining) = regnet_chain_with_prefix(2, 3);
    let (_next_block, next_hex) = &remaining[0];

    let tx_pool = shared_tx_pool(&chain);
    let sync_manager = Arc::new(Mutex::new(dcroxide_node::sync::new_sync_manager(
        Arc::clone(&chain),
        &params,
        false,
        8,
        1000,
        Arc::clone(&tx_pool),
    )));
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
        filterer_v2: Box::new(()),
        exists_addresser: None,
        log_manager: Box::new(()),
        fee_estimator: Box::new(()),
        block_templater: None,
        sanity_checker: Box::new(()),
        time_source: Box::new(dcroxide_node::rpcrun::SystemTimeSource),
        proxy: String::new(),
        test_net: false,
        runtime_version: String::new(),
        cpu_miner: Box::new(IdleCpuMiner),
        mix_pooler: Box::new(()),
        profiler_mgr: Box::new(()),
        addr_manager: Box::new(()),
        mining_addrs: Vec::new(),
        user_agent_version: "0.1.0".to_string(),
        net_info: Vec::new(),
        services: 0,
        request_shutdown: Box::new(|| {}),
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
    )
    .expect("start rpc listener");
    let port = listener.bound_addrs()[0].port();

    // Accepted: submitblock returns JSON null (dcrd's handleSubmitBlock
    // success), and the chain advances to the submitted block.
    let response = post(
        port,
        &format!(r#"{{"jsonrpc":"1.0","id":1,"method":"submitblock","params":["{next_hex}"]}}"#),
    );
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.contains("\"result\":null"), "{response}");
    assert!(!response.contains("\"error\":{"), "{response}");
    assert_eq!(
        chain.lock().expect("chain").best_snapshot().height,
        3,
        "the submitted block became the new tip"
    );

    // Duplicate: dcrd answers the "rejected: already have block ..."
    // string as the result (not an error object).
    let response = post(
        port,
        &format!(r#"{{"jsonrpc":"1.0","id":2,"method":"submitblock","params":["{next_hex}"]}}"#),
    );
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(
        response.contains("rejected: already have block"),
        "{response}"
    );

    listener.shutdown();
}
