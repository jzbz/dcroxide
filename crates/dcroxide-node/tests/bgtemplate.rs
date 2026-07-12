// SPDX-License-Identifier: ISC
//! End-to-end checks for the background block template generator: a
//! regnet chain built from dcrd's own full-block battery backs the
//! live generator thread, which drives the ported regeneration state
//! machine over the chain and mempool.  The startup tip inject builds
//! a template the getwork RPC then serves over the listener, and a
//! forced regeneration rebuilds and fans the template out to a
//! subscriber.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};
use dcroxide_mining::MiningPolicy;
use dcroxide_node::bgtemplate::{NodeRpcBlockTemplater, start_generator};
use dcroxide_node::rpcrun::{
    IdleCpuMiner, NodeRpcChain, NodeRpcConnManager, NodeRpcSyncManager, start_rpc_listener,
};
use dcroxide_node::runtime::ConnectedPeers;
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::server::{Config, RpcBlockTemplater, RpcSubsidyParams, Server, TemplateRecv};
use dcroxide_standalone::SubsidyCache;
use dcroxide_testutil::unhex;
use dcroxide_wire::{MsgBlock, PROTOCOL_VERSION};

/// The leading consecutive main-chain prefix of accepted blocks from
/// dcrd's `fullblocktests.Generate` battery (fully signed regnet
/// blocks), with the battery's recorded generation time.
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
/// processed, plus a live mempool over it.
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
        assert!(errs.is_empty(), "history block must accept: {errs:?}");
    }
    (dir, chain)
}

/// A regnet premine pay-to-pubkey-hash payout used as the mining
/// address.
fn mining_address() -> dcroxide_txscript::stdaddr::Address {
    let params = dcroxide_chaincfg::regnet_params();
    dcroxide_txscript::stdaddr::decode_address("RsKrWb7Vny1jnzL1sDLgKTAteh9RZcRr5g6", &params)
        .expect("mining address")
}

/// The mining policy the daemon builds from its configuration.
fn mining_policy() -> MiningPolicy {
    let params = dcroxide_chaincfg::regnet_params();
    MiningPolicy {
        block_max_size: params.maximum_block_sizes[0] as u32,
        tx_min_free_fee: 10000,
        aggressive_mining: true,
    }
}

/// Poll the templater until it yields a template, failing after a
/// generous deadline (the startup inject builds it asynchronously on
/// the generator thread).
fn wait_for_template(templater: &mut NodeRpcBlockTemplater) -> MsgBlock {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match templater.current_template() {
            Ok(Some(block)) => return block,
            Ok(None) => {}
            Err(err) => panic!("template errored: {err}"),
        }
        assert!(
            Instant::now() < deadline,
            "the generator must produce a template"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Extract the value of a `"key":"value"` JSON string field from the
/// response text.
fn json_string_field(response: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = response.find(&needle)? + needle.len();
    let rest = &response[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
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

#[test]
fn serves_getwork_over_the_live_generator() {
    let params = dcroxide_chaincfg::regnet_params();
    let (_dir, chain) = regnet_chain(2);
    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    );

    let policy = mining_policy();
    let generator = start_generator(
        Arc::clone(&chain),
        Arc::clone(&tx_pool),
        params.clone(),
        vec![mining_address()],
        policy.clone(),
        0,
        true,
        None,
        None,
    );

    // The startup inject builds the height-3 template; wait for it.
    let mut poller = NodeRpcBlockTemplater::new(
        generator.current_handle(),
        generator.subscribers_handle(),
        generator.sink(),
        Arc::clone(&chain),
        Arc::clone(&tx_pool),
        params.clone(),
        policy.clone(),
        0,
    );
    let template = wait_for_template(&mut poller);
    assert_eq!(template.header.height, 3, "startup template height");

    // Serve getwork over an RPC listener backed by the generator.
    let block_templater = Box::new(NodeRpcBlockTemplater::new(
        generator.current_handle(),
        generator.subscribers_handle(),
        generator.sink(),
        Arc::clone(&chain),
        Arc::clone(&tx_pool),
        params.clone(),
        policy.clone(),
        0,
    )) as Box<dyn RpcBlockTemplater + Send>;

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
        block_templater: Some(block_templater),
        sanity_checker: Box::new(()),
        time_source: Box::new(dcroxide_node::rpcrun::SystemTimeSource),
        proxy: String::new(),
        test_net: false,
        runtime_version: String::new(),
        cpu_miner: Box::new(IdleCpuMiner),
        mix_pooler: Box::new(()),
        profiler_mgr: Box::new(()),
        addr_manager: Box::new(()),
        mining_addrs: vec![mining_address()],
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
        128,
    )
    .expect("start rpc listener");
    let port = listener.bound_addrs()[0].port();

    let response = post(
        port,
        r#"{"jsonrpc":"1.0","id":1,"method":"getwork","params":[]}"#,
    );
    assert!(
        response.contains("\"error\":null"),
        "getwork must succeed: {response}"
    );
    // The work data and target are non-empty hex strings.
    let data = json_string_field(&response, "data").expect("data field");
    let target = json_string_field(&response, "target").expect("target field");
    assert!(!data.is_empty(), "work data must be present");
    assert!(!target.is_empty(), "target must be present");
    assert!(
        data.chars().all(|c| c.is_ascii_hexdigit()),
        "work data is hex: {data}"
    );
    assert!(
        target.chars().all(|c| c.is_ascii_hexdigit()),
        "target is hex: {target}"
    );

    listener.shutdown();
    generator.shutdown();
}

#[test]
fn regentemplate_forces_a_new_template() {
    let params = dcroxide_chaincfg::regnet_params();
    let (_dir, chain) = regnet_chain(2);
    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    );

    let policy = mining_policy();
    let generator = start_generator(
        Arc::clone(&chain),
        Arc::clone(&tx_pool),
        params.clone(),
        vec![mining_address()],
        policy.clone(),
        0,
        true,
        None,
        None,
    );

    let mut templater = NodeRpcBlockTemplater::new(
        generator.current_handle(),
        generator.subscribers_handle(),
        generator.sink(),
        Arc::clone(&chain),
        Arc::clone(&tx_pool),
        params.clone(),
        policy.clone(),
        0,
    );
    // Wait for the startup template.
    let first = wait_for_template(&mut templater);
    assert_eq!(first.header.height, 3, "startup template height");

    // Subscribe, drain the immediately-delivered current template,
    // then force a regeneration and observe the rebuilt template
    // arrive over the subscription.
    let mut subscription = templater.subscribe();
    match subscription.recv() {
        TemplateRecv::Template(_) => {}
        other => panic!("subscription must deliver the current template: {other:?}"),
    }
    templater.force_regen();
    match subscription.recv_with_timeout() {
        TemplateRecv::Template(block) => {
            assert_eq!(block.header.height, 3, "rebuilt template height");
        }
        other => panic!("force regen must rebuild a template: {other:?}"),
    }
    subscription.stop();

    // The current template stays available after the forced rebuild.
    assert!(
        templater.current_template().expect("no error").is_some(),
        "a template remains available after force regen"
    );

    generator.shutdown();
}

#[test]
fn the_drain_hook_runs_after_each_processed_event() {
    // The generator runs its drain hook after every event it processes,
    // which is how the chain handler's deferred maintenance is driven
    // for a reorg the generator itself initiates (a real
    // force_head_reorganization needs a competing side chain at stake
    // validation height, out of reach of this regnet prefix, so the
    // wiring is exercised directly through the hook here).
    let params = dcroxide_chaincfg::regnet_params();
    let (_dir, chain) = regnet_chain(2);
    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    );

    let policy = mining_policy();
    let drains = Arc::new(AtomicUsize::new(0));
    let hook_drains = Arc::clone(&drains);
    let generator = start_generator(
        Arc::clone(&chain),
        Arc::clone(&tx_pool),
        params.clone(),
        vec![mining_address()],
        policy.clone(),
        0,
        true,
        None,
        Some(Box::new(move || {
            hook_drains.fetch_add(1, Ordering::SeqCst);
        })),
    );

    let mut templater = NodeRpcBlockTemplater::new(
        generator.current_handle(),
        generator.subscribers_handle(),
        generator.sink(),
        Arc::clone(&chain),
        Arc::clone(&tx_pool),
        params.clone(),
        policy.clone(),
        0,
    );
    let _ = wait_for_template(&mut templater);
    let after_startup = drains.load(Ordering::SeqCst);
    assert!(
        after_startup >= 1,
        "the startup tip inject runs the drain hook"
    );

    // A processed force-regeneration event runs the hook again.
    templater.force_regen();
    let deadline = Instant::now() + Duration::from_secs(5);
    while drains.load(Ordering::SeqCst) <= after_startup {
        assert!(
            Instant::now() < deadline,
            "a processed event must run the drain hook"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    generator.shutdown();
}

#[test]
fn a_reorg_clears_and_then_recovers_getwork() {
    // Drive the generator's no-rebuild publish path: a reorg-started
    // event clears the current template without queuing a build, so the
    // getwork mirror must follow (reporting no work) rather than keep
    // serving the stale pre-reorg template, and a reorg-done event then
    // rebuilds on the tip so getwork recovers.  A real
    // force_head_reorganization that leaves the new tip awaiting votes —
    // the window in which a mispublished mirror would serve an
    // orphan-parent template — needs a competing side chain at stake
    // validation height, out of reach of this regnet prefix (the
    // state-machine clear itself is covered by dcroxide-mining's
    // differential tests, and the publish primitive by the
    // `publish_tracks_a_cleared_template` unit test); here the reorg
    // events exercise the wiring end-to-end.
    let params = dcroxide_chaincfg::regnet_params();
    let (_dir, chain) = regnet_chain(2);
    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    );

    let policy = mining_policy();
    let generator = start_generator(
        Arc::clone(&chain),
        Arc::clone(&tx_pool),
        params.clone(),
        vec![mining_address()],
        policy.clone(),
        0,
        true,
        None,
        None,
    );

    let mut templater = NodeRpcBlockTemplater::new(
        generator.current_handle(),
        generator.subscribers_handle(),
        generator.sink(),
        Arc::clone(&chain),
        Arc::clone(&tx_pool),
        params.clone(),
        policy.clone(),
        0,
    );
    let first = wait_for_template(&mut templater);
    assert_eq!(first.header.height, 3, "startup template height");

    // A reorg starts: the generator clears the template and reports no
    // work (dcrd's `CurrentTemplate` blocks on the stale-template wait
    // group; the port returns `Ok(None)`).
    generator.sink().chain_reorg_started();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match templater.current_template() {
            Ok(None) => break,
            Ok(Some(_)) => {}
            Err(err) => panic!("a reorg must not error the template: {err}"),
        }
        assert!(
            Instant::now() < deadline,
            "a reorg must clear the getwork work signal"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    // A reorg finishes: the generator rebuilds on the tip and getwork
    // recovers a fresh template.
    generator.sink().chain_reorg_done();
    let recovered = wait_for_template(&mut templater);
    assert_eq!(recovered.header.height, 3, "recovered post-reorg template");

    generator.shutdown();
}
