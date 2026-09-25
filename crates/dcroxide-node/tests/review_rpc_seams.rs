// SPDX-License-Identifier: ISC
//! Every chain seam the RPC handlers reach, driven through the daemon's
//! own `NodeRpcChain` over a regnet chain built from dcrd's full-block
//! battery.
//!
//! The handler vector suites run over mock chains, so they could not see
//! that the daemon's adapter left fourteen `RpcChain` methods at their
//! trait defaults: getstakedifficulty, getblocksubsidy at or below the
//! tip, estimatestakediff, ticketvwap, getstakeversions,
//! getstakeversioninfo, getvoteinfo, gettreasurybalance,
//! ticketsforaddress, invalidateblock and reconsiderblock failed with
//! "RPC server seam X is not wired in this build", getchaintips
//! answered `[]`, and a mined tspend read as unknown.  These tests run
//! the real adapter and fail on the unwired-seam text.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::{Arc, Mutex};

use dcroxide_blockchain::process::Chain;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_node::rpcrun::{IdleCpuMiner, NodeRpcChain, NodeRpcConnManager, NodeRpcSyncManager};
use dcroxide_node::runtime::ConnectedPeers;
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::server::{Config, RpcChain, Server};
use dcroxide_standalone::SubsidyCache;
use dcroxide_testutil::unhex;
use dcroxide_wire::{MsgBlock, PROTOCOL_VERSION};

/// The text every trait default reports (`server.rs` `unwired_seam`).
const UNWIRED: &str = "is not wired in this build";

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

/// A server over the daemon's chain adapter, with the remaining seams
/// the way the other daemon-level RPC tests build them.
fn server_over(chain: &Arc<Mutex<Chain>>) -> Server<NodeRpcChain> {
    server_with_adapter(
        chain,
        NodeRpcChain::new(Arc::clone(chain), dcroxide_chaincfg::regnet_params()),
    )
}

/// A server over the given chain adapter.
fn server_with_adapter(chain: &Arc<Mutex<Chain>>, adapter: NodeRpcChain) -> Server<NodeRpcChain> {
    let params = dcroxide_chaincfg::regnet_params();
    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    );
    let sync_manager = Arc::new(Mutex::new(dcroxide_node::sync::new_sync_manager(
        Arc::clone(chain),
        &params,
        false,
        8,
        1000,
        Arc::clone(&tx_pool),
        dcroxide_node::mixnode::shared_mix_pool(Arc::clone(chain), params.clone(), &tx_pool),
    )));
    Server::new(Config {
        chain: adapter,
        chain_params: params.clone(),
        subsidy_cache: std::sync::Mutex::new(SubsidyCache::new(params.clone())),
        min_relay_tx_fee: 10000,
        max_protocol_version: PROTOCOL_VERSION,
        sync_mgr: Box::new(NodeRpcSyncManager::new(sync_manager, Arc::clone(&tx_pool))),
        conn_mgr: Box::new(NodeRpcConnManager::new(
            ConnectedPeers::new(),
            Arc::new(dcroxide_node::transport::NetByteTotals::new()),
        )),
        client_cert_auth: false,
        tx_mempooler: Box::new(dcroxide_node::txmempool::NodeRpcTxMempooler::new(tx_pool)),
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
    })
}

/// Run one JSON-RPC request through the ported `jsonRPCRead` pipeline
/// as an admin and return the response text.
fn call(server: &Server<NodeRpcChain>, method: &str, params: &str) -> String {
    let body = format!(r#"{{"jsonrpc":"1.0","id":1,"method":"{method}","params":{params}}}"#);
    let response = dcroxide_rpc::http::process_body(server, &body, true);
    String::from_utf8(response).expect("utf-8 response")
}

/// Every handler that reaches one of the formerly unwired seams answers
/// from the chain, not with the unwired-seam error.
#[test]
fn every_chain_seam_the_handlers_reach_is_wired() {
    let params = dcroxide_chaincfg::regnet_params();
    let (_dir, chain) = regnet_chain(3);
    let server = server_over(&chain);
    let (tip_hash, tip_height) = {
        let chain = chain.lock().expect("chain");
        let best = chain.best_snapshot();
        (best.hash, best.height)
    };
    let vote_version = params.deployments[0].0;
    let stake_addr = dcroxide_txscript::stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(
        &[0x11; 20],
        &params,
    )
    .expect("stake address")
    .to_string();

    let calls: Vec<(&str, String)> = vec![
        ("getchaintips", "[]".to_string()),
        ("getstakedifficulty", "[]".to_string()),
        ("getblocksubsidy", format!("[{tip_height},5]")),
        ("estimatestakediff", "[]".to_string()),
        ("ticketvwap", "[]".to_string()),
        ("getstakeversions", format!(r#"["{tip_hash}",2]"#)),
        ("getstakeversioninfo", "[]".to_string()),
        ("getvoteinfo", format!("[{vote_version}]")),
        ("gettreasurybalance", "[]".to_string()),
        ("ticketsforaddress", format!(r#"["{stake_addr}"]"#)),
    ];
    for (method, params) in &calls {
        let response = call(&server, method, params);
        assert!(!response.contains(UNWIRED), "{method}: {response}");
        assert!(
            !response.contains(r#""code":-32603"#),
            "{method} failed internally: {response}"
        );
    }

    // getchaintips always includes the active tip (dcrd `ChainTips`).
    let tips = call(&server, "getchaintips", "[]");
    assert!(
        tips.contains(&format!(
            r#"{{"height":{tip_height},"hash":"{tip_hash}","branchlen":0,"status":"active"}}"#
        )),
        "{tips}"
    );

    // getstakeversions walks back from the requested block.
    let versions = call(&server, "getstakeversions", &format!(r#"["{tip_hash}",2]"#));
    assert!(versions.contains(&tip_hash.to_string()), "{versions}");

    // The address holds no tickets, which is an empty answer, not an
    // error.
    let tickets = call(
        &server,
        "ticketsforaddress",
        &format!(r#"["{stake_addr}"]"#),
    );
    assert!(tickets.contains(r#""result":{"tickets":[]}"#), "{tickets}");
}

/// `invalidateblock` rolls the tip back to its parent and
/// `reconsiderblock` restores it, and getchaintips then reports the
/// invalidated branch as `invalid` (dcrd `InvalidateBlock` /
/// `ReconsiderBlock` / `ChainTips`).
#[test]
fn invalidate_and_reconsider_move_the_tip() {
    let params = dcroxide_chaincfg::regnet_params();
    let (_dir, chain) = regnet_chain(3);
    // The daemon's chain handler, installed as the chain callback and on
    // the adapter the way `rpc_config` wires it, so the reorganizations'
    // deferred work drains after each call -- with the chain mutex
    // released, or this would deadlock.
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
        None,
        params.clone(),
        true,
        dcroxide_node::sync::SyncGate::always_current(),
        None,
        tx_pool,
        dcroxide_node::dispatch::SyncPeers::new(),
        dcroxide_node::dispatch::new_recently_advertised(),
    );
    {
        let callback = handler.clone();
        chain
            .lock()
            .expect("chain")
            .set_notification_callback(Box::new(move |n| callback.handle(n)));
    }
    let server = server_with_adapter(
        &chain,
        NodeRpcChain::new(Arc::clone(&chain), params.clone()).with_chain_ntfn_handler(handler),
    );
    let (tip_hash, tip_height, parent_hash) = {
        let chain = chain.lock().expect("chain");
        let best = chain.best_snapshot();
        (best.hash, best.height, best.prev_hash)
    };

    let response = call(&server, "invalidateblock", &format!(r#"["{tip_hash}"]"#));
    assert!(
        response.contains(r#""result":null,"error":null"#),
        "{response}"
    );
    assert_eq!(
        chain.lock().expect("chain").best_snapshot().hash,
        parent_hash,
        "invalidating the tip reorganizes back to its parent"
    );
    let tips = call(&server, "getchaintips", "[]");
    assert!(
        tips.contains(&format!(
            r#"{{"height":{tip_height},"hash":"{tip_hash}","branchlen":1,"status":"invalid"}}"#
        )),
        "{tips}"
    );

    let response = call(&server, "reconsiderblock", &format!(r#"["{tip_hash}"]"#));
    assert!(
        response.contains(r#""result":null,"error":null"#),
        "{response}"
    );
    assert_eq!(
        chain.lock().expect("chain").best_snapshot().hash,
        tip_hash,
        "reconsidering the block restores it as the tip"
    );

    // An unknown block is dcrd's "Block not found" for both.
    let unknown = Hash([0x42; 32]);
    for method in ["invalidateblock", "reconsiderblock"] {
        let response = call(&server, method, &format!(r#"["{unknown}"]"#));
        assert!(
            response.contains(&format!("Block not found: {unknown}")),
            "{method}: {response}"
        );
    }

    // The genesis block cannot be invalidated (dcrd
    // `ErrInvalidateGenesisBlock`, reported as an invalid parameter).
    let genesis = dcroxide_chaincfg::regnet_params().genesis_hash;
    let response = call(&server, "invalidateblock", &format!(r#"["{genesis}"]"#));
    assert!(
        response.contains("invalidating the genesis block is not allowed"),
        "{response}"
    );
}

/// getchaintips orders tips of equal height -- the two sides of each of
/// the battery's early forks -- the way dcrd's `nodeHeightSorter` does
/// under `sort.Reverse`: descending height, then descending raw hash
/// bytes (`chainquery.go:33`), not in the order the index learned them.
#[test]
fn equal_height_chain_tips_sort_by_descending_hash() {
    let params = dcroxide_chaincfg::regnet_params();
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcroxide-blockchain/tests/data/fullblock_vectors.txt"
    );
    let data = std::fs::read_to_string(path).expect("fullblock vectors");
    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    let server = server_over(&chain);

    // Every block the battery accepts, main chain or side chain, through
    // its first three forks, checking the tips after each side block.
    let forks = ["bf3", "bf5", "bf7"];
    let mut now: i64 = 0;
    let mut checked = 0;
    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("generation time"),
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                let (_, errs) = chain
                    .lock()
                    .expect("chain")
                    .process_block(&block, now, &params);
                assert!(errs.is_empty(), "{} must accept: {errs:?}", f[1]);
                if !forks.contains(&f[1]) {
                    continue;
                }
                let mut tips: Vec<(i64, Hash)> = Vec::new();
                {
                    let chain = chain.lock().expect("chain");
                    let _ = chain.index.for_each_chain_tip(
                        |tip| -> Result<(), core::convert::Infallible> {
                            let node = chain.store.node(tip);
                            tips.push((node.height, node.hash));
                            Ok(())
                        },
                    );
                }
                let height = i64::from(block.header.height);
                assert_eq!(
                    tips.iter().filter(|(h, _)| *h == height).count(),
                    2,
                    "{} forks at height {height}: {tips:?}",
                    f[1]
                );
                tips.sort_by(|a, b| b.cmp(a));
                let response = call(&server, "getchaintips", "[]");
                let positions: Vec<usize> = tips
                    .iter()
                    .map(|(_, hash)| {
                        response
                            .find(&format!(r#""hash":"{hash}""#))
                            .unwrap_or_else(|| panic!("{hash} is listed: {response}"))
                    })
                    .collect();
                assert!(
                    positions.windows(2).all(|w| w[0] < w[1]),
                    "after {}, expected {tips:?}: {response}",
                    f[1]
                );
                checked += 1;
                if checked == forks.len() {
                    return;
                }
            }
            _ => {}
        }
    }
    panic!("the battery must provide the forks {forks:?}");
}

/// The seams whose failures reach clients through the internal error
/// carry dcrd's error texts, and the seams without a handler-level
/// check answer from the chain.
#[test]
fn the_adapter_answers_with_dcrds_texts() {
    let (_dir, chain) = regnet_chain(3);
    let adapter = NodeRpcChain::new(Arc::clone(&chain), dcroxide_chaincfg::regnet_params());
    let unknown = Hash([0x42; 32]);

    // dcrd `errNotInMainChainByHeight` and `unknownBlockError`.
    assert_eq!(
        adapter.block_by_height(1000).expect_err("no such height"),
        "no block at height 1000 exists"
    );
    assert_eq!(
        adapter
            .block_hash_by_height(-1)
            .expect_err("no such height"),
        "no block at height -1 exists"
    );
    assert_eq!(
        adapter.header_by_height(1000).expect_err("no such height"),
        "no block at height 1000 exists"
    );
    assert_eq!(
        adapter.block_by_hash(&unknown).expect_err("unknown block"),
        format!("block {unknown} is not known")
    );
    assert_eq!(
        adapter.header_by_hash(&unknown).expect_err("unknown block"),
        format!("block {unknown} is not known")
    );
    assert_eq!(
        adapter.chain_work(&unknown).expect_err("unknown block"),
        format!("block {unknown} is not known")
    );
    assert_eq!(
        adapter
            .median_time_by_hash(&unknown)
            .expect_err("unknown block"),
        format!("block {unknown} is not known")
    );
    // dcrd `errNotInMainChainByHash`.
    assert_eq!(
        adapter
            .block_height_by_hash(&unknown)
            .expect_err("unknown block"),
        format!("block {unknown} is not in the main chain")
    );

    // A tspend that was never mined is dcrd's missing-key error, which
    // the handler turns into "No information available".
    assert_eq!(
        adapter.fetch_tspend(&unknown).expect_err("never mined"),
        format!("tspend db missing key: {unknown}")
    );

    // ws rebroadcastwinners reads the lottery through this seam.
    let tip = chain.lock().expect("chain").best_snapshot().hash;
    adapter
        .lottery_data_for_block(&tip)
        .expect("the tip's lottery data");
    assert!(
        adapter.lottery_data_for_block(&unknown).is_err(),
        "an unknown block has no lottery data"
    );

    // dcrd `CalcWantHeight` over regnet's stake validation height (144)
    // and its 320-block rule change interval.
    assert_eq!(adapter.calc_want_height(320, 500), 463);
    assert_eq!(
        adapter.calc_want_height(320, 500),
        dcroxide_blockchain::stakever::calc_want_height(144, 320, 500)
    );
}

/// `ticketsforaddress` finds the live tickets whose voting rights pay to
/// the address: every live ticket sharing the first ticket's voting
/// rights script, and nothing else (dcrd `TicketsWithAddress`).
#[test]
fn tickets_for_address_finds_the_live_tickets_paying_to_it() {
    let params = dcroxide_chaincfg::regnet_params();
    // Past the stake enabled height, so the battery's tickets are live.
    let (_dir, chain) = regnet_chain(60);
    let server = server_over(&chain);

    // The voting rights script of the first live ticket, and every live
    // ticket paying to the same one.
    let (script, expected) = {
        let chain = chain.lock().expect("chain");
        let live = chain.live_tickets();
        assert!(!live.is_empty(), "the battery has live tickets by now");
        let script_of = |hash: Hash| {
            chain
                .fetch_utxo_entry(&dcroxide_wire::OutPoint {
                    hash,
                    index: 0,
                    tree: dcroxide_wire::TX_TREE_STAKE,
                })
                .expect("live ticket output")
                .pk_script()
                .to_vec()
        };
        let script = script_of(live[0]);
        let mut expected: Vec<String> = live
            .into_iter()
            .filter(|&hash| script_of(hash) == script)
            .map(|hash| hash.to_string())
            .collect();
        expected.sort();
        (script, expected)
    };
    // The address the voting rights script pays: OP_SSTX followed by a
    // P2PKH (OP_DUP OP_HASH160 OP_DATA_20 <hash160> OP_EQUALVERIFY
    // OP_CHECKSIG) or P2SH (OP_HASH160 OP_DATA_20 <hash160> OP_EQUAL)
    // script.
    let addr = match script.len() {
        26 => dcroxide_txscript::stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(
            &script[4..24],
            &params,
        ),
        24 => dcroxide_txscript::stdaddr::new_address_script_hash_v0_from_hash(
            &script[3..23],
            &params,
        ),
        len => panic!("unexpected voting rights script length {len}: {script:02x?}"),
    }
    .expect("stake address")
    .to_string();

    let response = call(&server, "ticketsforaddress", &format!(r#"["{addr}"]"#));
    let mut found: Vec<String> = expected
        .iter()
        .filter(|hash| response.contains(hash.as_str()))
        .cloned()
        .collect();
    found.sort();
    assert_eq!(found, expected, "{response}");
    assert_eq!(
        response.matches('"').count(),
        // The fixed keys and values, plus two quotes per ticket hash.
        "{\"jsonrpc\":\"1.0\",\"result\":{\"tickets\":[]},\"error\":null,\"id\":1}"
            .matches('"')
            .count()
            + 2 * expected.len(),
        "no ticket paying elsewhere is reported: {response}"
    );
}

/// `getblockchaininfo`'s sync height and `sendrawtransaction`'s
/// recently-confirmed probe answer while the sync manager mutex is held
/// -- as the dispatcher holds it across a block's whole validation and
/// connection -- because dcrd reads the first with a bare atomic load
/// and the second under the filter's own lock.
#[test]
fn sync_state_seams_do_not_wait_on_the_sync_manager() {
    use dcroxide_rpc::server::RpcSyncManager;

    let params = dcroxide_chaincfg::regnet_params();
    let (_dir, chain) = regnet_chain(3);
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
    let rpc_sync = NodeRpcSyncManager::new(Arc::clone(&sync_manager), tx_pool);

    // Hold the manager the way a block intake does, and ask from another
    // thread.
    let held = sync_manager.lock().expect("sync manager");
    let (tx, rx) = std::sync::mpsc::channel();
    let asker = std::thread::spawn(move || {
        let height = rpc_sync.sync_height();
        let confirmed = rpc_sync.recently_confirmed_txn(&Hash([0x42; 32]));
        let _ = tx.send((height, confirmed));
    });
    let answer = rx.recv_timeout(std::time::Duration::from_secs(5));
    drop(held);
    asker.join().expect("asker thread");
    let (height, confirmed) = answer.expect("the seams answered without the manager lock");
    assert_eq!(
        height, 3,
        "the sync height starts at the chain's best height"
    );
    assert!(!confirmed, "nothing has been confirmed");
}
