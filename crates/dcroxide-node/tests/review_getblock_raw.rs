// SPDX-License-Identifier: ISC
//! `getblock <hash> false` hands back the block's serialized bytes as
//! they are held, as dcrd hex-encodes `blk.Bytes()`, rather than decoding
//! the stored block (or copying the cached one) only to serialize it
//! again.  The answer must not change: these tests pin the daemon's
//! `block_bytes_by_hash` to `block_by_hash`'s block re-serialized, for a
//! block in the chain's recent window and for one only the database
//! holds, and the not-found answer to the same error.

use std::sync::{Arc, Mutex};

use dcroxide_blockchain::process::Chain;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_node::rpcrun::{NodeRpcChain, NodeRpcConnManager, NodeRpcSyncManager};
use dcroxide_node::runtime::ConnectedPeers;
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::server::{Config, RpcChain, Server};
use dcroxide_standalone::SubsidyCache;
use dcroxide_testutil::unhex;
use dcroxide_wire::{MsgBlock, PROTOCOL_VERSION};

/// A regnet chain with the first `count` blocks of dcrd's
/// `fullblocktests.Generate` battery connected, and those blocks.
fn regnet_chain(count: usize) -> (tempfile::TempDir, Arc<Mutex<Chain>>, Vec<MsgBlock>) {
    let params = dcroxide_chaincfg::regnet_params();
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcroxide-blockchain/tests/data/fullblock_vectors.txt"
    );
    let data = std::fs::read_to_string(path).expect("fullblock vectors");
    let mut now: i64 = 0;
    let mut tip = params.genesis_hash;
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
                if blocks.len() == count {
                    break;
                }
            }
            _ => {}
        }
    }
    assert_eq!(blocks.len(), count, "battery must provide the prefix");

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
    (dir, chain, blocks)
}

/// A server over the daemon's chain adapter.
fn server_over(chain: &Arc<Mutex<Chain>>) -> Server<NodeRpcChain> {
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
        chain: NodeRpcChain::new(Arc::clone(chain), params.clone()),
        chain_params: params.clone(),
        subsidy_cache: Mutex::new(SubsidyCache::new(params.clone())),
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
    })
}

/// `getblock <hash> false` through the ported `jsonRPCRead` pipeline.
fn getblock_raw(server: &Server<NodeRpcChain>, hash: &Hash) -> String {
    let body =
        format!(r#"{{"jsonrpc":"1.0","id":1,"method":"getblock","params":["{hash}",false]}}"#);
    String::from_utf8(dcroxide_rpc::http::process_body(server, &body, true)).expect("utf-8")
}

/// The reply carrying `bytes` as getblock's hex result.
fn raw_reply(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{{\"jsonrpc\":\"1.0\",\"result\":\"{hex}\",\"error\":null,\"id\":1}}\n")
}

#[test]
fn raw_getblock_answers_the_block_serialization_cached_or_stored() {
    let (_dir, chain, blocks) = regnet_chain(8);
    let server = server_over(&chain);
    let adapter = NodeRpcChain::new(Arc::clone(&chain), dcroxide_chaincfg::regnet_params());
    let genesis = dcroxide_chaincfg::regnet_params().genesis_block;
    let all: Vec<MsgBlock> = std::iter::once(genesis).chain(blocks).collect();

    for evicted in [false, true] {
        for block in &all {
            let hash = block.header.block_hash();
            if evicted {
                // Only the database holds it now.
                chain.lock().expect("chain").blocks.remove(&hash.0);
            } else {
                assert!(
                    chain.lock().expect("chain").blocks.contains_key(&hash.0),
                    "block {hash} is in the recent window"
                );
            }
            let expected = block.serialize();
            assert_eq!(
                adapter.block_by_hash(&hash).expect("block").serialize(),
                expected,
                "block {hash} (evicted: {evicted})"
            );
            assert_eq!(
                adapter.block_bytes_by_hash(&hash).expect("bytes"),
                expected,
                "block {hash} (evicted: {evicted})"
            );
            assert_eq!(getblock_raw(&server, &hash), raw_reply(&expected));
        }
    }

    // An unknown block fails both ways with the same error, which the
    // handler turns into the same not-found reply.
    let unknown = Hash([0x5a; 32]);
    assert_eq!(
        adapter.block_bytes_by_hash(&unknown),
        adapter
            .block_by_hash(&unknown)
            .map(|block| block.serialize()),
    );
    assert_eq!(
        getblock_raw(&server, &unknown),
        format!(
            "{{\"jsonrpc\":\"1.0\",\"result\":null,\"error\":{{\"code\":-5,\"message\":\"Block not found: \
             {unknown}\"}},\"id\":1}}\n"
        )
    );
}
