// SPDX-License-Identifier: ISC
//! The mixing RPCs over the daemon's own seams.
//!
//! The daemon built a live mixing pool for the peers but handed the RPC
//! server `mix_pooler: ()` and left `accept_mix_message` at its trait
//! default: `getmixpairrequests` answered `[]` whatever the pool held,
//! `getmixmessage` reported every hash as not found, and
//! `sendrawmixmessage` failed every message with "RPC server seam
//! accept_mix_message is not wired in this build".  dcrd wires
//! `MixPooler: s.mixMsgPool` and accepts into the same pool.

// Test-harness arithmetic over a fixed height.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::{Arc, Mutex};

use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_dcrec::secp256k1::PrivateKey;
use dcroxide_mixing::{MixBlockChain, Pool, PoolMessage, SCRIPT_CLASS_P2PKH_V0, sign_message};
use dcroxide_node::rpcrun::{
    IdleCpuMiner, NodeRpcChain, NodeRpcConnManager, NodeRpcMixPooler, NodeRpcSyncManager,
};
use dcroxide_node::runtime::ConnectedPeers;
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::server::{Config, RpcMixPooler, RpcSubsidyParams, Server};
use dcroxide_standalone::SubsidyCache;
use dcroxide_wire::{MixPairReqUTXO, MsgMixPairReq, OutPoint, PROTOCOL_VERSION};

/// The text every trait default reports (`server.rs` `unwired_seam`).
const UNWIRED: &str = "is not wired in this build";

/// A signed pair request over one output that no chain holds.
fn pair_request(tip_height: i64) -> MsgMixPairReq {
    let mut bytes = [0u8; 32];
    bytes[0] = 0x22;
    bytes[31] = 9;
    let priv_key = PrivateKey::from_bytes(&bytes).expect("private key");
    let id = priv_key.public_key().serialize_compressed();
    let mut hash = [0u8; 32];
    hash[0] = 9;
    let mut pr = MsgMixPairReq {
        signature: [0u8; 64],
        identity: id,
        expiry: (tip_height + 10) as u32,
        mix_amount: 10_000_000,
        script_class: SCRIPT_CLASS_P2PKH_V0.to_string(),
        tx_version: 1,
        lock_time: 0,
        message_count: 1,
        input_value: 10_100_000,
        utxos: vec![MixPairReqUTXO {
            out_point: OutPoint {
                hash: Hash(hash),
                index: 3,
                tree: 0,
            },
            script: Vec::new(),
            pub_key: id.to_vec(),
            signature: vec![0u8; 64],
            opcode: 0,
        }],
        change: None,
        flags: 0,
        pairing_flags: 0,
    };
    sign_message(&mut pr, &priv_key).expect("sign pair request");
    pr
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The message's wire payload at the mixing protocol version, in hex.
fn message_hex(msg: &dcroxide_wire::Message) -> String {
    hex(&msg
        .encode_payload(dcroxide_wire::MIX_VERSION)
        .expect("encode"))
}

/// A chain view at a fixed height, for a pool with no UTXO fetcher.
struct StubChain {
    params: Params,
}

impl MixBlockChain for StubChain {
    fn chain_params(&self) -> &Params {
        &self.params
    }

    fn current_tip(&self) -> (Hash, i64) {
        (Hash([0u8; 32]), 100)
    }
}

/// A server whose sync manager submits to the daemon's shared pool and
/// whose mix pooler reads `pooler`.
fn server_with(
    pooler: Box<dyn RpcMixPooler + Send + Sync>,
) -> (tempfile::TempDir, Server<NodeRpcChain>) {
    let params = dcroxide_chaincfg::simnet_params();
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
    let mix_pool =
        dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone(), &tx_pool);
    let sync_manager = Arc::new(Mutex::new(dcroxide_node::sync::new_sync_manager(
        Arc::clone(&chain),
        &params,
        false,
        8,
        1000,
        Arc::clone(&tx_pool),
        Arc::clone(&mix_pool),
    )));
    let server = Server::new(Config {
        chain: NodeRpcChain::new(Arc::clone(&chain), params.clone()),
        chain_params: params.clone(),
        subsidy_cache: std::sync::Mutex::new(SubsidyCache::new(RpcSubsidyParams(params.clone()))),
        min_relay_tx_fee: 10000,
        max_protocol_version: PROTOCOL_VERSION,
        sync_mgr: Box::new(
            NodeRpcSyncManager::new(sync_manager, Arc::clone(&tx_pool)).with_mix_pool(mix_pool),
        ),
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
        mix_pooler: pooler,
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
    });
    (dir, server)
}

/// Run one JSON-RPC request as an admin and return the response text.
fn call(server: &Server<NodeRpcChain>, method: &str, params: &str) -> String {
    let body = format!(r#"{{"jsonrpc":"1.0","id":1,"method":"{method}","params":{params}}}"#);
    let response = dcroxide_rpc::http::process_body(server, &body, true);
    String::from_utf8(response).expect("utf-8 response")
}

/// getmixpairrequests and getmixmessage read the pool: a pair request it
/// holds is listed and found by hash.
#[test]
fn the_mix_queries_read_the_pool() {
    let pr = pair_request(100);
    let hash = PoolMessage::PR(pr.clone()).mix_hash().expect("hash");
    let mut pool = Pool::new(
        StubChain {
            params: dcroxide_chaincfg::simnet_params(),
        },
        None,
    );
    pool.accept_message(&PoolMessage::PR(pr.clone()), 0, &|_| false)
        .expect("the pool accepts the pair request");
    let (_dir, server) = server_with(Box::new(NodeRpcMixPooler::new(Arc::new(Mutex::new(pool)))));
    let pr_hex = message_hex(&dcroxide_wire::Message::MixPairReq(pr));

    let listed = call(&server, "getmixpairrequests", "[]");
    assert!(
        listed.contains(&format!(r#""result":["{pr_hex}"]"#)),
        "{listed}"
    );

    let found = call(&server, "getmixmessage", &format!(r#"["{hash}"]"#));
    assert!(found.contains(r#""error":null"#), "{found}");
    assert!(found.contains(r#""type":"mixpairreq""#), "{found}");
    assert!(found.contains(&pr_hex), "{found}");
}

/// sendrawmixmessage submits to the daemon's pool, whose own checks
/// answer -- here the pair request's output exists on no chain.
#[test]
fn sendrawmixmessage_reaches_the_pool() {
    let (_dir, server) = server_with(Box::new(()));
    let pr_hex = message_hex(&dcroxide_wire::Message::MixPairReq(pair_request(0)));
    let rejected = call(
        &server,
        "sendrawmixmessage",
        &format!(r#"["mixpairreq","{pr_hex}"]"#),
    );
    assert!(rejected.contains("Rejected mix message: "), "{rejected}");
    assert!(!rejected.contains(UNWIRED), "{rejected}");
}
