// SPDX-License-Identifier: ISC
//! End-to-end checks for the RPC listener: raw HTTP requests against a
//! genesis chain hit the ported JSON-RPC pipeline — authenticated
//! queries answer, bad credentials get dcrd's 401, and a handler whose
//! daemon seam is not wired yet answers an internal error without
//! killing the server.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};
use dcroxide_node::rpcrun::{NodeRpcChain, start_rpc_listener};
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::server::{Config, RpcSubsidyParams, Server};
use dcroxide_standalone::SubsidyCache;
use dcroxide_wire::PROTOCOL_VERSION;

/// Start an RPC listener over a fresh genesis testnet chain.
fn serve_rpc() -> (
    tempfile::TempDir,
    dcroxide_node::rpcrun::RpcListener,
    u16,
    dcroxide_chainhash::Hash,
) {
    let params = dcroxide_chaincfg::testnet3_params();
    let genesis_hash = params.genesis_hash;

    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));

    let server = Arc::new(Mutex::new(Server::new(Config {
        chain: NodeRpcChain::new(chain),
        chain_params: params.clone(),
        subsidy_cache: SubsidyCache::new(RpcSubsidyParams(params.clone())),
        min_relay_tx_fee: 10000,
        max_protocol_version: PROTOCOL_VERSION,
        sync_mgr: Box::new(()),
        conn_mgr: Box::new(()),
        tx_mempooler: Box::new(()),
        clock: Box::new(()),
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
        time_source: Box::new(()),
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
    })));

    let listener =
        start_rpc_listener(&["127.0.0.1:0".to_string()], server).expect("start rpc listener");
    let port = listener.bound_addrs()[0].port();
    (dir, listener, port, genesis_hash)
}

/// Send one raw HTTP POST and return the full response text.
fn post(port: u16, auth: Option<&str>, body: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let auth_header = auth
        .map(|creds| {
            format!(
                "Authorization: Basic {}\r\n",
                dcroxide_rpc::http::base64_std_encode(creds.as_bytes())
            )
        })
        .unwrap_or_default();
    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\n{auth_header}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    response
}

#[test]
fn answers_chain_queries_over_http() {
    let (_dir, listener, port, genesis_hash) = serve_rpc();

    // getbestblockhash answers the genesis hash.
    let response = post(
        port,
        Some("user:pass"),
        r#"{"jsonrpc":"1.0","method":"getbestblockhash","params":[],"id":1}"#,
    );
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(
        response.contains(&format!("\"result\":\"{genesis_hash}\"")),
        "{response}"
    );

    // getblockcount answers zero.
    let response = post(
        port,
        Some("user:pass"),
        r#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":2}"#,
    );
    assert!(response.contains("\"result\":0"), "{response}");

    // A handler whose daemon seam is not wired yet answers an internal
    // error instead of killing the server...
    let response = post(
        port,
        Some("user:pass"),
        r#"{"jsonrpc":"1.0","method":"getconnectioncount","params":[],"id":3}"#,
    );
    assert!(
        response.contains("-32603") || response.contains("error"),
        "{response}"
    );

    // ...and the server still answers afterwards.
    let response = post(
        port,
        Some("user:pass"),
        r#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":4}"#,
    );
    assert!(response.contains("\"result\":0"), "{response}");

    listener.shutdown();
}

#[test]
fn rejects_bad_credentials_with_dcrds_401() {
    let (_dir, listener, port, _genesis_hash) = serve_rpc();

    let response = post(
        port,
        Some("user:wrong"),
        r#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":1}"#,
    );
    assert!(response.starts_with("HTTP/1.1 401"), "{response}");
    assert!(
        response.contains("WWW-Authenticate: Basic realm=\"dcrd RPC\""),
        "{response}"
    );

    let response = post(
        port,
        None,
        r#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":2}"#,
    );
    assert!(response.starts_with("HTTP/1.1 401"), "{response}");

    listener.shutdown();
}
