// SPDX-License-Identifier: ISC
//! `addnode` and `node connect` answer a canceled or timed-out
//! connection attempt with dcrd's cancel errors.
//!
//! dcrd's handlers test the `Connect` error with `errors.Is` against
//! `context.Canceled` and `context.DeadlineExceeded`
//! (`internal/rpcserver/rpcserver.go` handleAddNode and handleNode) and
//! return `rpcCancelError("<subcmd>: connection attempt to <addr>
//! canceled")` or `rpcCancelError("<subcmd>: timeout connecting to
//! <addr>")`.  The port mapped every failure to an internal error, so a
//! dial to a black-holed address came back as an internal error
//! carrying the dial text instead of dcrd's cancel code and message.

use std::sync::Mutex;

use dcroxide_chaincfg::mainnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_dcrjson::{GoValue, RPCError, codes};
use dcroxide_rpc::handlers::{handle_add_node, handle_node};
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::server::{
    CONNECT_CANCELED, CONNECT_DEADLINE_EXCEEDED, Config, RpcBestState, RpcChain, RpcConnManager,
    RpcPeerInfo, Server,
};
use dcroxide_standalone::SubsidyCache;
use dcroxide_wire::PROTOCOL_VERSION;

/// A chain answering only the best-state query.
struct StubChain;

impl RpcChain for StubChain {
    fn best_snapshot(&self) -> RpcBestState {
        RpcBestState {
            hash: Hash([0x11; 32]),
            prev_hash: Hash([0x22; 32]),
            height: 1,
            bits: 0x1d00_ffff,
            next_stake_diff: 1,
            total_subsidy: 0,
            block_size: 0,
            num_txns: 0,
        }
    }
}

/// A connection manager whose every connect fails with `error`.
struct FailingConnMgr {
    error: &'static str,
}

impl RpcConnManager for FailingConnMgr {
    fn connect(&self, _addr: &str, _permanent: bool) -> Result<(), String> {
        Err(self.error.to_string())
    }

    fn connected_peers(&self) -> Vec<RpcPeerInfo> {
        Vec::new()
    }
}

fn server(error: &'static str) -> Server<StubChain> {
    let params = mainnet_params();
    Server::new(Config {
        chain: StubChain,
        chain_params: params.clone(),
        subsidy_cache: Mutex::new(SubsidyCache::new(params)),
        min_relay_tx_fee: 10000,
        max_protocol_version: PROTOCOL_VERSION,
        sync_mgr: Box::new(()),
        conn_mgr: Box::new(FailingConnMgr { error }),
        client_cert_auth: false,
        tx_mempooler: Box::new(()),
        clock: Box::new(()),
        interfaces: Box::new(NoInterfaces),
        rand_u64: Box::new(|| 0),
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
        test_net: false,
        runtime_version: String::new(),
        cpu_miner: Box::new(()),
        mix_pooler: Box::new(()),
        profiler_mgr: Box::new(()),
        addr_manager: Box::new(()),
        mining_addrs: Vec::new(),
        user_agent_version: String::new(),
        net_info: Vec::new(),
        services: 0,
        request_shutdown: Box::new(|| {}),
        allow_unsynced_mining: false,
        rpc_user: String::new(),
        rpc_pass: String::new(),
        rpc_limit_user: String::new(),
        rpc_limit_pass: String::new(),
    })
}

fn add_node(error: &'static str, sub_cmd: &str) -> RPCError {
    let cmd = GoValue::Struct(vec![
        GoValue::String("10.255.255.1".to_string()),
        GoValue::String(sub_cmd.to_string()),
    ]);
    handle_add_node(&server(error), &cmd).expect_err("the connect fails")
}

fn node_connect(error: &'static str) -> RPCError {
    let cmd = GoValue::Struct(vec![
        GoValue::String("connect".to_string()),
        GoValue::String("10.255.255.1".to_string()),
        GoValue::String("temp".to_string()),
    ]);
    handle_node(&server(error), &cmd).expect_err("the connect fails")
}

#[test]
fn a_timed_out_connect_is_dcrds_timeout_error() {
    let err = add_node(CONNECT_DEADLINE_EXCEEDED, "onetry");
    assert_eq!(err.code, codes::CANCEL);
    assert_eq!(
        err.message,
        "onetry: timeout connecting to 10.255.255.1:9108"
    );

    let err = node_connect(CONNECT_DEADLINE_EXCEEDED);
    assert_eq!(err.code, codes::CANCEL);
    assert_eq!(
        err.message,
        "connect: timeout connecting to 10.255.255.1:9108"
    );
}

#[test]
fn a_canceled_connect_is_dcrds_cancel_error() {
    let err = add_node(CONNECT_CANCELED, "onetry");
    assert_eq!(err.code, codes::CANCEL);
    assert_eq!(
        err.message,
        "onetry: connection attempt to 10.255.255.1:9108 canceled"
    );

    let err = node_connect(CONNECT_CANCELED);
    assert_eq!(err.code, codes::CANCEL);
    assert_eq!(
        err.message,
        "connect: connection attempt to 10.255.255.1:9108 canceled"
    );
}

/// Any other failure stays an internal error carrying the raw text
/// (`rpcInternalErr` logs its "failed operation on" prefix only).
#[test]
fn another_connect_failure_stays_an_internal_error() {
    let internal = dcroxide_dcrjson::err_rpc_internal().code;
    let refused = "dial tcp 10.255.255.1:9108: connect: connection refused";
    let err = add_node(refused, "onetry");
    assert_eq!(err.code, internal);
    assert_eq!(err.message, refused);

    let err = node_connect("tor has been disabled");
    assert_eq!(err.code, internal);
    assert_eq!(err.message, "tor has been disabled");
}
