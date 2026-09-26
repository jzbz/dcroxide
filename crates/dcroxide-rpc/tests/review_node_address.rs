// SPDX-License-Identifier: ISC
//! `addnode` and `node` split their target with Go's `net.SplitHostPort`
//! exactly, stray brackets included.
//!
//! Go's `SplitHostPort` (`net/ipsock.go`) rejects a '[' past the opening
//! one and a ']' past the closing one.  dcrd's `normalizeAddress` then
//! keeps the whole target as the host and appends the default port, and
//! `handleNode`'s disconnect and remove arms answer "invalid address or
//! node ID" when neither `SplitHostPort` nor `ParseIP` accepts it
//! (`internal/rpcserver/rpcserver.go`).  The port's copy skipped both
//! scans in its bracketed branch, so `[::1]:9108]` split into `::1` and
//! `9108]`: addnode handed the connection manager `[::1]:9108]` where dcrd
//! hands it `[[::1]:9108]]:9108`, and `node disconnect` went on to the
//! connection manager instead of answering the invalid-parameter error.

use std::sync::Mutex;

use dcroxide_chaincfg::mainnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_dcrjson::{GoValue, codes};
use dcroxide_rpc::handlers::{handle_add_node, handle_node};
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::server::{Config, RpcBestState, RpcChain, RpcConnManager, RpcPeerInfo, Server};
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

/// A connection manager recording every address it is handed.
#[derive(Default)]
struct RecordingConnMgr {
    calls: Mutex<Vec<String>>,
}

impl RecordingConnMgr {
    fn record(&self, call: String) -> Result<(), String> {
        self.calls.lock().unwrap().push(call);
        Ok(())
    }
}

impl RpcConnManager for &'static RecordingConnMgr {
    fn connect(&self, addr: &str, permanent: bool) -> Result<(), String> {
        self.record(format!("connect {addr} {permanent}"))
    }

    fn remove_by_addr(&self, addr: &str) -> Result<(), String> {
        self.record(format!("remove {addr}"))
    }

    fn disconnect_by_addr(&self, addr: &str) -> Result<(), String> {
        self.record(format!("disconnect {addr}"))
    }

    fn connected_peers(&self) -> Vec<RpcPeerInfo> {
        Vec::new()
    }
}

fn server(conn_mgr: &'static RecordingConnMgr) -> Server<StubChain> {
    let params = mainnet_params();
    Server::new(Config {
        chain: StubChain,
        chain_params: params.clone(),
        subsidy_cache: Mutex::new(SubsidyCache::new(params)),
        min_relay_tx_fee: 10000,
        max_protocol_version: PROTOCOL_VERSION,
        sync_mgr: Box::new(()),
        conn_mgr: Box::new(conn_mgr),
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

fn strs(items: &[&str]) -> GoValue {
    GoValue::Struct(
        items
            .iter()
            .map(|s| GoValue::String(s.to_string()))
            .collect(),
    )
}

/// `addnode` with a target Go cannot split normalizes the whole target
/// with the default port, as dcrd's `normalizeAddress` does.
#[test]
fn addnode_keeps_a_target_with_stray_brackets_whole() {
    let conn_mgr: &'static RecordingConnMgr = Box::leak(Box::default());
    let server = server(conn_mgr);
    for (target, sub_cmd) in [
        ("[::1]:9108]", "add"),
        ("[a[b]:80", "onetry"),
        ("[abc", "remove"),
        ("a]:80", "add"),
        ("[::1]:19108", "add"),
        ("[::1]", "add"),
    ] {
        handle_add_node(&server, &strs(&[target, sub_cmd])).expect("recorded");
    }
    assert_eq!(
        *conn_mgr.calls.lock().unwrap(),
        [
            "connect [[::1]:9108]]:9108 true",
            "connect [[a[b]:80]:9108 false",
            "remove [abc:9108",
            "connect [a]:80]:9108 true",
            "connect [::1]:19108 true",
            "connect [[::1]]:9108 true",
        ]
    );
}

/// `node disconnect` and `node remove` answer dcrd's invalid-parameter
/// error for a target neither `SplitHostPort` nor `ParseIP` accepts, and
/// never reach the connection manager.
#[test]
fn node_rejects_a_target_with_stray_brackets() {
    let conn_mgr: &'static RecordingConnMgr = Box::leak(Box::default());
    let server = server(conn_mgr);
    for (sub_cmd, target) in [
        ("disconnect", "[::1]:9108]"),
        ("remove", "[::1]:9108]"),
        ("disconnect", "[a[b]:80"),
        ("remove", "[a]:[1"),
    ] {
        let cmd = GoValue::Struct(vec![
            GoValue::String(sub_cmd.to_string()),
            GoValue::String(target.to_string()),
            GoValue::Null,
        ]);
        let err = handle_node(&server, &cmd).expect_err(target);
        assert_eq!(err.code, codes::INVALID_PARAMETER, "{sub_cmd} {target}");
        assert_eq!(
            err.message,
            format!("{sub_cmd}: invalid address or node ID"),
            "{target}"
        );
    }
    assert!(conn_mgr.calls.lock().unwrap().is_empty());

    // A well-formed bracketed target still goes through.
    let cmd = GoValue::Struct(vec![
        GoValue::String("disconnect".to_string()),
        GoValue::String("[::1]:9108".to_string()),
        GoValue::Null,
    ]);
    handle_node(&server, &cmd).expect("recorded");
    assert_eq!(*conn_mgr.calls.lock().unwrap(), ["disconnect [::1]:9108"]);
}
