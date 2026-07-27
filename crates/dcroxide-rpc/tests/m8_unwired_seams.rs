// SPDX-License-Identifier: ISC
//! Regression coverage for M-8: a server seam the daemon has not
//! wired up must answer a remote request with an ordinary JSON-RPC
//! error, never by unwinding the handler thread.
//!
//! The `RpcChain`/`RpcSyncManager`/`RpcConnManager` trait defaults
//! used to be `unimplemented!()`, so any JSON-RPC method reaching an
//! unwired seam panicked inside the handler.  Most of those methods
//! are on dcrd's limited-credential list, so the panic was reachable
//! without admin rights, and the HTTP layer could only contain it by
//! catching the unwind and force-recovering the server mutex with
//! `into_inner()` — reusing a `Server` that unwound mid-mutation.
//!
//! Every case below drives a request through the normal dispatch
//! path (`process_request`, including the limited-user gate) against
//! a server whose seams are left at their defaults.  Restoring any
//! `unimplemented!()` turns these assertions into a panic, which
//! fails the test.

use dcroxide_chaincfg::mainnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_dcrjson::RpcId;
use dcroxide_rpc::dispatch::{RPC_LIMITED, process_request};
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::server::{Config, RpcBestState, RpcChain, RpcSubsidyParams, Server};
use dcroxide_standalone::SubsidyCache;
use dcroxide_wire::PROTOCOL_VERSION;

/// The JSON-RPC internal error code every unwired seam reports
/// through (dcrd `ErrRPCInternal`).
const INTERNAL_ERROR_CODE: &str = "\"code\":-32603";

/// A chain that only answers the best-state query, leaving every
/// other seam at its trait default: the shape of a daemon build in
/// which a seam was never wired up.
struct UnwiredChain;

impl RpcChain for UnwiredChain {
    fn best_snapshot(&self) -> RpcBestState {
        RpcBestState {
            hash: Hash([0x11; 32]),
            prev_hash: Hash([0x22; 32]),
            height: 432_100,
            bits: 0x1a01_a1a1,
            next_stake_diff: 14_428_162_590,
            total_subsidy: 1_122_503_888_072_909,
            block_size: 4_000,
            num_txns: 7,
        }
    }
}

/// A server over [`UnwiredChain`] with every optional dependency left
/// at the no-op stand-in, so each seam under test resolves to its
/// trait default.
fn unwired_server() -> Server<UnwiredChain> {
    let params = mainnet_params();
    Server::new(Config {
        chain: UnwiredChain,
        chain_params: params.clone(),
        subsidy_cache: std::sync::Mutex::new(SubsidyCache::new(RpcSubsidyParams(params))),
        min_relay_tx_fee: 10000,
        max_protocol_version: PROTOCOL_VERSION,
        sync_mgr: Box::new(()),
        conn_mgr: Box::new(()),
        client_cert_auth: false,
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
        rpc_user: "admin".to_string(),
        rpc_pass: "adminpass".to_string(),
        rpc_limit_user: "limited".to_string(),
        rpc_limit_pass: "limitedpass".to_string(),
    })
}

/// Drive one request through the full dispatch path and return the
/// marshalled response body.
fn request(method: &str, raw_params: &[&str], is_admin: bool) -> String {
    let server = unwired_server();
    process_request(&server, "2.0", method, raw_params, &RpcId::Int(1), is_admin)
        .expect("a request with a non-null id always produces a reply")
}

/// Assert the reply is a JSON-RPC internal error naming the seam that
/// is not wired, rather than a panic or a fabricated success.
fn assert_unwired_error(body: &str, seam: &str) {
    assert!(
        body.contains(INTERNAL_ERROR_CODE),
        "expected the internal error code for the unwired {seam} seam, got: {body}"
    );
    assert!(
        body.contains(seam),
        "the error must name the unwired seam so an operator can tell it apart from a \
         chain failure, got: {body}"
    );
    assert!(
        body.contains("not wired in this build"),
        "the error must say the seam is unwired, got: {body}"
    );
    assert!(
        body.contains("\"result\":null"),
        "an unwired seam must not produce a result, got: {body}"
    );
}

/// `getblocksubsidy` at any height at or below the tip reaches
/// `RpcChain::header_by_height`, and it is on dcrd's limited list, so
/// this is the sharpest form of the finding: an ordinary
/// limited-credential request used to panic the handler.
#[test]
fn get_block_subsidy_limited_user_gets_error_not_panic() {
    assert!(RPC_LIMITED.contains(&"getblocksubsidy"));
    let body = request("getblocksubsidy", &["100", "5"], false);
    assert_unwired_error(&body, "header_by_height");
}

/// `estimatestakediff` reaches
/// `RpcChain::estimate_next_stake_difficulty` and is likewise
/// reachable with a limited credential.
#[test]
fn estimate_stake_diff_limited_user_gets_error_not_panic() {
    assert!(RPC_LIMITED.contains(&"estimatestakediff"));
    let body = request("estimatestakediff", &[], false);
    assert_unwired_error(&body, "estimate_next_stake_difficulty");
}

/// `gettreasurybalance` reaches `RpcChain::treasury_balance`, whose
/// failure type carries dcrd's classification flags; the unwired
/// default must leave them clear so the handler renders a plain
/// internal error instead of claiming the block is unknown.
#[test]
fn get_treasury_balance_limited_user_gets_error_not_panic() {
    assert!(RPC_LIMITED.contains(&"gettreasurybalance"));
    let body = request("gettreasurybalance", &[], false);
    assert_unwired_error(&body, "treasury_balance");
    assert!(
        !body.contains("Block not found"),
        "an unwired seam must not be reported as a missing block, got: {body}"
    );
}

/// `invalidateblock` is admin-only, but the admin path used to panic
/// in exactly the same way; it reaches `RpcChain::invalidate_block`.
#[test]
fn invalidate_block_admin_gets_error_not_panic() {
    assert!(!RPC_LIMITED.contains(&"invalidateblock"));
    let body = request(
        "invalidateblock",
        &["\"00000000000000001919191919191919191919191919191919191919191919\""],
        true,
    );
    assert_unwired_error(&body, "invalidate_block");
}

/// The limited-user gate still rejects an admin-only method before
/// the seam is ever consulted, so closing the panic did not widen
/// what a limited credential can reach.
#[test]
fn invalidate_block_stays_admin_only() {
    let body = request(
        "invalidateblock",
        &["\"00000000000000001919191919191919191919191919191919191919191919\""],
        false,
    );
    assert!(
        body.contains("limited user not authorized for this method"),
        "the limited-user gate must still reject invalidateblock, got: {body}"
    );
    assert!(
        !body.contains("invalidate_block"),
        "the seam must not run for an unauthorized caller, got: {body}"
    );
}

/// `RpcChain::chain_tips` returns a bare `Vec`, so its default cannot
/// report a failure the way the fallible seams do; it must still
/// answer a limited-credential `getchaintips` with a well-formed
/// response instead of unwinding.
#[test]
fn get_chain_tips_limited_user_does_not_panic() {
    assert!(RPC_LIMITED.contains(&"getchaintips"));
    let body = request("getchaintips", &[], false);
    assert!(
        body.contains("\"error\":null"),
        "the unwired chain_tips default must answer, not fail, got: {body}"
    );
    assert!(
        body.contains("\"result\":[]"),
        "the unwired chain_tips default must report no tips, got: {body}"
    );
}
