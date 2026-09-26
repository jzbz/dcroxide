// SPDX-License-Identifier: ISC
//! The RPC server's log lines against dcrd's.  dcrd's `rpcserver`
//! package logs through its `UseLogger` logger: every failed Basic auth
//! at warn with the client's address (`checkAuthMAC`, `checkAuth`),
//! every internal error at error with its context (`rpcInternalErr`),
//! every reply it drops because it failed to marshal
//! (`processRequest`, `serviceRequest`), and every notification it
//! abandons on a failed agenda check.  The port's RPC crate had no
//! logger at all, so all of it was silent.
//!
//! The logger is process-wide, as dcrd's package variable is, so every
//! test in this binary shares one capture and looks only for lines that
//! name what it alone did.

use std::sync::{Arc, Mutex, OnceLock};

use dcroxide_chaincfg::mainnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_dcrjson::{GoValue, RpcId};
use dcroxide_rpc::dispatch::process_request;
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::log::{LogLevel, use_logger};
use dcroxide_rpc::server::{Config, RpcBestState, RpcChain, RpcTxMempooler, Server};
use dcroxide_rpc::websocket::{WsClient, ws_service_request};
use dcroxide_standalone::SubsidyCache;
use dcroxide_wire::{MsgTx, PROTOCOL_VERSION};

/// The lines a sink has captured, with their levels.
type Captured = Mutex<Vec<(LogLevel, String)>>;

/// Every line logged by this test binary.
fn captured() -> &'static Captured {
    static LINES: OnceLock<Arc<Captured>> = OnceLock::new();
    LINES.get_or_init(|| {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&lines);
        use_logger(Arc::new(move |level: LogLevel, msg: &str| {
            sink.lock().expect("capture").push((level, msg.to_string()));
        }));
        lines
    })
}

/// The captured lines containing `needle`.
fn lines_with(needle: &str) -> Vec<(LogLevel, String)> {
    captured()
        .lock()
        .expect("capture")
        .iter()
        .filter(|(_, line)| line.contains(needle))
        .cloned()
        .collect()
}

/// A chain at a fixed best state whose other seams are unwired, so any
/// handler that needs one fails with an internal error.
struct FixedChain;

impl RpcChain for FixedChain {
    fn best_snapshot(&self) -> RpcBestState {
        RpcBestState {
            hash: dcroxide_chainhash::Hash([7; 32]),
            prev_hash: dcroxide_chainhash::Hash([6; 32]),
            height: 100,
            bits: 0x1d00ffff,
            next_stake_diff: 0,
            total_subsidy: 0,
            block_size: 0,
            num_txns: 0,
        }
    }
}

fn server() -> Server<FixedChain> {
    server_with_mempool(Box::new(()))
}

/// A mempool holding one transaction under every hash.
struct OneTxMempool;

impl RpcTxMempooler for OneTxMempool {
    fn fetch_transaction(&self, _tx_hash: &Hash) -> Result<(MsgTx, i8), String> {
        Ok((MsgTx::default(), 0))
    }
}

fn server_with_mempool(tx_mempooler: Box<dyn RpcTxMempooler + Send + Sync>) -> Server<FixedChain> {
    let params = mainnet_params();
    Server::new(Config {
        chain: FixedChain,
        chain_params: params.clone(),
        subsidy_cache: Mutex::new(SubsidyCache::new(params)),
        min_relay_tx_fee: 10000,
        max_protocol_version: PROTOCOL_VERSION,
        sync_mgr: Box::new(()),
        conn_mgr: Box::new(()),
        client_cert_auth: false,
        tx_mempooler,
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
        rpc_user: "user".to_string(),
        rpc_pass: "pass".to_string(),
        rpc_limit_user: "limit".to_string(),
        rpc_limit_pass: "limitpass".to_string(),
    })
}

/// `Basic ` and the standard base64 of `user_pass`.
fn basic(user_pass: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::from("Basic ");
    for chunk in user_pass.as_bytes().chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> shift) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// dcrd warns "RPC authentication failure from <addr>" for a header
/// that matches neither user, and for a missing one when authentication
/// is required; a missing header on the websocket upgrade, which may
/// authenticate in-band later, and a good one are not logged.
#[test]
fn http_auth_failures_are_warned_with_the_client_address() {
    let server = server();
    captured();

    assert!(
        server
            .check_auth(Some(&basic("user:wrong")), true, "192.0.2.1:4001")
            .is_err()
    );
    assert!(server.check_auth(None, true, "192.0.2.1:4002").is_err());
    assert_eq!(
        server.check_auth(None, false, "192.0.2.1:4003"),
        Ok((false, false))
    );
    assert_eq!(
        server.check_auth(Some(&basic("user:pass")), true, "192.0.2.1:4004"),
        Ok((true, true))
    );
    assert_eq!(
        server.check_auth(Some(&basic("limit:limitpass")), true, "192.0.2.1:4005"),
        Ok((true, false))
    );

    for addr in ["192.0.2.1:4001", "192.0.2.1:4002"] {
        assert_eq!(
            lines_with(addr),
            vec![(
                LogLevel::Warn,
                format!("RPC authentication failure from {addr}")
            )],
        );
    }
    for addr in ["192.0.2.1:4003", "192.0.2.1:4004", "192.0.2.1:4005"] {
        assert!(lines_with(addr).is_empty(), "{addr} was logged");
    }
}

/// The websocket `authenticate` command's check is dcrd's
/// `checkAuthUserPass`, which warns through `checkAuthMAC` too.
#[test]
fn a_failed_websocket_authenticate_is_warned() {
    let server = server();
    captured();

    assert_eq!(
        server.check_auth_user_pass("user", "nope", "192.0.2.2:5001"),
        (false, false)
    );
    assert_eq!(
        server.check_auth_user_pass("user", "pass", "192.0.2.2:5002"),
        (true, true)
    );
    assert_eq!(
        lines_with("192.0.2.2:5001"),
        vec![(
            LogLevel::Warn,
            "RPC authentication failure from 192.0.2.2:5001".to_string()
        )],
    );
    assert!(lines_with("192.0.2.2:5002").is_empty());
}

/// An internal error reaches the client as the bare error text and the
/// log as `context: error` (dcrd `rpcInternalErr`); `livetickets`
/// fails with the context "Could not get live tickets".
#[test]
fn an_internal_error_is_logged_with_its_context() {
    let server = server();
    captured();

    let reply =
        process_request(&server, "1.0", "livetickets", &[], &RpcId::Int(1), true).expect("a reply");
    let seam_err = "RPC server seam live_tickets is not wired in this build";
    assert!(
        reply.contains(&format!(r#""code":-32603,"message":"{seam_err}""#)),
        "{reply}"
    );
    assert_eq!(
        lines_with("Could not get live tickets"),
        vec![(
            LogLevel::Error,
            format!("Could not get live tickets: {seam_err}")
        )],
    );
}

/// A reply that fails to marshal is dropped, and dcrd logs why: an id
/// of a type `MarshalResponse` refuses is the reachable case.
#[test]
fn a_reply_that_fails_to_marshal_is_logged() {
    let server = server();
    captured();

    let id = RpcId::Invalid("[]interface {}".to_string());
    assert_eq!(
        process_request(&server, "1.0", "getbestblockhash", &[], &id, true),
        None
    );
    let marshal = lines_with("the id of type '[]interface {}' is invalid");
    assert!(
        marshal.iter().any(|(level, line)| *level == LogLevel::Error
            && line.starts_with("Failed to marshal reply: ")),
        "{marshal:?}"
    );

    // The websocket path logs the command's name with it.
    let wsc = Mutex::new(WsClient::new(1));
    let cmd = GoValue::Struct(Vec::new());
    assert_eq!(
        ws_service_request(&server, &wsc, "1.0", "getbestblockhash", &cmd, &id),
        None
    );
    let marshal = lines_with("Failed to marshal reply for <getbestblockhash> command: ");
    assert_eq!(marshal.len(), 1, "{marshal:?}");
    assert_eq!(marshal[0].0, LogLevel::Error);
}

/// A notification abandoned because its agenda check failed is logged
/// twice, as dcrd's is: once by the server's check (`rpcInternalErr`
/// with its context) and once by the notifier, which prints that
/// internal error's `Error()` text, code included.
#[test]
fn a_notification_whose_agenda_check_fails_is_logged() {
    use dcroxide_rpc::websocket::{TemplateUpdateReason, notify_for_new_tx, notify_work};

    let server = server();
    captured();
    let seam_err = |seam: &str| format!("RPC server seam {seam} is not wired in this build");

    // A work notification: the blake3 agenda is checked against the
    // template's parent.
    let mut template = mainnet_params().genesis_block;
    template.header.prev_block = dcroxide_chainhash::Hash([0x42; 32]);
    let parent = template.header.prev_block;
    let mut work_client = WsClient::new(3);
    assert!(
        notify_work(
            &server,
            &[&mut work_client],
            template,
            TemplateUpdateReason::NewParent
        )
        .is_empty()
    );
    let blake3 = seam_err("is_blake3_pow_agenda_active");
    assert_eq!(
        lines_with(&format!("for block {parent}")),
        vec![(
            LogLevel::Error,
            format!(
                "Could not obtain blake3 proof of work agenda status for block {parent}: {blake3}"
            )
        )],
    );
    assert_eq!(
        lines_with("Could not obtain blake3 agenda status: "),
        vec![(
            LogLevel::Error,
            format!("Could not obtain blake3 agenda status: -32603: {blake3}")
        )],
    );

    // A transaction-accepted notification: the treasury agenda is
    // checked against the best block.
    let mut tx_client = WsClient::new(4);
    assert!(
        notify_for_new_tx(&server, &[&mut tx_client], &dcroxide_wire::MsgTx::default()).is_empty()
    );
    let treasury = seam_err("is_treasury_agenda_active");
    assert_eq!(
        lines_with("Could not obtain treasury agenda status: "),
        vec![(
            LogLevel::Error,
            format!("Could not obtain treasury agenda status: -32603: {treasury}")
        )],
    );
}

/// getrawtransaction wraps a failed treasury check in a second internal
/// error (`rpcInternalErr(err, "Treasury Status")`), so the client's
/// message is the first error's `Error()` text, `-32603: ` included,
/// and both errors are logged.
#[test]
fn getrawtransaction_wraps_a_failed_treasury_check_as_dcrd_does() {
    let server = server_with_mempool(Box::new(OneTxMempool));
    captured();

    let txid = format!("\"{}\"", "ab".repeat(32));
    let reply = process_request(
        &server,
        "1.0",
        "getrawtransaction",
        &[&txid, "1"],
        &RpcId::Int(1),
        true,
    )
    .expect("a reply");
    let seam_err = "RPC server seam is_treasury_agenda_active is not wired in this build";
    assert_eq!(
        reply,
        format!(
            r#"{{"jsonrpc":"1.0","result":null,"error":{{"code":-32603,"message":"-32603: {seam_err}"}},"id":1}}"#
        )
    );
    assert_eq!(
        lines_with("Treasury Status: "),
        vec![(
            LogLevel::Error,
            format!("Treasury Status: -32603: {seam_err}")
        )],
    );
}

/// `messageToHex` logs an encode failure under the message's Go type as
/// `%T` prints it (`Failed to encode msg of type *wire.MsgGetCFTypes`);
/// the reply carries the error text alone.
#[test]
fn an_encode_failure_is_logged_with_the_go_message_type() {
    captured();

    let err = dcroxide_rpc::txresults::message_to_hex(&dcroxide_wire::Message::GetCFTypes, 0)
        .expect_err("getcftypes is invalid at protocol version 0");
    assert_eq!(
        lines_with("Failed to encode msg of type "),
        vec![(
            LogLevel::Error,
            format!(
                "Failed to encode msg of type *wire.MsgGetCFTypes: {}",
                err.message
            )
        )],
    );
}
