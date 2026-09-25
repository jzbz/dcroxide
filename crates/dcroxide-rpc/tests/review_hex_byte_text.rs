// SPDX-License-Identifier: ISC
//! The invalid-hex-byte error text four RPC paths return, pinned against
//! the strings dcrd returns for the same requests.
//!
//! Each surfaces Go's `hex.InvalidByteError`, whose text is
//! `encoding/hex: invalid byte: %#U`: `submitblock` through
//! `rpcInternalErr(err, "Block decode")`, which returns `err.Error()`
//! alone (`rpcserver.go:414-421`), `sendrawmixmessage` through
//! `rpcDeserializationError("Could not decode mix message: %v", err)`,
//! `getheaders` through `rpcInvalidError("Failed to decode hashstop:
//! %v", err)` over `chainhash.Decode` (`rpcserver.go:2495-2498`), and
//! websocket `loadtxfilter` with `err.Error()` from `NewHashFromStr` as
//! the message (`rpcwebsocket.go:2104-2108`).  `%#U` appends the
//! character in quotes only when `strconv.IsPrint` accepts it, and then
//! writes it raw; the port rendered it with Rust's char `Debug`, which
//! quotes control characters and escapes `'` and `\`.  Before the fix,
//! getheaders did not produce Go's text at all, even for a plain letter.

use std::sync::Mutex;

use dcroxide_chaincfg::mainnet_params;
use dcroxide_dcrjson::{GoValue, RPCError, Registry, parse_params};
use dcroxide_rpc::handlers;
use dcroxide_rpc::server::{Config, RpcChain, Server};
use dcroxide_rpc::websocket::{WsClient, handle_load_tx_filter};
use dcroxide_rpctypes::{method, register_all};
use dcroxide_standalone::SubsidyCache;
use dcroxide_wire::PROTOCOL_VERSION;

/// No chain access: every request fails while decoding, before the
/// handler reaches the chain.
struct NoChain;

impl RpcChain for NoChain {}

fn server() -> Server<NoChain> {
    let params = mainnet_params();
    Server::new(Config {
        chain: NoChain,
        chain_params: params.clone(),
        subsidy_cache: std::sync::Mutex::new(SubsidyCache::new(params)),
        min_relay_tx_fee: 10000,
        max_protocol_version: PROTOCOL_VERSION,
        sync_mgr: Box::new(()),
        conn_mgr: Box::new(()),
        client_cert_auth: false,
        tx_mempooler: Box::new(()),
        clock: Box::new(()),
        interfaces: Box::new(dcroxide_rpc::helpers::NoInterfaces),
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

/// Run one request, its parameters given as JSON, through dcrd's
/// parameter parsing and the handler, and return its error.
fn call_err(server: &Server<NoChain>, method_name: &str, params: &[&str]) -> RPCError {
    let mut registry = Registry::new();
    register_all(&mut registry);
    let cmd = parse_params(&registry, &method(method_name), params)
        .unwrap_or_else(|e| panic!("{method_name} {params:?}: parse params: {e:?}"));
    let cmd = GoValue::Struct(cmd.fields);
    let wsc = Mutex::new(WsClient::new(1));
    let result = match method_name {
        "submitblock" => handlers::handle_submit_block(server, &cmd),
        "sendrawmixmessage" => handlers::handle_send_raw_mix_message(server, &cmd),
        "getheaders" => handlers::handle_get_headers(server, &cmd),
        "loadtxfilter" => handle_load_tx_filter(server, &wsc, &cmd),
        other => panic!("unknown method {other}"),
    };
    match result {
        Ok(value) => panic!("{method_name} {params:?}: expected an error, got {value:?}"),
        Err(err) => err,
    }
}

/// dcrjson's `ErrRPCInvalidParameter`, `ErrRPCDeserialization` and
/// `ErrRPCInternal` codes.
const INVALID_PARAMETER: i32 = -8;
const DESERIALIZATION: i32 = -22;
const INTERNAL: i32 = -32603;

/// The JSON string literal for `s`, escaping what JSON requires.
fn q(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A loadtxfilter parameter list watching one outpoint with the given
/// hash string.
fn outpoint(hash: &str) -> String {
    format!("[{{\"hash\":{},\"tree\":0,\"index\":0}}]", q(hash))
}

#[test]
fn invalid_hex_bytes_reach_clients_as_dcrd_words_them() {
    let server = server();
    let hex = |b: &str| -> String { format!("encoding/hex: invalid byte: {b}") };

    // (bad character, Go's `%#U` rendering of it)
    let bytes = [
        ('\'', "U+0027 '''"),
        ('\\', "U+005C '\\'"),
        ('\u{1}', "U+0001"),
        ('\t', "U+0009"),
        ('\u{7f}', "U+007F"),
        ('z', "U+007A 'z'"),
    ];
    for (c, rendered) in bytes {
        let pair = format!("0{c}");

        let err = call_err(&server, "submitblock", &[&q(&pair)]);
        assert_eq!(
            (err.code, err.message.as_str()),
            (INTERNAL, hex(rendered).as_str()),
            "submitblock {pair:?}"
        );

        let err = call_err(&server, "sendrawmixmessage", &[&q("mixpairreq"), &q(&pair)]);
        assert_eq!(
            (err.code, err.message.as_str()),
            (
                DESERIALIZATION,
                format!("Could not decode mix message: {}", hex(rendered)).as_str()
            ),
            "sendrawmixmessage {pair:?}"
        );

        let err = call_err(&server, "getheaders", &["[]", &q(&pair)]);
        assert_eq!(
            (err.code, err.message.as_str()),
            (
                INVALID_PARAMETER,
                format!("Failed to decode hashstop: {}", hex(rendered)).as_str()
            ),
            "getheaders {pair:?}"
        );

        let err = call_err(
            &server,
            "loadtxfilter",
            &["false", "[]", &outpoint(&c.to_string())],
        );
        assert_eq!(
            (err.code, err.message.as_str()),
            (INVALID_PARAMETER, hex(rendered).as_str()),
            "loadtxfilter {c:?}"
        );
    }

    // The size error keeps chainhash's `ErrHashStrSize` text.
    let long = "0".repeat(65);
    let err = call_err(&server, "getheaders", &["[]", &q(&long)]);
    assert_eq!(
        err.message,
        "Failed to decode hashstop: max hash string length is 64 bytes"
    );
    let err = call_err(&server, "loadtxfilter", &["false", "[]", &outpoint(&long)]);
    assert_eq!(err.message, "max hash string length is 64 bytes");
}
