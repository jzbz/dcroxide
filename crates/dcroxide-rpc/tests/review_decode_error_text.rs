// SPDX-License-Identifier: ISC
//! The decode error text five RPC handlers return, pinned against the
//! strings dcrd returns for the same requests.
//!
//! dcrd's handlers print the wire error's own text: `decoderawtransaction`
//! and `sendrawtransaction` answer `rpcDeserializationError("Could not
//! decode Tx: %v", err)` (`rpcserver.go:1418`, `:4415`), `submitblock`
//! answers `rpcInternalErr(err, "Block decode")`, which returns
//! `err.Error()` alone (`rpcserver.go:414-421`, `:4586`),
//! `getrawtransaction` does the same for a stored transaction that does
//! not decode (`rpcserver.go:3036-3039`), and `sendrawmixmessage` answers
//! `rpcDeserializationError("Could not decode mix message: %v", err)`
//! (`rpcserver.go:4372`).  The wire text itself is pinned against dcrd's
//! wire package by the wire crate's text differentials; these rows pin
//! that each handler passes it through, for Go's two short-read errors
//! (`EOF` at a field boundary, `unexpected EOF` inside a field) and for
//! coded errors.

use dcroxide_chaincfg::mainnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_dcrjson::{GoValue, RPCError, Registry, parse_params};
use dcroxide_rpc::handlers;
use dcroxide_rpc::server::{
    Config, RpcBestState, RpcChain, RpcDb, RpcSubsidyParams, RpcTxIndexEntry, RpcTxIndexer, Server,
};
use dcroxide_rpctypes::{method, register_all};
use dcroxide_standalone::SubsidyCache;
use dcroxide_wire::PROTOCOL_VERSION;

/// No chain access: the requests fail while decoding, before the
/// handler reaches the chain or the sync manager.
struct NoChain;

impl RpcChain for NoChain {}

/// A chain whose tip is the zero hash at height zero, where the
/// transaction index is synced.
struct TipChain;

impl RpcChain for TipChain {
    fn best_snapshot(&self) -> RpcBestState {
        RpcBestState {
            hash: Hash::ZERO,
            prev_hash: Hash::ZERO,
            height: 0,
            bits: 0,
            next_stake_diff: 0,
            total_subsidy: 0,
            block_size: 0,
            num_txns: 0,
        }
    }
    fn block_height_by_hash(&self, _hash: &Hash) -> Result<i64, String> {
        Ok(0)
    }
}

/// A transaction index that places every transaction in the stored
/// record [`StoredTx`] returns.
struct IndexAtTip;

impl RpcTxIndexer for IndexAtTip {
    fn name(&self) -> String {
        "transaction index".into()
    }
    fn tip(&self) -> Result<(i64, Hash), String> {
        Ok((0, Hash::ZERO))
    }
    fn entry(&self, _tx_hash: &Hash) -> Result<Option<RpcTxIndexEntry>, String> {
        Ok(Some(RpcTxIndexEntry {
            block_hash: Hash::ZERO,
            offset: 0,
            len: 0,
            block_index: 0,
        }))
    }
}

/// A database whose block regions all hold the same bytes, a stored
/// transaction that does not decode.
struct StoredTx(Vec<u8>);

impl RpcDb for StoredTx {
    fn fetch_block_region(
        &self,
        _block_hash: &Hash,
        _offset: u32,
        _len: u32,
    ) -> Result<Vec<u8>, String> {
        Ok(self.0.clone())
    }
}

fn server<C: RpcChain>(
    chain: C,
    tx_indexer: Option<Box<dyn RpcTxIndexer + Send + Sync>>,
    db: Box<dyn RpcDb + Send + Sync>,
) -> Server<C> {
    let params = mainnet_params();
    Server::new(Config {
        chain,
        chain_params: params.clone(),
        subsidy_cache: std::sync::Mutex::new(SubsidyCache::new(RpcSubsidyParams(params))),
        min_relay_tx_fee: 10000,
        max_protocol_version: PROTOCOL_VERSION,
        sync_mgr: Box::new(()),
        conn_mgr: Box::new(()),
        client_cert_auth: false,
        tx_mempooler: Box::new(()),
        clock: Box::new(()),
        interfaces: Box::new(dcroxide_rpc::helpers::NoInterfaces),
        rand_u64: Box::new(|| 0),
        tx_indexer,
        db,
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
fn call_err<C: RpcChain>(server: &Server<C>, method_name: &str, params: &[&str]) -> RPCError {
    let mut registry = Registry::new();
    register_all(&mut registry);
    let cmd = parse_params(&registry, &method(method_name), params)
        .unwrap_or_else(|e| panic!("{method_name} {params:?}: parse params: {e:?}"));
    let cmd = GoValue::Struct(cmd.fields);
    let result = match method_name {
        "decoderawtransaction" => handlers::handle_decode_raw_transaction(server, &cmd),
        "sendrawtransaction" => handlers::handle_send_raw_transaction(server, &cmd),
        "submitblock" => handlers::handle_submit_block(server, &cmd),
        "sendrawmixmessage" => handlers::handle_send_raw_mix_message(server, &cmd),
        "getrawtransaction" => handlers::handle_get_raw_transaction(server, &cmd),
        other => panic!("unknown method {other}"),
    };
    match result {
        Ok(value) => panic!("{method_name} {params:?}: expected an error, got {value:?}"),
        Err(err) => err,
    }
}

/// dcrjson's `ErrRPCDeserialization` and `ErrRPCInternal` codes.
const DESERIALIZATION: i64 = -22;
const INTERNAL: i64 = -32603;

/// A JSON string parameter.
fn q(s: &str) -> String {
    format!("\"{s}\"")
}

#[test]
fn decode_errors_reach_clients_as_dcrd_words_them() {
    let server = server(NoChain, None, Box::new(()));
    // Signature and identity, then a mixing message's session ID and run.
    let sig_id = "00".repeat(64 + 33);
    let session_run = format!("{sig_id}{}", "00".repeat(32 + 4));
    let zero_header = "00".repeat(180);
    let tx_bad_type = "01000300";
    // A version, then an input count of 2^32.
    let tx_too_many_inputs = "01000000ff0000000001000000";
    // A version, one input, and three bytes of its outpoint hash.
    let tx_cut_in_hash = "0100000001aabbcc";
    let block_too_many_txs = format!("{zero_header}fe00000100");
    let pair_req_negative = format!("{sig_id}00000000ffffffffffffffff");
    let slot_reserve_no_msgs = format!("{session_run}00");

    let rows: Vec<(&str, Vec<&str>, i64, String)> = vec![
        (
            "decoderawtransaction",
            vec![""],
            DESERIALIZATION,
            "Could not decode Tx: EOF".into(),
        ),
        (
            "decoderawtransaction",
            vec!["01000000"],
            DESERIALIZATION,
            "Could not decode Tx: EOF".into(),
        ),
        (
            "decoderawtransaction",
            vec![tx_cut_in_hash],
            DESERIALIZATION,
            "Could not decode Tx: unexpected EOF".into(),
        ),
        (
            "decoderawtransaction",
            vec![tx_bad_type],
            DESERIALIZATION,
            "Could not decode Tx: MsgTx.BtcDecode: unsupported transaction type".into(),
        ),
        (
            "decoderawtransaction",
            vec![tx_too_many_inputs],
            DESERIALIZATION,
            "Could not decode Tx: MsgTx.decodePrefix: too many input transactions to fit \
             into max message size [count 4294967296, max 780336]"
                .into(),
        ),
        (
            "sendrawtransaction",
            vec![""],
            DESERIALIZATION,
            "Could not decode Tx: EOF".into(),
        ),
        (
            "sendrawtransaction",
            vec![tx_cut_in_hash],
            DESERIALIZATION,
            "Could not decode Tx: unexpected EOF".into(),
        ),
        (
            "sendrawtransaction",
            vec![tx_bad_type],
            DESERIALIZATION,
            "Could not decode Tx: MsgTx.BtcDecode: unsupported transaction type".into(),
        ),
        ("submitblock", vec![""], INTERNAL, "EOF".into()),
        (
            "submitblock",
            vec![&zero_header[..100]],
            INTERNAL,
            "unexpected EOF".into(),
        ),
        (
            "submitblock",
            vec![&block_too_many_txs],
            INTERNAL,
            // `MsgBlock.Deserialize` decodes at protocol version 0, whose
            // per-tree limit is `MaxTxPerTxTree(0)`.
            "MsgBlock.BtcDecode: too many transactions to fit into a block \
             [count 65536, max 33334]"
                .into(),
        ),
        (
            "sendrawmixmessage",
            vec!["mixpairreq", ""],
            DESERIALIZATION,
            "Could not decode mix message: EOF".into(),
        ),
        (
            "sendrawmixmessage",
            vec!["mixpairreq", &sig_id[..100]],
            DESERIALIZATION,
            "Could not decode mix message: unexpected EOF".into(),
        ),
        // dcrd reads through a lazy hex decoder, whose invalid-byte error
        // replaces the reader's `EOF` at a field boundary and its
        // `unexpected EOF` inside a field.
        (
            "sendrawmixmessage",
            vec!["mixpairreq", "zz"],
            DESERIALIZATION,
            "Could not decode mix message: encoding/hex: invalid byte: U+007A 'z'".into(),
        ),
        (
            "sendrawmixmessage",
            vec!["mixpairreq", "00zz"],
            DESERIALIZATION,
            "Could not decode mix message: encoding/hex: invalid byte: U+007A 'z'".into(),
        ),
        (
            "sendrawmixmessage",
            vec!["mixpairreq", &pair_req_negative],
            DESERIALIZATION,
            "Could not decode mix message: MsgMixPairReq.BtcDecode: mixing pair request \
             contains negative mixed amount"
                .into(),
        ),
        (
            "sendrawmixmessage",
            vec!["mixslotres", &slot_reserve_no_msgs],
            DESERIALIZATION,
            "Could not decode mix message: MsgMixSlotReserve.BtcDecode: too few mixed \
             messages [0]"
                .into(),
        ),
    ];
    for (method_name, params, code, message) in &rows {
        let json: Vec<String> = params.iter().map(|p| q(p)).collect();
        let json: Vec<&str> = json.iter().map(String::as_str).collect();
        let err = call_err(&server, method_name, &json);
        assert_eq!(
            (i64::from(err.code), err.message.as_str()),
            (*code, message.as_str()),
            "{method_name} {params:?}"
        );
    }
}

/// `getrawtransaction` with verbose output decodes the transaction it
/// loads from the database, and a stored record that does not decode
/// returns the wire error's text as an internal error.  The request
/// reaches the index only once the mempool lookup fails, which the
/// stub mempool always does.
#[test]
fn a_stored_transaction_that_does_not_decode_reports_the_wire_text() {
    let txid = q(&"11".repeat(32));
    for (stored, message) in [
        ("", "EOF"),
        ("0100000001aabbcc", "unexpected EOF"),
        ("01000300", "MsgTx.BtcDecode: unsupported transaction type"),
    ] {
        let server = server(
            TipChain,
            Some(Box::new(IndexAtTip)),
            Box::new(StoredTx(dcroxide_testutil::unhex(stored))),
        );
        let err = call_err(&server, "getrawtransaction", &[&txid, "1"]);
        assert_eq!(
            (i64::from(err.code), err.message.as_str()),
            (INTERNAL, message),
            "stored {stored}"
        );
    }
}
