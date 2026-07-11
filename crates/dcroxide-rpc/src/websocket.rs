// SPDX-License-Identifier: ISC
//! The websocket client core (dcrd internal/rpcserver
//! `rpcwebsocket.go`): the per-client transaction filter, block
//! rescanning, the websocket command handlers, and the service
//! routing that falls back to the standard dispatch.  The connection
//! shell (the in/out/queue handler goroutines and the notification
//! fan-out) has no synchronous counterpart; the notification manager
//! sits behind a seam.

// Amount accumulation and pool pruning arithmetic mirror Go.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::HashSet;

use dcroxide_chainhash::Hash;
use dcroxide_dcrjson::{GoType, GoValue, RPCError, RpcId, codes};
use dcroxide_txscript::{stdaddr, stdscript};
use dcroxide_wire::{Message, MsgBlock, MsgTx, OutPoint};

use crate::dispatch::{create_marshalled_reply, standard_cmd_result};
use crate::rpcerrors::rpc_internal_err;
use crate::server::{RpcChain, Server};
use crate::txresults;

/// The websocket extension command methods (dcrd
/// `wsHandlersBeforeInit`).
pub static WS_HANDLER_METHODS: &[&str] = &[
    "help",
    "loadtxfilter",
    "notifyblocks",
    "notifywork",
    "notifytspend",
    "notifywinningtickets",
    "notifynewtickets",
    "notifynewtransactions",
    "notifymixmessages",
    "rebroadcastwinners",
    "rescan",
    "session",
    "stopnotifyblocks",
    "stopnotifywork",
    "stopnotifytspend",
    "stopnotifynewtransactions",
    "stopnotifymixmessages",
];

/// The notification manager operations the websocket handlers perform
/// (the registration surface of dcrd's `wsNotificationManager`; the
/// manager itself arrives with the notification fan-out).
pub trait RpcNtfnManager {
    /// dcrd `RegisterBlockUpdates`.
    fn register_block_updates(&mut self, _session_id: u64) {
        unimplemented!("register_block_updates")
    }
    /// dcrd `UnregisterBlockUpdates`.
    fn unregister_block_updates(&mut self, _session_id: u64) {
        unimplemented!("unregister_block_updates")
    }
    /// dcrd `RegisterWorkUpdates`.
    fn register_work_updates(&mut self, _session_id: u64) {
        unimplemented!("register_work_updates")
    }
    /// dcrd `UnregisterWorkUpdates`.
    fn unregister_work_updates(&mut self, _session_id: u64) {
        unimplemented!("unregister_work_updates")
    }
    /// dcrd `RegisterTSpendUpdates`.
    fn register_tspend_updates(&mut self, _session_id: u64) {
        unimplemented!("register_tspend_updates")
    }
    /// dcrd `UnregisterTSpendUpdates`.
    fn unregister_tspend_updates(&mut self, _session_id: u64) {
        unimplemented!("unregister_tspend_updates")
    }
    /// dcrd `RegisterWinningTickets`.
    fn register_winning_tickets(&mut self, _session_id: u64) {
        unimplemented!("register_winning_tickets")
    }
    /// dcrd `RegisterNewTickets`.
    fn register_new_tickets(&mut self, _session_id: u64) {
        unimplemented!("register_new_tickets")
    }
    /// dcrd `RegisterNewMempoolTxsUpdates`.
    fn register_new_mempool_txs_updates(&mut self, _session_id: u64) {
        unimplemented!("register_new_mempool_txs_updates")
    }
    /// dcrd `UnregisterNewMempoolTxsUpdates`.
    fn unregister_new_mempool_txs_updates(&mut self, _session_id: u64) {
        unimplemented!("unregister_new_mempool_txs_updates")
    }
    /// dcrd `RegisterMixMessages`.
    fn register_mix_messages(&mut self, _session_id: u64) {
        unimplemented!("register_mix_messages")
    }
    /// dcrd `UnregisterMixMessages`.
    fn unregister_mix_messages(&mut self, _session_id: u64) {
        unimplemented!("unregister_mix_messages")
    }
    /// dcrd `NotifyWinningTickets`.
    fn notify_winning_tickets(
        &mut self,
        _block_hash: &Hash,
        _block_height: i64,
        _tickets: &[Hash],
    ) {
        unimplemented!("notify_winning_tickets")
    }
}

impl RpcNtfnManager for () {}

/// The per-client transaction filter (dcrd `wsClientFilter`): typed
/// fast paths for the common address kinds plus a fallback string
/// map, and the set of unspent outpoints.
pub struct WsClientFilter {
    pub_key_hashes: HashSet<[u8; 20]>,
    script_hashes: HashSet<[u8; 20]>,
    compressed_pub_keys: HashSet<[u8; 33]>,
    other_addresses: HashSet<String>,
    unspent: HashSet<(Hash, u32, i8)>,
}

impl WsClientFilter {
    /// A new filter over the given addresses and unspent outpoints
    /// (dcrd `makeWSClientFilter`).
    pub fn new(
        addresses: &[String],
        unspent_out_points: &[OutPoint],
        params: &dcroxide_chaincfg::Params,
    ) -> WsClientFilter {
        let mut filter = WsClientFilter {
            pub_key_hashes: HashSet::new(),
            script_hashes: HashSet::new(),
            compressed_pub_keys: HashSet::new(),
            other_addresses: HashSet::new(),
            unspent: HashSet::new(),
        };
        for s in addresses {
            filter.add_address_str(s, params);
        }
        for op in unspent_out_points {
            filter.add_unspent_out_point(op);
        }
        filter
    }

    /// Add an address to the filter (dcrd `addAddress`).
    pub fn add_address(&mut self, a: &stdaddr::Address) {
        match a {
            stdaddr::Address::PubKeyHashEcdsaSecp256k1V0 { .. } => {
                self.pub_key_hashes
                    .insert(*a.hash160().expect("p2pkh has a hash160"));
                return;
            }
            stdaddr::Address::ScriptHashV0 { .. } => {
                self.script_hashes
                    .insert(*a.hash160().expect("p2sh has a hash160"));
                return;
            }
            stdaddr::Address::PubKeyEcdsaSecp256k1V0 {
                serialized_pub_key, ..
            } if serialized_pub_key.len() == 33 => {
                let mut compressed = [0u8; 33];
                compressed.copy_from_slice(serialized_pub_key);
                self.compressed_pub_keys.insert(compressed);
                return;
            }
            _ => {}
        }

        self.other_addresses.insert(a.to_string());
    }

    /// Add an address by its string form, silently ignoring addresses
    /// that fail to decode (dcrd `addAddressStr`).
    pub fn add_address_str(&mut self, s: &str, params: &dcroxide_chaincfg::Params) {
        // There is no point in saving the address if it can't be
        // decoded since it should also be impossible to create the
        // address from an inspected transaction output script.
        if let Ok(a) = stdaddr::decode_address(s, params) {
            self.add_address(&a);
        }
    }

    /// Whether the address is contained in the filter (dcrd
    /// `existsAddress`).
    pub fn exists_address(&self, a: &stdaddr::Address) -> bool {
        match a {
            stdaddr::Address::PubKeyHashEcdsaSecp256k1V0 { .. } => {
                return self
                    .pub_key_hashes
                    .contains(a.hash160().expect("p2pkh has a hash160"));
            }
            stdaddr::Address::ScriptHashV0 { .. } => {
                return self
                    .script_hashes
                    .contains(a.hash160().expect("p2sh has a hash160"));
            }
            stdaddr::Address::PubKeyEcdsaSecp256k1V0 {
                serialized_pub_key, ..
            } if serialized_pub_key.len() == 33 => {
                let mut compressed = [0u8; 33];
                compressed.copy_from_slice(serialized_pub_key);
                if self.compressed_pub_keys.contains(&compressed) {
                    return true;
                }
                let pkh = a
                    .address_pub_key_hash()
                    .expect("pubkey address hashes to p2pkh");
                return self
                    .pub_key_hashes
                    .contains(pkh.hash160().expect("p2pkh has a hash160"));
            }
            _ => {}
        }

        self.other_addresses.contains(&a.to_string())
    }

    /// Add an unspent outpoint to the filter (dcrd
    /// `addUnspentOutPoint`).
    pub fn add_unspent_out_point(&mut self, op: &OutPoint) {
        self.unspent.insert((op.hash, op.index, op.tree));
    }

    /// Whether the outpoint is contained in the filter (dcrd
    /// `existsUnspentOutPoint`).
    pub fn exists_unspent_out_point(&self, op: &OutPoint) -> bool {
        self.unspent.contains(&(op.hash, op.index, op.tree))
    }
}

/// The serialized transaction hex (dcrd `txHexString`; transaction
/// serialization does not vary with the protocol version).
fn tx_hex_string(tx: &MsgTx) -> String {
    txresults::message_to_hex(&Message::Tx(tx.clone()), dcroxide_wire::PROTOCOL_VERSION)
        .expect("transaction encoding cannot fail")
}

/// Rescan a block for any relevant transactions for the passed filter
/// and return the discovered transactions as serialized hex (dcrd
/// `rescanBlock`).
pub fn rescan_block(
    filter: &mut WsClientFilter,
    block: &MsgBlock,
    params: &dcroxide_chaincfg::Params,
    is_treasury_enabled: bool,
) -> Vec<String> {
    let mut transactions: Vec<String> = Vec::new();

    let mut check_transaction = |filter: &mut WsClientFilter, tx: &MsgTx, tree: i8| {
        // Track whether the transaction has already been added to the
        // result; it shouldn't be added twice.
        let mut added = false;

        // Skip previous output checks for coinbase inputs and the
        // stakebase input of votes since these do not reference a
        // previous output.
        let skip_inputs =
            tree == 0 && dcroxide_standalone::is_coin_base_tx(tx, is_treasury_enabled);
        let inputs = if tree != 0 && dcroxide_stake::is_ssgen(tx) {
            &tx.tx_in[1..]
        } else {
            &tx.tx_in[..]
        };
        if !skip_inputs {
            for input in inputs {
                if !filter.exists_unspent_out_point(&input.previous_out_point) {
                    continue;
                }
                if !added {
                    transactions.push(tx_hex_string(tx));
                    added = true;
                }
            }
        }

        for (i, output) in tx.tx_out.iter().enumerate() {
            let (script_type, addrs) =
                stdscript::extract_addrs(output.version, &output.pk_script, params);
            if script_type == stdscript::ScriptType::NonStandard {
                continue;
            }
            for a in &addrs {
                if !filter.exists_address(a) {
                    continue;
                }

                let op = OutPoint {
                    hash: tx.tx_hash(),
                    index: i as u32,
                    tree,
                };
                filter.add_unspent_out_point(&op);

                if !added {
                    transactions.push(tx_hex_string(tx));
                    added = true;
                }
            }
        }
    };

    for tx in &block.stransactions {
        check_transaction(&mut *filter, tx, 1);
    }
    for tx in &block.transactions {
        check_transaction(&mut *filter, tx, 0);
    }

    transactions
}

/// The per-connection websocket client state the handlers touch (the
/// synchronous surface of dcrd `wsClient`).
pub struct WsClient {
    /// Whether the client has been authenticated.
    pub authenticated: bool,
    /// Whether the client may change the state of the server.
    pub is_admin: bool,
    /// The random per-connection session id.
    pub session_id: u64,
    /// Whether the client requested verbose transaction
    /// notifications.
    pub verbose_tx_updates: bool,
    /// The client's transaction filter.
    pub filter_data: Option<WsClientFilter>,
}

impl WsClient {
    /// A new client with the given session id (the synchronous parts
    /// of dcrd `newWebsocketClient`).
    pub fn new(session_id: u64) -> WsClient {
        WsClient {
            authenticated: false,
            is_admin: false,
            session_id,
            verbose_tx_updates: false,
            filter_data: None,
        }
    }
}

fn fields(v: &GoValue) -> &[GoValue] {
    match v {
        GoValue::Struct(fields) => fields,
        other => panic!("expected struct value, got {other:?}"),
    }
}

/// handlewebsockethelp (dcrd `handleWebsocketHelp`): like the HTTP
/// help handler but over the websocket usage variant and the combined
/// method lists.
pub fn handle_websocket_help<C: RpcChain>(
    server: &mut Server<C>,
    _wsc: &mut WsClient,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let command = match &c[0] {
        GoValue::Null => "",
        GoValue::String(s) => s.as_str(),
        other => panic!("expected optional string field, got {other:?}"),
    };

    // Provide a usage overview of all commands when no specific
    // command was specified.
    if command.is_empty() {
        // The context "Failed to generate RPC usage" is log-only.
        let usage = server
            .help_cacher
            .rpc_usage(&server.registry, true)
            .map_err(|e| rpc_internal_err(&e))?;
        return Ok(GoValue::String(usage));
    }

    // Check that the command asked for is supported and implemented:
    // the websocket handlers as well as the main list of handlers.
    let valid = crate::help::RPC_HANDLER_METHODS.contains(&command)
        || WS_HANDLER_METHODS.contains(&command);
    if !valid {
        return Err(RPCError::new(
            codes::INVALID_PARAMETER,
            &format!("Unknown method: {command}"),
        ));
    }

    // Get the help for the command; the context "Failed to generate
    // help" is log-only.
    let help = server
        .help_cacher
        .rpc_method_help(&server.registry, command)
        .map_err(|e| rpc_internal_err(&e))?;
    Ok(GoValue::String(help))
}

/// handleloadtxfilter (dcrd `handleLoadTxFilter`).
pub fn handle_load_tx_filter<C: RpcChain>(
    server: &mut Server<C>,
    wsc: &mut WsClient,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let reload = match &c[0] {
        GoValue::Bool(b) => *b,
        other => panic!("expected bool field, got {other:?}"),
    };
    let addresses: Vec<String> = match &c[1] {
        GoValue::Array(items) => items
            .iter()
            .map(|v| match v {
                GoValue::String(s) => s.clone(),
                other => panic!("expected string element, got {other:?}"),
            })
            .collect(),
        GoValue::Null => Vec::new(),
        other => panic!("expected array field, got {other:?}"),
    };
    let outpoint_values: &[GoValue] = match &c[2] {
        GoValue::Array(items) => items,
        GoValue::Null => &[],
        other => panic!("expected array field, got {other:?}"),
    };

    let mut out_points = Vec::with_capacity(outpoint_values.len());
    for op in outpoint_values {
        let f = fields(op);
        let hash_str = match &f[0] {
            GoValue::String(s) => s.as_str(),
            other => panic!("expected string field, got {other:?}"),
        };
        // The error text is Go's raw error: the chainhash size error
        // or encoding/hex's invalid-byte error.
        let hash: Hash = hash_str
            .parse()
            .map_err(|e: dcroxide_chainhash::HashError| {
                let text = match e {
                    dcroxide_chainhash::HashError::InvalidHexByte(b) => {
                        format!("encoding/hex: invalid byte: U+{:04X} {:?}", b, b as char)
                    }
                    other => other.to_string(),
                };
                RPCError::new(codes::INVALID_PARAMETER, &text)
            })?;
        let tree = match &f[1] {
            GoValue::Int(n) => *n as i8,
            other => panic!("expected int field, got {other:?}"),
        };
        let index = match &f[2] {
            GoValue::Uint(n) => *n as u32,
            other => panic!("expected uint field, got {other:?}"),
        };
        out_points.push(OutPoint { hash, index, tree });
    }

    match wsc.filter_data.as_mut() {
        Some(filter) if !reload => {
            for a in &addresses {
                filter.add_address_str(a, &server.cfg.chain_params);
            }
            for op in &out_points {
                filter.add_unspent_out_point(op);
            }
        }
        _ => {
            wsc.filter_data = Some(WsClientFilter::new(
                &addresses,
                &out_points,
                &server.cfg.chain_params,
            ));
        }
    }

    Ok(GoValue::Null)
}

/// handlesession (dcrd `handleSession`); the result is a
/// `SessionResult` value.
pub fn handle_session<C: RpcChain>(
    _server: &mut Server<C>,
    wsc: &mut WsClient,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    Ok(GoValue::Struct(vec![GoValue::Uint(wsc.session_id)]))
}

/// handlerebroadcastwinners (dcrd `handleRebroadcastWinners`).
pub fn handle_rebroadcast_winners<C: RpcChain>(
    server: &mut Server<C>,
    _wsc: &mut WsClient,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let best_height = server.cfg.chain.best_snapshot().height;
    let blocks = server.cfg.chain.tip_generation();

    for block_hash in &blocks {
        // Lottery data can legitimately be missing when the header is
        // known but not the block data; the failure is log-only.
        let Ok(winning_tickets) = server.cfg.chain.lottery_data_for_block(block_hash) else {
            continue;
        };
        server
            .ntfn_mgr
            .notify_winning_tickets(block_hash, best_height, &winning_tickets);
    }

    Ok(GoValue::Null)
}

/// handlenotifynewtransactions (dcrd `handleNotifyNewTransactions`).
pub fn handle_notify_new_transactions<C: RpcChain>(
    server: &mut Server<C>,
    wsc: &mut WsClient,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let verbose = match &c[0] {
        GoValue::Null => false,
        GoValue::Bool(b) => *b,
        other => panic!("expected optional bool field, got {other:?}"),
    };
    wsc.verbose_tx_updates = verbose;
    server
        .ntfn_mgr
        .register_new_mempool_txs_updates(wsc.session_id);
    Ok(GoValue::Null)
}

/// handlerescan (dcrd `handleRescan`); the result is a `RescanResult`
/// value.
pub fn handle_rescan<C: RpcChain>(
    server: &mut Server<C>,
    wsc: &mut WsClient,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    // The client's transaction filter must exist in order to continue.
    if wsc.filter_data.is_none() {
        return Err(RPCError::new(
            codes::MISC,
            "Transaction filter must be loaded before rescanning",
        ));
    }

    let c = fields(cmd);
    let hash_strs: Vec<String> = match &c[0] {
        GoValue::Array(items) => items
            .iter()
            .map(|v| match v {
                GoValue::String(s) => s.clone(),
                other => panic!("expected string element, got {other:?}"),
            })
            .collect(),
        other => panic!("expected array field, got {other:?}"),
    };
    let block_hashes = crate::helpers::decode_hashes(&hash_strs)?;

    let mut discovered_data: Vec<GoValue> = Vec::new();

    // Iterate over each block in the request and rescan; when a block
    // contains relevant transactions, add it to the response.
    let mut last_block_hash: Option<Hash> = None;
    for block_hash in &block_hashes {
        let block = server.cfg.chain.block_by_hash(block_hash).map_err(|e| {
            RPCError::new(
                codes::BLOCK_NOT_FOUND,
                &format!("Failed to fetch block: {e}"),
            )
        })?;
        let prev_blk_hash = block.header.prev_block;
        if let Some(last) = last_block_hash
            && prev_blk_hash != last
        {
            return Err(RPCError::new(
                codes::INVALID_PARAMETER,
                &format!("Block {block_hash} is not a child of {last}"),
            ));
        }
        last_block_hash = Some(*block_hash);

        // Determine if the treasury rules are active as of the block.
        let is_treasury_enabled = server.is_treasury_agenda_active(&prev_blk_hash)?;

        let filter = wsc.filter_data.as_mut().expect("checked above");
        let transactions = rescan_block(
            filter,
            &block,
            &server.cfg.chain_params,
            is_treasury_enabled,
        );
        if !transactions.is_empty() {
            discovered_data.push(GoValue::Struct(vec![
                GoValue::String(block_hash.to_string()),
                GoValue::Array(transactions.into_iter().map(GoValue::String).collect()),
            ]));
        }
    }

    Ok(GoValue::Struct(vec![GoValue::Array(discovered_data)]))
}

/// Route a websocket command to its extension handler, falling back
/// to the standard command dispatch (the routing inside dcrd
/// `serviceRequest`).
pub fn ws_cmd_result<C: RpcChain>(
    server: &mut Server<C>,
    wsc: &mut WsClient,
    method_name: &str,
    cmd: &GoValue,
) -> Result<(GoValue, GoType), RPCError> {
    let pair = match method_name {
        "help" => (handle_websocket_help(server, wsc, cmd)?, GoType::String),
        "loadtxfilter" => (
            handle_load_tx_filter(server, wsc, cmd)?,
            GoType::Int64.ptr(),
        ),
        "notifyblocks" => {
            server.ntfn_mgr.register_block_updates(wsc.session_id);
            (GoValue::Null, GoType::Int64.ptr())
        }
        "notifywork" => {
            server.ntfn_mgr.register_work_updates(wsc.session_id);
            (GoValue::Null, GoType::Int64.ptr())
        }
        "notifytspend" => {
            server.ntfn_mgr.register_tspend_updates(wsc.session_id);
            (GoValue::Null, GoType::Int64.ptr())
        }
        "notifywinningtickets" => {
            server.ntfn_mgr.register_winning_tickets(wsc.session_id);
            (GoValue::Null, GoType::Int64.ptr())
        }
        "notifynewtickets" => {
            server.ntfn_mgr.register_new_tickets(wsc.session_id);
            (GoValue::Null, GoType::Int64.ptr())
        }
        "notifynewtransactions" => (
            handle_notify_new_transactions(server, wsc, cmd)?,
            GoType::Int64.ptr(),
        ),
        "notifymixmessages" => {
            server.ntfn_mgr.register_mix_messages(wsc.session_id);
            (GoValue::Null, GoType::Int64.ptr())
        }
        "rebroadcastwinners" => (
            handle_rebroadcast_winners(server, wsc, cmd)?,
            GoType::Int64.ptr(),
        ),
        "rescan" => (
            handle_rescan(server, wsc, cmd)?,
            dcroxide_rpctypes::chainsvrwsresults::rescan_result(),
        ),
        "session" => (
            handle_session(server, wsc, cmd)?,
            dcroxide_rpctypes::chainsvrwsresults::session_result(),
        ),
        "stopnotifyblocks" => {
            server.ntfn_mgr.unregister_block_updates(wsc.session_id);
            (GoValue::Null, GoType::Int64.ptr())
        }
        "stopnotifywork" => {
            server.ntfn_mgr.unregister_work_updates(wsc.session_id);
            (GoValue::Null, GoType::Int64.ptr())
        }
        "stopnotifytspend" => {
            server.ntfn_mgr.unregister_tspend_updates(wsc.session_id);
            (GoValue::Null, GoType::Int64.ptr())
        }
        "stopnotifynewtransactions" => {
            server
                .ntfn_mgr
                .unregister_new_mempool_txs_updates(wsc.session_id);
            (GoValue::Null, GoType::Int64.ptr())
        }
        "stopnotifymixmessages" => {
            server.ntfn_mgr.unregister_mix_messages(wsc.session_id);
            (GoValue::Null, GoType::Int64.ptr())
        }
        _ => standard_cmd_result(server, method_name, cmd)?,
    };
    Ok(pair)
}

/// Execute a parsed websocket request and build the marshalled reply
/// (the reply construction inside dcrd `serviceRequest`).
pub fn ws_service_request<C: RpcChain>(
    server: &mut Server<C>,
    wsc: &mut WsClient,
    jsonrpc: &str,
    method_name: &str,
    cmd: &GoValue,
    id: &RpcId,
) -> Option<String> {
    let (result, err) = match ws_cmd_result(server, wsc, method_name, cmd) {
        Ok(pair) => (Some(pair), None),
        Err(err) => (None, Some(err)),
    };
    create_marshalled_reply(
        jsonrpc,
        id,
        result.as_ref().map(|(value, typ)| (typ, value)),
        err.as_ref(),
    )
    .ok()
}

/// A template update reason (dcrd `mining.TemplateUpdateReason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateUpdateReason {
    /// A new parent block (dcrd `TURNewParent`).
    NewParent,
    /// New votes arrived (dcrd `TURNewVotes`).
    NewVotes,
    /// New transactions arrived (dcrd `TURNewTxns`).
    NewTxns,
    /// The template was regenerated for an unclassified reason, such
    /// as a forced regeneration (dcrd's internal `turUnknown`, which
    /// still notifies work clients).
    Unknown,
}

/// Convert a template update reason to the work notification string
/// (dcrd `updateReasonToWorkNtfnString`; every reason outside the
/// three classified ones maps to "unknown").
fn update_reason_to_work_ntfn_string(reason: TemplateUpdateReason) -> &'static str {
    match reason {
        TemplateUpdateReason::NewParent => "newparent",
        TemplateUpdateReason::NewVotes => "newvotes",
        TemplateUpdateReason::NewTxns => "newtxns",
        TemplateUpdateReason::Unknown => "unknown",
    }
}

/// Marshal a notification exactly like dcrd's
/// `dcrjson.MarshalCmd("1.0", nil, &ntfn)`.
fn marshal_ntfn<C: RpcChain>(
    server: &Server<C>,
    ntfn_type: dcroxide_dcrjson::GoType,
    fields: Vec<GoValue>,
) -> Option<String> {
    let instance = dcroxide_dcrjson::CmdInstance {
        cmd_type: ntfn_type.ptr(),
        nil: false,
        fields,
    };
    dcroxide_dcrjson::marshal_cmd(&server.registry, "1.0", &RpcId::Null, &instance).ok()
}

/// The clients whose filters consider the transaction relevant,
/// updating their filters to watch discovered outputs; the result is
/// parallel to the client list (dcrd `subscribedClients`, which also
/// covers the ticket commitment address path).
pub fn subscribed_clients<C: RpcChain>(
    server: &mut Server<C>,
    tx: &MsgTx,
    tree: i8,
    clients: &mut [&mut WsClient],
) -> Vec<bool> {
    let params = server.cfg.chain_params.clone();
    let mut subscribed = vec![false; clients.len()];

    let mut is_ticket = false; // lazily set
    for (ci, client) in clients.iter_mut().enumerate() {
        let Some(f) = client.filter_data.as_mut() else {
            continue;
        };

        for input in &tx.tx_in {
            if f.exists_unspent_out_point(&input.previous_out_point) {
                subscribed[ci] = true;
            }
        }

        for (i, output) in tx.tx_out.iter().enumerate() {
            let mut watch_output = true;
            let (script_type, mut addrs) =
                stdscript::extract_addrs(output.version, &output.pk_script, &params);
            if script_type == stdscript::ScriptType::NonStandard {
                // Clients are not able to subscribe to nonstandard or
                // non-address outputs.
                continue;
            }
            if script_type == stdscript::ScriptType::NullData
                && i & 1 == 1
                && (is_ticket || dcroxide_stake::is_sstx(tx))
            {
                is_ticket = true;
                // OP_RETURN ticket commitments may contain relevant
                // P2PKH or P2SH HASH160s.  These outputs cannot be
                // spent and do not need to be watched.
                match dcroxide_stake::addr_from_sstx_pk_scr_commitment(&output.pk_script, &params) {
                    Ok(addr) => {
                        addrs = vec![addr];
                        watch_output = false;
                    }
                    Err(_) => continue, // log-only in dcrd
                }
            }
            for a in &addrs {
                if f.exists_address(a) {
                    subscribed[ci] = true;
                    if watch_output {
                        let op = OutPoint {
                            hash: tx.tx_hash(),
                            index: i as u32,
                            tree,
                        };
                        f.add_unspent_out_point(&op);
                    }
                }
            }
        }
    }

    subscribed
}

/// Notify block-update clients about a connected block; the result
/// pairs each notified client's session id with the marshalled
/// notification (dcrd `notifyBlockConnected`).
pub fn notify_block_connected<C: RpcChain>(
    server: &mut Server<C>,
    clients: &mut [&mut WsClient],
    block: &MsgBlock,
) -> Vec<(u64, String)> {
    if clients.is_empty() {
        return Vec::new();
    }

    // The common portion of the notification.
    let header_hex: String = block
        .header
        .serialize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    // Search for relevant transactions for each client.
    let mut subscribed_txs: Vec<Vec<String>> = vec![Vec::new(); clients.len()];
    for tx in &block.stransactions {
        let flags = subscribed_clients(server, tx, 1, clients);
        for (ci, hit) in flags.iter().enumerate() {
            if *hit {
                subscribed_txs[ci].push(tx_hex_string(tx));
            }
        }
    }
    for tx in &block.transactions {
        let flags = subscribed_clients(server, tx, 0, clients);
        for (ci, hit) in flags.iter().enumerate() {
            if *hit {
                subscribed_txs[ci].push(tx_hex_string(tx));
            }
        }
    }

    let mut out = Vec::with_capacity(clients.len());
    for (ci, client) in clients.iter().enumerate() {
        let txs = if subscribed_txs[ci].is_empty() {
            GoValue::Null
        } else {
            GoValue::Array(
                subscribed_txs[ci]
                    .iter()
                    .map(|s| GoValue::String(s.clone()))
                    .collect(),
            )
        };
        if let Some(marshalled) = marshal_ntfn(
            server,
            dcroxide_rpctypes::chainsvrwsntfns::block_connected_ntfn(),
            vec![GoValue::String(header_hex.clone()), txs],
        ) {
            out.push((client.session_id, marshalled));
        }
    }
    out
}

/// Notify block-update clients about a disconnected block (dcrd
/// `notifyBlockDisconnected`).
pub fn notify_block_disconnected<C: RpcChain>(
    server: &mut Server<C>,
    clients: &[&mut WsClient],
    block: &MsgBlock,
) -> Vec<(u64, String)> {
    if clients.is_empty() {
        return Vec::new();
    }

    let header_hex: String = block
        .header
        .serialize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let Some(marshalled) = marshal_ntfn(
        server,
        dcroxide_rpctypes::chainsvrwsntfns::block_disconnected_ntfn(),
        vec![GoValue::String(header_hex)],
    ) else {
        return Vec::new();
    };
    clients
        .iter()
        .map(|c| (c.session_id, marshalled.clone()))
        .collect()
}

/// Notify work-update clients about a new block template, adding the
/// template to the pool and pruning it when the parent changed (dcrd
/// `notifyWork`).
pub fn notify_work<C: RpcChain>(
    server: &mut Server<C>,
    clients: &[&mut WsClient],
    template_block: &MsgBlock,
    reason: TemplateUpdateReason,
) -> Vec<(u64, String)> {
    if clients.is_empty() {
        return Vec::new();
    }

    // Serialize the data that represents work to be solved; the
    // agenda failure is log-only.
    let header = template_block.header;
    let Ok(is_blake3_pow_active) = server
        .cfg
        .chain
        .is_blake3_pow_agenda_active(&header.prev_block)
    else {
        return Vec::new();
    };
    let data = crate::handlers::serialize_get_work_data(&header, is_blake3_pow_active);

    // The byte-swapped legacy target.
    let target =
        crate::helpers::big_to_le_uint256(&dcroxide_standalone::compact_to_big(header.bits));

    let Some(marshalled) = marshal_ntfn(
        server,
        dcroxide_rpctypes::chainsvrwsntfns::work_ntfn(),
        vec![
            GoValue::String(data.iter().map(|b| format!("{b:02x}")).collect()),
            GoValue::String(target.iter().map(|b| format!("{b:02x}")).collect()),
            GoValue::String(update_reason_to_work_ntfn_string(reason).to_string()),
        ],
    ) else {
        return Vec::new();
    };

    // Prune old templates when the best block changed and add the
    // template to the pool.
    let template_key = crate::handlers::get_work_template_key(&header);
    if reason == TemplateUpdateReason::NewParent {
        let best_height = server.cfg.chain.best_snapshot().height;
        let prune_height = best_height - 3;
        server
            .work_state
            .template_pool
            .retain(|_, block| i64::from(block.header.height) >= prune_height);
    }
    server
        .work_state
        .template_pool
        .insert(template_key, template_block.clone());

    clients
        .iter()
        .map(|c| (c.session_id, marshalled.clone()))
        .collect()
}

/// Notify tspend clients about a new mempool treasury spend (dcrd
/// `notifyTSpend`).
pub fn notify_tspend<C: RpcChain>(
    server: &mut Server<C>,
    clients: &[&mut WsClient],
    tspend: &MsgTx,
) -> Vec<(u64, String)> {
    if clients.is_empty() {
        return Vec::new();
    }

    let Some(marshalled) = marshal_ntfn(
        server,
        dcroxide_rpctypes::chainsvrwsntfns::tspend_ntfn(),
        vec![GoValue::String(tx_hex_string(tspend))],
    ) else {
        return Vec::new();
    };
    clients
        .iter()
        .map(|c| (c.session_id, marshalled.clone()))
        .collect()
}

/// Notify block-update clients about a chain reorganization (dcrd
/// `notifyReorganization`).
pub fn notify_reorganization<C: RpcChain>(
    server: &mut Server<C>,
    clients: &[&mut WsClient],
    old_hash: &Hash,
    old_height: i64,
    new_hash: &Hash,
    new_height: i64,
) -> Vec<(u64, String)> {
    if clients.is_empty() {
        return Vec::new();
    }

    let Some(marshalled) = marshal_ntfn(
        server,
        dcroxide_rpctypes::chainsvrwsntfns::reorganization_ntfn(),
        vec![
            GoValue::String(old_hash.to_string()),
            GoValue::Int(i64::from(old_height as i32)),
            GoValue::String(new_hash.to_string()),
            GoValue::Int(i64::from(new_height as i32)),
        ],
    ) else {
        return Vec::new();
    };
    clients
        .iter()
        .map(|c| (c.session_id, marshalled.clone()))
        .collect()
}

/// Notify winning-ticket clients (dcrd `notifyWinningTickets`; the
/// tickets ride in a map keyed by their decimal index).
pub fn notify_winning_tickets_ntfn<C: RpcChain>(
    server: &mut Server<C>,
    clients: &[&mut WsClient],
    block_hash: &Hash,
    block_height: i64,
    tickets: &[Hash],
) -> Vec<(u64, String)> {
    let ticket_map: Vec<(String, GoValue)> = tickets
        .iter()
        .enumerate()
        .map(|(i, t)| (i.to_string(), GoValue::String(t.to_string())))
        .collect();

    let Some(marshalled) = marshal_ntfn(
        server,
        dcroxide_rpctypes::chainsvrwsntfns::winning_tickets_ntfn(),
        vec![
            GoValue::String(block_hash.to_string()),
            GoValue::Int(i64::from(block_height as i32)),
            GoValue::Map(ticket_map),
        ],
    ) else {
        return Vec::new();
    };
    clients
        .iter()
        .map(|c| (c.session_id, marshalled.clone()))
        .collect()
}

/// Notify maturing-ticket clients (dcrd `notifyNewTickets`).
pub fn notify_new_tickets<C: RpcChain>(
    server: &mut Server<C>,
    clients: &[&mut WsClient],
    hash: &Hash,
    height: i64,
    stake_difficulty: i64,
    tickets_new: &[Hash],
) -> Vec<(u64, String)> {
    let tickets: Vec<GoValue> = tickets_new
        .iter()
        .map(|h| GoValue::String(h.to_string()))
        .collect();

    let Some(marshalled) = marshal_ntfn(
        server,
        dcroxide_rpctypes::chainsvrwsntfns::new_tickets_ntfn(),
        vec![
            GoValue::String(hash.to_string()),
            GoValue::Int(i64::from(height as i32)),
            GoValue::Int(stake_difficulty),
            GoValue::Array(tickets),
        ],
    ) else {
        return Vec::new();
    };
    clients
        .iter()
        .map(|c| (c.session_id, marshalled.clone()))
        .collect()
}

/// Notify mempool-transaction clients about a new transaction, with
/// the verbose variant for clients that requested it (dcrd
/// `notifyForNewTx`).
pub fn notify_for_new_tx<C: RpcChain>(
    server: &mut Server<C>,
    clients: &[&mut WsClient],
    tx: &MsgTx,
) -> Vec<(u64, String)> {
    let tx_hash_str = tx.tx_hash().to_string();

    let mut amount: i64 = 0;
    for tx_out in &tx.tx_out {
        amount += tx_out.value;
    }

    let Some(marshalled) = marshal_ntfn(
        server,
        dcroxide_rpctypes::chainsvrwsntfns::tx_accepted_ntfn(),
        vec![
            GoValue::String(tx_hash_str.clone()),
            GoValue::Float64(txresults::to_coin(amount)),
        ],
    ) else {
        return Vec::new();
    };

    // Determine if the treasury rules are active as of the current
    // best tip; the failure is log-only.
    let prev_blk_hash = server.cfg.chain.best_snapshot().hash;
    let Ok(is_treasury_enabled) = server.cfg.chain.is_treasury_agenda_active(&prev_blk_hash) else {
        return Vec::new();
    };

    let mut out = Vec::with_capacity(clients.len());
    let mut marshalled_verbose: Option<String> = None;
    for client in clients {
        if client.verbose_tx_updates {
            if let Some(verbose) = &marshalled_verbose {
                out.push((client.session_id, verbose.clone()));
                continue;
            }

            let Ok(raw_tx) = txresults::create_tx_raw_result(
                &server.cfg.chain_params,
                tx,
                &tx_hash_str,
                0xffffffff, // wire.NullBlockIndex
                None,
                "",
                0,
                0,
                is_treasury_enabled,
                server.cfg.max_protocol_version,
                server.cfg.chain_params.net,
            ) else {
                // dcrd returns silently, skipping remaining clients.
                return out;
            };

            let Some(verbose) = marshal_ntfn(
                server,
                dcroxide_rpctypes::chainsvrwsntfns::tx_accepted_verbose_ntfn(),
                vec![raw_tx],
            ) else {
                return out;
            };
            out.push((client.session_id, verbose.clone()));
            marshalled_verbose = Some(verbose);
        } else {
            out.push((client.session_id, marshalled.clone()));
        }
    }
    out
}

/// Notify clients whose filters find the transaction relevant,
/// watching discovered outputs (dcrd `notifyRelevantTxAccepted`).
pub fn notify_relevant_tx_accepted<C: RpcChain>(
    server: &mut Server<C>,
    clients: &mut [&mut WsClient],
    tx: &MsgTx,
    tree: i8,
) -> Vec<(u64, String)> {
    let params = server.cfg.chain_params.clone();
    let mut notify = vec![false; clients.len()];

    for (ci, client) in clients.iter_mut().enumerate() {
        let Some(f) = client.filter_data.as_mut() else {
            continue;
        };

        for input in &tx.tx_in {
            if f.exists_unspent_out_point(&input.previous_out_point) {
                notify[ci] = true;
            }
        }

        for (i, output) in tx.tx_out.iter().enumerate() {
            let (script_type, addrs) =
                stdscript::extract_addrs(output.version, &output.pk_script, &params);
            if script_type == stdscript::ScriptType::NonStandard {
                continue;
            }
            for a in &addrs {
                if f.exists_address(a) {
                    notify[ci] = true;

                    let op = OutPoint {
                        hash: tx.tx_hash(),
                        index: i as u32,
                        tree,
                    };
                    f.add_unspent_out_point(&op);
                }
            }
        }
    }

    if !notify.iter().any(|n| *n) {
        return Vec::new();
    }
    let Some(marshalled) = marshal_ntfn(
        server,
        dcroxide_rpctypes::chainsvrwsntfns::relevant_tx_accepted_ntfn(),
        vec![GoValue::String(tx_hex_string(tx))],
    ) else {
        return Vec::new();
    };
    clients
        .iter()
        .zip(notify.iter())
        .filter(|(_, hit)| **hit)
        .map(|(c, _)| (c.session_id, marshalled.clone()))
        .collect()
}

/// Notify mix-message clients about an accepted mixing message (dcrd
/// `notifyMixMessage`).
pub fn notify_mix_message<C: RpcChain>(
    server: &mut Server<C>,
    clients: &[&mut WsClient],
    msg: &Message,
) -> Vec<(u64, String)> {
    if clients.is_empty() {
        return Vec::new();
    }

    // The encode failure is log-only and unreachable for accepted
    // messages.
    let Ok(payload_hex) = txresults::message_to_hex(msg, dcroxide_wire::MIX_VERSION) else {
        return Vec::new();
    };
    let Some(marshalled) = marshal_ntfn(
        server,
        dcroxide_rpctypes::chainsvrwsntfns::mix_message_ntfn(),
        vec![
            GoValue::String(msg.command().to_string()),
            GoValue::String(payload_hex),
        ],
    ) else {
        return Vec::new();
    };
    clients
        .iter()
        .map(|c| (c.session_id, marshalled.clone()))
        .collect()
}
