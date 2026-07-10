// SPDX-License-Identifier: ISC
//! The RPC request dispatch core (dcrd internal/rpcserver
//! `parseCmd`, `standardCmdResult`, `createMarshalledReply`, and
//! `processRequest`): requests parsed through the dcrjson pipeline,
//! routed to the ported command handlers, and marshalled into
//! JSON-RPC responses, including the wallet/unimplemented method
//! classification and the limited-user gate.

use dcroxide_dcrjson::{
    GoType, GoValue, RPCError, RpcId, codes, err_rpc_method_not_found, gojson, marshal_response,
    parse_params,
};
use dcroxide_rpctypes::chainsvrresults as results;
use dcroxide_rpctypes::method;

use crate::handlers;
use crate::rpcerrors::rpc_invalid_error;
use crate::server::{RpcChain, Server};

/// Commands recognized as wallet commands (dcrd `rpcAskWallet`).
pub static RPC_ASK_WALLET: &[&str] = &[
    "abandontransaction",
    "accountaddressindex",
    "accountsyncaddressindex",
    "addmultisigaddress",
    "addtransaction",
    "addticket",
    "auditreuse",
    "consolidate",
    "createmultisig",
    "createnewaccount",
    "createsignature",
    "createvotingaccount",
    "discoverusage",
    "dumpprivkey",
    "fundrawtransaction",
    "generatevote",
    "getaccount",
    "getaccountaddress",
    "getaddressesbyaccount",
    "getbalance",
    "getcoinjoinsbyacct",
    "getmasterpubkey",
    "getmultisigoutinfo",
    "getnewaddress",
    "getrawchangeaddress",
    "getreceivedbyaccount",
    "getreceivedbyaddress",
    "getstakeinfo",
    "gettickets",
    "gettransaction",
    "getunconfirmedbalance",
    "getvotechoices",
    "getwalletfee",
    "importprivkey",
    "importscript",
    "importxpub",
    "listaccounts",
    "listaddresstransactions",
    "listalltransactions",
    "listlockunspent",
    "listreceivedbyaccount",
    "listreceivedbyaddress",
    "listsinceblock",
    "listtransactions",
    "listunspent",
    "lockunspent",
    "mixoutput",
    "purchaseticket",
    "redeemmultisigout",
    "redeemmultisigouts",
    "renameaccount",
    "rescanwallet",
    "revoketickets",
    "sendfrom",
    "sendfromtreasury",
    "sendmany",
    "sendtoaddress",
    "sendtomultisig",
    "sendtotreasury",
    "setticketfee",
    "settxfee",
    "setvotechoice",
    "signmessage",
    "signrawtransaction",
    "signrawtransactions",
    "sweepaccount",
    "ticketinfo",
    "verifymessage",
    "walletinfo",
    "walletislocked",
    "walletlock",
    "walletpassphrase",
    "walletpassphrasechange",
    "walletpubpassphrasechange",
];

/// Commands recognized but not implemented (dcrd `rpcUnimplemented`).
pub static RPC_UNIMPLEMENTED: &[&str] = &["estimatepriority"];

/// Commands available to a limited user (dcrd `rpcLimited`).
pub static RPC_LIMITED: &[&str] = &[
    // Websockets commands.
    "notifyblocks",
    "notifymixmessages",
    "notifynewtransactions",
    "rescan",
    "session",
    "rebroadcastwinners",
    // Websockets AND HTTP/S commands.
    "help",
    // HTTP/S-only commands.
    "createrawsstx",
    "createrawssrtx",
    "createrawtransaction",
    "decoderawtransaction",
    "decodescript",
    "estimatefee",
    "estimatesmartfee",
    "estimatestakediff",
    "existsaddress",
    "existsaddresses",
    "existsliveticket",
    "existslivetickets",
    "existsmempooltxs",
    "getbestblock",
    "getbestblockhash",
    "getblock",
    "getblockchaininfo",
    "getblockcount",
    "getblockhash",
    "getblockheader",
    "getblocksubsidy",
    "getcfilterv2",
    "getchaintips",
    "getcoinsupply",
    "getcurrentnet",
    "getdifficulty",
    "getheaders",
    "getinfo",
    "getmixmessage",
    "getmixpairrequests",
    "getnettotals",
    "getnetworkhashps",
    "getnetworkinfo",
    "getrawmempool",
    "getstakedifficulty",
    "getstakeversioninfo",
    "getstakeversions",
    "getrawtransaction",
    "gettreasurybalance",
    "gettxout",
    "getvoteinfo",
    "livetickets",
    "regentemplate",
    "sendrawmixmessage",
    "sendrawtransaction",
    "submitblock",
    "ticketfeeinfo",
    "ticketsforaddress",
    "ticketvwap",
    "txfeeinfo",
    "validateaddress",
    "verifymessage",
    "version",
];

/// The error returned to RPC clients when the provided command is
/// recognized but not implemented (dcrd `ErrRPCUnimplemented`).
pub fn err_rpc_unimplemented() -> RPCError {
    RPCError::new(codes::UNIMPLEMENTED, "Command unimplemented")
}

/// The error returned to RPC clients when the provided command is
/// recognized as a wallet command (dcrd `ErrRPCNoWallet`).
pub fn err_rpc_no_wallet() -> RPCError {
    RPCError::new(
        codes::NO_WALLET,
        "This implementation does not implement wallet commands",
    )
}

/// A JSON-RPC request parsed into a known concrete command (dcrd
/// `parsedRPCCmd`).
pub struct ParsedRpcCmd {
    /// The JSON-RPC protocol version.
    pub jsonrpc: String,
    /// The request id.
    pub id: RpcId,
    /// The requested method.
    pub method: String,
    /// The parsed command instance when parsing succeeded.
    pub params: Option<GoValue>,
    /// The reply-ready error when the command was invalid.
    pub err: Option<RPCError>,
}

/// Parse a JSON-RPC request into a known concrete command; the `err`
/// field of the result carries an error suitable for replies when the
/// command is invalid (dcrd `parseCmd`).
pub fn parse_cmd(
    registry: &dcroxide_dcrjson::Registry,
    jsonrpc: &str,
    method_name: &str,
    raw_params: &[&str],
    id: &RpcId,
) -> ParsedRpcCmd {
    let mut parsed = ParsedRpcCmd {
        jsonrpc: jsonrpc.to_string(),
        id: id.clone(),
        method: method_name.to_string(),
        params: None,
        err: None,
    };

    match parse_params(registry, &method(method_name), raw_params) {
        Ok(instance) => parsed.params = Some(GoValue::Struct(instance.fields)),
        Err(err) => {
            // Produce a relevant error when the requested method is
            // not registered depending on whether or not it is
            // recognized as a wallet command, as unimplemented, or is
            // completely unrecognized.
            if err.kind == dcroxide_dcrjson::ErrorKind::UnregisteredMethod {
                parsed.err = Some(err_rpc_method_not_found());
                if RPC_ASK_WALLET.contains(&method_name) {
                    parsed.err = Some(err_rpc_no_wallet());
                } else if RPC_UNIMPLEMENTED.contains(&method_name) {
                    parsed.err = Some(err_rpc_unimplemented());
                }
                return parsed;
            }

            // Otherwise, some type of invalid parameters is the
            // cause.
            parsed.err = Some(rpc_invalid_error(&format!(
                "Failed to parse request: {err}"
            )));
        }
    }
    parsed
}

/// Execute the handler for the parsed command and pair the result
/// with the type that drives its JSON encoding (dcrd
/// `standardCmdResult`; the encoding in dcrd rides on the concrete Go
/// result types).
pub fn standard_cmd_result<C: RpcChain>(
    server: &mut Server<C>,
    method_name: &str,
    cmd: &GoValue,
) -> Result<(GoValue, GoType), RPCError> {
    use handlers as h;
    let pair = match method_name {
        "addnode" => (h::handle_add_node(server, cmd)?, GoType::Int64.ptr()),
        "createrawssrtx" => (h::handle_create_raw_ssrtx(server, cmd)?, GoType::String),
        "createrawsstx" => (h::handle_create_raw_sstx(server, cmd)?, GoType::String),
        "createrawtransaction" => (
            h::handle_create_raw_transaction(server, cmd)?,
            GoType::String,
        ),
        "debuglevel" => (h::handle_debug_level(server, cmd)?, GoType::String),
        "decoderawtransaction" => (
            h::handle_decode_raw_transaction(server, cmd)?,
            results::tx_raw_decode_result(),
        ),
        "decodescript" => (
            h::handle_decode_script(server, cmd)?,
            results::decode_script_result(),
        ),
        "estimatefee" => (h::handle_estimate_fee(server, cmd)?, GoType::Float64),
        "estimatesmartfee" => (
            h::handle_estimate_smart_fee(server, cmd)?,
            results::estimate_smart_fee_result(),
        ),
        "estimatestakediff" => (
            h::handle_estimate_stake_diff(server, cmd)?,
            results::estimate_stake_diff_result(),
        ),
        "existsaddress" => (h::handle_exists_address(server, cmd)?, GoType::Bool),
        "existsaddresses" => (h::handle_exists_addresses(server, cmd)?, GoType::String),
        "existsliveticket" => (h::handle_exists_live_ticket(server, cmd)?, GoType::Bool),
        "existslivetickets" => (h::handle_exists_live_tickets(server, cmd)?, GoType::String),
        "existsmempooltxs" => (h::handle_exists_mempool_txs(server, cmd)?, GoType::String),
        "generate" => (h::handle_generate(server, cmd)?, GoType::String.slice()),
        "getaddednodeinfo" => {
            let value = h::handle_get_added_node_info(server, cmd)?;
            let typ = match &value {
                GoValue::Array(items) if items.iter().all(|v| matches!(v, GoValue::String(_))) => {
                    GoType::String.slice()
                }
                _ => results::get_added_node_info_result().ptr().slice(),
            };
            (value, typ)
        }
        "getbestblock" => (
            h::handle_get_best_block(server, cmd)?,
            results::get_best_block_result(),
        ),
        "getbestblockhash" => (h::handle_get_best_block_hash(server, cmd)?, GoType::String),
        "getblock" => {
            let value = h::handle_get_block(server, cmd)?;
            let typ = match &value {
                GoValue::String(_) => GoType::String,
                _ => results::get_block_verbose_result(),
            };
            (value, typ)
        }
        "getblockchaininfo" => (
            h::handle_get_blockchain_info(server, cmd)?,
            results::get_block_chain_info_result(),
        ),
        "getblockcount" => (h::handle_get_block_count(server, cmd)?, GoType::Int64),
        "getblockhash" => (h::handle_get_block_hash(server, cmd)?, GoType::String),
        "getblockheader" => {
            let value = h::handle_get_block_header(server, cmd)?;
            let typ = match &value {
                GoValue::String(_) => GoType::String,
                _ => results::get_block_header_verbose_result(),
            };
            (value, typ)
        }
        "getblocksubsidy" => (
            h::handle_get_block_subsidy(server, cmd)?,
            results::get_block_subsidy_result(),
        ),
        "getcfilterv2" => (
            h::handle_get_cfilter_v2(server, cmd)?,
            results::get_cfilter_v2_result(),
        ),
        "getchaintips" => (
            h::handle_get_chain_tips(server, cmd)?,
            results::get_chain_tips_result().slice(),
        ),
        "getcoinsupply" => (h::handle_get_coin_supply(server, cmd)?, GoType::Int64),
        "getconnectioncount" => (h::handle_get_connection_count(server, cmd)?, GoType::Int32),
        "getcurrentnet" => (h::handle_get_current_net(server, cmd)?, GoType::Uint32),
        "getdifficulty" => (h::handle_get_difficulty(server, cmd)?, GoType::Float64),
        "getgenerate" => (h::handle_get_generate(server, cmd)?, GoType::Bool),
        "gethashespersec" => (h::handle_get_hashes_per_sec(server, cmd)?, GoType::Int64),
        "getheaders" => (
            h::handle_get_headers(server, cmd)?,
            results::get_headers_result(),
        ),
        "getinfo" => (
            h::handle_get_info(server, cmd)?,
            results::info_chain_result(),
        ),
        "getmempoolinfo" => (
            h::handle_get_mempool_info(server, cmd)?,
            results::get_mempool_info_result(),
        ),
        "getmininginfo" => (
            h::handle_get_mining_info(server, cmd)?,
            results::get_mining_info_result(),
        ),
        "getmixmessage" => (
            h::handle_get_mix_message(server, cmd)?,
            results::get_mix_message_result(),
        ),
        "getmixpairrequests" => (
            h::handle_get_mix_pair_requests(server, cmd)?,
            GoType::String.slice(),
        ),
        "getnettotals" => (
            h::handle_get_net_totals(server, cmd)?,
            results::get_net_totals_result(),
        ),
        "getnetworkhashps" => (h::handle_get_network_hash_ps(server, cmd)?, GoType::Int64),
        "getnetworkinfo" => (
            h::handle_get_network_info(server, cmd)?,
            results::get_network_info_result(),
        ),
        "getpeerinfo" => (
            h::handle_get_peer_info(server, cmd)?,
            results::get_peer_info_result().ptr().slice(),
        ),
        "getrawmempool" => {
            let value = h::handle_get_raw_mempool(server, cmd)?;
            let typ = match &value {
                GoValue::Map(_) => GoType::Map(
                    Box::new(GoType::String),
                    Box::new(results::get_raw_mempool_verbose_result().ptr()),
                ),
                _ => GoType::String.slice(),
            };
            (value, typ)
        }
        "getrawtransaction" => {
            let value = h::handle_get_raw_transaction(server, cmd)?;
            let typ = match &value {
                GoValue::String(_) => GoType::String,
                _ => results::tx_raw_result(),
            };
            (value, typ)
        }
        "getstakedifficulty" => (
            h::handle_get_stake_difficulty(server, cmd)?,
            results::get_stake_difficulty_result(),
        ),
        "getstakeversioninfo" => (
            h::handle_get_stake_version_info(server, cmd)?,
            results::get_stake_version_info_result(),
        ),
        "getstakeversions" => (
            h::handle_get_stake_versions(server, cmd)?,
            results::get_stake_versions_result(),
        ),
        "getticketpoolvalue" => (
            h::handle_get_ticket_pool_value(server, cmd)?,
            GoType::Float64,
        ),
        "gettreasurybalance" => (
            h::handle_get_treasury_balance(server, cmd)?,
            results::get_treasury_balance_result(),
        ),
        "gettreasuryspendvotes" => (
            h::handle_get_treasury_spend_votes(server, cmd)?,
            results::get_treasury_spend_votes_result(),
        ),
        // dcrd returns a *GetTxOutResult: a missing or spent output
        // answers JSON null through the nil pointer.
        "gettxout" => (
            h::handle_get_tx_out(server, cmd)?,
            results::get_tx_out_result().ptr(),
        ),
        "gettxoutsetinfo" => (
            h::handle_get_tx_out_set_info(server, cmd)?,
            results::get_tx_out_set_info_result(),
        ),
        "getvoteinfo" => (
            h::handle_get_vote_info(server, cmd)?,
            results::get_vote_info_result(),
        ),
        "getwork" => {
            let value = h::handle_get_work(server, cmd)?;
            let typ = match &value {
                GoValue::Bool(_) => GoType::Bool,
                _ => results::get_work_result(),
            };
            (value, typ)
        }
        "help" => (h::handle_help(server, cmd)?, GoType::String),
        "invalidateblock" => (
            h::handle_invalidate_block(server, cmd)?,
            GoType::Int64.ptr(),
        ),
        "livetickets" => (
            h::handle_live_tickets(server, cmd)?,
            results::live_tickets_result(),
        ),
        "node" => (h::handle_node(server, cmd)?, GoType::Int64.ptr()),
        "ping" => (h::handle_ping(server, cmd)?, GoType::Int64.ptr()),
        "reconsiderblock" => (
            h::handle_reconsider_block(server, cmd)?,
            GoType::Int64.ptr(),
        ),
        "regentemplate" => (h::handle_regen_template(server, cmd)?, GoType::Int64.ptr()),
        "sendrawmixmessage" => (
            h::handle_send_raw_mix_message(server, cmd)?,
            GoType::Int64.ptr(),
        ),
        "sendrawtransaction" => (h::handle_send_raw_transaction(server, cmd)?, GoType::String),
        "setgenerate" => (h::handle_set_generate(server, cmd)?, GoType::Int64.ptr()),
        "startprofiler" => (
            h::handle_start_profiler(server, cmd)?,
            results::start_profiler_result(),
        ),
        "stop" => (h::handle_stop(server, cmd)?, GoType::String),
        "stopprofiler" => (h::handle_stop_profiler(server, cmd)?, GoType::String),
        "submitblock" => (h::handle_submit_block(server, cmd)?, GoType::String.ptr()),
        "ticketfeeinfo" => (
            h::handle_ticket_fee_info(server, cmd)?,
            results::ticket_fee_info_result(),
        ),
        "ticketsforaddress" => (
            h::handle_tickets_for_address(server, cmd)?,
            results::tickets_for_address_result(),
        ),
        "ticketvwap" => (h::handle_ticket_vwap(server, cmd)?, GoType::Float64),
        "txfeeinfo" => (
            h::handle_tx_fee_info(server, cmd)?,
            results::tx_fee_info_result(),
        ),
        "validateaddress" => (
            h::handle_validate_address(server, cmd)?,
            results::validate_address_chain_result(),
        ),
        "verifychain" => (h::handle_verify_chain(server, cmd)?, GoType::Bool),
        "verifymessage" => (h::handle_verify_message(server, cmd)?, GoType::Bool),
        "version" => (
            h::handle_version(server, cmd)?,
            GoType::Map(
                Box::new(GoType::String),
                Box::new(results::version_result()),
            ),
        ),
        _ => return Err(err_rpc_method_not_found()),
    };
    Ok(pair)
}

/// A new marshalled JSON-RPC response for the given parameters (dcrd
/// `createMarshalledReply`; every error the port produces is already
/// an RPC error, so the internal-error conversion for other kinds
/// does not arise).
pub fn create_marshalled_reply(
    rpc_version: &str,
    id: &RpcId,
    result: Option<(&GoType, &GoValue)>,
    reply_err: Option<&RPCError>,
) -> Result<String, dcroxide_dcrjson::DcrjsonError> {
    let marshalled = result.map(|(typ, value)| gojson::encode(typ, value));
    marshal_response(rpc_version, id, marshalled.as_deref(), reply_err)
}

/// Parse the request, execute it, and return the marshalled response;
/// `None` when the request is a notification (dcrd `processRequest`;
/// marshalling failures, which dcrd logs and drops, cannot occur for
/// the id types accepted here).
pub fn process_request<C: RpcChain>(
    server: &mut Server<C>,
    jsonrpc: &str,
    method_name: &str,
    raw_params: &[&str],
    id: &RpcId,
    is_admin: bool,
) -> Option<String> {
    let mut json_err: Option<RPCError> = None;

    if !is_admin && !RPC_LIMITED.contains(&method_name) {
        json_err = Some(rpc_invalid_error(
            "limited user not authorized for this method",
        ));
    }

    let mut result: Option<(GoValue, GoType)> = None;
    if json_err.is_none() {
        if method_name.is_empty() {
            let json_err = RPCError::new(
                dcroxide_dcrjson::err_rpc_invalid_request().code,
                "Invalid request: malformed",
            );
            return create_marshalled_reply(jsonrpc, id, None, Some(&json_err)).ok();
        }

        // Valid requests with no ID (notifications) must not have a
        // response per the JSON-RPC spec.
        if matches!(id, RpcId::Null) {
            return None;
        }

        // Attempt to parse the JSON-RPC request into a known concrete
        // command.
        let parsed = parse_cmd(&server.registry, jsonrpc, method_name, raw_params, id);
        match parsed.err {
            Some(err) => json_err = Some(err),
            None => {
                let cmd = parsed.params.expect("parsed without error");
                match standard_cmd_result(server, method_name, &cmd) {
                    Ok(pair) => result = Some(pair),
                    Err(err) => json_err = Some(err),
                }
            }
        }
    }

    // Marshal the response.
    create_marshalled_reply(
        jsonrpc,
        id,
        result.as_ref().map(|(value, typ)| (typ, value)),
        json_err.as_ref(),
    )
    .ok()
}
