// SPDX-License-Identifier: ISC
//! Help and usage generation for the RPC server commands (dcrd
//! internal/rpcserver `rpcserverhelp.go`).

use std::collections::HashMap;

use dcroxide_dcrjson::{GoType, Registry};
use dcroxide_rpctypes::chainsvrresults as results;
use dcroxide_rpctypes::chainsvrwsresults as wsresults;
use dcroxide_rpctypes::method;

use crate::helpdescs::HELP_DESCS_EN_US;

/// The methods handled by the HTTP POST handlers (the keys of dcrd's
/// `rpcHandlers` map), sorted.
pub static RPC_HANDLER_METHODS: &[&str] = &[
    "addnode",
    "createrawssrtx",
    "createrawsstx",
    "createrawtransaction",
    "debuglevel",
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
    "generate",
    "getaddednodeinfo",
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
    "getconnectioncount",
    "getcurrentnet",
    "getdifficulty",
    "getgenerate",
    "gethashespersec",
    "getheaders",
    "getinfo",
    "getmempoolinfo",
    "getmininginfo",
    "getmixmessage",
    "getmixpairrequests",
    "getnettotals",
    "getnetworkhashps",
    "getnetworkinfo",
    "getpeerinfo",
    "getrawmempool",
    "getrawtransaction",
    "getstakedifficulty",
    "getstakeversioninfo",
    "getstakeversions",
    "getticketpoolvalue",
    "gettreasurybalance",
    "gettreasuryspendvotes",
    "gettxout",
    "gettxoutsetinfo",
    "getvoteinfo",
    "getwork",
    "help",
    "invalidateblock",
    "livetickets",
    "node",
    "ping",
    "reconsiderblock",
    "regentemplate",
    "sendrawmixmessage",
    "sendrawtransaction",
    "setgenerate",
    "startprofiler",
    "stop",
    "stopprofiler",
    "submitblock",
    "ticketfeeinfo",
    "ticketsforaddress",
    "ticketvwap",
    "txfeeinfo",
    "validateaddress",
    "verifychain",
    "verifymessage",
    "version",
];

/// The methods handled by the websocket handlers (the keys of dcrd's
/// `wsHandlers` map), sorted.
pub static WS_HANDLER_METHODS: &[&str] = &[
    "help",
    "loadtxfilter",
    "notifyblocks",
    "notifymixmessages",
    "notifynewtickets",
    "notifynewtransactions",
    "notifytspend",
    "notifywinningtickets",
    "notifywork",
    "rebroadcastwinners",
    "rescan",
    "session",
    "stopnotifyblocks",
    "stopnotifymixmessages",
    "stopnotifynewtransactions",
    "stopnotifytspend",
    "stopnotifywork",
];

/// The result types each RPC command can return (dcrd
/// `rpcResultTypes`): pointers to the result descriptors, with `None`
/// standing for Go's nil (no return value).  A method absent from the
/// table returns `None` overall, matching a missing map entry.
pub fn rpc_result_types(method: &str) -> Option<Vec<Option<GoType>>> {
    fn p(t: GoType) -> Option<GoType> {
        Some(t.ptr())
    }
    let string = GoType::String;
    Some(match method {
        "addnode" => vec![],
        "createrawssrtx" => vec![p(string.clone())],
        "createrawsstx" => vec![p(string.clone())],
        "createrawtransaction" => vec![p(string.clone())],
        "debuglevel" => vec![p(string.clone()), p(string.clone())],
        "decoderawtransaction" => vec![p(results::tx_raw_decode_result())],
        "decodescript" => vec![p(results::decode_script_result())],
        "estimatefee" => vec![p(GoType::Float64)],
        "estimatesmartfee" => vec![p(results::estimate_smart_fee_result())],
        "estimatestakediff" => vec![p(results::estimate_stake_diff_result())],
        "existsaddress" => vec![p(GoType::Bool)],
        "existsaddresses" => vec![p(string.clone())],
        "existsliveticket" => vec![p(GoType::Bool)],
        "existslivetickets" => vec![p(string.clone())],
        "existsmempooltxs" => vec![p(string.clone())],
        "generate" => vec![p(string.clone().slice()), None],
        "getaddednodeinfo" => vec![
            p(string.clone().slice()),
            p(results::get_added_node_info_result().slice()),
        ],
        "getbestblock" => vec![p(results::get_best_block_result())],
        "getbestblockhash" => vec![p(string.clone())],
        "getblock" => vec![p(string.clone()), p(results::get_block_verbose_result())],
        "getblockchaininfo" => vec![p(results::get_block_chain_info_result())],
        "getblockcount" => vec![p(GoType::Int64)],
        "getblockhash" => vec![p(string.clone())],
        "getblockheader" => vec![
            p(string.clone()),
            p(results::get_block_header_verbose_result()),
        ],
        "getblocksubsidy" => vec![p(results::get_block_subsidy_result())],
        "getcfilterv2" => vec![p(results::get_cfilter_v2_result())],
        "getchaintips" => vec![p(results::get_chain_tips_result().slice())],
        "getcoinsupply" => vec![p(GoType::Int64)],
        "getconnectioncount" => vec![p(GoType::Int32)],
        "getcurrentnet" => vec![p(GoType::Uint32)],
        "getdifficulty" => vec![p(GoType::Float64)],
        "getgenerate" => vec![p(GoType::Bool)],
        "gethashespersec" => vec![p(GoType::Float64)],
        "getheaders" => vec![p(results::get_headers_result())],
        "getinfo" => vec![p(results::info_chain_result())],
        "getmempoolinfo" => vec![p(results::get_mempool_info_result())],
        "getmininginfo" => vec![p(results::get_mining_info_result())],
        "getmixmessage" => vec![p(results::get_mix_message_result())],
        "getmixpairrequests" => vec![p(string.clone().slice())],
        "getnettotals" => vec![p(results::get_net_totals_result())],
        "getnetworkhashps" => vec![p(GoType::Int64)],
        "getnetworkinfo" => vec![p(results::get_network_info_result().slice())],
        "getpeerinfo" => vec![p(results::get_peer_info_result().slice())],
        "getrawmempool" => vec![
            p(string.clone().slice()),
            p(results::get_raw_mempool_verbose_result()),
        ],
        "getrawtransaction" => vec![p(string.clone()), p(results::tx_raw_result())],
        "getstakedifficulty" => vec![p(results::get_stake_difficulty_result())],
        "getstakeversioninfo" => vec![p(results::get_stake_version_info_result())],
        "getstakeversions" => vec![p(results::get_stake_versions_result())],
        "getticketpoolvalue" => vec![p(GoType::Float64)],
        "gettreasurybalance" => vec![p(results::get_treasury_balance_result())],
        "gettreasuryspendvotes" => vec![p(results::get_treasury_spend_votes_result())],
        "gettxout" => vec![p(results::get_tx_out_result())],
        "gettxoutsetinfo" => vec![p(results::get_tx_out_set_info_result())],
        "getvoteinfo" => vec![p(results::get_vote_info_result())],
        "getwork" => vec![p(results::get_work_result()), p(GoType::Bool)],
        "help" => vec![p(string.clone()), p(string.clone())],
        "invalidateblock" => vec![],
        "livetickets" => vec![p(results::live_tickets_result())],
        "node" => vec![],
        "ping" => vec![],
        "reconsiderblock" => vec![],
        "regentemplate" => vec![],
        "sendrawmixmessage" => vec![],
        "sendrawtransaction" => vec![p(string.clone())],
        "setgenerate" => vec![],
        "startprofiler" => vec![p(results::start_profiler_result())],
        "stop" => vec![p(string.clone())],
        "stopprofiler" => vec![p(string.clone())],
        "submitblock" => vec![None, p(string.clone())],
        "ticketfeeinfo" => vec![p(results::ticket_fee_info_result())],
        "ticketsforaddress" => vec![p(results::tickets_for_address_result())],
        "ticketvwap" => vec![p(GoType::Float64)],
        "txfeeinfo" => vec![p(results::tx_fee_info_result())],
        "validateaddress" => vec![p(results::validate_address_chain_result())],
        "verifychain" => vec![p(GoType::Bool)],
        "verifymessage" => vec![p(GoType::Bool)],
        "version" => vec![p(GoType::Map(
            Box::new(GoType::String),
            Box::new(results::version_result()),
        ))],
        // Websocket commands.
        "loadtxfilter" => vec![],
        "notifyblocks" => vec![],
        "notifymixmessages" => vec![],
        "notifynewtickets" => vec![],
        "notifynewtransactions" => vec![],
        "notifytspend" => vec![],
        "notifywinningtickets" => vec![],
        "notifywork" => vec![],
        "rebroadcastwinners" => vec![],
        "rescan" => vec![p(wsresults::rescan_result())],
        "session" => vec![p(wsresults::session_result())],
        "stopnotifyblocks" => vec![],
        "stopnotifymixmessages" => vec![],
        "stopnotifynewtransactions" => vec![],
        "stopnotifytspend" => vec![],
        "stopnotifywork" => vec![],
        _ => return None,
    })
}

/// Help and usage provider for the RPC server commands that caches
/// its results (dcrd `helpCacher`).  dcrd's mutex is daemon-phase
/// concurrency; the port takes `&mut self`.
///
/// The usage cache holds a single string regardless of the websocket
/// flag, exactly like dcrd: whichever variant is requested first is
/// returned for both (QK-0005).
pub struct HelpCacher {
    descs: HashMap<String, String>,
    usage: String,
    method_help: HashMap<String, String>,
}

impl HelpCacher {
    /// A new help cacher (dcrd `newHelpCacher`).
    pub fn new() -> HelpCacher {
        HelpCacher {
            descs: HELP_DESCS_EN_US
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            usage: String::new(),
            method_help: HashMap::new(),
        }
    }

    /// An RPC help string for the provided method (dcrd
    /// `RPCMethodHelp`).  The error is dcrd's plain error text.
    pub fn rpc_method_help(
        &mut self,
        registry: &Registry,
        method_name: &str,
    ) -> Result<String, String> {
        // Return the cached method help if it exists.
        if let Some(help) = self.method_help.get(method_name) {
            return Ok(help.clone());
        }

        // Look up the result types for the method.
        let Some(result_types) = rpc_result_types(method_name) else {
            return Err(format!(
                "no result types specified for method {method_name}"
            ));
        };

        // Generate, cache, and return the help.
        let (help, err) = registry.generate_help(&method(method_name), &self.descs, &result_types);
        if let Some(err) = err {
            return Err(err.description);
        }
        self.method_help
            .insert(method_name.to_string(), help.clone());
        Ok(help)
    }

    /// One-line usage for all supported RPC commands (dcrd
    /// `RPCUsage`).
    pub fn rpc_usage(
        &mut self,
        registry: &Registry,
        include_websockets: bool,
    ) -> Result<String, String> {
        // Return the cached usage if it is available.
        if !self.usage.is_empty() {
            return Ok(self.usage.clone());
        }

        // Generate a list of one-line usage for every command.
        let mut usage_texts = Vec::with_capacity(RPC_HANDLER_METHODS.len());
        for m in RPC_HANDLER_METHODS {
            let usage = registry
                .method_usage_text(&method(m))
                .map_err(|e| e.description)?;
            usage_texts.push(usage);
        }

        // Include websockets commands if requested.
        if include_websockets {
            for m in WS_HANDLER_METHODS {
                let usage = registry
                    .method_usage_text(&method(m))
                    .map_err(|e| e.description)?;
                usage_texts.push(usage);
            }
        }

        usage_texts.sort();
        self.usage = usage_texts.join("\n");
        Ok(self.usage.clone())
    }
}

impl Default for HelpCacher {
    fn default() -> Self {
        HelpCacher::new()
    }
}
