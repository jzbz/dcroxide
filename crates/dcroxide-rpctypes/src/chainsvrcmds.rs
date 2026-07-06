// SPDX-License-Identifier: ISC
//! Chain server command definitions (dcrd rpc/jsonrpc/types
//! `chainsvrcmds.go`).
//!
//! Each Go command struct becomes a function returning its [`GoType`]
//! descriptor; [`register_chain_svr_cmds`] performs the registrations
//! dcrd performs in this file's `init` function, in the same order.

use dcroxide_dcrjson::{GoType, Registry, UsageFlag};

use crate::{f, method, named_str, strukt};

/// dcrd `ANAdd`: the host should be added as a persistent peer.
pub const AN_ADD: &str = "add";
/// dcrd `ANRemove`: the peer should be removed.
pub const AN_REMOVE: &str = "remove";
/// dcrd `ANOneTry`: try to connect once without persistence.
pub const AN_ONE_TRY: &str = "onetry";

/// dcrd `NConnect`: the host should be connected to.
pub const N_CONNECT: &str = "connect";
/// dcrd `NRemove`: the peer should be removed as persistent.
pub const N_REMOVE: &str = "remove";
/// dcrd `NDisconnect`: the peer should be disconnected.
pub const N_DISCONNECT: &str = "disconnect";

/// dcrd `EstimateSmartFeeEconomical`.
pub const ESTIMATE_SMART_FEE_ECONOMICAL: &str = "economical";
/// dcrd `EstimateSmartFeeConservative`.
pub const ESTIMATE_SMART_FEE_CONSERVATIVE: &str = "conservative";

/// dcrd `GRMAll`: any type of transaction.
pub const GRM_ALL: &str = "all";
/// dcrd `GRMRegular`: only regular transactions.
pub const GRM_REGULAR: &str = "regular";
/// dcrd `GRMTickets`: only tickets.
pub const GRM_TICKETS: &str = "tickets";
/// dcrd `GRMVotes`: only votes.
pub const GRM_VOTES: &str = "votes";
/// dcrd `GRMRevocations`: only revocations.
pub const GRM_REVOCATIONS: &str = "revocations";
/// dcrd `GRMTSpend`: only tspends.
pub const GRM_TSPEND: &str = "tspend";
/// dcrd `GRMTAdd`: only tadds.
pub const GRM_TADD: &str = "tadd";

/// The `AddNodeCmd` type (dcrd `addnode`).
pub fn add_node_cmd() -> GoType {
    strukt(
        "AddNodeCmd",
        vec![
            f("Addr", GoType::String),
            f("SubCmd", named_str("AddNodeSubCmd")).with_usage("\"add|remove|onetry\""),
        ],
    )
}

/// The `SStxInput` type: an input to an SStx transaction.
pub fn sstx_input() -> GoType {
    strukt(
        "SStxInput",
        vec![
            f("Txid", GoType::String).with_json_tag("txid"),
            f("Vout", GoType::Uint32).with_json_tag("vout"),
            f("Tree", GoType::Int8).with_json_tag("tree"),
            f("Amt", GoType::Int64).with_json_tag("amt"),
        ],
    )
}

/// The `SStxCommitOut` type: an output to an SStx transaction.
pub fn sstx_commit_out() -> GoType {
    strukt(
        "SStxCommitOut",
        vec![
            f("Addr", GoType::String).with_json_tag("addr"),
            f("CommitAmt", GoType::Int64).with_json_tag("commitamt"),
            f("ChangeAddr", GoType::String).with_json_tag("changeaddr"),
            f("ChangeAmt", GoType::Int64).with_json_tag("changeamt"),
        ],
    )
}

/// The `CreateRawSStxCmd` type (dcrd `createrawsstx`).
pub fn create_raw_sstx_cmd() -> GoType {
    strukt(
        "CreateRawSStxCmd",
        vec![
            f("Inputs", sstx_input().slice()),
            f(
                "Amount",
                GoType::Map(Box::new(GoType::String), Box::new(GoType::Int64)),
            )
            .with_usage("{\"address\":amount}"),
            f("COuts", sstx_commit_out().slice()),
        ],
    )
}

/// The `CreateRawSSRtxCmd` type (dcrd `createrawssrtx`).
pub fn create_raw_ssrtx_cmd() -> GoType {
    strukt(
        "CreateRawSSRtxCmd",
        vec![
            f("Inputs", transaction_input().slice())
                .with_usage("[{\"amount\":n.nnn,\"txid\":\"value\",\"vout\":n,\"tree\":n}]"),
            f("Fee", GoType::Float64.ptr()),
        ],
    )
}

/// The `TransactionInput` type: a transaction hash and output number
/// pair with Decred additions.
pub fn transaction_input() -> GoType {
    strukt(
        "TransactionInput",
        vec![
            f("Amount", GoType::Float64).with_json_tag("amount,omitempty"),
            f("Txid", GoType::String).with_json_tag("txid"),
            f("Vout", GoType::Uint32).with_json_tag("vout"),
            f("Tree", GoType::Int8).with_json_tag("tree"),
        ],
    )
}

/// The `CreateRawTransactionCmd` type (dcrd `createrawtransaction`).
pub fn create_raw_transaction_cmd() -> GoType {
    strukt(
        "CreateRawTransactionCmd",
        vec![
            f("Inputs", transaction_input().slice()),
            f(
                "Amounts",
                GoType::Map(Box::new(GoType::String), Box::new(GoType::Float64)),
            )
            .with_usage("{\"address\":amount,...}"),
            f("LockTime", GoType::Int64.ptr()),
            f("Expiry", GoType::Int64.ptr()),
        ],
    )
}

/// The `DebugLevelCmd` type (dcrd `debuglevel`).
pub fn debug_level_cmd() -> GoType {
    strukt("DebugLevelCmd", vec![f("LevelSpec", GoType::String)])
}

/// The `DecodeRawTransactionCmd` type (dcrd `decoderawtransaction`).
pub fn decode_raw_transaction_cmd() -> GoType {
    strukt("DecodeRawTransactionCmd", vec![f("HexTx", GoType::String)])
}

/// The `DecodeScriptCmd` type (dcrd `decodescript`).
pub fn decode_script_cmd() -> GoType {
    strukt(
        "DecodeScriptCmd",
        vec![
            f("HexScript", GoType::String),
            f("Version", GoType::Uint16.ptr()),
        ],
    )
}

/// The `EstimateFeeCmd` type (dcrd `estimatefee`).
pub fn estimate_fee_cmd() -> GoType {
    strukt("EstimateFeeCmd", vec![f("NumBlocks", GoType::Int64)])
}

/// The `EstimateSmartFeeCmd` type (dcrd `estimatesmartfee`).
pub fn estimate_smart_fee_cmd() -> GoType {
    strukt(
        "EstimateSmartFeeCmd",
        vec![
            f("Confirmations", GoType::Int64),
            f("Mode", named_str("EstimateSmartFeeMode").ptr()).with_default("\"conservative\""),
        ],
    )
}

/// The `EstimateStakeDiffCmd` type (dcrd `estimatestakediff`).
pub fn estimate_stake_diff_cmd() -> GoType {
    strukt(
        "EstimateStakeDiffCmd",
        vec![f("Tickets", GoType::Uint32.ptr())],
    )
}

/// The `ExistsAddressCmd` type (dcrd `existsaddress`).
pub fn exists_address_cmd() -> GoType {
    strukt("ExistsAddressCmd", vec![f("Address", GoType::String)])
}

/// The `ExistsAddressesCmd` type (dcrd `existsaddresses`).
pub fn exists_addresses_cmd() -> GoType {
    strukt(
        "ExistsAddressesCmd",
        vec![f("Addresses", GoType::String.slice())],
    )
}

/// The `ExistsLiveTicketCmd` type (dcrd `existsliveticket`).
pub fn exists_live_ticket_cmd() -> GoType {
    strukt("ExistsLiveTicketCmd", vec![f("TxHash", GoType::String)])
}

/// The `ExistsLiveTicketsCmd` type (dcrd `existslivetickets`).
pub fn exists_live_tickets_cmd() -> GoType {
    strukt(
        "ExistsLiveTicketsCmd",
        vec![f("TxHashes", GoType::String.slice())],
    )
}

/// The `ExistsMempoolTxsCmd` type (dcrd `existsmempooltxs`).
pub fn exists_mempool_txs_cmd() -> GoType {
    strukt(
        "ExistsMempoolTxsCmd",
        vec![f("TxHashes", GoType::String.slice())],
    )
}

/// The `GenerateCmd` type (dcrd `generate`).
pub fn generate_cmd() -> GoType {
    strukt("GenerateCmd", vec![f("NumBlocks", GoType::Uint32)])
}

/// The `GetAddedNodeInfoCmd` type (dcrd `getaddednodeinfo`).
pub fn get_added_node_info_cmd() -> GoType {
    strukt(
        "GetAddedNodeInfoCmd",
        vec![f("DNS", GoType::Bool), f("Node", GoType::String.ptr())],
    )
}

/// The `GetBestBlockCmd` type (dcrd `getbestblock`).
pub fn get_best_block_cmd() -> GoType {
    strukt("GetBestBlockCmd", vec![])
}

/// The `GetBestBlockHashCmd` type (dcrd `getbestblockhash`).
pub fn get_best_block_hash_cmd() -> GoType {
    strukt("GetBestBlockHashCmd", vec![])
}

/// The `GetBlockCmd` type (dcrd `getblock`).
pub fn get_block_cmd() -> GoType {
    strukt(
        "GetBlockCmd",
        vec![
            f("Hash", GoType::String),
            f("Verbose", GoType::Bool.ptr()).with_default("true"),
            f("VerboseTx", GoType::Bool.ptr()).with_default("false"),
        ],
    )
}

/// The `GetBlockChainInfoCmd` type (dcrd `getblockchaininfo`).
pub fn get_block_chain_info_cmd() -> GoType {
    strukt("GetBlockChainInfoCmd", vec![])
}

/// The `GetBlockCountCmd` type (dcrd `getblockcount`).
pub fn get_block_count_cmd() -> GoType {
    strukt("GetBlockCountCmd", vec![])
}

/// The `GetBlockHashCmd` type (dcrd `getblockhash`).
pub fn get_block_hash_cmd() -> GoType {
    strukt("GetBlockHashCmd", vec![f("Index", GoType::Int64)])
}

/// The `GetBlockHeaderCmd` type (dcrd `getblockheader`).
pub fn get_block_header_cmd() -> GoType {
    strukt(
        "GetBlockHeaderCmd",
        vec![
            f("Hash", GoType::String),
            f("Verbose", GoType::Bool.ptr()).with_default("true"),
        ],
    )
}

/// The `GetBlockSubsidyCmd` type (dcrd `getblocksubsidy`).
pub fn get_block_subsidy_cmd() -> GoType {
    strukt(
        "GetBlockSubsidyCmd",
        vec![f("Height", GoType::Int64), f("Voters", GoType::Uint16)],
    )
}

/// The `GetCFilterV2Cmd` type (dcrd `getcfilterv2`).
pub fn get_cfilter_v2_cmd() -> GoType {
    strukt("GetCFilterV2Cmd", vec![f("BlockHash", GoType::String)])
}

/// The `GetChainTipsCmd` type (dcrd `getchaintips`).
pub fn get_chain_tips_cmd() -> GoType {
    strukt("GetChainTipsCmd", vec![])
}

/// The `GetCoinSupplyCmd` type (dcrd `getcoinsupply`).
pub fn get_coin_supply_cmd() -> GoType {
    strukt("GetCoinSupplyCmd", vec![])
}

/// The `GetConnectionCountCmd` type (dcrd `getconnectioncount`).
pub fn get_connection_count_cmd() -> GoType {
    strukt("GetConnectionCountCmd", vec![])
}

/// The `GetCurrentNetCmd` type (dcrd `getcurrentnet`).
pub fn get_current_net_cmd() -> GoType {
    strukt("GetCurrentNetCmd", vec![])
}

/// The `GetDifficultyCmd` type (dcrd `getdifficulty`).
pub fn get_difficulty_cmd() -> GoType {
    strukt("GetDifficultyCmd", vec![])
}

/// The `GetGenerateCmd` type (dcrd `getgenerate`).
pub fn get_generate_cmd() -> GoType {
    strukt("GetGenerateCmd", vec![])
}

/// The `GetHashesPerSecCmd` type (dcrd `gethashespersec`).
pub fn get_hashes_per_sec_cmd() -> GoType {
    strukt("GetHashesPerSecCmd", vec![])
}

/// The `GetInfoCmd` type (dcrd `getinfo`).
pub fn get_info_cmd() -> GoType {
    strukt("GetInfoCmd", vec![])
}

/// The `GetHeadersCmd` type (dcrd `getheaders`).
pub fn get_headers_cmd() -> GoType {
    strukt(
        "GetHeadersCmd",
        vec![
            f("BlockLocators", GoType::String.slice()).with_json_tag("blocklocators"),
            f("HashStop", GoType::String).with_json_tag("hashstop"),
        ],
    )
}

/// The `GetMempoolInfoCmd` type (dcrd `getmempoolinfo`).
pub fn get_mempool_info_cmd() -> GoType {
    strukt("GetMempoolInfoCmd", vec![])
}

/// The `GetMiningInfoCmd` type (dcrd `getmininginfo`).
pub fn get_mining_info_cmd() -> GoType {
    strukt("GetMiningInfoCmd", vec![])
}

/// The `GetMixMessageCmd` type (dcrd `getmixmessage`).
pub fn get_mix_message_cmd() -> GoType {
    strukt("GetMixMessageCmd", vec![f("Hash", GoType::String)])
}

/// The `GetMixPairRequestsCmd` type (dcrd `getmixpairrequests`).
pub fn get_mix_pair_requests_cmd() -> GoType {
    strukt("GetMixPairRequestsCmd", vec![])
}

/// The `GetNetworkInfoCmd` type (dcrd `getnetworkinfo`).
pub fn get_network_info_cmd() -> GoType {
    strukt("GetNetworkInfoCmd", vec![])
}

/// The `GetNetTotalsCmd` type (dcrd `getnettotals`).
pub fn get_net_totals_cmd() -> GoType {
    strukt("GetNetTotalsCmd", vec![])
}

/// The `GetNetworkHashPSCmd` type (dcrd `getnetworkhashps`).
pub fn get_network_hash_ps_cmd() -> GoType {
    strukt(
        "GetNetworkHashPSCmd",
        vec![
            f("Blocks", GoType::Int.ptr()).with_default("120"),
            f("Height", GoType::Int.ptr()).with_default("-1"),
        ],
    )
}

/// The `GetPeerInfoCmd` type (dcrd `getpeerinfo`).
pub fn get_peer_info_cmd() -> GoType {
    strukt("GetPeerInfoCmd", vec![])
}

/// The `GetRawMempoolCmd` type (dcrd `getrawmempool`).
pub fn get_raw_mempool_cmd() -> GoType {
    strukt(
        "GetRawMempoolCmd",
        vec![
            f("Verbose", GoType::Bool.ptr()).with_default("false"),
            f("TxType", GoType::String.ptr()),
        ],
    )
}

/// The `GetRawTransactionCmd` type (dcrd `getrawtransaction`).  The
/// verbose field is an int versus a bool to remain compatible with
/// Bitcoin Core.
pub fn get_raw_transaction_cmd() -> GoType {
    strukt(
        "GetRawTransactionCmd",
        vec![
            f("Txid", GoType::String),
            f("Verbose", GoType::Int.ptr()).with_default("0"),
        ],
    )
}

/// The `GetStakeDifficultyCmd` type (dcrd `getstakedifficulty`).
pub fn get_stake_difficulty_cmd() -> GoType {
    strukt("GetStakeDifficultyCmd", vec![])
}

/// The `GetStakeVersionInfoCmd` type (dcrd `getstakeversioninfo`).
pub fn get_stake_version_info_cmd() -> GoType {
    strukt(
        "GetStakeVersionInfoCmd",
        vec![f("Count", GoType::Int32.ptr())],
    )
}

/// The `GetStakeVersionsCmd` type (dcrd `getstakeversions`).
pub fn get_stake_versions_cmd() -> GoType {
    strukt(
        "GetStakeVersionsCmd",
        vec![f("Hash", GoType::String), f("Count", GoType::Int32)],
    )
}

/// The `GetTicketPoolValueCmd` type (dcrd `getticketpoolvalue`).
pub fn get_ticket_pool_value_cmd() -> GoType {
    strukt("GetTicketPoolValueCmd", vec![])
}

/// The `GetTxOutCmd` type (dcrd `gettxout`).
pub fn get_tx_out_cmd() -> GoType {
    strukt(
        "GetTxOutCmd",
        vec![
            f("Txid", GoType::String),
            f("Vout", GoType::Uint32),
            f("Tree", GoType::Int8),
            f("IncludeMempool", GoType::Bool.ptr()).with_default("true"),
        ],
    )
}

/// The `GetTxOutSetInfoCmd` type (dcrd `gettxoutsetinfo`).
pub fn get_tx_out_set_info_cmd() -> GoType {
    strukt("GetTxOutSetInfoCmd", vec![])
}

/// The `GetVoteInfoCmd` type (dcrd `getvoteinfo`).
pub fn get_vote_info_cmd() -> GoType {
    strukt("GetVoteInfoCmd", vec![f("Version", GoType::Uint32)])
}

/// The `GetTreasuryBalanceCmd` type (dcrd `gettreasurybalance`).
pub fn get_treasury_balance_cmd() -> GoType {
    strukt(
        "GetTreasuryBalanceCmd",
        vec![
            f("Hash", GoType::String.ptr()),
            f("Verbose", GoType::Bool.ptr()).with_default("false"),
        ],
    )
}

/// The `GetTreasurySpendVotesCmd` type (dcrd `gettreasuryspendvotes`).
pub fn get_treasury_spend_votes_cmd() -> GoType {
    strukt(
        "GetTreasurySpendVotesCmd",
        vec![
            f("Block", GoType::String.ptr()),
            f("TSpends", GoType::String.slice().ptr()),
        ],
    )
}

/// The `GetWorkCmd` type (dcrd `getwork`).
pub fn get_work_cmd() -> GoType {
    strukt("GetWorkCmd", vec![f("Data", GoType::String.ptr())])
}

/// The `RegenTemplateCmd` type (dcrd `regentemplate`).
pub fn regen_template_cmd() -> GoType {
    strukt("RegenTemplateCmd", vec![])
}

/// The `HelpCmd` type (dcrd `help`).
pub fn help_cmd() -> GoType {
    strukt("HelpCmd", vec![f("Command", GoType::String.ptr())])
}

/// The `InvalidateBlockCmd` type (dcrd `invalidateblock`).
pub fn invalidate_block_cmd() -> GoType {
    strukt("InvalidateBlockCmd", vec![f("BlockHash", GoType::String)])
}

/// The `LiveTicketsCmd` type (dcrd `livetickets`).
pub fn live_tickets_cmd() -> GoType {
    strukt("LiveTicketsCmd", vec![])
}

/// The `NodeCmd` type (dcrd `node`).
pub fn node_cmd() -> GoType {
    strukt(
        "NodeCmd",
        vec![
            f("SubCmd", named_str("NodeSubCmd")).with_usage("\"connect|remove|disconnect\""),
            f("Target", GoType::String),
            f("ConnectSubCmd", GoType::String.ptr()).with_usage("\"perm|temp\""),
        ],
    )
}

/// The `PingCmd` type (dcrd `ping`).
pub fn ping_cmd() -> GoType {
    strukt("PingCmd", vec![])
}

/// The `ReconsiderBlockCmd` type (dcrd `reconsiderblock`).
pub fn reconsider_block_cmd() -> GoType {
    strukt("ReconsiderBlockCmd", vec![f("BlockHash", GoType::String)])
}

/// The `SendRawMixMessageCmd` type (dcrd `sendrawmixmessage`).
pub fn send_raw_mix_message_cmd() -> GoType {
    strukt(
        "SendRawMixMessageCmd",
        vec![f("Command", GoType::String), f("Message", GoType::String)],
    )
}

/// The `SendRawTransactionCmd` type (dcrd `sendrawtransaction`).
pub fn send_raw_transaction_cmd() -> GoType {
    strukt(
        "SendRawTransactionCmd",
        vec![
            f("HexTx", GoType::String),
            f("AllowHighFees", GoType::Bool.ptr()).with_default("false"),
        ],
    )
}

/// The `SetGenerateCmd` type (dcrd `setgenerate`).
pub fn set_generate_cmd() -> GoType {
    strukt(
        "SetGenerateCmd",
        vec![
            f("Generate", GoType::Bool),
            f("GenProcLimit", GoType::Int.ptr()).with_default("-1"),
        ],
    )
}

/// The `StartProfilerCmd` type (dcrd `startprofiler`).
pub fn start_profiler_cmd() -> GoType {
    strukt(
        "StartProfilerCmd",
        vec![
            f("Addr", GoType::String),
            f("AllowNonLoopback", GoType::Bool.ptr()).with_default("false"),
        ],
    )
}

/// The `StopCmd` type (dcrd `stop`).
pub fn stop_cmd() -> GoType {
    strukt("StopCmd", vec![])
}

/// The `StopProfilerCmd` type (dcrd `stopprofiler`).
pub fn stop_profiler_cmd() -> GoType {
    strukt("StopProfilerCmd", vec![])
}

/// The `SubmitBlockOptions` type: optional options provided with a
/// submitblock command.
pub fn submit_block_options() -> GoType {
    strukt(
        "SubmitBlockOptions",
        vec![f("WorkID", GoType::String).with_json_tag("workid,omitempty")],
    )
}

/// The `SubmitBlockCmd` type (dcrd `submitblock`).
pub fn submit_block_cmd() -> GoType {
    strukt(
        "SubmitBlockCmd",
        vec![
            f("HexBlock", GoType::String),
            f("Options", submit_block_options().ptr()),
        ],
    )
}

/// The `TicketFeeInfoCmd` type (dcrd `ticketfeeinfo`).
pub fn ticket_fee_info_cmd() -> GoType {
    strukt(
        "TicketFeeInfoCmd",
        vec![
            f("Blocks", GoType::Uint32.ptr()),
            f("Windows", GoType::Uint32.ptr()),
        ],
    )
}

/// The `TicketsForAddressCmd` type (dcrd `ticketsforaddress`).
pub fn tickets_for_address_cmd() -> GoType {
    strukt("TicketsForAddressCmd", vec![f("Address", GoType::String)])
}

/// The `TicketVWAPCmd` type (dcrd `ticketvwap`).
pub fn ticket_vwap_cmd() -> GoType {
    strukt(
        "TicketVWAPCmd",
        vec![
            f("Start", GoType::Uint32.ptr()),
            f("End", GoType::Uint32.ptr()),
        ],
    )
}

/// The `TxFeeInfoCmd` type (dcrd `txfeeinfo`).
pub fn tx_fee_info_cmd() -> GoType {
    strukt(
        "TxFeeInfoCmd",
        vec![
            f("Blocks", GoType::Uint32.ptr()),
            f("RangeStart", GoType::Uint32.ptr()),
            f("RangeEnd", GoType::Uint32.ptr()),
        ],
    )
}

/// The `ValidateAddressCmd` type (dcrd `validateaddress`).
pub fn validate_address_cmd() -> GoType {
    strukt("ValidateAddressCmd", vec![f("Address", GoType::String)])
}

/// The `VerifyChainCmd` type (dcrd `verifychain`).
pub fn verify_chain_cmd() -> GoType {
    strukt(
        "VerifyChainCmd",
        vec![
            f("CheckLevel", GoType::Int64.ptr()).with_default("3"),
            f("CheckDepth", GoType::Int64.ptr()).with_default("288"),
        ],
    )
}

/// The `VerifyMessageCmd` type (dcrd `verifymessage`).
pub fn verify_message_cmd() -> GoType {
    strukt(
        "VerifyMessageCmd",
        vec![
            f("Address", GoType::String),
            f("Signature", GoType::String),
            f("Message", GoType::String),
        ],
    )
}

/// The `VersionCmd` type (dcrd `version`).
pub fn version_cmd() -> GoType {
    strukt("VersionCmd", vec![])
}

/// Register every chain server command exactly as dcrd's
/// `chainsvrcmds.go` `init` function does (no special flags).
pub fn register_chain_svr_cmds(registry: &mut Registry) {
    let flags = UsageFlag(0);
    let regs: Vec<(&str, GoType)> = vec![
        ("addnode", add_node_cmd()),
        ("createrawssrtx", create_raw_ssrtx_cmd()),
        ("createrawsstx", create_raw_sstx_cmd()),
        ("createrawtransaction", create_raw_transaction_cmd()),
        ("debuglevel", debug_level_cmd()),
        ("decoderawtransaction", decode_raw_transaction_cmd()),
        ("decodescript", decode_script_cmd()),
        ("estimatefee", estimate_fee_cmd()),
        ("estimatesmartfee", estimate_smart_fee_cmd()),
        ("estimatestakediff", estimate_stake_diff_cmd()),
        ("existsaddress", exists_address_cmd()),
        ("existsaddresses", exists_addresses_cmd()),
        ("existsliveticket", exists_live_ticket_cmd()),
        ("existslivetickets", exists_live_tickets_cmd()),
        ("existsmempooltxs", exists_mempool_txs_cmd()),
        ("generate", generate_cmd()),
        ("getaddednodeinfo", get_added_node_info_cmd()),
        ("getbestblock", get_best_block_cmd()),
        ("getbestblockhash", get_best_block_hash_cmd()),
        ("getblock", get_block_cmd()),
        ("getblockchaininfo", get_block_chain_info_cmd()),
        ("getblockcount", get_block_count_cmd()),
        ("getblockhash", get_block_hash_cmd()),
        ("getblockheader", get_block_header_cmd()),
        ("getblocksubsidy", get_block_subsidy_cmd()),
        ("getcfilterv2", get_cfilter_v2_cmd()),
        ("getchaintips", get_chain_tips_cmd()),
        ("getcoinsupply", get_coin_supply_cmd()),
        ("getconnectioncount", get_connection_count_cmd()),
        ("getcurrentnet", get_current_net_cmd()),
        ("getdifficulty", get_difficulty_cmd()),
        ("getgenerate", get_generate_cmd()),
        ("gethashespersec", get_hashes_per_sec_cmd()),
        ("getheaders", get_headers_cmd()),
        ("getinfo", get_info_cmd()),
        ("getmempoolinfo", get_mempool_info_cmd()),
        ("getmininginfo", get_mining_info_cmd()),
        ("getmixmessage", get_mix_message_cmd()),
        ("getmixpairrequests", get_mix_pair_requests_cmd()),
        ("getnetworkinfo", get_network_info_cmd()),
        ("getnettotals", get_net_totals_cmd()),
        ("getnetworkhashps", get_network_hash_ps_cmd()),
        ("getpeerinfo", get_peer_info_cmd()),
        ("getrawmempool", get_raw_mempool_cmd()),
        ("getrawtransaction", get_raw_transaction_cmd()),
        ("getstakedifficulty", get_stake_difficulty_cmd()),
        ("getstakeversioninfo", get_stake_version_info_cmd()),
        ("getstakeversions", get_stake_versions_cmd()),
        ("getticketpoolvalue", get_ticket_pool_value_cmd()),
        ("gettreasurybalance", get_treasury_balance_cmd()),
        ("gettreasuryspendvotes", get_treasury_spend_votes_cmd()),
        ("gettxout", get_tx_out_cmd()),
        ("gettxoutsetinfo", get_tx_out_set_info_cmd()),
        ("getvoteinfo", get_vote_info_cmd()),
        ("getwork", get_work_cmd()),
        ("help", help_cmd()),
        ("invalidateblock", invalidate_block_cmd()),
        ("livetickets", live_tickets_cmd()),
        ("node", node_cmd()),
        ("ping", ping_cmd()),
        ("reconsiderblock", reconsider_block_cmd()),
        ("regentemplate", regen_template_cmd()),
        ("sendrawmixmessage", send_raw_mix_message_cmd()),
        ("sendrawtransaction", send_raw_transaction_cmd()),
        ("setgenerate", set_generate_cmd()),
        ("startprofiler", start_profiler_cmd()),
        ("stop", stop_cmd()),
        ("stopprofiler", stop_profiler_cmd()),
        ("submitblock", submit_block_cmd()),
        ("ticketfeeinfo", ticket_fee_info_cmd()),
        ("ticketsforaddress", tickets_for_address_cmd()),
        ("ticketvwap", ticket_vwap_cmd()),
        ("txfeeinfo", tx_fee_info_cmd()),
        ("validateaddress", validate_address_cmd()),
        ("verifychain", verify_chain_cmd()),
        ("verifymessage", verify_message_cmd()),
        ("version", version_cmd()),
    ];
    for (name, typ) in regs {
        registry.must_register(&method(name), &typ.ptr(), flags);
    }
}
