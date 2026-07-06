// SPDX-License-Identifier: ISC
//! Chain server result definitions (dcrd rpc/jsonrpc/types
//! `chainsvrresults.go`).
//!
//! `Vin` carries a custom `json.Marshaler` in dcrd that renders one of
//! five shapes depending on the input kind; [`marshal_vin`] ports that
//! switch and produces raw JSON for embedding via [`GoValue::Raw`].

use dcroxide_dcrjson::{GoType, GoValue, gojson};

use crate::{f, strukt};

/// dcrd `AgendaInfoStatusDefined`.
pub const AGENDA_INFO_STATUS_DEFINED: &str = "defined";
/// dcrd `AgendaInfoStatusStarted`.
pub const AGENDA_INFO_STATUS_STARTED: &str = "started";
/// dcrd `AgendaInfoStatusLockedIn`.
pub const AGENDA_INFO_STATUS_LOCKED_IN: &str = "lockedin";
/// dcrd `AgendaInfoStatusActive`.
pub const AGENDA_INFO_STATUS_ACTIVE: &str = "active";
/// dcrd `AgendaInfoStatusFailed`.
pub const AGENDA_INFO_STATUS_FAILED: &str = "failed";

/// The `TxRawDecodeResult` type (decoderawtransaction).
pub fn tx_raw_decode_result() -> GoType {
    strukt(
        "TxRawDecodeResult",
        vec![
            f("Txid", GoType::String).with_json_tag("txid"),
            f("Version", GoType::Int32).with_json_tag("version"),
            f("Locktime", GoType::Uint32).with_json_tag("locktime"),
            f("Expiry", GoType::Uint32).with_json_tag("expiry"),
            f("Vin", vin().slice()).with_json_tag("vin"),
            f("Vout", vout().slice()).with_json_tag("vout"),
        ],
    )
}

/// The `DecodeScriptResult` type (decodescript).
pub fn decode_script_result() -> GoType {
    strukt(
        "DecodeScriptResult",
        vec![
            f("Asm", GoType::String).with_json_tag("asm"),
            f("ReqSigs", GoType::Int32).with_json_tag("reqSigs,omitempty"),
            f("Type", GoType::String).with_json_tag("type"),
            f("Addresses", GoType::String.slice()).with_json_tag("addresses,omitempty"),
            f("P2sh", GoType::String).with_json_tag("p2sh,omitempty"),
        ],
    )
}

/// The `EstimateSmartFeeResult` type (estimatesmartfee).
pub fn estimate_smart_fee_result() -> GoType {
    strukt(
        "EstimateSmartFeeResult",
        vec![
            f("FeeRate", GoType::Float64).with_json_tag("feerate"),
            f("Errors", GoType::String.slice()).with_json_tag("errors,omitempty"),
            f("Blocks", GoType::Int64).with_json_tag("blocks"),
        ],
    )
}

/// The `EstimateStakeDiffResult` type (estimatestakediff).
pub fn estimate_stake_diff_result() -> GoType {
    strukt(
        "EstimateStakeDiffResult",
        vec![
            f("Min", GoType::Float64).with_json_tag("min"),
            f("Max", GoType::Float64).with_json_tag("max"),
            f("Expected", GoType::Float64).with_json_tag("expected"),
            f("User", GoType::Float64.ptr()).with_json_tag("user,omitempty"),
        ],
    )
}

/// The `GetAddedNodeInfoResultAddr` type.
pub fn get_added_node_info_result_addr() -> GoType {
    strukt(
        "GetAddedNodeInfoResultAddr",
        vec![
            f("Address", GoType::String).with_json_tag("address"),
            f("Connected", GoType::String).with_json_tag("connected"),
        ],
    )
}

/// The `GetAddedNodeInfoResult` type (getaddednodeinfo).
pub fn get_added_node_info_result() -> GoType {
    strukt(
        "GetAddedNodeInfoResult",
        vec![
            f("AddedNode", GoType::String).with_json_tag("addednode"),
            f("Connected", GoType::Bool.ptr()).with_json_tag("connected,omitempty"),
            f("Addresses", get_added_node_info_result_addr().slice().ptr())
                .with_json_tag("addresses,omitempty"),
        ],
    )
}

/// The `GetBlockVerboseResult` type (getblock with verbose set).
pub fn get_block_verbose_result() -> GoType {
    strukt(
        "GetBlockVerboseResult",
        vec![
            f("Hash", GoType::String).with_json_tag("hash"),
            f("PoWHash", GoType::String).with_json_tag("powhash"),
            f("Confirmations", GoType::Int64).with_json_tag("confirmations"),
            f("Size", GoType::Int32).with_json_tag("size"),
            f("Height", GoType::Int64).with_json_tag("height"),
            f("Version", GoType::Int32).with_json_tag("version"),
            f("MerkleRoot", GoType::String).with_json_tag("merkleroot"),
            f("StakeRoot", GoType::String).with_json_tag("stakeroot"),
            f("Tx", GoType::String.slice()).with_json_tag("tx,omitempty"),
            f("RawTx", tx_raw_result().slice()).with_json_tag("rawtx,omitempty"),
            f("STx", GoType::String.slice()).with_json_tag("stx,omitempty"),
            f("RawSTx", tx_raw_result().slice()).with_json_tag("rawstx,omitempty"),
            f("Time", GoType::Int64).with_json_tag("time"),
            f("MedianTime", GoType::Int64).with_json_tag("mediantime"),
            f("Nonce", GoType::Uint32).with_json_tag("nonce"),
            f("VoteBits", GoType::Uint16).with_json_tag("votebits"),
            f("FinalState", GoType::String).with_json_tag("finalstate"),
            f("Voters", GoType::Uint16).with_json_tag("voters"),
            f("FreshStake", GoType::Uint8).with_json_tag("freshstake"),
            f("Revocations", GoType::Uint8).with_json_tag("revocations"),
            f("PoolSize", GoType::Uint32).with_json_tag("poolsize"),
            f("Bits", GoType::String).with_json_tag("bits"),
            f("SBits", GoType::Float64).with_json_tag("sbits"),
            f("ExtraData", GoType::String).with_json_tag("extradata"),
            f("StakeVersion", GoType::Uint32).with_json_tag("stakeversion"),
            f("Difficulty", GoType::Float64).with_json_tag("difficulty"),
            f("ChainWork", GoType::String).with_json_tag("chainwork"),
            f("PreviousHash", GoType::String).with_json_tag("previousblockhash"),
            f("NextHash", GoType::String).with_json_tag("nextblockhash,omitempty"),
        ],
    )
}

/// The `AgendaInfo` type: an overview of an agenda in a consensus
/// deployment.
pub fn agenda_info() -> GoType {
    strukt(
        "AgendaInfo",
        vec![
            f("Status", GoType::String).with_json_tag("status"),
            f("Since", GoType::Int64).with_json_tag("since,omitempty"),
            f("StartTime", GoType::Uint64).with_json_tag("starttime"),
            f("ExpireTime", GoType::Uint64).with_json_tag("expiretime"),
        ],
    )
}

/// The `GetBestBlockResult` type (getbestblock).
pub fn get_best_block_result() -> GoType {
    strukt(
        "GetBestBlockResult",
        vec![
            f("Hash", GoType::String).with_json_tag("hash"),
            f("Height", GoType::Int64).with_json_tag("height"),
        ],
    )
}

/// The `GetBlockChainInfoResult` type (getblockchaininfo).
pub fn get_block_chain_info_result() -> GoType {
    strukt(
        "GetBlockChainInfoResult",
        vec![
            f("Chain", GoType::String).with_json_tag("chain"),
            f("Blocks", GoType::Int64).with_json_tag("blocks"),
            f("Headers", GoType::Int64).with_json_tag("headers"),
            f("SyncHeight", GoType::Int64).with_json_tag("syncheight"),
            f("BestBlockHash", GoType::String).with_json_tag("bestblockhash"),
            f("Difficulty", GoType::Uint32).with_json_tag("difficulty"),
            f("DifficultyRatio", GoType::Float64).with_json_tag("difficultyratio"),
            f("VerificationProgress", GoType::Float64).with_json_tag("verificationprogress"),
            f("ChainWork", GoType::String).with_json_tag("chainwork"),
            f("InitialBlockDownload", GoType::Bool).with_json_tag("initialblockdownload"),
            f("MaxBlockSize", GoType::Int64).with_json_tag("maxblocksize"),
            f(
                "Deployments",
                GoType::Map(Box::new(GoType::String), Box::new(agenda_info())),
            )
            .with_json_tag("deployments"),
        ],
    )
}

/// The `GetBlockHeaderVerboseResult` type (getblockheader with
/// verbose set).
pub fn get_block_header_verbose_result() -> GoType {
    strukt(
        "GetBlockHeaderVerboseResult",
        vec![
            f("Hash", GoType::String).with_json_tag("hash"),
            f("PowHash", GoType::String).with_json_tag("powhash"),
            f("Confirmations", GoType::Int64).with_json_tag("confirmations"),
            f("Version", GoType::Int32).with_json_tag("version"),
            f("MerkleRoot", GoType::String).with_json_tag("merkleroot"),
            f("StakeRoot", GoType::String).with_json_tag("stakeroot"),
            f("VoteBits", GoType::Uint16).with_json_tag("votebits"),
            f("FinalState", GoType::String).with_json_tag("finalstate"),
            f("Voters", GoType::Uint16).with_json_tag("voters"),
            f("FreshStake", GoType::Uint8).with_json_tag("freshstake"),
            f("Revocations", GoType::Uint8).with_json_tag("revocations"),
            f("PoolSize", GoType::Uint32).with_json_tag("poolsize"),
            f("Bits", GoType::String).with_json_tag("bits"),
            f("SBits", GoType::Float64).with_json_tag("sbits"),
            f("Height", GoType::Uint32).with_json_tag("height"),
            f("Size", GoType::Uint32).with_json_tag("size"),
            f("Time", GoType::Int64).with_json_tag("time"),
            f("MedianTime", GoType::Int64).with_json_tag("mediantime"),
            f("Nonce", GoType::Uint32).with_json_tag("nonce"),
            f("ExtraData", GoType::String).with_json_tag("extradata"),
            f("StakeVersion", GoType::Uint32).with_json_tag("stakeversion"),
            f("Difficulty", GoType::Float64).with_json_tag("difficulty"),
            f("ChainWork", GoType::String).with_json_tag("chainwork"),
            f("PreviousHash", GoType::String).with_json_tag("previousblockhash,omitempty"),
            f("NextHash", GoType::String).with_json_tag("nextblockhash,omitempty"),
        ],
    )
}

/// The `GetBlockSubsidyResult` type (getblocksubsidy).
pub fn get_block_subsidy_result() -> GoType {
    strukt(
        "GetBlockSubsidyResult",
        vec![
            f("Developer", GoType::Int64).with_json_tag("developer"),
            f("PoS", GoType::Int64).with_json_tag("pos"),
            f("PoW", GoType::Int64).with_json_tag("pow"),
            f("Total", GoType::Int64).with_json_tag("total"),
        ],
    )
}

/// The `GetChainTipsResult` type (getchaintips).
pub fn get_chain_tips_result() -> GoType {
    strukt(
        "GetChainTipsResult",
        vec![
            f("Height", GoType::Int64).with_json_tag("height"),
            f("Hash", GoType::String).with_json_tag("hash"),
            f("BranchLen", GoType::Int64).with_json_tag("branchlen"),
            f("Status", GoType::String).with_json_tag("status"),
        ],
    )
}

/// The `GetCFilterV2Result` type (getcfilterv2).
pub fn get_cfilter_v2_result() -> GoType {
    strukt(
        "GetCFilterV2Result",
        vec![
            f("BlockHash", GoType::String).with_json_tag("blockhash"),
            f("Data", GoType::String).with_json_tag("data"),
            f("ProofIndex", GoType::Uint32).with_json_tag("proofindex"),
            f("ProofHashes", GoType::String.slice()).with_json_tag("proofhashes"),
        ],
    )
}

/// The `GetHeadersResult` type (getheaders).
pub fn get_headers_result() -> GoType {
    strukt(
        "GetHeadersResult",
        vec![f("Headers", GoType::String.slice()).with_json_tag("headers")],
    )
}

/// The `InfoChainResult` type (getinfo).
pub fn info_chain_result() -> GoType {
    strukt(
        "InfoChainResult",
        vec![
            f("Version", GoType::Int32).with_json_tag("version"),
            f("ProtocolVersion", GoType::Int32).with_json_tag("protocolversion"),
            f("Blocks", GoType::Int64).with_json_tag("blocks"),
            f("TimeOffset", GoType::Int64).with_json_tag("timeoffset"),
            f("Connections", GoType::Int32).with_json_tag("connections"),
            f("Proxy", GoType::String).with_json_tag("proxy"),
            f("Difficulty", GoType::Float64).with_json_tag("difficulty"),
            f("TestNet", GoType::Bool).with_json_tag("testnet"),
            f("RelayFee", GoType::Float64).with_json_tag("relayfee"),
            f("Errors", GoType::String).with_json_tag("errors"),
            f("TxIndex", GoType::Bool).with_json_tag("txindex"),
        ],
    )
}

/// The `GetMempoolInfoResult` type (getmempoolinfo).
pub fn get_mempool_info_result() -> GoType {
    strukt(
        "GetMempoolInfoResult",
        vec![
            f("Size", GoType::Int64).with_json_tag("size"),
            f("Bytes", GoType::Int64).with_json_tag("bytes"),
        ],
    )
}

/// The `GetMiningInfoResult` type (getmininginfo).
pub fn get_mining_info_result() -> GoType {
    strukt(
        "GetMiningInfoResult",
        vec![
            f("Blocks", GoType::Int64).with_json_tag("blocks"),
            f("CurrentBlockSize", GoType::Uint64).with_json_tag("currentblocksize"),
            f("CurrentBlockTx", GoType::Uint64).with_json_tag("currentblocktx"),
            f("Difficulty", GoType::Float64).with_json_tag("difficulty"),
            f("StakeDifficulty", GoType::Int64).with_json_tag("stakedifficulty"),
            f("Errors", GoType::String).with_json_tag("errors"),
            f("Generate", GoType::Bool).with_json_tag("generate"),
            f("GenProcLimit", GoType::Int32).with_json_tag("genproclimit"),
            f("HashesPerSec", GoType::Int64).with_json_tag("hashespersec"),
            f("NetworkHashPS", GoType::Int64).with_json_tag("networkhashps"),
            f("PooledTx", GoType::Uint64).with_json_tag("pooledtx"),
            f("TestNet", GoType::Bool).with_json_tag("testnet"),
        ],
    )
}

/// The `GetMixMessageResult` type (getmixmessage).
pub fn get_mix_message_result() -> GoType {
    strukt(
        "GetMixMessageResult",
        vec![
            f("Type", GoType::String).with_json_tag("type"),
            f("Message", GoType::String).with_json_tag("message"),
        ],
    )
}

/// The `LocalAddressesResult` type (getnetworkinfo).
pub fn local_addresses_result() -> GoType {
    strukt(
        "LocalAddressesResult",
        vec![
            f("Address", GoType::String).with_json_tag("address"),
            f("Port", GoType::Uint16).with_json_tag("port"),
            f("Score", GoType::Int32).with_json_tag("score"),
        ],
    )
}

/// The `NetworksResult` type (getnetworkinfo).
pub fn networks_result() -> GoType {
    strukt(
        "NetworksResult",
        vec![
            f("Name", GoType::String).with_json_tag("name"),
            f("Limited", GoType::Bool).with_json_tag("limited"),
            f("Reachable", GoType::Bool).with_json_tag("reachable"),
            f("Proxy", GoType::String).with_json_tag("proxy"),
            f("ProxyRandomizeCredentials", GoType::Bool).with_json_tag("proxyrandomizecredentials"),
        ],
    )
}

/// The `GetNetworkInfoResult` type (getnetworkinfo).
pub fn get_network_info_result() -> GoType {
    strukt(
        "GetNetworkInfoResult",
        vec![
            f("Version", GoType::Int32).with_json_tag("version"),
            f("SubVersion", GoType::String).with_json_tag("subversion"),
            f("ProtocolVersion", GoType::Int32).with_json_tag("protocolversion"),
            f("TimeOffset", GoType::Int64).with_json_tag("timeoffset"),
            f("Connections", GoType::Int32).with_json_tag("connections"),
            f("Networks", networks_result().slice()).with_json_tag("networks"),
            f("RelayFee", GoType::Float64).with_json_tag("relayfee"),
            f("LocalAddresses", local_addresses_result().slice()).with_json_tag("localaddresses"),
            f("LocalServices", GoType::String).with_json_tag("localservices"),
        ],
    )
}

/// The `GetNetTotalsResult` type (getnettotals).
pub fn get_net_totals_result() -> GoType {
    strukt(
        "GetNetTotalsResult",
        vec![
            f("TotalBytesRecv", GoType::Uint64).with_json_tag("totalbytesrecv"),
            f("TotalBytesSent", GoType::Uint64).with_json_tag("totalbytessent"),
            f("TimeMillis", GoType::Int64).with_json_tag("timemillis"),
        ],
    )
}

/// The `GetPeerInfoResult` type (getpeerinfo).
pub fn get_peer_info_result() -> GoType {
    strukt(
        "GetPeerInfoResult",
        vec![
            f("ID", GoType::Int32).with_json_tag("id"),
            f("Addr", GoType::String).with_json_tag("addr"),
            f("AddrLocal", GoType::String).with_json_tag("addrlocal,omitempty"),
            f("Services", GoType::String).with_json_tag("services"),
            f("RelayTxes", GoType::Bool).with_json_tag("relaytxes"),
            f("LastSend", GoType::Int64).with_json_tag("lastsend"),
            f("LastRecv", GoType::Int64).with_json_tag("lastrecv"),
            f("BytesSent", GoType::Uint64).with_json_tag("bytessent"),
            f("BytesRecv", GoType::Uint64).with_json_tag("bytesrecv"),
            f("ConnTime", GoType::Int64).with_json_tag("conntime"),
            f("TimeOffset", GoType::Int64).with_json_tag("timeoffset"),
            f("PingTime", GoType::Float64).with_json_tag("pingtime"),
            f("PingWait", GoType::Float64).with_json_tag("pingwait,omitempty"),
            f("Version", GoType::Uint32).with_json_tag("version"),
            f("SubVer", GoType::String).with_json_tag("subver"),
            f("Inbound", GoType::Bool).with_json_tag("inbound"),
            f("StartingHeight", GoType::Int64).with_json_tag("startingheight"),
            f("CurrentHeight", GoType::Int64).with_json_tag("currentheight,omitempty"),
            f("BanScore", GoType::Int32).with_json_tag("banscore"),
            f("SyncNode", GoType::Bool).with_json_tag("syncnode"),
        ],
    )
}

/// The `GetRawMempoolVerboseResult` type (getrawmempool with verbose
/// set).
pub fn get_raw_mempool_verbose_result() -> GoType {
    strukt(
        "GetRawMempoolVerboseResult",
        vec![
            f("Size", GoType::Int32).with_json_tag("size"),
            f("Fee", GoType::Float64).with_json_tag("fee"),
            f("Time", GoType::Int64).with_json_tag("time"),
            f("Height", GoType::Int64).with_json_tag("height"),
            f("StartingPriority", GoType::Float64).with_json_tag("startingpriority"),
            f("CurrentPriority", GoType::Float64).with_json_tag("currentpriority"),
            f("Depends", GoType::String.slice()).with_json_tag("depends"),
        ],
    )
}

/// The `TxRawResult` type (getrawtransaction).
pub fn tx_raw_result() -> GoType {
    strukt(
        "TxRawResult",
        vec![
            f("Hex", GoType::String).with_json_tag("hex"),
            f("Txid", GoType::String).with_json_tag("txid"),
            f("Version", GoType::Int32).with_json_tag("version"),
            f("LockTime", GoType::Uint32).with_json_tag("locktime"),
            f("Expiry", GoType::Uint32).with_json_tag("expiry"),
            f("Vin", vin().slice()).with_json_tag("vin"),
            f("Vout", vout().slice()).with_json_tag("vout"),
            f("BlockHash", GoType::String).with_json_tag("blockhash,omitempty"),
            f("BlockHeight", GoType::Int64).with_json_tag("blockheight,omitempty"),
            f("BlockIndex", GoType::Uint32).with_json_tag("blockindex,omitempty"),
            f("Confirmations", GoType::Int64).with_json_tag("confirmations,omitempty"),
            f("Time", GoType::Int64).with_json_tag("time,omitempty"),
            f("Blocktime", GoType::Int64).with_json_tag("blocktime,omitempty"),
        ],
    )
}

/// The `GetStakeDifficultyResult` type (getstakedifficulty).
pub fn get_stake_difficulty_result() -> GoType {
    strukt(
        "GetStakeDifficultyResult",
        vec![
            f("CurrentStakeDifficulty", GoType::Float64).with_json_tag("current"),
            f("NextStakeDifficulty", GoType::Float64).with_json_tag("next"),
        ],
    )
}

/// The `VersionCount` type: a generic version:count tuple.
pub fn version_count() -> GoType {
    strukt(
        "VersionCount",
        vec![
            f("Version", GoType::Uint32).with_json_tag("version"),
            f("Count", GoType::Uint32).with_json_tag("count"),
        ],
    )
}

/// The `VersionInterval` type: a cooked version count for an interval.
pub fn version_interval() -> GoType {
    strukt(
        "VersionInterval",
        vec![
            f("StartHeight", GoType::Int64).with_json_tag("startheight"),
            f("EndHeight", GoType::Int64).with_json_tag("endheight"),
            f("PoSVersions", version_count().slice()).with_json_tag("posversions"),
            f("VoteVersions", version_count().slice()).with_json_tag("voteversions"),
        ],
    )
}

/// The `GetStakeVersionInfoResult` type (getstakeversioninfo).
pub fn get_stake_version_info_result() -> GoType {
    strukt(
        "GetStakeVersionInfoResult",
        vec![
            f("CurrentHeight", GoType::Int64).with_json_tag("currentheight"),
            f("Hash", GoType::String).with_json_tag("hash"),
            f("Intervals", version_interval().slice()).with_json_tag("intervals"),
        ],
    )
}

/// The `VersionBits` type: a generic version:bits tuple.
pub fn version_bits() -> GoType {
    strukt(
        "VersionBits",
        vec![
            f("Version", GoType::Uint32).with_json_tag("version"),
            f("Bits", GoType::Uint16).with_json_tag("bits"),
        ],
    )
}

/// The `StakeVersions` type.
pub fn stake_versions() -> GoType {
    strukt(
        "StakeVersions",
        vec![
            f("Hash", GoType::String).with_json_tag("hash"),
            f("Height", GoType::Int64).with_json_tag("height"),
            f("BlockVersion", GoType::Int32).with_json_tag("blockversion"),
            f("StakeVersion", GoType::Uint32).with_json_tag("stakeversion"),
            f("Votes", version_bits().slice()).with_json_tag("votes"),
        ],
    )
}

/// The `GetStakeVersionsResult` type (getstakeversions).
pub fn get_stake_versions_result() -> GoType {
    strukt(
        "GetStakeVersionsResult",
        vec![f("StakeVersions", stake_versions().slice()).with_json_tag("stakeversions")],
    )
}

/// The `GetTxOutResult` type (gettxout).
pub fn get_tx_out_result() -> GoType {
    strukt(
        "GetTxOutResult",
        vec![
            f("BestBlock", GoType::String).with_json_tag("bestblock"),
            f("Confirmations", GoType::Int64).with_json_tag("confirmations"),
            f("Value", GoType::Float64).with_json_tag("value"),
            f("ScriptPubKey", script_pub_key_result()).with_json_tag("scriptPubKey"),
            f("Coinbase", GoType::Bool).with_json_tag("coinbase"),
        ],
    )
}

/// The `GetTxOutSetInfoResult` type (gettxoutsetinfo).
pub fn get_tx_out_set_info_result() -> GoType {
    strukt(
        "GetTxOutSetInfoResult",
        vec![
            f("Height", GoType::Int64).with_json_tag("height"),
            f("BestBlock", GoType::String).with_json_tag("bestblock"),
            f("Transactions", GoType::Int64).with_json_tag("transactions"),
            f("TxOuts", GoType::Int64).with_json_tag("txouts"),
            f("SerializedHash", GoType::String).with_json_tag("serializedhash"),
            f("DiskSize", GoType::Int64).with_json_tag("disksize"),
            f("TotalAmount", GoType::Int64).with_json_tag("totalamount"),
        ],
    )
}

/// The `Choice` type: an individual choice inside an agenda.
pub fn choice() -> GoType {
    strukt(
        "Choice",
        vec![
            f("ID", GoType::String).with_json_tag("id"),
            f("Description", GoType::String).with_json_tag("description"),
            f("Bits", GoType::Uint16).with_json_tag("bits"),
            f("IsAbstain", GoType::Bool).with_json_tag("isabstain"),
            f("IsNo", GoType::Bool).with_json_tag("isno"),
            f("Count", GoType::Uint32).with_json_tag("count"),
            f("Progress", GoType::Float64).with_json_tag("progress"),
        ],
    )
}

/// The `Agenda` type: an individual agenda including its choices.
pub fn agenda() -> GoType {
    strukt(
        "Agenda",
        vec![
            f("ID", GoType::String).with_json_tag("id"),
            f("Description", GoType::String).with_json_tag("description"),
            f("Mask", GoType::Uint16).with_json_tag("mask"),
            f("StartTime", GoType::Uint64).with_json_tag("starttime"),
            f("ExpireTime", GoType::Uint64).with_json_tag("expiretime"),
            f("Status", GoType::String).with_json_tag("status"),
            f("QuorumProgress", GoType::Float64).with_json_tag("quorumprogress"),
            f("Choices", choice().slice()).with_json_tag("choices"),
        ],
    )
}

/// The `GetVoteInfoResult` type (getvoteinfo).
pub fn get_vote_info_result() -> GoType {
    strukt(
        "GetVoteInfoResult",
        vec![
            f("CurrentHeight", GoType::Int64).with_json_tag("currentheight"),
            f("StartHeight", GoType::Int64).with_json_tag("startheight"),
            f("EndHeight", GoType::Int64).with_json_tag("endheight"),
            f("Hash", GoType::String).with_json_tag("hash"),
            f("VoteVersion", GoType::Uint32).with_json_tag("voteversion"),
            f("Quorum", GoType::Uint32).with_json_tag("quorum"),
            f("TotalVotes", GoType::Uint32).with_json_tag("totalvotes"),
            f("Agendas", agenda().slice()).with_json_tag("agendas,omitempty"),
        ],
    )
}

/// The `GetTreasuryBalanceResult` type (gettreasurybalance).
pub fn get_treasury_balance_result() -> GoType {
    strukt(
        "GetTreasuryBalanceResult",
        vec![
            f("Hash", GoType::String).with_json_tag("hash"),
            f("Height", GoType::Int64).with_json_tag("height"),
            f("Balance", GoType::Uint64).with_json_tag("balance"),
            f("Updates", GoType::Int64.slice()).with_json_tag("updates,omitempty"),
        ],
    )
}

/// The `TreasurySpendVotes` type: vote data for a single tspend.
pub fn treasury_spend_votes() -> GoType {
    strukt(
        "TreasurySpendVotes",
        vec![
            f("Hash", GoType::String).with_json_tag("hash"),
            f("Expiry", GoType::Int64).with_json_tag("expiry"),
            f("VoteStart", GoType::Int64).with_json_tag("votestart"),
            f("VoteEnd", GoType::Int64).with_json_tag("voteend"),
            f("YesVotes", GoType::Int64).with_json_tag("yesvotes"),
            f("NoVotes", GoType::Int64).with_json_tag("novotes"),
        ],
    )
}

/// The `GetTreasurySpendVotesResult` type (gettreasuryspendvotes).
pub fn get_treasury_spend_votes_result() -> GoType {
    strukt(
        "GetTreasurySpendVotesResult",
        vec![
            f("Hash", GoType::String).with_json_tag("hash"),
            f("Height", GoType::Int64).with_json_tag("height"),
            f("Votes", treasury_spend_votes().slice()).with_json_tag("votes"),
        ],
    )
}

/// The `GetWorkResult` type (getwork).
pub fn get_work_result() -> GoType {
    strukt(
        "GetWorkResult",
        vec![
            f("Data", GoType::String).with_json_tag("data"),
            f("Target", GoType::String).with_json_tag("target"),
        ],
    )
}

/// The `Ticket` type.
pub fn ticket() -> GoType {
    strukt(
        "Ticket",
        vec![
            f("Hash", GoType::String).with_json_tag("hash"),
            f("Owner", GoType::String).with_json_tag("owner"),
        ],
    )
}

/// The `LiveTicketsResult` type (livetickets).
pub fn live_tickets_result() -> GoType {
    strukt(
        "LiveTicketsResult",
        vec![f("Tickets", GoType::String.slice()).with_json_tag("tickets")],
    )
}

/// The `StartProfilerResult` type (startprofiler).
pub fn start_profiler_result() -> GoType {
    strukt(
        "StartProfilerResult",
        vec![f("Listeners", GoType::String.slice()).with_json_tag("listeners")],
    )
}

fn fee_info_fields() -> Vec<dcroxide_dcrjson::StructField> {
    vec![
        f("Number", GoType::Uint32).with_json_tag("number"),
        f("Min", GoType::Float64).with_json_tag("min"),
        f("Max", GoType::Float64).with_json_tag("max"),
        f("Mean", GoType::Float64).with_json_tag("mean"),
        f("Median", GoType::Float64).with_json_tag("median"),
        f("StdDev", GoType::Float64).with_json_tag("stddev"),
    ]
}

/// The `FeeInfoBlock` type: ticket fee information about a block.
pub fn fee_info_block() -> GoType {
    let mut fields = vec![f("Height", GoType::Uint32).with_json_tag("height")];
    fields.extend(fee_info_fields());
    strukt("FeeInfoBlock", fields)
}

/// The `FeeInfoMempool` type: ticket fee information about the
/// mempool.
pub fn fee_info_mempool() -> GoType {
    strukt("FeeInfoMempool", fee_info_fields())
}

/// The `FeeInfoRange` type: ticket fee information about a range.
pub fn fee_info_range() -> GoType {
    strukt("FeeInfoRange", fee_info_fields())
}

/// The `FeeInfoWindow` type: ticket fee information about an
/// adjustment window.
pub fn fee_info_window() -> GoType {
    let mut fields = vec![
        f("StartHeight", GoType::Uint32).with_json_tag("startheight"),
        f("EndHeight", GoType::Uint32).with_json_tag("endheight"),
    ];
    fields.extend(fee_info_fields());
    strukt("FeeInfoWindow", fields)
}

/// The `TicketFeeInfoResult` type (ticketfeeinfo).
pub fn ticket_fee_info_result() -> GoType {
    strukt(
        "TicketFeeInfoResult",
        vec![
            f("FeeInfoMempool", fee_info_mempool()).with_json_tag("feeinfomempool"),
            f("FeeInfoBlocks", fee_info_block().slice()).with_json_tag("feeinfoblocks"),
            f("FeeInfoWindows", fee_info_window().slice()).with_json_tag("feeinfowindows"),
        ],
    )
}

/// The `TxFeeInfoResult` type (txfeeinfo).
pub fn tx_fee_info_result() -> GoType {
    strukt(
        "TxFeeInfoResult",
        vec![
            f("FeeInfoMempool", fee_info_mempool()).with_json_tag("feeinfomempool"),
            f("FeeInfoBlocks", fee_info_block().slice()).with_json_tag("feeinfoblocks"),
            f("FeeInfoRange", fee_info_range()).with_json_tag("feeinforange"),
        ],
    )
}

/// The `TicketsForAddressResult` type (ticketsforaddress).
pub fn tickets_for_address_result() -> GoType {
    strukt(
        "TicketsForAddressResult",
        vec![f("Tickets", GoType::String.slice()).with_json_tag("tickets")],
    )
}

/// The `ValidateAddressChainResult` type (validateaddress).
pub fn validate_address_chain_result() -> GoType {
    strukt(
        "ValidateAddressChainResult",
        vec![
            f("IsValid", GoType::Bool).with_json_tag("isvalid"),
            f("Address", GoType::String).with_json_tag("address,omitempty"),
        ],
    )
}

/// The `VersionResult` type (version).
pub fn version_result() -> GoType {
    strukt(
        "VersionResult",
        vec![
            f("VersionString", GoType::String).with_json_tag("versionstring"),
            f("Major", GoType::Uint32).with_json_tag("major"),
            f("Minor", GoType::Uint32).with_json_tag("minor"),
            f("Patch", GoType::Uint32).with_json_tag("patch"),
            f("Prerelease", GoType::String).with_json_tag("prerelease"),
            f("BuildMetadata", GoType::String).with_json_tag("buildmetadata"),
        ],
    )
}

/// The `ScriptPubKeyResult` type: the scriptPubKey data of a tx
/// script.
pub fn script_pub_key_result() -> GoType {
    strukt(
        "ScriptPubKeyResult",
        vec![
            f("Asm", GoType::String).with_json_tag("asm"),
            f("Hex", GoType::String).with_json_tag("hex,omitempty"),
            f("ReqSigs", GoType::Int32).with_json_tag("reqSigs,omitempty"),
            f("Type", GoType::String).with_json_tag("type"),
            f("Addresses", GoType::String.slice()).with_json_tag("addresses,omitempty"),
            f("CommitAmt", GoType::Float64.ptr()).with_json_tag("commitamt,omitempty"),
            f("Version", GoType::Uint16).with_json_tag("version"),
        ],
    )
}

/// The `ScriptSig` type: a signature script.
pub fn script_sig() -> GoType {
    strukt(
        "ScriptSig",
        vec![
            f("Asm", GoType::String).with_json_tag("asm"),
            f("Hex", GoType::String).with_json_tag("hex"),
        ],
    )
}

/// The `Vin` type: parts of the tx input data.  Marshalling uses
/// [`marshal_vin`], which ports dcrd's custom `MarshalJSON`; this
/// descriptor describes the full struct as declared (used for
/// unmarshalling).
pub fn vin() -> GoType {
    strukt(
        "Vin",
        vec![
            f("Coinbase", GoType::String).with_json_tag("coinbase"),
            f("Stakebase", GoType::String).with_json_tag("stakebase"),
            f("Treasurybase", GoType::Bool).with_json_tag("treasurybase"),
            f("TreasurySpend", GoType::String).with_json_tag("treasuryspend"),
            f("Txid", GoType::String).with_json_tag("txid"),
            f("Vout", GoType::Uint32).with_json_tag("vout"),
            f("Tree", GoType::Int8).with_json_tag("tree"),
            f("Sequence", GoType::Uint32).with_json_tag("sequence"),
            f("AmountIn", GoType::Float64).with_json_tag("amountin"),
            f("BlockHeight", GoType::Uint32).with_json_tag("blockheight"),
            f("BlockIndex", GoType::Uint32).with_json_tag("blockindex"),
            f("ScriptSig", script_sig().ptr()).with_json_tag("scriptSig"),
        ],
    )
}

/// Marshal a [`vin`]-shaped value exactly as dcrd's custom
/// `Vin.MarshalJSON` does: a coinbase, stakebase, treasurybase, or
/// treasury spend input renders only its identifying field plus the
/// sequence/amount/height/index shared by all shapes, and every other
/// input renders the regular outpoint form with its script.  The
/// result is raw JSON for embedding via [`GoValue::Raw`].
pub fn marshal_vin(value: &GoValue) -> String {
    let fields = match value {
        GoValue::Struct(fields) => fields,
        _ => return "null".to_string(),
    };
    let field = |i: usize| fields.get(i).cloned().unwrap_or(GoValue::Null);
    let is_set = |i: usize| matches!(&fields[i], GoValue::String(s) if !s.is_empty());
    let shared = |first: dcroxide_dcrjson::StructField, first_val: GoValue| {
        let typ = GoType::Struct(vec![
            first,
            f("Sequence", GoType::Uint32).with_json_tag("sequence"),
            f("AmountIn", GoType::Float64).with_json_tag("amountin"),
            f("BlockHeight", GoType::Uint32).with_json_tag("blockheight"),
            f("BlockIndex", GoType::Uint32).with_json_tag("blockindex"),
        ]);
        let val = GoValue::Struct(vec![first_val, field(7), field(8), field(9), field(10)]);
        gojson::encode(&typ, &val)
    };

    // IsCoinBase.
    if is_set(0) {
        return shared(
            f("Coinbase", GoType::String).with_json_tag("coinbase"),
            field(0),
        );
    }
    // IsStakeBase.
    if is_set(1) {
        return shared(
            f("Stakebase", GoType::String).with_json_tag("stakebase"),
            field(1),
        );
    }
    // Treasurybase.
    if matches!(&fields[2], GoValue::Bool(true)) {
        return shared(
            f("Treasurybase", GoType::Bool).with_json_tag("treasurybase"),
            field(2),
        );
    }
    // IsTreasurySpend.
    if is_set(3) {
        return shared(
            f("TreasurySpend", GoType::String).with_json_tag("treasuryspend"),
            field(3),
        );
    }

    // The regular transaction input shape.
    let typ = GoType::Struct(vec![
        f("Txid", GoType::String).with_json_tag("txid"),
        f("Vout", GoType::Uint32).with_json_tag("vout"),
        f("Tree", GoType::Int8).with_json_tag("tree"),
        f("Sequence", GoType::Uint32).with_json_tag("sequence"),
        f("AmountIn", GoType::Float64).with_json_tag("amountin"),
        f("BlockHeight", GoType::Uint32).with_json_tag("blockheight"),
        f("BlockIndex", GoType::Uint32).with_json_tag("blockindex"),
        f("ScriptSig", script_sig().ptr()).with_json_tag("scriptSig"),
    ]);
    let val = GoValue::Struct(vec![
        field(4),
        field(5),
        field(6),
        field(7),
        field(8),
        field(9),
        field(10),
        field(11),
    ]);
    gojson::encode(&typ, &val)
}

/// The `Vout` type: parts of the tx output data.
pub fn vout() -> GoType {
    strukt(
        "Vout",
        vec![
            f("Value", GoType::Float64).with_json_tag("value"),
            f("N", GoType::Uint32).with_json_tag("n"),
            f("Version", GoType::Uint16).with_json_tag("version"),
            f("ScriptPubKey", script_pub_key_result()).with_json_tag("scriptPubKey"),
        ],
    )
}
